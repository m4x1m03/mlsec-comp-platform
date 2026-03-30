import docker
import docker.errors
from celery.utils.log import get_task_logger
from worker.db import get_engine
from worker.redis_client import get_redis_client

logger = get_task_logger(__name__)

def prune_orphans():
    """Find and remove any orphaned evaluation resources (networks, containers, and gateway rules)."""
    # Lock to ensure only one worker runs pruning at a time on startup.
    try:
        redis_client = get_redis_client()
        lock_key = "lock:prune_orphans"
        if not redis_client.set(lock_key, "1", nx=True, ex=60):
            logger.info("Skipping orphaned resource pruning: another worker is already running it.")
            return
    except Exception as e:
        print(f"Redis connection failed in prune_orphans: {e}")
        return

    try:
        from sqlalchemy import text
        client = docker.from_env()
        engine = get_engine()
        
        # Prune orphaned evaluation containers
        try:
            with engine.connect() as conn:
                # Check for both running and exited containers starting with 'eval_defense_'
                containers = client.containers.list(all=True, filters={"name": "eval_defense_"})
                for container in containers:
                    try:
                        name = container.name.lstrip('/')
                        # Name format: eval_defense_{job_id}_{defense_id_prefix}
                        parts = name.split('_')
                        if len(parts) < 3:
                            continue
                        job_id = parts[2]
                        
                        # Check job status in database
                        res = conn.execute(
                            text("SELECT status FROM jobs WHERE id = :job_id"),
                            {"job_id": job_id}
                        ).fetchone()
                        
                        # Prune if job is finished, failed, or missing from DB
                        if not res or res[0] in ['done', 'failed']:
                            logger.info(f"Pruning orphaned evaluation container: {name} (Job Status: {res[0] if res else 'Not Found'})")
                            try:
                                container.remove(force=True)
                            except docker.errors.NotFound:
                                pass # Already removed by another worker
                    except Exception as e:
                        logger.debug(f"Could not remove container {container.name}: {e}")
        except Exception as e:
            logger.error(f"Error during orphaned container pruning: {e}")

        # Prune orphaned evaluation networks
        try:
            networks = client.networks.list()
            pruned_net_count = 0
            
            for net in networks:
                if net.name.startswith("eval_net_") and net.name != "eval_net":
                    try:
                        # Reload to get latest container info
                        net.reload()
                        containers = net.attrs.get('Containers', {})
                        
                        # If no containers OR only mlsec-gateway is connected, it's orphaned
                        student_containers = [
                            c_info.get('Name') 
                            for c_info in containers.values() 
                            if c_info.get('Name').strip('/') != 'mlsec-gateway'
                        ]
                        
                        if not student_containers:
                            logger.info(f"Pruning orphaned evaluation network: {net.name}")
                            for c_id in list(containers.keys()):
                                try:
                                    net.disconnect(c_id, force=True)
                                except (docker.errors.NotFound, Exception):
                                    pass
                            
                            try:
                                net.remove()
                                pruned_net_count += 1
                            except docker.errors.NotFound:
                                pass # Already removed
                    except docker.errors.NotFound:
                        continue # Network disappeared
                    except Exception as e:
                        logger.warning(f"Failed to remove orphaned network {net.name}: {e}")
            
            if pruned_net_count > 0:
                logger.info(f"Successfully pruned {pruned_net_count} orphaned evaluation networks")
        except Exception as e:
            logger.error(f"Error during orphaned network pruning: {e}")

        # Prune orphaned iptables rules on gateway
        try:
            gateway = client.containers.get("mlsec-gateway")
            for table in ["nat", "filter"]:
                result = gateway.exec_run(f"iptables -t {table} -S")
                if result.exit_code != 0:
                    continue
                
                rules = result.output.decode().splitlines()
                # Refresh networks list for exact rule matching
                current_networks = [n.name for n in client.networks.list()]
                
                for rule in rules:
                    if "comment eval_net_" in rule:
                        parts = rule.split()
                        try:
                            comment_idx = parts.index("--comment")
                            rule_id = parts[comment_idx + 1]
                            
                            # Check if the network (with the same name as the comment/rule_id) still exists
                            if rule_id not in current_networks:
                                logger.info(f"Pruning orphaned iptables rule in table {table}: {rule_id}")
                                delete_rule = rule.replace("-A ", "-D ", 1)
                                gateway.exec_run(f"iptables -t {table} {delete_rule}")
                        except (ValueError, IndexError):
                            continue
        except (docker.errors.NotFound, Exception) as e:
            logger.warning(f"Failed to prune orphaned iptables rules: {e}")
            
    except Exception as e:
        logger.error(f"Error during orphaned resource pruning: {e}")
    finally:
        pass
