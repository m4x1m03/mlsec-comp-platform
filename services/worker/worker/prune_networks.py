import docker
import logging

logger = logging.getLogger(__name__)

def prune_orphans():
    """Find and remove any orphaned evaluation networks and gateway rules with no containers."""
    try:
        client = docker.from_env()
        networks = client.networks.list()
        pruned_count = 0
        
        for net in networks:
            if net.name.startswith("eval_net_"):
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
                    try:
                        for c_id in list(containers.keys()):
                            try:
                                net.disconnect(c_id, force=True)
                            except:
                                pass
                        
                        net.remove()
                        pruned_count += 1
                    except Exception as e:
                        logger.warning(f"Failed to remove orphaned network {net.name}: {e}")
        
        if pruned_count > 0:
            logger.info(f"Successfully pruned {pruned_count} orphaned evaluation networks")

        # Prune orphaned iptables rules on gateway
        try:
            gateway = client.containers.get("mlsec-gateway")
            for table in ["nat", "filter"]:
                result = gateway.exec_run(f"iptables -t {table} -S")
                if result.exit_code != 0:
                    continue
                
                rules = result.output.decode().splitlines()
                for rule in rules:
                    if "comment eval_net_" in rule:
                        parts = rule.split()
                        try:
                            comment_idx = parts.index("--comment")
                            rule_id = parts[comment_idx + 1]
                            
                            existing_networks = [n.name for n in networks]
                            if rule_id not in existing_networks:
                                logger.info(f"Pruning orphaned iptables rule in table {table}: {rule_id}")
                                delete_rule = rule.replace("-A ", "-D ", 1)
                                gateway.exec_run(f"iptables -t {table} {delete_rule}")
                        except (ValueError, IndexError):
                            continue
        except Exception as e:
            logger.warning(f"Failed to prune orphaned iptables rules: {e}")
            
    except Exception as e:
        logger.error(f"Error during orphaned resource pruning: {e}")
