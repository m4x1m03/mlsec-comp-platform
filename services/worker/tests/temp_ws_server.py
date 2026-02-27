import os
import asyncio
import json
import logging
import websockets
import sys

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("temp_ws_server")

async def handle_client(websocket):
    logger.info("Worker client connected to mock WebSocket server.")
    
    # Load minimal.exe once
    with open("services/worker/tests/minimal.exe", "rb") as f:
        file_bytes = f.read()

    try:
        # Accept valid Database IDs
        attack_sub_id = sys.argv[1] if len(sys.argv) > 1 else "dummy-attack-sub"
        file_ids_str = sys.argv[2] if len(sys.argv) > 2 else ""
        file_ids = file_ids_str.split(",") if file_ids_str else ["dummy-file-id"]

        logger.info(f"Streaming {len(file_ids)} samples for attack submission {attack_sub_id}")

        for i, file_id in enumerate(file_ids):
            metadata = {
                "file_id": file_id,
                "filename": f"sample_{i}.exe",
                "attack_submission_id": attack_sub_id
            }
            logger.info(f"Sending metadata for sample {i+1}/{len(file_ids)}: {file_id}")
            await websocket.send(json.dumps(metadata))
            
            # Delay to test sequential queue processing
            # await asyncio.sleep(0.5) 
            
            logger.info(f"Sending binary data for sample {i+1}/{len(file_ids)}")
            await websocket.send(file_bytes)
            
            # Wait a bit between samples to distinguish them in logs
            # await asyncio.sleep(1)

        # Finish stream
        await websocket.send(json.dumps({"status": "done"}))
        logger.info("Finished streaming all samples to worker client.")
        
    except websockets.exceptions.ConnectionClosed:
        logger.info("Worker client disconnected.")
    except Exception as e:
        logger.error(f"Error streaming samples: {e}")
        try:
            await websocket.send(json.dumps({"error": str(e)}))
        except:
            pass

async def main():
    port = int(os.getenv("WS_PORT", "8765"))
    host = os.getenv("WS_HOST", "0.0.0.0")
    logger.info(f"Starting mock WebSocket server on ws://{host}:{port}")
    async with websockets.serve(handle_client, host, port, max_size=None):
        await asyncio.sleep(120)

if __name__ == "__main__":
    asyncio.run(main())
