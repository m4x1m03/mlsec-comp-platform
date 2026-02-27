import os
import logging
import httpx
from fastapi import FastAPI, Request, Response
import uvicorn

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI()
client = httpx.AsyncClient(timeout=30.0)

GATEWAY_SECRET = os.getenv("GATEWAY_SECRET", "welovemarcus")

@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"])
async def proxy(request: Request, path: str):
    auth_header = request.headers.get("X-Gateway-Auth")
    if auth_header != GATEWAY_SECRET:
        logger.warning(f"Unauthorized access attempt to {path}")
        return Response(content="Unauthorized", status_code=401)

    target_base = request.headers.get("X-Target-Url")
    if not target_base:
        return Response(content="X-Target-Url header missing", status_code=400)
    
    if not target_base.endswith("/"):
        target_base += "/"
    
    target_url = target_base + path
    if request.url.query:
        target_url += "?" + request.url.query
        
    headers = dict(request.headers)
    headers.pop("host", None)
    headers.pop("x-target-url", None)
    headers.pop("x-gateway-auth", None)
    
    body = await request.body()
    
    try:
        r = await client.request(
            request.method,
            target_url,
            headers=headers,
            content=body
        )
        return Response(
            content=r.content,
            status_code=r.status_code,
            headers={k: v for k, v in r.headers.items() 
                     if k.lower() not in ("content-encoding", "content-length", "transfer-encoding", "connection")}
        )
    except httpx.RequestError as exc:
        logger.error(f"Error proxying to {target_url}: {exc}")
        return Response(content=f"Proxy error: {exc}", status_code=502)

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8080)
