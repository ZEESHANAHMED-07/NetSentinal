from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from fastapi.security.api_key import APIKeyHeader
from starlette.status import HTTP_403_FORBIDDEN
from logger.logger import AlertLogger
from config import API_HOST, API_PORT, API_KEY
import os

app = FastAPI(title='NetSentinel API')

# Restrict CORS to localhost origins and specify allowed GET methods for security
allowed_origins = [
    f"http://{API_HOST}:{API_PORT}",
    f"http://localhost:{API_PORT}",
    f"http://127.0.0.1:{API_PORT}",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["GET"],
    allow_headers=["*"],
)

logger = AlertLogger()

API_KEY_NAME = "X-API-Key"
api_key_header = APIKeyHeader(name=API_KEY_NAME, auto_error=False)

def verify_api_key(api_key: str = Depends(api_key_header)):
    if api_key == API_KEY:
        return api_key
    raise HTTPException(
        status_code=HTTP_403_FORBIDDEN, detail="Access denied. Invalid or missing API key."
    )

@app.get('/', response_class=HTMLResponse)
def root():
    path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'dashboard', 'index.html')
    with open(path, 'r', encoding='utf-8') as f:
        return f.read()

@app.get('/api/alerts', dependencies=[Depends(verify_api_key)])
def get_alerts():
    return logger.get_all()

@app.get('/api/stats', dependencies=[Depends(verify_api_key)])
def get_stats():
    return logger.get_stats()

@app.get('/api/summary', dependencies=[Depends(verify_api_key)])
def get_summary():
    alerts = logger.get_all()
    stats = logger.get_stats()
    total_count = logger.get_total_count()
    return {
        'total_alerts': total_count,
        'attack_types': len(stats),
        'latest': alerts[0] if alerts else None,
        'breakdown': stats
    }
