"""Minimal Vercel test - barebones FastAPI app."""
from fastapi import FastAPI
from fastapi.responses import JSONResponse

app = FastAPI()

@app.get("/")
async def root():
    return {"message": "Hello from Sentinel Cyber AI on Vercel!", "status": "ok"}
