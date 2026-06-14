"""Minimal Vercel Python handler - no external dependencies."""
import json

def handler(event, context):
    return {
        "statusCode": 200,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps({
            "message": "Sentinel Cyber AI running on Vercel!",
            "status": "ok"
        })
    }
