import os
import hmac
import hashlib
import json
from fastapi import FastAPI, Request, HTTPException

app = FastAPI()

# Get Slack Signing Secret from Render environment variables
SLACK_SIGNING_SECRET = os.getenv("SLACK_SIGNING_SECRET", "")


def verify_slack_request(request: Request, body: bytes):
    """Verify Slack request authenticity using signing secret"""
    timestamp = request.headers.get("X-Slack-Request-Timestamp", "")
    slack_signature = request.headers.get("X-Slack-Signature", "")

    if not slack_signature or not timestamp:
        raise HTTPException(status_code=403, detail="Missing Slack headers")

    # Slack signing procedure: v0:{timestamp}:{body}
    basestring = f"v0:{timestamp}:{body.decode('utf-8')}".encode("utf-8")
    my_signature = "v0=" + hmac.new(
        SLACK_SIGNING_SECRET.encode("utf-8"),
        basestring,
        hashlib.sha256
    ).hexdigest()

    if not hmac.compare_digest(my_signature, slack_signature):
        raise HTTPException(status_code=403, detail="Invalid Slack signature")


@app.post("/slack/events")
async def slack_events(request: Request):
    """Handles incoming Slack Events"""
    body = await request.body()
    verify_slack_request(request, body)

    data = json.loads(body.decode("utf-8"))

    # 1️⃣ Slack URL verification challenge
    if data.get("type") == "url_verification":
        return {"challenge": data["challenge"]}

    # 2️⃣ Slack Event
    if "event" in data:
        event = data["event"]
        event_type = event.get("type")

        if event_type == "file_shared":
            print("📂 File shared event:", json.dumps(event, indent=2))
            # Later: use SLACK_BOT_TOKEN to fetch the file contents
            return {"ok": True}

        print(f"⚡ Unhandled event: {event_type}")
        return {"ok": True}

    return {"ok": True}


@app.get("/")
def home():
    return {"message": "Slack Bot is live on Render 🚀"}
