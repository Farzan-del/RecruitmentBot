import os
import hmac
import hashlib
import json
import requests
from fastapi import FastAPI, Request, HTTPException

app = FastAPI()

# 🔑 Environment variables (set in Render Dashboard → Environment)
SLACK_SIGNING_SECRET = os.getenv("SLACK_SIGNING_SECRET", "")
SLACK_BOT_TOKEN = os.getenv("SLACK_BOT_TOKEN", "")


def verify_slack_request(request: Request, body: bytes):
    """Verify Slack request authenticity using signing secret"""
    timestamp = request.headers.get("X-Slack-Request-Timestamp", "")
    slack_signature = request.headers.get("X-Slack-Signature", "")

    if not slack_signature or not timestamp:
        raise HTTPException(status_code=403, detail="Missing Slack headers")

    basestring = f"v0:{timestamp}:{body.decode('utf-8')}".encode("utf-8")
    my_signature = "v0=" + hmac.new(
        SLACK_SIGNING_SECRET.encode("utf-8"),
        basestring,
        hashlib.sha256
    ).hexdigest()

    if not hmac.compare_digest(my_signature, slack_signature):
        raise HTTPException(status_code=403, detail="Invalid Slack signature")


def download_slack_file(file_id: str):
    """Fetch file info from Slack and download it"""
    # 1️⃣ Get file info (to get the private download URL)
    info_url = "https://slack.com/api/files.info"
    headers = {"Authorization": f"Bearer {SLACK_BOT_TOKEN}"}
    resp = requests.get(info_url, headers=headers, params={"file": file_id})

    if not resp.ok or not resp.json().get("ok"):
        print("❌ Failed to get file info:", resp.text)
        return None

    file_info = resp.json()["file"]
    download_url = file_info["url_private_download"]
    filename = file_info["name"]

    # 2️⃣ Download the actual file using the private URL
    file_resp = requests.get(download_url, headers=headers)
    if file_resp.status_code == 200:
        os.makedirs("downloads", exist_ok=True)
        filepath = os.path.join("downloads", filename)
        with open(filepath, "wb") as f:
            f.write(file_resp.content)
        print(f"✅ File downloaded: {filepath}")
        return filepath
    else:
        print("❌ Failed to download file:", file_resp.text)
        return None


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
            file_id = event["file"]["id"]
            print(f"📂 File shared with ID: {file_id}")
            filepath = download_slack_file(file_id)
            if filepath:
                print(f"🎉 Resume saved at {filepath}")
            return {"ok": True}

        print(f"⚡ Unhandled event: {event_type}")
        return {"ok": True}

    return {"ok": True}


@app.get("/")
def home():
    return {"message": "Slack Bot is live on Render 🚀"}
