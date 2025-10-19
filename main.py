import os, re, requests, secrets, base64, hashlib, hmac, urllib.parse
from dotenv import load_dotenv
from slack_bolt import App
from slack_bolt.adapter.socket_mode import SocketModeHandler

load_dotenv()

app = App(token=os.getenv("SLACK_BOT_TOKEN"), signing_secret=os.getenv("SLACK_SIGNING_SECRET"))

YUBICO_CLIENT_ID = os.getenv("YUBICO_CLIENT_ID")
YUBICO_SECRET_KEY = os.getenv("YUBICO_SECRET_KEY")
TARGET_CHANNEL = os.getenv("CHANNEL_ID")

assert YUBICO_CLIENT_ID is not None, "YUBICO_CLIENT_ID missing"
assert YUBICO_SECRET_KEY is not None, "YUBICO_SECRET_KEY missing"
assert TARGET_CHANNEL is not None, "TARGET_CHANNEL missing"


YUBIKEY_REGEX = re.compile(r"\b[cbdefghijklnrtuv]{44}\b") # regex is crazy

def verify_yubico_otp(otp: str) -> bool:
    nonce = secrets.token_hex(16)
    params = {
        "id": YUBICO_CLIENT_ID,
        "otp": otp,
        "nonce": nonce,
        "timestamp": "1",
        "sl": "secure",
    }

    # create HMAC-SHA1 signature using secret key

    message = "&".join(f"{k}={v}" for k, v in sorted(params.items()))
    key = base64.b64decode(YUBICO_SECRET_KEY)
    digest = hmac.new(key, message.encode("utf-8"), hashlib.sha1).digest()
    signature = base64.b64encode(digest).decode("utf-8")

    # add signature
    params["h"] = signature
    url = f"https://api.yubico.com/wsapi/2.0/verify?{urllib.parse.urlencode(params)}"

    try:
        res = requests.get(url, timeout=5)
        return "status=OK" in res.text
    except Exception as e:
        print(f"Yubico verification error: {e}")
        return False
    

otp_in = input("What's your otp? ")

print(verify_yubico_otp(otp_in))