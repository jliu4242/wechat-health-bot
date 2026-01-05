import hashlib
import os
import time
from xml.etree import ElementTree as ET

from flask import Flask, request, make_response
from openai import OpenAI

app = Flask(__name__)

# Only secret needed: the token you set in WeChat Platform for server verification.
# Strip to avoid mismatch from accidental whitespace in the env var.
WECHAT_TOKEN = os.environ.get("WECHAT_TOKEN", "").strip()
# OpenAI key for generating replies to user messages.
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY", "").strip()
OPENAI_MODEL = os.environ.get("OPENAI_MODEL", "gpt-3.5-turbo").strip()

_openai_client = OpenAI(api_key=OPENAI_API_KEY) if OPENAI_API_KEY else None


def _verify_signature(signature: str, timestamp: str, nonce: str) -> bool:
    """Validate request comes from WeChat."""
    if not WECHAT_TOKEN:
        return False
    pieces = [WECHAT_TOKEN, timestamp, nonce]
    pieces.sort()
    check_str = "".join(pieces).encode("utf-8")
    expected = hashlib.sha1(check_str).hexdigest()
    return expected == signature


def _build_text_reply(to_user: str, from_user: str, content: str) -> str:
    now = int(time.time())
    return (
        "<xml>"
        f"<ToUserName><![CDATA[{to_user}]]></ToUserName>"
        f"<FromUserName><![CDATA[{from_user}]]></FromUserName>"
        f"<CreateTime>{now}</CreateTime>"
        "<MsgType><![CDATA[text]]></MsgType>"
        f"<Content><![CDATA[{content}]]></Content>"
        "</xml>"
    )


def _chat_reply(user_text: str) -> str:
    """Send the user's text to OpenAI and return the response text."""
    if not _openai_client or not OPENAI_MODEL:
        return "OpenAI is not configured."

    try:
        completion = _openai_client.chat.completions.create(
            model=OPENAI_MODEL,
            messages=[
                {
                    "role": "system",
                    "content": "You are a helpful assistant replying succinctly to WeChat text messages.",
                },
                {"role": "user", "content": user_text},
            ],
            max_tokens=200,
            temperature=0.7,
        )
        return completion.choices[0].message.content.strip()
    except Exception:
        return "Sorry, I could not generate a reply right now."


@app.route("/wechat", methods=["GET"])
def wechat_verify(echostr=None):
    # WeChat sends signature/timestamp/nonce/echostr as query params; echo back echostr on success.
    signature = request.args.get("signature", "")
    timestamp = request.args.get("timestamp", "")
    nonce = request.args.get("nonce", "")
    if echostr is None:
        echostr = request.args.get("echostr", "")
    if not _verify_signature(signature, timestamp, nonce):
        return "invalid signature", 403
    return echostr


@app.route("/wechat", methods=["POST"])
def wechat_message():
    signature = request.args.get("signature", "")
    timestamp = request.args.get("timestamp", "")
    nonce = request.args.get("nonce", "")
    if not _verify_signature(signature, timestamp, nonce):
        return "invalid signature", 403

    xml_data = request.data
    root = ET.fromstring(xml_data)
    msg_type = root.findtext("MsgType")
    from_user = root.findtext("FromUserName")
    to_user = root.findtext("ToUserName")
    content = root.findtext("Content", "")

    if msg_type != "text":
        reply_content = "Only text messages are supported right now."
    else:
        reply_content = _chat_reply(content)

    reply_xml = _build_text_reply(from_user, to_user, reply_content)
    resp = make_response(reply_xml)
    resp.headers["Content-Type"] = "application/xml"
    return resp


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)
