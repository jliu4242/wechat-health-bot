import hashlib
import os
import time
from xml.etree import ElementTree as ET

from flask import Flask, request, make_response

app = Flask(__name__)

# Only secret needed: the token you set in WeChat Platform for server verification
WECHAT_TOKEN = os.environ.get("WECHAT_TOKEN", "")


def _verify_signature(signature: str, timestamp: str, nonce: str) -> bool:
    """Validate request comes from WeChat."""
    if not WECHAT_TOKEN:
        return False
    pieces = [WECHAT_TOKEN, timestamp, nonce]
    pieces.sort()
    check_str = "".join(pieces).encode("utf-8")
    return hashlib.sha1(check_str).hexdigest() == signature


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


@app.route("/wechat", methods=["GET"])
def wechat_verify():
    signature = request.args.get("signature", "")
    timestamp = request.args.get("timestamp", "")
    nonce = request.args.get("nonce", "")
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
        reply_content = f"You said: {content}"

    reply_xml = _build_text_reply(from_user, to_user, reply_content)
    resp = make_response(reply_xml)
    resp.headers["Content-Type"] = "application/xml"
    return resp


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)