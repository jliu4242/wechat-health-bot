import hashlib
import os
import time
import xml.etree.ElementTree as ET
from flask import Flask, request, make_response

TOKEN = os.getenv("WECHAT_TOKEN")

app = Flask(__name__)

def check_signature(signature: str, timestamp: str, nonce: str) -> bool:
    combo = "".join(sorted([TOKEN, timestamp, nonce]))
    return hashlib.sha1(combo.encode()).hexdigest() == signature

@app.route("/wechat", methods=["GET", "POST"])
def wechat():
    signature = request.args.get("signature", "")
    timestamp = request.args.get("timestamp", "")
    nonce = request.args.get("nonce", "")
    echostr = request.args.get("echostr", "")

    # Step 1: WeChat server verification (GET)
    if request.method == "GET":
        if check_signature(signature, timestamp, nonce):
            return make_response(echostr)
        return "forbidden", 403

    # Step 2: Incoming messages (POST, XML)
    if not check_signature(signature, timestamp, nonce):
        return "forbidden", 403

    raw_xml = request.data.decode("utf-8")
    if not raw_xml:
        return ""

    # Parse the incoming XML and build a reply
    try:
        post_obj = ET.fromstring(raw_xml)
        from_username = post_obj.findtext("FromUserName", default="")
        to_username = post_obj.findtext("ToUserName", default="")
        keyword = (post_obj.findtext("Content", default="") or "").strip()
    except ET.ParseError:
        return "bad request", 400

    now = int(time.time())
    if keyword:
        content = "Welcome to wechat world!"
    else:
        content = "Input something..."

    reply = f"""<xml>
<ToUserName><![CDATA[{from_username}]]></ToUserName>
<FromUserName><![CDATA[{to_username}]]></FromUserName>
<CreateTime>{now}</CreateTime>
<MsgType><![CDATA[text]]></MsgType>
<Content><![CDATA[{content}]]></Content>
<FuncFlag>0</FuncFlag>
</xml>"""
    return make_response(reply)

if __name__ == "__main__":
    # set WECHAT_TOKEN in your env to match the token in the WeChat admin
    app.run(host="0.0.0.0", port=8000)
