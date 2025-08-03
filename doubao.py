"""
逆向自豆包AI(https://www.doubao.com/)接口
图片上传 AWS Signature V4 - Volcano Version 算法逆向
需要cookie 和 AI接口url查询参数
仅供学习, 本脚本面向开发人员, 专于分析图片上传算法, 未对AI接口做任何处理, 不可直接使用

注意: 该接口仅用于学习和研究, 请遵守豆包AI的使用条款和政策。
该脚本仅用于学习交流, 请遵守法律, 禁止用于违法活动.
使用该脚本造成的一切后果与本人无关, 此脚本仅做技术分享
开源协议: MIT License
By @Pafonshaw
Github: https://github.com/Pafonshaw
2025/08/03
"""

"""
MIT License

Copyright (c) 2025 Pafonshaw

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""



import json
import os
import random
import uuid
import hashlib
import hmac
import datetime
import time
import urllib.parse
import requests
import zlib
from typing import Any, Dict, Optional

cookies: Dict[str, str] = {
    # 自己抓web端ck
}


# 签名算法: 
class VolcanoSigner:
    """
    AWS Signature V4 - Volcano Version 签名算法
    """

    class constant:
        algorithm = "AWS4-HMAC-SHA256"
        v4Identifier = "aws4_request"
        dateHeader = "X-Amz-Date"
        tokenHeader = "x-amz-security-token"
        contentSha256Header = "X-Amz-Content-Sha256"
        kDatePrefix = "AWS4"
    
    def __init__(self, access_key: str, secret_access_key: str, date: str, region: str='cn-north-1'):
        self.access_key = access_key
        self.secret_access_key = secret_access_key
        self.region = region
        self.service = "imagex"
        self.date = date
    
    def set_request(self, method: str, url: str, headers: Dict[str, str], payload: Optional[Dict] = None):
        """
        设置请求参数

        :param method: 请求方法
        :param url: 请求URL
        :param headers: 请求头, 注意仅需签以X-Amz-开头的两个参数
        :param payload: 请求体
        :return: self
        """
        self.method = method
        self.url = url
        self.headers = headers
        self.payload = payload
        return self

    def hmac_sha256(self, key, msg) -> hmac.HMAC:
        if isinstance(key, str):
            key = key.encode("utf-8")
        if isinstance(msg, str):
            msg = msg.encode("utf-8")
        if isinstance(key, hmac.HMAC):
            key = key.digest()
        return hmac.new(key, msg, hashlib.sha256)

    def getSigningKey(self) -> bytes:
        """
        获取签名密钥

        :return: 签名密钥
        """
        temp = self.hmac_sha256(self.constant.kDatePrefix+self.secret_access_key, self.date[:8])
        temp = self.hmac_sha256(temp, self.region)
        temp = self.hmac_sha256(temp, self.service)
        temp = self.hmac_sha256(temp, self.constant.v4Identifier)
        return temp.digest()
    
    def credentialString(self) -> str:
        p1 = self.date[:8]
        return "/".join([p1, self.region, self.service, self.constant.v4Identifier])
    
    def canonicalString(self) -> str:
        """
        构建规范请求

        :return: 规范请求字符串
        """
        parsed_url = urllib.parse.urlparse(self.url)
        query_params = parsed_url.query

        p1 = self.method.upper()
        p2 = parsed_url.path or "/"
        p3 = "&".join(sorted(query_params.split("&"))) if query_params else ""
        p4 = self.canonicalHeaders() + '\n'
        p5 = self.signedHeaders()
        p6 = self.hexEncodedBodyHash()
        return "\n".join([p1, p2, p3, p4, p5, p6])

    def canonicalHeaders(self) -> str:
        """
        构建规范请求头

        :return: 规范请求头字符串
        """
        sortable_headers: list[tuple[str, str]] = [
            (key.strip().lower(), value.strip())
            for key, value in self.headers.items()
        ]
        sortable_headers.sort(key=lambda x: x[0])
        canonical_lines = [
            f"{key}:{value}"
            for key, value in sortable_headers
            if value
        ]
        return "\n".join(canonical_lines)

    def signedHeaders(self) -> str:
        """
        构建签名请求头

        :return: 签名请求头字符串
        """
        return ";".join(sorted([key.lower() for key in self.headers.keys() if key.lower().startswith('x-amz-')]))

    def hexEncodedBodyHash(self) -> str:
        if temp:=self.headers.get(self.constant.contentSha256Header):
            return temp
        if not self.payload:
            # 上传图片需要用到的到这里就会返回了, 下边的payload连接根据js编写, 无法确定是否正确
            return hashlib.sha256(b"").hexdigest()
        result = []
        for key, value in self.payload.items():
            if value is None:
                continue
            quote_key = urllib.parse.quote(key, safe="-_.~")

            if not quote_key:
                continue
            if isinstance(value, list):
                quote_items = sorted([urllib.parse.quote(item, safe="-_.~") for item in value])
                result.append("&".join(f"{quote_key}={v}" for v in quote_items))
            else:
                quote_value = urllib.parse.quote(value, safe="-_.~")
                result.append(f"{quote_key}={quote_value}")
        return hashlib.sha256("&".join(result).encode("utf-8")).hexdigest()

    def stringToSign(self) -> str:
        """
        构建待签字符串

        :return: 待签字符串
        """
        p1 = self.constant.algorithm
        p2 = self.date
        p3 = self.credentialString()
        temp = self.canonicalString()
        p4 = hashlib.sha256(temp.encode("utf-8")).hexdigest()
        return "\n".join([p1, p2, p3, p4])
    
    def signature(self) -> str:
        """
        计算签名

        :return: 签名字符串
        """
        p1 = self.getSigningKey()
        p2 = self.stringToSign()
        p3 = self.hmac_sha256(p1, p2)
        return p3.hexdigest()
    
    def addAuthorization(self) -> Dict[str, str]:
        """
        添加Authorization头

        :return: 添加Authorization字段的请求头
        """
        p1 = self.constant.algorithm
        p2 = ' Credential='
        p3 = self.access_key
        p4 = '/'
        p5 = self.credentialString()
        p6 = ', SignedHeaders='
        p7 = self.signedHeaders()
        p8 = ', Signature='
        p9 = self.signature()
        Authorization = ''.join([p1, p2, p3, p4, p5, p6, p7, p8, p9])
        self.headers.update({
            "Authorization": Authorization,
        })
        return self.headers

# 图片上传流程
class DouBaoImgUploder:
    """
    豆包图片上传
    """
    def __init__(self, cookies: Dict):
        """
        初始化豆包图片上传器

        :param cookies: 抓的豆包web端ck
        """
        self.cookies = cookies

    @staticmethod
    def s() -> str:
        """原js: n.s = Math.random().toString(36).substring(2)"""
        base_str = 'abcdefghigklmnopqrstuvwxyz0123456789'
        return ''.join(random.choices(base_str, k=random.randint(8, 12)))
    
    def prepare_upload(self) -> Dict:
        """
        准备上传

        :return: 上传信息
        """
        url = "https://www.doubao.com/alice/resource/prepare_upload?"
        headers = {
            "Host": "www.doubao.com",
            "Connection": "keep-alive",
            "Agw-Js-Conv": "str",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0",
            "Accept": "application/json, text/plain, */*",
            "Content-Type": "application/json",
            "Origin": "https://www.doubao.com",
            "Referer": "https://www.doubao.com/chat",
        }
        data = {
            "tenant_id": "5",
            "scene_id": "5",
            "resource_type": 2,
        }
        res = requests.post(url, headers=headers, cookies=self.cookies, json=data)
        return res.json()
    
    def upload_img(self, img: str, refresh: bool=False):
        """
        上传图片

        :param img: 图片路径
        :param refresh: 是否强制刷新STSToken
        :return: 上传结果
        """
        if not os.path.exists(img):
            raise ValueError('图呢?')
        if os.path.exists("STSToken.json"):
            with open("STSToken.json", "r+", encoding="utf-8") as f:
                data = json.load(f)
                if time.time() - data["time"] > 60 * 58 or refresh:
                    # 58分钟刷新一次STSToken
                    STSToken = self.prepare_upload()
                    if STSToken["code"] != 0:
                        raise ValueError("获取STSToken失败")
                    data["STSToken"] = STSToken
                    data["time"] = time.time()
                    f.seek(0)
                    f.write(json.dumps(data, ensure_ascii=False, indent=2))
                    f.truncate()
                else:
                    STSToken = data["STSToken"]
        else:
            STSToken = self.prepare_upload()
            if STSToken["code"] != 0:
                raise ValueError("获取STSToken失败")
            with open("STSToken.json", "w", encoding="utf-8") as f:
                json.dump({"STSToken": STSToken, "time": time.time()}, f, ensure_ascii=False, indent=2)
        
        with open(img, "rb") as f:
            img_data = f.read()
        
        upurl = "https://" + STSToken["data"]["upload_host"] + "/"
        ApplyImageUpload_url = upurl + f"?Action=ApplyImageUpload&Version=2018-08-01&ServiceId={STSToken['data']['service_id']}&NeedFallback=true&FileSize={len(img_data)}&FileExtension=.{img.split('.')[-1]}&s={self.s()}"
        utc_time = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        headers = {
            "X-Amz-Date": utc_time,
            "x-amz-security-token": STSToken["data"]["upload_auth_token"]["session_token"],
        }
        headers = VolcanoSigner(
            access_key=STSToken["data"]["upload_auth_token"]["access_key"],
            secret_access_key=STSToken["data"]["upload_auth_token"]["secret_key"],
            date=utc_time
        ).set_request(
            method="GET",
            url=ApplyImageUpload_url,
            headers=headers
        ).addAuthorization()
        headers.update({
            "Host": STSToken["data"]["upload_host"],
            "Connection": "keep-alive",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0",
            "Accept": "*/*",
            "Origin": "https://www.doubao.com",
            "Referer": "https://www.doubao.com/",
        })
        upload_info = requests.get(ApplyImageUpload_url, headers=headers).json()
        if upload_info.get("Error"):
            raise ValueError(upload_info["Error"]["Message"])
        UploadAddress: Dict[str, Any] = upload_info["Result"]["UploadAddress"]
        StoreInfo = UploadAddress["StoreInfos"][0]
        StoreUri = StoreInfo["StoreUri"]
        Auth = StoreInfo["Auth"]
        UploadHost = UploadAddress["UploadHosts"][0]
        SessionKey = UploadAddress["SessionKey"]
        upload_url = "https://" + UploadHost + "/upload/v1/" + StoreUri
        headers = {
            "Host": UploadHost,
            "Connection": "keep-alive",
            "Authorization": Auth,
            "Content-CRC32": "{:08x}".format(zlib.crc32(img_data)&0xFFFFFFFF),
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0",
            # "X-Storage-U": "886674796068636",
            "Content-Type": "application/octet-stream",
            "Content-Disposition": "attachment; filename=\"undefined\"",
            "Accept": "*/*",
            "Origin": "https://www.doubao.com",
            "Referer": "https://www.doubao.com/",
        }
        upload_result = requests.post(upload_url, headers=headers, data=img_data).json()
        if upload_result.get("code") != 2000:
            raise ValueError(upload_result.get("message"))

        CommitImageUpload_url = upurl + "?Action=CommitImageUpload&Version=2018-08-01&ServiceId=" + STSToken['data']['service_id']
        data = '{"SessionKey":"'+SessionKey+'"}'
        utc_time = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        headers = {
            "X-Amz-Content-Sha256": hashlib.sha256(data.encode("utf-8")).hexdigest(),
            "x-amz-security-token": STSToken["data"]["upload_auth_token"]["session_token"],
            "X-Amz-Date": utc_time,
        }
        headers = VolcanoSigner(
            access_key=STSToken["data"]["upload_auth_token"]["access_key"],
            secret_access_key=STSToken["data"]["upload_auth_token"]["secret_key"],
            date=utc_time
        ).set_request(
            method="POST",
            url=CommitImageUpload_url,
            headers=headers
        ).addAuthorization()
        headers.update({
            "Host": STSToken["data"]["upload_host"],
            "Connection": "keep-alive",
            "Content-Type": "application/json",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0",
            "Accept": "*/*",
            "Origin": "https://www.doubao.com",
            "Referer": "https://www.doubao.com/",
        })
        result = requests.post(CommitImageUpload_url, headers=headers, data=data).json()
        if result.get("Error"):
            raise ValueError(result["Error"]["Message"])
        return result["Result"]["Results"][0]["Uri"]


imgUploader = DouBaoImgUploder(cookies=cookies)

imgUri = imgUploader.upload_img(input("请输入图片路径："))

url = "https://www.doubao.com/samantha/chat/completion"
params = {
    # 填抓的url查询参数
    "aid": "",
    "device_id": "",
    "device_platform": "web",
    "language": "zh",
    "pc_version": "2.30.0",
    "pkg_type": "release_version",
    "real_aid": "",
    "region": "CN",
    "samantha_web": "1",
    "sys_region": "CN",
    "tea_uuid": "",
    "use-olympus-account": "1",
    "version_code": "",
    "web_id": "",
    "msToken": "",
    "a_bogus": ""
}

local_conversation_id = "local_" + ''.join(random.choices("0123456789", k=16))

headers = {
  "Host": "www.doubao.com",
  "Connection": "keep-alive",
  "Agw-Js-Conv": "str, str",
  "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0",
  "content-type": "application/json",
  "Accept": "*/*",
  "Origin": "https://www.doubao.com",
  "Referer": "https://www.doubao.com/chat/"
}


data = {
    "messages": [
        {
            "content": '{"text":"识别图片"}',
            "content_type": 2009,
            "attachments": [
                {
                    "type": "image",
                    "key": imgUri,
                    "extra": {"refer_types": "overall"},
                    "identifier": str(uuid.uuid4()),
                }
            ],
        }
    ],
    "completion_option": {
        "is_regen": False,
        "with_suggest": False,
        "need_create_conversation": True,
        "launch_stage": 1,
        "is_replace": False,
        "is_delete": False,
        "message_from": 0,
        "use_auto_cot": False,
        "resend_for_regen": False,
        "event_id": "0",
    },
    "evaluate_option": {"web_ab_params": ""},
    "conversation_id": "0",
    "local_conversation_id": local_conversation_id,
    "local_message_id": str(uuid.uuid4()),
}

# print(imgUri)
# print(headers)
# print(data)

res = requests.post(url, params=params, headers=headers, cookies=cookies, json=data, stream=True)

for line in res.iter_lines():
    if line:
        line = line.decode("utf-8")
        print(line)





