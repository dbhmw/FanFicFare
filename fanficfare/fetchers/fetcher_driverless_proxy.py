# Copyright 2021 FanFicFare team
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
from .. import exceptions
from .log import make_log
from .base_fetcher import FetcherResponse
from .fetcher_requests import RequestsFetcher
from ..six.moves.http_cookiejar import Cookie

import socket,base64,ssl,time
import json as _json
from hashlib import sha256
from zlib import decompress
from random import randint

import logging
logger = logging.getLogger(__name__)

class Driverless_ProxyFetcher(RequestsFetcher):
    CHUNK_SIZE = 8192
    CLOUDFLARE_CODES = {520: "Web Server Returned an Unknown Error", 521: "Web Server Is Down",  522: "Connection Timed Out", 523: "Origin Is Unreachable", 524: "A Timeout Occurred", 525: "SSL Handshake Failed", 526: "Invalid SSL Certificate", 530: "1xxx Error"}

    def __init__(self, getConfig_fn, getConfigList_fn):
        super(Driverless_ProxyFetcher, self).__init__(getConfig_fn, getConfigList_fn)
        try:
            self.context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
            self.context.load_cert_chain(certfile=self.getConfig("driverless_proxy_cert"), keyfile=self.getConfig("driverless_proxy_key"))
            self.context.verify_mode = ssl.CERT_REQUIRED
            self.context.load_verify_locations(cafile=self.getConfig("driverless_proxy_cacert"))
            self.context.check_hostname = False
        except IOError:
            raise IOError('driverless_proxy: Unable to locate certificate files. Have you correctly configured the servercert, cert, and key?')
        self.timeout = float(self.getConfig("connect_timeout", 60))
        self.address = (self.getConfig("driverless_proxy_address", "127.0.0.1"), int(self.getConfig("driverless_proxy_port", 23000)))
        self.retries = 0

    def decode(self, packet):
        logger.debug("Process the response")
        checksum = base64.b64decode(packet[:44])
        if not checksum or len(checksum) < 32:
            raise socket.error("Connection interrupted.")

        content = decompress(packet[44:-1])
        if not checksum == sha256(content).digest():
            raise ValueError("Verification failed. Message is corrupted.")
        offsets = content[:18].decode('utf-8')
        response = content[18:]
        #logger.debug(offsets)

        status_offset = int(offsets[:2])
        content_type_offset = status_offset + int(offsets[2:4])
        source_offset = content_type_offset + int(offsets[4:13])
        cookies_offset = source_offset + int(offsets[13:18])

        if not 0 <= status_offset <= content_type_offset <= source_offset <= cookies_offset == len(response):
            raise IndexError("Invalid offsets: %s, %s, %s, %s, len=%s"%str(status_offset),str(content_type_offset),str(source_offset),str(cookies_offset),str(len(response)))

        status = response[:status_offset].decode('utf-8')
        ctype = response[status_offset:content_type_offset].decode('utf-8')
        source = response[content_type_offset:source_offset].decode('utf-8')
        source = base64.b64decode(source)
        cookies = response[source_offset:cookies_offset].decode('utf-8')

        return {"content-type": ctype, "content": source, "status_code": int(status), "cookies": cookies}

    def encode(self, packet):
        encoded_packet = packet.encode("utf-8")
        checksum = sha256(encoded_packet).digest()
        b64_checksum = base64.b64encode(checksum)
        b64_packet = base64.b64encode(encoded_packet)
        packet = b64_checksum + b64_packet + b'\0'
        return packet

    def get_session(self):
        for cookie in self.get_cookiejar():
            if cookie.name == '__DriverlessSession__':
                self.session_cookie = cookie
                return cookie._rest['session']
        cookie = Cookie(
            version=0, name='__DriverlessSession__', value='__None__', domain='', path='/',
            port=None, port_specified=False, domain_specified=False,  domain_initial_dot=False,
            path_specified=False, secure=False, expires=None, discard=False, comment=None, comment_url=None,
            rest={
                'HttpOnly': True,
                'session': str(self.getConfig("driverless_proxy_session", None) or randint(0,4294967295)),
            }
        )
        self.cookiejar.set_cookie(cookie)
        self.session_cookie = cookie
        return cookie._rest['session']

    def get_cookies(self):
        cookies = []
        if self.cookiejar is None:
            return cookies

        for cookie in self.cookiejar:
            if cookie.name == '__DriverlessSession__':
                continue

            cookies.append({
                'name': cookie.name,
                'value': cookie.value,
                'domain': cookie.domain,
                'path': cookie.path,
                'expires': cookie.expires if cookie.expires else -1,
                'secure': cookie.secure,
                'httpOnly': cookie._rest is not None and cookie.has_nonstandard_attr('HttpOnly'),
            })
        return cookies

    def save_cookies(self, cookies):
        cookies_list = _json.loads(cookies)
        for cookie in cookies_list:
            _cookie = Cookie(version=0, name=str(cookie["name"]), value=str(cookie["value"]), port=None, port_specified=False,
                domain=str(cookie["domain"]), domain_specified=True, domain_initial_dot=cookie["domain"].startswith('.'),
                path=str(cookie["path"]), path_specified=bool(cookie["path"]),
                secure=cookie["secure"], expires=str(cookie["expires"]), discard=False,
                comment=None, comment_url=None, rest={},
            )
            self.get_cookiejar().set_cookie(_cookie)

    def raise_for_status(self, url, response):
        if 300 > response['status_code'] >= 200:
            return
        http_error_msg = None

        if response["status_code"] in {-400, -1}:
            raise exceptions.FailedToDownload("Failed to fetch %s. [%s]" % (url, response["status_code"]))

        if response['status_code'] in Driverless_ProxyFetcher.CLOUDFLARE_CODES:
            http_error_msg = u"%s Server Error: %s for url: %s" % (response['status_code'], Driverless_ProxyFetcher.CLOUDFLARE_CODES[response['status_code']], url)
        else:
            if 400 <= response["status_code"] < 500:
                http_error_msg = u'%s Client Error. For url: %s' % (response['status_code'], url)
            elif 500 <= response["status_code"] < 600:
                http_error_msg = u'%s Server Error. For url: %s' % (response['status_code'], url)

        if http_error_msg:
            raise exceptions.HTTPErrorFFF(url, response["status_code"], http_error_msg, response["content"])
        raise exceptions.FailedToDownload("Failed. %s"%url)

    def cooldown(self, status_code):
        if not status_code in [413, 429, 500, 502, 503, 504] or self.retries > 3:
            return False
        self.retries += 1
        sleep_time = round(int(self.getConfig("driverless_proxy_retry", 2)))
        slow_down = float((sleep_time + self.retries) * 2 ** self.retries)
        logger.debug("Cooldown: %.2f"%min(slow_down, 3600.0))
        time.sleep(min(slow_down, 3600.0))
        return True

    def send_request(self, packet):
        response = {"status_code": -400, "cookies": "None", "content": "", "content-type": ""}
        end_marker = b"\0\0\0\xFF\xFF\xFF\0\0\0"

        try:
            conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            ssl_s = self.context.wrap_socket(conn, server_side=False)
            ssl_s.connect(self.address)
            #logger.debug("SSL established. Peer: {}".format(s.getpeercert()))
        except (socket.error, ssl.SSLError):
            raise RuntimeError('driverless_proxy unavailable, connection error %s %s'%self.address)

        try:
            logger.debug("Send the request to the server at %s", self.address)
            ssl_s.sendall(packet)

            ssl_s.settimeout(self.timeout)
            logger.debug("Receive the response from the server. Timeout(%s)", str(self.timeout))
            while response["status_code"] == -400:
                chunks = []
                prev_tail = b""
                while True:
                    chunk = ssl_s.recv(Driverless_ProxyFetcher.CHUNK_SIZE)
                    if not chunk:
                        logger.debug('No data received, closing socket.')
                        response["status_code"] = -1
                        break
                    chunks.append(chunk)

                    if end_marker in (prev_tail + chunk):
                        logger.debug("End of data received.")
                        break
                    # Update prev_tail to the last len(end_marker)-1 of current chunk.
                    prev_tail = chunk[-(len(end_marker) - 1):]
                data = b"".join(chunks)

                response = self.decode(data)
        except (socket.error, ssl.SSLError) as e:
            logger.debug(e)
        finally:
            if ssl_s:
                try:
                    ssl_s.shutdown(socket.SHUT_RDWR)
                except socket.error as e:
                    logger.debug(e) # Ignore "not connected" errors
                ssl_s.close()
            if conn:
                conn.close()

        return response

    def request(self, method, url, headers=None, parameters=None, json=None):
        if method not in ('GET','POST'):
            raise NotImplementedError()
        logger.debug(make_log('driverless_ProxyFetcher', method, url, hit='REQ', bar='-'))

        if isinstance(parameters, dict):
            parameters = _json.dumps(parameters)
        else:
            parameters = str(parameters)

        is_image = str("Accept" in headers)
        headers.pop('User-Agent', None)
        headers.pop('Accept', None)
        packet_str = method +\
            "\x01\x7f\x01" + url +\
            "\x01\x7f\x01" + _json.dumps(headers) +\
            "\x01\x7f\x01" + parameters +\
            "\x01\x7f\x01" + is_image +\
            "\x01\x7f\x01" + _json.dumps(self.get_cookies()) +\
            "\x01\x7f\x01" + str(self.get_session()) +\
            "\x01\x7f\x01" + str(self.timeout*0.5)

        packet = self.encode(packet_str)
        response = self.send_request(packet)

        if response["cookies"] != "None":
            self.save_cookies(response["cookies"])
        if self.getConfig("driverless_proxy_retry", False):
            if self.cooldown(response["status_code"]):
                return self.request(method, url, headers, parameters, json)

        self.raise_for_status(url, response)
        return FetcherResponse(response["content"], url, False)
