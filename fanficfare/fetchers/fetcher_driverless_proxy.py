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

import socket,base64,ssl,json,time
import inspect
from hashlib import sha256
from zlib import decompress
from ..six.moves.http_cookiejar import Cookie
from random import randint

import logging
logger = logging.getLogger(__name__)

from .. import exceptions
from .log import make_log
from .base_fetcher import FetcherResponse
from .fetcher_requests import RequestsFetcher

class SSLConnection:
    def __init__(self, hostname, address, port, context):
        self.hostname = hostname
        self.address = address
        self.port = port
        self.context = context
        self.ssl_s = None
        self.conn = None

    def __enter__(self):
        try:
            self.conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.ssl_s = self.context.wrap_socket(self.conn, server_side=False, server_hostname=self.hostname)
            self.ssl_s.connect((self.address, self.port))
            #logger.debug("SSL established. Peer: {}".format(s.getpeercert()))
        except (socket.error, ssl.SSLError) as e:
            logger.error("driverless_proxy unavailable, connection error: %s" % str(e))
            raise ConnectionError('driverless_proxy unavailable(%s:%s)'%(self.address, self.port))

        return self.ssl_s

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.ssl_s:
            try:
                self.ssl_s.shutdown(socket.SHUT_RDWR)
            except socket.error as e:
                logger.debug(e)
                pass  # Ignore "not connected" errors
            self.ssl_s.close()
        if self.conn:
            self.conn.close()

class Driverless_ProxyFetcher(RequestsFetcher):
    CHUNK_SIZE = 8192
    CLOUDFLARE_CODES = {520: "Web Server Returned an Unknown Error", 521: "Web Server Is Down",  522: "Connection Timed Out", 523: "Origin Is Unreachable", 524: "A Timeout Occurred", 525: "SSL Handshake Failed", 526: "Invalid SSL Certificate", 530: "1xxx Error"}
    HOSTNAME = None

    def __init__(self, getConfig_fn, getConfigList_fn):
        super(Driverless_ProxyFetcher, self).__init__(getConfig_fn, getConfigList_fn)
        try:
            if not Driverless_ProxyFetcher.HOSTNAME:
                Driverless_ProxyFetcher.HOSTNAME = self.extract_common_name(ssl._ssl._test_decode_cert(self.getConfig("driverless_proxy_servercert")))
            self.context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=self.getConfig("driverless_proxy_servercert"))
            self.context.load_cert_chain(certfile=self.getConfig("driverless_proxy_cert"), keyfile=self.getConfig("driverless_proxy_key"))
            self.context.verify_mode = ssl.CERT_REQUIRED
            self.context.load_verify_locations(cafile=self.getConfig("driverless_proxy_servercert"))
        except IOError as e:
            raise IOError('driverless_proxy: Unable to locate certificate files. Have you correctly configured the servercert, cert, and key?')
        self.configurable = self.__dict__["getConfig"].__self__
        self.timeout = float(self.getConfig("connect_timeout", 60))

    def extract_common_name(self, data):
        common_names = []
        logger.debug("Extracting: %s"%data)

        def recursive_extract(item):
            if isinstance(item, tuple):
                if item[0] == 'commonName':
                    common_names.append(item[1])
                for sub_item in item:
                    recursive_extract(sub_item)
            elif isinstance(item, list):
                for sub_item in item:
                    recursive_extract(sub_item)
            elif isinstance(item, dict):
                for key, value in item.items():
                    recursive_extract(value)
            elif isinstance(item, str):
                return

        if 'subject' in data:
            recursive_extract(data['subject'])

        return common_names[0]
    
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

        offset_1 = int(offsets[:2])
        status = int(response[:offset_1].decode('utf-8'))

        offset_2 = offset_1 + int(offsets[2:4])
        ctype = response[int(offset_1):int(offset_2)].decode('utf-8')

        offset_1 = offset_2 + int(offsets[4:13])
        if offset_2 >= offset_1:
            raise IndexError("offset is invalid. of1[%s], of2[%s]"%(offset_1,offset_2))
        source = response[int(offset_2):offset_1]
        source = base64.b64decode(source.decode('utf-8'))

        offset_2 = offset_1 + int(offsets[13:18])
        if offset_2 != len(response) or offset_1 >= offset_2:
            raise IndexError("offset is invalid. of1[%s], of2[%s], len[%s]"%(offset_1,offset_2,len(response)))
        cookies = (response[int(offset_1):offset_2]).decode('utf-8')

        return {"content-type": ctype, "content": source, "status_code": status, "cookies": cookies}

    def encode(self, packet):
        encoded_packet = (json.dumps(packet)).encode("utf-8")
        checksum = sha256(encoded_packet).digest()
        b64_checksum = base64.b64encode(checksum)
        b64_packet = base64.b64encode(encoded_packet)
        packet = b64_checksum + b64_packet + b'\0'
        return packet

    def get_session(self):
        session_name = self.getConfig("driverless_proxy_session")
        slow = self.getConfig("slow_down_sleep_time")
        for cookie in self.get_cookiejar():
            if cookie.name == '__DriverlessSession__':
                self.session = cookie
                return cookie.value
        else:
            cookie = Cookie(
                version=0, name='__DriverlessSession__', value=('S' + str(session_name if session_name else randint(1000, 9999))),
                domain='example.com', path='/', port=str(0), port_specified=True, domain_specified=True,  domain_initial_dot=False,
                path_specified=True, secure=False, expires=str(slow if slow else 1), discard=False, comment=None, comment_url=None, rest={'HttpOnly': True}
            )
            self.cookiejar.set_cookie(cookie)
            self.session = cookie
            return cookie.value

    def get_cookies(self):
        cookies = []
        if self.cookiejar is None:
            return cookies
        logger.debug(len(self.cookiejar))
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

    def is_image(self):
        for call in inspect.stack():
            if call[3] == 'addImgUrl':
                return'True'
        return 'False'

    def save_cookies(self, cookies):
        cookies_dict = json.loads(cookies)
        for x in cookies_dict:
            cookie_dict = cookies_dict[x]
            cookie = Cookie(version=0, name=str(cookie_dict["name"]), value=str(cookie_dict["value"]), port=None, port_specified=False,
                domain=str(cookie_dict["domain"]), domain_specified=True, domain_initial_dot=cookie_dict["domain"].startswith('.'),
                path=str(cookie_dict["path"]), path_specified=True if cookie_dict["path"] else False,
                secure=cookie_dict["secure"], expires=str(cookie_dict["expires"]), discard=False,
                comment=None, comment_url=None, rest={},
            )
            self.get_cookiejar().set_cookie(cookie)

    def raise_for_status(self, url, response):
        if 300 > response['status_code'] >= 200:
            return
        
        if response["status_code"] in {-400, -1}:
            raise exceptions.FailedToDownload("Failed to fetch %s. [%s]" % (url, response["content-type"]))

        if response['status_code'] in Driverless_ProxyFetcher.CLOUDFLARE_CODES:
            http_error_msg = "%s Server Error: %s for url: %s" % (response['status_code'], Driverless_ProxyFetcher.CLOUDFLARE_CODES[response['status_code']], url)
        else:
            if 400 <= response["status_code"] < 500:
                http_error_msg = u'%s Client Error. For url: %s' % (response['status_code'], url)
            elif 500 <= response["status_code"] < 600:
                http_error_msg = u'%s Server Error. For url: %s' % (response['status_code'], url)

        if http_error_msg:
            raise exceptions.HTTPErrorFFF(url, response["status_code"], http_error_msg, response["content"])
        raise exceptions.FailedToDownload("We aren't suppose to be here %s"%url)

    def cooldown(self, status_code):
        retries = int(self.session.port)
        if status_code != 429:
            if retries <= 0:
                return
            retries -= 1
            if retries == 0:
                self.configurable.set_sleep_override(float(self.session.expires))
            else:
                sleep_time = (4*3**retries)
                logger.debug("New sleep %s"%sleep_time)
                self.configurable.set_sleep_override(sleep_time)
        elif status_code == 429 and retries < 5:
            sleep_time = int(4*2**(retries/0.75))
            logger.debug("New sleep %s"%sleep_time)
            retries += 1
            self.configurable.set_sleep_override(sleep_time)

        self.session.port = str(retries)
        self.cookiejar.set_cookie(self.session)

    def recv_req(self, s):
        chunks = []
        prev_tail = b""
        end_marker = b"\xFF\x00\x00\x00"
        while True:
            chunk = s.recv(Driverless_ProxyFetcher.CHUNK_SIZE)
            if not chunk:
                logger.debug('No data received, closing socket.')
                break
            chunks.append(chunk)

            if end_marker in (prev_tail + chunk):
                logger.debug("End of data received.")
                break
            # Update prev_tail to the last len(end_marker)-1 bytes of current chunk.
            prev_tail = chunk[-(len(end_marker) - 1):]

        return chunks

    def request(self, method, url, headers=None, parameters=None):
        if method not in ('GET','POST'):
            raise NotImplementedError()
        logger.debug(make_log('driverless_ProxyFetcher', method, url, hit='REQ', bar='-'))

        headers.pop('User-Agent', None)
        packet_dict = {'method': method, 'url': url, 'headers': json.dumps(headers), 'parameters': json.dumps(parameters), 'image': self.is_image(), 'cookies': json.dumps(self.get_cookies()), 'session': str(self.get_session()), 'heartbeat': str(self.timeout*0.5)}
        packet = self.encode(packet_dict)

        with SSLConnection(context=self.context, hostname=Driverless_ProxyFetcher.HOSTNAME, address=self.getConfig("driverless_proxy_address", "localhost"), port=int(self.getConfig("driverless_proxy_port", 23000))) as s:
            s.sendall(packet)

            s.settimeout(self.timeout)
            logger.debug("Receive the response from the server. Timeout(%s)"%str(self.timeout))
            while True:
                chunks = self.recv_req(s)
                data = b"".join(chunks)

                response = self.decode(data)
                if response["status_code"] == -400:
                    logger.debug("Keep Alive")
                    continue
                break

        if response["cookies"] != "None":
            self.save_cookies(response["cookies"])
        self.cooldown(response["status_code"])

        self.raise_for_status(url, response)
        return FetcherResponse(response["content"], url, False)
