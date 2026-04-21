from hashlib import md5
import uuid
import time


class DigestAuth:
    """Digest 认证工具类（框架无关）"""

    def __init__(self, realm: str = "Protected Area", expire_seconds: int = 300):
        self.realm = realm
        self.expire_seconds = expire_seconds
        self.qop = 'auth'

    def generate_challenge(self, is_stale: bool = False) -> str:
        """生成 WWW-Authenticate 挑战头"""
        nonce = uuid.uuid4().hex + ':' + str(int(time.time()))
        challenge = f'Digest realm="{self.realm}", qop="{self.qop}", nonce="{nonce}", algorithm=MD5'
        if is_stale:
            challenge += ', stale=true'
        return challenge

    def _parse_authorization_header(self, auth_header: str) -> dict:
        """解析客户端传来的 Authorization 头"""
        parts = auth_header.split(', ')
        auth_info = {}
        for part in parts:
            if '=' in part:
                key, value = part.split('=', 1)
                auth_info[key.strip()] = value.strip().strip('"')
        return auth_info

    def _compute_digest(self, username: str, password: str, method: str, uri: str, nonce: str, nc: str, cnonce: str, qop: str) -> str:
        """服务器端计算期望的响应摘要"""
        # HA1 = MD5(username:realm:password)
        ha1_str = f'{username}:{self.realm}:{password}'
        ha1 = md5(ha1_str.encode()).hexdigest()

        # HA2 = MD5(method:uri)
        ha2_str = f'{method}:{uri}'
        ha2 = md5(ha2_str.encode()).hexdigest()

        # Response = MD5(HA1:nonce:nc:cnonce:qop:HA2)
        response_str = f'{ha1}:{nonce}:{nc}:{cnonce}:{qop}:{ha2}'
        return md5(response_str.encode()).hexdigest()

    def authenticate(self, auth_header: str | None, method: str, uri: str, get_password_func) -> str | None:
        """
        主认证函数

        :param auth_header: 请求中的 Authorization 头
        :param method: HTTP 方法 (GET, POST 等)
        :param uri: 请求的 URI
        :param get_password_func: 回调函数，根据用户名返回密码
        :return: 认证成功返回用户名，失败返回 None，nonce 过期返回 '...'
        """
        if not auth_header or not auth_header.startswith('Digest '):
            return None

        auth_info = self._parse_authorization_header(auth_header[7:])

        username = auth_info.get('username')
        nonce = auth_info.get('nonce')
        uri_client = auth_info.get('uri', '')
        response = auth_info.get('response')
        nc = auth_info.get('nc', '')
        cnonce = auth_info.get('cnonce', '')
        qop = auth_info.get('qop', '')

        # 1. 检查 URI 是否匹配
        if (i := uri_client.split('?')[0].replace(uri, '')) and not i.startswith('/'):
            return None

        # 2. 检查 nonce 是否过期（5 分钟）
        try:
            timestamp = int(nonce.split(':')[-1])
            if timestamp < int(time.time()) - self.expire_seconds:
                return ...  # nonce 过期
        except (ValueError, IndexError):
            return None

        # 3. 获取用户密码
        password_correct = get_password_func(username)
        if not password_correct:
            return None

        # 4. 计算期望的摘要值
        expected_response = self._compute_digest(
            username, password_correct, method, uri_client, nonce, nc, cnonce, qop
        )

        # 5. 比较摘要
        return username if response == expected_response else None

digest_auth = DigestAuth()
