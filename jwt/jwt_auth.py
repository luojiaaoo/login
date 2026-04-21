import base64
import hashlib
import hmac
import json
import secrets
import time
from flask import request


class JWTAuth:
    def __init__(self, secret: str = 'change-me', expire_seconds: int = 300):
        self.secret = secret.encode('utf-8')
        self.expire_seconds = expire_seconds

    def _b64url_encode(self, raw: bytes) -> str:
        return base64.urlsafe_b64encode(raw).rstrip(b'=').decode('utf-8')

    def _b64url_decode(self, raw: str) -> bytes:
        padding = '=' * (-len(raw) % 4)
        return base64.urlsafe_b64decode(raw + padding)

    def _sign(self, message: bytes) -> str:
        digest = hmac.new(self.secret, message, hashlib.sha256).digest()
        return self._b64url_encode(digest)

    def create_access_token(self, username: str) -> str:
        header = {'alg': 'HS256', 'typ': 'JWT'}
        payload = {'sub': username, 'exp': int(time.time()) + self.expire_seconds}

        header_b64 = self._b64url_encode(json.dumps(header, separators=(',', ':')).encode('utf-8'))
        payload_b64 = self._b64url_encode(json.dumps(payload, separators=(',', ':')).encode('utf-8'))
        signing_input = f'{header_b64}.{payload_b64}'.encode('utf-8')
        signature_b64 = self._sign(signing_input)
        return f'{header_b64}.{payload_b64}.{signature_b64}'

    def verify_access_token(self, token: str) -> str | None:
        try:
            header_b64, payload_b64, signature_b64 = token.split('.')
        except ValueError:
            return None

        signing_input = f'{header_b64}.{payload_b64}'.encode('utf-8')
        expected_signature = self._sign(signing_input)
        if not hmac.compare_digest(signature_b64, expected_signature):
            return None

        try:
            payload = json.loads(self._b64url_decode(payload_b64))
        except Exception:
            return None

        sub = payload.get('sub')
        exp = payload.get('exp')

        if not isinstance(sub, str) or not isinstance(exp, int):
            return None

        if exp < int(time.time()):
            return None

        return sub

    def authenticate(self, auth_header: str | None) -> str | None:
        if not auth_header or not auth_header.startswith('Bearer '):
            return None
        return self.verify_access_token(auth_header[7:])

    def login(self, username: str, password: str, user_auth: dict[str, dict[str, str | None]]) -> dict[str, str] | None:
        user = user_auth.get(username)
        if not user or user.get('password') != password:
            return None

        refresh_token = secrets.token_urlsafe(32)
        user['refresh_token'] = refresh_token
        access_token = self.create_access_token(username)

        return {'access_token': access_token, 'refresh_token': refresh_token}

    def refresh(self, refresh_token: str, user_auth: dict[str, dict[str, str | None]]) -> str | None:
        for username, user in user_auth.items():
            if user.get('refresh_token') == refresh_token:
                return self.create_access_token(username)
        return None

    @property
    def user_id(self) -> str | None:
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return None
        return self.verify_access_token(auth_header[7:])


jwt_auth = JWTAuth()
