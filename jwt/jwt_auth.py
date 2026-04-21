import secrets
from datetime import datetime, timedelta, timezone
from fastapi import Depends, HTTPException, status
from typing import Annotated
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import jwt


# 全局用户数据存储（实际项目中应使用数据库）
USERS: dict[str, dict[str, str | None]] = {
    'alice': {'password': 'alice123'},
    'bob': {'password': 'bob456'},
    'admin': {'password': 'admin789'},
}


security = HTTPBearer()


class JWTAuth:
    def __init__(self, secret: str = 'change-me', expire_seconds: int = 300, refresh_expire_days: int = 30):
        self.secret = secret
        self.expire_seconds = expire_seconds
        self.refresh_expire_days = refresh_expire_days

    def _create_access_token(self, username: str) -> str:
        """使用 PyJWT 创建访问令牌"""
        payload = {
            'sub': username,
            'exp': datetime.now(timezone.utc) + timedelta(seconds=self.expire_seconds),
            'iat': datetime.now(timezone.utc)
        }
        return jwt.encode(payload, self.secret, algorithm='HS256')

    def _decode_access_token(self, token: str) -> dict:
        """解码 JWT 访问令牌，返回 payload"""
        return jwt.decode(token, self.secret, algorithms=['HS256'])

    def get_current_user(self, credentials: Annotated[HTTPAuthorizationCredentials, Depends(security)]) -> str:
        """依赖注入：从 Authorization 头中提取并验证令牌，返回用户名

        Raises:
            HTTPException: 400 格式错误 / 401 令牌过期或无效
        """
        auth_header = credentials.credentials

        if not auth_header:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={"code": "MISSING_AUTH", "message": "缺少 Authorization 请求头"}
            )
        if not auth_header.startswith('Bearer '):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={"code": "INVALID_AUTH_FORMAT", "message": "Authorization 格式错误，应为 Bearer token"}
            )

        token = auth_header[7:]
        try:
            payload = self._decode_access_token(token)
        except jwt.ExpiredSignatureError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={"code": "TOKEN_EXPIRED", "message": "访问令牌已过期"}
            )
        except jwt.InvalidTokenError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={"code": "TOKEN_INVALID", "message": "令牌无效"}
            )

        return payload.get('sub')

    def _verify_credentials(self, username: str, password: str) -> bool:
        """校验用户名和密码"""
        user = USERS.get(username)
        return user is not None and user.get('password') == password

    def login(self, username: str, password: str) -> dict[str, str]:
        """用户登录，验证密码并发放令牌

        Raises:
            HTTPException: 401 用户名或密码错误
        """
        if not self._verify_credentials(username, password):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={"code": "INVALID_CREDENTIALS", "message": "用户名或密码错误"}
            )
        refresh_token = secrets.token_urlsafe(32)
        USERS[username]['refresh_token'] = refresh_token
        USERS[username]['refresh_exp'] = datetime.now(timezone.utc) + timedelta(days=self.refresh_expire_days)
        access_token = self._create_access_token(username)
        return {'access_token': access_token, 'refresh_token': refresh_token}

    def refresh(self, username: str, refresh_token: str) -> str:
        """使用刷新令牌获取新的访问令牌

        Raises:
            HTTPException: 401 用户名/token 错误或 refresh_token 过期
        """
        user = USERS.get(username)
        if not user or user.get('refresh_token') != refresh_token:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={"code": "INVALID_REFRESH_TOKEN", "message": "用户名或 refresh_token 错误"}
            )

        refresh_exp = user.get('refresh_exp')
        if refresh_exp and refresh_exp < datetime.now(timezone.utc):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={"code": "REFRESH_TOKEN_EXPIRED", "message": "登录已过期，请重新登录"}
            )

        return self._create_access_token(username)


jwt_auth = JWTAuth()
