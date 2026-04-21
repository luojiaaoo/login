import secrets
from datetime import datetime, timedelta, timezone
import jwt


# 全局用户数据存储（实际项目中应使用数据库）
USERS: dict[str, dict[str, str | None]] = {
    'alice': {'password': 'alice123'},
    'bob': {'password': 'bob456'},
    'admin': {'password': 'admin789'},
}


class AuthenticationError(Exception):
    """认证失败异常基类"""
    pass


class AuthFormatError(AuthenticationError):
    """认证格式错误（非 Bearer 格式）"""
    pass


class TokenExpiredError(AuthenticationError):
    """访问令牌已过期，可使用 refresh_token 刷新"""
    pass


class TokenInvalidError(AuthenticationError):
    """令牌无效或已损坏，无法刷新"""
    pass


class RefreshTokenExpiredError(AuthenticationError):
    """refresh_token 已过期，需要重新登录"""
    pass


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

    def authenticate(self, auth_header: str | None) -> str:
        """从 Authorization 头中提取并验证令牌，返回用户名

        Raises:
            AuthFormatError: Authorization 格式错误
            TokenExpiredError: 令牌已过期
            TokenInvalidError: 令牌无效
        """
        if not auth_header:
            raise AuthFormatError("缺少 Authorization 请求头")
        if not auth_header.startswith('Bearer '):
            raise AuthFormatError("Authorization 格式错误，应为 Bearer token")

        token = auth_header[7:]
        try:
            payload = self._decode_access_token(token)
        except jwt.ExpiredSignatureError:
            raise TokenExpiredError("访问令牌已过期")
        except jwt.InvalidTokenError:
            raise TokenInvalidError("令牌无效或已损坏")

        return payload.get('sub')

    def _verify_credentials(self, username: str, password: str) -> bool:
        """校验用户名和密码"""
        user = USERS.get(username)
        return user is not None and user.get('password') == password

    def login(self, username: str, password: str) -> dict[str, str]:
        """用户登录，验证密码并发放令牌

        Raises:
            AuthenticationError: 用户名或密码错误
        """
        if not self._verify_credentials(username, password):
            raise AuthenticationError("用户名或密码错误")
        refresh_token = secrets.token_urlsafe(32)
        USERS[username]['refresh_token'] = refresh_token
        USERS[username]['refresh_exp'] = datetime.now(timezone.utc) + timedelta(days=self.refresh_expire_days)
        access_token = self._create_access_token(username)
        return {'access_token': access_token, 'refresh_token': refresh_token}

    def refresh(self, username: str, refresh_token: str) -> str:
        """使用刷新令牌获取新的访问令牌

        Raises:
            AuthenticationError: 用户名不存在或 refresh_token 不匹配
            RefreshTokenExpiredError: refresh_token 已过期
        """
        user = USERS.get(username)
        if not user or user.get('refresh_token') != refresh_token:
            raise AuthenticationError("用户名或 refresh_token 错误")

        refresh_exp = user.get('refresh_exp')
        if refresh_exp and refresh_exp < datetime.now(timezone.utc):
            raise RefreshTokenExpiredError("登录已过期，请重新登录")

        return self._create_access_token(username)


jwt_auth = JWTAuth()
