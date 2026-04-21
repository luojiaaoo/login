# Digest 认证使用说明

## 1. 请求前钩子（`before_request`）

```python
from digest_auth import digest_auth

@server.before_request
def protected_resource():
    def get_user_password(username) -> str | None:
        ...

    # 1) 从请求头中读取 Authorization
    auth_header = request.headers.get('Authorization')

    # 2) 执行 Digest 认证
    username = digest_auth.authenticate(
        auth_header,
        request.method,
        request.path,
        get_user_password,
    )

    # nonce 过期：返回 stale challenge，提示客户端重试
    if username is ...:
        return (
            jsonify(error='Stale nonce, please retry'),
            401,
            {'WWW-Authenticate': digest_auth.generate_challenge(is_stale=True)},
        )

    # 认证失败：返回 401 challenge
    if username is None:
        challenge = digest_auth.generate_challenge()
        return jsonify(error='Authentication required'), 401, {'WWW-Authenticate': challenge}
```

## 2. 获取当前认证用户 ID

```python
from digest_auth import digest_auth

digest_auth.user_id
```
