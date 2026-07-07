# JWT 认证工作流程（feature `jwt`）

请求从 cookie 或 `Authorization: Bearer` 取出自签发的 JWT，验签后直接从 claims
重建用户——**服务端无状态、每请求不查库**。公开 API（`AuthSession`）保持不变，
只需在路由上把 `AuthManagerLayer` 换成 `JwtManagerLayer`。

## A. 分层结构

```
请求  (携带 cookie 或 Bearer token)
  │
  ▼
JwtManager  ── 提取 → 验签 → 重建用户 → 注入 AuthSession
  │
  ▼
你的 handler  (auth_session.user() / login() / logout())
```

对比 session 版的 `CookieManager → SessionManager → AuthManager` 三层加存储，
JWT 版**只有一层、无 SessionStore**。

## B. Token 结构

```
eyJ0eXAiOiJKV1Qi…  .  eyJzdWIiOjEsImV4cCI6…  .  MgJrVUEquh8Z6PO…
└──── Header ────┘     └───── Payload ─────┘     └── Signature ──┘
     HS256              sub · iat · exp · user{}      密钥签名
```

`user{}` 来自 `AuthUser::to_claims()` 的脱敏视图——**密码等敏感字段绝不进入
token**。时效由 `exp` 决定。

## C. 请求进来 · 认证（无状态）

1. **提取 token** — `extract_token()`：先查 cookie `axum-login.jwt`，缺失则退回
   `Authorization: Bearer`。
2. **验签 + 解码** — `config.decode()`：校验签名与 `exp` 过期；无 token / 篡改 /
   过期 → `None`（降级为匿名）。
3. **重建用户（不查库）** — `User::from_claims()` 直接反序列化 claims 里的用户，
   **完全不调用 `backend.get_user`**。
4. **注入扩展** — `AuthSession::from_jwt()` 建 `Inner::Jwt` 放入请求扩展；中间件
   保留一个共享句柄供响应阶段使用。
5. **调用 handler** — `auth_session.user()` 即可拿到用户；`login_required!` 等路由
   保护照常工作。

## D. Handler 里 · 只标记意图

cookie 必须在响应阶段写，而 handler 还在请求处理中，所以 `login`/`logout` 在
JWT 模式下**不立即签发**，只在共享的 `Inner::Jwt` 里打标记：

- `login(&user)` → 设置当前用户，标记 `pending = Issue`。
- `logout()` → 取出并清空用户，标记 `pending = Clear`。

因此 `login`/`logout` 的公开签名与行为不变，`Serialize` 约束只落在 `JwtManager`
上，**`AuthSession` 不需新增任何约束**。

## E. 响应出去 · 签发 / 清除 cookie

handler 返回后，中间件通过共享句柄读取标记（`take_pending_cookie()`）：

- **Issue** → `encode(&user)` 签发 JWT →
  `Set-Cookie: axum-login.jwt=…; Path=/; HttpOnly; SameSite=Lax; Max-Age=<ttl>`
  （`with_secure(true)` 时追加 `Secure`）。
- **Clear** → 写 `Max-Age=0` 过期 cookie。
- 无标记 → 原样返回。

## F. 完整时序 · 一次登录 + 一次访问

```
① POST /login  （无 token）
   JwtManager  extract→无 · decode→None · AuthSession(user=None)
   handler     authenticate(creds)→user · login(user) → 标记 Issue
   JwtManager  pending=Issue · encode · Set-Cookie: axum-login.jwt=eyJ…
                                                  ↓ 客户端保存 token

② GET /   （带 cookie 或 Bearer）
   JwtManager  extract→token · decode→验签+exp OK · from_claims→user (不查库)
   handler     user() → Some(ferris) ✓
   JwtManager  pending=None · 原样返回
```

## G. 与 session 版的本质区别

| 维度 | session（原） | JWT（新） |
| --- | --- | --- |
| 身份存储 | 服务端 SessionStore | 客户端 token（cookie / Bearer） |
| 每请求查库 | 是（`get_user`） | **否** |
| 会话校验 | `auth_hash` 常量时间比对（改密码即失效） | 靠 `exp` 过期（改密码不使旧 token 失效） |
| 主动登出 | `flush` 服务端会话 | 仅清 cookie；到 `exp` 前仍有效 |
| 中间件层数 | 3 层 + 存储 | 1 层，无存储 |

## 用法

`User` 类型需实现 `Serialize + Deserialize`，并剔除敏感字段（用 `#[serde(skip)]`
或自定义 `to_claims`）。完整可运行示例见 [`examples/jwt`](../examples/jwt)。

```rust
use axum_login::{JwtConfig, JwtManagerLayer};

let config = JwtConfig::from_secret(b"a-very-secret-key");
let jwt_layer = JwtManagerLayer::new(backend, config);
// let app = Router::new()./* routes */.layer(jwt_layer);
```

> **MSRV**：`jwt` feature 依赖 `jsonwebtoken` 10，要求 Rust ≥ 1.88。

## 只要 JWT，不要 session（去掉 tower-sessions 依赖）

session 路径挂在默认开启的 `session` feature 下。只需 JWT 时，关掉默认 features
即可把 `tower-sessions` / `tower-cookies` / `subtle` 从依赖树移除：

```toml
[dependencies]
axum-login = { version = "*", default-features = false, features = ["jwt"] }
# 需要路由保护宏时再加 "macros-middleware"（它不依赖 tower-sessions）
```

Cargo feature 是「叠加」语义——无法靠「启用 jwt 自动删掉 session」，只能通过关闭
`session` feature 来去掉。两者都要时用 `features = ["session", "jwt"]`。

