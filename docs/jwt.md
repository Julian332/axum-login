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

1. **提取 token** — `extract_token()`：先查 cookie `auth.access`，缺失则退回
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
  `Set-Cookie: auth.access=…; Path=/; HttpOnly; SameSite=Lax; Max-Age=<ttl>`
  （`with_secure(true)` 时追加 `Secure`）。
- **Clear** → 写 `Max-Age=0` 过期 cookie。
- **无标记，但 token 剩余寿命 ≤ 1/3** → 滑动刷新（见下）自动重签。
- 其余 → 原样返回。

### 滑动刷新（sliding refresh）

默认开启。当解码出有效 token 且其剩余寿命 ≤ 总寿命的 1/3 时，即使本次请求没有
`login`/`logout`，中间件也会用当前用户重签一份新 cookie。这样活跃会话不必重新登录
即可续期，而闲置的 token 仍会到期失效。

- 判定用 token 自带的 `iat`/`exp`（`3 × 剩余 ≤ iat..exp 总寿命`），不依赖 `ttl`。
- 显式 `login`（Issue）/`logout`（Clear）**优先**于滑动刷新。
- 关闭：`JwtConfig::from_secret(..).with_sliding_refresh(false)`。

## F. 完整时序 · 一次登录 + 一次访问

```
① POST /login  （无 token）
   JwtManager  extract→无 · decode→None · AuthSession(user=None)
   handler     authenticate(creds)→user · login(user) → 标记 Issue
   JwtManager  pending=Issue · encode · Set-Cookie: auth.access=eyJ…
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

## 刷新令牌（refresh token）

默认关闭，`with_refresh_enabled(true)` 开启。开启后：

- `login()` 除签发短期 **access token**（cookie `auth.access`，`Path=/`）外，
  额外签发长期 **refresh token**（cookie `auth.refresh`，`Path` 由
  `with_refresh_path` 设置，如 `/auth/refresh`）。两种 token 用 `typ` claim
  （`access` / `refresh`）区分，互相不可冒用。
- 因为 refresh cookie 带 `Path` 作用域，浏览器**只在刷新端点**附带它。普通请求只
  认 access token；access 过期即匿名。
- 命中刷新端点（携带了有效 refresh cookie）时，中间件用 refresh token 认证该请求
  并**一定签发新的 access cookie**（`Path=/`）——**无论随请求带来的 access token
  是否仍然新鲜**，因为「带上了 refresh cookie」本身就代表客户端在请求刷新。刷新
  端点的 handler 只需读 `auth_session.user()` 返回结果即可。
- refresh token 同样有 1/3 续杯：当它进入自身寿命的最后 1/3 时，随该请求一并轮换。
- `logout()` 同时清除 access 与 refresh 两个 cookie。

```rust
let config = JwtConfig::from_secret(b"secret")
    .with_ttl(Duration::from_secs(60))                 // 短 access
    .with_refresh_enabled(true)
    .with_refresh_path("/auth/refresh")                // refresh cookie 作用域
    .with_refresh_ttl(Duration::from_secs(60 * 60 * 24 * 7)); // 长 refresh
```

可运行示例（含 `/auth/refresh` 端点与 curl 演示）见 [`examples/jwt`](../examples/jwt)。

## Feature 与依赖

默认 features 为 `macros-middleware` + `jwt`——**开箱即用的是 JWT 路径，不含
`tower-sessions`**。

```toml
# 默认：JWT + 路由保护宏，无 tower-sessions / tower-cookies
axum-login = "*"

# 需要服务端 session 路径时，显式启用 session
axum-login = { version = "*", features = ["session"] }
```

`session` feature 挂载 `tower-sessions` / `tower-cookies` / `subtle`；不启用它，
这三个依赖就不会进入依赖树。Cargo feature 是「叠加」语义，故用「是否启用
`session`」来决定要不要 session 路径，而非靠 jwt 去删它。

