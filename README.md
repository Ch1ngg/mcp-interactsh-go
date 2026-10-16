# mcp-interactsh-go

**[English](#english) · [简体中文](#简体中文)**

---

<a id="english"></a>

## English

A Go port of [tachote/mcp-interactsh](https://github.com/tachote/mcp-interactsh): exposes [ProjectDiscovery's interactsh](https://github.com/projectdiscovery/interactsh) as a [Model Context Protocol](https://modelcontextprotocol.io/) server, with **three transports (stdio / Streamable HTTP / legacy HTTP+SSE)**, **bearer-token protection** and **proxy support** built in.

Single static binary, zero runtime dependencies.

### Features

- **Session provisioning** — generates RSA-2048 key pairs, registers with any interactsh server (public fleet or self-hosted), returns ready-to-use callback domains.
- **Polling & decryption** — retrieves encrypted interaction data and decrypts it locally (RSA-OAEP-SHA256 unwrapped AES key + AES-256-CTR payloads, with an AES-256-CFB fallback for older fleets; verified against the live oast.pro fleet).
- **Lifecycle management** — list cached sessions, deregister when done.
- **Three transports**
  - `stdio` — for Claude Code / Cursor / Codex and any local MCP client.
  - `http` — Streamable HTTP (`POST /mcp`), MCP 2025-03-26+.
  - `sse` — legacy HTTP+SSE (`GET /sse` + POST back to the advertised endpoint), MCP 2024-11-05.
  - `http+sse` — both HTTP flavors on one listener.
- **Token protection** — `--token` requires `Authorization: Bearer <token>` (raw token or `X-Api-Key` also accepted) on every HTTP/SSE endpoint. Constant-time compared.
- **Proxy support** — `--proxy` / `INTERACTSH_PROXY` (HTTP or SOCKS5) for all outbound interactsh traffic, falling back to `HTTPS_PROXY` / `HTTP_PROXY` / `NO_PROXY`; **plus a per-session `proxy` argument on `create_interactsh_session`** so one tool call can use a different egress without touching anything else.

### Tools

| Tool | Description |
|------|-------------|
| `create_interactsh_session` | Register a new session. Optional `proxy` argument overrides the outbound proxy for this session only. Returns `correlation_id`, `secret_key`, `private_key_pem`, `callback_domain`, `server_url`, probe instructions and a `sample_probe_host`. |
| `list_interactsh_sessions` | List all sessions cached in this process. |
| `poll_interactsh_session` | Fetch + decrypt interactions. Optional filters: `method`, `path_contains`, `query_contains`, `protocol`, `text_contains`. |
| `deregister_interactsh_session` | Deregister server-side and drop the local cache entry. |

Probing rules (identical to the Node bridge): build the host as `<correlation_id><nonce13>.<domain>` — 20 lowercase hex chars + exactly 13 lowercase alphanumeric chars. Requests to `<correlation_id>.<domain>` without a nonce are ignored by interactsh.

### Install

```bash
# from source (Go 1.24+)
go install github.com/Ch1ngg/mcp-interactsh-go@latest

# or grab a prebuilt binary from Releases (built by GitHub Actions)
# https://github.com/Ch1ngg/mcp-interactsh-go/releases
```

### Usage

```bash
# stdio (default) — for local MCP clients
mcp-interactsh-go

# Streamable HTTP + legacy SSE on one listener, protected by a token
mcp-interactsh-go --transport http+sse --addr 0.0.0.0:8080 --token s3cret

# custom interactsh server + auth + outbound proxy
mcp-interactsh-go --base-url https://oast.fun --interactsh-token xxx \
                  --proxy socks5://127.0.0.1:1080
```

#### Flags & environment

| Flag | Env | Default | Description |
|------|-----|---------|-------------|
| `--base-url` | `INTERACTSH_BASE_URL` | `https://oast.pro` | interactsh server base URL. |
| `--domain-suffix` | `INTERACTSH_DOMAIN_SUFFIX` | host of base URL | Callback domain suffix. |
| `--interactsh-token` | `INTERACTSH_TOKEN` | _(empty)_ | Authorization token sent to the interactsh server (raw header, no Bearer). |
| `--proxy` | `INTERACTSH_PROXY` | _(empty)_ | HTTP/SOCKS5 proxy for outbound interactsh traffic. Empty → `HTTPS_PROXY`/`HTTP_PROXY`/`NO_PROXY` env chain. |
| `--transport` | `MCP_TRANSPORT` | `stdio` | `stdio` \| `http` \| `sse` \| `http+sse`. |
| `--addr` | `MCP_ADDR` | `:8080` | Listen address for `http`/`sse`. |
| `--token` | `MCP_TOKEN` / `MCP_AUTH_TOKEN` | _(empty)_ | Bearer token required by the HTTP/SSE endpoints (empty = no auth). `/healthz` stays open for probes. |
| `--version` | — | — | Print version and exit. |

#### Claude Code (stdio)

```json
{
  "mcpServers": {
    "interactsh": {
      "command": "mcp-interactsh-go",
      "env": {
        "INTERACTSH_BASE_URL": "https://oast.pro"
      }
    }
  }
}
```

Or: `claude mcp add interactsh -- mcp-interactsh-go`

#### Cursor / any Streamable HTTP client

```json
{
  "mcpServers": {
    "interactsh": {
      "url": "http://your-host:8080/mcp",
      "headers": { "Authorization": "Bearer s3cret" }
    }
  }
}
```

#### Legacy HTTP+SSE client

Endpoint: `http://your-host:8080/sse` (same `Authorization: Bearer` header).

#### Codex (TOML)

```toml
[mcp_servers.interactsh]
command = "mcp-interactsh-go"
args = []
env = { INTERACTSH_BASE_URL = "https://oast.pro" }
```

### Proxy notes & avoiding conflicts between multiple MCP plugins

`HTTP_PROXY`/`HTTPS_PROXY` are **process-scoped** environment variables. Conflicts between plugins only happen when the plugins share a process or share a shell rc file. The reliable patterns:

1. **Per-server env in the MCP config** — each `mcpServers` entry spawns its own process with its own `env` block; set the proxy there, not in `~/.zshrc`.
2. **App-specific variable names** — this server reads `INTERACTSH_PROXY` first, so a global `HTTPS_PROXY` meant for a *different* plugin never hijacks interactsh traffic (and vice versa).
3. **Precedence is explicit and documented** — flag `--proxy` > `INTERACTSH_PROXY` > `HTTPS_PROXY`/`HTTP_PROXY` env > direct.
4. **Per-session override** — `create_interactsh_session` accepts a `proxy` argument: one session egresses through proxy A, the next through proxy B, same process, zero interference. This is the cleanest fix when one agent runs tools that need different egresses.
5. **`NO_PROXY` carve-outs** — add `127.0.0.1,localhost,::1` when a plugin's proxy is another local plugin (e.g. a local mitm/Burp MCP), so loopback traffic stays direct.
6. **Containers/units as isolation boundaries** — one MCP server per container or systemd unit, each with its own `Environment=`, when you want hard isolation.

### Build & CI

```bash
go build -trimpath -ldflags "-s -w -X main.version=1.2.3" -o mcp-interactsh-go .
go test -race ./...
```

GitHub Actions (`.github/workflows/`):

- `build.yml` — on every push/PR: gofmt check, `go vet`, `go test -race` (Linux/macOS/Windows matrix), a stdio smoke test that lists tools, artifact upload.
- `release.yml` — on `v*` tags: cross-compiles `linux/{amd64,arm64}`, `darwin/{amd64,arm64}`, `windows/amd64`, attaches tarballs/zips + SHA-256 checksums to a GitHub Release.

### Credits

- [ProjectDiscovery interactsh](https://github.com/projectdiscovery/interactsh) — the OOB testing platform.
- [tachote/mcp-interactsh](https://github.com/tachote/mcp-interactsh) — the original Node.js MCP bridge this project ports to Go.
- [modelcontextprotocol/go-sdk](https://github.com/modelcontextprotocol/go-sdk) — the official Go MCP SDK.

License: MIT (see [LICENSE](LICENSE)).

---

<a id="简体中文"></a>

## 简体中文

[tachote/mcp-interactsh](https://github.com/tachote/mcp-interactsh) 的 Go 移植版:把 [ProjectDiscovery 的 interactsh](https://github.com/projectdiscovery/interactsh) 封装成 [MCP](https://modelcontextprotocol.io/) 服务器,内置**三种传输(stdio / Streamable HTTP / 传统 HTTP+SSE)**、**Token 鉴权**和**代理支持**。

单一静态二进制,无任何运行时依赖。

### 功能

- **会话开通** — 生成 RSA-2048 密钥对,向任意 interactsh 服务器(公共集群或自建)注册,返回可直接使用的回调域名。
- **轮询与解密** — 拉取加密交互数据并本地解密(RSA-OAEP-SHA256 解包 AES 密钥 + AES-256-CTR 载荷,兼容旧集群的 AES-256-CFB;已在 oast.pro 真实集群上验证)。
- **生命周期管理** — 列出缓存会话、用完注销。
- **三种传输**
  - `stdio` — 供 Claude Code / Cursor / Codex 等本地 MCP 客户端使用。
  - `http` — Streamable HTTP(`POST /mcp`),MCP 2025-03-26+。
  - `sse` — 传统 HTTP+SSE(`GET /sse`,再向通告的端点 POST),MCP 2024-11-05。
  - `http+sse` — 一个监听器同时提供两种 HTTP 传输。
- **Token 保护** — `--token` 开启后,所有 HTTP/SSE 端点都要求 `Authorization: Bearer <token>`(裸 token 或 `X-Api-Key` 也可以),常数时间比较。
- **代理支持** — `--proxy` / `INTERACTSH_PROXY`(HTTP 或 SOCKS5)作用于全部出站流量,缺省回落到 `HTTPS_PROXY` / `HTTP_PROXY` / `NO_PROXY`;此外 **`create_interactsh_session` 支持 `proxy` 参数做单会话覆盖**,一次调用单独走一个出口,互不干扰。

### 工具

| 工具 | 说明 |
|------|------|
| `create_interactsh_session` | 注册新会话。可选 `proxy` 参数仅覆盖该会话的出站代理。返回 `correlation_id`、`secret_key`、`private_key_pem`、`callback_domain`、`server_url`、探测指引和 `sample_probe_host`。 |
| `list_interactsh_sessions` | 列出本进程缓存的所有会话。 |
| `poll_interactsh_session` | 拉取并解密交互事件。可选过滤:`method`、`path_contains`、`query_contains`、`protocol`、`text_contains`。 |
| `deregister_interactsh_session` | 服务端注销并删除本地缓存。 |

探测规则(与 Node 版一致):主机名拼成 `<correlation_id><nonce13>.<domain>` —— 20 位小写十六进制 + 恰好 13 位小写字母数字。不带 nonce 的 `<correlation_id>.<domain>` 请求会被 interactsh 忽略。

### 安装

```bash
# 源码安装(Go 1.24+)
go install github.com/Ch1ngg/mcp-interactsh-go@latest

# 或直接下载 Releases 里由 GitHub Actions 编译好的二进制
# https://github.com/Ch1ngg/mcp-interactsh-go/releases
```

### 使用

```bash
# stdio(默认)— 本地 MCP 客户端
mcp-interactsh-go

# 一个监听器同时提供 Streamable HTTP + 传统 SSE,Token 保护
mcp-interactsh-go --transport http+sse --addr 0.0.0.0:8080 --token s3cret

# 自定义 interactsh 服务器 + 鉴权 + 出站代理
mcp-interactsh-go --base-url https://oast.fun --interactsh-token xxx \
                  --proxy socks5://127.0.0.1:1080
```

#### 参数与环境变量

| 参数 | 环境变量 | 默认值 | 说明 |
|------|----------|--------|------|
| `--base-url` | `INTERACTSH_BASE_URL` | `https://oast.pro` | interactsh 服务器地址。 |
| `--domain-suffix` | `INTERACTSH_DOMAIN_SUFFIX` | base URL 的主机名 | 回调域名后缀。 |
| `--interactsh-token` | `INTERACTSH_TOKEN` | _(空)_ | 发给 interactsh 服务器的 Authorization token(裸头,无 Bearer 前缀)。 |
| `--proxy` | `INTERACTSH_PROXY` | _(空)_ | 出站代理(HTTP/SOCKS5)。为空则走 `HTTPS_PROXY`/`HTTP_PROXY`/`NO_PROXY` 环境变量链。 |
| `--transport` | `MCP_TRANSPORT` | `stdio` | `stdio` \| `http` \| `sse` \| `http+sse`。 |
| `--addr` | `MCP_ADDR` | `:8080` | `http`/`sse` 的监听地址。 |
| `--token` | `MCP_TOKEN` / `MCP_AUTH_TOKEN` | _(空)_ | HTTP/SSE 端点的 Bearer Token(空 = 不鉴权)。`/healthz` 保持开放供探活。 |
| `--version` | — | — | 打印版本退出。 |

#### Claude Code(stdio)

```json
{
  "mcpServers": {
    "interactsh": {
      "command": "mcp-interactsh-go",
      "env": {
        "INTERACTSH_BASE_URL": "https://oast.pro"
      }
    }
  }
}
```

或者:`claude mcp add interactsh -- mcp-interactsh-go`

#### Cursor / 任意 Streamable HTTP 客户端

```json
{
  "mcpServers": {
    "interactsh": {
      "url": "http://your-host:8080/mcp",
      "headers": { "Authorization": "Bearer s3cret" }
    }
  }
}
```

#### 传统 HTTP+SSE 客户端

端点:`http://your-host:8080/sse`(同样带 `Authorization: Bearer` 头)。

#### Codex(TOML)

```toml
[mcp_servers.interactsh]
command = "mcp-interactsh-go"
args = []
env = { INTERACTSH_BASE_URL = "https://oast.pro" }
```

### 代理说明:多个 MCP 插件都要代理时怎么避免冲突

`HTTP_PROXY`/`HTTPS_PROXY` 是**进程级**环境变量。插件之间会冲突的唯一场景,是它们共享同一个进程或同一个 shell 配置文件。可靠的套路:

1. **在 MCP 配置里给每个 server 单独配 env** — 每个 `mcpServers` 条目都是独立进程、独立 `env` 块;代理写在那里,别写进 `~/.zshrc`。
2. **应用专属变量名** — 本服务优先读 `INTERACTSH_PROXY`,别的插件的全局 `HTTPS_PROXY` 抢不走 interactsh 的流量(反向同理)。
3. **优先级明确** — `--proxy` > `INTERACTSH_PROXY` > `HTTPS_PROXY`/`HTTP_PROXY` 环境变量 > 直连。
4. **单会话覆盖** — `create_interactsh_session` 接受 `proxy` 参数:同一进程里,A 会话走代理 A,B 会话走代理 B,零干扰。一个 agent 同时跑多个需要不同出口的工具时,这是最干净的解法。
5. **`NO_PROXY` 挖洞** — 当一个插件的代理是另一个本地插件(比如本地 mitm/Burp MCP)时,加 `127.0.0.1,localhost,::1`,让回环流量保持直连。
6. **容器/systemd 单元做隔离边界** — 每个插件一个容器或一个 unit,各自 `Environment=`,需要硬隔离时用。

### 编译与 CI

```bash
go build -trimpath -ldflags "-s -w -X main.version=1.2.3" -o mcp-interactsh-go .
go test -race ./...
```

GitHub Actions(`.github/workflows/`):

- `build.yml` — 每次 push/PR:gofmt 检查、`go vet`、`go test -race`(Linux/macOS/Windows 矩阵)、stdio 冒烟测试列出工具、上传产物。
- `release.yml` — 打 `v*` 标签时:交叉编译 `linux/{amd64,arm64}`、`darwin/{amd64,arm64}`、`windows/amd64`,把 tar/zip 包和 SHA-256 校验附到 GitHub Release。

### 致谢

- [ProjectDiscovery interactsh](https://github.com/projectdiscovery/interactsh) — OOB 测试平台本体。
- [tachote/mcp-interactsh](https://github.com/tachote/mcp-interactsh) — 本项目移植自它的 Node.js 版。
- [modelcontextprotocol/go-sdk](https://github.com/modelcontextprotocol/go-sdk) — 官方 Go MCP SDK。

许可证:MIT(见 [LICENSE](LICENSE))。
