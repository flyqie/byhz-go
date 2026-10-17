# 鲍鱼盒子 直播 Web 观看端（Go）

对 `co.rjm1tdo8oef0`（鲍鱼盒子 5.0.0）直播链路的 Go 重写版：
游客/会员登录、热门/平台/搜索房间列表、房间详情、Agora / yunceng / 小奶猫 / HLS
四种播放路线，以及一个嵌在二进制里的单页 Web 前端。

整个项目只依赖 Go 标准库（AES-CBC、HTTP、TLS、embeded 静态资源、WebSocket 帧、
protobuf 编码都是手写的），不需要 CGO，也不需要 Python 或模拟器。

## 项目结构

```
byhz-go/
├── cmd/byhz/main.go             # 入口
├── go.mod
├── internal/
│   ├── config/config.go         # 环境变量配置
│   ├── backend/backend.go       # App 自有 API：签名、AES、登录、房间接口、域名发现
│   ├── playback/playback.go     # 播放参数解析 + Agora token 缓存 + 小奶猫
│   ├── kiwi/
│   │   ├── kiwi.go              # libkiwi 复刻：appkey/节点/route/隧道
│   │   ├── rabbit.go            # Rabbit 流密码（逐字移植 Java 实现）
│   │   └── agora.go             # native Agora token：Rabbit + protobuf + WebSocket
│   └── server/server.go         # HTTP 服务、relay、静态资源
└── web/
    ├── embed.go                 # //go:embed index.html css js
    ├── index.html               # 页面骨架
    ├── css/style.css            # 样式（深色播放器 UI）
    └── js/
        ├── app.js               # 前端逻辑（房间列表 / 会员 / HLS / FLV / Agora）
        └── vendor/              # 本地 hls.min.js / mpegts.min.js
```

## 构建与运行

```bash
cd byhz-go
go build -o byhz.exe ./cmd/byhz
# Windows
set APP_PID=29320397
set PROXY=http://127.0.0.1:10809
byhz.exe
# Linux/macOS
APP_PID=29320397 ./byhz
```

打开 <http://127.0.0.1:8000>。

交叉编译：

```bash
GOOS=linux   GOARCH=amd64 go build -o byhz-linux   ./cmd/byhz
GOOS=windows GOARCH=amd64 go build -o byhz.exe     ./cmd/byhz
GOOS=darwin  GOARCH=arm64 go build -o byhz-darwin  ./cmd/byhz
```

## 配置（环境变量）

| 变量 | 说明 | 默认 |
|---|---|---|
| `API_BASE` | 自有后端根地址，例如 `https://api.example.com` | 空（DoH 自动发现） |
| `APP_PID` | 游客登录的 `pid`（App 里取自 APK ZIP comment，即邀请码） | `0` |
| `APP_DEVICE` | 设备号 | 随机生成 |
| `APP_TOKEN` | 已有 token（形如 `Bearer eyJ...`），设置后跳过游客登录 | 空 |
| `APP_AES_IV` | 接口 AES 的 IV（16 字符） | 密钥常量前 16 位 |
| `APP_UA` | 请求自有后端的 User-Agent | `Dart/3.5 (dart:io)` |
| `RELAY_UA` | relay 拉流时的 User-Agent | `okhttp/4.8.0` |
| `PROXY` | 可选。自有 API、域名发现、小奶猫接口使用的代理，例如 `http://127.0.0.1:10809` | 空（使用系统 `HTTP(S)_PROXY`，没有则直连） |
| `RELAY_PROXY` | 可选。`/api/proxy` 拉流使用的代理；不设置则**直连**，失败时自动回退另一条路径 | 空（直连） |
| `HOST` / `PORT` | 监听地址/端口 | `127.0.0.1` / `8000` |

地址发现顺序：

1. 设置了 `API_BASE` 时直接使用；
2. 并发查询 DoH TXT `bydoh.h8ghweg.com`（Cloudflare / Google / 阿里 / 腾讯等）；
3. 并发拉取 jsDelivr npm 包 `6vd-pub-api1` / `6vd-pub-api2` 最新版本的
   `info.json`，用内置 `apiDecrypt` 解出 `bbs_site`；
4. 依次用 `tourist_login` 试探，第一个登录成功的地址作为 API 根地址。

也可以在页面顶部手动填写 API 地址后保存。

## 接口

| 路径 | 方法 | 说明 |
|---|---|---|
| `/` | GET | 播放器页面（内嵌，`Cache-Control: no-store`） |
| `/api/status` | GET | 当前 API 地址、登录状态、设备号 |
| `/api/base` | POST | `{base}`，保存/自动发现 API 地址并重新登录 |
| `/api/relogin` | POST | 强制重新游客登录 |
| `/api/member_login` | POST | `{kind, account, password}`，会员登录 |
| `/api/logout` | POST | 退出会员，切回游客 |
| `/api/session` | GET | 当前会话 |
| `/api/plats` | GET | 平台列表 |
| `/api/rooms` | GET | 热门/平台房间列表（`page` `page_size` `plat_id` `room_type`） |
| `/api/search` | GET | 搜索房间（`key` `page` `page_size`） |
| `/api/gentoken` | GET | gentoken 摘要（appkey 是否存在、版本等） |
| `/api/room` | GET | 房间详情并解析播放参数（`room_id` `plat_id` `pwd`） |
| `/api/proxy` | GET | 拉流 relay（`url`，支持 m3u8 改写与 Range） |

`/api/room` 返回的 `mode` 为 `agora` / `hls` / `unsupported`。
Agora 房间直接返回浏览器 Agora Web SDK 所需的 `appId/token/channelId/uid`。

## 播放路线

房间详情 `LivePlayModel` 由 `encrypt_type / yunceng / encrypt` 决定：

- **Agora 直连**（`encrypt_type == "agora"`）：取 `agora_play_info`，
  缺字段回退到 `encrypt_ext`，浏览器以 audience 身份加入频道。
- **yunceng**：纯 Go 复刻的 libkiwi 打开 `kiwi_live` 隧道，
  走 `AgoraPlayManager` 的原生流程自动拿 Agora token：
  - `POST /go/<encryptPath("login/quick")>?z=1&nobase64=1`
    （Rabbit 流密码 + `LoginQuickRequest` protobuf）拿 `jwt_token/user_id`；
  - WebSocket `/go/<encryptPath("/ws/chat")>?z=1&nobase64=1`，
    `/login/init` → `/stream/generate_agora_token`。
  **不需要手动填写 token。**
- **小奶猫 XNM**：带 `X-Live-Butter2 / knockknock / X-Live-Pretty /
  x-accept-puzzle` 请求 `encrypt_ext.reqUrl`，响应为
  `base64(AES-128-CBC)`，key = `md5(token)[0:16]`、iv = `md5(token)[16:32]`
  （token 取 `encrypt_ext.token`，与 URL 无关），解出 `data.stream.pull_url`。
  `pull_url` 是 `rtmp://` 时自动改写成同路径的 `https://…flv`（腾讯云/阿里云
  风格 CDN 均支持），交给 mpegts.js 播放。
- **通用 HLS/FLV**：使用 `play_url`，经本地 `/api/proxy` relay：
  m3u8 内的相对地址、`#EXT-X-KEY`、`#EXT-X-MAP`、`#EXT-X-MEDIA` 都会改写；
  URL 不以 `.m3u8` 结尾时会嗅探响应开头的 `#EXTM3U`，仍然按播放列表改写；
  分片流式转发，透传 Range / Content-Range / Accept-Ranges 等响应头。
  `rtmp://` 的 `play_url` 同样会改写为 HTTPS-FLV。

## 错误与重试

- 上游网络错误（连接失败、超时、连接重置）自动重试 3 次；
- 上游 429/502/503/504 自动重试；
- 上游 `code 1035 / 1009`（登录失效）或 `400/401/403` 会自动重新登录并重试一次；
  会员账号密码只保存在进程内存中用于自动重登，退出登录即清除；
- 所有上游错误统一返回 HTTP 502 + `{"detail": "..."}`，不会出现无信息的 500；
- 常见上游 code：
  - `1003 观看次数不足`：游客观看配额用尽，登录会员账号；
  - `1000 获取数据失败:code != 200`：上游平台拉取房间失败（平台侧不可用）；
  - `1001 参数错误`：上游参数校验失败（房间下线/接口变动）。

## 与 Python 版的关系

协议细节与 `../kiwi`（Python 复刻的 libkiwi）一致：

- appkey：`base64(AES-128-CBC(JSON))`；
- 节点：`#H#/#D#/#M#/#Rnn#` 占位符 + `md5(tag)` 替换 `#KIWIKEY#`；
- API 路由：56 字节 type=2，`sdkver` 必须为 `A521`，数据与 `route[18]` 单字节 XOR；
- 服务路由：响应里的 type=4 route，隧道握手 16 字节后双向 XOR；
- Rabbit 流密码、`encryptPath`、protobuf 结构与 Android 端一致。

`IntSecret` 的端口混淆（`encode_port` / `decode_port`）也已实现，Go 里主要作为
协议完整性保留（当前服务端不需要本地监听端口）。

## 已知限制

- **观看次数配额**：游客账号在服务端有观影次数限制，房间详情可能返回
  “观看次数不足”。这是服务端策略，登录会员账号可解除。
- **Agora token 有效期**：native 流程生成的 token 在进程内缓存 10 分钟，
  游客登录缓存 30 分钟；失效后重新进入房间即可。
- **yunceng 服务端拒绝**：`kiwi_live` 的 `login/quick` 可能返回
  “未知错误”（例如短时间内大量登录触发风控）。此时房间会以
  `mode=unsupported` 返回原因，换时间或换设备重试即可。
- **RTMP-only 源**：极少数 CDN 不提供 HTTP-FLV/HLS 变体，浏览器无法播放，
  需要在服务端做 RTMP→FLV 转封装。
- **前端 CDN**：`js/app.js` 只在进入 Agora 房间时从 jsDelivr 懒加载
  `agora-rtc-sdk-ng@4.20.0`；hls.js / mpegts.js 已内置在 `web/js/vendor/`，
  CDN 不可达时 Agora 房间无法播放，HLS/FLV 不受影响。
- **仅供本机**：relay 会代理任意 http/https URL（已拒绝 localhost），
  不要把服务绑定到 `0.0.0.0` 或暴露到公网。
