# sakichat —— C++ WebSocket 聊天室

从零实现的类 QQ 聊天项目：**C++ epoll 服务端 + HTML/JS WebSocket 前端**，不依赖 Qt。

## 技术栈

| 层级 | 技术 |
|------|------|
| 服务端 | C++17 + epoll 非阻塞 I/O + WebSocket(RFC 6455) |
| 前端 | 纯 HTML/CSS/JS（WebSocket API） |
| 依赖 | OpenSSL（仅用于握手时算 SHA1） |

## 目录结构

```
sakichat/
├── server/
│   ├── websocket.h   # WebSocket 协议层：握手 / 帧解析 / 帧打包
│   ├── main.cpp      # epoll 服务端：登录 / 群聊 / 私聊 / 在线列表
│   └── Makefile
├── client/
│   └── index.html    # 前端页面（浏览器直接打开）
└── README.md
```

## 编译运行

> 需要 Linux/WSL 环境（epoll + POSIX socket），并安装 libssl-dev：
> `sudo apt install g++ make libssl-dev`

```bash
cd server
make
./sakichat_server
```

然后浏览器打开 `client/index.html`（或 `python3 -m http.server` 后访问）。

开两个浏览器标签页（或两台电脑），用不同昵称登录，即可群聊/私聊。

## 消息协议（JSON 文本）

```
客户端 → 服务端：
  {"type":"login","username":"tom"}                      # 登录
  {"type":"chat","to":"jerry","text":"你好"}             # 私聊；to 为空 = 群聊
  {"type":"online_list"}                                 # 请求在线列表

服务端 → 客户端：
  {"type":"login_ok","username":"tom"}                   # 登录成功
  {"type":"error","msg":"用户名已在线"}                  # 错误提示
  {"type":"chat","from":"tom","to":"jerry","text":"你好"}
  {"type":"system","text":"tom 加入了聊天室"}            # 系统通知
  {"type":"online_list","users":["tom","jerry"]}         # 在线用户列表
```

## 已实现功能

- [x] WebSocket 握手（HTTP 101 + Sec-WebSocket-Accept）
- [x] 帧解析（粘包/拆包、掩码解算）
- [x] 多用户并发（epoll 边缘触发）
- [x] 登录 / 用户名冲突检测
- [x] 群聊广播 / 私聊定向转发
- [x] 在线用户列表（登录、退出实时刷新）
- [x] 前端：登录页、在线列表、消息气泡、私聊切换

## 待做（进阶）

- [ ] 注册与账号存储（SQLite + 密码哈希）
- [ ] 离线消息暂存与推送
- [ ] 心跳保活 + 超时踢出
- [ ] 消息历史（聊天记录持久化）
- [ ] 文件传输 / 表情
- [ ] 部署：Nginx 反代 WebSocket（wss://）+ Docker

## 关键设计说明

1. **为什么服务端要自己实现 WebSocket？**
   浏览器只能发 WebSocket，发不了裸 TCP。服务端在 accept 后收到的是 HTTP 升级请求，
   需要回 101 并转成帧协议。`websocket.h` 里就是这么干的。

2. **客户端→服务端必须掩码**
   RFC 6455 规定浏览器发来的每一帧 MASK=1，payload 要和 4 字节 mask key 逐字节异或。
   服务端回包 MASK=0，不用掩码。

3. **JSON 解析是手写的**
   `json_get()` 只做教学用（支持字符串/数字取值），正式项目应换 nlohmann/json。
