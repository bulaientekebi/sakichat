/**
 * sakichat_server —— C++ epoll + WebSocket 聊天服务器
 *
 * 功能：
 * 1. 多客户端并发（epoll 非阻塞 I/O）
 * 2. WebSocket 握手 + 帧解析（复用 websocket.h）
 * 3. 业务：登录 / 群聊广播 / 私聊 / 在线列表
 *
 * 编译：make
 * 运行：./sakichat_server
 * 测试：浏览器打开 client/index.html
 *
 * 消息协议（JSON 文本）：
 *   客户端 → 服务端：
 *     {"type":"login","username":"tom"}
 *     {"type":"chat","to":"jerry","text":"你好"}     // to 为空 = 群聊
 *     {"type":"online_list"}
 *   服务端 → 客户端：
 *     {"type":"login_ok","username":"tom"}
 *     {"type":"error","msg":"用户名已在线"}
 *     {"type":"chat","from":"tom","to":"jerry","text":"你好"}
 *     {"type":"system","text":"tom 加入了聊天室"}
 *     {"type":"online_list","users":["tom","jerry"]}
 */

#include <iostream>
#include <cstring>
#include <string>
#include <unordered_map>

#include <sys/socket.h>
#include <sys/epoll.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>

#include "websocket.h"

constexpr int PORT        = 9000;   // 部署：Nginx 反代到 127.0.0.1:9000
constexpr int MAX_EVENTS  = 64;
constexpr int BUFFER_SIZE = 4096;

// ---- 全局状态 ----
std::unordered_map<int, std::string>  fd_to_user;     // fd → 用户名
std::unordered_map<std::string, int>  user_to_fd;     // 用户名 → fd（私聊路由用）
std::unordered_map<int, WebSocketBuffer> ws_buffers;  // 每个连接的帧缓冲区
std::unordered_map<int, std::string>  handshake_buf;  // 握手期暂存 HTTP 头
std::unordered_map<int, bool>         handshaked;     // 是否已完成 WebSocket 握手

// ============================================================
// 工具函数
// ============================================================
void set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

// 给指定 fd 发送一条 JSON 文本消息（自动打包成 WebSocket 帧）
void send_to(int fd, const std::string& json_text) {
    std::string frame = ws_send_text(json_text);
    write(fd, frame.data(), frame.size());
}

// 广播给所有在线用户（except_fd 除外）
void broadcast(const std::string& json_text, int except_fd = -1) {
    for (auto& [fd, name] : fd_to_user) {
        if (fd == except_fd) continue;
        send_to(fd, json_text);
    }
}

// 给指定用户发送在线用户列表
void send_online_list(int fd) {
    std::string users = "[";
    bool first = true;
    for (auto& [name, f] : user_to_fd) {
        if (!first) users += ",";
        users += "\"" + name + "\"";
        first = false;
    }
    users += "]";
    send_to(fd, "{\"type\":\"online_list\",\"users\":" + users + "}");
}

// 刷新所有在线的在线列表（登录/退出时调用）
void refresh_online_lists() {
    for (auto& [fd, name] : fd_to_user) {
        send_online_list(fd);
    }
}

// ============================================================
// 简化 JSON 取值（教学版，正式项目用 nlohmann/json）
// json_get("{\"type\":\"chat\",\"to\":\"jerry\"}", "to") → "jerry"
// ============================================================
std::string json_get(const std::string& json, const std::string& key) {
    std::string pattern = "\"" + key + "\"";
    size_t pos = json.find(pattern);
    if (pos == std::string::npos) return "";
    pos = json.find(':', pos);
    if (pos == std::string::npos) return "";
    pos++;
    while (pos < json.size() && (json[pos] == ' ' || json[pos] == '\t')) pos++;
    if (pos >= json.size()) return "";

    if (json[pos] == '"') {  // 字符串值
        size_t end = json.find('"', pos + 1);
        if (end == std::string::npos) return "";
        return json.substr(pos + 1, end - pos - 1);
    }
    // 数字/布尔值
    size_t end = pos;
    while (end < json.size() && json[end] != ',' && json[end] != '}') end++;
    return json.substr(pos, end - pos);
}

// ============================================================
// 业务处理：一条 JSON 消息
// ============================================================
void handle_message(int fd, const std::string& json) {
    std::string type = json_get(json, "type");

    if (type == "login") {
        std::string name = json_get(json, "username");
        if (name.empty()) {
            send_to(fd, "{\"type\":\"error\",\"msg\":\"用户名不能为空\"}");
            return;
        }
        if (user_to_fd.count(name)) {
            send_to(fd, "{\"type\":\"error\",\"msg\":\"用户名 \"" + name + "\" 已在线\"}");
            return;
        }

        fd_to_user[fd] = name;
        user_to_fd[name] = fd;
        std::cout << "[登录] " << name << " (fd=" << fd << ")" << std::endl;

        send_to(fd, "{\"type\":\"login_ok\",\"username\":\"" + name + "\"}");
        broadcast("{\"type\":\"system\",\"text\":\"" + name + " 加入了聊天室\"}", fd);
        refresh_online_lists();
    }
    else if (type == "chat") {
        std::string from = fd_to_user.count(fd) ? fd_to_user[fd] : "未知";
        std::string to   = json_get(json, "to");
        std::string text = json_get(json, "text");

        if (text.empty()) return;

        std::string msg = "{\"type\":\"chat\",\"from\":\"" + from +
                          "\",\"to\":\"" + to + "\",\"text\":\"" + text + "\"}";

        if (to.empty()) {
            broadcast(msg);  // 群聊
            std::cout << "[" << from << " → 所有人] " << text << std::endl;
        } else if (user_to_fd.count(to)) {
            send_to(user_to_fd[to], msg);  // 发给对方
            send_to(fd, msg);              // 也发给自己一份（本地显示）
            std::cout << "[" << from << " → " << to << "] " << text << std::endl;
        } else {
            send_to(fd, "{\"type\":\"error\",\"msg\":\"用户 \"" + to + "\" 不在线\"}");
        }
    }
    else if (type == "online_list") {
        send_online_list(fd);
    }
    else {
        send_to(fd, "{\"type\":\"error\",\"msg\":\"未知消息类型\"}");
    }
}

// ============================================================
// 断开一个客户端（清理所有状态）
// ============================================================
void disconnect(int fd, int epoll_fd) {
    if (fd_to_user.count(fd)) {
        std::string name = fd_to_user[fd];
        std::cout << "[断开] " << name << " (fd=" << fd << ")" << std::endl;
        user_to_fd.erase(name);
        fd_to_user.erase(fd);
        broadcast("{\"type\":\"system\",\"text\":\"" + name + " 离开了聊天室\"}", fd);
        refresh_online_lists();
    }
    ws_buffers.erase(fd);
    handshake_buf.erase(fd);
    handshaked.erase(fd);
    epoll_ctl(epoll_fd, EPOLL_CTL_DEL, fd, nullptr);
    close(fd);
}

// ============================================================
// 主函数
// ============================================================
int main() {
    // ---- 1. 创建监听 socket ----
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) { std::cerr << "创建 socket 失败!" << std::endl; return 1; }

    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    sockaddr_in address{};
    address.sin_family      = AF_INET;
    address.sin_addr.s_addr = inet_addr("127.0.0.1");   // 仅本机回环，由 Nginx 反向代理
    address.sin_port        = htons(PORT);

    if (bind(server_fd, (sockaddr*)&address, sizeof(address)) < 0) {
        std::cerr << "绑定端口 " << PORT << " 失败!" << std::endl;
        close(server_fd);
        return 1;
    }
    if (listen(server_fd, SOMAXCONN) < 0) {
        std::cerr << "监听失败!" << std::endl;
        close(server_fd);
        return 1;
    }
    set_nonblocking(server_fd);

    // ---- 2. 创建 epoll ----
    int epoll_fd = epoll_create1(0);
    if (epoll_fd < 0) { std::cerr << "创建 epoll 失败!" << std::endl; close(server_fd); return 1; }

    epoll_event ev{};
    ev.events  = EPOLLIN;
    ev.data.fd = server_fd;
    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, server_fd, &ev);

    std::cout << "========================================" << std::endl;
    std::cout << "  sakichat 服务器已启动，端口 " << PORT << std::endl;
    std::cout << "  浏览器打开 client/index.html 开始聊天" << std::endl;
    std::cout << "========================================" << std::endl;

    // ---- 3. 事件循环 ----
    epoll_event events[MAX_EVENTS];
    char raw_buffer[BUFFER_SIZE];

    while (true) {
        int n = epoll_wait(epoll_fd, events, MAX_EVENTS, -1);

        for (int i = 0; i < n; i++) {
            int fd = events[i].data.fd;

            // ---- 情况1：新的连接请求 ----
            if (fd == server_fd) {
                sockaddr_in client_addr{};
                socklen_t client_len = sizeof(client_addr);
                int client_fd = accept(server_fd, (sockaddr*)&client_addr, &client_len);
                if (client_fd < 0) continue;

                set_nonblocking(client_fd);
                ev.events  = EPOLLIN | EPOLLET;   // 边缘触发
                ev.data.fd = client_fd;
                epoll_ctl(epoll_fd, EPOLL_CTL_ADD, client_fd, &ev);

                ws_buffers[client_fd]   = WebSocketBuffer();
                handshake_buf[client_fd] = "";
                handshaked[client_fd]   = false;

                char ip[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &client_addr.sin_addr, ip, sizeof(ip));
                std::cout << "[连接] 新客户端 fd=" << client_fd << " IP=" << ip << std::endl;
            }
            // ---- 情况2：已有客户端发来数据 ----
            else {
                memset(raw_buffer, 0, sizeof(raw_buffer));
                int bytes = read(fd, raw_buffer, sizeof(raw_buffer) - 1);

                // 客户端断开
                if (bytes <= 0) {
                    if (bytes == 0 || errno != EAGAIN) disconnect(fd, epoll_fd);
                    continue;
                }

                // ---- 握手阶段：先收 HTTP 升级请求 ----
                if (!handshaked[fd]) {
                    handshake_buf[fd].append(raw_buffer, bytes);
                    size_t pos = handshake_buf[fd].find("\r\n\r\n");
                    if (pos == std::string::npos) continue;  // 头没收齐，继续等

                    std::string req  = handshake_buf[fd].substr(0, pos);
                    std::string resp = ws_handshake_response(req);
                    write(fd, resp.data(), resp.size());

                    handshaked[fd] = true;
                    std::cout << "[握手] fd=" << fd << " 升级为 WebSocket" << std::endl;

                    // 若头部之后还有多余数据（同一包到达），喂给帧缓冲区
                    if (handshake_buf[fd].size() > pos + 4) {
                        ws_buffers[fd].append(
                            handshake_buf[fd].data() + pos + 4,
                            handshake_buf[fd].size() - pos - 4);
                    }
                    handshake_buf.erase(fd);
                    continue;
                }

                // ---- 已握手：喂入帧缓冲区并解析 ----
                ws_buffers[fd].append(raw_buffer, bytes);

                std::string text;
                bool closed = false;
                while (ws_buffers[fd].try_parse(text, closed)) {
                    if (closed) { disconnect(fd, epoll_fd); break; }
                    if (!text.empty()) handle_message(fd, text);
                }
            }
        }
    }

    close(server_fd);
    close(epoll_fd);
    return 0;
}
