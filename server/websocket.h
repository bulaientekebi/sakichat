/**
 * websocket.h —— WebSocket 协议层（RFC 6455）
 *
 * 包含三件事：
 * 1. 握手：解析浏览器发来的 HTTP 升级请求，算出 Sec-WebSocket-Accept
 * 2. 帧解析：把浏览器发来的 WebSocket 帧解成文本（处理掩码/粘包/拆包）
 * 3. 帧打包：把服务端文本消息打成 WebSocket 帧发出去
 *
 * 编译需要 OpenSSL（SHA1）：sudo apt install libssl-dev
 */

#ifndef WEBSOCKET_H
#define WEBSOCKET_H

#include <string>
#include <cstring>
#include <cstdint>
#include <openssl/sha.h>

// ============================================================
// 1. 握手：返回 101 Switching Protocols 响应
// ============================================================
inline std::string ws_handshake_response(const std::string& request) {
    // 从 HTTP 请求头中提取 Sec-WebSocket-Key
    std::string key;
    size_t pos = request.find("Sec-WebSocket-Key:");
    if (pos != std::string::npos) {
        size_t start = pos + strlen("Sec-WebSocket-Key:");
        size_t end = request.find("\r\n", start);
        key = request.substr(start, end - start);
        // 去掉首尾空白
        while (!key.empty() && (key.front() == ' ' || key.front() == '\t')) key.erase(key.begin());
        while (!key.empty() && (key.back() == ' ' || key.back() == '\t' || key.back() == '\r')) key.pop_back();
    }

    // Sec-WebSocket-Accept = Base64(SHA1(key + GUID))
    // GUID 是 RFC 6455 规定的固定字符串
    const char* GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    std::string input = key + GUID;

    unsigned char digest[SHA_DIGEST_LENGTH];
    SHA1((const unsigned char*)input.data(), input.size(), digest);

    // Base64 编码（手写，20 字节 → 28 字符）
    static const char table[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string base64;
    for (int i = 0; i < SHA_DIGEST_LENGTH; i += 3) {
        uint32_t v = digest[i] << 16;
        if (i + 1 < SHA_DIGEST_LENGTH) v |= digest[i + 1] << 8;
        if (i + 2 < SHA_DIGEST_LENGTH) v |= digest[i + 2];
        base64 += table[(v >> 18) & 0x3F];
        base64 += table[(v >> 12) & 0x3F];
        base64 += (i + 1 < SHA_DIGEST_LENGTH) ? table[(v >> 6) & 0x3F] : '=';
        base64 += (i + 2 < SHA_DIGEST_LENGTH) ? table[v & 0x3F] : '=';
    }

    return "HTTP/1.1 101 Switching Protocols\r\n"
           "Upgrade: websocket\r\n"
           "Connection: Upgrade\r\n"
           "Sec-WebSocket-Accept: " + base64 + "\r\n\r\n";
}

// ============================================================
// 2. 帧缓冲区：浏览器 → 服务端（必须解掩码，处理粘包/拆包）
// ============================================================
class WebSocketBuffer {
public:
    void append(const char* data, size_t len) { buffer_.append(data, len); }

    /**
     * 尝试从缓冲区中解析出一条帧。
     * 返回 true  = 消费了一条帧（text 非空表示收到文本，closed 表示客户端关闭）
     * 返回 false = 数据不够，需要继续接收
     */
    bool try_parse(std::string& text, bool& closed) {
        closed = false;
        text.clear();
        if (buffer_.size() < 2) return false;

        unsigned char b0 = buffer_[0];   // FIN + opcode
        unsigned char b1 = buffer_[1];   // MASK + payload length
        int      opcode = b0 & 0x0F;
        bool     masked = b1 & 0x80;
        uint64_t len    = b1 & 0x7F;

        size_t offset = 2;

        // 长度扩展：126 → 后面2字节是长度；127 → 后面8字节
        if (len == 126) {
            if (buffer_.size() < 4) return false;
            len = ((unsigned char)buffer_[2] << 8) | (unsigned char)buffer_[3];
            offset = 4;
        } else if (len == 127) {
            if (buffer_.size() < 10) return false;
            len = 0;
            for (int i = 0; i < 8; i++) len = (len << 8) | (unsigned char)buffer_[2 + i];
            offset = 10;
        }

        // 掩码键：客户端→服务端 必须掩码
        uint8_t mask_key[4] = {0, 0, 0, 0};
        if (masked) {
            if (buffer_.size() < offset + 4) return false;
            memcpy(mask_key, buffer_.data() + offset, 4);
            offset += 4;
        }

        if (buffer_.size() < offset + len) return false;

        // 取出 payload 并解掩码（逐字节异或）
        std::string payload(buffer_.data() + offset, len);
        if (masked) {
            for (uint64_t i = 0; i < len; i++) payload[i] ^= mask_key[i % 4];
        }

        buffer_.erase(0, offset + len);  // 消费掉这条帧

        if (opcode == 0x8) { closed = true; return true; }   // 关闭帧
        if (opcode == 0x1) { text = std::move(payload); }    // 文本帧
        // 0x9 ping / 0xA pong：忽略（浏览器 JS API 会自动应答）
        return true;
    }

private:
    std::string buffer_;
};

// ============================================================
// 3. 帧打包：服务端 → 浏览器（不需要掩码）
// ============================================================
inline std::string ws_send_text(const std::string& text) {
    std::string frame;
    frame.push_back(0x81);  // 0x80 FIN + 0x01 文本帧

    size_t len = text.size();
    if (len < 126) {
        frame.push_back((char)len);
    } else if (len < 65536) {
        frame.push_back(126);
        frame.push_back((char)(len >> 8));
        frame.push_back((char)(len & 0xFF));
    } else {
        frame.push_back(127);
        for (int i = 7; i >= 0; i--) frame.push_back((char)((len >> (i * 8)) & 0xFF));
    }

    frame += text;
    return frame;
}

#endif // WEBSOCKET_H
