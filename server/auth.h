/**
 * auth.h —— 注册 / 登录 / 账号持久化（SQLite + PBKDF2 密码哈希）
 *
 * 设计说明：
 *   1. 纯数据层：只负责「输入 (username, password) → 校验/读写数据库 → 状态码」，
 *      不接触 socket / epoll / WebSocket / JSON，方便独立测试与替换实现。
 *   2. 密码绝不明文存储，采用 PBKDF2-HMAC-SHA256（OpenSSL 提供，零新增系统依赖）：
 *        随机 16 字节盐 + 20 万次迭代 → 慢哈希，抗彩虹表与 GPU 爆破。
 *   3. 存储格式（单列 credential，带版本前缀，方便未来平滑升级算法）：
 *        credential = v1:<salt_hex>:<hash_hex>
 *   4. 安全细节：
 *        - SQL 全程参数绑定（sqlite3_bind_*），杜绝注入；
 *        - 用户不存在时也执行一次等成本 PBKDF2，防「存在性」时序枚举；
 *        - 哈希比对用 CRYPTO_memcmp（恒定时间），防侧信道；
 *        - 用户名白名单校验，非法字符根本进不了库（顺带防昵称 XSS）。
 *   5. 线程模型：当前服务为单线程 epoll，DB 句柄共享无并发问题。
 *      本模块非线程安全，调用方需保证同一时刻只有一个执行流。
 *
 * 表结构：
 *   CREATE TABLE IF NOT EXISTS users(
 *     id         INTEGER PRIMARY KEY AUTOINCREMENT,
 *     username   TEXT UNIQUE NOT NULL,   -- UNIQUE 兜底并发重复注册
 *     credential TEXT NOT NULL,          -- v1:<salt_hex>:<hash_hex>
 *     created_at TEXT DEFAULT (datetime('now'))
 *   );
 *
 * 编译需要：apt install libsqlite3-dev（Makefile LDFLAGS 增加 -lsqlite3）
 */

#ifndef AUTH_H
#define AUTH_H

#include <iostream>
#include <string>

#include <sqlite3.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>

namespace auth {

// ---------------- 参数（放文件顶部，便于统一调整） ----------------
constexpr int SALT_LEN     = 16;    // 随机盐字节数
constexpr int HASH_LEN     = 32;    // SHA-256 派生密钥字节数
constexpr int PBKDF2_ITERS = 200000; // 慢化迭代次数（登录是低频操作，几十 ms 可接受）
constexpr int USERNAME_MIN = 2;     // 用户名最小长度（字节）
constexpr int USERNAME_MAX = 20;    // 用户名最大长度（字节，中文按 3 字节/字计）
constexpr int PASSWORD_MIN = 6;     // 密码最小长度
constexpr int PASSWORD_MAX = 64;    // 密码最大长度（字节）

// ---------------- 返回码（对外只暴露语义，message 由调用方映射） ----------------
enum class Result {
    Ok,            // 成功
    BadInput,      // 用户名/密码格式不合法
    UserExists,    // 注册：用户名已被占用
    UserNotFound,  // 登录：无此用户
    WrongPassword, // 登录：密码错误
    DbError,       // 数据库内部错误
};

namespace detail {

inline sqlite3* g_db = nullptr;  // C++17 inline 变量：多 TU 共享单实例

// hex 编码：二进制 → 文本（每字节 2 字符），便于入库/日志
inline std::string to_hex(const unsigned char* data, size_t len) {
    static const char* digits = "0123456789abcdef";
    std::string s;
    s.reserve(len * 2);
    for (size_t i = 0; i < len; i++) {
        s += digits[data[i] >> 4];   // 高 4 位
        s += digits[data[i] & 0x0F]; // 低 4 位
    }
    return s;
}

// hex 解码：文本 → 二进制。失败返回 false（长度非偶 / 非法字符）
inline bool from_hex(const std::string& hex, std::string& bin) {
    if (hex.size() % 2) return false;
    auto val = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    bin.clear();
    bin.reserve(hex.size() / 2);
    for (size_t i = 0; i < hex.size(); i += 2) {
        int hi = val(hex[i]), lo = val(hex[i + 1]);
        if (hi < 0 || lo < 0) return false;
        bin.push_back(char((hi << 4) | lo));
    }
    return true;
}

// RAII：任何 return 路径都自动 finalize，杜绝长驻进程的 statement 泄漏
struct StmtGuard {
    sqlite3_stmt* p = nullptr;
    ~StmtGuard() { if (p) sqlite3_finalize(p); }
};

// 用户名：ASCII 字母/数字/下划线 + 任意多字节字符（中文/emoji 放行），
// 以此白名单把 '"'、'\'、'<'、空格等会破坏 JSON/HTML 的字符挡在库外。
inline bool valid_username(const std::string& u) {
    if (u.size() < USERNAME_MIN || u.size() > USERNAME_MAX) return false;
    for (unsigned char c : u) {
        if (c < 0x80) {
            bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                      (c >= '0' && c <= '9') || c == '_';
            if (!ok) return false;
        }
        // c >= 0x80：UTF-8 多字节字符，放行
    }
    return true;
}

// 密码：长度 6~64 字节；不允许 '"' 与 '\'（本项目为手工 JSON 解析，
// 这两个字符会破坏取值）；不允许控制字符。
inline bool valid_password(const std::string& p) {
    if (p.size() < PASSWORD_MIN || p.size() > PASSWORD_MAX) return false;
    for (unsigned char c : p) {
        if (c < 0x20 || c == '"' || c == '\\') return false;
    }
    return true;
}

// PBKDF2 派生：password + salt → out(32 字节)。成功返回 true
inline bool derive(const std::string& password, const unsigned char* salt,
                   int salt_len, unsigned char* out) {
    return PKCS5_PBKDF2_HMAC(password.data(), (int)password.size(),
                             salt, salt_len, PBKDF2_ITERS,
                             EVP_sha256(), HASH_LEN, out) == 1;
}

} // namespace detail

// ============================================================
// 对外接口
// ============================================================

// 打开数据库并建表。失败返回 false（调用方应 fail-fast 直接退出）
inline bool db_init(const char* path) {
    if (sqlite3_open(path, &detail::g_db) != SQLITE_OK) {
        std::cerr << "[auth] 打开数据库失败: "
                  << (detail::g_db ? sqlite3_errmsg(detail::g_db) : "unknown")
                  << std::endl;
        if (detail::g_db) sqlite3_close(detail::g_db);
        detail::g_db = nullptr;
        return false;
    }

    char* err = nullptr;
    if (sqlite3_exec(detail::g_db, "PRAGMA journal_mode=WAL;",
                     nullptr, nullptr, &err) != SQLITE_OK) {
        std::cerr << "[auth] 设置 WAL 失败: " << (err ? err : "") << std::endl;
        sqlite3_free(err);
    }

    const char* sql =
        "CREATE TABLE IF NOT EXISTS users("
        "  id         INTEGER PRIMARY KEY AUTOINCREMENT,"
        "  username   TEXT UNIQUE NOT NULL,"
        "  credential TEXT NOT NULL,"
        "  created_at TEXT DEFAULT (datetime('now'))"
        ");";
    if (sqlite3_exec(detail::g_db, sql, nullptr, nullptr, &err) != SQLITE_OK) {
        std::cerr << "[auth] 创建 users 表失败: " << (err ? err : "") << std::endl;
        sqlite3_free(err);
        return false;
    }
    return true;
}

// 注册：白名单校验 → 随机盐 → PBKDF2 → INSERT（依赖 UNIQUE 捕获重名）
inline Result register_user(const std::string& username, const std::string& password) {
    if (!detail::valid_username(username) || !detail::valid_password(password))
        return Result::BadInput;

    if (!detail::g_db) return Result::DbError;

    unsigned char salt[SALT_LEN], hash[HASH_LEN];
    if (RAND_bytes(salt, SALT_LEN) != 1) {
        std::cerr << "[auth] 生成随机盐失败" << std::endl;
        return Result::DbError;
    }
    if (!detail::derive(password, salt, SALT_LEN, hash))
        return Result::DbError;

    std::string credential =
        "v1:" + detail::to_hex(salt, SALT_LEN) + ":" + detail::to_hex(hash, HASH_LEN);

    detail::StmtGuard s;
    const char* sql = "INSERT INTO users(username, credential) VALUES(?, ?);";
    if (sqlite3_prepare_v2(detail::g_db, sql, -1, &s.p, nullptr) != SQLITE_OK) {
        std::cerr << "[auth] 预编译 INSERT 失败: "
                  << sqlite3_errmsg(detail::g_db) << std::endl;
        return Result::DbError;
    }
    sqlite3_bind_text(s.p, 1, username.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(s.p, 2, credential.c_str(), -1, SQLITE_TRANSIENT);

    int rc = sqlite3_step(s.p);
    if (rc == SQLITE_CONSTRAINT) return Result::UserExists;   // UNIQUE 冲突
    if (rc != SQLITE_DONE) {
        std::cerr << "[auth] INSERT 执行失败: "
                  << sqlite3_errmsg(detail::g_db) << std::endl;
        return Result::DbError;
    }
    return Result::Ok;
}

// 登录：取存储的 credential → 拆 salt/hash → 重算 PBKDF2 → 恒定时间比对
inline Result login(const std::string& username, const std::string& password) {
    if (!detail::valid_username(username) || !detail::valid_password(password))
        return Result::BadInput;
    if (!detail::g_db) return Result::DbError;

    detail::StmtGuard s;
    const char* sql = "SELECT credential FROM users WHERE username = ?;";
    if (sqlite3_prepare_v2(detail::g_db, sql, -1, &s.p, nullptr) != SQLITE_OK) {
        std::cerr << "[auth] 预编译 SELECT 失败: "
                  << sqlite3_errmsg(detail::g_db) << std::endl;
        return Result::DbError;
    }
    sqlite3_bind_text(s.p, 1, username.c_str(), -1, SQLITE_TRANSIENT);

    int rc = sqlite3_step(s.p);
    std::string credential;
    if (rc == SQLITE_ROW) {
        const unsigned char* txt = sqlite3_column_text(s.p, 0);
        if (txt) credential.assign((const char*)txt);
    }

    // 解析 v1:<salt_hex>:<hash_hex>
    std::string salt_bin, hash_bin;
    bool have_record = false;
    if (credential.rfind("v1:", 0) == 0) {
        size_t c1 = credential.find(':', 3);
        size_t c2 = credential.find(':', c1 + 1);
        if (c1 != std::string::npos && c2 != std::string::npos) {
            have_record =
                detail::from_hex(credential.substr(3, c1 - 3), salt_bin) &&
                detail::from_hex(credential.substr(c1 + 1), hash_bin);
        }
    }

    if (!have_record) {
        // 用户不存在 / 记录损坏：仍执行一次等成本派生，防止通过响应时间
        // 判断「用户是否存在」→ 防用户名枚举的时序侧信道
        static const unsigned char dummy_salt[SALT_LEN] = {0};
        unsigned char dummy_hash[HASH_LEN];
        detail::derive(password, dummy_salt, SALT_LEN, dummy_hash);
        return Result::UserNotFound;
    }

    unsigned char hash[HASH_LEN];
    if (!detail::derive(password, (const unsigned char*)salt_bin.data(),
                        (int)salt_bin.size(), hash))
        return Result::DbError;

    if (salt_bin.size() != SALT_LEN || hash_bin.size() != HASH_LEN)
        return Result::DbError;

    if (CRYPTO_memcmp(hash, hash_bin.data(), HASH_LEN) == 0)
        return Result::Ok;
    return Result::WrongPassword;
}

} // namespace auth

#endif // AUTH_H
