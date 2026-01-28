//! src/main.zig
//! Gatekeeper 安全网关服务主程序 (基于解耦 Reactor)

const std = @import("std");
const net = std.net;
const mem = std.mem;
const posix = std.posix;
const Thread = std.Thread;
const reactor = @import("reactor/mod.zig");

// ====================  常量定义 ====================
const LOCAL_PORT = 3001;
const TARGET_HOST = "127.0.0.1";
const TARGET_PORT = 3000;
const MAX_CONNECTIONS = 10000;
const BUFFER_SIZE = 16 * 1024;

const TrustedSubnet = struct {
    ip: u32,
    mask: u32,
};

// CIDR 白名单：只信任这些 IP 发来的 X-Forwarded-For / CF-Connecting-IP
// 默认仅信任本机回环 (127.0.0.0/8)
const TRUSTED_PROXIES = [_]TrustedSubnet{
    .{ .ip = 0x7F000000, .mask = 0xFF000000 },
};

fn isTrustedProxy(ip: u32) bool {
    // ip 是主机字节序
    for (TRUSTED_PROXIES) |subnet| {
        if ((ip & subnet.mask) == (subnet.ip & subnet.mask)) return true;
    }
    return false;
}

fn sendErrorResponse(fd: posix.socket_t, code: []const u8, reason: []const u8, body: []const u8) !void {
    const header =
        "HTTP/1.1 {s} {s}\r\n" ++
        "Content-Type: text/plain\r\n" ++
        "Connection: close\r\n" ++
        "Content-Length: {d}\r\n" ++
        "\r\n";

    var buf: [512]u8 = undefined;
    const msg = try std.fmt.bufPrint(&buf, header, .{ code, reason, body.len });

    _ = try posix.write(fd, msg);
    _ = try posix.write(fd, body);
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // 1. 初始化黑名单索引
    const index_mod = @import("utils/index.zig");
    const index_path = "rules/blacklist.idx";
    if (std.fs.cwd().access(index_path, .{})) |_| {} else |_| {
        try index_mod.buildIndex(allocator, "rules", index_path);
    }
    var ip_index = try index_mod.IndexReader.init(allocator, index_path);
    defer ip_index.deinit();

    // 2. 初始化频率限制器
    const ratelimit_mod = @import("utils/ratelimit.zig");
    var rate_limiter = ratelimit_mod.RateLimiter.init(allocator);
    defer rate_limiter.deinit();

    const cleanup_thread = try Thread.spawn(.{}, cleanupTask, .{&rate_limiter});
    cleanup_thread.detach();

    // 3. 构建业务逻辑上下文
    var proxy = ProxyContext{
        .ip_index = &ip_index,
        .rate_limiter = &rate_limiter,
        .target_host = TARGET_HOST,
        .target_port = TARGET_PORT,
    };

    // 4. 初始化 Reactor 引擎并绑定业务逻辑
    var engine = try reactor.Engine.init(
        allocator,
        MAX_CONNECTIONS,
        BUFFER_SIZE,
        .{
            .ptr = &proxy,
            .onHeader = ProxyContext.onHeader,
            .onPumping = ProxyContext.onPumping,
            .onBackendError = ProxyContext.onBackendError,
        },
    );
    defer engine.deinit();

    // 5. 绑定监听端口
    const address = try net.Address.parseIp4("0.0.0.0", LOCAL_PORT);
    const listen_sock = try posix.socket(posix.AF.INET, posix.SOCK.STREAM, 0);
    defer posix.close(listen_sock);
    try posix.setsockopt(listen_sock, posix.SOL.SOCKET, posix.SO.REUSEADDR, &mem.toBytes(@as(c_int, 1)));
    try posix.bind(listen_sock, &address.any, address.getOsSockLen());
    try posix.listen(listen_sock, 128);
    try reactor.setNonBlock(listen_sock);

    try engine.addFD(listen_sock, 0, .listener);

    std.debug.print("Gatekeeper (Decoupled Architecture) started\n", .{});
    while (true) {
        try engine.run(100);
    }
}

/// ProxyContext 封装所有核心业务逻辑（解耦后的成果）
const ProxyContext = struct {
    ip_index: *@import("utils/index.zig").IndexReader,
    rate_limiter: *@import("utils/ratelimit.zig").RateLimiter,
    target_host: []const u8,
    target_port: u16,

    // 健康检查状态
    consecutive_failures: usize = 0,
    last_failure_time: i64 = 0,
    const HEALTH_THRESHOLD = 5;
    const COOLING_PERIOD_MS = 10000;

    const HttpState = enum {
        IDLE,
        HEADERS,
        BODY,
    };

    /// 内部连接元数据（存放重试次数等）
    const ConnMeta = struct {
        retries: u8 = 0,
        // TCP 分片重组缓冲区 (最大方法长度 "OPTIONS " = 8)
        frag_buf: [8]u8 = undefined,
        frag_len: usize = 0,

        // HTTP 状态机 - 防止 False Positive 和 Smuggling
        http_state: HttpState = .IDLE,
        body_remaining: usize = 0,
    };

    pub fn onHeader(ptr: *anyopaque, engine: *reactor.Engine, slot: usize, data: []const u8) anyerror!bool {
        const self: *ProxyContext = @ptrCast(@alignCast(ptr));
        const conn = &engine.conn_pool[slot].?;

        // 0. Lazy Init Context (if not exists)
        if (conn.context == null) {
            const meta = try engine.allocator.create(ConnMeta);
            meta.* = .{};
            conn.context = meta;
        }

        // 1. 累积 Header 数据 (利用 s2c_buf 作为临时存储，最大 16KB)
        // 防止 Header 被切分导致 extractRealIP 找不到关键字
        if (conn.s2c_len + data.len > conn.s2c_buf.len) return false; // Header Too Large
        @memcpy(conn.s2c_buf[conn.s2c_len..][0..data.len], data);
        conn.s2c_len += data.len;

        const full_header = conn.s2c_buf[0..conn.s2c_len];

        // 2. 检查 Header 是否完整
        if (std.mem.indexOf(u8, full_header, "\r\n\r\n") == null) {
            // 不完整，继续等待更多数据
            return true;
        }

        // 3. 获取客户端 IP & 提取真实 IP
        const socket_ip = blk: {
            var peer_storage: posix.sockaddr.storage = undefined;
            var peer_len: posix.socklen_t = @sizeOf(posix.sockaddr.storage);
            try posix.getpeername(conn.client_fd, @ptrCast(&peer_storage), &peer_len);
            const peer_net_addr = net.Address.initPosix(@ptrCast(&peer_storage));
            break :blk @byteSwap(peer_net_addr.in.sa.addr);
        };

        const real_ip = try extractRealIP(full_header, socket_ip);
        conn.real_ip_cached = real_ip;

        // 4. 安全检查
        if (try self.ip_index.isBlocked(real_ip)) return false;
        if (!(try self.rate_limiter.checkLimit(real_ip))) return false;

        // 5. 健康检查
        if (self.consecutive_failures >= HEALTH_THRESHOLD) {
            if (reactor.getMonotonicMs() - self.last_failure_time < COOLING_PERIOD_MS) {
                return false;
            }
        }

        // 6. 恢复 c2s_buf 用于转发 (将完整的 Header 放回 c2s_buf)
        // reactor 在 PUMPING 状态下会发送 c2s_buf 内容
        @memcpy(conn.c2s_buf[0..full_header.len], full_header);
        conn.c2s_len = full_header.len;
        conn.s2c_len = 0; // 清空临时累积区

        // 7. 发起后端连接
        return try self.connectToBackend(engine, slot);
    }

    fn connectToBackend(self: *ProxyContext, engine: *reactor.Engine, slot: usize) !bool {
        _ = self;
        const conn = &engine.conn_pool[slot].?;
        const target_addr = try net.Address.parseIp4(TARGET_HOST, TARGET_PORT);
        const s_fd = try posix.socket(posix.AF.INET, posix.SOCK.STREAM, 0);
        try reactor.setNonBlock(s_fd);

        posix.connect(s_fd, &target_addr.any, target_addr.getOsSockLen()) catch |err| {
            if (err != error.WouldBlock) return false;
        };

        conn.server_fd = s_fd;
        conn.state = .BACKEND_CONNECTING;
        try engine.addFD(s_fd, slot, .server);
        return true;
    }

    pub fn onPumping(ptr: *anyopaque, engine: *reactor.Engine, slot: usize, data: []const u8) anyerror!bool {
        const self: *ProxyContext = @ptrCast(@alignCast(ptr));
        const conn = &engine.conn_pool[slot].?;
        var meta: *ConnMeta = @ptrCast(@alignCast(conn.context.?));

        // 1. 构造跨包视图：[上一包尾部] + [当前包]
        // 使用非常小的栈上缓冲，避免动态分配
        var combined_buf: [16 * 1024 + 8]u8 = undefined;
        // 安全检查：防止栈溢出 (虽然 reactor 限制了 read buffer size)
        if (meta.frag_len + data.len > combined_buf.len) return false;

        @memcpy(combined_buf[0..meta.frag_len], meta.frag_buf[0..meta.frag_len]);
        @memcpy(combined_buf[meta.frag_len .. meta.frag_len + data.len], data);

        const view_data = combined_buf[0 .. meta.frag_len + data.len];

        // 2. HTTP 状态机流式处理
        const http_mod = @import("utils/http.zig");
        var cursor: usize = 0;
        const total_len = meta.frag_len + data.len;

        while (cursor < total_len) {
            switch (meta.http_state) {
                .BODY => {
                    const available = total_len - cursor;
                    const consume = @min(available, meta.body_remaining);
                    meta.body_remaining -= consume;
                    cursor += consume;
                    if (meta.body_remaining == 0) {
                        meta.http_state = .IDLE; // Body 结束，准备处理下一个请求
                    }
                },
                .IDLE, .HEADERS => {
                    // IDLE/HEADERS 状态下需要扫描 \r\n\r\n
                    // 我们只扫描 view_data[cursor..]
                    const slice = view_data[cursor..];

                    // 1. 如果还在 IDLE，探测 Method
                    if (meta.http_state == .IDLE) {
                        const methods = [_][]const u8{ "GET ", "POST ", "HEAD ", "PUT ", "DELETE ", "OPTIONS ", "PATCH " };
                        for (methods) |m| {
                            if (std.mem.startsWith(u8, slice, m)) {
                                if (!(try self.rate_limiter.checkLimit(conn.real_ip_cached))) return false;
                                meta.http_state = .HEADERS;
                                break;
                            }
                        }
                        // 如果是 IDLE 但开头不是 Method，可能是 Pipeline 中的 \r\n 残留，也可能是非法数据
                        // 简单起见，我们默认切到 HEADERS 模式寻找结尾，或者继续等待
                        if (meta.http_state == .IDLE) meta.http_state = .HEADERS;
                    }

                    // 2. 寻找 Header 结束符
                    if (std.mem.indexOf(u8, slice, "\r\n\r\n")) |end_pos| {
                        // 找到 Header 结束
                        const header_bytes = slice[0 .. end_pos + 4];
                        const cl = http_mod.parseContentLength(header_bytes);

                        meta.http_state = .BODY;
                        meta.body_remaining = cl;

                        // 移动 cursor 越过 Header
                        cursor += end_pos + 4;
                    } else {
                        // 没找到 Header 结束符，说明 Header 跨包了
                        // 这一整块数据都是 Header 的一部分
                        cursor = total_len; // 消耗完
                    }
                },
            }
        }

        // 3. 更新尾部缓冲 (滚动追加模式)
        if (data.len >= 8) {
            @memcpy(meta.frag_buf[0..8], data[data.len - 8 ..]);
            meta.frag_len = 8;
        } else {
            const space_needed = 8 - data.len;
            const keep_existing = @min(meta.frag_len, space_needed);

            if (keep_existing > 0) {
                std.mem.copyForwards(u8, meta.frag_buf[0..keep_existing], meta.frag_buf[meta.frag_len - keep_existing .. meta.frag_len]);
            }
            @memcpy(meta.frag_buf[keep_existing .. keep_existing + data.len], data);
            meta.frag_len = keep_existing + data.len;
        }

        return true;
    }

    pub fn onBackendError(ptr: *anyopaque, engine: *reactor.Engine, slot: usize) anyerror!void {
        const self: *ProxyContext = @ptrCast(@alignCast(ptr));
        var conn = &engine.conn_pool[slot].?;

        self.consecutive_failures += 1;
        self.last_failure_time = reactor.getMonotonicMs();

        // 懒加载 Context
        if (conn.context == null) {
            const meta = try engine.allocator.create(ConnMeta);
            meta.* = .{ .retries = 0 };
            conn.context = meta;
        }
        var meta: *ConnMeta = @ptrCast(@alignCast(conn.context.?));

        // 清理旧后端 FD
        engine.removeFDByFD(conn.server_fd);
        posix.close(conn.server_fd);
        conn.server_fd = reactor.invalid_sock;

        if (meta.retries < 3) {
            meta.retries += 1;
            std.debug.print("[PROXY] Retrying backend {d}/3...\n", .{meta.retries});
            _ = try self.connectToBackend(engine, slot);
        } else {
            // 发送 502 并标记关闭
            sendErrorResponse(conn.client_fd, "502", "Bad Gateway", "Gatekeeper: Backend Unreachable after retries.") catch {};
            conn.state = .CLOSING;
            engine.allocator.destroy(meta);
            conn.context = null;
        }
    }
};

fn cleanupTask(rate_limiter: *@import("utils/ratelimit.zig").RateLimiter) void {
    while (true) {
        std.Thread.sleep(60 * std.time.ns_per_s);
        rate_limiter.cleanup();
    }
}

fn extractRealIP(buffer: []const u8, socket_ip: u32) !u32 {
    const index_mod = @import("utils/index.zig");
    // 仅在来自可信代理（如 Nginx/Cloudflare Tunnel 转发）时尝试提取真实 IP
    if (!isTrustedProxy(socket_ip)) return socket_ip;

    // 2. 使用安全解析器提取 IP
    const http_mod = @import("utils/http.zig");
    if (http_mod.findHeaderValue(buffer, "CF-Connecting-IP")) |val| {
        return index_mod.parseIPv4(val) catch socket_ip;
    }

    return socket_ip;
}
