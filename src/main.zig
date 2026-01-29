//! src/main.zig
//! Gatekeeper 安全网关服务主程序 (基于解耦 Reactor)

const std = @import("std");
const net = std.net;
const mem = std.mem;
const posix = std.posix;
const Thread = std.Thread;
const reactor = @import("reactor/mod.zig");
const http_state = @import("utils/http_state.zig");

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

fn sendErrorResponse(conn: *reactor.Connection, code: []const u8, reason: []const u8, body: []const u8) !void {
    const header =
        "HTTP/1.1 {s} {s}\r\n" ++
        "Content-Type: text/plain\r\n" ++
        "Connection: close\r\n" ++
        "Content-Length: {d}\r\n" ++
        "\r\n";

    var buf: [1024]u8 = undefined;
    var final_msg: []const u8 = undefined;
    var final_body: []const u8 = undefined;

    if (std.fmt.bufPrint(&buf, header, .{ code, reason, body.len })) |formatted| {
        final_msg = formatted;
        final_body = body;
    } else |_| {
        // Fallback if formatting fails (e.g. overflow)
        final_msg = "HTTP/1.1 500 Internal Server Error\r\nConnection: close\r\nContent-Length: 21\r\n\r\nInternal Server Error";
        final_body = "";
    }

    // 尝试直接发送
    var total_sent: usize = 0;
    const iov = [_]posix.iovec_const{
        .{ .base = final_msg.ptr, .len = final_msg.len },
        .{ .base = final_body.ptr, .len = final_body.len },
    };

    // 使用 writev 尝试一次性发送 header + body
    if (posix.writev(conn.client_fd, &iov)) |n| {
        total_sent = n;
    } else |err| {
        if (err != error.WouldBlock) return err;
    }

    const total_len = final_msg.len + final_body.len;
    if (total_sent < total_len) {
        // 发送不完整，需要缓冲剩余部分并进入 FLUSHING 状态
        // 我们利用 s2c_buf 作为缓冲 (假设此时没有正常的后端转发数据)
        conn.s2c_len = 0;
        conn.s2c_sent = 0;

        var remaining = total_len - total_sent;
        var offset: usize = 0;

        // 填充 msg 剩余部分
        if (total_sent < final_msg.len) {
            const part = final_msg[total_sent..];
            @memcpy(conn.s2c_buf[offset..][0..part.len], part);
            offset += part.len;
            remaining -= part.len;
        }

        // 填充 body 剩余部分
        if (remaining > 0) {
            const body_sent = if (total_sent > final_msg.len) total_sent - final_msg.len else 0;
            const part = final_body[body_sent..];
            @memcpy(conn.s2c_buf[offset..][0..part.len], part);
            offset += part.len;
        }

        conn.s2c_len = offset;
        conn.state = .FLUSHING;
    } else {
        // 发送完毕
        conn.state = .CLOSING;
    }
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
            .onKeepAlive = ProxyContext.onKeepAlive,
            .onCleanup = ProxyContext.onCleanup,
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

    const ConnMeta = struct {
        retries: u8 = 0,
        sm: http_state.StateMachine,
        total_read: usize = 0,
    };

    pub fn onHeader(ptr: *anyopaque, engine: *reactor.Engine, slot: usize, data: []const u8) anyerror!bool {
        const self: *ProxyContext = @ptrCast(@alignCast(ptr));
        const conn = &engine.conn_pool[slot].?;

        // 懒加载 Context
        if (conn.context == null) {
            const meta = try engine.allocator.create(ConnMeta);
            meta.* = .{
                .retries = 0,
                .sm = http_state.StateMachine.init(),
            };
            conn.context = meta;
        }
        var meta: *ConnMeta = @ptrCast(@alignCast(conn.context.?));
        meta.total_read += data.len;

        // 1. Accumulate Header data (using s2c_buf as temporary storage, max 16KB)
        // Prevent Header truncation causing extractRealIP to miss keywords
        if (conn.s2c_len + data.len > conn.s2c_buf.len) return false; // Header Too Large

        @memcpy(conn.s2c_buf[conn.s2c_len..][0..data.len], data);
        conn.s2c_len += data.len;

        const combined_header = conn.s2c_buf[0..conn.s2c_len];

        // 2. Check strict HTTP header completeness
        // Robustness: Support both CRLF (\r\n\r\n) and LF (\n\n) terminators
        var header_end_len: usize = 0;
        const end_pos_opt = blk: {
            const p1 = mem.indexOf(u8, combined_header, "\r\n\r\n");
            const p2 = mem.indexOf(u8, combined_header, "\n\n");
            if (p1) |pos1| {
                if (p2) |pos2| {
                    if (pos1 < pos2) {
                        header_end_len = 4;
                        break :blk pos1;
                    } else {
                        header_end_len = 2;
                        break :blk pos2;
                    }
                }
                header_end_len = 4;
                break :blk p1;
            }
            if (p2) |pos2| {
                header_end_len = 2;
                break :blk pos2;
            }
            break :blk null;
        };

        if (end_pos_opt) |end_pos| {
            // Header complete
            // Initial Security Checks
            var peer_storage: posix.sockaddr.storage = undefined;
            var peer_len: posix.socklen_t = @sizeOf(posix.sockaddr.storage);
            try posix.getpeername(conn.client_fd, @ptrCast(&peer_storage), &peer_len);
            const peer_net_addr = net.Address.initPosix(@ptrCast(&peer_storage));
            const socket_ip = @byteSwap(peer_net_addr.in.sa.addr);
            conn.real_ip_cached = try extractRealIP(combined_header, socket_ip);

            // Smuggling Checks (Duplicate Headers, CL.TE)
            const http_mod = @import("utils/http.zig");
            http_mod.validateHeaderSection(combined_header[0 .. end_pos + header_end_len]) catch return false;

            if (http_mod.hasSmugglingRisk(combined_header[0 .. end_pos + header_end_len])) {
                std.debug.print("[SECURITY] HTTP Smuggling Risk Detected IP:{}\n", .{conn.real_ip_cached});
                return false;
            }

            // Header 收齐了，进行一次性的 SM 校验来确保合法性（同步状态机与 Header）
            // Reset SM
            meta.sm.reset();
            var event: http_state.Event = .CONTINUE;
            for (combined_header) |b| {
                if (!(try meta.sm.feed(b, &event))) {
                    std.debug.print("[SECURITY] Invalid Header Byte in SM check IP:{}\n", .{conn.real_ip_cached});
                    return false;
                }
                // Header 阶段不应该 FINISHED（除非 GET 没有 Body）
            }
            // 此时 SM 应该处于 BODY 状态或 READY for next

            // 安全检查：Rate Limit
            if (!(try self.rate_limiter.checkLimit(conn.real_ip_cached))) {
                std.debug.print("[SECURITY] Rate Limit Triggered IP:{d}.{d}.{d}.{d}\n", .{
                    (conn.real_ip_cached >> 24) & 0xFF,
                    (conn.real_ip_cached >> 16) & 0xFF,
                    (conn.real_ip_cached >> 8) & 0xFF,
                    conn.real_ip_cached & 0xFF,
                });
                return false;
            }

            // 5. 健康检查
            if (self.consecutive_failures >= HEALTH_THRESHOLD) {
                if (reactor.getMonotonicMs() - self.last_failure_time < COOLING_PERIOD_MS) {
                    return false;
                }
            }

            // 准备连接后端
            conn.state = .BACKEND_CONNECTING;
            // Reactor logic: client_fd -> c2s_buf.
            // We need to move combined_header back to c2s_buf?
            // Actually `BACKEND_CONNECTING` logic usually doesn't send data yet.
            // Once connected (.PUMPING), proper proxying starts using whatever is in c2s_buf?
            // NO. The `onHeader` accumulates. We need to send this accumulation to Backend.
            // We should Copy valid header to c2s_buf and set c2s_len.

            @memcpy(conn.c2s_buf[0..conn.s2c_len], combined_header);
            conn.c2s_len = conn.s2c_len;
            conn.s2c_len = 0; // Clear temp use

            std.debug.print("[ACCESS] Allowed IP:{d}.{d}.{d}.{d}\n", .{
                (conn.real_ip_cached >> 24) & 0xFF,
                (conn.real_ip_cached >> 16) & 0xFF,
                (conn.real_ip_cached >> 8) & 0xFF,
                conn.real_ip_cached & 0xFF,
            });
            _ = try self.connectToBackend(engine, slot);
            return true;
        }

        return true;
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
        meta.total_read += data.len;

        var event: http_state.Event = .CONTINUE;

        // Anti-Smuggling: Feed every byte to Strict State Machine
        for (data) |b| {
            // 如果 SM 发现协议错误 (e.g. Chunk Size 非法，Smuggling 迹象)，直接断开
            if (!(try meta.sm.feed(b, &event))) {
                std.debug.print("[SECURITY] Smuggling Detected: Invalid Byte sequence IP:{}\n", .{conn.real_ip_cached});
                return false;
            }

            if (event == .REQUEST_FINISHED) {
                // 当前请求结束，SM 自动重置为 IDLE，准备接受 Pipeline 的下一个请求
                // 必须对下一个请求进行限流检查
                if (!(try self.rate_limiter.checkLimit(conn.real_ip_cached))) {
                    std.debug.print("[SECURITY] Rate Limit Triggered on Pipeline Request IP:{}\n", .{conn.real_ip_cached});
                    return false;
                }
            }
        }

        return true;
    }

    pub fn onBackendError(ptr: *anyopaque, engine: *reactor.Engine, slot: usize) anyerror!void {
        const self: *ProxyContext = @ptrCast(@alignCast(ptr));
        const conn = &engine.conn_pool[slot].?;

        self.consecutive_failures += 1;
        self.last_failure_time = reactor.getMonotonicMs();

        // 懒加载 Context
        if (conn.context == null) {
            const meta = try engine.allocator.create(ConnMeta);
            meta.* = .{
                .retries = 0,
                .sm = http_state.StateMachine.init(),
                // total_read defaults to 0
            };
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
            // 发送 502 并标记关闭 (由 sendErrorResponse 管理状态：FLUSHING 或 CLOSING)
            sendErrorResponse(conn, "502", "Bad Gateway", "Gatekeeper: Backend Unreachable after retries.") catch {};
            // 注意：不要在这里强制设置 CLOSING，因为 sendErrorResponse 可能置为 FLUSHING
            engine.allocator.destroy(meta);
            conn.context = null;
        }
    }

    pub fn onCleanup(ptr: *anyopaque, engine: *reactor.Engine, slot: usize) void {
        const self: *ProxyContext = @ptrCast(@alignCast(ptr));
        _ = self;
        if (engine.conn_pool[slot]) |*conn| {
            if (conn.context) |ctx| {
                const meta: *ConnMeta = @ptrCast(@alignCast(ctx));
                // Anti-Leak: Ensure ConnMeta is freed when connection is destroyed (even if onBackendError didn't catch it)
                engine.allocator.destroy(meta);
                conn.context = null;
            }
        }
    }

    pub fn onKeepAlive(ptr: *anyopaque, engine: *reactor.Engine, slot: usize) anyerror!bool {
        _ = ptr;
        const conn = &engine.conn_pool[slot].?;
        if (conn.context == null) return true; // 还没发数据，由基础 Header Timeout 控制

        const meta: *ConnMeta = @ptrCast(@alignCast(conn.context.?));
        const now = reactor.getMonotonicMs();
        const duration = now - conn.start_time;

        const MIN_RATE = 15; // 15 bytes/sec (Relaxed for bad networks)

        // 宽限期 10 秒
        if (duration < 10000) return true;

        if (meta.total_read == 0) return false; // 10s 还没发任何数据，杀

        const rate = meta.total_read * 1000 / @as(usize, @intCast(duration));
        if (rate < MIN_RATE) {
            std.debug.print("[SECURITY] Slowloris Detected: Rate {} B/s < {} B/s IP:{}\n", .{ rate, MIN_RATE, conn.real_ip_cached });
            return false;
        }
        return true;
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
