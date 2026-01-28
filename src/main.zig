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

    /// 内部连接元数据（存放重试次数等）
    const ConnMeta = struct {
        retries: u8 = 0,
    };

    pub fn onHeader(ptr: *anyopaque, engine: *reactor.Engine, slot: usize, data: []const u8) anyerror!bool {
        const self: *ProxyContext = @ptrCast(@alignCast(ptr));
        const conn = &engine.conn_pool[slot].?;

        // 1. 获取客户端 IP
        const socket_ip = blk: {
            var peer_storage: posix.sockaddr.storage = undefined;
            var peer_len: posix.socklen_t = @sizeOf(posix.sockaddr.storage);
            try posix.getpeername(conn.client_fd, @ptrCast(&peer_storage), &peer_len);
            const peer_net_addr = net.Address.initPosix(@ptrCast(&peer_storage));
            break :blk @byteSwap(peer_net_addr.in.sa.addr);
        };

        const real_ip = try extractRealIP(data, socket_ip);

        // 2. 安全检查
        if (try self.ip_index.isBlocked(real_ip)) return false;
        if (!(try self.rate_limiter.checkLimit(real_ip))) return false;

        // 3. 健康检查
        if (self.consecutive_failures >= HEALTH_THRESHOLD) {
            if (reactor.getMonotonicMs() - self.last_failure_time < COOLING_PERIOD_MS) {
                return false;
            }
        }

        // 4. 发起后端连接
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
            const msg = "HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nGatekeeper: Backend Unreachable after retries.";
            _ = posix.write(conn.client_fd, msg) catch {};
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
    if (socket_ip != 0x7F000001) return socket_ip;
    const cf_header = "CF-Connecting-IP: ";
    if (std.mem.indexOf(u8, buffer, cf_header)) |pos| {
        const start = pos + cf_header.len;
        if (std.mem.indexOfScalar(u8, buffer[start..], '\r')) |end_rel| {
            return index_mod.parseIPv4(buffer[start .. start + end_rel]);
        }
    }
    return socket_ip;
}
