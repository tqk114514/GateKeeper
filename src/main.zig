//! src/main.zig
//! Gatekeeper 安全网关服务主程序
//!
//! 功能：
//! - 监听本地 3001 端口接收 HTTP 请求
//! - 基于 IP 地址的简单黑名单拦截逻辑
//! - 针对非法 IP 返回自定义 "Oops" 拦截页面
//! - 针对合法 IP 将流量全双工转发至本地 3000 端口
//! - 使用标准库抽象，支持 Windows 和 Linux 跨平台运行
//!
//! 依赖：
//! - std.net: 网络通信
//! - std.posix: 跨平台系统调用
//! - std.Thread: 多线程并发处理

const std = @import("std");
const net = std.net;
const Thread = std.Thread;

/// std_options 全局配置
/// 禁用 SIGPIPE 以防止在 Linux 上写入已关闭的 Socket 时导致进程退出
pub const std_options = std.Options{
    .keep_sigpipe = false,
};

// ====================  常量定义 ====================

const LOCAL_PORT = 3001;
const TARGET_HOST = "127.0.0.1";
const TARGET_PORT = 3000;

/// SOCKET_TIMEOUT_MS Socket 读取超时时间（毫秒）
const SOCKET_TIMEOUT_MS = 30000; // 30 秒

/// MAX_CONNECTIONS 最大并发连接数限制，防止线程爆炸
const MAX_CONNECTIONS = 1024;
var connection_semaphore = std.Thread.Semaphore{ .permits = MAX_CONNECTIONS };

/// THREAD_STACK_SIZE 线程栈大小（字节）
/// 设置为 128KB 以减小 1024 个线程并发时的总虚拟内存占用（从 8GB 降至 ~128MB）
const THREAD_STACK_SIZE = 128 * 1024;

/// MAX_SESSION_DURATION_MS 全局会话超时时间（毫秒）
/// 无论是否有流量，连接超过此时间将被强制切断，防御 Slowloris 攻击
const MAX_SESSION_DURATION_MS = 60000; // 60 秒

/// BLOCK_HTML 拦截页面的 HTML 内容
const BLOCK_HTML = @embedFile("block.html");

/// BLOCK_RESPONSE 完整的 HTTP 拦截响应报文
const BLOCK_RESPONSE =
    "HTTP/1.1 200 OK\r\n" ++
    "Content-Type: text/html; charset=UTF-8\r\n" ++
    "Connection: close\r\n" ++
    "\r\n" ++
    BLOCK_HTML;

/// Direction 转发方向
const Direction = enum {
    client_to_server,
    server_to_client,

    pub fn toString(self: Direction) []const u8 {
        return switch (self) {
            .client_to_server => "C->S",
            .server_to_client => "S->C",
        };
    }
};

// ====================  结构体定义 ====================

/// PipeContext 管道上下文
/// 用于在双向转发线程间传递 Socket 句柄和连接信息
const PipeContext = struct {
    client: net.Stream,
    server: net.Stream,
    direction: Direction,
    initial_data: []const u8,
    initial_len: usize,
    start_time: i64,
};

// ====================  公开函数 ====================

/// main 程序主入口
/// 初始化服务端监听，循环接受连接并分发给工作线程
///
/// 返回：
///   - !void: 可能返回运行错误
pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const index_mod = @import("utils/index.zig");

    const index_path = "rules/blacklist.idx";
    const rules_dir = "rules";

    const needs_rebuild = blk: {
        const index_file = std.fs.cwd().openFile(index_path, .{}) catch {
            std.debug.print("Index file not found, building...\n", .{});
            break :blk true;
        };
        index_file.close();
        break :blk false;
    };

    if (needs_rebuild) {
        std.debug.print("Building IP blacklist index...\n", .{});
        try index_mod.buildIndex(allocator, rules_dir, index_path);
        std.debug.print("Index build complete!\n\n", .{});
    }

    var ip_index = try index_mod.IndexReader.init(allocator, index_path);
    defer ip_index.deinit();

    std.debug.print("IP blacklist loaded successfully\n", .{});

    const ratelimit_mod = @import("utils/ratelimit.zig");
    var rate_limiter = ratelimit_mod.RateLimiter.init(allocator);
    defer rate_limiter.deinit();

    std.debug.print("Rate limiter initialized (1s/5req, 10s/50req)\n", .{});

    // [FIX] 启动后台清理线程，防止僵尸 IP 记录导致内存泄漏 (OOM)
    const cleanup_thread = Thread.spawn(.{ .stack_size = THREAD_STACK_SIZE }, cleanupTask, .{&rate_limiter}) catch |err| {
        std.debug.print("[WARN] Failed to spawn cleanup thread: {any}\n", .{err});
        return err;
    };
    cleanup_thread.detach();

    const address = try net.Address.parseIp4("0.0.0.0", LOCAL_PORT);
    var server = try address.listen(.{ .reuse_address = true });
    defer server.deinit();

    std.debug.print("Gatekeeper listening on port {d}\n", .{LOCAL_PORT});
    std.debug.print("Target service: {s}:{d}\n\n", .{ TARGET_HOST, TARGET_PORT });

    while (true) {
        const connection = server.accept() catch |err| {
            std.debug.print("Failed to accept connection: {any}\n", .{err});
            continue;
        };

        // [OPTIMIZATION] 使用 timedWait(0) 模拟 tryWait()，避免阻塞主线程
        // 如果连接数达到上限，立即进行 Load Shedding（负载卸载），而不是让主进程“假死”
        connection_semaphore.timedWait(0) catch |err| {
            if (err == error.Timeout) {
                std.debug.print("[LOAD_SHEDDING] Server at capacity ({d}), immediate close\n", .{MAX_CONNECTIONS});
                // [CRITICAL] 不在主线程进行 writeAll，防止恶意客户端通过 0 窗口阻塞主循环
                connection.stream.close();
                continue;
            }
            // 其他错误（如系统级信号中断）
            std.debug.print("Semaphore error: {any}\n", .{err});
            connection.stream.close();
            continue;
        };

        const thread = Thread.spawn(.{ .stack_size = THREAD_STACK_SIZE }, handleConnection, .{ allocator, connection, &ip_index, &rate_limiter }) catch |err| {
            std.debug.print("Failed to spawn thread: {any}\n", .{err});
            connection.stream.close();
            connection_semaphore.post();
            continue;
        };
        thread.detach();
    }
}

// ====================  私有函数 ====================

/// setSocketTimeout 设置 Socket 读取超时
/// 跨平台实现，适配 Windows 和 POSIX
fn setSocketTimeout(handle: std.posix.socket_t, timeout_ms: u32) !void {
    if (@import("builtin").os.tag == .windows) {
        const timeout = timeout_ms;
        try std.posix.setsockopt(handle, 0xFFFF, 0x1006, std.mem.asBytes(&timeout));
    } else {
        const timeout = std.posix.timeval{
            .tv_sec = @intCast(timeout_ms / 1000),
            .tv_usec = @intCast((timeout_ms % 1000) * 1000),
        };
        try std.posix.setsockopt(handle, std.posix.SOL.SOCKET, std.posix.SO.RCVTIMEO, std.mem.asBytes(&timeout));
    }
}

/// sendBlockedResponse 发送拦截响应（零分配优化版）
/// 使用分块写入避免在堆上生成完整的 HTML 字符串
fn sendBlockedResponse(stream: net.Stream, ip: u32, status_code: []const u8) !void {
    const placeholder = "{{CLIENT_IP}}";
    const pos = std.mem.indexOf(u8, BLOCK_HTML, placeholder) orelse {
        // 如果没找到占位符，直接发送原始 HTML
        try stream.writeAll(status_code);
        try stream.writeAll("Content-Type: text/html; charset=UTF-8\r\nConnection: close\r\n\r\n");
        try stream.writeAll(BLOCK_HTML);
        return;
    };

    var ip_buf: [16]u8 = undefined;
    const ip_str = try std.fmt.bufPrint(&ip_buf, "{d}.{d}.{d}.{d}", .{
        (ip >> 24) & 0xFF,
        (ip >> 16) & 0xFF,
        (ip >> 8) & 0xFF,
        ip & 0xFF,
    });

    try stream.writeAll(status_code);
    try stream.writeAll("Content-Type: text/html; charset=UTF-8\r\nConnection: close\r\n\r\n");

    // 分三段写入，避免堆分配
    try stream.writeAll(BLOCK_HTML[0..pos]);
    try stream.writeAll(ip_str);
    try stream.writeAll(BLOCK_HTML[pos + placeholder.len ..]);
}

/// getMonotonicMs 获取当前单调时间（毫秒）
fn getMonotonicMs() i64 {
    return @intCast(@divTrunc(std.time.nanoTimestamp(), std.time.ns_per_ms));
}

/// extractRealIP 从 HTTP 请求头中提取真实客户端 IP
/// 专门针对 Cloudflare Tunnel 环境设计
///
/// 参数：
///   - buffer: 包含请求数据的缓冲区
///   - socket_ip: TCP 层获取的原始 IP
///
/// 返回：
///   - u32: 探测到的真实 IP (如果探测失败则回退至 socket_ip)
fn extractRealIP(buffer: []const u8, socket_ip: u32) !u32 {
    const index_mod = @import("utils/index.zig");

    // [SECURITY] 仅当连接来自 127.0.0.1 (cloudflared 隧道) 时才处理标头
    const is_tunnel = (socket_ip == 0x7F000001);

    const cf_header = "cf-connecting-ip: ";
    if (std.mem.indexOf(u8, buffer, cf_header)) |pos| {
        const start = pos + cf_header.len;
        if (std.mem.indexOfScalar(u8, buffer[start..], '\r')) |end_rel| {
            const ip_str = buffer[start .. start + end_rel];
            if (index_mod.parseIPv4(ip_str)) |parsed_ip| {
                return parsed_ip;
            } else |_| {}
        }
    }

    // 回退方案：寻找标准的 X-Forwarded-For
    const xff_header = "x-forwarded-for: ";
    if (std.mem.indexOf(u8, buffer, xff_header)) |pos| {
        const start = pos + xff_header.len;
        if (std.mem.indexOfScalar(u8, buffer[start..], '\r')) |end_rel| {
            var line = buffer[start .. start + end_rel];
            if (std.mem.indexOfScalar(u8, line, ',')) |comma_pos| {
                line = line[0..comma_pos];
            }
            if (index_mod.parseIPv4(line)) |parsed_ip| {
                return parsed_ip;
            } else |_| {}
        }
    }

    // [CRITICAL] 如果是隧道连接但没找到有效标头，必须报错拒绝，防止回退到 127.0.0.1 导致 DoS
    if (is_tunnel) return error.MissingRequiredHeader;

    return socket_ip;
}

/// handleConnection 处理单个客户端连接
/// 执行 IP 过滤和流量转发逻辑
fn handleConnection(allocator: std.mem.Allocator, client_conn: net.Server.Connection, ip_index: *@import("utils/index.zig").IndexReader, rate_limiter: *@import("utils/ratelimit.zig").RateLimiter) void {
    defer client_conn.stream.close();
    defer connection_semaphore.post(); // 释放许可，允许新连接进入

    const start_time = getMonotonicMs();

    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const arena_allocator = arena.allocator();

    const index_mod = @import("utils/index.zig");

    // 1. 获取 TCP 层原始 IP (内网穿透环境下通常是 127.0.0.1)
    const socket_ip = index_mod.ipFromAddress(client_conn.address) catch 0x7F000001;

    // [SECURITY] 增加缓冲区至 16KB，防止攻击者通过超大头部将 IP 字段挤出探测窗口
    var buffer: [16384]u8 = undefined;
    setSocketTimeout(client_conn.stream.handle, SOCKET_TIMEOUT_MS) catch {};

    // 2. 预读数据以提取 Cloudflare 注入的真实访客 IP
    const bytes_read = client_conn.stream.read(&buffer) catch 0;
    const client_ip = extractRealIP(buffer[0..bytes_read], socket_ip) catch |err| {
        // [CRITICAL] 识别失败（如隧道连接缺少标头），立即中断，防止 127.0.0.1 回退 DoS
        std.debug.print("[SECURITY_EVENT] IP extraction failed: {any}. Force close.\n", .{err});
        return;
    };

    if (client_ip != socket_ip) {
        std.debug.print("[CF_DETECTED] Real Visitor IP: {d}.{d}.{d}.{d}\n", .{
            (client_ip >> 24) & 0xFF,
            (client_ip >> 16) & 0xFF,
            (client_ip >> 8) & 0xFF,
            client_ip & 0xFF,
        });
    }

    // 3. 执行黑名单检查
    const is_blocked = ip_index.isBlocked(client_ip) catch false;
    if (is_blocked) {
        std.debug.print("[BLOCK] IP blocked: {d}.{d}.{d}.{d}\n", .{
            (client_ip >> 24) & 0xFF,
            (client_ip >> 16) & 0xFF,
            (client_ip >> 8) & 0xFF,
            client_ip & 0xFF,
        });
        sendBlockedResponse(client_conn.stream, client_ip, "HTTP/1.1 200 OK\r\n") catch {};
        return;
    }

    // 4. 执行速率限制检查
    const rate_ok = rate_limiter.checkLimit(client_ip) catch false;
    if (!rate_ok) {
        std.debug.print("[RATE_LIMIT] IP exceeded rate limit: {d}.{d}.{d}.{d}\n", .{
            (client_ip >> 24) & 0xFF,
            (client_ip >> 16) & 0xFF,
            (client_ip >> 8) & 0xFF,
            client_ip & 0xFF,
        });
        sendBlockedResponse(client_conn.stream, client_ip, "HTTP/1.1 429 Too Many Requests\r\n") catch {};
        return;
    }

    // 转发逻辑
    std.debug.print("[ALLOW] Forwarding to backend\n", .{});

    // 连接后端服务
    const target_stream = net.tcpConnectToHost(arena_allocator, TARGET_HOST, TARGET_PORT) catch |err| {
        std.debug.print("Failed to connect to backend: {any}\n", .{err});
        _ = client_conn.stream.write("HTTP/1.1 502 Bad Gateway\r\n\r\nService Unavailable") catch {};
        return;
    };
    defer target_stream.close();

    setSocketTimeout(target_stream.handle, SOCKET_TIMEOUT_MS) catch {};

    const initial_data_heap = if (bytes_read > 0)
        arena_allocator.dupe(u8, buffer[0..bytes_read]) catch {
            std.debug.print("[ERROR] Out of memory when duping initial data\n", .{});
            return;
        }
    else
        &[_]u8{};

    const ctx_c2s = PipeContext{
        .client = client_conn.stream,
        .server = target_stream,
        .direction = .client_to_server,
        .initial_data = initial_data_heap,
        .initial_len = bytes_read,
        .start_time = start_time,
    };

    const ctx_s2c = PipeContext{
        .client = client_conn.stream,
        .server = target_stream,
        .direction = .server_to_client,
        .initial_data = &[_]u8{},
        .initial_len = 0,
        .start_time = start_time,
    };

    const t1 = Thread.spawn(.{ .stack_size = THREAD_STACK_SIZE }, forwardStreamWithContext, .{ctx_c2s}) catch return;

    forwardStreamWithContext(ctx_s2c);

    // [FIX] 强制关闭 Socket 以唤醒阻塞在 read() 上的另一个线程
    // 避免因为一方连接挂起导致的线程死锁（Zombie Thread Deadlock）
    std.posix.shutdown(client_conn.stream.handle, .both) catch {};
    std.posix.shutdown(target_stream.handle, .both) catch {};

    t1.join();
}

/// forwardStreamWithContext 转发 TCP 数据流（带上下文信息）
/// 阻塞式地从 reader 读取数据并写入 writer，包含断开日志和 IP 动态拉黑检测
fn forwardStreamWithContext(ctx: PipeContext) void {
    const reader = if (ctx.direction == .client_to_server) ctx.client else ctx.server;
    const writer = if (ctx.direction == .client_to_server) ctx.server else ctx.client;

    var buffer: [4096]u8 = undefined;
    var total_bytes: usize = 0;

    const dir_str = ctx.direction.toString();

    if (ctx.initial_len > 0) {
        _ = writer.write(ctx.initial_data[0..ctx.initial_len]) catch {
            std.debug.print("[{s}] Failed to send initial data\n", .{dir_str});
            return;
        };
        total_bytes += ctx.initial_len;
        std.debug.print("[{s}] Sent initial {d} bytes\n", .{ dir_str, ctx.initial_len });
    }

    while (true) {
        // [SLOWLORIS PROTECTION] 检查全局会话超时
        if (getMonotonicMs() - ctx.start_time > MAX_SESSION_DURATION_MS) {
            std.debug.print("[{s}] Session deadline reached (Slowloris protection). Transferred {d} bytes.\n", .{ dir_str, total_bytes });
            break;
        }

        const bytes_read = reader.read(&buffer) catch |err| {
            if (err == error.WouldBlock or err == error.ConnectionTimedOut) {
                std.debug.print("[{s}] Connection timeout ({d} bytes transferred)\n", .{ dir_str, total_bytes });
            } else {
                std.debug.print("[{s}] Read error: {any} ({d} bytes transferred)\n", .{ dir_str, err, total_bytes });
            }
            break;
        };

        if (bytes_read == 0) {
            std.debug.print("[{s}] Connection closed gracefully ({d} bytes transferred)\n", .{ dir_str, total_bytes });
            break;
        }

        total_bytes += bytes_read;

        _ = writer.write(buffer[0..bytes_read]) catch |err| {
            std.debug.print("[{s}] Send error: {any} ({d} bytes transferred)\n", .{ dir_str, err, total_bytes });
            break;
        };
    }
}

/// cleanupTask 后台清理任务
/// 每分钟运行一次，清理速率限制器中的过期 IP 记录
fn cleanupTask(rate_limiter: *@import("utils/ratelimit.zig").RateLimiter) void {
    while (true) {
        // 每 60 秒执行一次清理
        std.Thread.sleep(60 * std.time.ns_per_s);
        rate_limiter.cleanup();
        std.debug.print("[CLEANUP] Rate limiter records pruned. Current active IPs: {d}\n", .{rate_limiter.getStats()});
    }
}
