//! src/reactor/mod.zig
//! Reactor 核心引擎模块
//!
//! 功能：
//! - 高性能 I/O 多路复用 (Linux: epoll, Others: poll)
//! - 维护 TCP 连接全双工转发状态机

const std = @import("std");
const net = std.net;
const mem = std.mem;
const posix = std.posix;
const builtin = @import("builtin");

const is_win = builtin.os.tag == .windows;
const is_linux = builtin.os.tag == .linux;
pub const invalid_sock = if (is_win) @as(posix.socket_t, @ptrFromInt(@as(usize, ~@as(usize, 0)))) else -1;

pub fn isInvalid(fd: posix.socket_t) bool {
    return fd == invalid_sock;
}

pub const ConnKind = enum { listener, client, server };
pub const ConnState = enum {
    HEADER_PENDING, // 等待读入足以探测 IP 的头部数据
    BACKEND_CONNECTING, // 正在异步建立后端连接
    PUMPING, // 正常双向转发数据
    FLUSHING, // 发送剩余数据后关闭 (Graceful Shutdown)
    CLOSING, // 标记为关闭，等待清理
};

/// Connection 连接上下文
pub const Connection = struct {
    pub const BUFFER_SIZE = 16 * 1024;

    client_fd: posix.socket_t,
    server_fd: posix.socket_t = invalid_sock,
    state: ConnState = .HEADER_PENDING,

    c2s_buf: [BUFFER_SIZE]u8 = undefined,
    c2s_len: usize = 0,
    c2s_sent: usize = 0,

    s2c_buf: [BUFFER_SIZE]u8 = undefined,
    s2c_len: usize = 0,
    s2c_sent: usize = 0,

    start_time: i64,
    last_activity: i64,
    real_ip_cached: u32 = 0,

    // 业务预留：允许上层存放自定义数据（如重试次数等）
    context: ?*anyopaque = null,

    pub fn close(self: *Connection) void {
        if (!isInvalid(self.client_fd)) {
            posix.close(self.client_fd);
            self.client_fd = invalid_sock;
        }
        if (!isInvalid(self.server_fd)) {
            posix.close(self.server_fd);
            self.server_fd = invalid_sock;
        }
    }
};

/// EventHandler 业务逻辑处理接口
pub const EventHandler = struct {
    ptr: *anyopaque,
    // 当收到第一波数据，由上层决定是否允许连接，并启动后端连接
    onHeader: *const fn (ctx: *anyopaque, engine: *Engine, slot: usize, data: []const u8) anyerror!bool,
    // 当数据在 PUMPING 阶段从客户端流向服务端时，允许上层进行二次检查（如探测新请求）
    onPumping: *const fn (ctx: *anyopaque, engine: *Engine, slot: usize, data: []const u8) anyerror!bool,
    // 当后端连接出事（失败/断开）时的处理逻辑
    onBackendError: *const fn (ctx: *anyopaque, engine: *Engine, slot: usize) anyerror!void,
    // 定期检查连接是否健康 (Slowloris 防御 hook)
    onKeepAlive: *const fn (ctx: *anyopaque, engine: *Engine, slot: usize) anyerror!bool,
    // [New] 连接销毁时的清理回调 (防止内存泄漏)
    onCleanup: ?*const fn (ctx: *anyopaque, engine: *Engine, slot: usize) void = null,
};

/// Engine 反应器引擎
pub const Engine = struct {
    allocator: mem.Allocator,
    max_connections: usize,
    buffer_size: usize,

    // 多路复用后端
    backend_fd: if (is_linux) posix.fd_t else void = if (is_linux) undefined else {},
    epoll_events: if (is_linux) []std.os.linux.epoll_event else void = if (is_linux) undefined else {},

    poll_fds: if (!is_linux) []posix.pollfd else void = if (!is_linux) undefined else {},

    poll_meta: []PollMeta,
    poll_count: usize = 0,

    conn_pool: []?Connection,
    handler: EventHandler,

    const PollMeta = struct {
        slot_index: usize,
        kind: ConnKind,
        fd: posix.socket_t,
    };

    pub fn init(
        allocator: mem.Allocator,
        max_conns: usize,
        buf_size: usize,
        handler: EventHandler,
    ) !Engine {
        const pool = try allocator.alloc(?Connection, max_conns);
        @memset(pool, null);

        const poll_cap = max_conns * 2 + 1;
        const meta = try allocator.alloc(PollMeta, poll_cap);

        var self = Engine{
            .allocator = allocator,
            .max_connections = max_conns,
            .buffer_size = buf_size,
            .poll_meta = meta,
            .conn_pool = pool,
            .handler = handler,
            .poll_count = 0,
        };

        if (comptime is_linux) {
            self.backend_fd = try posix.epoll_create1(0);
            self.epoll_events = try allocator.alloc(std.os.linux.epoll_event, poll_cap);
        } else {
            self.poll_fds = try allocator.alloc(posix.pollfd, poll_cap);
        }

        return self;
    }

    pub fn deinit(self: *Engine) void {
        for (self.conn_pool) |*c| {
            if (c.*) |*conn| conn.close();
        }
        if (comptime is_linux) {
            posix.close(self.backend_fd);
            self.allocator.free(self.epoll_events);
        } else {
            self.allocator.free(self.poll_fds);
        }
        self.allocator.free(self.conn_pool);
        self.allocator.free(self.poll_meta);
    }

    pub fn findFreeSlot(self: Engine) ?usize {
        for (self.conn_pool, 0..) |c, i| if (c == null) return i;
        return null;
    }

    pub fn addFD(self: *Engine, fd: posix.socket_t, slot: usize, kind: ConnKind) !void {
        if (self.poll_count >= self.poll_meta.len) return error.PollCapacityReached;
        const idx = self.poll_count;
        self.poll_meta[idx] = .{ .slot_index = slot, .kind = kind, .fd = fd };

        if (comptime is_linux) {
            const kind_val: u32 = if (kind == .client) 1 else if (kind == .server) 2 else 0;
            const tag: u32 = (@as(u32, @intCast(slot)) + 1) << 2 | kind_val;
            var ev = std.os.linux.epoll_event{
                .events = std.os.linux.EPOLL.IN | std.os.linux.EPOLL.OUT | std.os.linux.EPOLL.RDHUP,
                .data = .{ .u32 = tag },
            };
            try posix.epoll_ctl(self.backend_fd, std.os.linux.EPOLL.CTL_ADD, fd, &ev);
        } else {
            self.poll_fds[idx] = .{ .fd = fd, .events = posix.POLL.IN, .revents = 0 };
        }
        self.poll_count += 1;
    }

    pub fn removeFDByFD(self: *Engine, fd: posix.socket_t) void {
        var i: usize = 0;
        while (i < self.poll_count) {
            if (self.poll_meta[i].fd == fd) {
                if (comptime is_linux) posix.epoll_ctl(self.backend_fd, std.os.linux.EPOLL.CTL_DEL, fd, null) catch {};
                if (i < self.poll_count - 1) {
                    const last_idx = self.poll_count - 1;
                    self.poll_meta[i] = self.poll_meta[last_idx];
                    if (comptime !is_linux) self.poll_fds[i] = self.poll_fds[last_idx];
                }
                self.poll_count -= 1;
                return;
            }
            i += 1;
        }
    }

    pub fn removeFDsForSlot(self: *Engine, slot: usize) void {
        // [Lifecycle] 1. Notify Application to Clean Up User Context
        if (self.handler.onCleanup) |cleanup| {
            cleanup(self.handler.ptr, self, slot);
        }

        // [Lifecycle] 2. Remove associated FDs from Poller
        var i: usize = 1;
        while (i < self.poll_count) {
            if (self.poll_meta[i].slot_index == slot) {
                const fd = self.poll_meta[i].fd;
                if (comptime is_linux) posix.epoll_ctl(self.backend_fd, std.os.linux.EPOLL.CTL_DEL, fd, null) catch {};

                // Swap with last element to remove in O(1)
                const last = self.poll_count - 1;
                if (i < last) {
                    self.poll_meta[i] = self.poll_meta[last];
                    if (comptime !is_linux) self.poll_fds[i] = self.poll_fds[last];
                    // Do not increment i, check the swapped-in element next loop
                }
                self.poll_count -= 1;
            } else {
                i += 1;
            }
        }

        // [Lifecycle] 3. Close Socket and Free Slot
        if (self.conn_pool[slot]) |*c| c.close();
        self.conn_pool[slot] = null;
    }

    pub fn run(self: *Engine, timeout: i32) !void {
        if (comptime is_linux) {
            const n = posix.epoll_wait(self.backend_fd, self.epoll_events, timeout);
            for (self.epoll_events[0..n]) |ev| {
                const tag = ev.data.u32;
                if (tag == 0) {
                    try self.handleAccept();
                    continue;
                }
                const slot = (tag >> 2) - 1;
                const kind_val = tag & 0x3;
                if (self.conn_pool[slot] == null) continue;
                const revents = self.translateEpollEvents(ev.events);
                _ = try self.handleEventBySlot(slot, if (kind_val == 1) .client else .server, revents);
            }
            self.checkTimeouts();
        } else {
            _ = try posix.poll(self.poll_fds[0..self.poll_count], timeout);
            if (self.poll_fds[0].revents & posix.POLL.IN != 0) try self.handleAccept();
            var i: usize = 1;
            while (i < self.poll_count) {
                const revents = self.poll_fds[i].revents;
                const meta = self.poll_meta[i];
                var keep = true;
                if (revents != 0) keep = self.handleEvent(i, revents) catch false;
                var timeout_ms: i64 = 30_000;
                if (self.conn_pool[meta.slot_index].?.state == .HEADER_PENDING) timeout_ms = 5_000;
                if (keep and getMonotonicMs() - self.conn_pool[meta.slot_index].?.last_activity > timeout_ms) keep = false;
                if (!keep) {
                    self.removeFDsForSlot(meta.slot_index);
                    i = 1;
                } else {
                    self.updatePollEvents(i);
                    i += 1;
                }
            }
        }
    }

    fn checkTimeouts(self: *Engine) void {
        var i: usize = 1;
        const now = getMonotonicMs();
        while (i < self.poll_count) {
            const meta = self.poll_meta[i];
            const conn = &self.conn_pool[meta.slot_index].?;
            var timeout_ms: i64 = 30_000;
            if (conn.state == .HEADER_PENDING) timeout_ms = 5_000; // Slowloris mitigation

            var keep = true;
            if (now - conn.last_activity > timeout_ms) {
                keep = false;
            } else {
                // Business Logic Check (e.g. Min Data Rate)
                keep = self.handler.onKeepAlive(self.handler.ptr, self, meta.slot_index) catch false;
            }

            if (!keep) {
                self.removeFDsForSlot(meta.slot_index);
                i = 1;
            } else {
                self.updatePollEvents(i);
                i += 1;
            }
        }
    }

    fn translateEpollEvents(self: Engine, events: u32) i16 {
        _ = self;
        var res: i16 = 0;
        if (events & std.os.linux.EPOLL.IN != 0) res |= posix.POLL.IN;
        if (events & std.os.linux.EPOLL.OUT != 0) res |= posix.POLL.OUT;
        if (events & (std.os.linux.EPOLL.ERR | std.os.linux.EPOLL.HUP | std.os.linux.EPOLL.RDHUP) != 0) res |= posix.POLL.HUP;
        return res;
    }

    fn handleAccept(self: *Engine) !void {
        var addr: posix.sockaddr = undefined;
        var addr_len: posix.socklen_t = @intCast(@sizeOf(posix.sockaddr));
        const listen_fd = if (is_linux) self.poll_meta[0].fd else self.poll_fds[0].fd;
        while (true) {
            const fd = posix.accept(listen_fd, &addr, &addr_len, posix.SOCK.NONBLOCK) catch |err| {
                if (err == error.WouldBlock) return;
                return err;
            };
            const slot = self.findFreeSlot() orelse {
                posix.close(fd);
                return;
            };
            const now = getMonotonicMs();
            self.conn_pool[slot] = Connection{ .client_fd = fd, .start_time = now, .last_activity = now };
            try self.addFD(fd, slot, .client);
        }
    }

    fn handleEvent(self: *Engine, index: usize, revents: i16) !bool {
        const meta = self.poll_meta[index];
        return self.handleEventBySlot(meta.slot_index, meta.kind, revents);
    }

    fn handleEventBySlot(self: *Engine, slot_index: usize, kind: ConnKind, revents: i16) !bool {
        var conn = &self.conn_pool[slot_index].?;
        if (revents & (posix.POLL.ERR | posix.POLL.HUP) != 0) return false;

        switch (conn.state) {
            .HEADER_PENDING => if (revents & posix.POLL.IN != 0) {
                const n = try posix.recv(conn.client_fd, &conn.c2s_buf, 0);
                if (n == 0) return false;
                conn.c2s_len = n;
                conn.last_activity = getMonotonicMs();
                if (!(try self.handler.onHeader(self.handler.ptr, self, slot_index, conn.c2s_buf[0..n]))) return false;
            },
            .BACKEND_CONNECTING => if (kind == .server and (revents & posix.POLL.OUT != 0)) {
                var err_val: c_int = 0;
                var err_len: i32 = @sizeOf(c_int);
                if (comptime is_win) _ = std.os.windows.ws2_32.getsockopt(conn.server_fd, posix.SOL.SOCKET, posix.SO.ERROR, mem.asBytes(&err_val), &err_len) else try posix.getsockopt(conn.server_fd, posix.SOL.SOCKET, posix.SO.ERROR, mem.asBytes(&err_val));
                if (err_val != 0) {
                    try self.handler.onBackendError(self.handler.ptr, self, slot_index);
                    return true;
                }
                conn.state = .PUMPING;
                conn.last_activity = getMonotonicMs();
            },
            .PUMPING => {
                const src_fd = if (kind == .client) conn.client_fd else conn.server_fd;
                if (revents & posix.POLL.IN != 0) {
                    const buf = if (kind == .client) &conn.c2s_buf else &conn.s2c_buf;
                    const len = if (kind == .client) &conn.c2s_len else &conn.s2c_len;
                    const n = posix.recv(src_fd, buf[len.*..], 0) catch 0;
                    if (n == 0) return false;
                    if (n > 0) {
                        if (kind == .client) {
                            // 允许上层业务逻辑在转发过程中探测新的 HTTP 请求
                            if (!(try self.handler.onPumping(self.handler.ptr, self, slot_index, buf[len.* .. len.* + n]))) return false;
                        }
                        len.* += n;
                        conn.last_activity = getMonotonicMs();
                    }
                }
                if (revents & posix.POLL.OUT != 0) {
                    const buf = if (kind == .client) &conn.s2c_buf else &conn.c2s_buf;
                    const len = if (kind == .client) &conn.s2c_len else &conn.c2s_len;
                    const sent = if (kind == .client) &conn.s2c_sent else &conn.c2s_sent;
                    const n = posix.send(src_fd, buf[sent.*..len.*], 0) catch 0;
                    if (n > 0) {
                        sent.* += n;
                        conn.last_activity = getMonotonicMs();
                        if (sent.* == len.*) {
                            sent.* = 0;
                            len.* = 0;
                        }
                    }
                }
            },
            .FLUSHING => {
                // FLUSHING 状态下，只关注将 s2c_buf 发送给 Client
                if (kind == .client and (revents & posix.POLL.OUT != 0)) {
                    const buf = &conn.s2c_buf;
                    const len = conn.s2c_len;
                    const sent = &conn.s2c_sent;

                    const n = posix.send(conn.client_fd, buf[sent.*..len], 0) catch 0;
                    if (n > 0) {
                        sent.* += n;
                        conn.last_activity = getMonotonicMs();
                        if (sent.* == len) {
                            // 全部发送完毕，进入 CLOSING
                            conn.state = .CLOSING;
                        }
                    }
                }
            },
            else => {},
        }
        return true;
    }

    fn updatePollEvents(self: *Engine, index: usize) void {
        const meta = self.poll_meta[index];
        const conn = self.conn_pool[meta.slot_index] orelse return;
        var desired_events: u16 = 0;
        switch (conn.state) {
            .HEADER_PENDING => if (meta.kind == .client) {
                desired_events = posix.POLL.IN;
            },
            .BACKEND_CONNECTING => if (meta.kind == .server) {
                desired_events = posix.POLL.OUT;
            },
            .PUMPING => {
                const out_len = if (meta.kind == .client) conn.s2c_len else conn.c2s_len;
                const out_sent = if (meta.kind == .client) conn.s2c_sent else conn.c2s_sent;
                if (out_len > out_sent) desired_events |= posix.POLL.OUT;

                // Allow POLLIN if buffer has space
                const in_len = if (meta.kind == .client) conn.c2s_len else conn.s2c_len;
                if (in_len < self.buffer_size) desired_events |= posix.POLL.IN;
            },
            .FLUSHING => if (meta.kind == .client) {
                if (conn.s2c_len > conn.s2c_sent) desired_events |= posix.POLL.OUT;
            },
            else => {},
        }
        if (comptime is_linux) {
            const kind_val: u32 = if (meta.kind == .client) 1 else if (meta.kind == .server) 2 else 0;
            var ev = std.os.linux.epoll_event{
                .events = std.os.linux.EPOLL.RDHUP,
                .data = .{ .u32 = (@as(u32, @intCast(meta.slot_index)) + 1) << 2 | kind_val },
            };
            if (desired_events & posix.POLL.IN != 0) ev.events |= std.os.linux.EPOLL.IN;
            if (desired_events & posix.POLL.OUT != 0) ev.events |= std.os.linux.EPOLL.OUT;
            posix.epoll_ctl(self.backend_fd, std.os.linux.EPOLL.CTL_MOD, meta.fd, &ev) catch {};
        } else {
            self.poll_fds[index].events = @intCast(desired_events);
        }
    }
};

pub fn setNonBlock(fd: posix.socket_t) !void {
    if (comptime is_win) {
        var mode: u32 = 1;
        _ = std.os.windows.ws2_32.ioctlsocket(fd, @bitCast(@as(u32, 0x8004667E)), &mode);
    } else {
        const flags = try posix.fcntl(fd, posix.F.GETFL, 0);
        _ = try posix.fcntl(fd, posix.F.SETFL, flags | posix.SOCK.NONBLOCK);
    }
}

pub fn getMonotonicMs() i64 {
    return @intCast(@divTrunc(std.time.nanoTimestamp(), std.time.ns_per_ms));
}
