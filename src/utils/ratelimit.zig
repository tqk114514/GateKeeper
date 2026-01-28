//! src/utils/ratelimit.zig
//! 请求频率限制模块
//!
//! 功能：
//! - 基于滑动窗口算法的速率限制
//! - 双层限制：1秒/5次 + 10秒/50次
//! - 线程安全的 IP 请求跟踪
//! - 自动清理过期记录

const std = @import("std");
const mem = std.mem;

// ====================  常量定义 ====================

/// SHORT_WINDOW_MS 短期窗口时间（毫秒）
const SHORT_WINDOW_MS: i64 = 1000; // 1 秒

/// SHORT_LIMIT 短期窗口请求限制
const SHORT_LIMIT: usize = 5;

/// LONG_WINDOW_MS 长期窗口时间（毫秒）
const LONG_WINDOW_MS: i64 = 10000; // 10 秒

/// LONG_LIMIT 长期窗口请求限制
const LONG_LIMIT: usize = 50;

/// CLEANUP_THRESHOLD 清理阈值（秒）
const CLEANUP_THRESHOLD: i64 = 60; // 60 秒未活动则清理

// ====================  辅助函数 ====================

/// getMonotonicMs 获取当前的单调毫秒时间戳
/// 使用单调时钟（Monotonic Clock）避免 NTP 时钟回拨影响
fn getMonotonicMs() i64 {
    return @intCast(@divTrunc(std.time.nanoTimestamp(), std.time.ns_per_ms));
}

// ====================  结构体定义 ====================

/// IPRecord IP 请求记录（优化版：使用头索引避免频繁数组移动）
const IPRecord = struct {
    timestamps: std.ArrayListUnmanaged(i64),
    head: usize, // 有效数据的起始索引
    last_access: i64,
    allocator: mem.Allocator,

    fn init(allocator: mem.Allocator) IPRecord {
        return .{
            .timestamps = .{},
            .head = 0,
            .last_access = getMonotonicMs(),
            .allocator = allocator,
        };
    }

    fn deinit(self: *IPRecord) void {
        self.timestamps.deinit(self.allocator);
    }

    /// getValidSlice 获取有效的时间戳切片
    fn getValidSlice(self: *IPRecord) []i64 {
        return self.timestamps.items[self.head..];
    }

    /// compact 压缩数组，移除过期数据
    /// 当 head 索引过大时调用以回收内存
    fn compact(self: *IPRecord) !void {
        if (self.head == 0) return;

        const valid_slice = self.getValidSlice();
        if (valid_slice.len == 0) {
            self.timestamps.clearRetainingCapacity();
            self.head = 0;
            return;
        }

        std.mem.copyForwards(i64, self.timestamps.items[0..valid_slice.len], valid_slice);
        self.timestamps.shrinkRetainingCapacity(valid_slice.len);
        self.head = 0;
    }
};

/// SHARD_COUNT 分片数量（使用 IP 第一个字节作为分片键）
const SHARD_COUNT = 256;

/// Shard 单个分片
const Shard = struct {
    map: std.AutoHashMap(u32, IPRecord),
    mutex: std.Thread.Mutex,

    fn init(allocator: mem.Allocator) Shard {
        return .{
            .map = std.AutoHashMap(u32, IPRecord).init(allocator),
            .mutex = .{},
        };
    }

    fn deinit(self: *Shard) void {
        var iter = self.map.valueIterator();
        while (iter.next()) |record| {
            record.deinit();
        }
        self.map.deinit();
    }
};

/// RateLimiter 速率限制器（分片锁版本）
pub const RateLimiter = struct {
    shards: [SHARD_COUNT]Shard,
    allocator: mem.Allocator,

    /// init 初始化速率限制器
    ///
    /// 参数：
    ///   - allocator: 内存分配器
    ///
    /// 返回：
    ///   - RateLimiter: 初始化的限制器
    pub fn init(allocator: mem.Allocator) RateLimiter {
        var shards: [SHARD_COUNT]Shard = undefined;
        for (&shards) |*shard| {
            shard.* = Shard.init(allocator);
        }

        return .{
            .shards = shards,
            .allocator = allocator,
        };
    }

    /// deinit 清理资源
    pub fn deinit(self: *RateLimiter) void {
        for (&self.shards) |*shard| {
            shard.deinit();
        }
    }

    /// getShard 根据 IP 获取对应的分片
    fn getShard(self: *RateLimiter, ip: u32) *Shard {
        const shard_idx = @as(usize, @intCast((ip >> 24) & 0xFF));
        return &self.shards[shard_idx];
    }

    /// checkLimit 检查 IP 是否超过速率限制
    /// 线程安全：使用分片锁减少竞争
    ///
    /// 参数：
    ///   - ip: 客户端 IP 地址
    ///
    /// 返回：
    ///   - bool: true 表示允许请求，false 表示超限
    pub fn checkLimit(self: *RateLimiter, ip: u32) !bool {
        const shard = self.getShard(ip);

        shard.mutex.lock();
        defer shard.mutex.unlock();

        const now = getMonotonicMs();

        const record = shard.map.get(ip);

        const MAX_IPS_PER_SHARD = 10000;

        if (record == null) {
            // 内存熔断保护：如果当前 Shard 追踪 IP 数过多，触发紧急清理
            if (shard.map.count() >= MAX_IPS_PER_SHARD) {
                // Fail Closed 策略：
                // 当分片已满且没有过期条目被 cleanupTask 清理掉时，说明遭受了持续的高强度攻击。
                // 此时拒绝追踪新 IP（直接视为被限流/拒绝服务）是保护系统内存和现有限流状态的唯一安全手段。
                // 绝对不能清空 Map，否则攻击者会利用它重置自己的计数器。
                return false;
            }

            var new_record = IPRecord.init(self.allocator);
            try new_record.timestamps.append(self.allocator, now);
            try shard.map.put(ip, new_record);
            return true;
        }

        var rec = shard.map.getPtr(ip).?;
        rec.last_access = now;

        const cutoff_long = if (now < LONG_WINDOW_MS) 0 else now - LONG_WINDOW_MS;

        // O(1) 更新 head 索引，跳过过期时间戳
        while (rec.head < rec.timestamps.items.len and rec.timestamps.items[rec.head] < cutoff_long) {
            rec.head += 1;
        }

        // 定期压缩：当浪费空间超过 50% 时
        if (rec.head > rec.timestamps.items.len / 2) {
            try rec.compact();
        }

        const valid_timestamps = rec.getValidSlice();

        const cutoff_short = if (now < SHORT_WINDOW_MS) 0 else now - SHORT_WINDOW_MS;
        var short_count: usize = 0;
        for (valid_timestamps) |ts| {
            if (ts >= cutoff_short) {
                short_count += 1;
            }
        }

        const long_count = valid_timestamps.len;

        if (short_count >= SHORT_LIMIT) {
            return false;
        }

        if (long_count >= LONG_LIMIT) {
            return false;
        }

        try rec.timestamps.append(self.allocator, now);
        return true;
    }

    /// cleanup 清理长时间未活动的 IP 记录
    /// 应定期调用以防止内存泄漏
    pub fn cleanup(self: *RateLimiter) void {
        const now = getMonotonicMs();
        const cleanup_ms = CLEANUP_THRESHOLD * 1000;
        const cutoff = if (now < cleanup_ms) 0 else now - cleanup_ms;

        for (&self.shards) |*shard| {
            shard.mutex.lock();
            defer shard.mutex.unlock();

            var to_remove = std.ArrayList(u32).empty;
            defer to_remove.deinit(self.allocator);

            var iter = shard.map.iterator();
            while (iter.next()) |entry| {
                if (entry.value_ptr.last_access < cutoff) {
                    to_remove.append(self.allocator, entry.key_ptr.*) catch continue;
                }
            }

            for (to_remove.items) |ip| {
                if (shard.map.fetchRemove(ip)) |kv| {
                    var record = kv.value;
                    record.deinit();
                }
            }
        }
    }

    /// getStats 获取统计信息（用于调试）
    ///
    /// 返回：
    ///   - usize: 当前跟踪的 IP 数量
    pub fn getStats(self: *RateLimiter) usize {
        var total: usize = 0;
        for (&self.shards) |*shard| {
            shard.mutex.lock();
            defer shard.mutex.unlock();
            total += shard.map.count();
        }
        return total;
    }
};
