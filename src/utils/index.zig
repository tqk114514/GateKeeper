//! src/utils/index.zig
//! IP 黑名单索引与查询模块
//!
//! 功能：
//! - 从 .ipset 和 .netset 文件构建高效索引
//! - 提供快速 IP 黑名单查询
//! - 使用分段索引优化查询性能
//! - 支持 CIDR 网段匹配
//!
//! 依赖：
//! - std.fs: 文件系统操作
//! - std.mem: 内存管理
//! - std.net: 网络地址处理

const std = @import("std");
const fs = std.fs;
const mem = std.mem;
const net = std.net;
const builtin = @import("builtin");

// ====================  常量定义 ====================

/// INDEX_MAGIC 索引文件魔数 "IPBX"
const INDEX_MAGIC = 0x58425049;

/// INDEX_VERSION 索引文件版本
const INDEX_VERSION: u32 = 1;

/// SEGMENT_COUNT IP 段数量 (按第一字节分段，0-255)
const SEGMENT_COUNT: usize = 256;

// ====================  结构体定义 ====================

/// IndexHeader 索引文件头部
const IndexHeader = packed struct {
    magic: u32,
    version: u32,
    segment_count: u32,
    total_entries: u64,

    pub fn fromLittleEndian(self: *IndexHeader) void {
        self.magic = mem.littleToNative(u32, self.magic);
        self.version = mem.littleToNative(u32, self.version);
        self.segment_count = mem.littleToNative(u32, self.segment_count);
        self.total_entries = mem.littleToNative(u64, self.total_entries);
    }

    pub fn toLittleEndian(self: *IndexHeader) void {
        self.magic = mem.nativeToLittle(u32, self.magic);
        self.version = mem.nativeToLittle(u32, self.version);
        self.segment_count = mem.nativeToLittle(u32, self.segment_count);
        self.total_entries = mem.nativeToLittle(u64, self.total_entries);
    }
};

/// SegmentEntry 段表条目
const SegmentEntry = packed struct {
    offset: u64,
    count: u32,

    pub fn fromLittleEndian(self: *SegmentEntry) void {
        self.offset = mem.littleToNative(u64, self.offset);
        self.count = mem.littleToNative(u32, self.count);
    }

    pub fn toLittleEndian(self: *SegmentEntry) void {
        self.offset = mem.nativeToLittle(u64, self.offset);
        self.count = mem.nativeToLittle(u32, self.count);
    }
};

/// IPEntry IP 条目（支持单个 IP 和 CIDR）
const IPEntry = packed struct {
    ip: u32,
    mask: u32,

    pub fn fromLittleEndian(self: *IPEntry) void {
        self.ip = mem.littleToNative(u32, self.ip);
        self.mask = mem.littleToNative(u32, self.mask);
    }

    pub fn toLittleEndian(self: *IPEntry) void {
        self.ip = mem.nativeToLittle(u32, self.ip);
        self.mask = mem.nativeToLittle(u32, self.mask);
    }
};

/// IndexReader 索引读取器（内存缓存版本）
pub const IndexReader = struct {
    segments: [SEGMENT_COUNT]SegmentData,
    allocator: mem.Allocator,

    const SegmentData = struct {
        ips: []u32, // /32 IP 列表（已排序，用于二分查找）
        ranges: []IPEntry, // CIDR 网段列表（通常数量较少，使用线性扫描）
    };

    /// init 初始化索引读取器
    /// 将整个索引加载到内存中，并根据掩码逻辑拆分 IP 和网段，优化查询速度
    pub fn init(allocator: mem.Allocator, index_path: []const u8) !IndexReader {
        var file = fs.cwd().openFile(index_path, .{}) catch |err| {
            std.debug.print("[ERROR] Failed to open index file {s}: {any}\n", .{ index_path, err });
            return err;
        };
        defer file.close();

        var header: IndexHeader = undefined;
        _ = try file.read(mem.asBytes(&header));
        header.fromLittleEndian();

        if (header.magic != INDEX_MAGIC) {
            return error.InvalidIndexFile;
        }

        if (header.version != INDEX_VERSION) {
            return error.UnsupportedVersion;
        }

        var segment_table: [SEGMENT_COUNT]SegmentEntry = undefined;
        _ = try file.read(mem.sliceAsBytes(&segment_table));
        for (&segment_table) |*seg| seg.fromLittleEndian();

        var segments: [SEGMENT_COUNT]SegmentData = undefined;

        for (segment_table, 0..) |seg_entry, i| {
            if (seg_entry.count == 0) {
                segments[i] = SegmentData{ .ips = &[_]u32{}, .ranges = &[_]IPEntry{} };
                continue;
            }

            try file.seekTo(seg_entry.offset);

            // 1. 读取原始条目
            const raw_entries = try allocator.alloc(IPEntry, seg_entry.count);
            defer allocator.free(raw_entries);
            _ = try file.read(mem.sliceAsBytes(raw_entries));

            for (raw_entries) |*entry| entry.fromLittleEndian();

            // 2. 统计 /32 IP 的数量
            var ip_count: usize = 0;
            for (raw_entries) |entry| {
                if (entry.mask == 0xFFFFFFFF) ip_count += 1;
            }

            // 3. 分配内存并拆分数据
            const ips = try allocator.alloc(u32, ip_count);
            errdefer allocator.free(ips);

            const ranges = try allocator.alloc(IPEntry, seg_entry.count - ip_count);
            errdefer allocator.free(ranges);

            var ip_idx: usize = 0;
            var range_idx: usize = 0;
            for (raw_entries) |entry| {
                if (entry.mask == 0xFFFFFFFF) {
                    ips[ip_idx] = entry.ip;
                    ip_idx += 1;
                } else {
                    ranges[range_idx] = entry;
                    range_idx += 1;
                }
            }

            segments[i] = SegmentData{
                .ips = ips,
                .ranges = ranges,
            };
        }

        std.debug.print("Index loaded: {d} segments partitioned into IPs and Ranges\n", .{SEGMENT_COUNT});

        return IndexReader{
            .segments = segments,
            .allocator = allocator,
        };
    }

    /// deinit 释放资源
    pub fn deinit(self: *IndexReader) void {
        for (&self.segments) |*seg| {
            if (seg.ips.len > 0) self.allocator.free(seg.ips);
            if (seg.ranges.len > 0) self.allocator.free(seg.ranges);
        }
    }

    /// isBlocked 检查 IP 是否在黑名单中
    /// 核心优化：
    /// 1. 对精确 IP 列表使用 O(log N) 二分查找
    /// 2. 对网段列表使用 O(M) 线性扫描（M 通常很小）
    pub fn isBlocked(self: *IndexReader, ip: u32) !bool {
        const segment_idx = @as(usize, @intCast((ip >> 24) & 0xFF));
        const data = &self.segments[segment_idx];

        // 1. 使用 Zig 标准库提供的二分查找进行精确匹配 (O(log N))
        const S = struct {
            fn compare(context: u32, item: u32) std.math.Order {
                return std.math.order(context, item);
            }
        };
        if (std.sort.binarySearch(u32, data.ips, ip, S.compare)) |_| {
            return true;
        }

        // 2. 检查 CIDR 网段列表 (O(M))
        for (data.ranges) |range| {
            if ((ip & range.mask) == range.ip) {
                return true;
            }
        }

        return false;
    }
};

// ====================  公开函数 ====================

/// buildIndex 构建 IP 黑名单索引
/// 扫描规则目录，解析所有 .ipset 和 .netset 文件，生成索引文件
///
/// 参数：
///   - allocator: 内存分配器
///   - rules_dir: 规则文件目录路径
///   - output_path: 输出索引文件路径
pub fn buildIndex(allocator: mem.Allocator, rules_dir: []const u8, output_path: []const u8) !void {
    std.debug.print("Building index from: {s}\n", .{rules_dir});

    var entries: std.ArrayListUnmanaged(IPEntry) = .empty;
    defer entries.deinit(allocator);

    var dir = try fs.cwd().openDir(rules_dir, .{ .iterate = true });
    defer dir.close();

    var iter = dir.iterate();
    while (try iter.next()) |entry| {
        if (entry.kind != .file) continue;

        const is_ipset = mem.endsWith(u8, entry.name, ".ipset");
        const is_netset = mem.endsWith(u8, entry.name, ".netset");

        if (!is_ipset and !is_netset) continue;

        std.debug.print("Processing: {s}\n", .{entry.name});

        const file_path = try fs.path.join(allocator, &[_][]const u8{ rules_dir, entry.name });
        defer allocator.free(file_path);

        try parseRuleFile(allocator, file_path, &entries);
    }

    std.debug.print("Total entries: {d}\n", .{entries.items.len});
    std.debug.print("Sorting entries...\n", .{});

    mem.sort(IPEntry, entries.items, {}, compareIPEntry);

    std.debug.print("Writing index file: {s}\n", .{output_path});

    try writeIndexFile(allocator, output_path, entries.items);

    std.debug.print("Index build complete!\n", .{});
}

/// parseIPv4 解析 IPv4 地址字符串
///
/// 参数：
///   - ip_str: IP 地址字符串 (如 "192.168.1.1")
///
/// 返回：
///   - u32: IP 地址的 32 位整数表示
pub fn parseIPv4(ip_str: []const u8) !u32 {
    var parts: [4]u8 = undefined;
    var iter = mem.splitScalar(u8, ip_str, '.');
    var i: usize = 0;

    while (iter.next()) |part| : (i += 1) {
        if (i >= 4) return error.InvalidIPFormat;
        parts[i] = try std.fmt.parseInt(u8, part, 10);
    }

    if (i != 4) return error.InvalidIPFormat;

    return (@as(u32, parts[0]) << 24) |
        (@as(u32, parts[1]) << 16) |
        (@as(u32, parts[2]) << 8) |
        @as(u32, parts[3]);
}

/// ipFromAddress 从 net.Address 提取 IPv4 地址
///
/// 参数：
///   - addr: 网络地址
///
/// 返回：
///   - u32: IPv4 地址
pub fn ipFromAddress(addr: net.Address) !u32 {
    return switch (addr.any.family) {
        std.posix.AF.INET => @byteSwap(addr.in.sa.addr),
        else => error.NotIPv4,
    };
}

// ====================  私有函数 ====================

/// parseRuleFile 解析规则文件
///
/// 参数：
///   - allocator: 内存分配器
///   - file_path: 文件路径
///   - entries: IP 条目列表
fn parseRuleFile(allocator: mem.Allocator, file_path: []const u8, entries: *std.ArrayListUnmanaged(IPEntry)) !void {
    const file = try fs.cwd().openFile(file_path, .{});
    defer file.close();

    const file_size = (try file.stat()).size;
    const content = try file.readToEndAlloc(allocator, file_size);
    defer allocator.free(content);

    var lines = mem.splitScalar(u8, content, '\n');
    while (lines.next()) |line| {
        const trimmed = mem.trim(u8, line, &std.ascii.whitespace);

        if (trimmed.len == 0 or trimmed[0] == '#') continue;

        if (mem.indexOf(u8, trimmed, "/")) |_| {
            const entry = try parseCIDR(trimmed);
            try entries.append(allocator, entry);
        } else {
            const ip = try parseIPv4(trimmed);
            try entries.append(allocator, .{ .ip = ip, .mask = 0xFFFFFFFF });
        }
    }
}

/// parseCIDR 解析 CIDR 表示法
///
/// 参数：
///   - cidr_str: CIDR 字符串 (如 "192.168.0.0/24")
///
/// 返回：
///   - IPEntry: IP 条目
fn parseCIDR(cidr_str: []const u8) !IPEntry {
    const slash_pos = mem.indexOf(u8, cidr_str, "/") orelse return error.InvalidCIDR;

    const ip_part = cidr_str[0..slash_pos];
    const prefix_part = cidr_str[slash_pos + 1 ..];

    const ip = try parseIPv4(ip_part);
    const prefix_len = try std.fmt.parseInt(u8, prefix_part, 10);

    if (prefix_len > 32) return error.InvalidPrefixLength;

    const mask: u32 = if (prefix_len == 0) 0 else ~@as(u32, 0) << @intCast(32 - prefix_len);

    return .{ .ip = ip & mask, .mask = mask };
}

/// writeIndexFile 写入索引文件
///
/// 参数：
///   - allocator: 内存分配器
///   - output_path: 输出文件路径
///   - entries: 已排序的 IP 条目列表
fn writeIndexFile(_: mem.Allocator, output_path: []const u8, entries: []const IPEntry) !void {
    var file = try fs.cwd().createFile(output_path, .{});
    defer file.close();

    var segments: [SEGMENT_COUNT]SegmentEntry = undefined;
    @memset(&segments, .{ .offset = 0, .count = 0 });

    for (entries) |entry| {
        const segment_idx = @as(usize, @intCast((entry.ip >> 24) & 0xFF));
        segments[segment_idx].count += 1;
    }

    var header = IndexHeader{
        .magic = INDEX_MAGIC,
        .version = INDEX_VERSION,
        .segment_count = @intCast(SEGMENT_COUNT),
        .total_entries = entries.len,
    };
    header.toLittleEndian();

    _ = try file.write(mem.asBytes(&header));

    var current_offset: u64 = @sizeOf(IndexHeader) + @sizeOf(SegmentEntry) * SEGMENT_COUNT;

    for (&segments) |*segment| {
        if (segment.count > 0) {
            segment.offset = current_offset;
            current_offset += @as(u64, segment.count) * @sizeOf(IPEntry);
        }
    }

    for (&segments) |*seg| seg.toLittleEndian();
    _ = try file.write(mem.sliceAsBytes(&segments));

    for (entries) |entry| {
        var e = entry;
        e.toLittleEndian();
        _ = try file.write(mem.asBytes(&e));
    }
}

/// compareIPEntry 比较两个 IP 条目（用于排序）
///
/// 参数：
///   - context: 上下文（未使用）
///   - a: 第一个条目
///   - b: 第二个条目
///
/// 返回：
///   - bool: a < b
fn compareIPEntry(context: void, a: IPEntry, b: IPEntry) bool {
    _ = context;
    return a.ip < b.ip;
}
