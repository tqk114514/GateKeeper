//! src/test.zig
//! 测试代码集合
//!
//! 功能：
//! - 单元测试
//! - 集成测试
//! - 性能测试
//!
//! 使用：
//! zig test src/test.zig

const std = @import("std");
const testing = std.testing;

// ====================  导入模块 ====================

const index = @import("utils/index.zig");

// ====================  IP 解析测试 ====================

test "parseIPv4 - 基本功能" {
    const ip = try index.parseIPv4("192.168.1.1");
    try testing.expectEqual(@as(u32, 0xC0A80101), ip);
}

test "parseIPv4 - 边界值" {
    const ip1 = try index.parseIPv4("0.0.0.0");
    try testing.expectEqual(@as(u32, 0), ip1);

    const ip2 = try index.parseIPv4("255.255.255.255");
    try testing.expectEqual(@as(u32, 0xFFFFFFFF), ip2);
}

test "parseIPv4 - 常见 IP" {
    const google_dns = try index.parseIPv4("8.8.8.8");
    try testing.expectEqual(@as(u32, 0x08080808), google_dns);

    const cloudflare_dns = try index.parseIPv4("1.1.1.1");
    try testing.expectEqual(@as(u32, 0x01010101), cloudflare_dns);
}

// ====================  CIDR 解析测试 ====================

test "parseCIDR - /24 网段" {
    // 这是一个内部函数，暂时注释
    // const entry = try index.parseCIDR("192.168.1.0/24");
    // try testing.expectEqual(@as(u32, 0xC0A80100), entry.ip);
    // try testing.expectEqual(@as(u32, 0xFFFFFF00), entry.mask);
}

// ====================  性能测试 ====================

test "IP 解析性能" {
    const iterations = 10000;
    var i: usize = 0;

    const start = std.time.milliTimestamp();
    while (i < iterations) : (i += 1) {
        _ = try index.parseIPv4("192.168.1.100");
    }
    const end = std.time.milliTimestamp();

    const elapsed = end - start;
    std.debug.print("\nIP 解析性能: {d} 次解析耗时 {d}ms (平均 {d:.2}μs/次)\n", .{
        iterations,
        elapsed,
        @as(f64, @floatFromInt(elapsed)) * 1000.0 / @as(f64, @floatFromInt(iterations)),
    });
}

// ====================  集成测试示例 ====================

test "索引构建和查询 - 集成测试" {
    // 这里可以添加完整的索引构建和查询测试
    // 需要准备测试数据文件

    // 示例框架：
    // 1. 创建临时测试规则文件
    // 2. 构建索引
    // 3. 加载索引
    // 4. 测试查询
    // 5. 清理临时文件

    std.debug.print("\n集成测试占位符 - 待实现\n", .{});
}

// ====================  辅助函数测试 ====================

test "IP 字节序转换" {
    const ip: u32 = 0xC0A80101; // 192.168.1.1

    const byte1 = (ip >> 24) & 0xFF;
    const byte2 = (ip >> 16) & 0xFF;
    const byte3 = (ip >> 8) & 0xFF;
    const byte4 = ip & 0xFF;

    try testing.expectEqual(@as(u8, 192), byte1);
    try testing.expectEqual(@as(u8, 168), byte2);
    try testing.expectEqual(@as(u8, 1), byte3);
    try testing.expectEqual(@as(u8, 1), byte4);
}
