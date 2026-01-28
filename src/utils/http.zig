const std = @import("std");

/// RFC 7230 compliant header extraction
/// 安全地查找 HTTP Header 值，防止 CRLF 注入和 Request Smuggling 混淆
pub fn findHeaderValue(buffer: []const u8, target_header: []const u8) ?[]const u8 {
    // 1. 定位 HTTP Body 分界线，限制搜索范围在头部区域
    const header_end = std.mem.indexOf(u8, buffer, "\r\n\r\n") orelse return null;
    const headers = buffer[0..header_end];

    var i: usize = 0;

    // 跳过 Request Line (第一行)
    if (std.mem.indexOfScalar(u8, headers, '\n')) |pos| {
        i = pos + 1;
    } else {
        return null;
    }

    while (i < headers.len) {
        const line_start = i;

        // 寻找行尾
        var line_end = headers.len;
        if (std.mem.indexOfScalarPos(u8, headers, i, '\n')) |pos| {
            line_end = pos;
            i = pos + 1;
        } else {
            // 最后一行没有换行符的异常情况，通常不应发生在完整 Header 中
            return null;
        }

        // 处理 CRLF 或 LF
        var effective_end = line_end;
        if (effective_end > line_start and headers[effective_end - 1] == '\r') {
            effective_end -= 1;
        }

        const line = headers[line_start..effective_end];
        if (line.len == 0) break; // 空行，Header 结束

        // 检查是否为 Obs-Fold（折行），即以空格或 Tab 开头
        // RFC 7230 虽弃用但在兼容旧系统时需防范将其视为新 Key
        if (line[0] == ' ' or line[0] == '\t') {
            continue;
        }

        // 查找冒号分隔符
        if (std.mem.indexOfScalar(u8, line, ':')) |colon_pos| {
            const key = line[0..colon_pos];

            // 简单的不区分大小写比较 (仅针对 ASCII Header 名)
            if (std.ascii.eqlIgnoreCase(key, target_header)) {
                // 提取值并去除空白
                return std.mem.trim(u8, line[colon_pos + 1 ..], " \t");
            }
        }
    }

    return null;
}
