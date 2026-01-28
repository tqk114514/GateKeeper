const std = @import("std");

/// RFC 7230 compliant header extraction
/// 安全地查找 HTTP Header 值，防止 CRLF 注入和 Request Smuggling 混淆
pub fn validateHeaderSection(buffer: []const u8) !void {
    const header_end = std.mem.indexOf(u8, buffer, "\r\n\r\n") orelse return;
    const headers = buffer[0..header_end];
    var i: usize = 0;

    // Skip Request Line
    if (std.mem.indexOfScalar(u8, headers, '\n')) |pos| {
        i = pos + 1;
    } else {
        return;
    }

    var cl_count: usize = 0;
    var te_count: usize = 0;

    while (i < headers.len) {
        const line_start = i;
        var line_end = headers.len;
        if (std.mem.indexOfScalarPos(u8, headers, i, '\n')) |pos| {
            line_end = pos;
            i = pos + 1;
        } else {
            return;
        } // Should not happen in valid block

        // CRLF adjustment
        var effective_end = line_end;
        if (effective_end > line_start and headers[effective_end - 1] == '\r') {
            effective_end -= 1;
        }
        const line = headers[line_start..effective_end];
        if (line.len == 0) break;

        // 1. Strict Obs-Fold Check (RFC 7230: MUST reject)
        if (line[0] == ' ' or line[0] == '\t') {
            return error.ObsFoldDetected;
        }

        // 2. Duplicate Critical Headers Check
        if (std.mem.indexOfScalar(u8, line, ':')) |colon_pos| {
            const key = line[0..colon_pos];
            if (std.ascii.eqlIgnoreCase(key, "Content-Length")) {
                cl_count += 1;
                if (cl_count > 1) return error.DuplicateCriticalHeader;
            } else if (std.ascii.eqlIgnoreCase(key, "Transfer-Encoding")) {
                te_count += 1;
                if (te_count > 1) return error.DuplicateCriticalHeader;
            }
        }
    }
}

pub fn findHeaderValue(buffer: []const u8, target_header: []const u8) ?[]const u8 {
    const header_end = std.mem.indexOf(u8, buffer, "\r\n\r\n") orelse return null;
    const headers = buffer[0..header_end];
    var i: usize = 0;

    if (std.mem.indexOfScalar(u8, headers, '\n')) |pos| {
        i = pos + 1;
    } else {
        return null;
    }

    var last_val: ?[]const u8 = null;

    while (i < headers.len) {
        const line_start = i;
        var line_end = headers.len;
        if (std.mem.indexOfScalarPos(u8, headers, i, '\n')) |pos| {
            line_end = pos;
            i = pos + 1;
        } else {
            return last_val;
        }

        var effective_end = line_end;
        if (effective_end > line_start and headers[effective_end - 1] == '\r') {
            effective_end -= 1;
        }
        const line = headers[line_start..effective_end];
        if (line.len == 0) break;

        // Skip Obs-Fold (Validation should catch this, but parsing continues safely)
        if (line[0] == ' ' or line[0] == '\t') continue;

        if (std.mem.indexOfScalar(u8, line, ':')) |colon_pos| {
            const key = line[0..colon_pos];
            if (std.ascii.eqlIgnoreCase(key, target_header)) {
                // Last-Value-Wins Strategy
                last_val = std.mem.trim(u8, line[colon_pos + 1 ..], " \t");
            }
        }
    }
    return last_val;
}

pub fn parseContentLength(buffer: []const u8) usize {
    if (findHeaderValue(buffer, "Content-Length")) |val| {
        return std.fmt.parseInt(usize, val, 10) catch 0;
    }
    return 0;
}

pub fn isChunked(buffer: []const u8) bool {
    if (findHeaderValue(buffer, "Transfer-Encoding")) |val| {
        return std.ascii.indexOfIgnoreCase(val, "chunked") != null;
    }
    return false;
}

pub fn hasSmugglingRisk(buffer: []const u8) bool {
    // RFC 7230: 如果同时存在 Content-Length 和 Transfer-Encoding，视为走私风险（或需忽略 CL）
    // 安全网关策略：直接拒绝歧义请求
    const has_cl = findHeaderValue(buffer, "Content-Length") != null;
    const has_te = findHeaderValue(buffer, "Transfer-Encoding") != null;
    return has_cl and has_te;
}
