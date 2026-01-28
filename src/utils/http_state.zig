const std = @import("std");
const mem = std.mem;
const ascii = std.ascii;
const fmt = std.fmt;

pub const State = enum {
    IDLE, // Waiting for new request
    METHOD, // Parsing Method
    URI, // Parsing URI
    VERSION, // Parsing Version
    HEADER_KEY, // Parsing Header Key
    HEADER_VALUE, // Parsing Header Value
    HEADER_LF, // Saw \n after value
    BODY_IDENTITY, // Content-Length Body
    CHUNK_SIZE, // Chunk Hex Size
    CHUNK_SIZE_CR, // Saw \r after size
    CHUNK_EXT, // Chunk Extension
    CHUNK_EXT_CR, // Saw \r after ext
    CHUNK_DATA, // Chunk Data
    CHUNK_DATA_END, // Finished chunk data, expecting CRLF
    CHUNK_DATA_CR, // Saw \r after chunk data
    TRAILERS, // Skipping Trailers
};

pub const Event = enum {
    CONTINUE,
    REQUEST_FINISHED,
};

const HeaderType = enum {
    NONE,
    CONTENT_LENGTH,
    TRANSFER_ENCODING,
};

pub const StateMachine = struct {
    // Limits
    const MAX_TOKEN_SIZE = 1024;

    state: State = .IDLE,

    // Internal buffer for parsing tokens
    token_buf: [MAX_TOKEN_SIZE]u8 = undefined,
    token_len: usize = 0,

    // Context
    current_header: HeaderType = .NONE,
    content_length: u64 = 0,
    chunk_remaining: u64 = 0,
    is_chunked: bool = false,
    header_bytes_total: usize = 0, // Total limit (e.g., 16KB)

    pub fn init() StateMachine {
        return StateMachine{};
    }

    pub fn reset(self: *StateMachine) void {
        self.state = .IDLE;
        self.token_len = 0;
        self.current_header = .NONE;
        self.content_length = 0;
        self.chunk_remaining = 0;
        self.is_chunked = false;
        self.header_bytes_total = 0;
    }

    pub fn feed(self: *StateMachine, byte: u8, event: *Event) !bool {
        event.* = .CONTINUE;

        // Global security limit for headers
        if (self.state == .METHOD or self.state == .URI or self.state == .VERSION or
            self.state == .HEADER_KEY or self.state == .HEADER_VALUE or self.state == .HEADER_LF)
        {
            self.header_bytes_total += 1;
            if (self.header_bytes_total > 16 * 1024) return error.HeaderTooLarge;
        }

        switch (self.state) {
            .IDLE => {
                if (byte == '\r' or byte == '\n') return true; // Ignore keep-alive CR/LF
                if (!isValidTokenChar(byte)) return error.InvalidMethod;
                self.reset();
                self.state = .METHOD;
                // Byte already counted in header_bytes_total check above? No, reset zeroes it.
                // We should count it.
                self.header_bytes_total = 1;
                try self.appendToken(byte);
            },
            .METHOD => {
                if (byte == ' ') {
                    self.token_len = 0;
                    self.state = .URI;
                } else {
                    if (!isValidTokenChar(byte)) return error.InvalidMethod;
                    try self.appendToken(byte);
                }
            },
            .URI => {
                if (byte == ' ') {
                    self.state = .VERSION;
                } else if (byte == '\r' or byte == '\n') {
                    // HTTP/0.9 strictly rejected
                    return error.Http09NotSupported;
                }
                // discard URI bytes
            },
            .VERSION => {
                if (byte == '\r') {
                    // wait LF
                } else if (byte == '\n') {
                    self.state = .HEADER_KEY;
                    self.token_len = 0;
                }
            },
            .HEADER_KEY => {
                if (byte == '\n') {
                    // Empty line -> End of Headers
                    return self.finalizeHeaders(event);
                } else if (byte == ':') {
                    self.state = .HEADER_VALUE;
                    self.checkHeaderName();
                    self.token_len = 0; // Prepare for value
                } else if (byte != '\r') {
                    try self.appendToken(std.ascii.toLower(byte));
                }
            },
            .HEADER_VALUE => {
                if (byte == '\n') {
                    try self.parseHeaderValue();
                    self.state = .HEADER_KEY; // OR .HEADER_LF if checking Obs-fold
                    self.token_len = 0;
                } else if (byte != '\r') {
                    // Trim leading spaces
                    if (self.token_len == 0 and (byte == ' ' or byte == '\t')) return true;
                    try self.appendToken(std.ascii.toLower(byte));
                }
            },
            .HEADER_LF => {
                // Not used currently, merged into simple loop
            },
            .BODY_IDENTITY => {
                self.content_length -= 1;
                if (self.content_length == 0) {
                    event.* = .REQUEST_FINISHED;
                    self.state = .IDLE;
                }
            },
            .CHUNK_SIZE => {
                if (byte == '\n') {
                    if (self.chunk_remaining == 0) {
                        self.state = .TRAILERS;
                    } else {
                        self.state = .CHUNK_DATA;
                    }
                } else if (byte == '\r') {
                    self.state = .CHUNK_SIZE_CR;
                } else if (byte == ';') {
                    self.state = .CHUNK_EXT;
                } else {
                    const digit = fmt.charToDigit(byte, 16) catch return error.InvalidChunkSize;
                    const new_val = std.math.mul(u64, self.chunk_remaining, 16) catch return error.ChunkSizeOverflow;
                    self.chunk_remaining = new_val + digit;
                }
            },
            .CHUNK_SIZE_CR => {
                if (byte == '\n') {
                    if (self.chunk_remaining == 0) {
                        self.state = .TRAILERS;
                    } else {
                        self.state = .CHUNK_DATA;
                    }
                } else return error.InvalidChunkTerminator;
            },
            .CHUNK_EXT => {
                if (byte == '\n') {
                    if (self.chunk_remaining == 0) {
                        self.state = .TRAILERS;
                    } else {
                        self.state = .CHUNK_DATA;
                    }
                } else if (byte == '\r') {
                    self.state = .CHUNK_EXT_CR;
                }
            },
            .CHUNK_EXT_CR => {
                if (byte == '\n') {
                    if (self.chunk_remaining == 0) {
                        self.state = .TRAILERS;
                    } else {
                        self.state = .CHUNK_DATA;
                    }
                } else return error.InvalidChunkTerminator;
            },
            .CHUNK_DATA => {
                self.chunk_remaining -= 1;
                if (self.chunk_remaining == 0) {
                    self.state = .CHUNK_DATA_END;
                }
            },
            .CHUNK_DATA_END => {
                if (byte == '\n') {
                    self.state = .CHUNK_SIZE;
                    self.chunk_remaining = 0;
                } else if (byte == '\r') {
                    self.state = .CHUNK_DATA_CR;
                } else return error.InvalidChunkTerminator;
            },
            .CHUNK_DATA_CR => {
                if (byte == '\n') {
                    self.state = .CHUNK_SIZE;
                    self.chunk_remaining = 0;
                } else return error.InvalidChunkTerminator;
            },
            .TRAILERS => {
                // Simplified strict trailer skipping:
                // We're looking for an empty line to finish the request.
                //
                // Problem: How to distinguish "Header: Value\n" from "\n"?
                // We reuse HEADER_KEY/VALUE logic?
                // Or implementing a mini-state just for this.
                //
                // Easiest robust way:
                // The current byte is the START of a line (or \r, \n).
                // If it is \r or \n -> Empty line -> Done.
                // Else -> consume header line.
                // But we process byte-by-byte. We lost context "Start of Line".
                //
                // Fix: State Machine needs a sub-state or just reuse HEADER_KEY logic
                // But finalizeHeaders expects to transition to BODY/CHUNK, here handled differently.
                //
                // Let's implement manually with a flag? or keep it simple:
                // If we are in TRAILERS state, we are *starting* a new line or *inside* a line.
                // We need `in_trailer_line` bool.
                // This is getting complex for a "simple" fix.
                //
                // Alternative: Just fail connection on Trailers?
                // RFC says proxies MUST support trailers? Not necessarily.
                // Reusing HEADER_KEY but modifying `finalizeHeaders` to check `is_chunked` & `chunk_remaining == 0`?
                // Yes!
                // If is_chunked and chunk_remaining == 0 (which it is if we entered TRAILERS),
                // then finalizing headers means "End of Request", not "Start of Body".

                // Let's switch to HEADER_KEY logic!
                // We need to set state to HEADER_KEY but ensure we know we come from chunked end.
                // chunk_remaining is 0. is_chunked is true.
                // But we are already in BODY phase logically.
                // No, let's keep it dedicated.

                if (self.token_len == 0) { // Start of line
                    if (byte == '\r') {
                        // ignore
                    } else if (byte == '\n') {
                        event.* = .REQUEST_FINISHED;
                        self.state = .IDLE;
                    } else {
                        self.token_len = 1; // Mark as inside line
                    }
                } else {
                    if (byte == '\n') {
                        self.token_len = 0; // End of line
                    }
                }
            },
        }

        return true;
    }

    fn appendToken(self: *StateMachine, byte: u8) !void {
        if (self.token_len >= self.token_buf.len) return error.TokenTooLong;
        self.token_buf[self.token_len] = byte;
        self.token_len += 1;
    }

    fn checkHeaderName(self: *StateMachine) void {
        const key = self.token_buf[0..self.token_len];
        if (mem.eql(u8, key, "content-length")) {
            self.current_header = .CONTENT_LENGTH;
        } else if (mem.eql(u8, key, "transfer-encoding")) {
            self.current_header = .TRANSFER_ENCODING;
        } else {
            self.current_header = .NONE;
        }
    }

    fn parseHeaderValue(self: *StateMachine) !void {
        const val = self.token_buf[0..self.token_len];
        switch (self.current_header) {
            .CONTENT_LENGTH => {
                if (self.is_chunked) return; // Ignore CL if Chunked present (RFC 7230)
                self.content_length = try fmt.parseInt(u64, val, 10);
            },
            .TRANSFER_ENCODING => {
                // If ends with "chunked"
                if (mem.endsWith(u8, val, "chunked")) {
                    self.is_chunked = true;
                    self.content_length = 0; // Ignore prior CL
                }
            },
            .NONE => {},
        }
    }

    fn finalizeHeaders(self: *StateMachine, event: *Event) !bool {
        // RFC 7230 Violation Check: Both CL and Chunked?
        // We already handled precedence (Chunked > CL).

        if (self.is_chunked) {
            self.state = .CHUNK_SIZE;
            self.chunk_remaining = 0;
        } else if (self.content_length > 0) {
            self.state = .BODY_IDENTITY;
        } else {
            // No body (GET/HEAD with 0 length)
            event.* = .REQUEST_FINISHED;
            self.state = .IDLE;
        }
        return true;
    }
};

fn isValidTokenChar(byte: u8) bool {
    // Basic alphanumeric checks + allowed symbols
    return ascii.isAlphanumeric(byte) or mem.indexOfScalar(u8, "!#$%&'*+-.^_`|~", byte) != null;
}
