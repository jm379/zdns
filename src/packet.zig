const std = @import("std");

const DNSError = error{
    LabelTooLong,
    DomainTooLong,
    BufferTooSmall,
    InsufficientData,
    WrongSize,
    InvalidCompression,
    InvalidPointer,
    EmptyPacket,
};

const QueryResponse = enum(u16) { query = 0, response = 0x80_00 };
const OperationCode = enum(u16) { standard = 0, inverse = 0x08_00, status = 0x10_00, notify = 0x18_00, update = 0x20_00 };
const AuthoritativeAnswer = enum(u16) { no = 0, yes = 0x04_00 };
const Truncated = enum(u16) { no = 0, yes = 0x02_00 };
const RecursionDesired = enum(u16) { no = 0, yes = 0x01_00 };
const RecursionAvailable = enum(u16) { no = 0, yes = 0x00_80 };
const ResponseCode = enum(u16) { no_error = 0, format_error, server_failure, name_error, not_implemented, refused, yx_domain, yx_rr_set, nx_rr_set, not_auth, not_zone };
const Flags = struct {
    query_response: QueryResponse = .query,
    operation_code: OperationCode = .standard,
    authorative_answer: AuthoritativeAnswer = .no,
    truncated: Truncated = .no,
    recursion_desired: RecursionDesired = .yes,
    recursion_available: RecursionAvailable = .no,
    response_code: ResponseCode = .no_error,
    fn serialize(self: *Flags) u16 {
        return @intFromEnum(self.query_response) |
            @intFromEnum(self.operation_code) |
            @intFromEnum(self.authorative_answer) |
            @intFromEnum(self.truncated) |
            @intFromEnum(self.recursion_desired) |
            @intFromEnum(self.recursion_available) |
            @intFromEnum(self.response_code);
    }
    fn deserialize(high: u8, low: u8) Flags {
        const value = bytesToInt(high, low);
        return .{
            .query_response = valueToEnum(QueryResponse, value, @intFromEnum(QueryResponse.response)),
            .operation_code = valueToEnum(OperationCode, value, 0x78_00),
            .authorative_answer = valueToEnum(AuthoritativeAnswer, value, @intFromEnum(AuthoritativeAnswer.yes)),
            .truncated = valueToEnum(Truncated, value, @intFromEnum(Truncated.yes)),
            .recursion_desired = valueToEnum(RecursionDesired, value, @intFromEnum(RecursionDesired.yes)),
            .recursion_available = valueToEnum(RecursionAvailable, value, @intFromEnum(RecursionAvailable.yes)),
            .response_code = valueToEnum(ResponseCode, value, 0x00_0F),
        };
    }
};

test "Should deserialize Flags" {
    const allocator = std.testing.allocator;
    const message = "\x81\x80";

    const data = try allocator.dupe(u8, message);
    defer allocator.free(data);

    const flags = Flags.deserialize(data[0], data[1]);

    try std.testing.expectEqual(QueryResponse.response, flags.query_response);
    try std.testing.expectEqual(OperationCode.standard, flags.operation_code);
    try std.testing.expectEqual(AuthoritativeAnswer.no, flags.authorative_answer);
    try std.testing.expectEqual(Truncated.no, flags.truncated);
    try std.testing.expectEqual(RecursionDesired.yes, flags.recursion_desired);
    try std.testing.expectEqual(RecursionAvailable.yes, flags.recursion_available);
    try std.testing.expectEqual(ResponseCode.no_error, flags.response_code);
}

const Header = struct {
    id: u16,
    flags: Flags,
    question_count: u16,
    answer_count: u16 = 0,
    authoritive_count: u16 = 0,
    additional_count: u16 = 0,
    fn serialize(self: *Header, buff: []u8) DNSError!usize {
        if (buff.len < 12) return DNSError.BufferTooSmall;

        @memcpy(buff[0..2], &intToBigBytes(self.id));
        @memcpy(buff[2..4], &intToBigBytes(self.flags.serialize()));
        @memcpy(buff[4..6], &intToBigBytes(self.question_count));
        @memcpy(buff[6..8], &intToBigBytes(self.answer_count));
        @memcpy(buff[8..10], &intToBigBytes(self.authoritive_count));
        @memcpy(buff[10..12], &intToBigBytes(self.additional_count));

        return 12;
    }
    fn deserialize(data: []u8) DNSError!Header {
        if (data.len != 12) return DNSError.WrongSize;

        return .{
            .id = bytesToInt(data[0], data[1]),
            .flags = Flags.deserialize(data[2], data[3]),
            .question_count = bytesToInt(data[4], data[5]),
            .answer_count = bytesToInt(data[6], data[7]),
            .authoritive_count = bytesToInt(data[8], data[9]),
            .additional_count = bytesToInt(data[10], data[11]),
        };
    }
};

test "Should serialize Header" {
    var buffer: [32]u8 = undefined;
    var header = Header{ .id = 0x12_34, .flags = Flags{}, .question_count = 1 };

    const expected = "\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00";
    const len = try header.serialize(&buffer);
    try std.testing.expectEqualSlices(u8, expected, buffer[0..len]);
}

test "Should deserialize Header" {
    const allocator = std.testing.allocator;
    const message = "\x12\x34\x81\x80\x00\x01\x00\x04\x00\x00\x00\x00";

    const data = try allocator.dupe(u8, message);
    defer allocator.free(data);
    const header = try Header.deserialize(data);

    try std.testing.expectEqual(0x12_34, header.id);
    try std.testing.expectEqual(QueryResponse.response, header.flags.query_response);
    try std.testing.expectEqual(OperationCode.standard, header.flags.operation_code);
    try std.testing.expectEqual(AuthoritativeAnswer.no, header.flags.authorative_answer);
    try std.testing.expectEqual(Truncated.no, header.flags.truncated);
    try std.testing.expectEqual(RecursionDesired.yes, header.flags.recursion_desired);
    try std.testing.expectEqual(RecursionAvailable.yes, header.flags.recursion_available);
    try std.testing.expectEqual(ResponseCode.no_error, header.flags.response_code);
    try std.testing.expectEqual(0x00_01, header.question_count);
    try std.testing.expectEqual(0x00_04, header.answer_count);
    try std.testing.expectEqual(0x00_00, header.authoritive_count);
    try std.testing.expectEqual(0x00_00, header.additional_count);
}

pub const QueryType = enum(u16) { A = 1, NS, MD, MF, CNAME, SOA, MB, MG, MR, NULl, WKS, PTR, HINFO, MINFO, MX, TXT, OPT = 41, AXFR = 252, MAILB = 253, MAILA = 254, ALL = 255 };
const QueryClass = enum(u16) { IN = 1, CS, CH, HS, ANY = 255, _ };

const QuestionConfig = struct { query_name: []u8, query_type: QueryType = .A, query_class: QueryClass = .IN };
const ResourceRecord = struct {
    allocator: std.mem.Allocator = undefined,
    name: []u8,
    type: QueryType,
    class: QueryClass,
    ttl: u32 = undefined,
    rd_length: u16 = undefined,
    // TODO:
    // Maybe make r_data an enum with all TYPES,
    // that can be deserialized
    r_data: ?[]u8 = null,
    fn init(config: QuestionConfig) !ResourceRecord {
        if (config.query_name.len > 253) return DNSError.DomainTooLong;

        return .{
            .name = config.query_name,
            .type = config.query_type,
            .class = config.query_class,
        };
    }
    fn deinit(self: *ResourceRecord) void {
        self.allocator.free(self.name);
    }
    fn serialize(self: *ResourceRecord, buff: []u8) !usize {
        const query_type = intToBigBytes(@intFromEnum(self.type));
        const query_class = intToBigBytes(@intFromEnum(self.class));

        const len = try domainToLabels(self.name, buff);
        @memcpy(buff[len .. len + 2], &query_type);
        @memcpy(buff[len + 2 .. len + 4], &query_class);

        return len + 4;
    }
    fn deserialize(allocator: std.mem.Allocator, data: []u8, pos: *usize, question: bool) !ResourceRecord {
        const name = try labelsToDomain(allocator, data, pos);
        var rd_length: u16 = 0;
        var ttl: u32 = 0;
        var r_data: ?[]u8 = null;

        const query_type = bytesToInt(data[pos.*], data[pos.* + 1]);
        pos.* += 2;
        const query_class = bytesToInt(data[pos.*], data[pos.* + 1]);
        pos.* += 2;

        if (!question) {
            std.debug.print("data: {x}\n", .{data[pos.*..]});
            // TODO: this is wrong
            ttl = bytesToInt(data[pos.*], data[pos.* + 1]) +
                bytesToInt(data[pos.* + 2], data[pos.* + 3]);
            pos.* += 4;

            rd_length = bytesToInt(data[pos.*], data[pos.* + 1]);
            pos.* += 2;

            r_data = data[pos.* .. pos.* + rd_length];
            pos.* += rd_length;
        }

        return .{
            .allocator = allocator,
            .name = name,
            .type = valueToEnum(QueryType, query_type, 0x00_FF),
            .class = valueToEnum(QueryClass, query_class, 0xFF_FF),
            .ttl = ttl,
            .rd_length = rd_length,
            .r_data = r_data,
        };
    }
};

test "Should serialize Question ResourceRecord" {
    const allocator = std.testing.allocator;
    var buffer: [512]u8 = undefined;
    var name = try allocator.dupe(u8, "www.example.com");
    defer allocator.free(name);
    var question = try ResourceRecord.init(.{ .query_name = name[0..] });

    const expected = "\x03\x77\x77\x77\x07\x65\x78\x61\x6d\x70\x6c\x65\x03\x63\x6f\x6d\x00\x00\x01\x00\x01";
    const len = try question.serialize(buffer[0..]);
    try std.testing.expectEqualSlices(u8, expected, buffer[0..len]);
}

test "Should deserialize Question ResourceRecord" {
    const allocator = std.testing.allocator;
    var message = [_]u8{
        // Headers
        0x12, 0x34, // ID
        0x81, 0x80, // Flags
        0x00, 0x01, // QD Count = 1
        0x00, 0x04, // AN Count = 4
        0x00, 0x00, // NS Count = 0
        0x00, 0x00, // AR Count = 0
        // Question
        0x03, 0x77, 0x77, 0x77, // www
        0x07, 0x65, 0x78, 0x61, 0x6D, 0x70, 0x6C, 0x65, // example
        0x03, 0x63, 0x6F, 0x6D, // com
        0x00, // null
        0x00, 0x01, // QType
        0x00, 0x01, // Class
    };
    var offset: usize = 12;
    var question = try ResourceRecord.deserialize(allocator, &message, &offset, true);
    defer question.deinit();

    try std.testing.expectEqualSlices(u8, "www.example.com", question.name);
    try std.testing.expectEqual(QueryType.A, question.type);
    try std.testing.expectEqual(QueryClass.IN, question.class);
    try std.testing.expectEqual(null, question.r_data);
    try std.testing.expectEqual(33, offset);
}

test "Should deserialize Answer ResourceRecord" {
    const allocator = std.testing.allocator;
    var message = [_]u8{
        // Headers
        0x12, 0x34, // ID
        0x81, 0x80, // Flags
        0x00, 0x01, // QD Count = 1
        0x00, 0x01, // AN Count = 1
        0x00, 0x00, // NS Count = 0
        0x00, 0x00, // AR Count = 0
        // Question
        0x03, 0x77, 0x77, 0x77, // www
        0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, // example
        0x03, 0x63, 0x6f, 0x6d, // com
        0x00, // null
        0x00, 0x01, // Type = A
        0x00, 0x01, // Class = IN
        // Answer
        0xc0, 0x0c, // Pointer to 0x0c - "www.example.com"
        0x00, 0x05, // Type = CNAME
        0x00, 0x01, // Class = IN
        0x00, 0x00, 0x00, 0x5b, // TTL = 91 seconds
        0x00, 0x22, // RDLENGTH = 34
        0x03, 0x77, 0x77, 0x77, // www
        0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, // example
        0x06, 0x63, 0x6f, 0x6d, 0x2d, 0x76, 0x34, // com-v4
        0x09, 0x65, 0x64, 0x67, 0x65, 0x73, 0x75, 0x69, 0x74, 0x65, // edgesuite
        0x03, 0x6e, 0x65, 0x74, // net
        0x00, // null
    };
    var offset: usize = 33;
    var answer = try ResourceRecord.deserialize(allocator, &message, &offset, false);
    defer answer.deinit();

    try std.testing.expectEqualSlices(u8, "www.example.com", answer.name);
    try std.testing.expectEqual(QueryType.CNAME, answer.type);
    try std.testing.expectEqual(QueryClass.IN, answer.class);
    try std.testing.expectEqual(91, answer.ttl);
    try std.testing.expectEqual(34, answer.rd_length);

    var r_data = [_]u8{
        0x03, 0x77, 0x77, 0x77, // www
        0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, // example
        0x06, 0x63, 0x6f, 0x6d, 0x2d, 0x76, 0x34, // com-v4
        0x09, 0x65, 0x64, 0x67, 0x65, 0x73, 0x75, 0x69, 0x74, 0x65, // edgesuite
        0x03, 0x6e, 0x65, 0x74, // net
        0x00,
    };
    try std.testing.expectEqualSlices(u8, &r_data, answer.r_data.?);
    try std.testing.expectEqual(78 + 1, offset);
}

// https://www.rfc-editor.org/rfc/rfc6891
test "Should deserialize OPT Aditional Record ResourceRecord" {
    const allocator = std.testing.allocator;
    var message = [_]u8{
        // Headers
        0x12, 0x34, // ID
        0x81, 0x80, // Flags
        0x00, 0x01, // QD Count = 1
        0x00, 0x00, // AN Count = 0
        0x00, 0x00, // NS Count = 0
        0x00, 0x01, // AR Count = 1
        // Question
        0x03, 0x77, 0x77, 0x77, // www
        0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, // example
        0x03, 0x63, 0x6f, 0x6d, // com
        0x00, // null
        0x00, 0x01, // Type = A
        0x00, 0x01, // Class = IN
        // Additional
        0x00, // null name
        0x00, 0x29, // Type = OPT
        0x04, 0xd0, // Class = UDP Payload Size
        0x00, 0x00, 0x00, 0x00, // TTL = Extended RCODE and Flags
        0x00, 0x00, // RDLENGTH = 0
    };
    var offset: usize = 33;
    var answer = try ResourceRecord.deserialize(allocator, &message, &offset, false);
    defer answer.deinit();

    try std.testing.expectEqualSlices(u8, "", answer.name);
    try std.testing.expectEqual(QueryType.OPT, answer.type);
    try std.testing.expectEqual(0x04_d0, @intFromEnum(answer.class));
    try std.testing.expectEqual(0, answer.ttl);
    try std.testing.expectEqual(0, answer.rd_length);

    var r_data = [_]u8{};
    try std.testing.expectEqualSlices(u8, &r_data, answer.r_data.?);
    try std.testing.expectEqual(43 + 1, offset);
}

const PacketConfig = struct { id: u16, query_type: QueryType = .A, query_name: []u8 };
pub const Packet = struct {
    data: []u8 = undefined,
    header: Header,
    question: ResourceRecord,
    answer: []ResourceRecord = undefined,
    authority: []ResourceRecord = undefined,
    additional: []ResourceRecord = undefined,
    pub fn init(config: PacketConfig) !Packet {
        return .{ .header = Header{
            .id = config.id,
            .flags = .{},
            .question_count = 1,
        }, .question = try ResourceRecord.init(.{
            .query_type = config.query_type,
            .query_name = config.query_name,
        }) };
    }
    pub fn deinit(self: *Packet) void {
        self.allocator.free(self.data);
    }
    pub fn serialize(self: *Packet, buff: []u8) !usize {
        var tlen: usize = 0;
        var len = try self.header.serialize(buff);
        tlen += len;

        len = try self.question.serialize(buff[len..]);
        tlen += len;

        return tlen;
    }
    pub fn deserialize() !Packet {}
};

test "Should serialize Packet" {
    const allocator = std.testing.allocator;
    var buffer: [512]u8 = undefined;
    var name = try allocator.dupe(u8, "www.example.com");
    defer allocator.free(name);
    var packet = try Packet.init(.{ .query_name = name[0..], .id = 0x1234 });

    const expected = "\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03\x77\x77\x77\x07\x65\x78\x61\x6d\x70\x6c\x65\x03\x63\x6f\x6d\x00\x00\x01\x00\x01";
    const len = try packet.serialize(&buffer);
    try std.testing.expectEqualSlices(u8, expected, buffer[0..len]);
}

test "Should deserialize Packet" {
    const buffer: [512]u8 = undefined;
    const message = [_]u8{
        // Headers
        0x12, 0x34, // ID
        0x81, 0x80, // Flags
        0x00, 0x01, // QD Count = 1
        0x00, 0x04, // AN Count = 4
        0x00, 0x00, // NS Count = 0
        0x00, 0x00, // AR Count = 0
        // Question
        0x03, 0x77, 0x77, 0x77, // www
        0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, // example
        0x03, 0x63, 0x6f, 0x6d, // com
        0x00, // null
        0x00, 0x01, // Type = A
        0x00, 0x01, // Class = IN
        // Answer 1
        0xc0, 0x0c, // Pointer to 0x0c - "www.example.com"
        0x00, 0x05, // Type = CNAME
        0x00, 0x01, // Class = IN
        0x00, 0x00, 0x00, 0x5b, // TTL = 91 seconds
        0x00, 0x22, // RDLENGTH = 34
        0x03, 0x77, 0x77, 0x77, // www
        0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, // example
        0x06, 0x63, 0x6f, 0x6d, 0x2d, 0x76, 0x34, // com-v4
        0x09, 0x65, 0x64, 0x67, 0x65, 0x73, 0x75, 0x69, 0x74, 0x65, // edgesuite
        0x03, 0x6e, 0x65, 0x74, // net
        0x00, // null
        // Answer 2
        0xc0, 0x2d, // Pointer to 0x2d - "www.example.com-v4.edgesuite.net"
        0x00, 0x05, // Type = CNAME
        0x00, 0x01, // Class = IN
        0x00, 0x00, 0x53, 0x8f, // TTL = 21391 seconds
        0x00, 0x14, // RDLENGTH = 20
        0x05, 0x61, 0x31, 0x34, 0x32, 0x32, // a1422
        0x04, 0x64, 0x73, 0x63, 0x72, // dscr
        0x06, 0x61, 0x6b, 0x61, 0x6d, 0x61, 0x69, // akamai
        0xc0, 0x4a, // Pointer to 0x4a - "net"
        // Answer 3
        0xc0, 0x5b, // Pointer to 0x5b - "a1422.dscr.akamai.net"
        0x00, 0x01, // Type = A
        0x00, 0x01, // Class = IN
        0x00, 0x00, 0x00, 0x14, // TTL = 20 seconds
        0x00, 0x04, // RDLENGTH = 4
        0x02, 0x13, 0x0a, 0x4b, // 2.19.10.75
        // Answer 4
        0xc0, 0x5b, // Pointer to 0x5b - "a1422.dscr.akamai.net"
        0x00, 0x01, // Type = A
        0x00, 0x01, // Class = IN
        0x00, 0x00, 0x00, 0x14, // TTL = 20 seconds
        0x00, 0x04, // RDLENGTH = 4
        0x02, 0x13, 0x0a, 0x33, // 2.19.10.51
    };
    _ = buffer;
    _ = message;
}

pub fn genRandomID(seed: u64) !u16 {
    // const seed: u64 = @truncate(@as(u128, @bitCast(std.time.nanoTimestamp())));
    const prng = std.rand.DefaultPrng.init(seed);

    return prng.random().init().init(u16);
}

fn intToBigBytes(value: u16) [2]u8 {
    var bytes: [2]u8 = undefined;
    std.mem.writeInt(u16, &bytes, value, .big);
    return bytes;
}

fn bytesToInt(high: u8, low: u8) u16 {
    return std.mem.readInt(u16, &[_]u8{ high, low }, .big);
}

fn valueToEnum(comptime T: type, value: u16, mask: u16) T {
    return @as(T, @enumFromInt(value & mask));
}

fn domainToLabels(domain: []const u8, buff: []u8) DNSError!usize {
    if (buff.len < domain.len + 2) return DNSError.BufferTooSmall;
    if (domain.len > 253) return DNSError.DomainTooLong;

    var pos: usize = 0;
    var it = std.mem.splitScalar(u8, domain, '.');

    while (it.next()) |label| {
        if (label.len == 0) continue;
        if (label.len > 63) return DNSError.LabelTooLong;

        buff[pos] = @intCast(label.len);
        pos += 1;
        @memcpy(buff[pos .. pos + label.len], label);
        pos += label.len;
    }
    buff[pos] = 0x00;
    pos += 1;

    return pos;
}

test "Should transform a domain to labels" {
    const domain = "www.example.com";
    var buffer: [24]u8 = undefined;

    const len = try domainToLabels(domain, &buffer);
    const expected = "\x03\x77\x77\x77\x07\x65\x78\x61\x6d\x70\x6c\x65\x03\x63\x6f\x6d\x00";
    try std.testing.expectEqualSlices(u8, expected, buffer[0..len]);
}

test "Should ignore empty labels" {
    const domains = [_][]const u8{ ".www.example.com", "www..example.com", "www.example..com", "www.example.com." };
    var buffer: [24]u8 = undefined;

    for (domains) |domain| {
        const len = try domainToLabels(domain, &buffer);
        const expected = "\x03\x77\x77\x77\x07\x65\x78\x61\x6d\x70\x6c\x65\x03\x63\x6f\x6d\x00";
        try std.testing.expectEqualSlices(u8, expected, buffer[0..len]);
    }
}

test "Should return DomainTooLongError when a label size is bigger than 253 chars" {
    const domain_253 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc.ddddddddddddddddddddddddddddddddddddddddddddddddddddddddd.com";
    const domain_254 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc.dddddddddddddddddddddddddddddddddddddddddddddddddddddddddd.com";
    var buffer: [512]u8 = undefined;

    _ = try domainToLabels(domain_253, &buffer);
    try std.testing.expectError(DNSError.DomainTooLong, domainToLabels(domain_254, &buffer));
}

test "Should return LabelTooLongError when a label size is bigger than 63 chars" {
    const domain_63 = "www.123456789012345678901234567890123456789012345678901234567890123.com";
    const domain_64 = "www.1234567890123456789012345678901234567890123456789012345678901234.com";
    var buffer: [128]u8 = undefined;

    _ = try domainToLabels(domain_63, &buffer);
    try std.testing.expectError(DNSError.LabelTooLong, domainToLabels(domain_64, &buffer));
}

test "Should return BufferTooSmall error when the buffer cant contain the result" {
    const domain = "www.example.com";
    var big_buffer: [17]u8 = undefined;
    var small_buffer: [16]u8 = undefined;

    _ = try domainToLabels(domain, &big_buffer);
    try std.testing.expectError(DNSError.BufferTooSmall, domainToLabels(domain, &small_buffer));
}

fn isCompressionByte(byte: u8) bool {
    return byte & 0xC0 == 0xC0;
}

fn sequentialLabelsToDomain(buff: []u8, labels: []u8, pos: usize) DNSError!usize {
    if (labels.len > 255) return DNSError.LabelTooLong;
    if (buff.len < labels.len + 2) return DNSError.BufferTooSmall;

    const len: u8 = labels[0];
    if (isCompressionByte(len)) return pos;
    if (len == 0 and pos == 0) return pos;
    if (len == 0) return pos - 1;

    @memcpy(buff[pos .. pos + len], labels[1 .. len + 1]);
    if (labels[len + 1] != 0) buff[pos + len] = '.';

    return try sequentialLabelsToDomain(buff, labels[len + 1 ..], pos + len + 1);
}

test "Should parse labels to a domain" {
    var buffer: [32]u8 = undefined;
    var labels = [_]u8{
        0x03, 0x77, 0x77, 0x77, // www
        0x07, 0x65, 0x78, 0x61, 0x6D, 0x70, 0x6C, 0x65, // example
        0x03, 0x63, 0x6F, 0x6D, // com
        0x00, // null
    };
    const len = try sequentialLabelsToDomain(&buffer, &labels, 0);
    try std.testing.expectEqualSlices(u8, "www.example.com", buffer[0..len]);
    try std.testing.expectEqual(15, len);
}

test "Should not parse when it doesnt have labels" {
    var buffer: [32]u8 = undefined;
    var labels = [_]u8{
        0x00, // null name
    };
    const len = try sequentialLabelsToDomain(&buffer, &labels, 0);
    try std.testing.expectEqualSlices(u8, "", buffer[0..len]);
    try std.testing.expectEqual(0, len);
}

test "Should parse labels with compression to a domain" {
    var buffer: [32]u8 = undefined;
    var labels = [_]u8{
        0x03, 0x77, 0x77, 0x77, // www
        0x07, 0x65, 0x78, 0x61, 0x6D, 0x70, 0x6C, 0x65, // example
        0x03, 0x63, 0x6F, 0x6D, // com
        0xC0, 0x04, // Pointer to example.com
    };
    const len = try sequentialLabelsToDomain(&buffer, &labels, 0);
    try std.testing.expectEqualSlices(u8, "www.example.com.", buffer[0..len]);
    try std.testing.expectEqual(16, len);
}

test "Should return BufferTooSmall when buffer is too small to fit the domain" {
    var buffer: [2]u8 = undefined;
    var labels = [_]u8{
        0x03, 0x77, 0x77, 0x77, // www
        0x07, 0x65, 0x78, 0x61, 0x6D, 0x70, 0x6C, 0x65, // example
        0x03, 0x63, 0x6F, 0x6D, // com
        0x00, // null
    };
    try std.testing.expectError(DNSError.BufferTooSmall, sequentialLabelsToDomain(&buffer, &labels, 0));
}

test "Should return LabelTooLong when the labels is too long for a valid domain" {
    var buffer: [512]u8 = undefined;
    var labels_253 = [_]u8{
        0x3f, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, // aaa...
        0x3f, 0x62, 0x62, 0x62, 0x62, 0x62, 0x62, 0x62, 0x62, 0x62, 0x62, 0x62, 0x62, 0x62, 0x62, 0x62, 0x62, 0x62, 0x62, 0x62, 0x62, 0x62, 0x62, 0x62, 0x62, 0x62, 0x62, 0x62, 0x62, 0x62, 0x62, 0x62, 0x62, 0x62, 0x62, 0x62, 0x62, 0x62, 0x62, 0x62, 0x62, 0x62, 0x62, 0x62, 0x62, 0x62, 0x62, 0x62, 0x62, 0x62, 0x62, 0x62, 0x62, 0x62, 0x62, 0x62, 0x62, 0x62, 0x62, 0x62, 0x62, 0x62, 0x62, 0x62, // bbb...
        0x3f, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, // ccc...
        0x39, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, // ddd...
        0x03, 0x63, 0x6f, 0x6d, // com
        0x00, // null
    };
    var labels_254 = [_]u8{
        0x3f, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, // aaa...
        0x3f, 0x62, 0x62, 0x62, 0x62, 0x62, 0x62, 0x62, 0x62, 0x62, 0x62, 0x62, 0x62, 0x62, 0x62, 0x62, 0x62, 0x62, 0x62, 0x62, 0x62, 0x62, 0x62, 0x62, 0x62, 0x62, 0x62, 0x62, 0x62, 0x62, 0x62, 0x62, 0x62, 0x62, 0x62, 0x62, 0x62, 0x62, 0x62, 0x62, 0x62, 0x62, 0x62, 0x62, 0x62, 0x62, 0x62, 0x62, 0x62, 0x62, 0x62, 0x62, 0x62, 0x62, 0x62, 0x62, 0x62, 0x62, 0x62, 0x62, 0x62, 0x62, 0x62, 0x62, // bbb...
        0x3f, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, // ccc...
        0x39, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, // ddd...
        0x04, 0x63, 0x6f, 0x6d, 0x69, // comi
        0x00, // null
    };

    _ = try sequentialLabelsToDomain(&buffer, &labels_253, 0);
    try std.testing.expectError(DNSError.LabelTooLong, sequentialLabelsToDomain(&buffer, &labels_254, 0));
}

fn labelsLen(labels: []u8) DNSError!usize {
    var len: usize = 0;
    var idx: usize = 0;
    var jumps: usize = 0;
    while (true) {
        const byte = labels[idx];
        if (byte == 0) break;
        if (isCompressionByte(byte)) break;
        if (len > 255) return DNSError.LabelTooLong;

        len += byte;
        idx += byte + 1;
        jumps += 1;
    }

    if (isCompressionByte(labels[len + jumps])) return len + jumps;
    return len + jumps + 1;
}

test "Should return the labels length" {
    var labels = [_]u8{
        0x03, 0x77, 0x77, 0x77, // www
        0x07, 0x65, 0x78, 0x61, 0x6D, 0x70, 0x6C, 0x65, // example
        0x03, 0x63, 0x6F, 0x6D, // com
        0x00, // null
    };

    try std.testing.expectEqual(17, try labelsLen(&labels));
}

test "Should return the labels with compression length" {
    var labels = [_]u8{
        0x03, 0x77, 0x77, 0x77, // www
        0x07, 0x65, 0x78, 0x61, 0x6D, 0x70, 0x6C, 0x65, // example
        0x03, 0x63, 0x6F, 0x6D, // com
        0xC0, 0x04, // Compression
    };

    try std.testing.expectEqual(16, try labelsLen(&labels));
}

fn compressedLabelsToDomain(packet: []u8, buff: []u8, compression: []u8) !usize {
    const pointer = bytesToInt(compression[0], compression[1]) ^ 0xC0_00;
    if (pointer > packet.len) return DNSError.InvalidPointer;
    if (isCompressionByte(packet[pointer])) return DNSError.InvalidPointer;

    var len = try labelsLen(packet[pointer..]);
    len = try sequentialLabelsToDomain(buff, packet[pointer .. pointer + len], 0);

    return len;
}

test "Should return compressed labels" {
    var buffer: [512]u8 = undefined;
    var packet = [_]u8{
        0x03, 0x77, 0x77, 0x77, // www
        0x07, 0x65, 0x78, 0x61, 0x6D, 0x70, 0x6C, 0x65, // example
        0x03, 0x63, 0x6F, 0x6D, // com
        0x00, // null
        0xC0, 0x04, // Pointer to example.com
    };
    var compression = [_]u8{ 0xC0, 0x04 };
    const len = try compressedLabelsToDomain(&packet, &buffer, &compression);

    try std.testing.expectEqualSlices(u8, "example.com", buffer[0..len]);
}

test "Should return InvalidPointer when compression pointer is out of bounds" {
    var buffer: [512]u8 = undefined;
    var packet = [_]u8{
        0x03, 0x77, 0x77, 0x77, // www
        0x07, 0x65, 0x78, 0x61, 0x6D, 0x70, 0x6C, 0x65, // example
        0x03, 0x63, 0x6F, 0x6D, // com
        0x00, // null
        0xC0, 0x20, // Invalid compression pointer (out of bounds)
    };
    var compression = [_]u8{ 0xC0, 0x20 };
    try std.testing.expectError(DNSError.InvalidPointer, compressedLabelsToDomain(&packet, &buffer, &compression));
}

test "Should return InvalidPointer when compression pointer points to another pointer" {
    var buffer: [512]u8 = undefined;
    var packet = [_]u8{
        0x03, 0x77, 0x77, 0x77, // www
        0x07, 0x65, 0x78, 0x61, 0x6D, 0x70, 0x6C, 0x65, // example
        0x03, 0x63, 0x6F, 0x6D, // com
        0x00, // null
        0xC0, 0x13, // Points to the next pointer
        0xC0, 0x04, // Points to example.com
    };
    var compression = [_]u8{ 0xC0, 0x13 };
    try std.testing.expectError(DNSError.InvalidPointer, compressedLabelsToDomain(&packet, &buffer, &compression));
}

fn labelsToDomain(allocator: std.mem.Allocator, packet: []u8, pos: *usize) ![]u8 {
    var temp: [512]u8 = undefined;
    var len: usize = 0;

    if (isCompressionByte(packet[pos.*])) {
        len = try compressedLabelsToDomain(packet, &temp, packet[pos.* .. pos.* + 2]);
    } else {
        len = try sequentialLabelsToDomain(&temp, packet[pos.*..], 0);
        if (len == 0) {
            pos.* += 1;
            return "";
        }
        pos.* += len;
        if (isCompressionByte(packet[pos.*])) {
            len += try compressedLabelsToDomain(packet, temp[len..], packet[pos.* .. pos.* + 2]);
        }
    }
    pos.* += 2;
    return try allocator.dupe(u8, temp[0..len]);
}

test "Should handle sequential labels" {
    const allocator = std.testing.allocator;
    var packet = [_]u8{
        0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, // Headers
        0x03, 0x77, 0x77, 0x77, // www
        0x07, 0x65, 0x78, 0x61, 0x6D, 0x70, 0x6C, 0x65, // example
        0x03, 0x63, 0x6F, 0x6D, // com
        0x00, // null
        0x03, 0x61, 0x70, 0x69, // api
        0xC0, 0x10, // Pointer to example.com
        0x00, 0x01, // QType
        0x00, 0x01, // Class
    };
    var pos: usize = 12;
    const buffer = try labelsToDomain(allocator, &packet, &pos);
    defer allocator.free(buffer);

    try std.testing.expectEqualSlices(u8, "www.example.com", buffer);
    try std.testing.expectEqual(29, pos);
}

test "Should handle multiple compression levels correctly" {
    const allocator = std.testing.allocator;
    var packet = [_]u8{
        0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, // Headers
        0x03, 0x77, 0x77, 0x77, // www
        0x07, 0x65, 0x78, 0x61, 0x6D, 0x70, 0x6C, 0x65, // example
        0x03, 0x63, 0x6F, 0x6D, // com
        0x00, // null
        0x03, 0x61, 0x70, 0x69, // api
        0xC0, 0x10, // Pointer to example.com
        0x00, 0x01, // QType
        0x00, 0x01, // Class
    };
    var pos: usize = 29;
    const buffer = try labelsToDomain(allocator, &packet, &pos);
    defer allocator.free(buffer);

    try std.testing.expectEqualSlices(u8, "api.example.com", buffer);
    try std.testing.expectEqual(35, pos);
}

test "Should handle when starting with compression" {
    const allocator = std.testing.allocator;
    var packet = [_]u8{
        0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, // Headers
        0x03, 0x77, 0x77, 0x77, // www
        0x07, 0x65, 0x78, 0x61, 0x6D, 0x70, 0x6C, 0x65, // example
        0x03, 0x63, 0x6F, 0x6D, // com
        0x00, // null
        0x03, 0x61, 0x70, 0x69, // api
        0xC0, 0x10, // Pointer to example.com
        0x00, 0x01, // QType
        0x00, 0x01, // Class
    };
    var pos: usize = 33;
    const buffer = try labelsToDomain(allocator, &packet, &pos);
    defer allocator.free(buffer);

    try std.testing.expectEqualSlices(u8, "example.com", buffer);
    try std.testing.expectEqual(35, pos);
}

test "Should handle an empty domain" {
    const allocator = std.testing.allocator;
    var packet = [_]u8{
        // Headers
        0x12, 0x34, // ID
        0x81, 0x80, // Flags
        0x00, 0x01, // QD Count = 1
        0x00, 0x00, // AN Count = 0
        0x00, 0x00, // NS Count = 0
        0x00, 0x01, // AR Count = 1
        // Question
        0x03, 0x77, 0x77, 0x77, // www
        0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, // example
        0x03, 0x63, 0x6f, 0x6d, // com
        0x00, // null
        0x00, 0x01, // Type = A
        0x00, 0x01, // Class = IN
        // Additional
        0x00, // null name
        0x00, 0x29, // Type = OPT
        0x04, 0xd0, // Class = UDP Payload Size
        0x00, 0x00, 0x00, 0x00, // TTL = Extended RCODE and Flags
        0x00, 0x00, // RDLENGTH = 0
    };
    var pos: usize = 33;
    const buffer = try labelsToDomain(allocator, &packet, &pos);
    defer allocator.free(buffer);

    try std.testing.expectEqualSlices(u8, "", buffer);
    try std.testing.expectEqual(34, pos);
}
