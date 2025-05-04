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
    PacketTooSmall,
    PacketTooLong,
};

var compressed: bool = false;

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
    fn deserialize(data: []u8) Flags {
        const value = bytesToInt(data[0], data[1]);
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

test "Should serialize Flags" {
    var flags: Flags = Flags{ .operation_code = .inverse };
    const data: u16 = flags.serialize();

    try std.testing.expectEqual(0b0000_1001_0000_0000, data);
}

test "Should deserialize Flags" {
    var data = [2]u8{ 0x81, 0x80 };
    const flags = Flags.deserialize(&data);
    _ = &data;

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
        if (data.len < 12) return DNSError.WrongSize;

        return .{
            .id = bytesToInt(data[0], data[1]),
            .flags = Flags.deserialize(data[2..4]),
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

    const expected = [_]u8{ 0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    const len = try header.serialize(&buffer);
    try std.testing.expectEqualSlices(u8, &expected, buffer[0..len]);
}

test "Should deserialize Header" {
    var data = [_]u8{ 0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00 };
    const header = try Header.deserialize(&data);
    _ = &data;

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
    fn deserialize(allocator: std.mem.Allocator, packet: []u8, pos: *usize, question: bool) !ResourceRecord {
        const name = try labelsToDomain(allocator, packet, pos);
        var rd_length: u16 = 0;
        var ttl: u32 = 0;
        var r_data: ?[]u8 = null;

        const query_type = parseQueryType(packet, pos);
        const query_class = parseQueryClass(packet, pos);

        if (!question) {
            ttl = parseTTL(packet, pos);
            rd_length = parseRDLength(packet, pos);
            r_data = parseRData(packet, query_type, rd_length, pos);
        }

        return .{
            .allocator = allocator,
            .name = name,
            .type = query_type,
            .class = query_class,
            .ttl = ttl,
            .rd_length = rd_length,
            .r_data = r_data,
        };
    }
    fn parseQueryType(packet: []u8, pos: *usize) QueryType {
        const h: u8 = packet[pos.*];
        const l: u8 = packet[pos.* + 1];
        pos.* += 2;

        return valueToEnum(QueryType, bytesToInt(h, l), 0x00_FF);
    }
    fn parseQueryClass(packet: []u8, pos: *usize) QueryClass {
        const h: u8 = packet[pos.*];
        const l: u8 = packet[pos.* + 1];
        pos.* += 2;

        return valueToEnum(QueryClass, bytesToInt(h, l), 0xFF_FF);
    }
    fn parseTTL(packet: []u8, pos: *usize) u32 {
        const b1: u8 = packet[pos.*];
        const b2: u8 = packet[pos.* + 1];
        const b3: u8 = packet[pos.* + 2];
        const b4: u8 = packet[pos.* + 3];
        pos.* += 4;

        return (@as(u32, b1) << 24) |
            (@as(u32, b2) << 16) |
            (@as(u32, b3) << 8) |
            @as(u32, b4);
    }
    fn parseRDLength(packet: []u8, pos: *usize) u16 {
        const h: u8 = packet[pos.*];
        const l: u8 = packet[pos.* + 1];
        pos.* += 2;

        return bytesToInt(h, l);
    }
    fn parseRData(packet: []u8, queryType: QueryType, rd_length: u16, pos: *usize) []u8 {
        // TODO: parse rdata depending on the QueryType
        _ = queryType;
        const r_data = packet[pos.* .. pos.* + rd_length];
        pos.* += rd_length;

        return r_data;
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
    var packet = [_]u8{
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
        0x00, 0x01, // Type = A
        0x00, 0x01, // Class = IN
    };
    var offset: usize = 12;
    var question = try ResourceRecord.deserialize(allocator, &packet, &offset, true);
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
        0x01, 0x02, 0x03, 0x04, // TTL = 16909060 seconds
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
    try std.testing.expectEqual(16909060, answer.ttl);
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
    try std.testing.expectEqual(0x04_D0, @intFromEnum(answer.class));
    try std.testing.expectEqual(0, answer.ttl);
    try std.testing.expectEqual(0, answer.rd_length);

    var r_data = [_]u8{};
    try std.testing.expectEqualSlices(u8, &r_data, answer.r_data.?);
    try std.testing.expectEqual(43 + 1, offset);
}

const PacketConfig = struct { allocator: std.mem.Allocator, id: u16, query_type: QueryType = .A, query_name: []u8 };
pub const Packet = struct {
    allocator: std.mem.Allocator = undefined,
    header: Header,
    question: ResourceRecord,
    answer: ?[]ResourceRecord = null,
    authority: ?[]ResourceRecord = null,
    additional: ?[]ResourceRecord = null,
    pub fn init(config: PacketConfig) !Packet {
        return .{ .allocator = config.allocator, .header = Header{
            .id = config.id,
            .flags = .{},
            .question_count = 1,
        }, .question = try ResourceRecord.init(.{
            .query_type = config.query_type,
            .query_name = config.query_name,
        }) };
    }
    pub fn deinit(self: *Packet) void {
        self.question.deinit();
        freeResourceRecords(self.allocator, self.answer);
        freeResourceRecords(self.allocator, self.authority);
        freeResourceRecords(self.allocator, self.additional);
    }
    fn freeResourceRecords(allocator: std.mem.Allocator, rrecords: ?[]ResourceRecord) void {
        if (rrecords) |records| {
            for (records) |*record| {
                record.deinit();
            }
            allocator.free(records);
        }
    }
    pub fn serialize(self: *Packet, buff: []u8) !usize {
        var tlen: usize = 0;
        var len = try self.header.serialize(buff);
        tlen += len;

        len = try self.question.serialize(buff[len..]);
        tlen += len;

        return tlen;
    }
    pub fn deserialize(allocator: std.mem.Allocator, data: []u8) !Packet {
        switch (data.len) {
            0 => return error.EmptyPacket,
            1...17 => return error.PacketTooSmall,
            18...512 => {},
            else => return error.PacketTooLong,
        }

        var pos: usize = 12;
        var packet = Packet{
            .allocator = allocator,
            .header = try Header.deserialize(data),
            .question = try ResourceRecord.deserialize(allocator, data, &pos, true),
        };

        if (packet.header.answer_count > 0) {
            packet.answer = try allocator.alloc(ResourceRecord, packet.header.answer_count);
            for (0..packet.header.answer_count) |i| {
                packet.answer.?[i] = try ResourceRecord.deserialize(allocator, data, &pos, false);
            }
        }
        if (packet.header.authoritive_count > 0) {
            packet.authority = try allocator.alloc(ResourceRecord, packet.header.authoritive_count);
            for (0..packet.header.authoritive_count) |i| {
                packet.authority.?[i] = try ResourceRecord.deserialize(allocator, data, &pos, false);
            }
        }
        if (packet.header.additional_count > 0) {
            packet.additional = try allocator.alloc(ResourceRecord, packet.header.additional_count);
            for (0..packet.header.additional_count) |i| {
                packet.additional.?[i] = try ResourceRecord.deserialize(allocator, data, &pos, false);
            }
        }

        return packet;
    }
};

test "Should serialize Packet" {
    const allocator = std.testing.allocator;
    var buffer: [512]u8 = undefined;
    var name = [_]u8{ 'w', 'w', 'w', '.', 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm' };
    var packet = try Packet.init(.{ .allocator = allocator, .query_name = &name, .id = 0x1234 });

    const expected = [_]u8{
        // Headers
        0x12, 0x34, // ID
        0x01, 0x00, // Flags
        0x00, 0x01, // QD Count = 1
        0x00, 0x00, // AN Count = 0
        0x00, 0x00, // NS Count = 0
        0x00, 0x00, // AR Count = 0
        // Question
        0x03, 0x77, 0x77, 0x77, // www
        0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, // example
        0x03, 0x63, 0x6f, 0x6d, // com
        0x00, // null
        0x00, 0x01, // Type = A
        0x00, 0x01, // Class = IN
    };
    const len = try packet.serialize(&buffer);

    try std.testing.expectEqualSlices(u8, &expected, buffer[0..len]);
}

test "Should deserialize Packet" {
    const allocator = std.testing.allocator;
    var packet = [_]u8{
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
    var answer = try Packet.deserialize(allocator, &packet);
    defer answer.deinit();

    // Headers
    try std.testing.expectEqual(0x12_34, answer.header.id);
    try std.testing.expectEqual(QueryResponse.response, answer.header.flags.query_response);
    try std.testing.expectEqual(OperationCode.standard, answer.header.flags.operation_code);
    try std.testing.expectEqual(AuthoritativeAnswer.no, answer.header.flags.authorative_answer);
    try std.testing.expectEqual(Truncated.no, answer.header.flags.truncated);
    try std.testing.expectEqual(RecursionDesired.yes, answer.header.flags.recursion_desired);
    try std.testing.expectEqual(RecursionAvailable.yes, answer.header.flags.recursion_available);
    try std.testing.expectEqual(ResponseCode.no_error, answer.header.flags.response_code);
    try std.testing.expectEqual(0x00_01, answer.header.question_count);
    try std.testing.expectEqual(0x00_04, answer.header.answer_count);
    try std.testing.expectEqual(0x00_00, answer.header.authoritive_count);
    try std.testing.expectEqual(0x00_00, answer.header.additional_count);

    // Question
    try std.testing.expectEqualSlices(u8, "www.example.com", answer.question.name);
    try std.testing.expectEqual(QueryType.A, answer.question.type);
    try std.testing.expectEqual(QueryClass.IN, answer.question.class);
    try std.testing.expectEqual(null, answer.question.r_data);

    // Answer 1
    try std.testing.expectEqualSlices(u8, "www.example.com", answer.answer.?[0].name);
    try std.testing.expectEqual(QueryType.CNAME, answer.answer.?[0].type);
    try std.testing.expectEqual(QueryClass.IN, answer.answer.?[0].class);
    try std.testing.expectEqual(91, answer.answer.?[0].ttl);
    try std.testing.expectEqual(34, answer.answer.?[0].rd_length);

    // Answer 2
    try std.testing.expectEqualSlices(u8, "www.example.com-v4.edgesuite.net", answer.answer.?[1].name);
    try std.testing.expectEqual(QueryType.CNAME, answer.answer.?[1].type);
    try std.testing.expectEqual(QueryClass.IN, answer.answer.?[1].class);
    try std.testing.expectEqual(21391, answer.answer.?[1].ttl);
    try std.testing.expectEqual(20, answer.answer.?[1].rd_length);

    // Answer 3
    var r_data = [_]u8{ 0x02, 0x13, 0x0a, 0x4b };
    try std.testing.expectEqualSlices(u8, "a1422.dscr.akamai.net", answer.answer.?[2].name);
    try std.testing.expectEqual(QueryType.A, answer.answer.?[2].type);
    try std.testing.expectEqual(QueryClass.IN, answer.answer.?[2].class);
    try std.testing.expectEqual(20, answer.answer.?[2].ttl);
    try std.testing.expectEqual(4, answer.answer.?[2].rd_length);
    try std.testing.expectEqualSlices(u8, &r_data, answer.answer.?[2].r_data.?);

    // Answer 4
    r_data = [_]u8{ 0x02, 0x13, 0x0a, 0x33 };
    try std.testing.expectEqualSlices(u8, "a1422.dscr.akamai.net", answer.answer.?[3].name);
    try std.testing.expectEqual(QueryType.A, answer.answer.?[3].type);
    try std.testing.expectEqual(QueryClass.IN, answer.answer.?[3].class);
    try std.testing.expectEqual(20, answer.answer.?[3].ttl);
    try std.testing.expectEqual(4, answer.answer.?[3].rd_length);
    try std.testing.expectEqualSlices(u8, &r_data, answer.answer.?[3].r_data.?);

    // Authorative Answers
    try std.testing.expectEqual(null, answer.authority);

    // Aditional
    try std.testing.expectEqual(null, answer.additional);
}

test "Should deserialize SOA Packet" {
    const allocator = std.testing.allocator;
    var packet = [_]u8{
        // Headers
        0x12, 0x34, // ID
        0x81, 0x80, // Flags
        0x00, 0x01, // QD Count = 1
        0x00, 0x00, // AN Count = 0
        0x00, 0x01, // NS Count = 1
        0x00, 0x00, // AR Count = 0
        // Question
        0x03, 0x77, 0x77, 0x77, // www
        0x07, 0x65, 0x78, 0x6d, 0x61, 0x70, 0x6c, 0x65, // exmaple
        0x03, 0x63, 0x6f, 0x6d, // com
        0x00, // null
        0x00, 0x01, // Type = A
        0x00, 0x01, // Class = IN
        // Authorative Answer
        0xc0, 0x10, // Pointer to www.exmaple.com
        0x00, 0x06, // Type = SOA
        0x00, 0x01, // Class = IN
        0x00, 0x00, 0x07, 0x08, // TTL = 1800
        0x00, 0x2e, // RD Length = 46
        // RData
        // MNAME
        0x03, 0x61, 0x72, 0x61, // ara
        0x02, 0x6e, 0x73, // ns
        0x0a, 0x63, 0x6c, 0x6f, 0x75, 0x64, 0x66, 0x6c, 0x61, 0x72, 0x65, // cloudflare
        0xc0, 0x18, // com
        // RNAME
        0x03, 0x64, 0x6e, 0x73, // dns
        0xc0, 0x34, // pointer to couldflare.com
        0x8d, 0x5f, 0xb5, 0x5f, // Serial = 2371859807
        0x00, 0x00, 0x27, 0x10, // Refresh = 10000
        0x00, 0x00, 0x09, 0x60, // Retry = 2400
        0x00, 0x09, 0x3a, 0x80, // Expire = 604800
        0x00, 0x00, 0x07, 0x08, // Minimum = 1800
    };
    var answer = try Packet.deserialize(allocator, &packet);
    defer answer.deinit();

    // Headers
    try std.testing.expectEqual(0x12_34, answer.header.id);
    try std.testing.expectEqual(QueryResponse.response, answer.header.flags.query_response);
    try std.testing.expectEqual(OperationCode.standard, answer.header.flags.operation_code);
    try std.testing.expectEqual(AuthoritativeAnswer.no, answer.header.flags.authorative_answer);
    try std.testing.expectEqual(Truncated.no, answer.header.flags.truncated);
    try std.testing.expectEqual(RecursionDesired.yes, answer.header.flags.recursion_desired);
    try std.testing.expectEqual(RecursionAvailable.yes, answer.header.flags.recursion_available);
    try std.testing.expectEqual(ResponseCode.no_error, answer.header.flags.response_code);
    try std.testing.expectEqual(0x00_01, answer.header.question_count);
    try std.testing.expectEqual(0x00_00, answer.header.answer_count);
    try std.testing.expectEqual(0x00_01, answer.header.authoritive_count);
    try std.testing.expectEqual(0x00_00, answer.header.additional_count);

    // Question
    try std.testing.expectEqualSlices(u8, "www.exmaple.com", answer.question.name);
    try std.testing.expectEqual(QueryType.A, answer.question.type);
    try std.testing.expectEqual(QueryClass.IN, answer.question.class);
    try std.testing.expectEqual(null, answer.question.r_data);

    // Answer
    try std.testing.expectEqual(null, answer.answer);

    // Authorative Answers
    try std.testing.expectEqualSlices(u8, "exmaple.com", answer.authority.?[0].name);
    try std.testing.expectEqual(QueryType.SOA, answer.authority.?[0].type);
    try std.testing.expectEqual(QueryClass.IN, answer.authority.?[0].class);
    try std.testing.expectEqual(1800, answer.authority.?[0].ttl);
    try std.testing.expectEqual(46, answer.authority.?[0].rd_length);
    try std.testing.expectEqual(46, answer.authority.?[0].r_data.?.len);

    // Aditional
    try std.testing.expectEqual(null, answer.additional);
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
    return byte == 0xC0;
}

fn sequentialLabelsToDomain(domain: []u8, packet: []u8, pos: *usize, mlen: usize) DNSError!usize {
    const len: u8 = packet[pos.*];
    if (len == 0) return mlen; // null byte
    if (isCompressionByte(len)) return mlen + try compressedLabelsToDomain(domain, packet, pos);

    @memcpy(domain[0..len], packet[pos.* + 1 .. pos.* + len + 1]);
    domain[len] = '.';

    pos.* += len + 1;
    return try sequentialLabelsToDomain(domain[len + 1 ..], packet, pos, mlen + len + 1);
}

test "Should parse labels to a domain" {
    compressed = false;
    var domain: [32]u8 = undefined;
    var packet = [_]u8{
        0x03, 0x77, 0x77, 0x77, // www
        0x07, 0x65, 0x78, 0x61, 0x6D, 0x70, 0x6C, 0x65, // example
        0x03, 0x63, 0x6F, 0x6D, // com
        0x00, // null
    };
    var pos: usize = 0;
    const len = try sequentialLabelsToDomain(&domain, &packet, &pos, 0);

    try std.testing.expectEqualSlices(u8, "www.example.com.", domain[0..len]);
    try std.testing.expectEqual(16, len);
    try std.testing.expectEqual(16, pos);
}

test "Should not parse when it doesnt have labels" {
    compressed = false;
    var domain: [32]u8 = undefined;
    var packet = [_]u8{
        0x00, // null name
    };
    var pos: usize = 0;
    const len = try sequentialLabelsToDomain(&domain, &packet, &pos, 0);

    try std.testing.expectEqualSlices(u8, "", domain[0..len]);
    try std.testing.expectEqual(0, len);
    try std.testing.expectEqual(0, pos);
}

test "Should parse labels with compression to a domain" {
    compressed = false;
    var domain: [32]u8 = undefined;
    var packet = [_]u8{
        0x03, 0x6e, 0x65, 0x74, // net
        0x00, // null
        0x03, 0x77, 0x77, 0x77, // www
        0x07, 0x65, 0x78, 0x61, 0x6D, 0x70, 0x6C, 0x65, // example
        0xC0, 0x00, // Pointer to .net
    };
    var pos: usize = 5;
    const len = try sequentialLabelsToDomain(&domain, &packet, &pos, 0);

    try std.testing.expectEqualSlices(u8, "www.example.net.", domain[0..len]);
    try std.testing.expectEqual(16, len);
    try std.testing.expectEqual(18, pos);
}

fn compressedLabelsToDomain(domain: []u8, packet: []u8, pos: *usize) !usize {
    if (!isCompressionByte(packet[pos.*])) return 0;

    var pointer: usize = packet[pos.* + 1];
    if (pointer > packet.len) return DNSError.InvalidPointer;
    if (isCompressionByte(packet[pointer])) return DNSError.InvalidPointer;

    if (!compressed) {
        pos.* += 1;
        compressed = true;
    }

    return try sequentialLabelsToDomain(domain, packet, &pointer, 0);
}

test "Should return compressed labels" {
    compressed = false;
    var domain: [512]u8 = undefined;
    var packet = [_]u8{
        0x03, 0x77, 0x77, 0x77, // www
        0x07, 0x65, 0x78, 0x61, 0x6D, 0x70, 0x6C, 0x65, // example
        0x03, 0x63, 0x6F, 0x6D, // com
        0x00, // null
        0xC0, 0x04, // Pointer to example.com
    };
    var pos: usize = 17;
    const len = try compressedLabelsToDomain(&domain, &packet, &pos);

    try std.testing.expectEqualSlices(u8, "example.com.", domain[0..len]);
    try std.testing.expectEqual(12, len);
    try std.testing.expectEqual(18, pos);
}

test "Should return InvalidPointer when compression pointer is out of bounds" {
    compressed = false;
    var domain: [512]u8 = undefined;
    var packet = [_]u8{
        0x03, 0x77, 0x77, 0x77, // www
        0x07, 0x65, 0x78, 0x61, 0x6D, 0x70, 0x6C, 0x65, // example
        0x03, 0x63, 0x6F, 0x6D, // com
        0x00, // null
        0xC0, 0xFF, // Invalid compression pointer (out of bounds)
    };
    var pos: usize = 17;

    try std.testing.expectError(DNSError.InvalidPointer, compressedLabelsToDomain(&domain, &packet, &pos));
    try std.testing.expectEqual(17, pos);
}

test "Should return InvalidPointer when compression pointer points to another pointer" {
    compressed = false;
    var domain: [512]u8 = undefined;
    var packet = [_]u8{
        0x03, 0x77, 0x77, 0x77, // www
        0x07, 0x65, 0x78, 0x61, 0x6D, 0x70, 0x6C, 0x65, // example
        0x03, 0x63, 0x6F, 0x6D, // com
        0x00, // null
        0xC0, 0x13, // Points to the next pointer
        0xC0, 0x04, // Points to example.com
    };
    var pos: usize = 17;

    try std.testing.expectError(DNSError.InvalidPointer, compressedLabelsToDomain(&domain, &packet, &pos));
    try std.testing.expectEqual(17, pos);
}

fn labelsToDomain(allocator: std.mem.Allocator, packet: []u8, pos: *usize) ![]u8 {
    var domain: [512]u8 = undefined;
    var len: usize = 0;
    compressed = false;

    len += try sequentialLabelsToDomain(&domain, packet, pos, 0);
    pos.* += 1;

    if (len == 0) return try allocator.dupe(u8, "");

    return try allocator.dupe(u8, domain[0 .. len - 1]);
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
