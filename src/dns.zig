const std = @import("std");
const print = std.debug.print;
const net = std.net;
const packet = @import("./packet.zig");

const DNSConfig = struct { upstream: []const u8, port: u16 };
pub const DNS = struct {
    upstream: net.Address,
    pub fn init(config: DNSConfig) !DNS {
        return .{ .upstream = try net.Address.parseIp(config.upstream, config.port) };
    }
    pub fn query(self: *DNS, target: []const u8) void {
        print("Querying upstream `{}' for `{s}'", .{ self.upstream, target });
        // var header = self.packet.Header{ .qdcount = 1 };
        // _ = try header.init();
    }
};
