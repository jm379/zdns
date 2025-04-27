// RFC 1035
// https://www.rfc-editor.org/rfc/rfc1035
const std = @import("std");
const print = std.debug.print;
const posix = std.posix;
const net = std.net;
const server = @import("./server.zig");
const dns = @import("./dns.zig");

pub fn main() !void {
    print("DNS Server initializing...\n", .{});
    var udp_server = server.UDPServer.init() catch |err| {
        print("Failed to initialize UDP server: {}\n", .{err});
        posix.exit(1);
    };
    _ = udp_server.bind(.{ .address = "127.0.0.1", .port = 6868 }) catch |err| {
        print("Failed to bind the UDP server: {}\n", .{err});
        posix.exit(1);
    };
    udp_server.start() catch |err| {
        print("Failed to start the UDP server: {}\n", .{err});
        posix.exit(1);
    };
    _ = try udp_server.write("Hello!\n");
    defer udp_server.close();

    // var wdns = dns.DNS.init(.{ .upstream = "1.1.1.1", .port = 53 }) catch |err| {
    //     print("Failed to initialize DNS: {}\n", .{err});
    //     posix.exit(1);
    // };
    // wdns.query("www.example.com");
}
