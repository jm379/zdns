// RFC 1035
// https://www.rfc-editor.org/rfc/rfc1035
const std = @import("std");
const print = std.debug.print;
const posix = std.posix;
const net = std.net;
const server = @import("./server.zig");
const packet = @import("./packet.zig");

pub fn main() !void {
    var buffer: [512]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&buffer);
    var arena = std.heap.ArenaAllocator.init(fba.allocator());
    defer arena.deinit();

    var pkt = try packet.Packet.init(.{ .allocator = arena.allocator(), .query_name = "www.example.com", .id = 0x1234 });
    defer pkt.deinit();

    const query = try pkt.serialize();
    var client = server.UDPClient.init(.{ .address = "1.1.1.1", .port = 53 }) catch |err| {
        print("Failed to initialize UDP client: {}\n", .{err});
        posix.exit(1);
    };
    defer client.close();

    client.connect() catch |err| {
        print("Failed to connect to the server {any}: {}\n", .{ client.addr, err });
        posix.exit(1);
    };

    _ = client.write(query) catch |err| {
        print("Failed to send a message to the server: {any}: {}", .{ client.addr, err });
    };
    var recv: [512]u8 = undefined;
    const len = try client.read(&recv);
    print("received from the server: {x}\n", .{recv[0..len]});
}
