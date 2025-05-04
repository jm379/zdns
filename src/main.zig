const std = @import("std");
const server = @import("./server.zig");
const packet = @import("./packet.zig");
const args = @import("./args.zig");

pub fn main() !void {
    var buffer: [4096]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&buffer);
    var arena = std.heap.ArenaAllocator.init(fba.allocator());
    defer arena.deinit();
    const allocator = arena.allocator();

    var cargs = try args.ArgV.init(allocator);
    defer cargs.deinit();

    if (!cargs.args.skip())
        std.debug.panic("Domain name needed\n", .{});

    const domain = try allocator.dupe(u8, cargs.args.next().?);
    defer allocator.free(domain);
    std.debug.print("domain: {s}\n", .{domain});

    var pkt = packet.Packet.init(.{ .allocator = allocator, .query_name = domain, .id = 0x1234 }) catch |err| {
        std.debug.panic("Failed to initialize Packet: {}\n", .{err});
    };

    defer pkt.deinit();

    var data_pkt = try allocator.alloc(u8, 512);
    var len = try pkt.serialize(data_pkt);
    var client = server.UDPClient.init(.{ .address = "1.1.1.1", .port = 53 }) catch |err| {
        std.debug.panic("Failed to initialize UDP client: {}\n", .{err});
    };
    defer client.close();

    client.connect() catch |err| {
        std.debug.panic("Failed to connect to the server {any}: {}\n", .{ client.addr, err });
    };

    _ = client.write(data_pkt[0..len]) catch |err| {
        std.debug.panic("Failed to send a message to the server: {any}: {}", .{ client.addr, err });
    };
    len = try client.read(data_pkt);
    std.debug.print("received from the server: {x}\n", .{data_pkt[0..len]});

    pkt = try packet.Packet.deserialize(allocator, data_pkt[0..len]);
    std.debug.print("deserialized packet: {any}\n", .{pkt});
}
