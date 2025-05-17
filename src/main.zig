const std = @import("std");
const server = @import("./server.zig");
const packet = @import("./packet.zig");
const args = @import("./args.zig");
const config = @import("./config.zig");

pub fn main() !void {
    var buffer: [4096]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&buffer);
    var arena = std.heap.ArenaAllocator.init(fba.allocator());
    defer arena.deinit();
    const allocator = arena.allocator();

    var argv = args.ArgV.init(allocator) catch |err| {
        std.debug.panic("Failed to parse args: {}\n", .{err});
    };
    defer argv.deinit();
    const domain = argv.query_name();
    const path = argv.config_file();

    var upstream_config = config.JSONConfiguration.init(.{ .allocator = allocator, .path = path }) catch |err| {
        std.debug.panic("Failed to load config file: {}\n", .{err});
    };
    defer upstream_config.deinit();

    var pkt = packet.Packet.init(.{ .allocator = allocator, .query_name = domain, .id = 0x1234 }) catch |err| {
        std.debug.panic("Failed to initialize Packet: {}\n", .{err});
    };
    defer pkt.deinit();

    var data_pkt = allocator.alloc(u8, 512) catch |err| {
        std.debug.panic("Failed allocate memory for the packet: {}\n", .{err});
    };
    var len = pkt.serialize(data_pkt) catch |err| {
        std.debug.panic("Failed to serialize Packet: {}\n", .{err});
    };

    const upstream = upstream_config.next_upstream() catch |err| {
        std.debug.panic("Failed to get next upstream: {}\n", .{err});
    };
    var client = server.UDPClient.init(.{ .address = upstream.ip, .port = upstream.port }) catch |err| {
        std.debug.panic("Failed to initialize UDP client: {}\n", .{err});
    };
    defer client.close();

    client.connect() catch |err| {
        std.debug.panic("Failed to connect to the server {any}: {}\n", .{ client.addr, err });
    };

    _ = client.write(data_pkt[0..len]) catch |err| {
        std.debug.panic("Failed to send a message to the server: {any}: {}", .{ client.addr, err });
    };
    len = client.read(data_pkt) catch |err| {
        std.debug.panic("Failed to receive a message from the server: {any}: {}", .{ client.addr, err });
    };
    std.debug.print("received from the server: {x}\n", .{data_pkt[0..len]});

    pkt = packet.Packet.deserialize(allocator, data_pkt[0..len]) catch |err| {
        std.debug.panic("Failed deserialize the received packet from the server: {}", .{err});
    };
    std.debug.print("deserialized packet: {any}\n", .{pkt});
}
