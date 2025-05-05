const std = @import("std");

pub const ArgV = struct {
    allocator: std.mem.Allocator,
    args: [][:0]u8,
    pub fn init(allocator: std.mem.Allocator) !ArgV {
        return .{
            .args = try std.process.argsAlloc(allocator),
            .allocator = allocator,
        };
    }
    pub fn deinit(self: *ArgV) void {
        std.process.argsFree(self.allocator, self.args);
    }
};

pub fn query_name(argv: ArgV) []u8 {
    var domain: []u8 = undefined;

    if (argv.args.len <= 1) {
        std.debug.print("Error: Please provide a valid domain name\n", .{});
        std.posix.exit(1);
    }

    domain = argv.allocator.dupe(u8, argv.args[1]) catch |err| {
        std.debug.panic("Failed to allocate memory for domain arg: {}\n", .{err});
    };

    std.debug.print("Querying for domain: {s}\n", .{domain});
    return domain;
}
