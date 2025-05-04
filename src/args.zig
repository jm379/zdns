const std = @import("std");

pub const ArgV = struct {
    allocator: std.mem.Allocator,
    args: std.process.ArgIterator,
    pub fn init(allocator: std.mem.Allocator) !ArgV {
        const args = try std.process.argsWithAllocator(allocator);
        return .{ .args = args, .allocator = allocator };
    }
    pub fn deinit(self: *ArgV) void {
        self.args.deinit();
    }
};
