const std = @import("std");

pub const ArgV = struct {
    allocator: std.mem.Allocator,
    args: [][:0]u8,
    domain: []u8 = undefined,
    path: ?[]u8 = null,

    pub fn init(allocator: std.mem.Allocator) !ArgV {
        return .{
            .args = try std.process.argsAlloc(allocator),
            .allocator = allocator,
        };
    }
    pub fn deinit(self: *ArgV) void {
        std.process.argsFree(self.allocator, self.args);
        if (self.path) |path| {
            self.allocator.free(path);
        }
    }
    pub fn query_name(self: *ArgV) []u8 {
        const len = self.args.len;

        if (len <= 1) {
            std.debug.print("Error: Please provide a valid domain name\n", .{});
            std.posix.exit(1);
        }

        self.domain = self.args[len - 1];
        std.debug.print("Querying for domain: {s}\n", .{self.domain});
        return self.domain;
    }
    pub fn config_file(self: *ArgV) []u8 {
        for (self.args, 0..) |arg, i| {
            if (std.mem.eql(u8, arg, "-c")) {
                self.path = self.allocator.dupe(u8, self.args[i + 1]) catch |err| {
                    std.debug.panic("Failed to allocate memory for config file: {}\n", .{err});
                };
                std.debug.print("Loading config file: {s}\n", .{self.path.?});
                return self.path.?;
            }
        }

        self.path = self.allocator.dupe(u8, "./config.json") catch |err| {
            std.debug.panic("Failed to allocate memory for default config file: {}\n", .{err});
        };
        std.debug.print("Loading default file: {s}\n", .{self.path.?});

        return self.path.?;
    }
};
