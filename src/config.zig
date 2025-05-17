const std = @import("std");

const ConfigError = error{
    EmptyUpstreams,
    NoUpstreamAvailable,
};

const Distribution = enum { round_robin };
const Upstream = struct {
    ip: []u8,
    port: u16 = 53,
};
const Configuration = struct {
    upstream: []Upstream,
    distribution: Distribution = .round_robin,
    last_index: usize = 0,

    pub fn next_upstream(self: *Configuration) !Upstream {
        if (self.upstream.len == 0) return ConfigError.NoUpstreamAvailable;

        switch (self.distribution) {
            .round_robin => {
                const upstream = self.upstream[self.last_index];
                self.last_index = (self.last_index + 1) % self.upstream.len;
                return upstream;
            },
        }
    }
};

const JSONConfig = struct { allocator: std.mem.Allocator, path: []const u8 };
const JSONConfiguration = struct {
    json: std.json.Parsed(Configuration),
    configuration: Configuration,

    pub fn init(config: JSONConfig) !JSONConfiguration {
        const file = try std.fs.cwd().openFile(config.path, .{});
        defer file.close();

        var json_data: [1024]u8 = undefined;
        const read = try file.readAll(&json_data);
        const json = try std.json.parseFromSlice(Configuration, config.allocator, json_data[0..read], .{});

        if (json.value.upstream.len < 0) return ConfigError.EmptyUpstreams;

        return .{
            .json = json,
            .configuration = json.value,
        };
    }
    pub fn deinit(self: *JSONConfiguration) void {
        self.json.deinit();
    }
    pub fn next_upstream(self: *JSONConfiguration) !Upstream {
        return self.configuration.next_upstream();
    }
};

test "Should initialize json config" {
    const allocator = std.testing.allocator;
    var config = try JSONConfiguration.init(.{ .allocator = allocator, .path = "./config.json" });
    defer config.deinit();

    try std.testing.expectEqual(Distribution.round_robin, config.configuration.distribution);

    try std.testing.expectEqual(2, config.configuration.upstream.len);
    try std.testing.expectEqualSlices(u8, "1.1.1.1", config.configuration.upstream[0].ip);
    try std.testing.expectEqual(53, config.configuration.upstream[0].port);

    try std.testing.expectEqualSlices(u8, "1.0.0.1", config.configuration.upstream[1].ip);
    try std.testing.expectEqual(53, config.configuration.upstream[1].port);
}

test "Should get next upstream from json config" {
    const allocator = std.testing.allocator;
    var config = try JSONConfiguration.init(.{ .allocator = allocator, .path = "./config.json" });
    defer config.deinit();

    try std.testing.expectEqual(Distribution.round_robin, config.configuration.distribution);

    const upstream1 = try config.next_upstream();
    try std.testing.expectEqualSlices(u8, "1.1.1.1", upstream1.ip);
    try std.testing.expectEqual(53, upstream1.port);

    const upstream2 = try config.next_upstream();
    try std.testing.expectEqualSlices(u8, "1.0.0.1", upstream2.ip);
    try std.testing.expectEqual(53, upstream2.port);

    const upstream3 = try config.next_upstream();
    try std.testing.expectEqualSlices(u8, "1.1.1.1", upstream3.ip);
    try std.testing.expectEqual(53, upstream3.port);
}
