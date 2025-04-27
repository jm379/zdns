const std = @import("std");
const net = std.net;
const posix = std.posix;

pub const UDPConfig = struct { address: []const u8, port: u16 };
pub const UDPServer = struct {
    sockfd: posix.socket_t,
    client_addr: posix.sockaddr = undefined,
    client_addr_len: posix.socklen_t = @sizeOf(posix.sockaddr),
    pub fn init() !UDPServer {
        const sockfd = try posix.socket(posix.AF.INET, posix.SOCK.DGRAM, posix.IPPROTO.UDP);

        try posix.setsockopt(sockfd, posix.SOL.SOCKET, posix.SO.REUSEADDR, &std.mem.toBytes(@as(usize, 1)));
        return .{ .sockfd = sockfd };
    }
    pub fn bind(self: *UDPServer, config: UDPConfig) !net.Address {
        const addr = try net.Address.parseIp(config.address, config.port);
        try posix.bind(self.sockfd, &addr.any, addr.getOsSockLen());

        return addr;
    }
    pub fn start(self: *UDPServer) !void {
        var buff: [512]u8 = undefined;
        _ = try self.read(&buff);
    }
    pub fn read(self: *UDPServer, buff: []u8) !usize {
        return try posix.recvfrom(self.sockfd, buff, 0, &self.client_addr, &self.client_addr_len);
    }
    pub fn write(self: *UDPServer, buff: []const u8) !usize {
        return try posix.sendto(self.sockfd, buff, 0, &self.client_addr, self.client_addr_len);
    }
    pub fn close(self: *UDPServer) void {
        posix.close(self.sockfd);
    }
};

pub const UDPClient = struct {
    sockfd: posix.socket_t,
    addr: net.Address,
    pub fn init(config: UDPConfig) !UDPClient {
        const sockfd = try posix.socket(posix.AF.INET, posix.SOCK.DGRAM, posix.IPPROTO.UDP);
        const addr = try net.Address.parseIp(config.address, config.port);
        return .{ .sockfd = sockfd, .addr = addr };
    }
    pub fn connect(self: *UDPClient) !void {
        try posix.connect(self.sockfd, &self.addr.any, self.addr.getOsSockLen());
    }
    pub fn read(self: *UDPClient, buff: []u8) !usize {
        return try posix.recv(self.sockfd, buff, 0);
    }
    pub fn write(self: *UDPClient, buff: []const u8) !usize {
        return try posix.send(self.sockfd, buff, 0);
    }
    pub fn close(self: *UDPClient) void {
        posix.close(self.sockfd);
    }
};
