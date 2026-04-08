pub const Status = enum { success, failure };
pub const CryptType = enum { JWT, UUID, Argon2, SHA256, SHA512, Base64, PEM, RSA, AES };

pub fn contains(haystack: []const u8, needle: []const u8) bool {
    return std.mem.indexOf(u8, haystack, needle) != null;
}

const std = @import("std");
