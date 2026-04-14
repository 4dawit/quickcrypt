pub const Status = enum { success, value_error, cli_error };

pub const CryptType = union(enum) {
    JWT: []const u8,
    UUID: void,
    Argon2Encode: []const u8,
    Argon2Verify: struct { hash: []const u8, plaintext: []const u8 },
    BcryptEncode: []const u8,
    BcryptVerify: struct { hash: []const u8, plaintext: []const u8 },
    Base64: []const u8,
    SHA1: []const u8,
    SHA2_256: []const u8,
    SHA2_512: []const u8,
    SHA3_256: []const u8,
    Blake2b512: []const u8,
    Blake3: []const u8,
    MD5: []const u8,
    PEM: []const u8,
    RSA: struct { data: []const u8, key: []const u8 },
    AES: struct { data: []const u8, key: []const u8 },
};
