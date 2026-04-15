pub fn parse(input_args: [][:0]u8) !CryptType {
    if ((input_args.len < 3) or (input_args.len > 7)) {
        return error.InvalidArgAmount;
    }

    const crypt_type_str = input_args[2];
    const positional_val: ?[]const u8 =
        if (input_args.len > 3 and !std.mem.startsWith(u8, input_args[3], "--"))
            input_args[3]
        else
            null;

    if (std.ascii.eqlIgnoreCase(crypt_type_str, "jwt")) {
        return .{ .JWT = positional_val orelse return error.MissingInput };
    }
    if (std.ascii.eqlIgnoreCase(crypt_type_str, "uuid")) {
        return .{ .UUID = {} };
    }
    if (std.ascii.eqlIgnoreCase(crypt_type_str, "argon2")) {
        if (get_flag(input_args, "--hash")) |hash| {
            return .{ .Argon2Verify = .{
                .hash = hash,
                .plaintext = get_flag(input_args, "--compare") orelse return error.MissingComparison,
            } };
        }
        return .{ .Argon2Encode = positional_val orelse return error.MissingInput };
    }
    if (std.ascii.eqlIgnoreCase(crypt_type_str, "bcrypt")) {
        if (get_flag(input_args, "--hash")) |hash| {
            return .{ .BcryptVerify = .{
                .hash = hash,
                .plaintext = get_flag(input_args, "--compare") orelse return error.MissingComparison,
            } };
        }
        return .{ .BcryptEncode = positional_val orelse return error.MissingInput };
    }
    if (std.ascii.eqlIgnoreCase(crypt_type_str, "base64")) {
        return .{ .Base64 = positional_val orelse return error.MissingInput };
    }
    if (std.ascii.eqlIgnoreCase(crypt_type_str, "sha1")) {
        return .{ .SHA1 = positional_val orelse return error.MissingInput };
    }
    if (std.ascii.eqlIgnoreCase(crypt_type_str, "sha2-256")) {
        return .{ .SHA2_256 = positional_val orelse return error.MissingInput };
    }
    if (std.ascii.eqlIgnoreCase(crypt_type_str, "sha2-512")) {
        return .{ .SHA2_512 = positional_val orelse return error.MissingInput };
    }
    if (std.ascii.eqlIgnoreCase(crypt_type_str, "sha3-256")) {
        return .{ .SHA3_256 = positional_val orelse return error.MissingInput };
    }
    if (std.ascii.eqlIgnoreCase(crypt_type_str, "blake2b-512")) {
        return .{ .Blake2b512 = positional_val orelse return error.MissingInput };
    }
    if (std.ascii.eqlIgnoreCase(crypt_type_str, "blake3")) {
        return .{ .Blake3 = positional_val orelse return error.MissingInput };
    }
    if (std.ascii.eqlIgnoreCase(crypt_type_str, "md5")) {
        return .{ .MD5 = positional_val orelse return error.MissingInput };
    }
    if (std.ascii.eqlIgnoreCase(crypt_type_str, "pem")) {
        return .{ .PEM = positional_val orelse return error.MissingInput };
    }
    if (std.ascii.eqlIgnoreCase(crypt_type_str, "rsa")) {
        return .{ .RSA = .{
            .data = positional_val orelse return error.MissingInput,
            .key = get_flag(input_args, "--key") orelse return error.MissingKey,
        } };
    }
    if (std.ascii.eqlIgnoreCase(crypt_type_str, "aes")) {
        return .{ .AES = .{
            .data = positional_val orelse return error.MissingInput,
            .key = get_flag(input_args, "--key") orelse return error.MissingKey,
        } };
    }

    return error.InvalidType;
}

fn get_flag(a: [][:0]u8, name: []const u8) ?[]const u8 {
    var i: usize = 3; // minimum args length

    while (i + 1 < a.len) : (i += 1) {
        if (std.mem.eql(u8, a[i], name)) return a[i + 1];
    }

    return null;
}

const std = @import("std");

const CryptType = @import("types.zig").CryptType;
