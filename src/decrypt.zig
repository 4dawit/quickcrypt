pub fn decrypt(crypt_type: CryptType) !void {
    switch (crypt_type) {
        .JWT => |token| {
            var iter = std.mem.splitScalar(u8, token, '.');
            _ = iter.next();
            const payload_b64 = iter.next() orelse {
                const dot_count = std.mem.count(u8, token, ".");
                var msg_buf: [256]u8 = undefined;
                const msg = std.fmt.bufPrint(&msg_buf, "JWT must have 3 parts separated by '.', got {d} part(s). Format: header.payload.signature", .{dot_count + 1}) catch "JWT must have 3 parts separated by '.' (header.payload.signature)";
                try display("Invalid JWT format", msg, .value_error);
                return;
            };
            const decoder = std.base64.url_safe_no_pad.Decoder;
            const decoded_len = decoder.calcSizeForSlice(payload_b64) catch {
                try display("Invalid JWT payload encoding", "Payload section is not valid base64url — it may be corrupted or not a real JWT", .value_error);
                return;
            };
            var buf: [4096]u8 = undefined;
            if (decoded_len > buf.len) {
                var msg_buf: [256]u8 = undefined;
                const msg = std.fmt.bufPrint(&msg_buf, "Decoded payload is {d} bytes, limit is 4096 bytes. JWTs are not designed to carry large payloads — consider moving large data to a database and referencing it by ID in the token", .{decoded_len}) catch "Payload exceeds 4096 byte limit. JWTs should contain only small claims, not large data blobs";
                try display("JWT payload too large", msg, .value_error);
                return;
            }
            try decoder.decode(buf[0..decoded_len], payload_b64);
            try display(null, buf[0..decoded_len], .success);
        },

        .UUID => {
            try display("UUID cannot be decoded", "UUIDs are random identifiers with no encoded data inside them. Use 'create uuid' to generate a new one", .cli_error);
        },

        .Argon2Verify => |h| {
            std.crypto.pwhash.argon2.strVerify(h.hash, h.plaintext, .{
                .allocator = std.heap.smp_allocator,
            }) catch {
                try display("Argon2 verification failed", "The plaintext does not match the hash. Either the password is wrong or the hash is from a different input", .value_error);
                return;
            };
            try display(null, "Hash verified successfully", .success);
        },

        .Argon2Encode => {
            try display("Wrong subcommand for Argon2 encoding", "Argon2 produces a one-way hash — use 'create argon2 <plaintext>' to hash a value, then 'view argon2 --hash <hash> --compare <plaintext>' to verify it", .cli_error);
        },

        .BcryptVerify => |h| {
            std.crypto.pwhash.bcrypt.strVerify(h.hash, h.plaintext, .{
                .allocator = null,
                .silently_truncate_password = false,
            }) catch {
                try display("Bcrypt verification failed", "The plaintext does not match the hash. Either the password is wrong or the hash is from a different input", .value_error);
                return;
            };
            try display(null, "Hash verified successfully", .success);
        },

        .BcryptEncode => {
            try display("Wrong subcommand for Bcrypt encoding", "Bcrypt produces a one-way hash — use 'create bcrypt <plaintext>' to hash a value, then 'view bcrypt --hash <hash> --compare <plaintext>' to verify it", .cli_error);
        },

        .Base64 => |value| {
            const decoder = std.base64.standard.Decoder;
            const decoded_len = decoder.calcSizeForSlice(value) catch {
                var msg_buf: [512]u8 = undefined;
                const msg = std.fmt.bufPrint(&msg_buf, "'{s}' is not valid base64 — valid base64 uses A-Z, a-z, 0-9, +, / and = for padding", .{value[0..@min(value.len, 40)]}) catch "Input contains characters outside the base64 alphabet (A-Z, a-z, 0-9, +, /, =)";
                try display("Invalid base64 input", msg, .value_error);
                return;
            };
            var buf: [4096]u8 = undefined;
            if (decoded_len > buf.len) {
                var msg_buf: [128]u8 = undefined;
                const msg = std.fmt.bufPrint(&msg_buf, "Decoded size would be {d} bytes, limit is 4096", .{decoded_len}) catch "Input too large to decode";
                try display("Base64 input too large", msg, .value_error);
                return;
            }
            decoder.decode(buf[0..decoded_len], value) catch {
                try display("Base64 decode failed", "Input length or padding is incorrect — base64 strings must have a length that is a multiple of 4 (with = padding)", .value_error);
                return;
            };
            try display(null, buf[0..decoded_len], .success);
        },

        .SHA1 => |value| {
            try simpleHexToBytes(std.crypto.hash.Sha1, value);
        },

        .SHA2_256 => |value| {
            try simpleHexToBytes(std.crypto.hash.sha2.Sha256, value);
        },

        .SHA2_512 => |value| {
            try simpleHexToBytes(std.crypto.hash.sha2.Sha512, value);
        },

        .SHA3_256 => |value| {
            try simpleHexToBytes(std.crypto.hash.sha3.Sha3_256, value);
        },

        .Blake2b512 => |value| {
            try simpleHexToBytes(std.crypto.hash.blake2.Blake2b512, value);
        },

        .Blake3 => |value| {
            try simpleHexToBytes(std.crypto.hash.Blake3, value);
        },

        .MD5 => |value| {
            try simpleHexToBytes(std.crypto.hash.Md5, value);
        },

        .PEM => |value| {
            var lines = std.mem.splitScalar(u8, value, '\n');
            var b64_buf: [8192]u8 = undefined;
            var b64_len: usize = 0;
            while (lines.next()) |line| {
                const trimmed = std.mem.trim(u8, line, " \r");
                if (std.mem.startsWith(u8, trimmed, "-----")) continue;
                if (b64_len + trimmed.len > b64_buf.len) {
                    try display("PEM content too large", "Extracted base64 content exceeds 8192 bytes — this tool is intended for inspecting PEM files, not processing large certificates", .value_error);
                    return;
                }
                @memcpy(b64_buf[b64_len..][0..trimmed.len], trimmed);
                b64_len += trimmed.len;
            }
            try display(null, b64_buf[0..b64_len], .success);
        },

        .RSA => {
            try display("RSA is not supported", "RSA is not available in Zig's stdlib. For RSA operations consider using openssl: 'openssl rsautl -decrypt -inkey key.pem'", .cli_error);
        },

        .AES => |aes| {
            const Aes256Gcm = std.crypto.aead.aes_gcm.Aes256Gcm;
            if (aes.key.len != Aes256Gcm.key_length) {
                var msg_buf: [128]u8 = undefined;
                const msg = std.fmt.bufPrint(&msg_buf, "Key is {d} bytes, AES-256-GCM requires exactly {d} bytes", .{ aes.key.len, Aes256Gcm.key_length }) catch "Key must be exactly 32 bytes for AES-256-GCM";
                try display("Invalid AES key length", msg, .value_error);
                return;
            }
            var key: [Aes256Gcm.key_length]u8 = undefined;
            @memcpy(&key, aes.key);
            const nonce_hex_len = Aes256Gcm.nonce_length * 2;
            const tag_hex_len = Aes256Gcm.tag_length * 2;
            const min_len = nonce_hex_len + tag_hex_len;
            if (aes.data.len < min_len) {
                var msg_buf: [256]u8 = undefined;
                const msg = std.fmt.bufPrint(&msg_buf, "Input is {d} hex chars, minimum is {d} (nonce={d} + tag={d}). Use the output from 'create aes' which includes the nonce and auth tag prepended to the ciphertext", .{ aes.data.len, min_len, nonce_hex_len, tag_hex_len }) catch "Input too short — must be hex output from 'create aes' (nonce + tag + ciphertext)";
                try display("Invalid AES ciphertext", msg, .value_error);
                return;
            }
            var nonce: [Aes256Gcm.nonce_length]u8 = undefined;
            var tag: [Aes256Gcm.tag_length]u8 = undefined;
            _ = std.fmt.hexToBytes(&nonce, aes.data[0..nonce_hex_len]) catch {
                try display("Invalid AES ciphertext", "Nonce portion (first 24 hex chars) contains non-hex characters", .value_error);
                return;
            };
            _ = std.fmt.hexToBytes(&tag, aes.data[nonce_hex_len .. nonce_hex_len + tag_hex_len]) catch {
                try display("Invalid AES ciphertext", "Auth tag portion contains non-hex characters", .value_error);
                return;
            };
            const ct_hex = aes.data[nonce_hex_len + tag_hex_len ..];
            const plaintext = try std.heap.smp_allocator.alloc(u8, ct_hex.len / 2);
            defer std.heap.smp_allocator.free(plaintext);
            const ciphertext = try std.heap.smp_allocator.alloc(u8, ct_hex.len / 2);
            defer std.heap.smp_allocator.free(ciphertext);
            _ = std.fmt.hexToBytes(ciphertext, ct_hex) catch {
                try display("Invalid AES ciphertext", "Ciphertext portion contains non-hex characters", .value_error);
                return;
            };
            Aes256Gcm.decrypt(plaintext, ciphertext, tag, "", nonce, key) catch {
                try display("AES decryption failed", "Authentication tag mismatch — the key is wrong, the ciphertext was modified, or this was not encrypted with 'create aes'", .value_error);
                return;
            };
            try display(null, plaintext, .success);
        },
    }
}

fn simpleHexToBytes(hash_type: anytype, value: []const u8) !void {
    var hash: [hash_type.digest_length]u8 = undefined;
    const bytes = try std.fmt.hexToBytes(&hash, value);
    try display(null, bytes, .success);
}

const std = @import("std");

const CryptType = @import("types.zig").CryptType;
const Status = @import("types.zig").Status;
const display = @import("display.zig").display;
