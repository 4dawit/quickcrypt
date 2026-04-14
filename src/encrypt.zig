pub fn encrypt(crypt_type: CryptType) !void {
    switch (crypt_type) {
        .JWT => |payload| {
            const encoder = std.base64.url_safe_no_pad.Encoder;
            var buf: [4096]u8 = undefined;
            if (encoder.calcSize(payload.len) > buf.len) {
                var msg_buf: [256]u8 = undefined;
                const msg = std.fmt.bufPrint(&msg_buf, "Payload is {d} bytes, limit is ~3072 bytes. JWTs are not designed for large payloads — store large data elsewhere and reference it by ID in the token", .{payload.len}) catch "Payload too large. JWTs should contain only small claims";
                try display("JWT payload too large", msg, .value_error);
                return;
            }
            const encoded = encoder.encode(&buf, payload);
            try display(null, encoded, .success);
        },

        .UUID => {
            var uuid: [16]u8 = undefined;
            std.crypto.random.bytes(&uuid);
            uuid[6] = (uuid[6] & 0x0f) | 0x40;
            uuid[8] = (uuid[8] & 0x3f) | 0x80;
            var buf: [36]u8 = undefined;
            _ = std.fmt.bufPrint(&buf, "{x:0>2}{x:0>2}{x:0>2}{x:0>2}-{x:0>2}{x:0>2}-{x:0>2}{x:0>2}-{x:0>2}{x:0>2}-{x:0>2}{x:0>2}{x:0>2}{x:0>2}{x:0>2}{x:0>2}", .{
                uuid[0],  uuid[1],  uuid[2],  uuid[3],
                uuid[4],  uuid[5],  uuid[6],  uuid[7],
                uuid[8],  uuid[9],  uuid[10], uuid[11],
                uuid[12], uuid[13], uuid[14], uuid[15],
            }) catch try display("Failed to generate UUID", "Zig version may be incomptaible (currently v0.15.2)", .cli_error);
            try display(null, &buf, .success);
        },

        .Base64 => |value| {
            const encoder = std.base64.standard.Encoder;
            const encoded_len = encoder.calcSize(value.len);
            var buf: [4096]u8 = undefined;
            if (encoded_len > buf.len) {
                var msg_buf: [128]u8 = undefined;
                const msg = std.fmt.bufPrint(&msg_buf, "Input is {d} bytes, encoded would be {d} bytes, limit is 4096", .{ value.len, encoded_len }) catch "Input too large to encode";
                try display("Base64 input too large", msg, .value_error);
                return;
            }
            const encoded = encoder.encode(&buf, value);
            try display(null, encoded, .success);
        },

        .Argon2Encode => |plaintext| {
            var buf: [128]u8 = undefined;
            const hash = try std.crypto.pwhash.argon2.strHash(plaintext, .{
                .allocator = std.heap.smp_allocator,
                .params = std.crypto.pwhash.argon2.Params.interactive_2id,
            }, &buf);
            try display(null, hash, .success);
        },

        .Argon2Verify => {
            try display("Wrong subcommand for Argon2 verification", "Use 'view argon2 --hash <hash> --compare <plaintext>' to verify a hash against a plaintext", .cli_error);
        },

        .BcryptEncode => |plaintext| {
            var buf: [60]u8 = undefined;
            const hash = try std.crypto.pwhash.bcrypt.strHash(plaintext, .{
                .allocator = null,
                .params = .{ .rounds_log = 12, .silently_truncate_password = false },
                .encoding = .crypt,
            }, &buf);
            try display(null, hash, .success);
        },

        .BcryptVerify => {
            try display("Wrong subcommand for Bcrypt verification", "Use 'view bcrypt --hash <hash> --compare <plaintext>' to verify a hash against a plaintext", .cli_error);
        },

        .SHA1 => |value| {
            var hash: [std.crypto.hash.Sha1.digest_length]u8 = undefined;
            std.crypto.hash.Sha1.hash(value, &hash, .{});
            const hex = std.fmt.bytesToHex(&hash, .lower);
            try display(null, &hex, .success);
        },

        .SHA2_256 => |value| {
            var hash: [std.crypto.hash.sha2.Sha256.digest_length]u8 = undefined;
            std.crypto.hash.sha2.Sha256.hash(value, &hash, .{});
            const hex = std.fmt.bytesToHex(&hash, .lower);
            try display(null, &hex, .success);
        },

        .SHA2_512 => |value| {
            var hash: [std.crypto.hash.sha2.Sha512.digest_length]u8 = undefined;
            std.crypto.hash.sha2.Sha512.hash(value, &hash, .{});
            const hex = std.fmt.bytesToHex(&hash, .lower);
            try display(null, &hex, .success);
        },

        .SHA3_256 => |value| {
            var hash: [std.crypto.hash.sha3.Sha3_256.digest_length]u8 = undefined;
            std.crypto.hash.sha3.Sha3_256.hash(value, &hash, .{});
            const hex = std.fmt.bytesToHex(&hash, .lower);
            try display(null, &hex, .success);
        },

        .Blake2b512 => |value| {
            var hash: [std.crypto.hash.blake2.Blake2b512.digest_length]u8 = undefined;
            std.crypto.hash.blake2.Blake2b512.hash(value, &hash, .{});
            const hex = std.fmt.bytesToHex(&hash, .lower);
            try display(null, &hex, .success);
        },

        .Blake3 => |value| {
            var hash: [std.crypto.hash.Blake3.digest_length]u8 = undefined;
            std.crypto.hash.Blake3.hash(value, &hash, .{});
            const hex = std.fmt.bytesToHex(&hash, .lower);
            try display(null, &hex, .success);
        },

        .MD5 => |value| {
            var hash: [std.crypto.hash.Md5.digest_length]u8 = undefined;
            std.crypto.hash.Md5.hash(value, &hash, .{});
            const hex = std.fmt.bytesToHex(&hash, .lower);
            try display(null, &hex, .success);
        },

        .PEM => |value| {
            var buf: [8192]u8 = undefined;
            const encoded = std.fmt.bufPrint(&buf, "-----BEGIN DATA-----\n{s}\n-----END DATA-----\n", .{value}) catch {
                var msg_buf: [128]u8 = undefined;
                const msg = std.fmt.bufPrint(&msg_buf, "Input is {d} bytes, limit is ~8150 bytes", .{value.len}) catch "Input too large";
                try display("PEM input too large", msg, .value_error);
                return;
            };
            try display(null, encoded, .success);
        },

        .RSA => {
            try display("RSA is not supported", "RSA is not available in Zig's stdlib. For RSA operations consider using openssl: 'openssl rsautl -encrypt -pubin -inkey key.pem'", .cli_error);
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
            var nonce: [Aes256Gcm.nonce_length]u8 = undefined;
            std.crypto.random.bytes(&nonce);
            const ciphertext = try std.heap.smp_allocator.alloc(u8, aes.data.len);
            defer std.heap.smp_allocator.free(ciphertext);
            var tag: [Aes256Gcm.tag_length]u8 = undefined;
            Aes256Gcm.encrypt(ciphertext, &tag, aes.data, "", nonce, key);
            const total = nonce.len + tag.len + ciphertext.len;
            const out = try std.heap.smp_allocator.alloc(u8, total * 2);
            defer std.heap.smp_allocator.free(out);
            var fbs = std.io.fixedBufferStream(out);
            const writer = fbs.writer();
            const nonce_hex = std.fmt.bytesToHex(&nonce, .lower);
            try writer.writeAll(&nonce_hex);
            const tag_hex = std.fmt.bytesToHex(&tag, .lower);
            try writer.writeAll(&tag_hex);
            const hex_chars = "0123456789abcdef";
            for (ciphertext) |b| {
                const hi = hex_chars[(b >> 4) & 0xF];
                const lo = hex_chars[b & 0xF];
                try writer.writeByte(hi);
                try writer.writeByte(lo);
            }
            try display(null, out, .success);
        },
    }
}

const std = @import("std");

const CryptType = @import("types.zig").CryptType;
const Status = @import("types.zig").Status;
const display = @import("display.zig").display;
