pub fn encrypt(input: []const u8, crypt_type: CryptType) !void {
    switch (crypt_type) {
        CryptType.JWT => {
            
            display("", Status.success);
        },
        CryptType.UUID => {
            
            display("", Status.success);
        },
        CryptType.Argon2 => {
            
            display("", Status.success);
        },
        CryptType.SHA256 => {
            
            display("", Status.success);
        },
        CryptType.SHA512 => {
            
            display("", Status.success);
        },
        CryptType.Base64 => {
            
            display("", Status.success);
        },
        CryptType.PEM => {
            
            display("", Status.success);
        },
        CryptType.RSA => {
            
            display("", Status.success);
        },
        CryptType.AES => {
            
            display("", Status.success);
        },
        _ => {
            display("Invalid crypt type subcommand", Status.failure);
        },
    }
}

const std = @import("std");

const CryptType = @import("utils.zig").CryptType;
const Status = @import("utils.zig").Status;
const display = @import("display.zig").display;
