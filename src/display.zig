const bold = "\x1b[1m";
const red = "\x1b[38;2;255;85;85m";
const orange = "\x1b[38;2;255;165;0m";
const reset = "\x1b[0m";

pub fn display(additional_message: ?[]const u8, output: []const u8, status: Status) !void {
    var stdout_buf: [1024]u8 = undefined;
    var stdout_writer = std.fs.File.stdout().writer(&stdout_buf);
    const stdout = &stdout_writer.interface;

    switch (status) {
        .success => {
            // exit 0, std.debug.print exits 1
            try stdout.print("\n{s}\n", .{output});
        },
        .value_error => {
            print(bold ++ orange ++ "Invalid input: {s}" ++ reset ++ "\n> {s}\n", .{
                additional_message orelse "",
                output,
            });
        },
        .cli_error => {
            print(bold ++ red ++ "Incorrect usage: {s}" ++ reset ++ "\n{s}\n", .{
                additional_message orelse "",
                output,
            });
        },
    }

    try stdout.flush();
}

pub fn help(additional_message: ?[]const u8) !void {
    const help_text =
        \\
        \\            (_)     | |                            _   
        \\  ____ _   _ _  ____| |  _ ____  ____ _   _ ____ _| |_ 
        \\ / _  | | | | |/ ___) |_/ ) ___)/ ___) | | |  _ (_   _)
        \\| |_| | |_| | ( (___|  _ ( (___| |   | |_| | |_| || |_ 
        \\ \__  |____/|_|\____)_| \_)____)_|    \__  |  __/  \__)
        \\    |_|                              (____/|_|         
        \\
        \\Simple CLI tool to quickly sanity check d/encrypted values
        \\
        \\Usage: quickcrypt <view|create> <type> [value] [options]
        \\
        \\  For most types, pass the value directly:
        \\    quickcrypt view jwt <token>
        \\    quickcrypt create sha2-256 <value>
        \\
        \\  For types requiring multiple inputs, use flags:
        \\    quickcrypt view argon2 --hash <hash> --compare <plaintext>
        \\    quickcrypt view aes <ciphertext> --key <key>
        \\
        \\Subcommands:
        \\  view    Decode/verify a value
        \\  create  Encode/encrypt a value (or random like UUID)
        \\
        \\Types:
        \\  jwt          JSON Web Token encode/decode
        \\  uuid         Universally Unique Identifier (no input, random generator)
        \\  argon2       Argon2 password hash (view requires --hash and --compare)
        \\  bcrypt       Bcrypt password hash (view requires --hash and --compare)
        \\  base64       Base64 encode/decode
        \\  sha1         SHA-1 (legacy, not secure)
        \\  sha2-256     SHA-2 256-bit
        \\  sha2-512     SHA-2 512-bit
        \\  sha3-256     SHA-3 256-bit
        \\  blake2b-512  BLAKE2b 512-bit
        \\  blake3       BLAKE3
        \\  md5          MD5 (legacy, not secure)
        \\  pem          PEM format parsing
        \\  rsa          RSA (not available in zig stdlib yet)
        \\  aes          AES-256-GCM encrypt/decrypt (requires --key)
    ;

    try display(additional_message, help_text, Status.cli_error);
}

const std = @import("std");
const print = std.debug.print;

const Status = @import("types.zig").Status;
