pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const input_args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, input_args);

    const crypt_type = args.parse(input_args) catch |err| {
        switch (err) {
            error.MissingInput => try args.help("Missing value argument"),
            error.MissingComparison => try args.help("Missing --compare argument"),
            error.MissingKey => try args.help("Missing --key argument"),
            error.UnknownType => try args.help("Unknown crypt type"),
            error.InvalidArgAmount => try args.help("Invalid amount of arguments provided"),
        }

        return;
    };

    if (std.mem.eql(u8, input_args[1], "view")) {
        try decrypt(crypt_type);
    } else if (std.mem.eql(u8, input_args[1], "create")) {
        try encrypt(crypt_type);
    } else {
        try args.help("Unknown subcommand");
    }
}

const std = @import("std");

const decrypt = @import("decrypt.zig").decrypt;
const encrypt = @import("encrypt.zig").encrypt;
const display = @import("display.zig").display;
const args = @import("args.zig");
const types = @import("types.zig");
