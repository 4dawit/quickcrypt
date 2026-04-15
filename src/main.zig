pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const input_args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, input_args);

    const action_type: ActionType = if (std.mem.eql(u8, input_args[1], "view"))
        ActionType.view
    else if (std.mem.eql(u8, input_args[1], "create"))
        ActionType.create
    else {
        try display.help("Invalid subcommand");
        return;
    };

    const crypt_type = args.parse(input_args) catch |err| {
        switch (err) {
            error.MissingInput => try display.help("Missing value argument"),
            error.MissingComparison => try display.help("Missing --compare argument"),
            error.MissingKey => try display.help("Missing --key argument"),
            error.InvalidType => try display.help("Invalid crypt type"),
            error.InvalidArgAmount => try display.help("Invalid amount of arguments provided"),
        }

        return;
    };

    switch (action_type) {
        ActionType.view => try decrypt(crypt_type),
        ActionType.create => try encrypt(crypt_type),
    }
}

const std = @import("std");

const args = @import("args.zig");
const display = @import("display.zig");
const decrypt = @import("decrypt.zig").decrypt;
const encrypt = @import("encrypt.zig").encrypt;
const ActionType = @import("types.zig").ActionType;
