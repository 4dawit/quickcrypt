pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();
    defer _ = gpa.deinit();

    var app = yazap.App.init(allocator, "quickcrypt", "Simple CLI tool to quickly sanity check d/encrypted values");
    defer app.deinit();

    var quickcrypt = app.rootCommand();
    try quickcrypt.addSubcommand(app.createCommand("view", "View decrypted value from input"));
    try quickcrypt.addSubcommand(app.createCommand("create", "Create ecrypted value from input (or random like UUID)"));

    const input = try app.parseProcess();
    if (input.subcommandMatches("help")) |_| {
        try app.displayHelp();
    } else if (input.containsArg("help")) {
        try app.displayHelp();
    } else if (input.containsArg("h")) {
        try app.displayHelp();
    }

    if (input.subcommandMatches("view")) |view_args| {
        try utils.parseArgs(view_args) |input, crypt_type| {
            decrypt.decrypt(input, crypt_type);
        }
    } else if (input.subcommandMatches("create")) |create_args| {
        try utils.parseArgs(create_args) |input, crypt_type| {
            encrypt.encrypt(input, crypt_type);
        }
    } else {
        display.display("Subcommand does not exist", utils.Status.failure);
        try app.displayHelp();
    }
}

const std = @import("std");
const yazap = @import("yazap");

const display = @import("display.zig");
const utils = @import("utils.zig");
const encrypt = @import("encrypt.zig");
const decrypt = @import("decrypt.zig");
