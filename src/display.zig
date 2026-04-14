const bold = "\x1b[1m";
const green = "\x1b[38;2;139;233;255m";
const red = "\x1b[38;2;255;85;85m";
const orange = "\x1b[38;2;255;165;0m";
const reset = "\x1b[0m";

pub fn banner() void {
    print(
        \\            (_)     | |                            _   
        \\  ____ _   _ _  ____| |  _ ____  ____ _   _ ____ _| |_ 
        \\ / _  | | | | |/ ___) |_/ ) ___)/ ___) | | |  _ (_   _)
        \\| |_| | |_| | ( (___|  _ ( (___| |   | |_| | |_| || |_ 
        \\ \__  |____/|_|\____)_| \_)____)_|    \__  |  __/  \__)
        \\    |_|                              (____/|_|         
        \\
    , .{});
}

pub fn display(additional_message: ?[]const u8, output: []const u8, status: Status) !void {
    var stdout_buf: [1024]u8 = undefined;
    var stdout_writer = std.fs.File.stdout().writer(&stdout_buf);
    const stdout = &stdout_writer.interface;

    switch (status) {
        .success => {
            try stdout.print(bold ++ green ++ "Success" ++ reset ++ "\n{s}\n", .{output});
        },
        .value_error => {
            print(bold ++ orange ++ "Invalid input: {s}" ++ reset ++ "\n{s}\n", .{
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

const std = @import("std");
const print = std.debug.print;

const Status = @import("types.zig").Status;
