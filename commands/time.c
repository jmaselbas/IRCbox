// SPDX-License-Identifier: GPL-2.0-only

#include <common.h>
#include <command.h>
#include <clock.h>
#include <linux/math64.h>
#include <malloc.h>

static int do_time(int argc, char *argv[])
{
	int i;
	unsigned char *buf;
	u64 start, end, diff64;
	bool nanoseconds = false;
	int len = 1; /* '\0' */

	if (argc < 2)
		return COMMAND_ERROR_USAGE;

	for (i = 1; i < argc; i++)
		len += strlen(argv[i]) + 1;

	buf = xzalloc(len);

	i = 1;
	if (!strcmp(argv[i], "-n")) {
		nanoseconds = true;
		i++;
	}

	for (; i < argc; i++) {
		strcat(buf, argv[i]);
		strcat(buf, " ");
	}

	start = get_time_ns();

	run_command(buf);

	end = get_time_ns();

	diff64 = end - start;

	if (!nanoseconds)
		do_div(diff64, 1000000);

	printf("time: %llu%cs\n", diff64, nanoseconds ? 'n' : 'm');

	free(buf);

	return 0;
}

BAREBOX_CMD_HELP_START(time)
BAREBOX_CMD_HELP_TEXT("Note: This command depends on COMMAND being interruptible,")
BAREBOX_CMD_HELP_TEXT("otherwise the timer may overrun resulting in incorrect results")
BAREBOX_CMD_HELP_TEXT("Options:")
BAREBOX_CMD_HELP_OPT ("-n",     "output elapsed time in nanoseconds")
BAREBOX_CMD_HELP_END

BAREBOX_CMD_START(time)
	.cmd		= do_time,
	BAREBOX_CMD_DESC("measure execution duration of a command")
	BAREBOX_CMD_OPTS("[-n] COMMAND")
	BAREBOX_CMD_GROUP(CMD_GRP_MISC)
	BAREBOX_CMD_HELP(cmd_time_help)
BAREBOX_CMD_END
