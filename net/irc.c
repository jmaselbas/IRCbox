// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2021 Jules Maselbas <jmaselbas@kalray.eu>

/* irc.c - IRC client */

#include <common.h>
#include <command.h>
#include <net.h>
#include <errno.h>
#include <getopt.h>
#include <linux/err.h>
#include <linux/string.h>
#include <linux/ctype.h>
#include <readkey.h>
#include <sched.h>
#include <crc.h>
#include <globalvar.h>

static IPaddr_t	net_ip;

static struct net_connection *con;

static char chan[32];
static char nick[32];
static char input_line[128];

static int redraw;
LIST_HEAD(irc_log);
static int irc_log_nb_msgs;

struct msg_entry {
	struct list_head list;
	unsigned char type;
	unsigned char flag;
	char *msg;
	char *nick;
};

enum type {
	NONE = 0,
	INFO = 1,
	PART,
	QUIT,
	JOIN,
	PRIV,
	EMOT,
};
enum flag {
	SELF = 1,
	HIGH = 2,
};

const char *nickcolor[] = {
	"\033[1m",  /* self */
	"\033[0m",  /* normal */
	"\033[31m", /* red */
	"\033[32m", /* green */
	"\033[33m", /* yellow */
	"\033[34m", /* blue */
	"\033[35m", /* purple */
	"\033[36m", /* cyan */
	"\033[1;31m",
	"\033[1;32m",
	"\033[1;33m",
	"\033[1;34m",
	"\033[1;35m",
	"\033[1;36m",
};

const char *color[] = {
	[NONE] = "",
	[INFO] = "\033[1;34m", /* blue */
	[PART] = "\033[1;31m", /* red */
	[QUIT] = "\033[1;31m", /* red */
	[JOIN] = "\033[1;32m", /* green */
	[PRIV] = "",
	[EMOT] = "",
};

const char *prefix[] = {
	[NONE] = "",
	[INFO] = "-!-",
	[PART] = "<--",
	[QUIT] = "<--",
	[JOIN] = "-->",
	[PRIV] = "",
	[EMOT] = "",
};

static int irc_send(const char *msg, int len);
static int irc_pong(const char *txt);
static int irc_ctcp(const char *dst, const char *act, const char *msg);

static void irc_print_msg(struct msg_entry *msg)
{
	const char *inv = "";
	const char *col = "";
	const char *off = "";
	const char *pre = prefix[msg->type];
	uint32_t crc;

	if (console_allow_color()) {
		crc = crc32(0, msg->nick, strlen(msg->nick));
		if (msg->type == PRIV || msg->type == EMOT)
			col = msg->flag & SELF ? nickcolor[0] : nickcolor[(crc%14) + 1];
		else
			col = color[msg->type];
		off = "\033[0m";

		if (msg->flag & HIGH)
			inv = "\033[7m";
	}

	if (msg->type == PRIV)
		printf("<%s%s%s%s> %s\n", inv, col, msg->nick, off, msg->msg);
	else if (msg->type == EMOT)
		printf(" * %s%s%s%s %s\n", inv, col, msg->nick, off, msg->msg);
	else
		printf("%s%s%s %s\n", col, pre, off, msg->msg);
}

static void irc_add_line(enum type type, enum flag flag, char *name, char *line)
{
	struct msg_entry *msg;

	msg = malloc(sizeof(*msg));
	if (!msg)
		return;
	msg->msg = line;
	msg->type = type;
	msg->flag = flag;
	msg->nick = basprintf("%s", name ? name : "");

	if (!(flag & SELF)) {
		if (strstr(line, nick) != NULL)
			msg->flag |= HIGH;
	}

	list_add_tail(&msg->list, &irc_log);
	irc_log_nb_msgs++;
	printf("\r\x1b[K");
	irc_print_msg(msg);
	printf("\r[%s] %s\x1b[K", nick, input_line);
}

static void irc_draw(void)
{
	struct msg_entry *msg;

	clear();
	printf("\r\x1b[K");
	list_for_each_entry(msg, &irc_log, list) {
		irc_print_msg(msg);
	}
	printf("\r[%s] %s\x1b[K", nick, input_line);
}

static void irc_recv(char *msg)
{
	char *nick = NULL, *host = NULL;
	char *cmd = NULL, *chan = NULL, *arg = NULL;
	char *text = NULL;
	char **argp[] = { &cmd, &chan, &arg };
	int argc = 0;
	char *p = NULL, *l = NULL;
	char t = NONE;

	/* :<nick>!<user>@<host> */
	if (msg[0] == ':') {
		nick = ++msg;
		if (!(p = strchr(msg, ' ')))
			return;
		*p = '\0';
		msg = skip_spaces(p + 1);
		if ((p = strchr(nick, '!'))) {
			*p = '\0';
			host = ++p;
		}
	}

	if ((p = strchr(msg, ':'))) {
		*p = '\0';
		text = ++p;
		if ((p = strchr(text, '\r')))
			*p = '\0';
	}

	/* <cmd> [<chan> [<arg> ]]\0 */
	while (argc < (ARRAY_SIZE(argp) - 1) && (p = strchr(msg, ' '))) {
		*p = '\0';
		*argp[argc++] = msg;
		msg = ++p;
	}
	if (argc == (ARRAY_SIZE(argp) - 1))
		*argp[argc] = msg;

	if (!cmd || !strcmp("PONG", cmd)) {
		return;
	} else if (!strcmp("PING", cmd)) {
		irc_pong(text);
		return;
	} else if (!nick || !host) {
		t = INFO;
		l = basprintf("%s%s", arg ? arg : "", text ? text : "");
	} else if (!strcmp("ERROR", cmd)) {
		t = INFO;
		l = basprintf("error %s", text ? text : "unknown");
	} else if (!strcmp("JOIN", cmd) && (chan || text)) {
		if (text)
			chan = text;
		t = JOIN;
		l = basprintf("%s(%s) has joined %s", nick, host, chan);
	} else if (!strcmp("PART", cmd) && chan) {
		t = PART;
		l = basprintf("%s(%s) has left %s", nick, host, chan);
	} else if (!strcmp("QUIT", cmd)) {
		t = QUIT;
		l = basprintf("%s(%s) has quit (%s)", nick, host, text ? text : "");
	} else if (!strcmp("NICK", cmd) && text) {
		t = INFO;
		l = basprintf("%s changed nick to %s", nick, text);
	} else if (!strcmp("NOTICE", cmd)) {
		t = INFO;
		l = basprintf("%s: %s", nick, text ? text : "");
	} else if (!strcmp("PRIVMSG", cmd)) {
		if (!text)
			text = "";
		if (!strncmp("\001ACTION", text, strlen("\001ACTION"))) {
			text += strlen("\001ACTION");
			if (text[0] == ' ')
				text++;
			if ((p = strchr(text, '\001')))
				*p = '\0';
			t = EMOT;
			l = basprintf("%s", text);
		} else if (!strncmp("\001VERSION", text, strlen("\001VERSION"))) {
			irc_ctcp(nick, "VERSION", version_string);
		} else if (!strncmp("\001CLIENTINFO", text, strlen("\001CLIENTINFO"))) {
			irc_ctcp(nick, "CLIENTINFO", "ACTION VERSION");
		} else {
			t = PRIV;
			l = basprintf("%s", text);
		}
	} else {
		t = INFO;
		l = basprintf("%s", cmd);
	}

	irc_add_line(t, 0, nick, l);
}

static int rem;

static void tcp_handler(char *buf, int len)
{
	static char msg[512];
	char *end, *eol;

	if (!len)
		return;

	end = buf + len;

	/* messages ends with CR LF "\r\n" */
	while ((eol = memchr(buf, '\n', len))) {
		*eol = '\0';
		if (rem) {
			strlcpy(msg + rem, buf, sizeof(msg) - rem);
			irc_recv(msg);
			rem = 0;
		} else {
			irc_recv(buf);
		}
		if (eol == end)
			break;
		len -= (eol - buf) + 1;
		buf += (eol - buf) + 1;
	}
	if (buf < end)
		rem += strlcpy(msg + rem, buf, min(end - buf + 1, sizeof(msg) - rem));

	printf("\r[%s] %s", nick, input_line);
}

static void net_handler(void *ctx, char *pkt, unsigned len)
{
	struct iphdr *ip = net_eth_to_iphdr(pkt);

	if (net_read_ip((void *)&ip->saddr) != net_ip) {
		printf("bad ip !\n");
		return;
	}

	tcp_handler(net_eth_to_tcp_payload(pkt), net_eth_to_tcplen(pkt));
}

static int irc_send(const char *msg, int len)
{
	char *buf = net_tcp_get_payload(con);

	if (len > 0) {
		memcpy(buf, msg, len);
		return net_tcp_send(con, len);
	}

	return 0; /* nothing to do */
}

static int irc_priv_msg(char *dst, char *str)
{
	char *buf = net_tcp_get_payload(con);
	int len;

	len = snprintf(buf, 256, "PRIVMSG %s :%s\r\n", dst, str);
	if (len <= 0)
		return -1;
	irc_add_line(PRIV, SELF, nick, basprintf("%s", str));
	return net_tcp_send(con, len);
}

static int irc_pong(const char *txt)
{
	char *buf = net_tcp_get_payload(con);
	int len;

	len = snprintf(buf, 256, "PONG %s\r\n", txt);
	if (len <= 0)
		return -1;
	return net_tcp_send(con, len);
}

static int irc_ctcp(const char *dst, const char *act, const char *msg)
{
	char *buf = net_tcp_get_payload(con);
	int len;

	len = snprintf(buf, 256, "NOTICE %s :\001%s %s \001\r\n", dst, act, msg);
	if (len <= 0)
		return -1;
	return net_tcp_send(con, len);
}

static char msg[512];

static int irc_input(char *buf)
{
	int len;
	char *p;
	char *k;

	if (buf[0] == '\0')
		return 0;
	if (buf[0] != '/')
		return irc_priv_msg(chan, buf);

	len = 0;
	p = strchr(buf, ' ');
	p = (p != NULL) ? p + 1 : NULL;
	switch (buf[1]) {
	case 'j': /* join */
		if (!p)
			break;
		len = snprintf(msg, sizeof(msg), "JOIN %s\r\n", p);
		k = strchr(p, ' ');
		if (k)
			*k = '\0';
		strlcpy(chan, p, sizeof(chan));
		break;
	case 'p': /* part */
	case 'l': /* leave */
		if (!p)
			p = "leaving";
		len = snprintf(msg, sizeof(msg), "PART %s :%s\r\n", chan, p);;
		break;
	case 'n': /* nick */
		if (!p)
			break;
		len = snprintf(msg, sizeof(msg), "NICK %s\r\n", p);
		strlcpy(nick, p, sizeof(nick));
		break;
	case 'm': /* me */
		if (!p)
			break;
		len = snprintf(msg, sizeof(msg),
			       "PRIVMSG %s :\001ACTION %s\001\r\n", chan, p);
		irc_add_line(EMOT, SELF, nick, basprintf("%s", p));
		break;
	case 'w': /* wisper */
		if (!p)
			break;
		k = strchr(p, ' ');
		if (!k)
			break;
		*k = '\0';
		return irc_priv_msg(p, k + 1);
	case 'q': /* quit */
		if (!p)
			p = "quiting";
		len = snprintf(msg, sizeof(msg), "QUIT :%s\r\n", p);
		break;
	default:
		len = snprintf(msg, sizeof(msg), "%s\r\n", &buf[1]);
		break;
	}

	return irc_send(msg, len);
}

static int irc_login(char *host, char *real)
{
	int len;

	len = snprintf(msg, sizeof(msg),
		       "NICK %s\r\n"
		       "USER %s localhost %s :%s\r\n",  nick, nick, host, real);

	return irc_send(msg, len);
}

static int irc_readline(char *buf, int len)
{
	int n, c;

	memset(buf, 0, len);
	printf("\r[%s] \x1b[K", nick);

	for (n = 0; n < len; ) {
		while (!tstc()) {
			if (redraw) {
				redraw = 0;
				irc_draw();
			}
			net_poll();
			resched();
		}
		c = getchar();
		if (c < 0)
			return (-1);
		switch (c) {
		case BB_KEY_DEL7:
		case BB_KEY_DEL:
			if (n > 0) {
				buf[--n] = '\0';
				printf("\b \b");
			}
			break;
		default:
			if (isascii(c) && isprint(c)) {
				buf[n++] = c;
				printf("%c", c);
			}
			break;
		case BB_KEY_CLEAR_SCREEN:
			redraw = 1;
			break;
		case '\r':
		case '\n':
			buf[n] = '\0';
			return n;
		case CTL_CH('c'):
			buf[0] = '\0';
			return -1;
		}
	}
	return n;
}

static int do_irc(int argc, char *argv[])
{
	int ret;
	char *host, *p;
	const char *command = NULL;
	uint16_t port = 6667;
	int opt;

	while ((opt = getopt(argc, argv, "c:n:")) > 0) {
		switch (opt) {
		case 'c':
			command = optarg;
			break;
		case 'n':
			strlcpy(nick, optarg, sizeof(nick));
			break;
		}
	}
	argv += optind;
	argc -= optind;
	if (argc < 1)
		return COMMAND_ERROR_USAGE;
	host = argv[0];
	if ((p = strchr(host, '/'))) {
		*p = '\0';
		port = simple_strtoul(p + 1, NULL, 10);
	}
	if (argc > 1)
		port = simple_strtoul(argv[1], NULL, 10);

	ret = resolv(host, &net_ip);
	if (ret) {
		printf("Cannot resolve \"%s\": %s\n", host, strerror(-ret));
		return ret;
	}

	con = net_tcp_new(net_ip, port, net_handler, NULL);
	if (IS_ERR(con)) {
		printf("net tcp new fail\n");
		ret = PTR_ERR(con);
		goto out;
	}

	ret = net_tcp_open(con);
	if (ret) {
		printf("net_tcp_open: %d\n", ret);
		goto out;
	}

	redraw = 1;
	rem = 0;
	chan[0] = '\0';
	if (nick[0] == '\0')
		strlcpy(nick, "barebox", sizeof(nick));
	irc_login(host, "barebox");

	if (command)
		irc_input(command);

	while (con->state == TCP_ESTABLISHED) {
		int len;
		len = irc_readline(input_line, sizeof(input_line) - 1);
		if (len < 0)
			break;
		if (irc_input(input_line) < 0)
			break;
		if (ctrlc()) {
			ret = -EINTR;
			break;
		}
	}
	net_tcp_close(con);
	net_poll();

	ret = con->ret;
out:
	if (!IS_ERR(con))
		net_unregister(con);

	return ret;
}
BAREBOX_CMD_HELP_START(irc)
BAREBOX_CMD_HELP_TEXT("Options:")
BAREBOX_CMD_HELP_OPT ("-n NICK\t", "nick to use")
BAREBOX_CMD_HELP_OPT ("-c COMMAND\t", "command to run after login")
BAREBOX_CMD_HELP_END

BAREBOX_CMD_START(irc)
	.cmd		= do_irc,
	BAREBOX_CMD_DESC("IRC client")
	BAREBOX_CMD_OPTS("[-nc] DESTINATION[[/]PORT]")
	BAREBOX_CMD_GROUP(CMD_GRP_NET)
BAREBOX_CMD_END
