// SPDX-License-Identifier: GPL-2.0-only
// SPDX-FileCopyrightText: (c) 2022 Jules Maselbas <jmaselbas@kalray.eu>

#include <common.h>
#include <command.h>
#include <complete.h>
#include <environment.h>
#include <getopt.h>
#include <net.h>

static void tcp_dump(struct eth_device *edev, void *pkt, int len)
{
	struct iphdr *ip = net_eth_to_iphdr(pkt);
	struct tcphdr *tcp = net_eth_to_tcphdr(pkt);
	uint16_t flag = ntohs(tcp->doff_flag) & TCP_FLAG_MASK;
	int opt = net_tcp_data_offset(tcp) - sizeof(struct tcphdr);
	char cksum[sizeof("0xffff")];
	char flags[sizeof("FSRPAU")] = {};
	char *f = flags;

	if (flag & TCP_FLAG_FIN) *f++ = 'F';
	if (flag & TCP_FLAG_SYN) *f++ = 'S';
	if (flag & TCP_FLAG_RST) *f++ = 'R';
	if (flag & TCP_FLAG_PSH) *f++ = 'P';
	if (flag & TCP_FLAG_ACK) *f++ = 'A';
	if (flag & TCP_FLAG_URG) *f++ = 'U';

	snprintf(cksum, sizeof(cksum), "%#.4x", tcp_checksum(ip, tcp, len));
	pr_debug("%pI4:%u > %pI4:%u [%s] cksum %#.4x (%s) seq %u ack %u win %u opt [%d] len %d\n",
		&ip->saddr, ntohs(tcp->src), &ip->daddr, ntohs(tcp->dst),
		flags, ntohs(tcp->sum),
		tcp_checksum_ok(ip, tcp, len) ? "correct" : cksum,
		ntohl(tcp->seq), ntohl(tcp->ack), ntohs(tcp->wnd),
		opt, len);
}

static int do_tcpdump(int argc, char *argv[])
{
	struct eth_device *edev;
	const char *edevname;
	bool remove = false;
	int opt;

	while ((opt = getopt(argc, argv, "r")) > 0) {
		switch (opt) {
		case 'r':
			remove = true;
			break;
		default:
			return COMMAND_ERROR_USAGE;
		}
	}

	if (optind == argc)
		edevname = "eth0";
	else
		edevname = argv[optind];

	edev = eth_get_byname(edevname);
	if (!edev) {
		printf("No such network device: %s\n", edevname);
		return 1;
	}

	if (remove)
		edev->tcp_dump = NULL;
	else
		edev->tcp_dump = tcp_dump;

	return 0;
}

BAREBOX_CMD_HELP_START(tcpdump)
BAREBOX_CMD_HELP_TEXT("Options:")
BAREBOX_CMD_HELP_OPT("-r", "remove log handler from Ethernet interface")
BAREBOX_CMD_HELP_END

BAREBOX_CMD_START(tcpdump)
	.cmd		= do_tcpdump,
	BAREBOX_CMD_DESC("tcpdump - tool to get dump of TCP packets")
	BAREBOX_CMD_OPTS("[-r] [device]")
	BAREBOX_CMD_GROUP(CMD_GRP_NET)
	BAREBOX_CMD_COMPLETE(eth_complete)
BAREBOX_CMD_END
