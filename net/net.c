// SPDX-License-Identifier: GPL-2.0-only
// SPDX-FileCopyrightText: 2010 Sascha Hauer <s.hauer@pengutronix.de>, Pengutronix
// SPDX-FileCopyrightText: 1994-2000 Neil Russell
// SPDX-FileCopyrightText: 2000 Roland Borde
// SPDX-FileCopyrightText: 2000 Paolo Scaffardi
// SPDX-FileCopyrightText: 2000-2002 Wolfgang Denk <wd@denx.de>

/*
 * net.c - barebox networking support
 *
 * based on U-Boot (LiMon) code
 */

#define pr_fmt(fmt) "net: " fmt

#include <common.h>
#include <clock.h>
#include <command.h>
#include <environment.h>
#include <param.h>
#include <net.h>
#include <driver.h>
#include <errno.h>
#include <malloc.h>
#include <init.h>
#include <globalvar.h>
#include <magicvar.h>
#include <linux/ctype.h>
#include <linux/err.h>

unsigned char *NetRxPackets[PKTBUFSRX]; /* Receive packets		*/
static unsigned int net_ip_id;

char *net_server;
IPaddr_t net_gateway;
static IPaddr_t net_nameserver;
static char *net_domainname;

static LIST_HEAD(connection_list);

static struct net_connection *net_ip_get_con(int proto, uint16_t port)
{
	struct net_connection *con;

	list_for_each_entry(con, &connection_list, list) {
		if (con->proto != proto)
			continue;
		if (con->proto == IPPROTO_UDP && ntohs(con->udp->uh_sport) == port)
			return con;
		if (con->proto == IPPROTO_TCP && ntohs(con->tcp->src) == port)
			return con;
	}

	return NULL;
}

void net_set_nameserver(IPaddr_t nameserver)
{
	net_nameserver = nameserver;
}

IPaddr_t net_get_nameserver(void)
{
	return net_nameserver;
}

void net_set_domainname(const char *name)
{
	free(net_domainname);
	if (name)
		net_domainname = xstrdup(name);
	else
		net_domainname = xstrdup("");
};

const char *net_get_domainname(void)
{
	return net_domainname;
}

int net_checksum_ok(unsigned char *ptr, int len)
{
	return net_checksum(ptr, len) == 0xffff;
}

uint16_t net_checksum(unsigned char *ptr, int len)
{
	uint32_t xsum = 0;
	uint16_t *p = (uint16_t *)ptr;

	if (len & 1)
		ptr[len] = 0;

	len = (len + 1) >> 1;

	while (len-- > 0)
		xsum += *p++;

	xsum = (xsum & 0xffff) + (xsum >> 16);
	xsum = (xsum & 0xffff) + (xsum >> 16);
	return xsum & 0xffff;
}

uint16_t tcp_checksum(struct iphdr *ip, struct tcphdr *tcp, int len)
{
	uint32_t xsum;
	struct psdhdr pseudo;
	size_t hdrsize = net_tcp_data_offset(tcp);

	pseudo.saddr = ip->saddr;
	pseudo.daddr = ip->daddr;
	pseudo.proto = htons(ip->protocol);
	pseudo.ttlen = htons(hdrsize + len);

	xsum = net_checksum((void *)&pseudo, sizeof(struct psdhdr));
	xsum += net_checksum((void *)tcp, hdrsize + len);

	while (xsum > 0xffff)
		xsum = (xsum & 0xffff) + (xsum >> 16);

	return xsum;
}

int tcp_checksum_ok(struct iphdr *ip, struct tcphdr *tcp, int len)
{
	return tcp_checksum(ip, tcp, len) == 0xffff;
}

IPaddr_t getenv_ip(const char *name)
{
	IPaddr_t ip;
	const char *var = getenv(name);

	if (!var)
		return 0;

	if (!string_to_ip(var, &ip))
		return ip;

	resolv(var, &ip);

	return ip;
}

int setenv_ip(const char *name, IPaddr_t ip)
{
	char str[sizeof("255.255.255.255")];

	sprintf(str, "%pI4", &ip);

	setenv(name, str);

	return 0;
}

static unsigned char *arp_ether;
static IPaddr_t arp_wait_ip;

static void arp_handler(struct arprequest *arp)
{
	IPaddr_t tmp;

	/* are we waiting for a reply */
	if (!arp_wait_ip)
		return;

	tmp = net_read_ip(&arp->ar_data[6]);

	/* matched waiting packet's address */
	if (tmp == arp_wait_ip) {
		/* save address for later use */
		memcpy(arp_ether, &arp->ar_data[0], 6);

		/* no arp request pending now */
		arp_wait_ip = 0;
	}
}

struct eth_device *net_route(IPaddr_t dest)
{
	struct eth_device *edev;

	for_each_netdev(edev) {
		if (!edev->ipaddr || !edev->ifup)
			continue;

		if ((dest & edev->netmask) == (edev->ipaddr & edev->netmask)) {
			pr_debug("Route: Using %s (ip=%pI4, nm=%pI4) to reach %pI4\n",
			      dev_name(&edev->dev), &edev->ipaddr, &edev->netmask,
				       &dest);
			return edev;
		}
	}

	pr_debug("Route: No device found for %pI4\n", &dest);

	return NULL;
}

static int arp_request(struct eth_device *edev, IPaddr_t dest, unsigned char *ether)
{
	char *pkt;
	struct arprequest *arp;
	uint64_t arp_start;
	static char *arp_packet;
	struct ethernet *et;
	unsigned retries = 0;
	int ret;

	if (!edev)
		return -EHOSTUNREACH;

	if (!arp_packet) {
		arp_packet = net_alloc_packet();
		if (!arp_packet)
			return -ENOMEM;
	}

	pkt = arp_packet;
	et = (struct ethernet *)arp_packet;

	arp_wait_ip = dest;

	pr_debug("send ARP broadcast for %pI4\n", &dest);

	memset(et->et_dest, 0xff, 6);
	memcpy(et->et_src, edev->ethaddr, 6);
	et->et_protlen = htons(PROT_ARP);

	arp = (struct arprequest *)(pkt + ETHER_HDR_SIZE);

	arp->ar_hrd = htons(ARP_ETHER);
	arp->ar_pro = htons(PROT_IP);
	arp->ar_hln = 6;
	arp->ar_pln = 4;
	arp->ar_op = htons(ARPOP_REQUEST);

	memcpy(arp->ar_data, edev->ethaddr, 6);	/* source ET addr	*/
	net_write_ip(arp->ar_data + 6, edev->ipaddr);	/* source IP addr	*/
	memset(arp->ar_data + 10, 0, 6);	/* dest ET addr = 0     */

	if ((dest & edev->netmask) != (edev->ipaddr & edev->netmask)) {
		if (!net_gateway)
			arp_wait_ip = dest;
		else
			arp_wait_ip = net_gateway;
	} else {
		arp_wait_ip = dest;
	}

	net_write_ip(arp->ar_data + 16, arp_wait_ip);

	arp_ether = ether;

	ret = eth_send(edev, arp_packet, ETHER_HDR_SIZE + ARP_HDR_SIZE);
	if (ret)
		return ret;
	arp_start = get_time_ns();

	while (arp_wait_ip) {
		if (ctrlc())
			return -EINTR;

		if (is_timeout(arp_start, 3 * SECOND)) {
			printf("T ");
			arp_start = get_time_ns();
			ret = eth_send(edev, arp_packet, ETHER_HDR_SIZE + ARP_HDR_SIZE);
			if (ret)
				return ret;
			retries++;
		}

		if (retries > PKT_NUM_RETRIES)
			return -ETIMEDOUT;

		net_poll();
	}

	pr_debug("Got ARP REPLY for %pI4: %02x:%02x:%02x:%02x:%02x:%02x\n",
		 &dest, ether[0], ether[1], ether[2], ether[3], ether[4],
		 ether[5]);
	return 0;
}

void net_poll(void)
{
	static bool in_net_poll;

	if (in_net_poll)
		return;

	in_net_poll = true;

	eth_rx();

	in_net_poll = false;
}

static void __net_poll(struct poller_struct *poller)
{
	static uint64_t last;

	/*
	 * USB network controllers take a long time in the receive path,
	 * so limit the polling rate to once per 10ms. This is due to
	 * deficiencies in the barebox USB stack: We can't queue URBs and
	 * receive a callback when they are done. Instead, we always
	 * synchronously queue an URB and wait for its completion. In case
	 * of USB network adapters the only way to detect if packets have
	 * been received is to queue a RX URB and see if it completes (in
	 * which case we have received data) or if it timeouts (no data
	 * available). The timeout can't be arbitrarily small, 2ms is the
	 * smallest we can do with the 1ms USB frame size.
	 *
	 * Given that we do a mixture of polling-as-fast-as-possible when
	 * we are waiting for network traffic (tftp, nfs and other users
	 * actively calling net_poll()) and doing a low frequency polling
	 * here to still get packets when no user is actively waiting for
	 * incoming packets. This is used to receive incoming ping packets
	 * and to get fastboot over ethernet going.
	 */
	if (!is_timeout(last, 10 * MSECOND))
		return;

	net_poll();

	last = get_time_ns();
}

static struct poller_struct net_poller = {
	.func = __net_poll,
};

static int init_net_poll(void)
{
	return poller_register(&net_poller, "net");
}
device_initcall(init_net_poll);

static uint16_t net_new_localport(int proto)
{
	const uint16_t min_port = 32768;
	const uint16_t max_port = 65535;
	const uint16_t num_port = max_port - min_port + 1;
	uint16_t localport;

	/* port randomization with the Algorithm 1 as defined in RFC6056 */
	localport = min_port + random32() % num_port;

	while (net_ip_get_con(proto, localport) != NULL) {
		if (localport == max_port)
			localport = min_port;
		else
			localport++;
	}

	return localport;
}

static uint16_t net_udp_new_localport(void)
{
	return net_new_localport(IPPROTO_UDP);
}

static uint16_t net_tcp_new_localport(void)
{
	return net_new_localport(IPPROTO_TCP);
}

IPaddr_t net_get_serverip(void)
{
	IPaddr_t ip;
	int ret;

	ret = resolv(net_server, &ip);
	if (ret)
		return 0;

	return ip;
}

void net_set_serverip(IPaddr_t ip)
{
	free(net_server);

	net_server = xasprintf("%pI4", &ip);
}

void net_set_serverip_empty(IPaddr_t ip)
{
	if (net_server && *net_server)
		return;

	net_set_serverip(ip);
}

void net_set_ip(struct eth_device *edev, IPaddr_t ip)
{
	edev->ipaddr = ip;
}

IPaddr_t net_get_ip(struct eth_device *edev)
{
	return edev->ipaddr;
}

void net_set_netmask(struct eth_device *edev, IPaddr_t nm)
{
	edev->netmask = nm;
}

void net_set_gateway(IPaddr_t gw)
{
	net_gateway = gw;
}

IPaddr_t net_get_gateway(void)
{
	return net_gateway;
}

static struct net_connection *net_new(struct eth_device *edev, IPaddr_t dest,
				      rx_handler_f *handler, void *ctx)
{
	struct net_connection *con;
	int ret;

	if (!edev) {
		edev = net_route(dest);
		if (!edev && net_gateway)
			edev = net_route(net_gateway);
		if (!edev)
			return ERR_PTR(-EHOSTUNREACH);
	}

	if (!is_valid_ether_addr(edev->ethaddr)) {
		char str[sizeof("xx:xx:xx:xx:xx:xx")];
		random_ether_addr(edev->ethaddr);
		ethaddr_to_string(edev->ethaddr, str);
		dev_warn(&edev->dev, "No MAC address set. Using random address %s\n", str);
		eth_set_ethaddr(edev, edev->ethaddr);
	}

	/* If we don't have an ip only broadcast is allowed */
	if (!edev->ipaddr && dest != IP_BROADCAST)
		return ERR_PTR(-ENETDOWN);

	con = xzalloc(sizeof(*con));
	con->packet = net_alloc_packet();
	con->priv = ctx;
	con->edev = edev;
	memset(con->packet, 0, PKTSIZE);

	con->et = (struct ethernet *)con->packet;
	con->ip = (struct iphdr *)(con->packet + ETHER_HDR_SIZE);
	con->udp = (struct udphdr *)(con->packet + ETHER_HDR_SIZE + sizeof(struct iphdr));
	con->tcp = (struct tcphdr *)(con->packet + ETHER_HDR_SIZE + sizeof(struct iphdr));
	con->icmp = (struct icmphdr *)(con->packet + ETHER_HDR_SIZE + sizeof(struct iphdr));
	con->handler = handler;

	if (dest == IP_BROADCAST) {
		memset(con->et->et_dest, 0xff, 6);
	} else {
		ret = arp_request(edev, dest, con->et->et_dest);
		if (ret)
			goto out;
	}

	con->et->et_protlen = htons(PROT_IP);
	memcpy(con->et->et_src, edev->ethaddr, 6);

	con->ip->hl_v = 0x45;
	con->ip->tos = 0;
	con->ip->frag_off = htons(0x4000);	/* No fragmentation */;
	con->ip->ttl = 255;
	net_copy_ip(&con->ip->daddr, &dest);
	net_copy_ip(&con->ip->saddr, &edev->ipaddr);

	list_add_tail(&con->list, &connection_list);

	return con;
out:
	free(con->packet);
	free(con);
	return ERR_PTR(ret);
}

struct net_connection *net_tcp_eth_new(struct eth_device *edev, IPaddr_t dest,
				       uint16_t dport, rx_handler_f *handler,
				       void *ctx)
{
	struct net_connection *con = net_new(edev, dest, handler, ctx);
	uint16_t doff;

	if (IS_ERR(con))
		return con;

	con->proto = IPPROTO_TCP;
	con->state = TCP_CLOSED;
	con->tcp->src = htons(net_tcp_new_localport());
	con->tcp->dst = htons(dport);
	con->tcp->seq = 0;
	con->tcp->ack = 0;
	doff = sizeof(struct tcphdr) / sizeof(uint32_t);
	con->tcp->doff_flag = htons(doff << TCP_DOFF_SHIFT);
	con->tcp->urp = 0;
	con->ip->protocol = IPPROTO_TCP;

	return con;
}

struct net_connection *net_udp_eth_new(struct eth_device *edev, IPaddr_t dest,
				       uint16_t dport, rx_handler_f *handler,
				       void *ctx)
{
	struct net_connection *con = net_new(edev, dest, handler, ctx);

	if (IS_ERR(con))
		return con;

	con->proto = IPPROTO_UDP;
	con->udp->uh_dport = htons(dport);
	con->udp->uh_sport = htons(net_udp_new_localport());
	con->ip->protocol = IPPROTO_UDP;

	return con;
}

struct net_connection *net_udp_new(IPaddr_t dest, uint16_t dport,
		rx_handler_f *handler, void *ctx)
{
	return net_udp_eth_new(NULL, dest, dport, handler, ctx);
}

struct net_connection *net_tcp_new(IPaddr_t dest, uint16_t dport,
		rx_handler_f *handler, void *ctx)
{
	return net_tcp_eth_new(NULL, dest, dport, handler, ctx);
}

struct net_connection *net_icmp_new(IPaddr_t dest, rx_handler_f *handler,
		void *ctx)
{
	struct net_connection *con = net_new(NULL, dest, handler, ctx);

	if (IS_ERR(con))
		return con;

	con->proto = IPPROTO_ICMP;
	con->ip->protocol = IPPROTO_ICMP;

	return con;
}

void net_unregister(struct net_connection *con)
{
	list_del(&con->list);
	free(con->packet);
	free(con);
}

static int net_ip_send(struct net_connection *con, int len)
{
	con->ip->tot_len = htons(sizeof(struct iphdr) + len);
	con->ip->id = htons(net_ip_id++);
	con->ip->check = 0;
	con->ip->check = ~net_checksum((unsigned char *)con->ip, sizeof(struct iphdr));

	return eth_send(con->edev, con->packet, ETHER_HDR_SIZE + sizeof(struct iphdr) + len);
}

int net_udp_send(struct net_connection *con, int len)
{
	con->udp->uh_ulen = htons(len + 8);
	con->udp->uh_sum = 0;

	return net_ip_send(con, sizeof(struct udphdr) + len);
}

static int tcp_send(struct net_connection *con, int len, uint16_t flags)
{
	size_t hdr_size = net_tcp_data_offset(con->tcp);

	con->tcp->doff_flag &= ~htons(TCP_FLAG_MASK);
	con->tcp->doff_flag |= htons(flags);
	con->tcp->sum = 0;
	con->tcp->sum = ~tcp_checksum(con->ip, con->tcp, len);

	return net_ip_send(con, hdr_size + len);
}

int net_tcp_send(struct net_connection *con, int len)
{
	struct tcb *tcb = &con->tcb;
	uint16_t flag = 0;

	if (con->proto != IPPROTO_TCP)
		return -EPROTOTYPE;
	switch (con->state) {
	case TCP_CLOSED:
		return -ENOTCONN;
	case TCP_LISTEN:
		/* TODO: proceed as open */
		break;
	case TCP_SYN_SENT:
	case TCP_SYN_RECV:
		/* queue request or "error:  insufficient resources". */
		break;
	case TCP_ESTABLISHED:
	case TCP_CLOSE_WAIT:
		/* proceed */
		break;
	case TCP_FIN_WAIT1:
	case TCP_FIN_WAIT2:
	case TCP_TIME_WAIT:
	case TCP_LAST_ACK:
	case TCP_CLOSING:
		return -ESHUTDOWN;
	}

	con->tcp->seq = htonl(tcb->snd_nxt);
	tcb->snd_nxt += len;
	flag |= TCP_FLAG_PSH;
	if (1 || ntohl(con->tcp->ack) < con->tcb.rcv_nxt) {
		flag |= TCP_FLAG_ACK;
		con->tcp->ack = htonl(con->tcb.rcv_nxt);
	} else {
		con->tcp->ack = 0;
	}

	return tcp_send(con, len, flag);
}

int net_tcp_listen(struct net_connection *con)
{
	if (con->proto != IPPROTO_TCP)
		return -EPROTOTYPE;

	con->state = TCP_LISTEN;
	return -1;
}

int net_tcp_open(struct net_connection *con)
{
	struct tcphdr *tcp = net_eth_to_tcphdr(con->packet);
	struct tcb *tcb = &con->tcb;
	int ret;

	if (con->proto != IPPROTO_TCP)
		return -EPROTOTYPE;
	switch (con->state) {
	case TCP_CLOSED:
	case TCP_LISTEN:
		break;
	case TCP_SYN_SENT:
	case TCP_SYN_RECV:
	case TCP_ESTABLISHED:
	case TCP_FIN_WAIT1:
	case TCP_FIN_WAIT2:
	case TCP_TIME_WAIT:
	case TCP_CLOSE_WAIT:
	case TCP_LAST_ACK:
	case TCP_CLOSING:
		return -EISCONN;
	}

	/* use a window smaller than the MTU, as only one tcp segment packet
	 * can be received at time */
	tcb->rcv_wnd = 1024;
	tcb->snd_wnd = 0;
	tcb->iss = random32() + (get_time_ns() >> 10);
	con->state = TCP_SYN_SENT;

	tcp->wnd = htons(tcb->rcv_wnd);
	tcp->seq = htonl(tcb->iss);
	tcb->snd_una = tcb->iss;
	tcb->snd_nxt = tcb->iss + 1;
	ret = tcp_send(con, 0, TCP_FLAG_SYN);
	if (ret)
		return ret;

	ret = wait_on_timeout(6000 * MSECOND, con->state == TCP_ESTABLISHED);
	if (ret)
		return -ETIMEDOUT;

	return con->ret; // TODO: return 0 ?
}

int net_tcp_close(struct net_connection *con)
{
	struct tcphdr *tcp = net_eth_to_tcphdr(con->packet);
	struct tcb *tcb = &con->tcb;
	int ret;

	if (con->proto != IPPROTO_TCP)
		return -EPROTOTYPE;
	switch (con->state) {
	case TCP_CLOSED:
		return -ENOTCONN;
	case TCP_LISTEN:
	case TCP_SYN_SENT:
		con->state = TCP_CLOSED;
		return 0;
		break;
	case TCP_SYN_RECV:
	case TCP_ESTABLISHED:
		/* wait for pending send */
		con->state = TCP_FIN_WAIT1;
		break;
	case TCP_FIN_WAIT1:
	case TCP_FIN_WAIT2:
		/* error: connection closing */
		return -1;
	case TCP_TIME_WAIT:
	case TCP_LAST_ACK:
	case TCP_CLOSING:
		/* error: connection closing */
		return -1;
	case TCP_CLOSE_WAIT:
		/* queue close request after pending sends */
		con->state = TCP_LAST_ACK;
		break;
	}

	tcp->seq = htonl(tcb->snd_nxt);
	tcp->ack = htonl(tcb->rcv_nxt);
	tcb->snd_nxt += 1;
	ret = tcp_send(con, 0, TCP_FLAG_FIN | TCP_FLAG_ACK);
	if (ret)
		return ret;

	ret = wait_on_timeout(1000 * MSECOND, con->state == TCP_CLOSED);
	if (ret)
		return -ETIMEDOUT;

	net_unregister(con);

	return con->ret; // TODO: return 0 ?
}

int net_icmp_send(struct net_connection *con, int len)
{
	con->icmp->checksum = ~net_checksum((unsigned char *)con->icmp,
			sizeof(struct icmphdr) + len);

	return net_ip_send(con, sizeof(struct icmphdr) + len);
}

static int net_answer_arp(struct eth_device *edev, unsigned char *pkt, int len)
{
	struct arprequest *arp = (struct arprequest *)(pkt + ETHER_HDR_SIZE);
	struct ethernet *et = (struct ethernet *)pkt;
	unsigned char *packet;
	int ret;

	pr_debug("%s\n", __func__);

	memcpy (et->et_dest, et->et_src, 6);
	memcpy (et->et_src, edev->ethaddr, 6);

	et->et_protlen = htons(PROT_ARP);
	arp->ar_op = htons(ARPOP_REPLY);
	memcpy(&arp->ar_data[10], &arp->ar_data[0], 6);
	net_copy_ip(&arp->ar_data[16], &arp->ar_data[6]);
	memcpy(&arp->ar_data[0], edev->ethaddr, 6);
	net_copy_ip(&arp->ar_data[6], &edev->ipaddr);

	packet = net_alloc_packet();
	if (!packet)
		return 0;
	memcpy(packet, pkt, ETHER_HDR_SIZE + ARP_HDR_SIZE);
	ret = eth_send(edev, packet, ETHER_HDR_SIZE + ARP_HDR_SIZE);
	free(packet);

	return ret;
}

static void net_bad_packet(unsigned char *pkt, int len)
{
#ifdef DEBUG
	/*
	 * We received a bad packet. for now just dump it.
	 * We could add more sophisticated debugging here
	 */
	memory_display(pkt, 0, len, 1, 0);
#endif
}

static int net_handle_arp(struct eth_device *edev, unsigned char *pkt, int len)
{
	struct arprequest *arp;

	pr_debug("%s: got arp\n", __func__);

	/*
	 * We have to deal with two types of ARP packets:
	 * - REQUEST packets will be answered by sending  our
	 *   IP address - if we know it.
	 * - REPLY packets are expected only after we asked
	 *   for the TFTP server's or the gateway's ethernet
	 *   address; so if we receive such a packet, we set
	 *   the server ethernet address
	 */
	arp = (struct arprequest *)(pkt + ETHER_HDR_SIZE);
	if (len < ARP_HDR_SIZE)
		goto bad;
	if (ntohs(arp->ar_hrd) != ARP_ETHER)
		goto bad;
	if (ntohs(arp->ar_pro) != PROT_IP)
		goto bad;
	if (arp->ar_hln != 6)
		goto bad;
	if (arp->ar_pln != 4)
		goto bad;
	if (edev->ipaddr == 0)
		return 0;
	if (net_read_ip(&arp->ar_data[16]) != edev->ipaddr)
		return 0;

	switch (ntohs(arp->ar_op)) {
	case ARPOP_REQUEST:
		return net_answer_arp(edev, pkt, len);
	case ARPOP_REPLY:
		arp_handler(arp);
		return 1;
	default:
		pr_debug("Unexpected ARP opcode 0x%x\n", ntohs(arp->ar_op));
		return -EINVAL;
	}

bad:
	net_bad_packet(pkt, len);
	return -EINVAL;
}

static int net_handle_udp(unsigned char *pkt, int len)
{
	struct iphdr *ip = (struct iphdr *)(pkt + ETHER_HDR_SIZE);
	struct net_connection *con;
	struct udphdr *udp;

	udp = (struct udphdr *)(ip + 1);
	con = net_ip_get_con(IPPROTO_UDP, ntohs(udp->uh_dport));
	if (con) {
		con->handler(con->priv, pkt, len);
		return 0;
	}
	return -EINVAL;
}

static int net_handle_tcp(unsigned char *pkt, int len)
{
	size_t min_size = ETHER_HDR_SIZE + sizeof(struct iphdr);
	struct net_connection *con;
	struct iphdr *ip = net_eth_to_iphdr(pkt);
	struct tcphdr *tcp = net_eth_to_tcphdr(pkt);
	struct tcb *tcb;
	uint16_t flag;
	uint16_t doff;
	uint32_t tcp_len;
	uint32_t seg_len;
	uint32_t seg_ack;
	uint32_t seg_seq;
	uint32_t seg_last;
	uint32_t rcv_wnd;
	uint32_t rcv_nxt;
	int seg_accept = 0;

	if (len < (min_size + sizeof(struct tcphdr)))
		goto bad;
	flag = ntohs(tcp->doff_flag) & TCP_FLAG_MASK;
	doff = net_tcp_data_offset(tcp);
	if (doff < sizeof(struct tcphdr))
		goto bad;
	if (len < (min_size + doff))
		goto bad;

	seg_ack = ntohl(tcp->ack);
	seg_seq = ntohl(tcp->seq);
	tcp_len = net_eth_to_tcplen(pkt);
	seg_len = tcp_len;
	seg_len += !!(flag & TCP_FLAG_FIN);
	seg_len += !!(flag & TCP_FLAG_SYN);

	if (!tcp_checksum_ok(ip, tcp, tcp_len))
		goto bad;

	con = net_ip_get_con(IPPROTO_TCP, ntohs(tcp->dst));
	if (con == NULL)
		goto bad;
	tcb = &con->tcb;

	/* segment arrives */
	seg_last = seg_seq + seg_len - 1;
	rcv_wnd = tcb->rcv_wnd;
	rcv_nxt = tcb->rcv_nxt;

	if (seg_len == 0 && rcv_wnd == 0)
		seg_accept = seg_seq == rcv_nxt;
	if (seg_len == 0 && rcv_wnd > 0)
		seg_accept = rcv_nxt <= seg_seq && seg_seq < (rcv_nxt + rcv_wnd);
	if (seg_len > 0 && rcv_wnd == 0)
		seg_accept = 0; /* not acceptable */
	if (seg_len > 0 && rcv_wnd > 0)
		seg_accept = (rcv_nxt <= seg_seq && seg_seq < (rcv_nxt + rcv_wnd))
			|| (rcv_nxt <= seg_last && seg_last < (rcv_nxt + rcv_wnd));

	switch (con->state) {
	case TCP_CLOSED:
		if (flag & TCP_FLAG_RST) {
			goto drop;
		}
		if (flag & TCP_FLAG_ACK) {
			con->tcp->seq = 0;
			con->tcp->ack = htonl(seg_seq + seg_len);
			con->ret = tcp_send(con, 0, TCP_FLAG_RST | TCP_FLAG_ACK);
		} else  {
			con->tcp->seq = htonl(seg_ack);
			con->ret = tcp_send(con, 0, TCP_FLAG_RST);
		}
		break;
	case TCP_LISTEN:
		/* TODO */
		break;
	case TCP_SYN_SENT:
		if (flag & TCP_FLAG_ACK) {
			if (seg_ack <= tcb->iss || seg_ack > tcb->snd_nxt) {
				if (flag & TCP_FLAG_RST)
					goto drop;
				con->tcp->seq = htonl(seg_ack);
				return tcp_send(con, 0, TCP_FLAG_RST);
			}
			if (tcb->snd_una > seg_ack || seg_ack > tcb->snd_nxt)
				goto drop; /* unacceptable */
		}
		if (flag & TCP_FLAG_RST) {
			con->state = TCP_CLOSED;
			con->ret = -ENETRESET;
			break;
		}
		if ((flag & TCP_FLAG_SYN) && !(flag & TCP_FLAG_RST)) {
			tcb->irs = seg_seq;
			tcb->rcv_nxt = seg_seq + 1;
			if (flag & TCP_FLAG_ACK)
				tcb->snd_una = seg_ack;
			if (tcb->snd_una > tcb->iss) {
				con->state = TCP_ESTABLISHED;
				con->tcp->seq = htonl(tcb->snd_nxt);
				con->tcp->ack = htonl(tcb->rcv_nxt);
				con->ret = tcp_send(con, 0, TCP_FLAG_ACK);
			} else {
				con->state = TCP_SYN_RECV;
				tcb->snd_nxt = tcb->iss + 1;
				con->tcp->seq = htonl(tcb->iss);
				con->tcp->ack = htonl(tcb->rcv_nxt);
				con->ret = tcp_send(con, 0, TCP_FLAG_SYN | TCP_FLAG_ACK);
			}
		}
		break;
	case TCP_SYN_RECV:
	case TCP_ESTABLISHED:
		if (flag & TCP_FLAG_RST) {
			/* TODO: if passive open then return to LISTEN */
			con->state = TCP_CLOSED;
			con->ret = -ECONNREFUSED;
			break;
		}
		if (!seg_accept) {
			/* segment is not acceptable, send an ack unless RST bit
			 * is set (done above) */
			con->tcp->seq = htonl(tcb->snd_nxt);
			con->tcp->ack = htonl(tcb->rcv_nxt);
			con->ret = tcp_send(con, 0, TCP_FLAG_ACK);
			goto drop;
		}
		if (flag & TCP_FLAG_FIN && flag & TCP_FLAG_ACK)
			con->state = TCP_CLOSE_WAIT;

		if (flag & TCP_FLAG_ACK)
			tcb->snd_una = seg_ack;

		tcb->rcv_nxt += seg_len;
		con->tcp->seq = htonl(tcb->snd_nxt);
		if (seg_len) {
			con->tcp->ack = htonl(tcb->rcv_nxt);
			con->ret = tcp_send(con, 0, TCP_FLAG_ACK |
					    /* send FIN+ACK if FIN is set */
					    (flag & TCP_FLAG_FIN));
		}
		con->handler(con->priv, pkt, len);
		break;
	case TCP_FIN_WAIT1:
		if (flag & TCP_FLAG_FIN)
			con->state = TCP_CLOSING;
		if (flag & TCP_FLAG_ACK)
			tcb->snd_una = seg_ack;
		/* fall-through */
	case TCP_FIN_WAIT2:
		tcb->rcv_nxt += seg_len;
		con->tcp->seq = htonl(tcb->snd_nxt);
		if (seg_len) {
			con->tcp->ack = htonl(tcb->rcv_nxt);
			con->ret = tcp_send(con, 0, TCP_FLAG_ACK);
		}
	case TCP_CLOSE_WAIT:
		/* all segment queues should be flushed */
		if (flag & TCP_FLAG_RST) {
			con->state = TCP_CLOSED;
			con->ret = -ENETRESET;
			break;
		}
		break;
	case TCP_CLOSING:
		con->state = TCP_TIME_WAIT;
	case TCP_LAST_ACK:
	case TCP_TIME_WAIT:
		if (flag & TCP_FLAG_RST) {
			con->state = TCP_CLOSED;
			con->ret = 0;
		}
		break;
	}
	return con->ret;
drop:
	return 0;
bad:
	net_bad_packet(pkt, len);
	return 0;
}

static int ping_reply(struct eth_device *edev, unsigned char *pkt, int len)
{
	struct ethernet *et = (struct ethernet *)pkt;
	struct icmphdr *icmp;
	struct iphdr *ip = (struct iphdr *)(pkt + ETHER_HDR_SIZE);
	unsigned char *packet;
	int ret;

	memcpy(et->et_dest, et->et_src, 6);
	memcpy(et->et_src, edev->ethaddr, 6);
	et->et_protlen = htons(PROT_IP);

	icmp = net_eth_to_icmphdr(pkt);

	icmp->type = ICMP_ECHO_REPLY;
	icmp->checksum = 0;
	icmp->checksum = ~net_checksum((unsigned char *)icmp,
				       len - sizeof(struct iphdr) - ETHER_HDR_SIZE);
	ip->check = 0;
	ip->frag_off = 0;
	net_copy_ip((void *)&ip->daddr, &ip->saddr);
	net_copy_ip((void *)&ip->saddr, &edev->ipaddr);
	ip->check = ~net_checksum((unsigned char *)ip, sizeof(struct iphdr));

	packet = net_alloc_packet();
	if (!packet)
		return 0;

	memcpy(packet, pkt, ETHER_HDR_SIZE + len);

	ret = eth_send(edev, packet, ETHER_HDR_SIZE + len);

	free(packet);

	return 0;
}

static int net_handle_icmp(struct eth_device *edev, unsigned char *pkt, int len)
{
	struct net_connection *con;
	struct icmphdr *icmp;

	pr_debug("%s\n", __func__);

	icmp = net_eth_to_icmphdr(pkt);
	if (icmp->type == ICMP_ECHO_REQUEST)
		ping_reply(edev, pkt, len);

	list_for_each_entry(con, &connection_list, list) {
		if (con->proto == IPPROTO_ICMP) {
			con->handler(con->priv, pkt, len);
			return 0;
		}
	}
	return 0;
}

static int net_handle_ip(struct eth_device *edev, unsigned char *pkt, int len)
{
	struct iphdr *ip = (struct iphdr *)(pkt + ETHER_HDR_SIZE);
	IPaddr_t tmp;

	pr_debug("%s\n", __func__);

	if (len < sizeof(struct ethernet) + sizeof(struct iphdr) ||
		len < ETHER_HDR_SIZE + ntohs(ip->tot_len)) {
		pr_debug("%s: bad len\n", __func__);
		goto bad;
	}

	if ((ip->hl_v & 0xf0) != 0x40)
		goto bad;

	if (ip->frag_off & htons(0x1fff)) /* Can't deal w/ fragments */
		goto bad;
	if (!net_checksum_ok((unsigned char *)ip, sizeof(struct iphdr)))
		goto bad;

	tmp = net_read_ip(&ip->daddr);
	if (edev->ipaddr && tmp != edev->ipaddr && tmp != IP_BROADCAST)
		return 0;

	switch (ip->protocol) {
	case IPPROTO_ICMP:
		return net_handle_icmp(edev, pkt, len);
	case IPPROTO_UDP:
		return net_handle_udp(pkt, len);
	case IPPROTO_TCP:
		return net_handle_tcp(pkt, len);
	}

	return 0;
bad:
	net_bad_packet(pkt, len);
	return 0;
}

int net_receive(struct eth_device *edev, unsigned char *pkt, int len)
{
	struct ethernet *et = (struct ethernet *)pkt;
	int et_protlen = ntohs(et->et_protlen);
	int ret;

	led_trigger_network(LED_TRIGGER_NET_RX);

	if (len < ETHER_HDR_SIZE) {
		ret = 0;
		goto out;
	}

	if (edev->rx_monitor)
		edev->rx_monitor(edev, pkt, len);

	if (edev->rx_preprocessor) {
		ret = edev->rx_preprocessor(edev, &pkt, &len);
		if (ret == -ENOMSG)
			return 0;
		if (ret) {
			pr_debug("%s: rx_preprocessor failed %pe\n", __func__,
				 ERR_PTR(ret));
			return ret;
		}
	}

	switch (et_protlen) {
	case PROT_ARP:
		ret = net_handle_arp(edev, pkt, len);
		break;
	case PROT_IP:
		ret = net_handle_ip(edev, pkt, len);
		break;
	default:
		pr_debug("%s: got unknown protocol type: %d\n", __func__, et_protlen);
		ret = 1;
		break;
	}
out:
	return ret;
}

static int net_init(void)
{
	int i;

	for (i = 0; i < PKTBUFSRX; i++)
		NetRxPackets[i] = net_alloc_packet();

	globalvar_add_simple_ip("net.nameserver", &net_nameserver);
	globalvar_add_simple_string("net.domainname", &net_domainname);
	globalvar_add_simple_string("net.server", &net_server);
	globalvar_add_simple_ip("net.gateway", &net_gateway);

	return 0;
}

postcore_initcall(net_init);

BAREBOX_MAGICVAR(global.net.nameserver, "The DNS server used for resolving host names");
BAREBOX_MAGICVAR(global.net.domainname, "Domain name used for DNS requests");
BAREBOX_MAGICVAR(global.net.server, "Standard server used for NFS/TFTP");
