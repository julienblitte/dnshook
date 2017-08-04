/* Configuration file parser and generator
 *
 * Copyright (C) 2017  Julien Blitte <julien.blitte@gmail.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#include <arpa/inet.h>
#include <byteswap.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <ifaddrs.h>

#define PROTOCOL		"udp"
#define PACKET_SIZE		2048
#define PORT_NUM		53
#define SYSLOG_NAME		"dnshook"
#define REPLY_DNS_TTL		0x00015180

#define DNS_RESPONSE	0x0080
#define DNS_RECURSION_AVAILABLE	0x8000
#define DNS_NAME_REFER	0xC000
#define DNS_CLASS	0x0001
#define DNS_TYPE_A	0x0001

#ifdef EASY_REMOTE
	#define DNS_TYPE_SET	0x000C
#else
	#define DNS_TYPE_SET	0xFF0C
#endif

#define PID_FILE	"/var/run/dnshook.pid"


#pragma pack(push)
#pragma pack(2)
typedef struct
{
	uint16_t transaction_id;
	uint16_t flags;
	uint16_t nb_question;
	uint16_t nb_answer;
	uint16_t authority;
	uint16_t additionnal;
} dns_header;

typedef struct
{
	uint16_t pname;
	uint16_t type;
	uint16_t class;
	uint32_t ttl;
	uint16_t len;
	uint32_t ip;
} dns_rr_entry;
#pragma pack(pop)

void die(const char *context)
{
	syslog(LOG_ERR, "fatal error: %s", context);
	if (errno == 0)
	{
		exit(EXIT_FAILURE);
	}

	syslog(LOG_ERR, "error code is %d", errno);
	exit(errno);
}

int get_protocol_id(const char *name)
{
	struct protoent *protocol;

	protocol = getprotobyname(name);

	return (protocol ? protocol->p_proto : 0);
}

char *iptos(uint32_t ip)
{
	static char result[INET_ADDRSTRLEN];

	inet_ntop(AF_INET, (void *)&ip, result, sizeof(result));

	return result;
}

char *dns_sgets(char *src)
{
	int i, sub_size;
	static char result[2048];

	i = 0;
	while(i < sizeof(result)-1)
	{
		sub_size = (unsigned char)*src;
		src++;
		if (sub_size == 0) break;
		result[i++] = '.';
		while(sub_size)
		{
			if (i >= sizeof(result)-1) break;
			result[i++] = *src;
			src++;
			sub_size--;
		}
	}
	result[i] = '\0';

	return result;
}

uint32_t ptr_ip(char *ptr)
{
	uint32_t ip[4];
	sscanf(ptr, ".%u.%u.%u.%u.in-addr.arpa", ip+3, ip+2, ip+1, ip);

	return ((ip[3]<<24)|(ip[2]<<16)|(ip[1]<<8)|ip[0]);
}

int dns_reply(char *buffer, int *buffer_size, uint32_t *ip)
{
	int i;
	int nb_request;
	int cursor;
	int nb_answer;
	dns_header *dns;

	char *ptr_request;

	dns_rr_entry reply;

	dns = (dns_header *)buffer;
	dns->flags |= htons(DNS_RESPONSE) | htons(DNS_RECURSION_AVAILABLE);
	nb_request = ntohs(dns->nb_question);
	
	nb_answer = 0;

	cursor = sizeof(dns_header);
	for(i=0; i < nb_request; i++)
	{
		reply.pname = htons(cursor);

		/* dns chain */
		while(buffer[cursor] != '\0')
		{
			cursor += (unsigned char)buffer[cursor] + 1;
		}
		cursor += 1;
		reply.type = *((uint16_t *)(buffer+cursor));
		cursor += 2;
		reply.class = *((uint16_t *)(buffer+cursor));
		cursor += 2;

		/* not internet */
		if (ntohs(reply.class) != DNS_CLASS)
		{
			continue;
		}

		/* ipv4 */
		if (ntohs(reply.type) == DNS_TYPE_A)
		{
			reply.pname |= htons(DNS_NAME_REFER);
			reply.ttl = htonl(REPLY_DNS_TTL);
			reply.len = htons(sizeof(reply.ip));
			reply.ip = *ip;

			memcpy(buffer+(*buffer_size), &reply, sizeof(reply));
			*buffer_size += sizeof(reply);

			nb_answer++;
		}
		/* remote address setup */
		else if (ntohs(reply.type) == DNS_TYPE_SET)
		{
			ptr_request = dns_sgets(buffer+ntohs(reply.pname));
			*ip = ptr_ip(ptr_request);
			syslog(LOG_NOTICE, "Hook to new address %s", iptos(*ip));

			reply.pname |= htons(DNS_NAME_REFER);
			reply.ttl = htonl(REPLY_DNS_TTL);

			memset(&reply.ip, 0, sizeof(reply.ip));
			/* must be strlen(1) + string(n) + \0(1) */
			strncpy((char *)&reply.ip, "\2ok", sizeof(reply.ip));
			reply.len = htons(strlen((char *)&reply.ip)+1);

			memcpy(buffer+(*buffer_size), &reply, sizeof(reply));
			*buffer_size += sizeof(reply);

			nb_answer++;
		}
	}

	dns->nb_answer = htons(nb_answer);

	return (nb_answer - nb_request);
}

int get_ip_address(uint32_t *ip)
{
	struct ifaddrs *ifaddr, *ifa;
	int family, s, n;
	int i;

	if (getifaddrs(&ifaddr) == -1)
	{
		return 0;
	}

	for (ifa = ifaddr, n = 0; ifa != NULL; ifa = ifa->ifa_next, n++)
	{
		if (ifa->ifa_addr == NULL)
			continue;

		if (ifa->ifa_addr->sa_family != AF_INET)
			continue;

		if (strcmp(ifa->ifa_name, "lo") == 0)
			continue;

		/* AF_INET */
		*ip = ((struct sockaddr_in *)ifa->ifa_addr)->sin_addr.s_addr;
		freeifaddrs(ifaddr);
		return 1;
	}

	freeifaddrs(ifaddr);
	return 0;
}

void usage()
{
	perror("Usage: dnshook [ip4_adress]\n");
	exit(1);
}

void daemonize() 
{
	FILE *run;

	if (daemon(0, 0) == -1)
	{
		die("unable to become deamon.");
	}
	if(run = fopen(PID_FILE, "wt"))
	{
		fprintf(run, "%d", getpid());
		fclose(run);
	}
}

int main(int argc, char *argv[])
{
	struct sockaddr_in server_socket, local_socket;
	static char buffer[PACKET_SIZE];
	socklen_t socket_size;
	int buffer_size;
	int hsocket, cc;

	uint32_t ip;

	openlog(SYSLOG_NAME, LOG_PERROR, LOG_DAEMON);

	if (argc == 1)
	{
		if (!get_ip_address(&ip))
		{
			die("no ip address found.");
		}
	}
	else if (argc == 2)
	{
		if (inet_pton(AF_INET, argv[1], (void *)&ip) != 1)
		{
			usage();
		}
	}
	else
	{
		usage();
	}


	if (geteuid() != 0)
	{
		die("you must be root!");
	}

#ifndef DEBUG
	daemonize();
#endif

	memset(&server_socket, 0, sizeof(server_socket));
	server_socket.sin_family = AF_INET;
	server_socket.sin_addr.s_addr = htonl(INADDR_ANY);
	server_socket.sin_port = htons(PORT_NUM);

	hsocket = socket(AF_INET, SOCK_DGRAM, get_protocol_id(PROTOCOL));
	if (hsocket < 0)
	{
		die("creating socket.");
	}

	if (bind(hsocket, (struct sockaddr *)&server_socket, sizeof(server_socket)) < 0)
	{
		die("binding socket.");
	}

	syslog(LOG_NOTICE, "Server ready, bound at %s/%d, hook to address %s", PROTOCOL, PORT_NUM, iptos(ip));

	while(1)
	{
		socket_size = sizeof(local_socket);
		buffer_size = recvfrom(hsocket, buffer, PACKET_SIZE, 0, (struct sockaddr *)&local_socket, &socket_size);

		if (buffer_size == -1)
		{
			syslog(LOG_WARNING, "error recieving packet.\n");
			continue;
		}


		syslog(LOG_INFO, "recieved query from %s:%d\n", iptos(*((uint32_t *)&local_socket.sin_addr)), ntohs(local_socket.sin_port));

		dns_reply(buffer, &buffer_size, &ip);

		if (sendto(hsocket, buffer, buffer_size, 0, (struct sockaddr *)&local_socket, socket_size) == -1)
		{
			syslog(LOG_WARNING, "error responding request.\n");
		}
	}
}

