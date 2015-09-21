/*
 * Copyright (c) 2015 by Farsight Security, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/time.h>
#include <ctype.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#include <protobuf-c/protobuf-c.h>

#include "dnstap.pb-c.h"
#include "evldns.h"

static void
print_socket(const struct sockaddr_storage *ss, FILE *fp)
{
	const char *addr = NULL;
	char s[INET6_ADDRSTRLEN] = {0};
	uint16_t port = 0;

	if (ss->ss_family == AF_INET) {
		const struct sockaddr_in *sai = (const struct sockaddr_in *) ss;
		addr = inet_ntop(AF_INET, &sai->sin_addr, s, sizeof(s));
		port = ntohs(sai->sin_port);
	} else if (ss->ss_family == AF_INET6) {
		const struct sockaddr_in6 *sai6 = (const struct sockaddr_in6 *) ss;
		addr = inet_ntop(AF_INET6, &sai6->sin6_addr, s, sizeof(s));
		port = ntohs(sai6->sin6_port);
	}

	if (addr) {
		fprintf(fp, "[%s]:%hu", addr, port);
	} else {
		fputs("[ERROR]", fp);
	}
}

static void
log_query(const evldns_server_request *q,
	  const ldns_rdf *qname,
	  const ldns_rr_type qtype,
	  const ldns_rr_class qclass,
	  const char *prefix,
	  FILE *fp)
{
	char *str_qtype = ldns_rr_type2str(qtype);
	char *str_qclass = ldns_rr_class2str(qclass);

	fprintf(fp, "dtwhoami: %s from ", prefix);
	print_socket(&q->addr, fp);
	fputs(" for ", fp);
	ldns_rdf_print(fp, qname);
	fprintf(fp, "/%s/%s\n", str_qclass, str_qtype);

	/* Cleanup. */
	free(str_qtype);
	free(str_qclass);
}

static ldns_rdf *
get_rdf_a(evldns_server_request *q)
{
	uint8_t data[4] = {0};

	if (q->addr.ss_family != AF_INET)
		return NULL;

	memcpy(data, &(((struct sockaddr_in *) &q->addr)->sin_addr), 4);
	return ldns_rdf_new_frm_data(LDNS_RDF_TYPE_A, 4, data);
}

static ldns_rdf *
get_rdf_aaaa(evldns_server_request *q)
{
	uint8_t data[16] = {0};

	if (q->addr.ss_family != AF_INET6)
		return NULL;

	memcpy(data, &(((struct sockaddr_in6 *) &q->addr)->sin6_addr), 16);
	return ldns_rdf_new_frm_data(LDNS_RDF_TYPE_AAAA, 16, data);
}

static bool
dt_pack(const Dnstap__Dnstap *d, void **buf, size_t *sz)
{
	ProtobufCBufferSimple sbuf = {0};

	sbuf.base.append = protobuf_c_buffer_simple_append;
	sbuf.len = 0;
	sbuf.alloced = 512;
	sbuf.data = malloc(sbuf.alloced);
	if (sbuf.data == NULL)
		return false;
	sbuf.must_free_data = 1;

	*sz = dnstap__dnstap__pack_to_buffer(d, (ProtobufCBuffer *) &sbuf);
	if (sbuf.data == NULL)
		return false;
	*buf = sbuf.data;

	return true;
}

static ldns_rdf *
get_rdf_null(evldns_server_request *q)
{
	/* Initialize top-level 'Dnstap' protobuf. */
	Dnstap__Dnstap d = {0};
	d.base.descriptor = &dnstap__dnstap__descriptor;

	/* Initialize 'Message' protobuf. */
	Dnstap__Message m = {0};
	m.base.descriptor = &dnstap__message__descriptor;

	/* Bind the Message to the Dnstap. */
	d.message = &m;
	d.type = DNSTAP__DNSTAP__TYPE__MESSAGE;

	/* Message.type */
	m.type = DNSTAP__MESSAGE__TYPE__AUTH_QUERY;

	/* Message.socket_family */
	if (q->addr.ss_family == AF_INET) {
		m.socket_family = DNSTAP__SOCKET_FAMILY__INET;
		m.has_socket_family = 1;

		struct sockaddr_in *s = (struct sockaddr_in *) &q->addr;

		/* Message.query_address */
		m.query_address.len = 4;
		m.query_address.data = (uint8_t *) &s->sin_addr;
		m.has_query_address = 1;

		/* Message.query_port */
		m.query_port = ntohs(s->sin_port);
		m.has_query_port = 1;

	} else if (q->addr.ss_family == AF_INET6) {
		m.socket_family = DNSTAP__SOCKET_FAMILY__INET6;

		struct sockaddr_in6 *s = (struct sockaddr_in6 *) &q->addr;

		/* Message.query_address */
		m.query_address.len = 16;
		m.query_address.data = (uint8_t *) &s->sin6_addr;
		m.has_query_address = 1;

		/* Message.query_port */
		m.query_port = ntohs(s->sin6_port);
		m.has_query_port = 1;

	} else {
		return NULL;
	}

	/* Message.socket_protocol */
	if (q->is_tcp) {
		m.socket_protocol = DNSTAP__SOCKET_PROTOCOL__TCP;
	} else {
		m.socket_protocol = DNSTAP__SOCKET_PROTOCOL__UDP;
	}

	/* Message.query_time_sec */
	struct timespec ts = {0};
	clock_gettime(CLOCK_REALTIME, &ts);
	m.query_time_sec = ts.tv_sec;
	m.query_time_nsec = ts.tv_nsec;
	m.has_query_time_sec = 1;
	m.has_query_time_nsec = 1;

	/* Message.query_message */
	m.query_message.len = q->wire_reqlen;
	m.query_message.data = q->wire_request;
	m.has_query_message = 1;

	/* Pack the Dnstap payload. */
	void *data = NULL;
	size_t sz = 0;

	if (!dt_pack(&d, &data, &sz))
		return NULL;

	/* Wrap the serialized Dnstap payload in an ldns_rdf. */
	ldns_rdf *rdf = ldns_rdf_new_frm_data(LDNS_RDF_TYPE_UNKNOWN, sz, data);

	/* Cleanup. */
	free(data);

	/* Return the ldns_rdf. */
	return rdf;
}

static void
query_dtwhoami(evldns_server_request *q,
	       void *user_data,
	       ldns_rdf *qname,
	       ldns_rr_type qtype,
	       ldns_rr_class qclass)
{
	log_query(q, qname, qtype, qclass, "Answering query", stderr);

	/* Initialize the response from the request. */
	q->response = evldns_response(q->request, LDNS_RCODE_NOERROR);

	/* Allocate an rr list for the answer. */
	ldns_rr_list *answer = ldns_rr_list_new();

	/* Generate an rdf based on the qtype. */
	ldns_rdf *rdf = NULL;
	if (qtype == LDNS_RR_TYPE_A) {
		rdf = get_rdf_a(q);
	} else if (qtype == LDNS_RR_TYPE_AAAA) {
		rdf = get_rdf_aaaa(q);
	} else if (qtype == LDNS_RR_TYPE_NULL) {
		rdf = get_rdf_null(q);
	}

	/* If it was a supported qtype, attach the rdf to an rr. */
	if (rdf) {
		ldns_rr *rr = ldns_rr_new();

		ldns_rdf *owner = ldns_dname_clone_from(qname, 0);
		ldns_rr_set_owner(rr, owner);

		ldns_rr_set_ttl(rr, 0);
		ldns_rr_set_class(rr, LDNS_RR_CLASS_IN);
		ldns_rr_set_type(rr, qtype);

		ldns_rr_push_rdf(rr, rdf);

		/* And attach the rr to the rr list for the answer. */
		ldns_rr_list_push_rr(answer, rr);
	}

	/* Put the answer rr list into the answer section of the response. */
	ldns_pkt_push_rr_list(q->response, LDNS_SECTION_ANSWER, answer);

	/* Cleanup. */
	ldns_rr_list_free(answer);
}

static void
query_drop(evldns_server_request *q,
	   void *user_data,
	   ldns_rdf *qname,
	   ldns_rr_type qtype,
	   ldns_rr_class qclass)
{
	log_query(q, qname, qtype, qclass, "Dropping query", stderr);
	q->blackhole = 1;
}

static void
usage(void)
{
	fprintf(stderr, "Usage: dtwhoami <ARG>...\n\n");
	fprintf(stderr, "Required arguments:\n");
	fprintf(stderr, "  -4 <IPV4-ADDRESS> or -6 <IPV6-ADDRESS>\n");
	fprintf(stderr, "  -p <PORT-NUMBER>\n");
	fprintf(stderr, "  -a <APEX-NAME>\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "Optional arguments:\n");
	fprintf(stderr, "  -t\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "dtwhoami will listen on IPV4-ADDRESS or IPV6-ADDRESS on port PORT-NUMBER.\n");
	fprintf(stderr, "It will serve UDP queries matching the APEX-NAMEs.\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "The -a parameter may be specified multiple times.\n");
	fprintf(stderr, "If -t is specified, also serve TCP queries.\n");
	fprintf(stderr, "\n");
	exit(EXIT_FAILURE);
}

static void
add_callback_domain(struct evldns_server *server, const char *base_domain_name)
{
	size_t len = 2 /* "*." */ + strlen(base_domain_name) + 1 /* \0 */;
	char domain_name[len];

	/* Construct asterisk-label prefixed version of the domain name. */
	domain_name[0] = '*';
	domain_name[1] = '.';
	strcpy(&domain_name[2], base_domain_name);

	fprintf(stderr, "dtwhoami: Registering handlers for \"%s\" queries.\n",
		domain_name);

	/**
	 * Add whoami query handler for asterisk-label prefixed version of the
	 * domain name.
	 */
	evldns_add_callback(server,
			    domain_name,
			    LDNS_RR_CLASS_IN,
			    LDNS_RR_TYPE_ANY,
			    query_dtwhoami,
			    NULL);

	/**
	 * Add whoami query handler for the apex name.
	 */
	evldns_add_callback(server,
			    base_domain_name,
			    LDNS_RR_CLASS_IN,
			    LDNS_RR_TYPE_ANY,
			    query_dtwhoami,
			    NULL);
}

int main(int argc, char **argv)
{
	int c;
	int socket;
	const char *ip_address = NULL;
	const char *ip4_address = NULL;
	const char *ip6_address = NULL;
	const char *port_number = NULL;
	bool domain_name = false;
	bool want_tcp = false;

	struct event_base *base = event_base_new();
	struct evldns_server *server = evldns_add_server(base);

	/* Args. */
	while ((c = getopt(argc, argv, "4:6:p:a:t")) != -1) {
		switch (c) {
		case '4':
			ip_address = optarg;
			ip4_address = optarg;
			break;
		case '6':
			ip_address = optarg;
			ip6_address = optarg;
			break;
		case 'p':
			port_number = optarg;
			break;
		case 'a':
			add_callback_domain(server, optarg);
			domain_name = true;
			break;
		case 't':
			want_tcp = true;
			break;
		default:
			usage();
		}
	}

	/* Validate args. */
	if ((!ip4_address && !ip6_address)	||
	    (ip4_address && ip6_address)	||
	    (!port_number)			||
	    (!domain_name))
		usage();

	/* Setup UDP socket. */
	socket = bind_to_udp_address(ip_address, port_number);
	if (socket < 0) {
		fprintf(stderr, "dtwhoami: bind_to_udp_address() failed\n");
		return EXIT_FAILURE;
	}
	evldns_add_server_port(server, socket);

	/* Setup TCP socket. */
	if (want_tcp) {
		socket = bind_to_tcp_address(ip_address, port_number, 10 /* backlog */);
		if (socket < 0) {
			fprintf(stderr, "dtwhoami: bind_to_tcp_address() failed\n");
			return EXIT_FAILURE;
		}
		evldns_add_server_port(server, socket);
	}

	fprintf(stderr, "dtwhoami: Listening for queries on [%s]:%s.\n",
		ip_address, port_number);

	/**
	 * Add a fallback handler that drops queries that don't match our
	 * configured domain names.
	 */
	evldns_add_callback(server, "*", LDNS_RR_CLASS_ANY, LDNS_RR_TYPE_ANY, query_drop, NULL);

	/* Run the event loop. */
	event_base_dispatch(base);

	return EXIT_SUCCESS;
}
