/* $Id$ */
/* Copyright (c) 2014 Pierre Pronchery <khorben@defora.org> */
/* This file is part of DeforaOS Network Transport */
/* This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>. */
/* FIXME:
 * - check for SSL errors
 * - check for event registration errors */



#include <sys/socket.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#ifdef DEBUG
# include <stdio.h>
#endif
#include <string.h>
#include <limits.h>
#include <errno.h>
#ifdef __WIN32__
# include <Winsock2.h>
#else
# include <netinet/in.h>
# include <arpa/inet.h>
# include <netdb.h>
#endif
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <System.h>
#include <System/App/appmessage.h>
#include <System/App/apptransport.h>

/* portability */
#ifdef __WIN32__
# define close(fd) closesocket(fd)
#endif

/* for ssl4 and ssl6 */
#ifndef TCP_FAMILY
# define TCP_FAMILY AF_UNSPEC
#endif


/* SSLTransport */
/* private */
/* types */
typedef struct _AppTransportPlugin SSLTransport;

typedef struct _SSLSocket
{
	SSLTransport * transport;
	AppTransportClient * client;

	int fd;
	SSL * ssl;
	struct sockaddr * sa;
	socklen_t sa_len;

	/* input queue */
	char * bufin;
	size_t bufin_cnt;
	/* output queue */
	char * bufout;
	size_t bufout_cnt;
} SSLSocket;

struct _AppTransportPlugin
{
	AppTransportMode mode;
	AppTransportPluginHelper * helper;

	SSL_CTX * ssl_ctx;

	struct addrinfo * ai;
	socklen_t ai_addrlen;

	union
	{
		struct
		{
			/* for servers */
			int fd;
			SSLSocket ** clients;
			size_t clients_cnt;
		} server;

		/* for clients */
		SSLSocket client;
	} u;
};


/* constants */
#define INC 1024

#include "common.h"
#include "common.c"


/* protected */
/* prototypes */
/* plug-in */
static SSLTransport * _ssl_init(AppTransportPluginHelper * helper,
		AppTransportMode mode, char const * name);
static void _ssl_destroy(SSLTransport * ssl);

static int _ssl_client_send(SSLTransport * ssl, AppTransportClient * client,
		AppMessage * message);
static int _ssl_send(SSLTransport * ssl, AppMessage * message);

/* useful */
static int _ssl_error(char const * message, int code);

/* servers */
static int _ssl_server_add_client(SSLTransport * ssl, SSLSocket * client);

/* sockets */
static int _ssl_socket_init(SSLSocket * sslsocket, int domain,
		SSLTransport * transport);
static void _ssl_socket_init_fd(SSLSocket * sslsocket, SSLTransport * transport,
		int fd, SSL * ssl, struct sockaddr * sa, socklen_t sa_len);
static SSLSocket * _ssl_socket_new_fd(SSLTransport * transport, int fd,
		SSL * ssl, struct sockaddr * sa, socklen_t sa_len);
static void _ssl_socket_delete(SSLSocket * sslsocket);
static void _ssl_socket_destroy(SSLSocket * sslsocket);

static int _ssl_socket_queue(SSLSocket * sslsocket, Buffer * buffer);

/* callbacks */
static int _ssl_callback_accept(int fd, SSLTransport * transport);
static int _ssl_callback_connect(int fd, SSLTransport * transport);
static int _ssl_socket_callback_read(int fd, SSLSocket * sslsocket);
static int _ssl_socket_callback_write(int fd, SSLSocket * sslsocket);


/* public */
/* constants */
/* plug-in */
AppTransportPluginDefinition transport =
{
	"SSLTransport",
	NULL,
	_ssl_init,
	_ssl_destroy,
	_ssl_send,
	_ssl_client_send
};


/* protected */
/* functions */
/* plug-in */
/* ssl_init */
static int _init_client(SSLTransport * ssl, char const * name);
static int _init_server(SSLTransport * ssl, char const * name);

static SSLTransport * _ssl_init(AppTransportPluginHelper * helper,
		AppTransportMode mode, char const * name)
{
	SSLTransport * ssl;
	int res;

#ifdef DEBUG
	fprintf(stderr, "DEBUG: %s(%u, \"%s\")\n", __func__, mode, name);
#endif
	if((ssl = object_new(sizeof(*ssl))) == NULL)
		return NULL;
	memset(ssl, 0, sizeof(*ssl));
	ssl->helper = helper;
	if((ssl->ssl_ctx = SSL_CTX_new(TLSv1_method())) == NULL
			|| SSL_CTX_set_cipher_list(ssl->ssl_ctx,
				SSL_DEFAULT_CIPHER_LIST) != 1
			|| SSL_CTX_load_verify_locations(ssl->ssl_ctx, NULL,
				"/etc/openssl/certs") != 1)
		/* FIXME report the underlying error */
		res = -error_set_code(1, "Could not initialize SSL");
	else
		switch((ssl->mode = mode))
		{
			case ATM_CLIENT:
				res = _init_client(ssl, name);
				break;
			case ATM_SERVER:
				res = _init_server(ssl, name);
				break;
			default:
				res = -error_set_code(1,
						"Unknown transport mode");
				break;
		}
	/* check for errors */
	if(res != 0)
	{
#ifdef DEBUG
		fprintf(stderr, "DEBUG: %s() => %d (%s)\n", __func__, res,
				error_get(NULL));
#endif
		_ssl_destroy(ssl);
		return NULL;
	}
#if 0 /* XXX may be useful */
	SSL_CTX_set_mode(ssl->ssl_ctx, SSL_MODE_ENABLE_PARTIAL_WRITE);
#endif
	return ssl;
}

static int _init_client(SSLTransport * ssl, char const * name)
{
	struct addrinfo * aip;
#ifdef DEBUG
	struct sockaddr_in * sa;
#endif

	ssl->u.client.transport = ssl;
	ssl->u.client.fd = -1;
	/* obtain the remote address */
	if((ssl->ai = _init_address(name, TCP_FAMILY, 0)) == NULL)
		return -1;
	/* connect to the remote host */
	for(aip = ssl->ai; aip != NULL; aip = aip->ai_next)
	{
		ssl->u.client.fd = -1;
		/* initialize the client socket */
		if(_ssl_socket_init(&ssl->u.client, aip->ai_family, ssl) != 0)
			continue;
#ifdef DEBUG
		if(aip->ai_family == AF_INET)
		{
			sa = (struct sockaddr_in *)aip->ai_addr;
			fprintf(stderr, "DEBUG: %s() %s (%s:%u)\n", __func__,
					"connect()", inet_ntoa(sa->sin_addr),
					ntohs(sa->sin_port));
		}
		else
			fprintf(stderr, "DEBUG: %s() %s %d\n", __func__,
					"connect()", aip->ai_family);
#endif
		if(connect(ssl->u.client.fd, aip->ai_addr, aip->ai_addrlen)
				!= 0)
		{
			if(errno != EINPROGRESS)
			{
				close(ssl->u.client.fd);
				ssl->u.client.fd = -1;
				_ssl_error("socket", 1);
				continue;
			}
			event_register_io_write(ssl->helper->event,
					ssl->u.client.fd,
					(EventIOFunc)_ssl_callback_connect,
					ssl);
		}
		else
			/* listen for any incoming message */
			event_register_io_read(ssl->helper->event,
					ssl->u.client.fd,
					(EventIOFunc)_ssl_socket_callback_read,
					&ssl->u.client);
		ssl->ai_addrlen = aip->ai_addrlen;
		break;
	}
	freeaddrinfo(ssl->ai);
	ssl->ai = NULL;
	return (aip != NULL) ? 0 : -1;
}

static int _init_server(SSLTransport * ssl, char const * name)
{
	struct addrinfo * aip;
	SSLSocket sslsocket;
#ifdef DEBUG
	struct sockaddr_in * sa;
#endif

	ssl->u.server.fd = -1;
	/* obtain the local address */
	if((ssl->ai = _init_address(name, TCP_FAMILY, AI_PASSIVE)) == NULL)
		return -1;
	for(aip = ssl->ai; aip != NULL; aip = aip->ai_next)
	{
		/* create the socket */
		if(_ssl_socket_init(&sslsocket, aip->ai_family, ssl) != 0)
			continue;
		/* XXX ugly */
		ssl->u.server.fd = sslsocket.fd;
		/* accept incoming connections */
#ifdef DEBUG
		if(aip->ai_family == AF_INET)
		{
			sa = (struct sockaddr_in *)aip->ai_addr;
			fprintf(stderr, "DEBUG: %s() %s (%s:%u)\n", __func__,
					"bind()", inet_ntoa(sa->sin_addr),
					ntohs(sa->sin_port));
		}
		else
			fprintf(stderr, "DEBUG: %s() %s %d\n", __func__,
					"bind()", aip->ai_family);
#endif
		if(bind(ssl->u.server.fd, aip->ai_addr, aip->ai_addrlen) != 0)
		{
			_ssl_error("bind", 1);
			close(ssl->u.server.fd);
			ssl->u.server.fd = -1;
			continue;
		}
#ifdef DEBUG
		fprintf(stderr, "DEBUG: %s() %s\n", __func__, "listen()");
#endif
		if(listen(ssl->u.server.fd, SOMAXCONN) != 0)
		{
			_ssl_error("listen", 1);
			close(ssl->u.server.fd);
			ssl->u.server.fd = -1;
			continue;
		}
		ssl->ai_addrlen = aip->ai_addrlen;
		event_register_io_read(ssl->helper->event, ssl->u.server.fd,
				(EventIOFunc)_ssl_callback_accept, ssl);
		break;
	}
	freeaddrinfo(ssl->ai);
	ssl->ai = NULL;
	return (aip != NULL) ? 0 : -1;
}


/* ssl_destroy */
static void _destroy_client(SSLTransport * ssl);
static void _destroy_server(SSLTransport * ssl);

static void _ssl_destroy(SSLTransport * ssl)
{
#ifdef DEBUG
	fprintf(stderr, "DEBUG: %s()\n", __func__);
#endif
	switch(ssl->mode)
	{
		case ATM_CLIENT:
			_destroy_client(ssl);
			break;
		case ATM_SERVER:
			_destroy_server(ssl);
			break;
	}
	if(ssl->ai != NULL)
		freeaddrinfo(ssl->ai);
	if(ssl->ssl_ctx != NULL)
		SSL_CTX_free(ssl->ssl_ctx);
	object_delete(ssl);
}

static void _destroy_client(SSLTransport * ssl)
{
	_ssl_socket_destroy(&ssl->u.client);
}

static void _destroy_server(SSLTransport * ssl)
{
	size_t i;

	for(i = 0; i < ssl->u.server.clients_cnt; i++)
		_ssl_socket_delete(ssl->u.server.clients[i]);
	free(ssl->u.server.clients);
	if(ssl->u.server.fd >= 0)
		close(ssl->u.server.fd);
}


/* ssl_client_send */
static int _ssl_client_send(SSLTransport * ssl, AppTransportClient * client,
		AppMessage * message)
{
	size_t i;
	SSLSocket * s;
	Buffer * buffer;

	if(ssl->mode != ATM_SERVER)
		return -error_set_code(1, "%s", "Not a server");
	/* lookup the client */
	for(i = 0; i < ssl->u.server.clients_cnt; i++)
	{
		s = ssl->u.server.clients[i];
		if(s->client == client)
			break;
	}
	if(i == ssl->u.server.clients_cnt)
		return -error_set_code(1, "%s", "Unknown client");
	/* send the message */
	if((buffer = buffer_new(0, NULL)) == NULL)
		return -1;
	if(appmessage_serialize(message, buffer) != 0
			|| _ssl_socket_queue(s, buffer) != 0)
	{
		buffer_delete(buffer);
		return -1;
	}
	return 0;
}


/* ssl_send */
static int _ssl_send(SSLTransport * ssl, AppMessage * message)
{
	Buffer * buffer;

	if(ssl->mode != ATM_CLIENT)
		return -error_set_code(1, "%s", "Not a client");
	/* send the message */
	if((buffer = buffer_new(0, NULL)) == NULL)
		return -1;
	if(appmessage_serialize(message, buffer) != 0
			|| _ssl_socket_queue(&ssl->u.client, buffer) != 0)
	{
		buffer_delete(buffer);
		return -1;
	}
	buffer_delete(buffer);
	return 0;
}


/* useful */
/* ssl_error */
static int _ssl_error(char const * message, int code)
{
#ifdef DEBUG
	fprintf(stderr, "DEBUG: %s(\"%s\", %d)\n", __func__, message, code);
#endif
	return error_set_code(code, "%s%s%s", (message != NULL) ? message : "",
			(message != NULL) ? ": " : "", strerror(errno));
}


/* servers */
/* ssl_server_add_client */
static int _ssl_server_add_client(SSLTransport * ssl, SSLSocket * client)
{
	SSLSocket ** p;
#ifndef NI_MAXHOST
# define NI_MAXHOST 256
#endif
	char host[NI_MAXHOST];
	char const * name = host;
	const int flags = NI_NUMERICSERV;

	if((p = realloc(ssl->u.server.clients, sizeof(*p)
					* (ssl->u.server.clients_cnt + 1)))
			== NULL)
		return -1;
	ssl->u.server.clients = p;
	/* XXX may not be instant */
	if(getnameinfo(client->sa, client->sa_len, host, sizeof(host), NULL, 0,
				NI_NAMEREQD | flags) != 0
			&& getnameinfo(client->sa, client->sa_len, host,
				sizeof(host), NULL, 0, NI_NUMERICHOST | flags)
			!= 0)
		name = NULL;
	if((client->client = ssl->helper->client_new(ssl->helper->transport,
					name)) == NULL)
		return -1;
	ssl->u.server.clients[ssl->u.server.clients_cnt++] = client;
	return 0;
}


/* sockets */
/* ssl_socket_init */
static int _ssl_socket_init(SSLSocket * sslsocket, int domain,
		SSLTransport * transport)
{
	SSL * ssl;
	int fd = -1;
	int flags;

	if((ssl = SSL_new(transport->ssl_ctx)) == NULL)
		/* FIXME report the error */
		return -1;
	if((fd = socket(domain, SOCK_STREAM, 0)) < 0)
	{
		SSL_free(ssl);
		return -_ssl_error("socket", 1);
	}
	_ssl_socket_init_fd(sslsocket, transport, fd, ssl, NULL, 0);
	/* set the socket as non-blocking */
	if((flags = fcntl(fd, F_GETFL)) == -1)
		return -_ssl_error("fcntl", 1);
	if((flags & O_NONBLOCK) == 0)
		if(fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1)
			return -_ssl_error("fcntl", 1);
#ifdef TCP_NODELAY
	/* do not wait before sending any traffic */
	flags = 1;
	setsockopt(fd, SOL_SOCKET, TCP_NODELAY, &flags, sizeof(flags));
#endif
	if(SSL_set_fd(ssl, fd) != 0)
		/* FIXME report the error */
		return -1;
	return 0;
}


/* ssl_socket_init_fd */
static void _ssl_socket_init_fd(SSLSocket * sslsocket, SSLTransport * transport,
		int fd, SSL * ssl, struct sockaddr * sa, socklen_t sa_len)
{
	sslsocket->transport = transport;
	sslsocket->client = NULL;
	sslsocket->fd = fd;
	sslsocket->ssl = ssl;
	sslsocket->sa = sa;
	sslsocket->sa_len = sa_len;
	sslsocket->bufin = NULL;
	sslsocket->bufin_cnt = 0;
	sslsocket->bufout = NULL;
	sslsocket->bufout_cnt = 0;
}


/* ssl_socket_new_fd */
static SSLSocket * _ssl_socket_new_fd(SSLTransport * transport, int fd,
		SSL * ssl, struct sockaddr * sa, socklen_t sa_len)
{
	SSLSocket * sslsocket;

	if((sslsocket = object_new(sizeof(*sslsocket))) == NULL)
		return NULL;
	_ssl_socket_init_fd(sslsocket, transport, fd, ssl, sa, sa_len);
	return sslsocket;
}


/* ssl_socket_delete */
static void _ssl_socket_delete(SSLSocket * sslsocket)
{
	_ssl_socket_destroy(sslsocket);
	object_delete(sslsocket);
}


/* ssl_socket_destroy */
static void _ssl_socket_destroy(SSLSocket * sslsocket)
{
	SSLTransport * transport = sslsocket->transport;
	AppTransportPluginHelper * helper = transport->helper;

	helper->client_delete(helper->transport, sslsocket->client);
	free(sslsocket->sa);
	if(sslsocket->fd >= 0)
	{
		event_unregister_io_read(sslsocket->transport->helper->event,
				sslsocket->fd);
		event_unregister_io_write(sslsocket->transport->helper->event,
				sslsocket->fd);
		close(sslsocket->fd);
	}
	free(sslsocket->bufin);
	free(sslsocket->bufout);
}


/* ssl_socket_queue */
static int _ssl_socket_queue(SSLSocket * sslsocket, Buffer * buffer)
{
	uint32_t len;
	char * p;
	Variable * v;
	Buffer * b = NULL;

#ifdef DEBUG
	fprintf(stderr, "DEBUG: %s(%d)\n", __func__, sslsocket->fd);
#endif
	/* serialize the buffer */
	v = variable_new(VT_BUFFER, buffer);
	b = buffer_new(0, NULL);
	if(v == NULL || b == NULL || variable_serialize(v, b, 0) != 0)
	{
		if(v != NULL)
			variable_delete(v);
		if(b != NULL)
			buffer_delete(b);
		return -1;
	}
	variable_delete(v);
	len = buffer_get_size(b);
	/* FIXME queue the serialized buffer directly as a message instead */
	if((p = realloc(sslsocket->bufout, sslsocket->bufout_cnt + len))
			== NULL)
	{
		buffer_delete(b);
		return -1;
	}
	sslsocket->bufout = p;
	memcpy(&p[sslsocket->bufout_cnt], buffer_get_data(b), len);
	/* register the callback if necessary */
	if(sslsocket->bufout_cnt == 0)
		event_register_io_write(sslsocket->transport->helper->event,
				sslsocket->fd,
				(EventIOFunc)_ssl_socket_callback_write,
				sslsocket);
	sslsocket->bufout_cnt += len;
	buffer_delete(b);
#ifdef DEBUG
	fprintf(stderr, "DEBUG: %s(%d) => %d\n", __func__, sslsocket->fd, 0);
#endif
	return 0;
}


/* callbacks */
/* ssl_callback_accept */
static int _accept_client(SSLTransport * transport, int fd, SSL * ssl,
		struct sockaddr * sa, socklen_t sa_len);

static int _ssl_callback_accept(int fd, SSLTransport * transport)
{
	struct sockaddr * sa;
	socklen_t sa_len = transport->ai_addrlen;
	SSL * ssl;

#ifdef DEBUG
	fprintf(stderr, "DEBUG: %s(%d)\n", __func__, fd);
#endif
	/* check parameters */
	if(transport->u.server.fd != fd)
		return -1;
	if((sa = malloc(sa_len)) == NULL)
		/* XXX this may not be enough to recover */
		sa_len = 0;
	if((fd = accept(fd, sa, &sa_len)) < 0
			|| (ssl = SSL_new(transport->ssl_ctx)) == NULL)
	{
		free(sa);
		return _ssl_error("accept", 1);
	}
	if(_accept_client(transport, fd, ssl, sa, sa_len) != 0)
	{
		/* just close the connection and keep serving */
		/* FIXME report error */
		SSL_free(ssl);
		close(fd);
		free(sa);
	}
#ifdef DEBUG
	else
		fprintf(stderr, "DEBUG: %s() %d\n", __func__, fd);
#endif
	return 0;
}

static int _accept_client(SSLTransport * transport, int fd, SSL * ssl,
		struct sockaddr * sa, socklen_t sa_len)
{
	SSLSocket * sslsocket;

#ifdef DEBUG
	fprintf(stderr, "DEBUG: %s(%d)\n", __func__, fd);
#endif
	if((sslsocket = _ssl_socket_new_fd(transport, fd, ssl, sa, sa_len))
			== NULL)
		return -1;
	if(_ssl_server_add_client(transport, sslsocket) != 0)
	{
		/* XXX workaround for a double-close() */
		sslsocket->fd = -1;
		_ssl_socket_delete(sslsocket);
		return -1;
	}
	SSL_set_accept_state(sslsocket->ssl);
	event_register_io_read(transport->helper->event, sslsocket->fd,
			(EventIOFunc)_ssl_socket_callback_read, sslsocket);
#ifdef DEBUG
	fprintf(stderr, "DEBUG: %s(%d) => 0\n", __func__, fd);
#endif
	return 0;
}


/* ssl_callback_connect */
static int _ssl_callback_connect(int fd, SSLTransport * transport)
{
	int res;
	socklen_t s = sizeof(res);

#ifdef DEBUG
	fprintf(stderr, "DEBUG: %s(%d)\n", __func__, fd);
#endif
	/* check parameters */
	if(transport->u.client.fd != fd)
		return -1;
	/* obtain the connection status */
	if(getsockopt(fd, SOL_SOCKET, SO_ERROR, &res, &s) != 0)
	{
		error_set_code(1, "%s: %s", "getsockopt", strerror(errno));
		SSL_free(transport->u.client.ssl);
		transport->u.client.ssl = NULL;
		close(fd);
		transport->u.client.fd = -1;
		/* FIXME report error */
#ifdef DEBUG
		fprintf(stderr, "DEBUG: %s() %s\n", __func__, strerror(errno));
#endif
		return -1;
	}
	if(res != 0)
	{
		/* the connection failed */
		error_set_code(1, "%s: %s", "connect", strerror(res));
		SSL_free(transport->u.client.ssl);
		transport->u.client.ssl = NULL;
		close(fd);
		transport->u.client.fd = -1;
		/* FIXME report error */
#ifdef DEBUG
		fprintf(stderr, "DEBUG: %s() %s\n", __func__, strerror(res));
#endif
		return -1;
	}
	SSL_set_connect_state(transport->u.client.ssl);
	/* listen for any incoming message */
	event_register_io_read(transport->helper->event, fd,
			(EventIOFunc)_ssl_socket_callback_read,
			&transport->u.client);
	/* write pending messages if any */
	if(transport->u.client.bufout_cnt > 0)
	{
		event_register_io_write(transport->helper->event, fd,
				(EventIOFunc)_ssl_socket_callback_write,
				&transport->u.client);
		return 0;
	}
	return 1;
}


/* ssl_socket_callback_read */
static AppMessage * _socket_callback_message(SSLSocket * sslsocket);
static void _socket_callback_read_client(SSLSocket * sslsocket,
		AppMessage * message);
static void _socket_callback_read_server(SSLSocket * sslsocket,
		AppMessage * message);
static int _socket_callback_recv(SSLSocket * sslsocket);

static int _ssl_socket_callback_read(int fd, SSLSocket * sslsocket)
{
	AppMessage * message;

#ifdef DEBUG
	fprintf(stderr, "DEBUG: %s(%d)\n", __func__, fd);
#endif
	/* check parameters */
	if(sslsocket->fd != fd)
		return -1;
	if(_socket_callback_recv(sslsocket) != 0)
		return -1;
	while((message = _socket_callback_message(sslsocket)) != NULL)
	{
		switch(sslsocket->transport->mode)
		{
			case ATM_CLIENT:
				_socket_callback_read_client(sslsocket,
						message);
				break;
			case ATM_SERVER:
				_socket_callback_read_server(sslsocket,
						message);
				break;
		}
		appmessage_delete(message);
	}
	return 0;
}

static AppMessage * _socket_callback_message(SSLSocket * sslsocket)
{
	AppMessage * message = NULL;
	size_t size;
	Variable * variable;
	Buffer * buffer;

	size = sslsocket->bufin_cnt;
	/* deserialize the data as a buffer (containing a message) */
	if((variable = variable_new_deserialize_type(VT_BUFFER, &size,
					sslsocket->bufin)) == NULL)
		/* XXX assumes not enough data was available */
		return NULL;
	sslsocket->bufin_cnt -= size;
	memmove(sslsocket->bufin, &sslsocket->bufin[size],
			sslsocket->bufin_cnt);
	if((variable_get_as(variable, VT_BUFFER, &buffer)) == 0)
	{
		message = appmessage_new_deserialize(buffer);
		buffer_delete(buffer);
	}
	variable_delete(variable);
	return message;
}

static void _socket_callback_read_client(SSLSocket * sslsocket,
		AppMessage * message)
{
	AppTransportPluginHelper * helper = sslsocket->transport->helper;

	helper->receive(helper->transport, message);
}

static void _socket_callback_read_server(SSLSocket * sslsocket,
		AppMessage * message)
{
	AppTransportPluginHelper * helper = sslsocket->transport->helper;

	helper->client_receive(helper->transport, sslsocket->client,
			message);
}

static int _socket_callback_recv(SSLSocket * sslsocket)
{
	const size_t inc = INC;
	int ssize;
	char * p;
	int err;
	char buf[128];

	if((p = realloc(sslsocket->bufin, sslsocket->bufin_cnt + inc)) == NULL)
		return -1;
	sslsocket->bufin = p;
	if((ssize = SSL_read(sslsocket->ssl,
					&sslsocket->bufin[sslsocket->bufin_cnt],
					inc)) <= 0)
	{
		/* FIXME not tested */
		if((err = SSL_get_error(sslsocket->ssl, ssize))
				== SSL_ERROR_WANT_WRITE)
		{
			event_unregister_io_write(
					sslsocket->transport->helper->event,
					sslsocket->fd);
			event_register_io_write(
					sslsocket->transport->helper->event,
					sslsocket->fd,
					(EventIOFunc)_ssl_socket_callback_read,
					sslsocket);
			return 1;
		}
		else if(err == SSL_ERROR_WANT_READ)
		{
			event_register_io_read(
					sslsocket->transport->helper->event,
					sslsocket->fd,
					(EventIOFunc)_ssl_socket_callback_read,
					sslsocket);
			return 1;
		}
		else
		{
			/* XXX report error (and reconnect clients) */
			ERR_error_string(err, buf);
			error_set_code(1, "%s", buf);
			SSL_free(sslsocket->ssl);
			sslsocket->ssl = NULL;
			close(sslsocket->fd);
			sslsocket->fd = -1;
			return -1;
		}
	}
	sslsocket->bufin_cnt += ssize;
	return 0;
}


/* ssl_socket_callback_write */
static int _ssl_socket_callback_write(int fd, SSLSocket * sslsocket)
{
	int ssize;
	int err;
	char buf[128];

#ifdef DEBUG
	fprintf(stderr, "DEBUG: %s(%d)\n", __func__, fd);
#endif
	/* check parameters */
	if(sslsocket->fd != fd)
		return -1;
	if((ssize = SSL_write(sslsocket->ssl, sslsocket->bufout,
					sslsocket->bufout_cnt)) <= 0)
	{
		/* FIXME not tested */
		if((err = SSL_get_error(sslsocket->ssl, ssize))
				== SSL_ERROR_WANT_READ)
		{
			event_unregister_io_read(
					sslsocket->transport->helper->event,
					sslsocket->fd);
			event_register_io_write(
					sslsocket->transport->helper->event,
					sslsocket->fd,
					(EventIOFunc)_ssl_socket_callback_write,
					sslsocket);
			return 1;
		}
		else if(err == SSL_ERROR_WANT_WRITE)
		{
			event_register_io_write(
					sslsocket->transport->helper->event,
					sslsocket->fd,
					(EventIOFunc)_ssl_socket_callback_write,
					sslsocket);
			return 1;
		}
		else
		{
			/* XXX report error (and reconnect clients) */
			ERR_error_string(err, buf);
			error_set_code(1, "%s", buf);
			SSL_free(sslsocket->ssl);
			sslsocket->ssl = NULL;
			close(sslsocket->fd);
			sslsocket->fd = -1;
			return -1;
		}
	}
#ifdef DEBUG
	fprintf(stderr, "DEBUG: %s() send() => %ld\n", __func__, ssize);
#endif
	/* XXX use a sliding cursor instead (and then queue the next message) */
	memmove(sslsocket->bufout, &sslsocket->bufout[ssize],
			sslsocket->bufout_cnt - ssize);
	sslsocket->bufout_cnt -= ssize;
	/* unregister the callback if there is nothing left to write */
	if(sslsocket->bufout_cnt == 0)
		return 1;
	return 0;
}
