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



/* init_address */
static struct addrinfo * _init_address(char const * name, int domain, int flags)
{
	struct addrinfo * ai = NULL;
	char * hostname;
	char * servname;
	char sep = ':';
	char * p;
	char * q;
	long l;
	struct addrinfo hints;
	int res = 0;

#ifdef DEBUG
	fprintf(stderr, "DEBUG: %s(\"%s\", %d, %d)\n", __func__, name, domain,
			flags);
#endif
	/* check the arguments */
	if(name == NULL || strlen(name) == 0)
	{
		error_set_code(1, "%s", "Empty names are not allowed");
		return NULL;
	}
	/* guess the port separator */
	if((p = strchr(name, ':')) != NULL && strchr(++p, ':') != NULL)
		sep = '.';
	/* obtain the name */
	if((p = strdup(name)) == NULL)
	{
		error_set_code(1, "%s", strerror(errno));
		return NULL;
	}
	hostname = p;
	/* obtain the port number */
	if((servname = strrchr(hostname, sep)) == NULL || servname[1] == '\0')
	{
		l = 0;
		servname = NULL;
	}
	else
	{
		*(servname++) = '\0';
		if(hostname[0] == '\0')
			hostname = NULL;
		l = strtol(servname, &q, 10);
		if(servname[0] == '\0' || *q != '\0')
			l = -error_set_code(1, "%s", strerror(EINVAL));
	}
	/* FIXME perform this asynchronously */
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = domain;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = flags;
#ifdef DEBUG
	fprintf(stderr, "DEBUG: %s() %ld \"%s\" \"%s\" %u\n", __func__, l,
			hostname, servname, flags);
#endif
	if(l >= 0)
		res = getaddrinfo(hostname, servname, &hints, &ai);
	free(p);
	/* check for errors */
	if(res != 0)
	{
		error_set_code(1, "%s", gai_strerror(res));
		if(ai != NULL)
			freeaddrinfo(ai);
		return NULL;
	}
	return ai;
}
