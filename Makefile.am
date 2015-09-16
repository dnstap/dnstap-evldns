ACLOCAL_AMFLAGS	= -I m4

AM_CFLAGS = \
	${libevent_CFLAGS} \
	${libldns_CFLAGS}

include_HEADERS = evldns.h

bin_PROGRAMS	= chaos as112d oas112d fixed

chaos_SOURCES	= chaos.c
chaos_LDADD     = libevldns.la ${libldns_LIBS} ${libevent_LIBS}

as112d_SOURCES	= as112d.c
as112d_LDADD    = libevldns.la ${libldns_LIBS} ${libevent_LIBS}

oas112d_SOURCES	= oas112d.c
oas112d_LDADD   = libevldns.la ${libldns_LIBS} ${libevent_LIBS}

fixed_SOURCES	= fixed.c
fixed_LDADD     = libevldns.la ${libldns_LIBS} ${libevent_LIBS}

lib_LTLIBRARIES	= libevldns.la mod_mangler.la mod_txtrec.la mod_arec.la mod_myip.la

libevldns_la_SOURCES	= evldns.c plugin.c function.c network.c

MODULE_LIBTOOL_FLAGS = -module -avoid-version -shared

mod_mangler_la_LDFLAGS = $(MODULE_LIBTOOL_FLAGS)
mod_txtrec_la_LDFLAGS = $(MODULE_LIBTOOL_FLAGS)
mod_arec_la_LDFLAGS = $(MODULE_LIBTOOL_FLAGS)
mod_myip_la_LDFLAGS = $(MODULE_LIBTOOL_FLAGS)
