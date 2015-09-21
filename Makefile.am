ACLOCAL_AMFLAGS	= -I m4
BUILT_SOURCES =
CLEANFILES =
EXTRA_DIST =

AM_CFLAGS = \
	${libevent_CFLAGS} \
	${libldns_CFLAGS}

SUFFIXES = .proto .pb-c.c .pb-c.h

.proto.pb-c.c:
	$(AM_V_GEN)@PROTOC_C@ "--c_out=`pwd`" -I$(top_srcdir) $<

.proto.pb-c.h:
	$(AM_V_GEN)@PROTOC_C@ "--c_out=`pwd`" -I$(top_srcdir) $<

EXTRA_DIST += dnstap.proto
PROTOBUF_SOURCES = dnstap.pb-c.c dnstap.pb-c.h
BUILT_SOURCES += ${PROTOBUF_SOURCES}
CLEANFILES += ${PROTOBUF_SOURCES}

noinst_HEADERS = evldns.h

bin_PROGRAMS	= chaos as112d oas112d fixed dtwhoami

chaos_SOURCES	= chaos.c
chaos_LDADD     = libevldns.la

as112d_SOURCES	= as112d.c
as112d_LDADD    = libevldns.la

oas112d_SOURCES	= oas112d.c
oas112d_LDADD   = libevldns.la

fixed_SOURCES	= fixed.c
fixed_LDADD     = libevldns.la

dtwhoami_SOURCES = dtwhoami.c
nodist_dtwhoami_SOURCES = ${PROTOBUF_SOURCES}
dtwhoami_LDADD   = libevldns.la ${libprotobuf_c_LIBS}

noinst_LTLIBRARIES = libevldns.la
libevldns_la_SOURCES = evldns.c plugin.c function.c network.c
libevldns_la_LIBADD = ${libldns_LIBS} ${libevent_LIBS}

lib_LTLIBRARIES	= mod_mangler.la mod_txtrec.la mod_arec.la mod_myip.la

MODULE_LIBTOOL_FLAGS = -module -avoid-version -shared
mod_mangler_la_LDFLAGS = $(MODULE_LIBTOOL_FLAGS)
mod_txtrec_la_LDFLAGS = $(MODULE_LIBTOOL_FLAGS)
mod_arec_la_LDFLAGS = $(MODULE_LIBTOOL_FLAGS)
mod_myip_la_LDFLAGS = $(MODULE_LIBTOOL_FLAGS)
