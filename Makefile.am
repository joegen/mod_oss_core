
include $(top_srcdir)/build/modmake.rulesam
MODNAME=mod_oss_core

OSS_CORE_LIBS = -loss_core \
    -lboost_thread \
    -lboost_system \
    -lPocoFoundation \
    -lPocoNetSSL \
    -lPocoNet \
    -lv8 \
    -lconfig++ \
    -lzmq \
    -lhiredis \
    -lpcap 

mod_LTLIBRARIES = mod_oss_core.la
mod_oss_core_la_SOURCES  = core_exports.cpp core_api.cpp mod_oss_core.cpp
mod_oss_core_la_CPPFLAGS   = $(AM_CPPFLAGS) -DHAVE_POLL -DBOOST_THREAD_PROVIDES_FUTURE 
mod_oss_core_la_CXXFLAGS   = $(AM_CXXFLAGS)
mod_oss_core_la_LIBADD   = $(switch_builddir)/libfreeswitch.la
mod_oss_core_la_LDFLAGS  = -avoid-version -module -no-undefined -shared $(OSS_CORE_LIBS)


