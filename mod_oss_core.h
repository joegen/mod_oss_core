// Library: MOD_OSS_CORE - FreeSWITCH Scripting Module
// Copyright (c) OSS Software Solutions
// Contributor: Joegen Baclor - mailto:joegen@ossapp.com
//
// Permission is hereby granted, to any person or organization
// obtaining a copy of the software and accompanying documentation covered by
// this license (the "Software") to use, execute, and to prepare
// derivative works of the Software, all subject to the
// "GNU Lesser General Public License (LGPL)".
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE, TITLE AND NON-INFRINGEMENT. IN NO EVENT
// SHALL THE COPYRIGHT HOLDERS OR ANYONE DISTRIBUTING THE SOFTWARE BE LIABLE
// FOR ANY DAMAGES OR OTHER LIABILITY, WHETHER IN CONTRACT, TORT OR OTHERWISE,
// ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// DEALINGS IN THE SOFTWARE.
//


#ifndef MOD_OSS_CORE_H_INCLUDED
#define MOD_OSS_CORE_H_INCLUDED

#include <switch.h>
#include <switch_json.h>
#include <sstream>

#include <boost/function.hpp>
#include <boost/thread/future.hpp>

#include <OSS/UTL/Thread.h>
#include <OSS/JS/JS.h>
#include <OSS/JS/JSIsolateManager.h>
#include <OSS/JS/JSEventLoop.h>
#include <OSS/JSON/Json.h>

#define LOG(resource, level, msg) { std::ostringstream __strm__; __strm__ << msg << "\n"; switch_log_printf(resource, level, "%s", __strm__.str().c_str()); }
#define CHAN_LOG(level, msg) LOG(SWITCH_CHANNEL_LOG, level, msg)
#define CHAN_LOG_INFO(msg) CHAN_LOG(SWITCH_LOG_INFO, msg)
#define CHAN_LOG_DEBUG(msg) CHAN_LOG(SWITCH_LOG_DEBUG, msg)
#define CHAN_LOG_ERROR(msg) CHAN_LOG(SWITCH_LOG_ERROR, msg)
#define CHAN_LOG_NOTICE(msg) CHAN_LOG(SWITCH_LOG_NOTICE, msg)
#define CHAN_LOG_WARNING(msg) CHAN_LOG(SWITCH_LOG_WARNING, msg)
#define CHAN_LOG_CRIT(msg) CHAN_LOG(SWITCH_LOG_CRIT, msg)
#define SWITCH_EXPORT_JS_HANDLER(METHOD) void METHOD(JSObjectTemplateHandle& _global_)
#define SWITCH_EXPORT_JS_METHOD(FUNC, METHOD) _global_->Set(v8::String::New(FUNC), v8::FunctionTemplate::New(METHOD))
#define SWITCH_CONST_EXPORT(Name) _global_->Set(v8::String::New(#Name), v8::Integer::New(Name), v8::ReadOnly)

typedef boost::promise<std::string> StringPromise;
typedef boost::future<std::string> StringFuture;
typedef boost::function<void(void*)> switch_threadpool_callback;

class session_string_promise : public StringPromise
{
public:
	session_string_promise(switch_core_session_t* session_ = 0) : session(session_) {}
	switch_core_session_t* session;
};

typedef session_string_promise SessionPromise;
typedef boost::future<std::string> SessionFuture;

class mod_oss_core_globals
{
public:
	static mod_oss_core_globals* instance();
	static void deleteInstance();
	
	bool xml_handler_enabled;
	bool switch_event_node_enabled;
	switch_event_node_t* event_node;
	OSS::thread_pool* api_thread_pool;
	OSS::thread_pool* app_thread_pool;
	OSS::thread_pool* xml_thread_pool;
	
protected:
	mod_oss_core_globals() {};
	~mod_oss_core_globals() {};
	static mod_oss_core_globals* _instance;
};

struct switch_async_api_arg
{
	std::string method;
	std::string args;
	std::string uuid;
	JSPersistentFunctionHandle* async_cb;
	SessionPromise* session_promise;
};

SWITCH_EXPORT_JS_HANDLER(export_core_api);
SWITCH_EXPORT_JS_HANDLER(export_core_exports);

#endif // MOD_OSS_CORE_H_INCLUDED
