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

#include "mod_oss_core.h"
#include "OSS/SIP/SBC/SBCManager.h"

using namespace OSS;

#define GLOBALS mod_oss_core_globals::instance()

enum switch_async_call_type
{
	TYPE_API,
	TYPE_APP
};

static struct {
	char* script_path;
	int api_threads_min;
	int api_threads_max;
	int app_threads_min;
	int app_threads_max;
	int xml_threads_min;
	int xml_threads_max;
} config_items;

static switch_xml_config_item_t config_settings[] = {
	/* key, flags, ptr, default_value, syntax, helptext */
	SWITCH_CONFIG_ITEM_STRING_STRDUP("script_path", CONFIG_REQUIRED, &config_items.script_path, "", NULL, "Path to the JavaScript file"),
	SWITCH_CONFIG_ITEM("api_threads_min", SWITCH_CONFIG_INT, CONFIG_RELOADABLE, &config_items.api_threads_min, (void *)2, NULL, NULL, "Initial number of API threads"),
	SWITCH_CONFIG_ITEM("api_threads_max", SWITCH_CONFIG_INT, CONFIG_RELOADABLE, &config_items.api_threads_max, (void *)1024, NULL, NULL, "Maximum number of API threads"),
	SWITCH_CONFIG_ITEM("app_threads_min", SWITCH_CONFIG_INT, CONFIG_RELOADABLE, &config_items.app_threads_min, (void *)2, NULL, NULL, "Initial number of application threads"),
	SWITCH_CONFIG_ITEM("app_threads_max", SWITCH_CONFIG_INT, CONFIG_RELOADABLE, &config_items.app_threads_max, (void *)1024, NULL, NULL, "Maximum number of application threads"),
	SWITCH_CONFIG_ITEM("xml_threads_min", SWITCH_CONFIG_INT, CONFIG_RELOADABLE, &config_items.xml_threads_min, (void *)2, NULL, NULL, "Initial number of xml threads"),
	SWITCH_CONFIG_ITEM("xml_threads_max", SWITCH_CONFIG_INT, CONFIG_RELOADABLE, &config_items.xml_threads_max, (void *)1024, NULL, NULL, "Maximum number of xml threads"),
	SWITCH_CONFIG_ITEM_END()
};

SWITCH_MODULE_LOAD_FUNCTION(mod_oss_core_load);
SWITCH_MODULE_SHUTDOWN_FUNCTION(mod_oss_core_shutdown);
SWITCH_MODULE_RUNTIME_FUNCTION(mod_oss_core_runtime);
SWITCH_MODULE_DEFINITION(mod_oss_core, mod_oss_core_load, mod_oss_core_shutdown, mod_oss_core_runtime);

static void oss_core_logger(const std::string& log, OSS::LogPriority prio)
{
	switch_log_level_t log_level;
	switch (prio)
	{
	case OSS::PRIO_FATAL:
	case OSS::PRIO_CRITICAL:
		log_level = SWITCH_LOG_CRIT;
		break;
	case OSS::PRIO_ERROR:
		log_level = SWITCH_LOG_ERROR;
		break;
	case OSS::PRIO_WARNING:
		log_level = SWITCH_LOG_WARNING;
		break;
	case OSS::PRIO_NOTICE:
		log_level = SWITCH_LOG_NOTICE;
		break;
	case OSS::PRIO_INFORMATION:
		log_level = SWITCH_LOG_INFO;
		break;
	case OSS::PRIO_DEBUG:
	case OSS::PRIO_TRACE:
		log_level = SWITCH_LOG_DEBUG;
		break;
	default:
		log_level = SWITCH_LOG_DEBUG;
	}
	switch_log_printf(SWITCH_CHANNEL_LOG, log_level, "[oss_core] %s\n", log.c_str());
}

mod_oss_core_globals* mod_oss_core_globals::_instance = 0;
mod_oss_core_globals* mod_oss_core_globals::instance()
{
	if (!_instance) {
		_instance = new mod_oss_core_globals();
		_instance->xml_handler_enabled = false;
		_instance->switch_event_node_enabled = false;
		_instance->event_node = 0;
		_instance->api_thread_pool = 0;
		_instance->app_thread_pool = 0;
		_instance->xml_thread_pool = 0;
	}
	return _instance;
}

void mod_oss_core_globals::deleteInstance()
{
	if (_instance) {
		delete _instance->api_thread_pool;
		delete _instance->app_thread_pool;
		delete _instance->xml_thread_pool;
		delete _instance;
		_instance = 0;
	}
}

static v8::Handle<v8::Value>  switch_execute_async(switch_async_call_type call_type, const v8::Arguments& _args_, const switch_threadpool_callback& cb)
{
	std::string uuid;
	std::string cmd;
	std::string arg;
	JSPersistentFunctionHandle* async_cb = new JSPersistentFunctionHandle;
	
	if (call_type == TYPE_API) {
		js_method_arg_assert_size_eq(3);
		cmd = js_method_arg_as_std_string(0);
		arg = js_method_arg_as_std_string(1);
		*async_cb = js_method_arg_as_persistent_function(2);
	} else if (call_type == TYPE_APP) {
		js_method_arg_assert_size_eq(4);
		uuid = js_method_arg_as_std_string(0);
		cmd = js_method_arg_as_std_string(1);
		arg = js_method_arg_as_std_string(2);
		*async_cb = js_method_arg_as_persistent_function(3);
	} else {
		return JSFalse;
	}

	switch_async_api_arg* async_arg = new switch_async_api_arg();
	async_arg->uuid = uuid;
	async_arg->method = cmd;
	async_arg->args = arg;
	async_arg->async_cb = async_cb;
	
	if (call_type == TYPE_API) {
		if (GLOBALS->api_thread_pool->schedule_with_arg(cb, (void*)async_arg) == -1) {
			return JSFalse;
		}
	} else {
		if (GLOBALS->app_thread_pool->schedule_with_arg(cb, (void*)async_arg) == -1) {
			return JSFalse;
		}
	}
	return JSTrue;
}

JS_METHOD_IMPL(switch_channel_log)
{
	js_method_arg_assert_size_eq(2);
	std::string level = js_method_arg_as_std_string(0);
	std::string msg = js_method_arg_as_std_string(1);
	OSS::string_to_lower(level);
	
	if (level == "info") {
		CHAN_LOG_INFO(msg);
	} else if (level == "debug") {
		CHAN_LOG_DEBUG(msg);
	} else if (level == "error") {
		CHAN_LOG_ERROR(msg);
	} else if (level == "notice") {
		CHAN_LOG_NOTICE(msg);
	}  else if (level == "warning") {
		CHAN_LOG_WARNING(msg);
	} else if (level == "crit") {
		CHAN_LOG_CRIT(msg);
	}
	return JSUndefined();
}

JS_METHOD_IMPL(switch_uuid_set_credential_func)
{
	js_method_arg_assert_size_eq(4);
	std::string uuid = js_method_arg_as_std_string(0);
	std::string auth_user = js_method_arg_as_std_string(1);
	std::string auth_password = js_method_arg_as_std_string(2);
	std::string auth_realm = js_method_arg_as_std_string(3);

	switch_core_session_t* session = switch_core_session_locate(uuid.c_str());
	if (session) {
		switch_channel_t* channel = switch_core_session_get_channel(session);
		if (channel) {
			switch_channel_set_variable(channel, "sip_auth_username", auth_user.c_str());
			switch_channel_set_variable(channel, "sip_auth_password", auth_password.c_str());
			switch_channel_set_variable(channel, "sip_auth_realm", auth_realm.c_str());
		}
		switch_core_session_rwunlock(session);
		return JSBoolean(true);
	}
	return JSBoolean(false);
}

JS_METHOD_IMPL(switch_uuid_channel_get_variable_func)
{
	js_method_arg_assert_size_eq(4);
	std::string uuid = js_method_arg_as_std_string(0);
	std::string var_name = js_method_arg_as_std_string(1);
	std::string value;
	switch_core_session_t* session = switch_core_session_locate(uuid.c_str());
	if (session) {
		switch_channel_t* channel = switch_core_session_get_channel(session);
		if (channel) {
			const char* val = switch_channel_get_variable(channel, var_name.c_str());
			if (!zstr(val)) {
				value = val;
			}
		}
		switch_core_session_rwunlock(session);
	}
	return JSString(value.c_str());
}

static std::string switch_js_func_execute(const std::string& method, const std::string& arg, void* userData = 0)
{
	OSS::JSON::Object func, arguments, result;
	func["method"] = OSS::JSON::String(method.c_str());
	
	std::stringstream strm;
	strm << arg;
	OSS::JSON::Reader::Read(arguments, strm);
	func["arguments"] = arguments;

	std::string resultVal;
	JS::JSIsolate::Ptr pIsolate = JS::JSIsolateManager::instance().rootIsolate();
	if (pIsolate->execute(func, result, 0, userData))
	{
		OSS::JSON::Object::iterator iter = result.Find("result");
		if (iter != result.End())
		{
			OSS::JSON::String ret = iter->element;
			resultVal =  ret.Value();
		}
	}
	
	return resultVal;
}

static void switch_js_notify_event(const std::string& event, const std::string& json, void* userData = 0) 
{
	JS::JSIsolate::Ptr pIsolate = JS::JSIsolateManager::instance().rootIsolate();
	std::ostringstream strm;
	strm << "{" << "\"method\" : \"" << event << "\", \"arguments\" : " << json << "}"; 
	pIsolate->notify(strm.str(), userData);
}

static void switch_js_notify_callback(const std::string& method, JSPersistentFunctionHandle* cb, const std::string& json) 
{
	JS::JSIsolate::Ptr pIsolate = JS::JSIsolateManager::instance().rootIsolate();
	std::ostringstream strm;
	strm << "{" << "\"method\" : \"" << method << "\", \"arguments\" : " << json << "}";  
	pIsolate->notify(strm.str(), 0, cb);
}

static std::string switch_serialize_event_as_json(const char *section, const char *tag_name, const char *key_name, const char *key_value, switch_event_t *params)
{
	cJSON *data = 0;
	switch_event_serialize_json_obj(params, &data);
	switch_assert(data);
	cJSON_AddItemToObject(data, "hostname", cJSON_CreateString(switch_core_get_switchname()));
	cJSON_AddItemToObject(data, "section", cJSON_CreateString(section));
	cJSON_AddItemToObject(data, "tag_name", cJSON_CreateString(tag_name));
	cJSON_AddItemToObject(data, "key_name", cJSON_CreateString(key_name));
	cJSON_AddItemToObject(data, "key_value", cJSON_CreateString(key_value));
	char *json_text = cJSON_Print(data);
	switch_assert(json_text);
	std::string json = json_text;
	switch_safe_free(json_text);
	cJSON_Delete(data);
	return json;
}

static switch_xml_t switch_xml_parse_string(const std::string& xml)
{
	if (xml.empty()) {
		return 0;
	}
	
	switch_uuid_t uuid;
	char uuid_str[SWITCH_UUID_FORMATTED_LENGTH + 1];
	switch_uuid_get(&uuid);
	switch_uuid_format(uuid_str, &uuid);
	
	std::ostringstream fn;
	fn << SWITCH_GLOBAL_dirs.temp_dir << SWITCH_PATH_SEPARATOR << uuid_str;
	
	std::ofstream out(fn.str().c_str());
	out << xml;
	out.close();
	
	return switch_xml_parse_file(fn.str().c_str());
}

void switch_xml_handler_callback(void* args_)
{
	switch_async_api_arg* args = (switch_async_api_arg*)args_;
	assert(args);
	assert(args->session_promise);
	assert(!args->args.empty());
	switch_js_func_execute("handle_switch_xml", args->args, (void*)args->session_promise);
	delete args;
}

static switch_xml_t switch_xml_handler(const char *section, const char *tag_name, const char *key_name, const char *key_value, switch_event_t *params, void *user_data)
{
	switch_xml_t result = 0;
	switch_async_api_arg* args = new switch_async_api_arg();
	SessionPromise* promise = new SessionPromise(0);
	args->session_promise = promise;
	
	args->args = switch_serialize_event_as_json(section, tag_name, key_name, key_value, params);
	StringFuture future = args->session_promise->get_future();
	
	if (GLOBALS->xml_thread_pool->schedule_with_arg(switch_xml_handler_callback, (void*)args) != -1) {
		std::string xml = future.get();
		if (!xml.empty()) {
			result = switch_xml_parse_string(xml);
		}
	}
	
	return result;
}

JS_METHOD_IMPL(switch_promise_get_session)
{
	js_method_arg_assert_size_eq(1);
	js_method_arg_assert_object(0);
	JSLocalObjectHandle promiseParam = js_method_arg_as_object(0);
	SessionPromise* promise = js_unwrap_pointer_from_local_object<SessionPromise>(promiseParam);

	if (promise) {
		JSObjectHandle obj = js_wrap_pointer_to_local_object(promise->session);
		return obj;
	}
	return JSUndefined();
}

JS_METHOD_IMPL(switch_promise_set_result)
{
	js_method_arg_assert_size_eq(2);
	js_method_arg_assert_object(0);
	JSLocalObjectHandle promiseParam = js_method_arg_as_object(0);
	SessionPromise* promise = js_unwrap_pointer_from_local_object<SessionPromise>(promiseParam);
	assert(promise);
	promise->set_value(js_method_arg_as_std_string(1));
}

void oss_core_json_api_callback(void* args_)
{
	switch_async_api_arg* args = (switch_async_api_arg*)args_;
	assert(args);
	assert(args->session_promise);
	assert(!args->args.empty());
	switch_js_func_execute("handle_switch_json_api", args->args, (void*)args->session_promise);
	delete args;
}

SWITCH_STANDARD_API(oss_core_json_api)
{
	switch_async_api_arg* args = new switch_async_api_arg();
	SessionPromise* promise = new SessionPromise(session);
	args->session_promise = promise;
	
	args->args = cmd;
	StringFuture future = args->session_promise->get_future();
	
	if (GLOBALS->api_thread_pool->schedule_with_arg(oss_core_json_api_callback, (void*)args) != -1) {
		std::string result = future.get();
		stream->write_function(stream, "%s", result.c_str());
	}
	delete promise;
	return SWITCH_STATUS_SUCCESS;
}

void oss_core_json_app_callback(void* args_)
{
	switch_async_api_arg* args = (switch_async_api_arg*)args_;
	assert(args);
	assert(args->session_promise);
	assert(!args->args.empty());
	switch_js_func_execute("handle_switch_json_app", args->args, (void*)args->session_promise);
	delete args;
}

SWITCH_STANDARD_APP(oss_core_json_app)
{
	switch_async_api_arg* args = new switch_async_api_arg();
	SessionPromise* promise = new SessionPromise(session);
	args->session_promise = promise;
	
	args->args = data;
	StringFuture future = args->session_promise->get_future();
	if (!args->args.empty() && GLOBALS->app_thread_pool->schedule_with_arg(oss_core_json_app_callback, (void*)args) != -1) {
		future.get();
	}
	delete promise;
}

JS_METHOD_IMPL(switch_enable_xml_handling)
{
	if (!GLOBALS->xml_handler_enabled) {
		js_method_arg_assert_size_eq(1);
		std::string bindings = js_method_arg_as_std_string(0);
		GLOBALS->xml_handler_enabled = (switch_xml_bind_search_function(switch_xml_handler, switch_xml_parse_section_string(bindings.c_str()), 0) == SWITCH_STATUS_SUCCESS);
	}
	return JSBoolean(GLOBALS->xml_handler_enabled);
}

static void switch_event_handler(switch_event_t *event) 
{
	if (!GLOBALS->switch_event_node_enabled) {
		return;
	}
	
	char *buf = NULL;
	std::string json;
	
	if (switch_event_serialize_json(event, &buf) == SWITCH_STATUS_SUCCESS) {
		json = buf;
		switch_safe_free(buf);
	} else {
		switch_safe_free(buf);
	}

	if (!json.empty()) {
		switch_js_notify_event("handle_switch_event", json);
	}
}

JS_METHOD_IMPL(switch_enable_event_handling)
{
	if (!GLOBALS->switch_event_node_enabled) {
		GLOBALS->switch_event_node_enabled =(switch_event_bind_removable(modname, SWITCH_EVENT_ALL, SWITCH_EVENT_SUBCLASS_ANY, switch_event_handler, 0, &GLOBALS->event_node) == SWITCH_STATUS_SUCCESS);
	}
	return JSBoolean(GLOBALS->switch_event_node_enabled);
}

static void switch_execute_api_async(void* arg)
{
	switch_async_api_arg* async_arg = static_cast<switch_async_api_arg*>(arg);
	
	if (async_arg) {
		std::string result;
		switch_stream_handle_t stream = { 0 };
		SWITCH_STANDARD_STREAM(stream);
		switch_status_t status = switch_api_execute(async_arg->method.c_str(), async_arg->args.c_str(), NULL, &stream);

		if (stream.data) {
			result = std::string(static_cast<const char*>(stream.data));
		}
		switch_safe_free(stream.data);

		JSPersistentFunctionHandle* async_cb = async_arg->async_cb;
		delete async_arg;
		//
		// notify the isolate
		//
		std::ostringstream strm;
		strm << "{\"result\" : \"" << result << "\"}";
		switch_js_notify_callback("switch_api_execute", async_cb, strm.str());
	}
}

JS_METHOD_IMPL(switch_execute_api)
{
	js_method_arg_assert_size_gteq(2);
	if (js_method_arg_length() == 3) {
		return switch_execute_async(TYPE_API, _args_, boost::bind(switch_execute_api_async, _1));
	}
	
	std::string cmd = js_method_arg_as_std_string(0);
	std::string arg = js_method_arg_as_std_string(1);
	switch_stream_handle_t stream = { 0 };
	SWITCH_STANDARD_STREAM(stream);
	switch_status_t status = switch_api_execute(cmd.c_str(), arg.c_str(), NULL, &stream);

	std::string result;
	if (stream.data) {
		result = std::string(static_cast<const char*>(stream.data));
	}
	switch_safe_free(stream.data);
	return JSString(result);
}

static void switch_execute_app_async(void* arg)
{
	switch_async_api_arg* async_arg = static_cast<switch_async_api_arg*>(arg);
	if (async_arg) {
		std::string uuid = async_arg->uuid; // UUID is in the method, yep
		std::string method = async_arg->method;
		std::string bridge_args = async_arg->args;
		switch_core_session_t* session = switch_core_session_locate(uuid.c_str());
		std::string result = "{\"result\" : \"true\"}";
		if (session) {
			if (switch_core_session_execute_application(session, method.c_str(), async_arg->args.c_str()) != SWITCH_STATUS_SUCCESS) {
				result = "{\"result\" : \"false\"}";
			}
			switch_core_session_rwunlock(session);
		}
		
		if (async_arg->async_cb) {
			switch_js_notify_callback(method, async_arg->async_cb, result);
		}
		
		delete async_arg;
	}
}

JS_METHOD_IMPL(switch_execute_app)
{
	js_method_arg_assert_size_gteq(3);
	if (js_method_arg_length() == 4) {
		return switch_execute_async(TYPE_APP, _args_, boost::bind(switch_execute_app_async, _1));
	}
	
	std::string uuid = js_method_arg_as_std_string(0);
	std::string cmd = js_method_arg_as_std_string(1);
	std::string arg = js_method_arg_as_std_string(2);
	
	int ret = SWITCH_STATUS_FALSE;
	switch_core_session_t* session = 0;
	if (!uuid.empty()) {
		session = switch_core_session_locate(uuid.c_str());
	}
	
	ret = (switch_core_session_execute_application(session, cmd.c_str(), arg.c_str()));
	
	if (session) {
		switch_core_session_rwunlock(session);
	}
	return JSInt32(ret);
}

SWITCH_EXPORT_JS_HANDLER(export_global_methods)
{
	SWITCH_EXPORT_JS_METHOD("switch_channel_log", switch_channel_log);
	SWITCH_EXPORT_JS_METHOD("switch_enable_xml_handling", switch_enable_xml_handling);
	SWITCH_EXPORT_JS_METHOD("switch_enable_event_handling", switch_enable_event_handling);
	SWITCH_EXPORT_JS_METHOD("switch_api_execute", switch_execute_api);
	SWITCH_EXPORT_JS_METHOD("switch_app_execute", switch_execute_app);
	SWITCH_EXPORT_JS_METHOD("switch_promise_get_session", switch_promise_get_session);
	SWITCH_EXPORT_JS_METHOD("switch_promise_set_result", switch_promise_set_result);
	
	SWITCH_EXPORT_JS_METHOD("switch_uuid_set_credential", switch_uuid_set_credential_func);
	SWITCH_EXPORT_JS_METHOD("switch_uuid_channel_get_variable", switch_uuid_channel_get_variable_func);
}

SWITCH_MODULE_RUNTIME_FUNCTION(mod_oss_core_runtime)
{
	boost::filesystem::path path(config_items.script_path);
	if (boost::filesystem::exists(path)) {
		JS::JSIsolate::Ptr pIsolate = JS::JSIsolateManager::instance().rootIsolate();
		
		JS::JSIsolateManager::instance().addExportHandler(boost::bind(export_core_exports, _1));
		JS::JSIsolateManager::instance().addExportHandler(boost::bind(export_core_api, _1));
		JS::JSIsolateManager::instance().addExportHandler(boost::bind(export_global_methods, _1));

		GLOBALS->api_thread_pool = new OSS::thread_pool(config_items.api_threads_min, config_items.api_threads_min);
		GLOBALS->app_thread_pool = new OSS::thread_pool(config_items.app_threads_min, config_items.app_threads_min);
		GLOBALS->xml_thread_pool = new OSS::thread_pool(config_items.xml_threads_min, config_items.xml_threads_min);
		
		OSS::SIP::SBC::SBCManager::instance()->modules().run(config_items.script_path, false);
		
		JS::JSIsolateManager::instance().resetRootIsolate();
	}
	return SWITCH_STATUS_TERM;
}

SWITCH_MODULE_LOAD_FUNCTION(mod_oss_core_load)
{
	switch_api_interface_t *commands_api_interface;
	switch_application_interface_t *app_interface;
	*module_interface = switch_loadable_module_create_module_interface(pool, modname);
	
	SWITCH_ADD_API(commands_api_interface, 
		"oss_core_json_api", 
		"Execute an oss_core JavaScript function", 
		oss_core_json_api, "<JSON_command>");
	
	SWITCH_ADD_APP(app_interface, 
		"oss_core_json_app",
		"mod_oss_core JavaScript application",
		"mod_oss_core JavaScript application", 
		oss_core_json_app, "<JSON_command>", SAF_SUPPORT_NOMEDIA);
	
	OSS::OSS_init();
	OSS::logger_init_external(boost::bind(oss_core_logger, _1, _2));
	mod_oss_core_globals::deleteInstance();
	mod_oss_core_globals::instance();
	
	memset(&config_items, 0, sizeof(config_items));
	if (switch_xml_config_parse_module_settings("oss_core.conf", SWITCH_FALSE, config_settings) != SWITCH_STATUS_SUCCESS) {
		CHAN_LOG_CRIT("Unable to load or parse config!");
		return SWITCH_STATUS_FALSE;
	}
	
	boost::filesystem::path path(config_items.script_path);
	if (!boost::filesystem::exists(path)) {
		CHAN_LOG_CRIT("Unable to locate script " << config_items.script_path);
		return SWITCH_STATUS_FALSE;
	}
	return SWITCH_STATUS_SUCCESS;
}

SWITCH_MODULE_SHUTDOWN_FUNCTION(mod_oss_core_shutdown)
{
	if (GLOBALS->xml_handler_enabled) {
		switch_xml_unbind_search_function_ptr(switch_xml_handler);
	}
	
	if (GLOBALS->switch_event_node_enabled) {
		switch_event_unbind(&GLOBALS->event_node);
	}
	
	switch_xml_config_cleanup(config_settings);
	
	JS::JSIsolateManager::instance().rootIsolate()->terminate();
	return SWITCH_STATUS_SUCCESS;
}