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

using namespace OSS;


JS_METHOD_IMPL(switch_version_major_func)
{
	return JSString(switch_version_major());
}

JS_METHOD_IMPL(switch_version_minor_func)
{
	return JSString(switch_version_minor());
}

JS_METHOD_IMPL(switch_version_micro_func)
{
	return JSString(switch_version_micro());
}

JS_METHOD_IMPL(switch_version_revision_func)
{
	return JSString(switch_version_revision());
}

JS_METHOD_IMPL(switch_version_revision_human_func)
{
	return JSString(switch_version_revision_human());
}

JS_METHOD_IMPL(switch_version_full_func)
{
	return JSString(switch_version_full());
}

JS_METHOD_IMPL(switch_version_full_human_func)
{
	return JSString(switch_version_full_human());
}



JS_METHOD_IMPL(switch_core_set_variable_func)
{
	js_method_arg_assert_size_eq(2);
	std::string var = js_method_arg_as_std_string(0);
	std::string val = js_method_arg_as_std_string(1);
	switch_core_set_variable(var.c_str(), val.c_str());
}

JS_METHOD_IMPL(switch_core_get_variable_func)
{
	js_method_arg_assert_size_eq(1);
	std::string var = js_method_arg_as_std_string(0);
	return JSString(switch_core_get_variable(var.c_str()));
}

JS_METHOD_IMPL(switch_core_get_variables_func)
{
	switch_event_t* vars = 0;
	switch_core_get_variables(&vars);
	if (vars) {
		cJSON *json = 0;
		switch_event_serialize_json_obj(vars, &json);
		if (json) {
			char *json_text = cJSON_Print(json);
			if (json_text) {
				JS::JSIsolate::Ptr pIsolate = JS::JSIsolateManager::instance().rootIsolate();
				JSValueHandle obj = pIsolate->parseJSON(json_text);
				switch_safe_free(json_text);
				switch_event_destroy(&vars);
				cJSON_Delete(json);
				return obj;
			}
			cJSON_Delete(json);
		}
		switch_event_destroy(&vars);
	}
	return JSUndefined();
}

JS_METHOD_IMPL(switch_core_get_domain_func)
{
	return JSString(switch_core_get_domain(SWITCH_FALSE));
}

JS_METHOD_IMPL(switch_core_get_hostname_func)
{
	return JSString(switch_core_get_hostname());
}

JS_METHOD_IMPL(switch_core_get_switchname_func)
{
	return JSString(switch_core_get_switchname());
}

JS_METHOD_IMPL(switch_core_session_count_func)
{
	return JSUInt32(switch_core_session_count());
}

JS_METHOD_IMPL(switch_core_session_set_loglevel_func)
{
	js_method_arg_assert_size_eq(2);
	js_method_arg_assert_object(0);
	JSLocalObjectHandle sessionParam = js_method_arg_as_object(0);
	switch_log_level_t log_level = (switch_log_level_t)js_method_arg_as_int32(1);
	switch_core_session_t* session = js_unwrap_pointer_from_local_object<switch_core_session_t>(sessionParam);
	int ret = SWITCH_STATUS_FALSE;
	if (session) {
		ret = switch_core_session_set_loglevel(session, log_level);
	}
	return JSInt32(ret);
}

JS_METHOD_IMPL(switch_core_session_get_loglevel_func)
{
	js_method_arg_assert_size_eq(1);
	js_method_arg_assert_object(0);
	JSLocalObjectHandle sessionParam = js_method_arg_as_object(0);
	switch_core_session_t* session = js_unwrap_pointer_from_local_object<switch_core_session_t>(sessionParam);
	if (session) {
		return JSInt32(switch_core_session_get_loglevel(session));
	}
	return JSUndefined();
}

JS_METHOD_IMPL(switch_core_session_locate_func)
{
	js_method_arg_assert_size_eq(1);
	std::string uuid = js_method_arg_as_std_string(0);
	switch_core_session_t* session = 0;
	JSObjectHandle sessionObject; 
	if (!uuid.empty()) {
		if (session = switch_core_session_locate(uuid.c_str())) {
			sessionObject = js_wrap_pointer_to_local_object(session);
			return sessionObject;
		}
	}
	return JSUndefined();
}

JS_METHOD_IMPL(switch_core_session_rwunlock_func)
{
	js_method_arg_assert_size_eq(1);
	js_method_arg_assert_object(0);
	JSLocalObjectHandle sessionParam = js_method_arg_as_object(0);
	switch_core_session_t* session = js_unwrap_pointer_from_local_object<switch_core_session_t>(sessionParam);
	if (!session) {
		switch_core_session_rwunlock(session);
	}
}

JS_METHOD_IMPL(switch_core_session_get_uuid_func)
{
	js_method_arg_assert_size_eq(1);
	js_method_arg_assert_object(0);
	JSLocalObjectHandle sessionParam = js_method_arg_as_object(0);
	switch_core_session_t* session = js_unwrap_pointer_from_local_object<switch_core_session_t>(sessionParam);
	if (session) {
		return JSString(switch_core_session_get_uuid(session));
	}
	return JSUndefined();
}

JS_METHOD_IMPL(switch_core_session_get_channel_func)
{
	js_method_arg_assert_size_eq(1);
	js_method_arg_assert_object(0);
	JSLocalObjectHandle sessionParam = js_method_arg_as_object(0);
	switch_core_session_t* session = js_unwrap_pointer_from_local_object<switch_core_session_t>(sessionParam);
	if (!session) {
		return JSUndefined();
	}
	switch_channel_t *channel = switch_core_session_get_channel(session);
	if (!channel) {
		return JSUndefined();
	}
	JSObjectHandle channelObject = js_wrap_pointer_to_local_object(channel);
	return channelObject;
}

JS_METHOD_IMPL(switch_core_session_get_partner_func)
{
	js_method_arg_assert_size_eq(1);
	js_method_arg_assert_object(0);
	JSLocalObjectHandle sessionParam = js_method_arg_as_object(0);
	switch_core_session_t* session = js_unwrap_pointer_from_local_object<switch_core_session_t>(sessionParam);
	switch_core_session_t* other_session = 0;
	if (!session) {
		return JSUndefined();
	}
	if (switch_core_session_get_partner(session, &other_session)) {
		JSObjectHandle otherSessionObject = js_wrap_pointer_to_local_object(other_session);
		return otherSessionObject;
	}
	return JSUndefined();
}

JS_METHOD_IMPL(switch_core_session_send_dtmf_string_func)
{
	js_method_arg_assert_size_eq(2);
	js_method_arg_assert_object(0);
	JSLocalObjectHandle sessionParam = js_method_arg_as_object(0);
	switch_core_session_t* session = js_unwrap_pointer_from_local_object<switch_core_session_t>(sessionParam);
	int ret = SWITCH_STATUS_FALSE;
	if (session) {
		std::string dtmf = js_method_arg_as_std_string(1);
		if (!dtmf.empty()) {
			ret = switch_core_session_send_dtmf_string(session, dtmf.c_str());
		}
	}
	
	return JSInt32(ret);
}

JS_METHOD_IMPL(switch_channel_get_uuid_func)
{
	js_method_arg_assert_size_eq(1);
	js_method_arg_assert_object(0);
	JSLocalObjectHandle channelParam = js_method_arg_as_object(0);
	switch_channel_t* channel= js_unwrap_pointer_from_local_object<switch_channel_t>(channelParam);
	if (!channel) {
		return JSUndefined();
	}
	char* uuid = switch_channel_get_uuid(channel);
	if (!uuid) {
		return JSUndefined();
	}
	return JSString(uuid);
}

JS_METHOD_IMPL(switch_channel_get_partner_uuid_func)
{
	js_method_arg_assert_size_eq(1);
	js_method_arg_assert_object(0);
	JSLocalObjectHandle channelParam = js_method_arg_as_object(0);
	switch_channel_t* channel= js_unwrap_pointer_from_local_object<switch_channel_t>(channelParam);
	if (!channel) {
		return JSUndefined();
	}
	const char* uuid = switch_channel_get_partner_uuid(channel);
	if (!uuid) {
		return JSUndefined();
	}
	return JSString(uuid);
}

JS_METHOD_IMPL(switch_channel_ring_ready_func)
{
	js_method_arg_assert_size_eq(1);
	js_method_arg_assert_object(0);
	JSLocalObjectHandle channelParam = js_method_arg_as_object(0);
	switch_channel_t* channel= js_unwrap_pointer_from_local_object<switch_channel_t>(channelParam);
	int ret = SWITCH_STATUS_FALSE;
	if (channel) {
		ret = switch_channel_answer(channel);
	}
	return JSInt32(ret);
}

JS_METHOD_IMPL(switch_channel_answer_func)
{
	js_method_arg_assert_size_eq(1);
	js_method_arg_assert_object(0);
	JSLocalObjectHandle channelParam = js_method_arg_as_object(0);
	switch_channel_t* channel= js_unwrap_pointer_from_local_object<switch_channel_t>(channelParam);
	int ret = SWITCH_STATUS_FALSE;
	if (channel) {
		ret = switch_channel_answer(channel);
	}
	return JSInt32(ret);
}

JS_METHOD_IMPL(switch_channel_hangup_func)
{
	js_method_arg_assert_size_eq(2);
	js_method_arg_assert_object(0);
	JSLocalObjectHandle channelParam = js_method_arg_as_object(0);
	switch_call_cause_t cause = (switch_call_cause_t)js_method_arg_as_int32(1);
	switch_channel_t* channel= js_unwrap_pointer_from_local_object<switch_channel_t>(channelParam);
	if (channel) {
		switch_channel_hangup(channel, cause);
	}
}

JS_METHOD_IMPL(switch_channel_get_state_func)
{
	js_method_arg_assert_size_eq(1);
	js_method_arg_assert_object(0);
	JSLocalObjectHandle channelParam = js_method_arg_as_object(0);
	switch_channel_t* channel= js_unwrap_pointer_from_local_object<switch_channel_t>(channelParam);
	int state;
	if (channel) {
		state = switch_channel_get_state(channel);
		return JSInt32(state);
	}
	return JSUndefined();
}

JS_METHOD_IMPL(switch_channel_get_running_state_func)
{
	js_method_arg_assert_size_eq(1);
	js_method_arg_assert_object(0);
	JSLocalObjectHandle channelParam = js_method_arg_as_object(0);
	switch_channel_t* channel= js_unwrap_pointer_from_local_object<switch_channel_t>(channelParam);
	int state = CS_NONE;
	if (channel) {
		state = switch_channel_get_running_state(channel);
	}
	return JSInt32(state);
}

JS_METHOD_IMPL(switch_channel_ready_func)
{
	js_method_arg_assert_size_eq(1);
	js_method_arg_assert_object(0);
	JSLocalObjectHandle channelParam = js_method_arg_as_object(0);
	switch_channel_t* channel= js_unwrap_pointer_from_local_object<switch_channel_t>(channelParam);
	bool ret = false;
	if (channel) {
		ret = switch_channel_ready(channel);
	}
	return JSBoolean(ret);
}

JS_METHOD_IMPL(switch_channel_media_ready_func)
{
	js_method_arg_assert_size_eq(1);
	js_method_arg_assert_object(0);
	JSLocalObjectHandle channelParam = js_method_arg_as_object(0);
	switch_channel_t* channel= js_unwrap_pointer_from_local_object<switch_channel_t>(channelParam);
	bool ret = false;
	if (channel) {
		ret = switch_channel_media_ready(channel);
	}
	return JSBoolean(ret);
}

JS_METHOD_IMPL(switch_channel_media_up_func)
{
	js_method_arg_assert_size_eq(1);
	js_method_arg_assert_object(0);
	JSLocalObjectHandle channelParam = js_method_arg_as_object(0);
	switch_channel_t* channel= js_unwrap_pointer_from_local_object<switch_channel_t>(channelParam);
	bool ret = false;
	if (channel) {
		ret = switch_channel_media_up(channel);
	}
	return JSBoolean(ret);
}

JS_METHOD_IMPL(switch_channel_up_func)
{
	js_method_arg_assert_size_eq(1);
	js_method_arg_assert_object(0);
	JSLocalObjectHandle channelParam = js_method_arg_as_object(0);
	switch_channel_t* channel= js_unwrap_pointer_from_local_object<switch_channel_t>(channelParam);
	bool ret = false;
	if (channel) {
		ret = switch_channel_up(channel);
	}
	return JSBoolean(ret);
}

JS_METHOD_IMPL(switch_channel_down_func)
{
	js_method_arg_assert_size_eq(1);
	js_method_arg_assert_object(0);
	JSLocalObjectHandle channelParam = js_method_arg_as_object(0);
	switch_channel_t* channel= js_unwrap_pointer_from_local_object<switch_channel_t>(channelParam);
	bool ret = false;
	if (channel) {
		ret = switch_channel_down(channel);
	}
	return JSBoolean(ret);
}

JS_METHOD_IMPL(switch_channel_up_nosig_func)
{
	js_method_arg_assert_size_eq(1);
	js_method_arg_assert_object(0);
	JSLocalObjectHandle channelParam = js_method_arg_as_object(0);
	switch_channel_t* channel= js_unwrap_pointer_from_local_object<switch_channel_t>(channelParam);
	bool ret = false;
	if (channel) {
		ret = switch_channel_up_nosig(channel);
	}
	return JSBoolean(ret);
}

JS_METHOD_IMPL(switch_channel_down_nosig_func)
{
	js_method_arg_assert_size_eq(1);
	js_method_arg_assert_object(0);
	JSLocalObjectHandle channelParam = js_method_arg_as_object(0);
	switch_channel_t* channel= js_unwrap_pointer_from_local_object<switch_channel_t>(channelParam);
	bool ret = false;
	if (channel) {
		ret = switch_channel_down_nosig(channel);
	}
	return JSBoolean(ret);
}

JS_METHOD_IMPL(switch_channel_media_ack_func)
{
	js_method_arg_assert_size_eq(1);
	js_method_arg_assert_object(0);
	JSLocalObjectHandle channelParam = js_method_arg_as_object(0);
	switch_channel_t* channel= js_unwrap_pointer_from_local_object<switch_channel_t>(channelParam);
	bool ret = false;
	if (channel) {
		ret = switch_channel_media_ack(channel);
	}
	return JSBoolean(ret);
}

JS_METHOD_IMPL(switch_channel_text_only_func)
{
	js_method_arg_assert_size_eq(1);
	js_method_arg_assert_object(0);
	JSLocalObjectHandle channelParam = js_method_arg_as_object(0);
	switch_channel_t* channel= js_unwrap_pointer_from_local_object<switch_channel_t>(channelParam);
	bool ret = false;
	if (channel) {
		ret = switch_channel_text_only(channel);
	}
	return JSBoolean(ret);
}

JS_METHOD_IMPL(switch_channel_set_state_func)
{
	js_method_arg_assert_size_eq(2);
	js_method_arg_assert_object(0);
	JSLocalObjectHandle channelParam = js_method_arg_as_object(0);
	switch_channel_t* channel= js_unwrap_pointer_from_local_object<switch_channel_t>(channelParam);
	switch_channel_state_t state;
	if (channel) {
		
		state = switch_channel_set_state(channel, state);
		return JSInt32(state);
	}
	return JSUndefined();
}

JS_METHOD_IMPL(switch_channel_set_running_state_func)
{
	js_method_arg_assert_size_eq(2);
	js_method_arg_assert_object(0);
	JSLocalObjectHandle channelParam = js_method_arg_as_object(0);
	switch_channel_t* channel= js_unwrap_pointer_from_local_object<switch_channel_t>(channelParam);
	switch_channel_state_t state;
	if (channel) {
		
		state = switch_channel_set_running_state(channel, state);
		return JSInt32(state);
	}
	return JSUndefined();
}

JS_METHOD_IMPL(switch_channel_get_cause_func)
{
	js_method_arg_assert_size_eq(1);
	js_method_arg_assert_object(0);
	JSLocalObjectHandle channelParam = js_method_arg_as_object(0);
	switch_channel_t* channel= js_unwrap_pointer_from_local_object<switch_channel_t>(channelParam);
	switch_call_cause_t cause;
	if (channel) {
		cause = switch_channel_get_cause(channel);
		return JSInt32(cause);
	}
	return JSUndefined();
}

JS_METHOD_IMPL(switch_channel_get_cause_q850_func)
{
	js_method_arg_assert_size_eq(1);
	js_method_arg_assert_object(0);
	JSLocalObjectHandle channelParam = js_method_arg_as_object(0);
	switch_channel_t* channel= js_unwrap_pointer_from_local_object<switch_channel_t>(channelParam);
	switch_call_cause_t cause;
	if (channel) {
		cause = switch_channel_get_cause_q850(channel);
		return JSInt32(cause);
	}
	return JSUndefined();
}

JS_METHOD_IMPL(switch_channel_set_variable_safe_func)
{
	js_method_arg_assert_size_eq(3);
	js_method_arg_assert_object(0);
	JSLocalObjectHandle channelParam = js_method_arg_as_object(0);
	switch_channel_t* channel= js_unwrap_pointer_from_local_object<switch_channel_t>(channelParam);
	switch_status_t ret = SWITCH_STATUS_FALSE;
	if (channel) {
		std::string var = js_method_arg_as_std_string(1);
		std::string val = js_method_arg_as_std_string(2);
		ret = switch_channel_set_variable_safe(channel, var.c_str(), val.c_str());
	}
	return JSInt32(ret);
}

JS_METHOD_IMPL(switch_channel_set_variable_func)
{
	js_method_arg_assert_size_eq(3);
	js_method_arg_assert_object(0);
	JSLocalObjectHandle channelParam = js_method_arg_as_object(0);
	switch_channel_t* channel= js_unwrap_pointer_from_local_object<switch_channel_t>(channelParam);
	switch_status_t ret = SWITCH_STATUS_FALSE;
	if (channel) {
		std::string var = js_method_arg_as_std_string(1);
		std::string val = js_method_arg_as_std_string(2);
		ret = switch_channel_set_variable(channel, var.c_str(), val.c_str());
	}
	return JSInt32(ret);
}

JS_METHOD_IMPL(switch_channel_set_variable_partner_func)
{
	js_method_arg_assert_size_eq(3);
	js_method_arg_assert_object(0);
	JSLocalObjectHandle channelParam = js_method_arg_as_object(0);
	switch_channel_t* channel= js_unwrap_pointer_from_local_object<switch_channel_t>(channelParam);
	switch_status_t ret = SWITCH_STATUS_FALSE;
	if (channel) {
		std::string var = js_method_arg_as_std_string(1);
		std::string val = js_method_arg_as_std_string(2);
		ret = switch_channel_set_variable_partner(channel, var.c_str(), val.c_str());
	}
	return JSInt32(ret);
}

JS_METHOD_IMPL(switch_channel_get_variable_func)
{
	js_method_arg_assert_size_eq(2);
	js_method_arg_assert_object(0);
	JSLocalObjectHandle channelParam = js_method_arg_as_object(0);
	switch_channel_t* channel= js_unwrap_pointer_from_local_object<switch_channel_t>(channelParam);
	if (channel) {
		std::string var = js_method_arg_as_std_string(1);
		const char* val = switch_channel_get_variable_dup(channel, var.c_str(), SWITCH_FALSE, -1);
		if (val) {
			return JSString(val);
		}
	}
	return JSUndefined();
}

JS_METHOD_IMPL(switch_channel_get_variable_partner_func)
{
	js_method_arg_assert_size_eq(2);
	js_method_arg_assert_object(0);
	JSLocalObjectHandle channelParam = js_method_arg_as_object(0);
	switch_channel_t* channel= js_unwrap_pointer_from_local_object<switch_channel_t>(channelParam);
	if (channel) {
		std::string var = js_method_arg_as_std_string(1);
		const char* val = switch_channel_get_variable_partner(channel, var.c_str());
		if (val) {
			return JSString(val);
		}
	}
	return JSUndefined();
}

JS_METHOD_IMPL(switch_channel_get_variables_func)
{
	js_method_arg_assert_size_eq(1);
	js_method_arg_assert_object(0);
	JSLocalObjectHandle channelParam = js_method_arg_as_object(0);
	switch_channel_t* channel= js_unwrap_pointer_from_local_object<switch_channel_t>(channelParam);
	if (channel) {
		switch_event_t* vars = 0;
		switch_channel_get_variables(channel, &vars);
		if (vars) {
			cJSON *json = 0;
			switch_event_serialize_json_obj(vars, &json);
			if (json) {
				char *json_text = cJSON_Print(json);
				if (json_text) {
					JS::JSIsolate::Ptr pIsolate = JS::JSIsolateManager::instance().rootIsolate();
					JSValueHandle obj = pIsolate->parseJSON(json_text);
					switch_safe_free(json_text);
					switch_event_destroy(&vars);
					cJSON_Delete(json);
					return obj;
				}
				cJSON_Delete(json);
			}
			switch_event_destroy(&vars);
		}
	}
	return JSUndefined();
}

JS_METHOD_IMPL(switch_channel_set_flag_func)
{
	js_method_arg_assert_size_eq(2);
	js_method_arg_assert_object(0);
	JSLocalObjectHandle channelParam = js_method_arg_as_object(0);
	switch_channel_t* channel= js_unwrap_pointer_from_local_object<switch_channel_t>(channelParam);
	if (channel) {
		switch_channel_flag_t flag = (switch_channel_flag_t)js_method_arg_as_int32(1);
		switch_channel_set_flag(channel, flag);
	}
}
JS_METHOD_IMPL(switch_channel_test_flag_func)
{
	js_method_arg_assert_size_eq(2);
	js_method_arg_assert_object(0);
	JSLocalObjectHandle channelParam = js_method_arg_as_object(0);
	switch_channel_t* channel= js_unwrap_pointer_from_local_object<switch_channel_t>(channelParam);
	if (channel) {
		switch_channel_flag_t flag = (switch_channel_flag_t)js_method_arg_as_int32(1);
		return JSBoolean(!!switch_channel_test_flag(channel, flag));
	}
	return JSUndefined();
}

JS_METHOD_IMPL(switch_channel_clear_flag_func)
{
	js_method_arg_assert_size_eq(2);
	js_method_arg_assert_object(0);
	JSLocalObjectHandle channelParam = js_method_arg_as_object(0);
	switch_channel_t* channel= js_unwrap_pointer_from_local_object<switch_channel_t>(channelParam);
	if (channel) {
		switch_channel_flag_t flag = (switch_channel_flag_t)js_method_arg_as_int32(1);
		switch_channel_clear_flag(channel, flag);
	}
}

JS_METHOD_IMPL(switch_channel_set_flag_partner_func)
{
	js_method_arg_assert_size_eq(2);
	js_method_arg_assert_object(0);
	JSLocalObjectHandle channelParam = js_method_arg_as_object(0);
	switch_channel_t* channel= js_unwrap_pointer_from_local_object<switch_channel_t>(channelParam);
	if (channel) {
		switch_channel_flag_t flag = (switch_channel_flag_t)js_method_arg_as_int32(1);
		switch_channel_set_flag_partner(channel, flag);
	}
}
JS_METHOD_IMPL(switch_channel_test_flag_partner_func)
{
	js_method_arg_assert_size_eq(2);
	js_method_arg_assert_object(0);
	JSLocalObjectHandle channelParam = js_method_arg_as_object(0);
	switch_channel_t* channel= js_unwrap_pointer_from_local_object<switch_channel_t>(channelParam);
	if (channel) {
		switch_channel_flag_t flag = (switch_channel_flag_t)js_method_arg_as_int32(1);
		return JSBoolean(!!switch_channel_test_flag_partner(channel, flag));
	}
	return JSUndefined();
}

JS_METHOD_IMPL(switch_channel_clear_flag_partner_func)
{
	js_method_arg_assert_size_eq(2);
	js_method_arg_assert_object(0);
	JSLocalObjectHandle channelParam = js_method_arg_as_object(0);
	switch_channel_t* channel= js_unwrap_pointer_from_local_object<switch_channel_t>(channelParam);
	if (channel) {
		switch_channel_flag_t flag = (switch_channel_flag_t)js_method_arg_as_int32(1);
		switch_channel_clear_flag_partner(channel, flag);
	}
}

JS_METHOD_IMPL(switch_channel_has_dtmf_func)
{
	js_method_arg_assert_size_eq(1);
	js_method_arg_assert_object(0);
	JSLocalObjectHandle channelParam = js_method_arg_as_object(0);
	switch_channel_t* channel= js_unwrap_pointer_from_local_object<switch_channel_t>(channelParam);
	if (channel) {
		return JSInt32(switch_channel_has_dtmf(channel));
	}
	return JSUndefined();
}

JS_METHOD_IMPL(switch_channel_dtmf_lock_func)
{
	js_method_arg_assert_size_eq(1);
	js_method_arg_assert_object(0);
	JSLocalObjectHandle channelParam = js_method_arg_as_object(0);
	switch_channel_t* channel= js_unwrap_pointer_from_local_object<switch_channel_t>(channelParam);
	switch_status_t status = SWITCH_STATUS_FALSE;
	if (channel) {
		status = switch_channel_dtmf_lock(channel);
	}
	return JSInt32(status);
}

JS_METHOD_IMPL(switch_channel_try_dtmf_lock_func)
{
	js_method_arg_assert_size_eq(1);
	js_method_arg_assert_object(0);
	JSLocalObjectHandle channelParam = js_method_arg_as_object(0);
	switch_channel_t* channel= js_unwrap_pointer_from_local_object<switch_channel_t>(channelParam);
	switch_status_t status = SWITCH_STATUS_FALSE;
	if (channel) {
		status = switch_channel_try_dtmf_lock(channel);
	}
	return JSInt32(status);
}

JS_METHOD_IMPL(switch_channel_dtmf_unlock_func)
{
	js_method_arg_assert_size_eq(1);
	js_method_arg_assert_object(0);
	JSLocalObjectHandle channelParam = js_method_arg_as_object(0);
	switch_channel_t* channel= js_unwrap_pointer_from_local_object<switch_channel_t>(channelParam);
	switch_status_t status = SWITCH_STATUS_FALSE;
	if (channel) {
		status = switch_channel_dtmf_unlock(channel);
	}
	return JSInt32(status);
}

JS_METHOD_IMPL(switch_channel_queue_dtmf_string_func)
{
	js_method_arg_assert_size_eq(2);
	js_method_arg_assert_object(0);
	JSLocalObjectHandle channelParam = js_method_arg_as_object(0);
	switch_channel_t* channel= js_unwrap_pointer_from_local_object<switch_channel_t>(channelParam);
	switch_status_t status = SWITCH_STATUS_FALSE;
	if (channel) {
		std::string dtmf = js_method_arg_as_std_string(1);
		status = switch_channel_queue_dtmf_string(channel, dtmf.c_str());
	}
	return JSInt32(status);
}

JS_METHOD_IMPL(switch_channel_dequeue_dtmf_string_func)
{
	js_method_arg_assert_size_eq(1);
	js_method_arg_assert_object(0);
	JSLocalObjectHandle channelParam = js_method_arg_as_object(0);
	switch_channel_t* channel= js_unwrap_pointer_from_local_object<switch_channel_t>(channelParam);
	int size = SWITCH_STATUS_FALSE;
	std::string dtmf;
	if (channel) {
		char buff[128];
		size = switch_channel_dequeue_dtmf_string(channel, buff, sizeof(buff));
		dtmf = std::string(buff, size);
	}
	return JSString(dtmf.c_str());
}

JS_METHOD_IMPL(switch_channel_direction_func)
{
	js_method_arg_assert_size_eq(1);
	js_method_arg_assert_object(0);
	JSLocalObjectHandle channelParam = js_method_arg_as_object(0);
	switch_channel_t* channel= js_unwrap_pointer_from_local_object<switch_channel_t>(channelParam);
	switch_call_direction_t direction;
	if (channel) {
		direction = switch_channel_direction(channel);
		return JSInt32(direction);
	}
	return JSUndefined();
}

JS_METHOD_IMPL(switch_channel_logical_direction_func)
{
	js_method_arg_assert_size_eq(1);
	js_method_arg_assert_object(0);
	JSLocalObjectHandle channelParam = js_method_arg_as_object(0);
	switch_channel_t* channel= js_unwrap_pointer_from_local_object<switch_channel_t>(channelParam);
	switch_call_direction_t direction;
	if (channel) {
		direction = switch_channel_logical_direction(channel);
		return JSInt32(direction);
	}
	return JSUndefined();
}

JS_METHOD_IMPL(switch_channel_get_session_func)
{
	js_method_arg_assert_size_eq(1);
	js_method_arg_assert_object(0);
	JSLocalObjectHandle channelParam = js_method_arg_as_object(0);
	switch_channel_t* channel= js_unwrap_pointer_from_local_object<switch_channel_t>(channelParam);
	if (!channel) {
		return JSUndefined();
	}
	switch_core_session_t* session = switch_channel_get_session(channel);
	if (!session) {
		return JSUndefined();
	}
	JSObjectHandle sessionObject = js_wrap_pointer_to_local_object(session);
	return sessionObject;
}

JS_METHOD_IMPL(switch_channel_get_callstate_func)
{
	js_method_arg_assert_size_eq(1);
	js_method_arg_assert_object(0);
	JSLocalObjectHandle channelParam = js_method_arg_as_object(0);
	switch_channel_t* channel= js_unwrap_pointer_from_local_object<switch_channel_t>(channelParam);
	switch_channel_callstate_t state;
	if (channel) {
		state = switch_channel_get_callstate(channel);
		return JSInt32(state);
	}
	return JSUndefined();
}

JS_METHOD_IMPL(switch_channel_mark_hold_func)
{
	js_method_arg_assert_size_eq(2);
	js_method_arg_assert_object(0);
	JSLocalObjectHandle channelParam = js_method_arg_as_object(0);
	switch_channel_t* channel= js_unwrap_pointer_from_local_object<switch_channel_t>(channelParam);
	switch_channel_callstate_t state;
	if (channel) {
		bool on = js_method_arg_as_bool(1);
		switch_channel_mark_hold(channel, on ? SWITCH_TRUE : SWITCH_FALSE);
	}
}

SWITCH_EXPORT_JS_HANDLER(export_core_api)
{
	SWITCH_EXPORT_JS_METHOD("switch_version_major", switch_version_major_func);
	SWITCH_EXPORT_JS_METHOD("switch_version_minor", switch_version_minor_func);
	SWITCH_EXPORT_JS_METHOD("switch_version_micro", switch_version_micro_func);
	SWITCH_EXPORT_JS_METHOD("switch_version_revision", switch_version_revision_func);
	SWITCH_EXPORT_JS_METHOD("switch_version_revision_human", switch_version_revision_human_func);
	SWITCH_EXPORT_JS_METHOD("switch_version_full", switch_version_full_func);
	SWITCH_EXPORT_JS_METHOD("switch_version_full_human", switch_version_full_human_func);

	SWITCH_EXPORT_JS_METHOD("switch_core_get_variable", switch_core_get_variable_func);
	SWITCH_EXPORT_JS_METHOD("switch_core_set_variable", switch_core_set_variable_func);
	SWITCH_EXPORT_JS_METHOD("switch_core_get_variables", switch_core_get_variables_func);
	SWITCH_EXPORT_JS_METHOD("switch_core_get_domain", switch_core_get_domain_func);
	SWITCH_EXPORT_JS_METHOD("switch_core_get_hostname", switch_core_get_hostname_func);
	SWITCH_EXPORT_JS_METHOD("switch_core_get_switchname", switch_core_get_switchname_func);
	SWITCH_EXPORT_JS_METHOD("switch_core_session_count", switch_core_session_count_func);
	SWITCH_EXPORT_JS_METHOD("switch_core_session_set_loglevel", switch_core_session_set_loglevel_func);
	SWITCH_EXPORT_JS_METHOD("switch_core_session_get_loglevel", switch_core_session_get_loglevel_func);
	SWITCH_EXPORT_JS_METHOD("switch_core_session_get_uuid", switch_core_session_get_uuid_func);
	SWITCH_EXPORT_JS_METHOD("switch_core_session_get_channel", switch_core_session_get_channel_func);
	SWITCH_EXPORT_JS_METHOD("switch_core_session_get_partner", switch_core_session_get_partner_func);
	SWITCH_EXPORT_JS_METHOD("switch_core_session_locate", switch_core_session_locate_func);
	SWITCH_EXPORT_JS_METHOD("switch_core_session_rwunlock", switch_core_session_rwunlock_func);
	
	SWITCH_EXPORT_JS_METHOD("switch_channel_get_uuid", switch_channel_get_uuid_func);
	SWITCH_EXPORT_JS_METHOD("switch_channel_get_partner_uuid", switch_channel_get_partner_uuid_func);
	SWITCH_EXPORT_JS_METHOD("switch_channel_ring_ready", switch_channel_ring_ready_func);
	SWITCH_EXPORT_JS_METHOD("switch_channel_answer", switch_channel_answer_func);
	SWITCH_EXPORT_JS_METHOD("switch_channel_hangup", switch_channel_hangup_func);
	SWITCH_EXPORT_JS_METHOD("switch_channel_get_state", switch_channel_get_state_func);
	SWITCH_EXPORT_JS_METHOD("switch_channel_get_running_state", switch_channel_get_running_state_func);
	SWITCH_EXPORT_JS_METHOD("switch_channel_ready", switch_channel_ready_func);
	SWITCH_EXPORT_JS_METHOD("switch_channel_media_ready", switch_channel_media_ready_func);
	SWITCH_EXPORT_JS_METHOD("switch_channel_media_up", switch_channel_media_up_func);
	SWITCH_EXPORT_JS_METHOD("switch_channel_up", switch_channel_up_func);
	SWITCH_EXPORT_JS_METHOD("switch_channel_down", switch_channel_down_func);
	SWITCH_EXPORT_JS_METHOD("switch_channel_up_nosig", switch_channel_up_nosig_func);
	SWITCH_EXPORT_JS_METHOD("switch_channel_down_nosig", switch_channel_down_nosig_func);
	SWITCH_EXPORT_JS_METHOD("switch_channel_media_ack", switch_channel_media_ack_func);
	SWITCH_EXPORT_JS_METHOD("switch_channel_text_only", switch_channel_text_only_func);
	SWITCH_EXPORT_JS_METHOD("switch_channel_set_state", switch_channel_set_state_func);
	SWITCH_EXPORT_JS_METHOD("switch_channel_set_running_state", switch_channel_set_running_state_func);
	SWITCH_EXPORT_JS_METHOD("switch_channel_get_cause", switch_channel_get_cause_func);
	SWITCH_EXPORT_JS_METHOD("switch_channel_get_cause_q850", switch_channel_get_cause_q850_func);
	SWITCH_EXPORT_JS_METHOD("switch_channel_set_variable_safe", switch_channel_set_variable_safe_func);
	SWITCH_EXPORT_JS_METHOD("switch_channel_set_variable", switch_channel_set_variable_func);
	SWITCH_EXPORT_JS_METHOD("switch_channel_set_variable_partner", switch_channel_set_variable_partner_func);
	SWITCH_EXPORT_JS_METHOD("switch_channel_get_variable", switch_channel_get_variable_func);
	SWITCH_EXPORT_JS_METHOD("switch_channel_get_variable_partner", switch_channel_get_variable_partner_func);
	SWITCH_EXPORT_JS_METHOD("switch_channel_get_variables", switch_channel_get_variables_func);
	SWITCH_EXPORT_JS_METHOD("switch_channel_set_flag", switch_channel_set_flag_func);
	SWITCH_EXPORT_JS_METHOD("switch_channel_test_flag", switch_channel_test_flag_func);
	SWITCH_EXPORT_JS_METHOD("switch_channel_clear_flag", switch_channel_clear_flag_func);
	SWITCH_EXPORT_JS_METHOD("switch_channel_set_flag_partner", switch_channel_set_flag_partner_func);
	SWITCH_EXPORT_JS_METHOD("switch_channel_test_flag_partner", switch_channel_test_flag_partner_func);
	SWITCH_EXPORT_JS_METHOD("switch_channel_clear_flag_partner", switch_channel_clear_flag_partner_func);
	SWITCH_EXPORT_JS_METHOD("switch_channel_has_dtmf", switch_channel_has_dtmf_func);
	SWITCH_EXPORT_JS_METHOD("switch_channel_dtmf_lock", switch_channel_dtmf_lock_func);
	SWITCH_EXPORT_JS_METHOD("switch_channel_try_dtmf_lock", switch_channel_try_dtmf_lock_func);
	SWITCH_EXPORT_JS_METHOD("switch_channel_dtmf_unlock", switch_channel_dtmf_unlock_func);
	SWITCH_EXPORT_JS_METHOD("switch_channel_queue_dtmf_string", switch_channel_queue_dtmf_string_func);
	SWITCH_EXPORT_JS_METHOD("switch_channel_dequeue_dtmf_string", switch_channel_dequeue_dtmf_string_func);
	SWITCH_EXPORT_JS_METHOD("switch_channel_direction", switch_channel_direction_func);
	SWITCH_EXPORT_JS_METHOD("switch_channel_logical_direction", switch_channel_logical_direction_func);
	SWITCH_EXPORT_JS_METHOD("switch_channel_get_session", switch_channel_get_session_func);
	SWITCH_EXPORT_JS_METHOD("switch_channel_get_callstate", switch_channel_get_callstate_func);
	SWITCH_EXPORT_JS_METHOD("switch_channel_mark_hold", switch_channel_mark_hold_func);
}