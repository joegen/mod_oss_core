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

SWITCH_EXPORT_JS_HANDLER(export_core_exports)
{
	SWITCH_CONST_EXPORT(SWITCH_FALSE);
	SWITCH_CONST_EXPORT(SWITCH_TRUE);
	
	SWITCH_CONST_EXPORT(SWITCH_STATUS_SUCCESS);
	SWITCH_CONST_EXPORT(SWITCH_STATUS_FALSE);
	SWITCH_CONST_EXPORT(SWITCH_STATUS_TIMEOUT);
	SWITCH_CONST_EXPORT(SWITCH_STATUS_RESTART);
	SWITCH_CONST_EXPORT(SWITCH_STATUS_INTR);
	SWITCH_CONST_EXPORT(SWITCH_STATUS_NOTIMPL);
	SWITCH_CONST_EXPORT(SWITCH_STATUS_MEMERR);
	SWITCH_CONST_EXPORT(SWITCH_STATUS_NOOP);
	SWITCH_CONST_EXPORT(SWITCH_STATUS_RESAMPLE);
	SWITCH_CONST_EXPORT(SWITCH_STATUS_GENERR);
	SWITCH_CONST_EXPORT(SWITCH_STATUS_INUSE);
	SWITCH_CONST_EXPORT(SWITCH_STATUS_BREAK);
	SWITCH_CONST_EXPORT(SWITCH_STATUS_SOCKERR);
	SWITCH_CONST_EXPORT(SWITCH_STATUS_MORE_DATA);
	SWITCH_CONST_EXPORT(SWITCH_STATUS_NOTFOUND);
	SWITCH_CONST_EXPORT(SWITCH_STATUS_UNLOAD);
	SWITCH_CONST_EXPORT(SWITCH_STATUS_NOUNLOAD);
	SWITCH_CONST_EXPORT(SWITCH_STATUS_IGNORE);
	SWITCH_CONST_EXPORT(SWITCH_STATUS_TOO_SMALL);
	SWITCH_CONST_EXPORT(SWITCH_STATUS_FOUND);
	SWITCH_CONST_EXPORT(SWITCH_STATUS_CONTINUE);
	SWITCH_CONST_EXPORT(SWITCH_STATUS_TERM);
	SWITCH_CONST_EXPORT(SWITCH_STATUS_NOT_INITALIZED);
	SWITCH_CONST_EXPORT(SWITCH_STATUS_TOO_LATE);
	SWITCH_CONST_EXPORT(SWITCH_STATUS_XBREAK);
	SWITCH_CONST_EXPORT(SWITCH_STATUS_WINBREAK);
			
	SWITCH_CONST_EXPORT(SWITCH_LOG_DEBUG10);
	SWITCH_CONST_EXPORT(SWITCH_LOG_DEBUG9);
	SWITCH_CONST_EXPORT(SWITCH_LOG_DEBUG8);
	SWITCH_CONST_EXPORT(SWITCH_LOG_DEBUG7);
	SWITCH_CONST_EXPORT(SWITCH_LOG_DEBUG6);
	SWITCH_CONST_EXPORT(SWITCH_LOG_DEBUG5);
	SWITCH_CONST_EXPORT(SWITCH_LOG_DEBUG4);
	SWITCH_CONST_EXPORT(SWITCH_LOG_DEBUG3);
	SWITCH_CONST_EXPORT(SWITCH_LOG_DEBUG2);
	SWITCH_CONST_EXPORT(SWITCH_LOG_DEBUG1);
	SWITCH_CONST_EXPORT(SWITCH_LOG_DEBUG);
	SWITCH_CONST_EXPORT(SWITCH_LOG_INFO);
	SWITCH_CONST_EXPORT(SWITCH_LOG_NOTICE);
	SWITCH_CONST_EXPORT(SWITCH_LOG_WARNING);
	SWITCH_CONST_EXPORT(SWITCH_LOG_ERROR);
	SWITCH_CONST_EXPORT(SWITCH_LOG_CRIT);
	SWITCH_CONST_EXPORT(SWITCH_LOG_ALERT);
	SWITCH_CONST_EXPORT(SWITCH_LOG_CONSOLE);
	SWITCH_CONST_EXPORT(SWITCH_LOG_INVALID);
	SWITCH_CONST_EXPORT(SWITCH_LOG_UNINIT);
			
	SWITCH_CONST_EXPORT(SWITCH_CAUSE_NONE);
	SWITCH_CONST_EXPORT(SWITCH_CAUSE_UNALLOCATED_NUMBER);
	SWITCH_CONST_EXPORT(SWITCH_CAUSE_NO_ROUTE_TRANSIT_NET);
	SWITCH_CONST_EXPORT(SWITCH_CAUSE_NO_ROUTE_DESTINATION);
	SWITCH_CONST_EXPORT(SWITCH_CAUSE_CHANNEL_UNACCEPTABLE);
	SWITCH_CONST_EXPORT(SWITCH_CAUSE_CALL_AWARDED_DELIVERED);
	SWITCH_CONST_EXPORT(SWITCH_CAUSE_NORMAL_CLEARING);
	SWITCH_CONST_EXPORT(SWITCH_CAUSE_USER_BUSY);
	SWITCH_CONST_EXPORT(SWITCH_CAUSE_NO_USER_RESPONSE);
	SWITCH_CONST_EXPORT(SWITCH_CAUSE_NO_ANSWER);
	SWITCH_CONST_EXPORT(SWITCH_CAUSE_SUBSCRIBER_ABSENT);
	SWITCH_CONST_EXPORT(SWITCH_CAUSE_CALL_REJECTED);
	SWITCH_CONST_EXPORT(SWITCH_CAUSE_NUMBER_CHANGED);
	SWITCH_CONST_EXPORT(SWITCH_CAUSE_REDIRECTION_TO_NEW_DESTINATION);
	SWITCH_CONST_EXPORT(SWITCH_CAUSE_EXCHANGE_ROUTING_ERROR);
	SWITCH_CONST_EXPORT(SWITCH_CAUSE_DESTINATION_OUT_OF_ORDER);
	SWITCH_CONST_EXPORT(SWITCH_CAUSE_INVALID_NUMBER_FORMAT);
	SWITCH_CONST_EXPORT(SWITCH_CAUSE_FACILITY_REJECTED);
	SWITCH_CONST_EXPORT(SWITCH_CAUSE_RESPONSE_TO_STATUS_ENQUIRY);
	SWITCH_CONST_EXPORT(SWITCH_CAUSE_NORMAL_UNSPECIFIED);
	SWITCH_CONST_EXPORT(SWITCH_CAUSE_NORMAL_CIRCUIT_CONGESTION);
	SWITCH_CONST_EXPORT(SWITCH_CAUSE_NETWORK_OUT_OF_ORDER);
	SWITCH_CONST_EXPORT(SWITCH_CAUSE_NORMAL_TEMPORARY_FAILURE);
	SWITCH_CONST_EXPORT(SWITCH_CAUSE_SWITCH_CONGESTION);
	SWITCH_CONST_EXPORT(SWITCH_CAUSE_ACCESS_INFO_DISCARDED);
	SWITCH_CONST_EXPORT(SWITCH_CAUSE_REQUESTED_CHAN_UNAVAIL);
	SWITCH_CONST_EXPORT(SWITCH_CAUSE_PRE_EMPTED);
	SWITCH_CONST_EXPORT(SWITCH_CAUSE_FACILITY_NOT_SUBSCRIBED);
	SWITCH_CONST_EXPORT(SWITCH_CAUSE_OUTGOING_CALL_BARRED);
	SWITCH_CONST_EXPORT(SWITCH_CAUSE_INCOMING_CALL_BARRED);
	SWITCH_CONST_EXPORT(SWITCH_CAUSE_BEARERCAPABILITY_NOTAUTH);
	SWITCH_CONST_EXPORT(SWITCH_CAUSE_BEARERCAPABILITY_NOTAVAIL);
	SWITCH_CONST_EXPORT(SWITCH_CAUSE_SERVICE_UNAVAILABLE);
	SWITCH_CONST_EXPORT(SWITCH_CAUSE_BEARERCAPABILITY_NOTIMPL);
	SWITCH_CONST_EXPORT(SWITCH_CAUSE_CHAN_NOT_IMPLEMENTED);
	SWITCH_CONST_EXPORT(SWITCH_CAUSE_FACILITY_NOT_IMPLEMENTED);
	SWITCH_CONST_EXPORT(SWITCH_CAUSE_SERVICE_NOT_IMPLEMENTED);
	SWITCH_CONST_EXPORT(SWITCH_CAUSE_INVALID_CALL_REFERENCE);
	SWITCH_CONST_EXPORT(SWITCH_CAUSE_INCOMPATIBLE_DESTINATION);
	SWITCH_CONST_EXPORT(SWITCH_CAUSE_INVALID_MSG_UNSPECIFIED);
	SWITCH_CONST_EXPORT(SWITCH_CAUSE_MANDATORY_IE_MISSING);
	SWITCH_CONST_EXPORT(SWITCH_CAUSE_MESSAGE_TYPE_NONEXIST);
	SWITCH_CONST_EXPORT(SWITCH_CAUSE_WRONG_MESSAGE);
	SWITCH_CONST_EXPORT(SWITCH_CAUSE_IE_NONEXIST);
	SWITCH_CONST_EXPORT(SWITCH_CAUSE_INVALID_IE_CONTENTS);
	SWITCH_CONST_EXPORT(SWITCH_CAUSE_WRONG_CALL_STATE);
	SWITCH_CONST_EXPORT(SWITCH_CAUSE_RECOVERY_ON_TIMER_EXPIRE);
	SWITCH_CONST_EXPORT(SWITCH_CAUSE_MANDATORY_IE_LENGTH_ERROR);
	SWITCH_CONST_EXPORT(SWITCH_CAUSE_PROTOCOL_ERROR);
	SWITCH_CONST_EXPORT(SWITCH_CAUSE_INTERWORKING);
	SWITCH_CONST_EXPORT(SWITCH_CAUSE_SUCCESS);
	SWITCH_CONST_EXPORT(SWITCH_CAUSE_ORIGINATOR_CANCEL);
	SWITCH_CONST_EXPORT(SWITCH_CAUSE_CRASH);
	SWITCH_CONST_EXPORT(SWITCH_CAUSE_SYSTEM_SHUTDOWN);
	SWITCH_CONST_EXPORT(SWITCH_CAUSE_LOSE_RACE);
	SWITCH_CONST_EXPORT(SWITCH_CAUSE_MANAGER_REQUEST);
	SWITCH_CONST_EXPORT(SWITCH_CAUSE_BLIND_TRANSFER);
	SWITCH_CONST_EXPORT(SWITCH_CAUSE_ATTENDED_TRANSFER);
	SWITCH_CONST_EXPORT(SWITCH_CAUSE_ALLOTTED_TIMEOUT);
	SWITCH_CONST_EXPORT(SWITCH_CAUSE_USER_CHALLENGE);
	SWITCH_CONST_EXPORT(SWITCH_CAUSE_MEDIA_TIMEOUT);
	SWITCH_CONST_EXPORT(SWITCH_CAUSE_PICKED_OFF);
	SWITCH_CONST_EXPORT(SWITCH_CAUSE_USER_NOT_REGISTERED);
	SWITCH_CONST_EXPORT(SWITCH_CAUSE_PROGRESS_TIMEOUT);
	SWITCH_CONST_EXPORT(SWITCH_CAUSE_INVALID_GATEWAY);
	SWITCH_CONST_EXPORT(SWITCH_CAUSE_GATEWAY_DOWN);
	SWITCH_CONST_EXPORT(SWITCH_CAUSE_INVALID_URL);
	SWITCH_CONST_EXPORT(SWITCH_CAUSE_INVALID_PROFILE);
	SWITCH_CONST_EXPORT(SWITCH_CAUSE_NO_PICKUP);
	SWITCH_CONST_EXPORT(SWITCH_CAUSE_SRTP_READ_ERROR);
	
	SWITCH_CONST_EXPORT(CS_NEW);
	SWITCH_CONST_EXPORT(CS_INIT);
	SWITCH_CONST_EXPORT(CS_ROUTING);
	SWITCH_CONST_EXPORT(CS_SOFT_EXECUTE);
	SWITCH_CONST_EXPORT(CS_EXECUTE);
	SWITCH_CONST_EXPORT(CS_EXCHANGE_MEDIA);
	SWITCH_CONST_EXPORT(CS_PARK);
	SWITCH_CONST_EXPORT(CS_CONSUME_MEDIA);
	SWITCH_CONST_EXPORT(CS_HIBERNATE);
	SWITCH_CONST_EXPORT(CS_RESET);
	SWITCH_CONST_EXPORT(CS_HANGUP);
	SWITCH_CONST_EXPORT(CS_REPORTING);
	SWITCH_CONST_EXPORT(CS_DESTROY);
	SWITCH_CONST_EXPORT(CS_NONE);
	
	SWITCH_CONST_EXPORT(CCS_DOWN);
	SWITCH_CONST_EXPORT(CCS_DIALING);
	SWITCH_CONST_EXPORT(CCS_RINGING);
	SWITCH_CONST_EXPORT(CCS_EARLY);
	SWITCH_CONST_EXPORT(CCS_ACTIVE);
	SWITCH_CONST_EXPORT(CCS_HELD);
	SWITCH_CONST_EXPORT(CCS_RING_WAIT);
	SWITCH_CONST_EXPORT(CCS_HANGUP);
	SWITCH_CONST_EXPORT(CCS_UNHELD);
	
	SWITCH_CONST_EXPORT(CF_ANSWERED);
	SWITCH_CONST_EXPORT(CF_OUTBOUND);
	SWITCH_CONST_EXPORT(CF_EARLY_MEDIA);
	SWITCH_CONST_EXPORT(CF_BRIDGE_ORIGINATOR);
	SWITCH_CONST_EXPORT(CF_UUID_BRIDGE_ORIGINATOR);
	SWITCH_CONST_EXPORT(CF_TRANSFER);
	SWITCH_CONST_EXPORT(CF_ACCEPT_CNG);
	SWITCH_CONST_EXPORT(CF_REDIRECT);
	SWITCH_CONST_EXPORT(CF_BRIDGED);
	SWITCH_CONST_EXPORT(CF_HOLD);
	SWITCH_CONST_EXPORT(CF_SERVICE);
	SWITCH_CONST_EXPORT(CF_TAGGED);
	SWITCH_CONST_EXPORT(CF_WINNER);
	SWITCH_CONST_EXPORT(CF_CONTROLLED);
	SWITCH_CONST_EXPORT(CF_PROXY_MODE);
	SWITCH_CONST_EXPORT(CF_PROXY_OFF);
	SWITCH_CONST_EXPORT(CF_SUSPEND);
	SWITCH_CONST_EXPORT(CF_EVENT_PARSE);
	SWITCH_CONST_EXPORT(CF_GEN_RINGBACK);
	SWITCH_CONST_EXPORT(CF_RING_READY);
	SWITCH_CONST_EXPORT(CF_BREAK);
	SWITCH_CONST_EXPORT(CF_BROADCAST);
	SWITCH_CONST_EXPORT(CF_UNICAST);
	SWITCH_CONST_EXPORT(CF_VIDEO);
	SWITCH_CONST_EXPORT(CF_EVENT_LOCK);
	SWITCH_CONST_EXPORT(CF_EVENT_LOCK_PRI);
	SWITCH_CONST_EXPORT(CF_RESET);
	SWITCH_CONST_EXPORT(CF_ORIGINATING);
	SWITCH_CONST_EXPORT(CF_STOP_BROADCAST);
	SWITCH_CONST_EXPORT(CF_PROXY_MEDIA);
	SWITCH_CONST_EXPORT(CF_INNER_BRIDGE);
	SWITCH_CONST_EXPORT(CF_REQ_MEDIA);
	SWITCH_CONST_EXPORT(CF_VERBOSE_EVENTS);
	SWITCH_CONST_EXPORT(CF_PAUSE_BUGS);
	SWITCH_CONST_EXPORT(CF_DIVERT_EVENTS);
	SWITCH_CONST_EXPORT(CF_BLOCK_STATE);
	SWITCH_CONST_EXPORT(CF_FS_RTP);
	SWITCH_CONST_EXPORT(CF_REPORTING);
	SWITCH_CONST_EXPORT(CF_PARK);
	SWITCH_CONST_EXPORT(CF_TIMESTAMP_SET);
	SWITCH_CONST_EXPORT(CF_ORIGINATOR);
	SWITCH_CONST_EXPORT(CF_XFER_ZOMBIE);
	SWITCH_CONST_EXPORT(CF_MEDIA_ACK);
	SWITCH_CONST_EXPORT(CF_THREAD_SLEEPING);
	SWITCH_CONST_EXPORT(CF_DISABLE_RINGBACK);
	SWITCH_CONST_EXPORT(CF_NOT_READY);
	SWITCH_CONST_EXPORT(CF_SIGNAL_BRIDGE_TTL);
	SWITCH_CONST_EXPORT(CF_MEDIA_BRIDGE_TTL);
	SWITCH_CONST_EXPORT(CF_BYPASS_MEDIA_AFTER_BRIDGE);
	SWITCH_CONST_EXPORT(CF_LEG_HOLDING);
	SWITCH_CONST_EXPORT(CF_BROADCAST_DROP_MEDIA);
	SWITCH_CONST_EXPORT(CF_EARLY_HANGUP);
	SWITCH_CONST_EXPORT(CF_MEDIA_SET);
	SWITCH_CONST_EXPORT(CF_CONSUME_ON_ORIGINATE);
	SWITCH_CONST_EXPORT(CF_PASSTHRU_PTIME_MISMATCH);
	SWITCH_CONST_EXPORT(CF_BRIDGE_NOWRITE);
	SWITCH_CONST_EXPORT(CF_RECOVERED);
	SWITCH_CONST_EXPORT(CF_JITTERBUFFER);
	SWITCH_CONST_EXPORT(CF_JITTERBUFFER_PLC);
	SWITCH_CONST_EXPORT(CF_DIALPLAN);
	SWITCH_CONST_EXPORT(CF_BLEG);
	SWITCH_CONST_EXPORT(CF_BLOCK_BROADCAST_UNTIL_MEDIA);
	SWITCH_CONST_EXPORT(CF_CNG_PLC);
	SWITCH_CONST_EXPORT(CF_ATTENDED_TRANSFER);
	SWITCH_CONST_EXPORT(CF_LAZY_ATTENDED_TRANSFER);
	SWITCH_CONST_EXPORT(CF_SIGNAL_DATA);
	SWITCH_CONST_EXPORT(CF_SIMPLIFY);
	SWITCH_CONST_EXPORT(CF_ZOMBIE_EXEC);
	SWITCH_CONST_EXPORT(CF_INTERCEPT);
	SWITCH_CONST_EXPORT(CF_INTERCEPTED);
	SWITCH_CONST_EXPORT(CF_VIDEO_REFRESH_REQ);
	SWITCH_CONST_EXPORT(CF_MANUAL_VID_REFRESH);
	SWITCH_CONST_EXPORT(CF_SERVICE_AUDIO);
	SWITCH_CONST_EXPORT(CF_SERVICE_VIDEO);
	SWITCH_CONST_EXPORT(CF_ZRTP_PASSTHRU_REQ);
	SWITCH_CONST_EXPORT(CF_ZRTP_PASSTHRU);
	SWITCH_CONST_EXPORT(CF_ZRTP_HASH);
	SWITCH_CONST_EXPORT(CF_CHANNEL_SWAP);
	SWITCH_CONST_EXPORT(CF_DEVICE_LEG);
	SWITCH_CONST_EXPORT(CF_FINAL_DEVICE_LEG);
	SWITCH_CONST_EXPORT(CF_PICKUP);
	SWITCH_CONST_EXPORT(CF_CONFIRM_BLIND_TRANSFER);
	SWITCH_CONST_EXPORT(CF_NO_PRESENCE);
	SWITCH_CONST_EXPORT(CF_CONFERENCE);
	SWITCH_CONST_EXPORT(CF_CONFERENCE_ADV);
	SWITCH_CONST_EXPORT(CF_RECOVERING);
	SWITCH_CONST_EXPORT(CF_RECOVERING_BRIDGE);
	SWITCH_CONST_EXPORT(CF_TRACKED);
	SWITCH_CONST_EXPORT(CF_TRACKABLE);
	SWITCH_CONST_EXPORT(CF_NO_CDR);
	SWITCH_CONST_EXPORT(CF_EARLY_OK);
	SWITCH_CONST_EXPORT(CF_MEDIA_TRANS);
	SWITCH_CONST_EXPORT(CF_HOLD_ON_BRIDGE);
	SWITCH_CONST_EXPORT(CF_SECURE);
	SWITCH_CONST_EXPORT(CF_LIBERAL_DTMF);
	SWITCH_CONST_EXPORT(CF_SLA_BARGE);
	SWITCH_CONST_EXPORT(CF_SLA_BARGING);
	SWITCH_CONST_EXPORT(CF_PROTO_HOLD);
	SWITCH_CONST_EXPORT(CF_HOLD_LOCK);
	SWITCH_CONST_EXPORT(CF_VIDEO_POSSIBLE);
	SWITCH_CONST_EXPORT(CF_NOTIMER_DURING_BRIDGE);
	SWITCH_CONST_EXPORT(CF_PASS_RFC2833);
	SWITCH_CONST_EXPORT(CF_T38_PASSTHRU);
	SWITCH_CONST_EXPORT(CF_DROP_DTMF);
	SWITCH_CONST_EXPORT(CF_REINVITE);
	SWITCH_CONST_EXPORT(CF_AUTOFLUSH_DURING_BRIDGE);
	SWITCH_CONST_EXPORT(CF_RTP_NOTIMER_DURING_BRIDGE);
	SWITCH_CONST_EXPORT(CF_AVPF);
	SWITCH_CONST_EXPORT(CF_AVPF_MOZ);
	SWITCH_CONST_EXPORT(CF_ICE);
	SWITCH_CONST_EXPORT(CF_DTLS);
	SWITCH_CONST_EXPORT(CF_VERBOSE_SDP);
	SWITCH_CONST_EXPORT(CF_DTLS_OK);
	SWITCH_CONST_EXPORT(CF_3PCC);
	SWITCH_CONST_EXPORT(CF_VIDEO_PASSIVE);
	SWITCH_CONST_EXPORT(CF_NOVIDEO);
	SWITCH_CONST_EXPORT(CF_VIDEO_BITRATE_UNMANAGABLE);
	SWITCH_CONST_EXPORT(CF_VIDEO_ECHO);
	SWITCH_CONST_EXPORT(CF_VIDEO_BLANK);
	SWITCH_CONST_EXPORT(CF_VIDEO_WRITING);
	SWITCH_CONST_EXPORT(CF_SLA_INTERCEPT);
	SWITCH_CONST_EXPORT(CF_VIDEO_BREAK);
	SWITCH_CONST_EXPORT(CF_AUDIO_PAUSE_READ);
	SWITCH_CONST_EXPORT(CF_AUDIO_PAUSE_WRITE);
	SWITCH_CONST_EXPORT(CF_VIDEO_PAUSE_READ);
	SWITCH_CONST_EXPORT(CF_VIDEO_PAUSE_WRITE);
	SWITCH_CONST_EXPORT(CF_BYPASS_MEDIA_AFTER_HOLD);
	SWITCH_CONST_EXPORT(CF_HANGUP_HELD);
	SWITCH_CONST_EXPORT(CF_CONFERENCE_RESET_MEDIA);
	SWITCH_CONST_EXPORT(CF_VIDEO_DECODED_READ);
	SWITCH_CONST_EXPORT(CF_VIDEO_DEBUG_READ);
	SWITCH_CONST_EXPORT(CF_VIDEO_DEBUG_WRITE);
	SWITCH_CONST_EXPORT(CF_VIDEO_ONLY);
	SWITCH_CONST_EXPORT(CF_VIDEO_READY);
	SWITCH_CONST_EXPORT(CF_VIDEO_MIRROR_INPUT);
	SWITCH_CONST_EXPORT(CF_VIDEO_READ_FILE_ATTACHED);
	SWITCH_CONST_EXPORT(CF_VIDEO_WRITE_FILE_ATTACHED);
	SWITCH_CONST_EXPORT(CF_3P_MEDIA_REQUESTED);
	SWITCH_CONST_EXPORT(CF_3P_NOMEDIA_REQUESTED);
	SWITCH_CONST_EXPORT(CF_3P_NOMEDIA_REQUESTED_BLEG);
	SWITCH_CONST_EXPORT(CF_IMAGE_SDP);
	SWITCH_CONST_EXPORT(CF_VIDEO_SDP_RECVD);
	SWITCH_CONST_EXPORT(CF_TEXT_SDP_RECVD);
	SWITCH_CONST_EXPORT(CF_HAS_TEXT);
	SWITCH_CONST_EXPORT(CF_TEXT_POSSIBLE);
	SWITCH_CONST_EXPORT(CF_TEXT_PASSIVE);
	SWITCH_CONST_EXPORT(CF_TEXT_ECHO);
	SWITCH_CONST_EXPORT(CF_TEXT_ACTIVE);
	SWITCH_CONST_EXPORT(CF_TEXT_IDLE);
	SWITCH_CONST_EXPORT(CF_TEXT_LINE_BASED);
	SWITCH_CONST_EXPORT(CF_QUEUE_TEXT_EVENTS);
	SWITCH_CONST_EXPORT(CF_FIRE_TEXT_EVENTS);
	SWITCH_CONST_EXPORT(CF_MSRP);
	SWITCH_CONST_EXPORT(CF_MSRPS);
	SWITCH_CONST_EXPORT(CF_WANT_MSRP);
	SWITCH_CONST_EXPORT(CF_WANT_MSRPS);
	SWITCH_CONST_EXPORT(CF_RTT);
	SWITCH_CONST_EXPORT(CF_WANT_RTT);
	SWITCH_CONST_EXPORT(CF_AUDIO);
	SWITCH_CONST_EXPORT(CF_AWAITING_STREAM_CHANGE);
	SWITCH_CONST_EXPORT(CF_PROCESSING_STREAM_CHANGE);
	SWITCH_CONST_EXPORT(CF_STREAM_CHANGED);

	SWITCH_CONST_EXPORT(SWITCH_CALL_DIRECTION_INBOUND);
	SWITCH_CONST_EXPORT(SWITCH_CALL_DIRECTION_OUTBOUND);
}