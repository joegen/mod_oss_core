var switch_isolate = require("isolate");
var dialplan = utils.multiline(function() {
  /*
  /<?xml version="1.0" encoding="UTF-8" standalone="no"?>
  <document type="freeswitch/xml">
    <section name="dialplan" description="Dial Plan For FreeSwitch">
      <context name="public">
        <extension name="mod_oss_core">
           <condition field="destination_number" expression="(.*?)">
              <action application="oss_core_json_app" data='{ "method" : "ring" }'/>
              <action application="oss_core_json_app" data='{ "method" : "answer" }'/>
              <action application="park" data=""/>
           </condition>
        </extension>
      </context>
    </section>
  </document>
  */
});

switch_channel_log("notice", "mod_oss_core script started");
switch_channel_log("notice", JSON.stringify(switch_core_get_variables(), null, 2));

var hadDialplan = switch_enable_xml_handling("dialplan");
var hasEvents = switch_enable_event_handling();

if (hadDialplan) {
    switch_isolate.on("handle_switch_xml", function(args) {
      var result = new Object();
      result.result = dialplan;
      return result;
    });
}

if (hasEvents) {
    switch_isolate.on("handle_switch_event", function(event)
    {
      if (event["Event-Name"] === "CHANNEL_PARK") {
        switch_app_execute(event["Unique-ID"], "bridge", "{dtmf_type=info}sofia/external/joegen-test-linphone@${local_ip_v4}:35060",
          function(result){
            switch_channel_log("info", JSON.stringify(result, null, 2));
          });
      }
    });
}

switch_isolate.on("handle_switch_json_api", function(args)
{
    // oss_core_json_api { "method" : "sum", "arguments" : {"var1" : 10, "var2" : 20} }
    var result = new Object();
    if (args.method === "sum") {
        var a = args.arguments.var1;
        var b = args.arguments.var2;
        result.result = (a + b).toString();
    }
    return result;
});

switch_isolate.on("handle_switch_json_app", function(args, session)
{
    if (args.method === "ring") {
        var channel = switch_core_session_get_channel(session);
         if (channel) {
             switch_channel_ring_ready(channel);
         }
    } else if (args.method === "answer") {
        var channel = switch_core_session_get_channel(session);
         if (channel) {
             switch_channel_answer(channel);
         }
    }
});