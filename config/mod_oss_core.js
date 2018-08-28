var Timer = require("async");
var freeswitch = require("isolate");

switch_enable_xml_handling("dialplan");
switch_enable_event_handling();

switch_channel_log("notice", "mod_oss_core script started");
//switch_channel_log("notice", JSON.stringify(switch_core_get_variables(), null, 2));

freeswitch.on("handle_switch_xml", function(args, promise) {
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
  switch_promise_set_result(promise, dialplan);
});

freeswitch.on("handle_switch_event", function(event)
{
  if (event["Event-Name"] === "CHANNEL_PARK") {
    switch_app_execute(event["Unique-ID"], "bridge", "{dtmf_type=info}sofia/external/joegen-test-linphone@${local_ip_v4}:35060",
      function(result){
        switch_channel_log("info", "Bridge application ENDED");
      });
  }
});


var on_sleep_timer = function(promise, start) {
  var now = new Date();
  var elapsed = now.getTime() - start.getTime();
  switch_channel_log("info", "elapsed: " + elapsed + " milliseconds");
  switch_promise_set_result(promise, "Hello Timers!");
}

freeswitch.on("handle_switch_json_api", function(args, promise)
{
    var result = "";
    if (args.method === "sum") {
        // oss_core_json_api { "method" : "sum", "arguments" : {"var1" : 10, "var2" : 20} }
        var a = args.arguments.var1;
        var b = args.arguments.var2;
        result = (a + b * 100).toString();
        switch_promise_set_result(promise, result);
    } else if (args.method === "sleep") {
        // oss_core_json_api { "method" : "sleep", "arguments" : {"expire" : 5} }
        var expires = parseInt(args.arguments.expire, 10);
        Timer.setTimeout(on_sleep_timer, expires * 1000, [promise, new Date()]);
        switch_channel_log("info", "Sleeping for " + expires + " seconds");
    } else {
        switch_promise_set_result(promise, "undefined");
    }
});

freeswitch.on("handle_switch_json_app", function(args, promise)
{
    switch_channel_log("info", args.method + " enter");
    var session = switch_promise_get_session(promise);
    if (session && args.method === "ring") {
        var channel = switch_core_session_get_channel(session);
         if (channel) {
             switch_channel_ring_ready(channel);
         }
    } else if (session && args.method === "answer") {
        var channel = switch_core_session_get_channel(session);
         if (channel) {
             switch_channel_answer(channel);
         }
    }
    switch_promise_set_result(promise, "ok");
});