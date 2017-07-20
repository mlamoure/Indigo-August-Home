Indigo (http://www.indigodomo.com) plugin for August Smart Locks and Doorbell

# Features #
* Obviously supports the Indigo lock device type - Lock, Unlock, Status Requests.  The intent is to give you the tools to delegate the "Auto Lock" functionality of the August to Indigo.  This way, you can tweak the behavior of the auto lock (such as not locking the door every 3 minutes) to instead base this behavior on a combination of other data - such as house presence.
* Uses the August cloud API's to control your lock, rather than bluetooth.  The bluetooth control is very hard to set up and control.
* Supports the use of the August doorbell as a bridge.  Once a lock that is using the doorbell as a bridge is set up, you will also receive doorbell events (motion, missed calls) in Indigo and can configure triggers.  You do not need to set up the doorbell in Indigo as a separate device for this to happen.
* Supports "via XXXX" to see how the lock state was changed from outside of Indigo (August App, August App Remote, HomeKit, Manually).  Triggers can exclude remote methods from the trigger event.
* Automatically creates variable folder and variables for tracking the lock and unlock time for each lock.  Usefull in creating Auto Lock feature based on variable values.

# Install Notes #
* The plugin will guide you thorough it.  You will have to get a verification code from August, sent to your email or phone, for the plugin to work.  August verifies based on a per device basis, not once per account.  The plugin must verify a unique ID associated with your August account in order for the plugin to work.

# Triggers #
* Lock and Unlock events by known people
* Lock and Unlock events by unknown people (typically manual use of the lock)
* Doorbell events - Missed call, Motion detected

# Limitations #
* The plugin works based on polling the August servers for updates to the lock status and your house activity feed.  The plugin supports 15, 30, 45, 60, 90 second polling intervals.  At this time there does not seem to be any better way to receive updates as they happen.  I believe that since August does not have a web application, they do not have a mechanism in their API for web-based event subscriptions.  The notifications on your phone likely use non standard ways of getting notifications as they happen.  Because of this, I've added maximum latency fields to the event triggers.
* Even if you set your polling frequency to a low setting, you can still experience lag in the plugin receiving events.  This is because the plugin obtains the event triggers from the August activity log for a given home, which sometimes lags the log records.  For example, if someone walks up to your house and motion is detected, you will get a notification on your phone immediately (this plugin cannot get this notification for the previously mentioned reasons).  Despite this happening, the activity log that August maintains will delay for the video to stop recording, and it will change behavior if the visitor rings the doorbell.  The result is that the activity log will be slightly delayed from real-time.  At present I don't believe there is anything that can be done about this until there is a web-standard way to get on-demand notifications.  The event triggers in Indigo can be configured with maximum lag settings.
* Sending lock and unlock commands from Indigo can have a lag, sometimes up to 20 seconds.  I've seen this happen while manually triggering the API's, so it has nothing to do with the plugin, though I'm still working to get the plugin to gracefully deal with this when it happens.  I'm guessing it has to do with August's servers connecting to the bridge which connects to the lock, the round trip can take time.

# Untested but supported #
* Multiple locks
* Multiple houses
* August connect as a bridge
