
Using this plugin I have sucessfully delegated the "Auto Lock" functionality of my August to Indigo.  This way, I can tweak the behavior of the auto lock (such as not locking the door every 3 minutes) to instead base this behavior on a combination of other data - such as house presence.

Features:
	- Obviously supports the Indigo lock device type - Lock, Unlock, Status Requests
	- Supports the use of the August doorbell as a bridge.  Once a lock that is using the doorbell as a bridge is set up, you will also recieve doorbell events (motion, calls) in Indigo and can configure triggers.  You do not need to set up the doorbell in Indigo as a seperate device for this to happen.
	- Supports "via XXXX" to see how the lock state was changed from outside of Indigo (August App, August App Remote, HomeKit, Manually).  Triggers can exclude remote methods from the trigger event.

Install Notes:
	- The plugin will guide you thorough it.  You will have to get a verification code from August, sent to your email or phone, for the plugin to work.  August verifies based on a per device basis, not once per account.  The plugin must verify a unique ID associated with your August account in order for the plugin to work.

Triggers:
	- Lock and Unlock events by known people
	- Lock and Unlock events by unknown people (usually manual use of the lock)
	- Doorbell events - Missed call, Motion detected

Limitations:
	- The plugin works based on polling the August servers for updates to the lock status and your house activty feed.  The plugin supports 15, 30, 45, 60, 90 second polling intervals.  At this time there does not seem to be any better way to recieve updates as they happen.  I believe that since August does not have a web application, they do not have a mechanism in their API For event subscriptions.  The notifications on your phone likely use non standard ways of getting notifications as they happen.  Because of this, I've added maximum latency fields to the event triggers.
	- The lock and unlock commands can have a lag, sometimes up to 20 seconds.  I've seen this happen while manually triggering the API's, so it has nothing to do with the plugin, though I'm still working to get the plugin to gracefully deal with this when it happens.  I'm guessing it has to do with August's servers connecting to the bridge which connects to the lock, the round trip can take time.


Untested but supported:
	- Multiple locks
	- Multiple houses
	- August connect as a bridge