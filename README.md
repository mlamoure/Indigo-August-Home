Indigo (http://www.indigodomo.com) plugin for August Smart Locks and Doorbell

# Requirements #
In addition to the August Lock, you will need either a August Doorbell or August Connect (untested, as I don't have one) in order for the plugin to work. Without one of these items, the August servers don't know the status of your lock and cannot control it remotely.  The keypad is optional but supported.

# Features #
* Supports the Indigo lock device type with the typical states - Lock, Unlock, Status Requests, and even Battery Level.  The intent is to give you the tools to delegate the "Auto Lock" functionality of the August to Indigo.  This way, you can tweak the behavior of the auto lock (such as not locking the door every 3 minutes) to instead base this behavior on a combination of other data - such as house presence.
* Uses the August cloud API's to control your lock, rather than bluetooth.  The bluetooth control is very hard to set up and control.
* Supports the use of the August doorbell as a bridge.  Once a lock that is using the doorbell as a bridge is set up, you will also receive doorbell events (motion, missed calls) in Indigo and can configure triggers.  You do not need to set up the doorbell in Indigo as a separate device for this to happen.
* Supports "via XXXX" to see how the lock state was changed from outside of Indigo (August App, August App Remote, HomeKit, Manually, August Keypad).  Triggers can exclude remote methods from the trigger event.
* Automatically creates device states and variable folder / variables for tracking the time since the last lock and unlock for each lock. Useful in creating Auto Lock feature based on variable values.
* Automatically creates house variables for tracking the last time since a motion event has occurred.
* Supports the August keypad including triggers for invalid entry.
* Automatic update notifications.

# Install Notes #
* The plugin will guide you thorough it.  You will have to get a verification code from August, sent to your email or phone, for the plugin to work.  August verifies based on a per device basis, not once per account.  The plugin must verify a unique ID associated with your August account in order for the plugin to work.

# Triggers #
* Lock and Unlock events by known people (with ability to exclude remote events - August App or HomeKit).  Note that HomeKit is not possible to decipher if the user was on the local network or remote.
* Lock and Unlock events by unknown people (typically manual use of the lock)
* Doorbell events - Missed call, Motion detected
* Keypad events - Invalid code entry

# Limitations #
* The plugin works based on polling the August servers for updates to the lock status and your house activity feed.  The plugin supports 10, 15, 30, 45, 60, 90 second polling intervals.  At this time there does not seem to be any better way to receive updates as they happen.  The house feed provides more information, but sometimes is lagged because of the way the August devices work.  Therefore, the plugin will prefer the house activity feed but periodically check the status API for sanity.  Given that the activity feed is the only source for doorbell events, such as motion detected, missed calls, etc., there can be a lag for these events to be discovered by the plugin.  Because of this, I've added maximum latency fields to the event triggers.
* Sending lock and unlock commands from Indigo can have a lag, sometimes up to 20 seconds.  I've seen this happen while manually triggering the API's, so it has nothing to do with the plugin.  The plugin has a long timeout period, but sometimes failures do happen.  I'm guessing it has to do with August's servers connecting to the bridge which connects to the lock, the round trip can take time.  I recommend creating sanity triggers or schedules to ensure that a lock takes place successfully.

# Untested but supported #
* Multiple locks
* Multiple houses
* August connect as a bridge
