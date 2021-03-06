Indigo (http://www.indigodomo.com) plugin for August Smart Locks and Doorbell

# Requirements #

Configurations supported:
* August Lock with August Doorbell
* August Lock Pro (now supports DoorSense as well) with Doorbell 
* All of the above, with addition of August Keypad

Configurations supported (and will likely work), but untested:
* August Lock with August Connect
* August Lock Pro with Connect
* August Doorbell with without August Lock

Please report on the forums if you have problems with, or are working successful with these configurations.

Configurations unsupported:
* August Lock without a bridge (Doorbell or Connect)
* August Lock Pro without a bridge (Doorbell or Connect)

Note about the August Pro: The August Pro is a ZWave compatible lock that works directly with Indigo without the need for this plugin.  I have one myself, and have tested this configuration.  This is the best configuration in my opinion, as it eliminates the communication to and from the cloud to lock, unlock, and validate status of the lock.  For August Pro users, this plugin adds support for events including Lock by Person, Unlock by Person.  Also, you will still be able to delegate the Auto-Lock and Auto-Unlock to Indigo rather than depending on the August App (See features for more information).

# Features #
* Supports the Indigo lock device type with the typical states - Lock, Unlock, Status Requests, and even Battery Level.  
* Uses the August cloud API's to control your lock, rather than bluetooth.  The bluetooth control is very hard to set up and control.
* Supports a seperate device for the August Pro DoorSense.  The DoorSense status (whether the door is opened or closed) is recorded and available to use in triggers and conditions.
* Timer states for the amount of time that your lock has been unlocked or locked, allowing you fully delegate the auto lock and auto unlock features from August to Indigo.  This way, as an example, you can tweak the behavior of the auto lock (such as not locking the door blindly every 3 minutes) to instead base this behavior on a combination of other data - such as house presence.
* Supports the use of the August doorbell as a bridge.  Once a lock that is using the doorbell as a bridge is set up, you will also receive doorbell events (motion, missed calls) in Indigo and can configure triggers.  You do not need to set up the doorbell in Indigo as a separate device for this to happen.
* Supports "via XXXX" in the Indigo event log to see how the lock state was changed from outside of Indigo (August App, August App Remote, HomeKit, Manually, August Keypad).
* Supports the August keypad.
* Automatic update notifications.

# Install Notes #
* The plugin will guide you thorough it.  You will have to get a verification code from August, sent to your email or phone, for the plugin to work.  August verifies based on a per device basis, not once per account.  The plugin must verify a unique ID associated with your August account in order for the plugin to work.

# Events #
* All events can be configured with a maximum latency.  This prevents events from being triggered if they occurred too long in the past.  Occasionally events can be discovered delayed, in particular if your bridge goes offline.  Read the Plugin Limitations for more details.

| Event                | Description                                                                                                                                                                                                                  |
|:---------------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| doorbell_motion_detected       | Event that fires when a motion_detected, or call_missed.  Requires a doorbell bridge for these events to occur.                                                                                       |
| lockByPerson       | Event that can trigger upon a lock or unlock event by a known person.  Options are available to include remote methods (HomeKit, August App Remote).  Note that HomeKit is not possible to decipher if the user was on the local network or remote.                                                                                       |
| lockByUnknownPerson       | Event that can trigger upon a lock or unlock event by a unknown person.  This will include manual unlocks.                                                                                       |
| invalidCode       | Event that can trigger when a invalid key code is entered.  Requires the August Keypad.                                                                                       |

# States #

| State                | Type    | Description                                                                                                                                                                                                                  |
|:---------------------|:--------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| lastSentIndigoUpdateTime       | String / DateTime  | Contains the timestamp of the last time that a status change originated from Indigo.                                                                                       |
| lastStateChangeTime       | String / DateTime  | Contains the timestamp of the last time that the lock was locked or unlocked internally within Indigo or externally.                                                                                       |
| locked_minutes       | String / DateTime  | Contains a timer of how long the lock has been locked.  Set to 0 if the lock is currently unlocked.                                                                                       |
| unlocked_minutes       | String / DateTime  | Contains a timer of how long the lock has been unlocked.  Set to 0 if the lock is currently locked.  Note that this time can be altered by using the "Reset Unlock Timer" Action.                                                                                       |

# Variables #
* The plugin automatically creates variables containing timers lock/unlock events.  The lock/unlock timers are the same as the locked_minutes and unlocked_minutes states, mentioned in the table above.  Any changes to these variables will be overwritten.  To reset the unlock_minutes timer, use the Action described below.
* If a doorbell is found linked to your account, the plugin will also create a timer for the amount of time since a motion event has occured.  It will be named <HOUSE NAME>_last_motion_minutes.  Every time that a a "motion detected" event occurs, this timer will reset to zero.  This can be used as an additional data point to decide when to auto-lock a door.

# Actions #
* An action to reset the Unlock Timer is available.  Useful if you are using the unlock timer for auto lock.

# Limitations #
* The plugin works based on polling the August servers for updates to the lock status and your house activity feed.  The plugin supports 10, 15, 30, 45, 60, 90 second polling intervals.  At this time there does not seem to be any better way to receive updates as they happen.  The house feed provides more information, but sometimes is lagged because of the way the August devices work.  Therefore, the plugin will prefer the house activity feed but periodically check the status API for sanity.  Given that the activity feed is the only source for doorbell events, such as motion detected, missed calls, etc., there can be a lag for these events to be discovered by the plugin.  Because of this, I've added maximum latency fields to the event triggers.
* Sending lock and unlock commands from Indigo can occasionally have a lag, sometimes up to 20 seconds.  I've seen this happen while manually triggering the API's, so it has nothing to do with the plugin.  The plugin has a long timeout period, but sometimes failures do happen.  I'm guessing it has to do with August's servers connecting to the bridge which connects to the lock, the round trip can take time.  I recommend creating sanity triggers or schedules to ensure that a lock takes place successfully.
