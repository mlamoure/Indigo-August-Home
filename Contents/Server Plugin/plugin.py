#! /usr/bin/env python
# -*- coding: utf-8 -*-
####################

import indigo

import os
import sys
import datetime
import time
import requests
import json
import uuid

API_KEY = "727dba56-fe45-498d-b4aa-293f96aae0e5"
CONTENT_TYPE = "application/json"
USER_AGENT = "August/Luna-3.2.2"
ACCEPT_VERSION = "0.0.1"
DEFAULT_POLLING_INTERVAL = 90  # number of seconds between each poll
MAXIMUM_ACTIVITY_ITEMS = 10 # Max number of activity items to request per house to process for latest state information
TIMEOUT_PUT = 10
TIMEOUT_GET = 4
ACTIVITY_MATCHING_THRESHOLD = 2 # The number of seconds as a threshold on the difference between server and local timestamps for event matching
FORCED_SERVER_REFRESH_RATE = 60 # number of minutes that the plugin will double check the accuracy of the device states

################################################################################
class Plugin(indigo.PluginBase):
	########################################
	def __init__(self, pluginId, pluginDisplayName, pluginVersion, pluginPrefs):
		super(Plugin, self).__init__(pluginId, pluginDisplayName, pluginVersion, pluginPrefs)
		self.debug = pluginPrefs.get("chkDebug", False)
		self.vPassword = False
		self.vInstallId = False

		if not "installId" in pluginPrefs:
			self.pluginPrefs["installId"] = str(uuid.uuid4())
			self.installId = pluginPrefs.get("installId", None)
			self.debugLog("Creating a one-time random deviceID to be registered with August: " + self.installId)

		self.installId = pluginPrefs.get("installId", None)
		self.configStatus = pluginPrefs.get("chkAllGood", None)
		self.pollingInterval = int(pluginPrefs.get("pollingInterval", DEFAULT_POLLING_INTERVAL))
		self.forceServerRefresh = False

		if self.configStatus and not self.vPassword:
			self.authenticate(pluginPrefs.get('txtLogin'), pluginPrefs.get('txtPassword'),
							  pluginPrefs.get('ddlLoginMethod'))

		if self.debug:
			self.house_list = []
			self.lastServerRefresh = datetime.datetime.now()

			self.house_list = ["7dbd9f1a-db02-4613-94a4-db1bcdbd91cd"]
			self.lastServerRefresh = datetime.datetime(2009, 1, 6, 15, 8, 24, 78915)
			self.lastForcedServerRefresh = datetime.datetime.now()
		else:
			self.house_list = []
			self.lastServerRefresh = datetime.datetime.now()
			self.lastForcedServerRefresh = datetime.datetime.now()

	########################################
	def startup(self):
		self.debugLog(u"startup called")
		if self.debug:
			self.update_all_from_august_activity_log()

	def shutdown(self):
		self.debugLog(u"shutdown called")

	def runConcurrentThread(self):
		self.logger.debug("Starting concurrent tread")
		try:
			# Polling - As far as what is known, there is no subscription method using web standards available from August.
			while True:
				try:
					if self.forceServerRefresh:
						self.logger.debug("Refreshing status from August \"/locks\" method, due to previous errors... Polling interval: " + str(self.pollingInterval))
						self.update_all_from_august(False)
					else:
						self.logger.debug("Refreshing status from August Activity Logs...  Last Server Refresh: " + self.lastServerRefresh.strftime('%Y-%m-%d %H:%M:%S.%f %Z') + " (" + str(int((datetime.datetime.now() - self.lastServerRefresh).total_seconds())) + " seconds ago) Polling interval: " + str(self.pollingInterval))
						self.update_all_from_august_activity_log()

						# every 120 minutes compare states with server
						if self.lastForcedServerRefresh < datetime.datetime.now()-datetime.timedelta(minutes=FORCED_SERVER_REFRESH_RATE):
							self.logger.debug("Refreshing status from August \"/locks\" method to ensure accuracy (every " + str(FORCED_SERVER_REFRESH_RATE) + " minutes).  Previous run: " + str(self.lastForcedServerRefresh))
							self.update_all_from_august(True)
				except:
					pass
				self.sleep(int(self.pollingInterval))

		except self.StopThread:
			self.logger.debug("Received StopThread")

	########################################
	# deviceStartComm() is called on application launch for all of our plugin defined
	# devices, and it is called when a new device is created immediately after its
	# UI settings dialog has been validated. This is a good place to force any properties
	# we need the device to have, and to cleanup old properties.
	def deviceStartComm(self, dev):
		# self.debugLog(u"deviceStartComm: %s" % (dev.name,))

		props = dev.pluginProps
		if dev.deviceTypeId == 'augLock':
			# Set IsLockSubType property so Indigo knows device accepts lock actions and should use lock UI.
			props["IsLockSubType"] = True
			serverState = self.getLockStatus(props["lockID"])

			if serverState is not None:
				dev.updateStateOnServer('onOffState', value=serverState)
			else:
				self.forceServerRefresh = True

			if not "houseID" in props:
				props["houseID"] = self.getLockDetails(props["lockID"])["HouseID"]

			if not props["houseID"] in self.house_list:
				self.house_list.append(props["houseID"])

			# Cleanup properties used by other device types. These can exist if user switches the device type.
			if "SupportsColor" in props:
				del props["SupportsColor"]

		dev.replacePluginPropsOnServer(props)

	########################################
	def validateDeviceConfigUi(self, valuesDict, typeId, devId):
		return (True, valuesDict)

	########################################
	# Relay / Dimmer Action callback
	######################
	def actionControlDevice(self, action, dev):
		props = dev.pluginProps

		###### LOCK ######
		if action.deviceAction == indigo.kDeviceAction.Lock:
			# Command hardware module (dev) to LOCK here:
			indigo.server.log(u"sending \"%s\" %s" % (dev.name, "lock"))

			sendSuccess = self.sendCommand(dev.pluginProps["lockID"], "lock")

			if sendSuccess:
				# If success then log that the command was successfully sent.
				indigo.server.log(u"sent \"%s\" %s" % (dev.name, "lock"))

				# Update a timestamp of the last time the device was updated by Indigo
				dev.updateStateOnServer("lastSentIndigoUpdateTime", datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

				# And then tell the Indigo Server to update the state.
				dev.updateStateOnServer("onOffState", True)
			else:
				# Else log failure but do NOT update state on Indigo Server.
				self.logger.error(u"send \"%s\" %s failed" % (dev.name, "lock"), isError=True)

		###### UNLOCK ######
		elif action.deviceAction == indigo.kDeviceAction.Unlock:
			# Command hardware module (dev) to turn UNLOCK here:
			indigo.server.log(u"sending \"%s\" %s" % (dev.name, "unlock"))
			sendSuccess = self.sendCommand(dev.pluginProps["lockID"], "unlock")

			if sendSuccess:
				# If success then log that the command was successfully sent.
				indigo.server.log(u"sent \"%s\" %s" % (dev.name, "unlock"))

				# Update a timestamp of the last time the device was updated by Indigo
				dev.updateStateOnServer("lastSentIndigoUpdateTime", datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

				# And then tell the Indigo Server to update the state:
				dev.updateStateOnServer("onOffState", False)
			else:
				# Else log failure but do NOT update state on Indigo Server.
				self.logger.error(u"send \"%s\" %s failed" % (dev.name, "unlock"), isError=True)

	########################################
	# General Action callback
	######################
	def actionControlUniversal(self, action, dev):

		###### STATUS REQUEST ######
		if action.deviceAction == indigo.kUniversalAction.RequestStatus:
			indigo.server.log(u"sent \"%s\" %s" % (dev.name, "status request"))

			serverState = self.getLockStatus(dev.pluginProps["lockID"])

			if serverState is not None:
				if dev.onState != serverState:
					if serverState:
							indigo.server.log(u"Received \"" + dev.name + "\" was locked")
					else:
							indigo.server.log(u"Received \"" + dev.name + "\" was unlocked")

					dev.updateStateOnServer('onOffState', value=serverState)
			else:
				indigo.server.log("Had errors while refreshing status from August, will try again in " + self.pollingInterval + " seconds")
				self.forceServerRefresh = True





	########################################
	# Custom Plugin Functions
	######################
	def authenticate(self, login, password, loginMethod):
		# Authenticate
		# POST https://api-production.august.com/session

		identifier = loginMethod + ":" + login

		try:
			response = requests.post(
				url="https://api-production.august.com/session",
				headers={
					"Accept-Version": ACCEPT_VERSION,
					"x-august-api-key": API_KEY,
					"x-kease-api-key": API_KEY,
					"Content-Type": CONTENT_TYPE,
					"User-Agent": USER_AGENT,
				},
				data=json.dumps({
					"password": password,
					"identifier": identifier,
					"installId": self.installId,
				})
			)
			self.logger.debug('Response HTTP Status Code: {status_code}'.format(
				status_code=response.status_code))
			self.logger.debug('Response HTTP Response Body: {content}'.format(
				content=response.content))

			resp_data = response.json()

			self.access_token = response.headers["x-august-access-token"]
			self.access_expires = resp_data["expiresAt"]
			self.vPassword = resp_data["vPassword"]
			self.vInstallId = resp_data["vInstallId"]

		except requests.exceptions.RequestException:
			self.logger.error('HTTP Request failed')

	def validatePhone(self, login, code):
		# Validate Phone
		# POST https://api-production.august.com/validate/phone

		try:
			response = requests.post(
				url="https://api-production.august.com/validate/phone",
				headers={
					"x-august-access-token": self.access_token,
					"Accept-Version": ACCEPT_VERSION,
					"x-august-api-key": API_KEY,
					"x-kease-api-key": API_KEY,
					"Content-Type": CONTENT_TYPE,
					"User-Agent": USER_AGENT,
				},
				data=json.dumps({
					"phone": login,
					"code": code
				})
			)
			print('Response HTTP Status Code: {status_code}'.format(
				status_code=response.status_code))
			print('Response HTTP Response Body: {content}'.format(
				content=response.content))
		except requests.exceptions.RequestException:
			print('HTTP Request failed')

		resp_data = response.json()

	def validateEmail(self, login, code):
		# Validate Email
		# POST https://api-production.august.com/validate/email

		try:
			response = requests.post(
				url="https://api-production.august.com/validate/email",
				headers={
					"x-august-access-token": self.access_token,
					"Accept-Version": ACCEPT_VERSION,
					"x-august-api-key": API_KEY,
					"x-kease-api-key": API_KEY,
					"Content-Type": CONTENT_TYPE,
					"User-Agent": USER_AGENT,
				},
				data=json.dumps({
					"phone": login,
					"code": code
				})
			)
			print('Response HTTP Status Code: {status_code}'.format(
				status_code=response.status_code))
			print('Response HTTP Response Body: {content}'.format(
				content=response.content))
		except requests.exceptions.RequestException:
			print('HTTP Request failed')

	def sendPhoneValidation(self, login):
		# Validate Phone
		# POST https://api-production.august.com/validation/phone

		try:
			response = requests.post(
				url="https://api-production.august.com/validation/phone",
				headers={
					"x-august-access-token": self.access_token,
					"Accept-Version": ACCEPT_VERSION,
					"x-august-api-key": API_KEY,
					"x-kease-api-key": API_KEY,
					"Content-Type": CONTENT_TYPE,
					"User-Agent": USER_AGENT,
				},
				data=json.dumps({
					"value": login
				})
			)
			print('Response HTTP Status Code: {status_code}'.format(
				status_code=response.status_code))
			print('Response HTTP Response Body: {content}'.format(
				content=response.content))
		except requests.exceptions.RequestException:
			print('HTTP Request failed')

		self.logger.debug("Validation request sent via Phone")

	def sendEmailValidation(self, login):
		# Validate Email
		# POST https://api-production.august.com/validation/email

		try:
			response = requests.post(
				url="https://api-production.august.com/validation/email",
				headers={
					"x-august-access-token": self.access_token,
					"Accept-Version": ACCEPT_VERSION,
					"x-august-api-key": API_KEY,
					"x-kease-api-key": API_KEY,
					"Content-Type": CONTENT_TYPE,
					"User-Agent": USER_AGENT,
				},
				data=json.dumps({
					"value": login
				})
			)
			print('Response HTTP Status Code: {status_code}'.format(
				status_code=response.status_code))
			print('Response HTTP Response Body: {content}'.format(
				content=response.content))
		except requests.exceptions.RequestException:
			print('HTTP Request failed')

		self.logger.debug("Validation request sent via Email")

	def getHouseActivity(self, houseID):
		# Get Locks
		# GET https://api-production.august.com/houses/<houseID>/activities"

		try:
			response = requests.get(
				url="https://api-production.august.com/houses/" + houseID + "/activities",
				params={
					"limit": MAXIMUM_ACTIVITY_ITEMS,
				},
				headers={
					"x-august-access-token": self.access_token,
					"Accept-Version": ACCEPT_VERSION,
					"x-august-api-key": API_KEY,
					"x-kease-api-key": API_KEY,
					"Content-Type": CONTENT_TYPE,
					"User-Agent": USER_AGENT,
				}
			)

			if response.status_code != 200:
				self.logger.debug('Response HTTP Status Code: {status_code}'.format(
					status_code=response.status_code))
				self.logger.debug('Response HTTP Response Body: {content}'.format(
					content=response.content))

			return response.json()

		except requests.exceptions.RequestException:
			self.logger.error('HTTP Request failed')


	def getLocks(self):
		# Get Locks
		# GET https://api-production.august.com/users/locks/mine
		self.logger.debug("Obtaining a list of locks...")

		try:
			response = requests.get(
				url="https://api-production.august.com/users/locks/mine",
				headers={
					"x-august-access-token": self.access_token,
					"Accept-Version": ACCEPT_VERSION,
					"x-august-api-key": API_KEY,
					"x-kease-api-key": API_KEY,
					"Content-Type": CONTENT_TYPE,
					"User-Agent": USER_AGENT,
				}
			)
			self.logger.debug('Response HTTP Status Code: {status_code}'.format(
				status_code=response.status_code))
			self.logger.debug('Response HTTP Response Body: {content}'.format(
				content=response.content))
		except requests.exceptions.RequestException:
			self.logger.error('HTTP Request failed')

		return json.loads(response.content)

	def getLockDetails(self, lockID):
		# Get Lock Status
		# PUT https://api-production.august.com/locks/<LOCK_ID>/status

		try:
			response = requests.get(
				url="https://api-production.august.com/locks/" + lockID,
				headers={
					"x-august-access-token": self.access_token,
					"Accept-Version": ACCEPT_VERSION,
					"x-august-api-key": API_KEY,
					"x-kease-api-key": API_KEY,
					"Content-Type": CONTENT_TYPE,
					"User-Agent": USER_AGENT,
				},
			)

			if response.status_code != 200:
				self.logger.error('Response HTTP Status Code: {status_code}'.format(
					status_code=response.status_code))
				self.logger.error('Response HTTP Response Body: {content}'.format(
					content=response.content))

			return response.json()

		except requests.exceptions.RequestException:
			self.logger.error('HTTP Request failed')

	def getLockStatus(self, lockID):
		# Get Lock Status
		# PUT https://api-production.august.com/remoteoperate/<LOCK_ID>/status

		try:
			response = requests.get(
				url="https://api-production.august.com/locks/" + lockID + "/status",
				headers={
					"x-august-access-token": self.access_token,
					"Accept-Version": ACCEPT_VERSION,
					"x-august-api-key": API_KEY,
					"x-kease-api-key": API_KEY,
					"Content-Type": CONTENT_TYPE,
					"User-Agent": USER_AGENT,
				}, timeout=TIMEOUT_GET,
			)

			self.logger.debug('Response HTTP Status Code: {status_code}'.format(
				status_code=response.status_code))
			self.logger.debug('Response HTTP Response Body: {content}'.format(
				content=response.content))

			if response.status_code != 200:
				return None

			return response.json()["status"] == "locked"

		except requests.exceptions.RequestException:
			self.logger.error('HTTP Request failed')

		return None

	def sendCommand(self, lockID, command):
		# Unlock
		# PUT https://api-production.august.com/remoteoperate/<LOCKID>/<'lock' or 'unlock'>

		try:
			response = requests.put(
				url="https://api-production.august.com/remoteoperate/" + lockID + "/" + command,
				headers={
					"x-august-access-token": self.access_token,
					"Accept-Version": ACCEPT_VERSION,
					"x-august-api-key": API_KEY,
					"x-kease-api-key": API_KEY,
					"Content-Type": CONTENT_TYPE,
					"User-Agent": USER_AGENT,
				},
			)
			print('Response HTTP Status Code: {status_code}'.format(
				status_code=response.status_code))
			print('Response HTTP Response Body: {content}'.format(
				content=response.content))

			return response.status_code == 200

		except requests.exceptions.RequestException:
			self.logger.error('HTTP Request failed')
			return False


	def sendVerification(self, valuesDict):
		if valuesDict['ddlLoginMethod'] == "phone":
			self.validatePhone(valuesDict['txtLogin'], valuesDict['code'])
		elif valuesDict['ddlLoginMethod'] == "email":
			self.validateEmail(valuesDict['txtLogin'], valuesDict['code'])

		self.authenticate(valuesDict['txtLogin'], valuesDict['txtPassword'], valuesDict['ddlLoginMethod'])
		return self.updateConfig(valuesDict)

	def updateConfig(self, valuesDict):
		if self.vPassword == False:
			valuesDict["chkStatusUnknown"] = "true"
			valuesDict["chkNotVerified"] = "false"
			valuesDict["chkAllGood"] = "false"
			valuesDict["checkboxValidationSent"] = "false"

			self.logger.error("Login failed")
		elif self.vPassword == True and self.vInstallId == False:

			if valuesDict['ddlLoginMethod'] == "phone":
				self.sendPhoneValidation(valuesDict['txtLogin'])
			elif valuesDict['ddlLoginMethod'] == "email":
				self.sendEmailValidation(valuesDict['txtLogin'])

			valuesDict["chkStatusUnknown"] = "false"
			valuesDict["chkNotVerified"] = "true"
			valuesDict["chkAllGood"] = "false"
			valuesDict["checkboxValidationSent"] = "true"

			self.logger.debug("Login Suceeded, must verify")
		elif self.vPassword == True and self.vInstallId == True:
			valuesDict["chkStatusUnknown"] = "false"
			valuesDict["chkNotVerified"] = "false"
			valuesDict["chkAllGood"] = "true"
			valuesDict["checkboxValidationSent"] = "false"

		return valuesDict

	def checkCredentialsAndVerify(self, valuesDict):
		self.authenticate(valuesDict['txtLogin'], valuesDict['txtPassword'], valuesDict['ddlLoginMethod'])
		return self.updateConfig(valuesDict)

	def availableLocks(self, filter="", valuesDict=None, typeId="", targetId=0):
		locks = self.getLocks()
		locks_list = []

		dev = indigo.devices.get(targetId, None)
		if dev and self.configStatus:
			for key, value in locks.items():
				locks_list.append((key, value["LockName"]))
		return locks_list

	def availableDoorbells(self, filter="", valuesDict=None, typeId="", targetId=0):
		pass

	def update_all_from_august_activity_log(self):
		if self.configStatus:
			for houseID in self.house_list:
				applicable_items = 0
				server_activity_too_close = False
				matchIndigoStatusChangeEvent = False

				for activityItem in reversed(self.getHouseActivity(houseID)):
					activityTime = datetime.datetime.fromtimestamp(int(activityItem["dateTime"]) / 1000.0)
					delta_time = datetime.datetime.now() - activityTime
					refresh_delta_time = activityTime - self.lastServerRefresh

					self.logger.debug("Evaluating an activity log that occured " + str(int(delta_time.total_seconds())) + " seconds ago, " + str(refresh_delta_time.total_seconds()) + " seconds since last refresh (" + self.lastServerRefresh.strftime('%Y-%m-%d %H:%M:%S.%f') + "), at: " + activityTime.strftime('%Y-%m-%d %H:%M:%S.%f %Z'))

					# Looking for activity items within the polling interval
					if refresh_delta_time.total_seconds() > -1:
						applicable_items += 1

						self.logger.debug("Processing relevent activity record:" + str(activityItem))
						
						if activityItem["deviceType"] == "lock":

							callingUSer = "Unknown User"
							if activityItem["callingUser"]["FirstName"] == "Manual":
								callingUser = "manually"
							else:
								callingUser = "by " + activityItem["callingUser"]["FirstName"] + " " + activityItem["callingUser"]["LastName"]

							via = "via Unknown Method"
							if 'remote' in activityItem["info"]:
								if activityItem["info"]["remote"]:
									via = "via August App Remotely"
							elif 'agent' in activityItem["info"]:
								if activityItem["info"]["agent"] == "homekit":
									via = "via HomeKit"
								elif activityItem["info"]["agent"] == "mercury":
									via = "via entry code"
							elif callingUser == "manually":
								via = ""
							elif callingUser != "manually" and 'mechanical' in activityItem["info"]:
								via = "via August app"

							for dev in [s for s in indigo.devices.iter(filter="self") if s.enabled]:

								# Check for the right lock
								if dev.pluginProps["lockID"] == activityItem["deviceID"]:

									# Check if the activity log item is an action performed by Indigo
									try:
										lastSentIndigoUpdateTime = datetime.datetime.strptime(dev.states["lastSentIndigoUpdateTime"], "%Y-%m-%d %H:%M:%S")
									except ValueError:
										lastSentIndigoUpdateTime = None

									if lastSentIndigoUpdateTime is not None:
										if via == "via August App Remotely":
											if activityTime - datetime.timedelta(seconds = ACTIVITY_MATCHING_THRESHOLD) <= lastSentIndigoUpdateTime <= activityTime + datetime.timedelta(seconds = ACTIVITY_MATCHING_THRESHOLD):
												# SKIP processing this record since it is the activty item that indigo recently performed
												self.logger.debug("Activty record for the device: " + dev.name + " was a status change performed by Indigo.  Delta: " + str(abs((lastSentIndigoUpdateTime - activityTime).total_seconds())) + ", Activity Time: " + str(activityTime) + ", Indigo Timestamp: " + dev.states["lastSentIndigoUpdateTime"])
												matchIndigoStatusChangeEvent = True
												continue

									# If an Indigo event has been detected and there are subsequent activity items after that event, it's best that we double check with the August /locks method to make sure we have sequenced the activities correctly.
									if matchIndigoStatusChangeEvent:
										server_activity_too_close = True

									serverState = activityItem["action"] == "lock"

									if dev.onState != serverState:
										indigo.server.log(u"Received \"" + dev.name + "\" was " + activityItem["action"] + "ed " + callingUser + " at " + str(activityTime) + " (" + str(int(delta_time.total_seconds())) + " seconds ago) " + via)
										dev.updateStateOnServer('onOffState', value=serverState)
									else:
										self.logger.error("Error processing activity records, will update device states from server.")
										server_activity_too_close = True

							# PROCESS LOCK TRIGGERS
							for trigger in indigo.triggers.iter("self"):
								self.logger.debug("Checking if trigger: \"" + trigger.name + "\" has occured. Max latency: " + str(trigger.pluginProps["maxLatency"]) + ", Event delta: " + str(delta_time.total_seconds()))
								if int(delta_time.total_seconds()) <= int(trigger.pluginProps["maxLatency"]):
									if trigger.pluginProps["lockUnlock"] == activityItem["action"] or trigger.pluginProps["lockUnlock"] == "any":
											if trigger.id == "lockByPerson":
												if trigger.pluginProps["txtName"].lower() in callingUser.lower():
													if via == "via August App Remotely" and trigger["chkIncludeRemote"]:
														indigo.trigger.execute(trigger)
													elif via == "via HomeKit" and trigger.pluginProps["chkIncludeHomeKit"]:
														indigo.trigger.execute(trigger)
													elif via != "via HomeKit" and via != "via August App Remotely":
														indigo.trigger.execute(trigger)

											elif callingUser == "Unknown User" and trigger.id == "lockByUnknownPerson":
												indigo.trigger.execute(trigger)

		
						elif activityItem["deviceType"] == "doorbell":
							if activityItem["action"] == "doorbell_call_missed":
								indigo.server.log(u"Received missed doorbell call at " + activityItem["deviceName"] + " at " + str(activityTime) + " (" + str(int(delta_time.total_seconds())) + " seconds ago)")
							elif activityItem["action"] == "doorbell_motion_detected":
								indigo.server.log(u"Received motion detected event at " + activityItem["deviceName"] + " at " + str(activityTime) + " (" + str(int(delta_time.total_seconds())) + " seconds ago)")

							# PROCESS DOORBELL TRIGGERS
							for trigger in indigo.triggers.iter("self.doorbellMotion"):
								if delta_time.total_seconds() <= int(trigger.pluginProps["maxLatency"]):
									if trigger.pluginProps["eventType"] == "any":
										indigo.trigger.execute(trigger)
									elif trigger.pluginProps["eventType"] == activityItem["action"]:
										indigo.trigger.execute(trigger)

				# if the count of applicable items is greater than the MAXIMUM_ACTIVITY_ITEMS we will check to make sure we didn't miss anything
				if applicable_items == MAXIMUM_ACTIVITY_ITEMS:
					indigo.server.log("More than " + str(MAXIMUM_ACTIVITY_ITEMS) + " activity items since last refresh for HouseID: " + houseID + ", event triggers may have been missed.  Will refresh device states from August servers.")
				else:
					self.logger.debug("Processed " + str(applicable_items) + " new activty records from August for HouseID: " + houseID)
				

				if server_activity_too_close:
					indigo.server.log("Too many activity events within a short period of time, events were processed but verifying the device states from August servers.")

				if applicable_items == MAXIMUM_ACTIVITY_ITEMS or server_activity_too_close:
					self.update_all_from_august(False)

			self.lastServerRefresh = datetime.datetime.now()


	def update_all_from_august(self, compare):
		had_errors = False

		for dev in [s for s in indigo.devices.iter(filter="self") if s.enabled]:
			serverState = self.getLockStatus(dev.pluginProps["lockID"])
			self.logger.debug("Server state for " + dev.name + " is " + str(serverState))
			if serverState is not None:
				if dev.onState != serverState:

					if compare:
						self.logger.error("Found that the local state does not equal the server state for " + dev.name)

					if serverState:
							indigo.server.log(u"Received \"" + dev.name + "\" was locked")
					else:
							indigo.server.log(u"Received \"" + dev.name + "\" was unlocked")

					dev.updateStateOnServer('onOffState', value=serverState)
			else:
				had_errors = True

		if had_errors:
			indigo.server.log("Had errors while refreshing status from August, will try again in " + self.pollingInterval + " seconds")

		self.forceServerRefresh = had_errors
		self.lastForcedServerRefresh = datetime.datetime.now()


	def closedPrefsConfigUi(self, valuesDict, userCancelled):
		if not userCancelled:
			self.pollingInterval = valuesDict["pollingInterval"]
			self.debug = valuesDict["chkDebug"]
