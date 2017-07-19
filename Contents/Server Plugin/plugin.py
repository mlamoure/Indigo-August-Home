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

class AugustActivityItem(object):

	def __init__(self, activityID, deviceName, deviceType, action, deviceID, dateTime, callingUser = "Unknown User", via = "via Unknown Method", has_processed = False):
		self.activityID = activityID
		self.deviceName = deviceName
		self.deviceType = deviceType
		self.action = action
		self.deviceID = deviceID
		self.dateTime = dateTime
		self.callingUser = callingUser
		self.via = via

		self.has_processed = has_processed
		self.is_Indigo_Action = False

	def onState(self):
		return self.action == "lock"


################################################################################
class Plugin(indigo.PluginBase):
	########################################
	def __init__(self, pluginId, pluginDisplayName, pluginVersion, pluginPrefs):
		super(Plugin, self).__init__(pluginId, pluginDisplayName, pluginVersion, pluginPrefs)
		self.debug = pluginPrefs.get("chkDebug", False)
		self.debug_L2 = pluginPrefs.get("chkDebug_L2", False)

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

		for houseID, activityItemList in self.house_list:
			self.load_activity_logs(houseID, True)

		self.sleep(int(self.pollingInterval))			
		
		try:
			# Polling - As far as what is known, there is no subscription method using web standards available from August.
			while True:
				try:
					if self.forceServerRefresh:
						self.logger.debug("Refreshing status from August \"/locks\" method, due to previous errors... Polling interval: " + str(self.pollingInterval))
						self.update_all_from_august(False)
					else:
						self.logger.debug("Refreshing status from August Activity Logs for " + str(len(self.house_list)) + " house(s)...  Last Server Refresh: " + self.lastServerRefresh.strftime('%Y-%m-%d %H:%M:%S.%f %Z') + " (" + str(int((datetime.datetime.now() - self.lastServerRefresh).total_seconds())) + " seconds ago) Polling interval: " + str(self.pollingInterval))
						self.update_all_from_august_activity_log()

						# every X minutes compare states with server
						if self.lastForcedServerRefresh < datetime.datetime.now()-datetime.timedelta(minutes=FORCED_SERVER_REFRESH_RATE):
							self.logger.debug("Refreshing status from August \"/locks\" method to ensure accuracy (every " + str(FORCED_SERVER_REFRESH_RATE) + " minutes).  Previous run: " + str(self.lastForcedServerRefresh))
							self.update_all_from_august(True)

							self.trim_local_cache()
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

			found = False
			for houseID, activityItemList in self.house_list:
				if houseID == props["houseID"]:
					found = True
					break

			if not found:
				self.logger.debug("Adding new house: " + props["houseID"] + " to house cache list")
				self.house_list.append([props["houseID"], []])

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

			# First check the server state to ensure properly sync'd
			serverState = self.getLockStatus(dev.pluginProps["lockID"])
			if serverState is not None:
				if dev.onState != serverState:
					if serverState:
							indigo.server.log(u"Received \"" + dev.name + "\" was locked")
					else:
							indigo.server.log(u"Received \"" + dev.name + "\" was unlocked")

					dev.updateStateOnServer('onOffState', value=serverState)
					self.logger.error("The state of the lock in Indigo was out of sync, " + dev.name + " was already locked")
					return

			if dev.onState:
				indigo.server.log(dev.name + " is already locked, no command sent")
				return

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
				self.logger.error(u"send \"%s\" %s failed" % (dev.name, "lock"))

		###### UNLOCK ######
		elif action.deviceAction == indigo.kDeviceAction.Unlock:

			# First check the server state to ensure properly sync'd
			serverState = self.getLockStatus(dev.pluginProps["lockID"])
			if serverState is not None:
				if dev.onState != serverState:
					if serverState:
							indigo.server.log(u"Received \"" + dev.name + "\" was locked")
					else:
							indigo.server.log(u"Received \"" + dev.name + "\" was unlocked")

					dev.updateStateOnServer('onOffState', value=serverState)
					self.logger.error("The state of the lock in Indigo was out of sync, " + dev.name + " was already unlocked")
					return

			if not dev.onState:
				indigo.server.log(dev.name + " is already unlocked, no command sent")
				return

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

	def trim_local_cache(self):
		self.logger.debug("trimming the local activity cache")
		for chk_houseID, activityItemList in self.house_list:
			if len(activityItemList) > MAXIMUM_ACTIVITY_ITEMS + 1:
				del activityItemList[MAXIMUM_ACTIVITY_ITEMS:]
				self.logger.debug("Trimmed the cache to " + str(len(activityItemList)) + " items")
			
			if self.debug_L2:
				for item in activityItemList:
					self.logger.debug(str(item.activityID) + ", " + str(item.dateTime) + ", " + str(item.has_processed))

	def load_activity_logs(self, houseID, initial_load):
		self.logger.debug("Processing activity logs for house ID: " + houseID)

		for chk_houseID, activityItemList in self.house_list:
			if houseID == chk_houseID:
				######## LOAD NEW ACTIVITY ITEMS
				newItemCount = 0
				for serverActivityItem in self.getHouseActivity(houseID):
					itemAlreadyExists = False
					for localAcivityItem in activityItemList:
						if localAcivityItem.activityID == serverActivityItem["dateTime"]:
							itemAlreadyExists = True
							break

					if itemAlreadyExists:
						# Since we are going through the list in chronological order from August, we can stop processing once we find one that already exists.
						break
					else:
						activityID = serverActivityItem["dateTime"]
						deviceName = serverActivityItem["deviceName"]
						deviceType = serverActivityItem["deviceType"]
						action = serverActivityItem["action"]
						deviceID = serverActivityItem["deviceID"]
						dateTime = datetime.datetime.fromtimestamp(int(serverActivityItem["dateTime"]) / 1000.0)

						callingUser = "Unknown User"
						via = "via Unknown Method"

						if deviceType == "lock":
							if serverActivityItem["callingUser"]["FirstName"] == "Manual":
								callingUser = "manually"
							else:
								callingUser = "by " + serverActivityItem["callingUser"]["FirstName"] + " " + serverActivityItem["callingUser"]["LastName"]

							if 'remote' in serverActivityItem["info"]:
								if serverActivityItem["info"]["remote"]:
									via = "via August App Remotely"
							elif 'agent' in serverActivityItem["info"]:
								if serverActivityItem["info"]["agent"] == "homekit":
									via = "via HomeKit"
								elif serverActivityItem["info"]["agent"] == "mercury":
									via = "via entry code"
							elif callingUser == "manually":
								via = ""
							elif callingUser != "manually" and 'mechanical' in serverActivityItem["info"]:
								via = "via August app"


						activityItemList.insert(0+newItemCount, AugustActivityItem(activityID, deviceName, deviceType, action, deviceID, dateTime, callingUser, via, initial_load))
						newItemCount += 1
				break
		
		self.logger.debug("Added " + str(newItemCount) + " new Activity log items to the plugin internal cache")
		self.logger.debug("Current list of cache timestamp log items for the house (size: " + str(len(activityItemList)) + "): ")

		if self.debug_L2:
			for item in activityItemList:
				self.logger.debug(str(item.activityID) + ", " + str(item.dateTime) + ", " + str(item.has_processed))

	def update_all_from_august_activity_log(self):
		if self.configStatus:
			had_errors_processing = False

			for houseID, activityItemList in self.house_list:

				self.load_activity_logs(houseID, False)

				####### PROCESS ACTIVITY ITEMS
				newItemCount = 0
				for activityItem in reversed(activityItemList):
					if not activityItem.has_processed:
						newItemCount += 1
						delta_time = datetime.datetime.now() - activityItem.dateTime
						refresh_delta_time = activityItem.dateTime - self.lastServerRefresh
		
						self.logger.debug("Evaluating an activity log that occured " + str(int(delta_time.total_seconds())) + " seconds ago, " + str(refresh_delta_time.total_seconds()) + " seconds since last refresh (" + self.lastServerRefresh.strftime('%Y-%m-%d %H:%M:%S.%f') + "), at: " + activityItem.dateTime.strftime('%Y-%m-%d %H:%M:%S.%f %Z'))

						if activityItem.deviceType == "lock":
							for dev in [s for s in indigo.devices.iter(filter="self") if s.enabled]:
								if dev.pluginProps["lockID"] == activityItem.deviceID:

									# Check if the activity log item is an action performed by Indigo
									try:
										lastSentIndigoUpdateTime = datetime.datetime.strptime(dev.states["lastSentIndigoUpdateTime"], "%Y-%m-%d %H:%M:%S")
									except ValueError:
										lastSentIndigoUpdateTime = None

									if lastSentIndigoUpdateTime is not None:
										if activityItem.via == "via August App Remotely":
											if activityItem.dateTime - datetime.timedelta(seconds = ACTIVITY_MATCHING_THRESHOLD) <= lastSentIndigoUpdateTime <= activityItem.dateTime + datetime.timedelta(seconds = ACTIVITY_MATCHING_THRESHOLD):
												# SKIP processing this record since it is the activty item that indigo recently performed
												self.logger.debug("MATCHED Indigo Activty record for the device: " + dev.name + ", Delta: " + str(abs((lastSentIndigoUpdateTime - activityItem.dateTime).total_seconds())) + ", Activity Time: " + str(activityItem.dateTime) + ", Indigo Timestamp: " + dev.states["lastSentIndigoUpdateTime"])
												activityItem.is_Indigo_Action = True
												activityItem.has_processed = True
												continue


									if dev.onState != activityItem.onState():
										indigo.server.log(u"Received \"" + dev.name + "\" was " + activityItem.action + "ed " + activityItem.callingUser + " at " + str(activityItem.dateTime) + " (" + str(int(delta_time.total_seconds())) + " seconds ago) " + activityItem.via)
										dev.updateStateOnServer('onOffState', value=activityItem.onState())
									else:
										had_errors_processing = True
										self.logger.error("Out of sync error while processing activity records, will update device states from server to correct the problem.")

							# PROCESS LOCK TRIGGERS
							for trigger in indigo.triggers.iter("self.lockByPerson"):
								self.logger.debug("Checking if trigger: \"" + trigger.name + "\" has occured. Max latency: " + str(trigger.pluginProps["maxLatency"]) + ", Event delta: " + str(delta_time.total_seconds()))
								if int(delta_time.total_seconds()) <= int(trigger.pluginProps["maxLatency"]):
									if trigger.pluginProps["lockUnlock"] == activityItem.action or trigger.pluginProps["lockUnlock"] == "any":
											if trigger.pluginProps["txtName"].lower() in activityItem.callingUser.lower():
												if activityItem.via == "via August App Remotely" and trigger["chkIncludeRemote"]:
													indigo.trigger.execute(trigger)
												elif activityItem.via == "via HomeKit" and trigger.pluginProps["chkIncludeHomeKit"]:
													indigo.trigger.execute(trigger)
												elif activityItem.via != "via HomeKit" and activityItem.via != "via August App Remotely":
													indigo.trigger.execute(trigger)

							for trigger in indigo.triggers.iter("self.lockByUnknownPerson"):
								self.logger.debug("Checking if trigger: \"" + trigger.name + "\" has occured. Max latency: " + str(trigger.pluginProps["maxLatency"]) + ", Event delta: " + str(delta_time.total_seconds()))
								if int(delta_time.total_seconds()) <= int(trigger.pluginProps["maxLatency"]):
									if trigger.pluginProps["lockUnlock"] == activityItem.action or trigger.pluginProps["lockUnlock"] == "any":
											if activityItem.callingUser == "Unknown User" and trigger.id == "lockByUnknownPerson":
												indigo.trigger.execute(trigger)

							self.logger.debug("Completed processing lock triggers")
						
						elif activityItem.deviceType == "doorbell":	
							if activityItem.action == "doorbell_call_missed":
								indigo.server.log(u"Received missed doorbell call at " + activityItem.deviceName + " at " + str(activityItem.dateTime) + " (" + str(int(delta_time.total_seconds())) + " seconds ago)")
							elif activityItem.action == "doorbell_motion_detected":
								indigo.server.log(u"Received motion detected event at " + activityItem.deviceName + " at " + str(activityItem.dateTime) + " (" + str(int(delta_time.total_seconds())) + " seconds ago)")

							# PROCESS DOORBELL TRIGGERS
							for trigger in indigo.triggers.iter("self.doorbellMotion"):
								self.logger.debug("Checking if trigger: \"" + trigger.name + "\" has occured. Max latency: " + str(trigger.pluginProps["maxLatency"]) + ", Event delta: " + str(delta_time.total_seconds()))
								if delta_time.total_seconds() <= 500000:  #int(trigger.pluginProps["maxLatency"])
									if trigger.pluginProps["eventType"] == "any":
										indigo.trigger.execute(trigger)
									elif trigger.pluginProps["eventType"] == activityItem.action:
										indigo.trigger.execute(trigger)
						
							self.logger.debug("Completed processing doorbell triggers")

						# Finally, marked the item as processed.
						activityItem.has_processed = True
						self.logger.debug("Completed processing activity item")

			self.logger.debug("Completed processing activity logs")
			if had_errors_processing:
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
			self.debug_L2= valuesDict["chkDebug_L2"]
