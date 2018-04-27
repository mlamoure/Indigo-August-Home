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
from ghpu import GitHubPluginUpdater


API_KEY = "727dba56-fe45-498d-b4aa-293f96aae0e5"
CONTENT_TYPE = "application/json"
USER_AGENT = "August/Luna-3.2.2"
ACCEPT_VERSION = "0.0.1"
DEFAULT_POLLING_INTERVAL = 90  # number of seconds between each poll
MAXIMUM_ACTIVITY_ITEMS = 20 # Max number of activity items to request per house to process for latest state information
MAXIMUM_ACTIVITY_ITEMS_QUERY = 8
TIMEOUT_PUT = 10
TIMEOUT_GET = 4
ACTIVITY_MATCHING_THRESHOLD = 2 # The number of seconds as a threshold on the difference between server and local timestamps for event matching
DEFAULT_UPDATE_FREQUENCY = 24 # frequency of update check

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
		return self.action == "lock" or self.action == "onetouchlock"


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

		# set the get Locks method to 4x the polling rate
		self.getLocksMethodRefreshRate = int(self.pollingInterval * 4)
		self.forceServerRefresh = False

		if self.configStatus and not self.vPassword:
			self.authenticate(pluginPrefs.get('txtLogin'), pluginPrefs.get('txtPassword'),
							  pluginPrefs.get('ddlLoginMethod'))

		self.house_list = []
		self.doorbell_list = []
		self.lastServerRefresh = datetime.datetime.now()
		self.lastForcedServerRefresh = datetime.datetime.now()

		self.indigoVariablesFolderName = pluginPrefs.get("indigoVariablesFolderName", None)
		self.indigoVariablesFolderID = None
		self.has_doorbell = False
		self.has_lock = False

		self.updater = GitHubPluginUpdater(self)
		self.updater.checkForUpdate(str(self.pluginVersion))
		self.lastUpdateCheck = datetime.datetime.now()			

		if self.indigoVariablesFolderName is not None:
			if self.indigoVariablesFolderName in indigo.variables.folders:
				self.indigoVariablesFolderID=indigo.variables.folders[self.indigoVariablesFolderName].id


	########################################
	def startup(self):
		self.debugLog(u"startup called")

		if self.configStatus:
			if self.debug:
				self.update_all_from_august_activity_log()

			self.configureDoorbells()

			self.createVariableFolder(self.indigoVariablesFolderName)
			self.updateVariables()


	def configureDoorbells(self):
		db_list = self.getDoorbells()	
		self.has_doorbell = len(db_list) > 0
		self.doorbell_list = []

		if self.has_doorbell:
			for key, value in db_list.items():
	
				self.doorbell_list.append((key, value["name"]))
				self.logger.debug("Added doorbell " + value["name"] + " with ID " + key)

				found = False

				for houseID, houseName, activityItemList in self.house_list:
					if houseID == value["HouseID"]:
						found = True
						break

				if not found:
					self.logger.debug("Adding new house: " + value["HouseID"] + " to house cache list")
					self.house_list.append([value["HouseID"], "Unknown house with Doorbell", []])

			self.logger.debug("Found a doorbell associated with this account")
			self.last_doorbell_motion = datetime.datetime.now()

	def checkForUpdates(self):
		self.updater.checkForUpdate()

	def updatePlugin(self):
		self.updater.update()

	def shutdown(self):
		self.debugLog(u"shutdown called")

	def runConcurrentThread(self):
		self.logger.debug("Starting concurrent tread")

		for houseID, houseName, activityItemList in self.house_list:
			self.load_activity_logs(houseID, True)

		self.sleep(int(self.pollingInterval))			
		
		try:
			# Polling - As far as what is known, there is no subscription method using web standards available from August.
			while True:
				try:
					if self.forceServerRefresh:
						self.logger.debug("Refreshing status from August \"/locks\" method, due to previous errors... Polling interval: " + str(self.pollingInterval))
						self.update_all_from_august()
					else:
						self.logger.debug("Refreshing status from August Activity Logs for " + str(len(self.house_list)) + " house(s)...  Last Server Refresh: " + self.lastServerRefresh.strftime('%Y-%m-%d %H:%M:%S.%f %Z') + " (" + str(int((datetime.datetime.now() - self.lastServerRefresh).total_seconds())) + " seconds ago) Polling interval: " + str(self.pollingInterval))
						self.update_all_from_august_activity_log()

						# every X minutes compare states with server
						if self.has_lock and self.lastForcedServerRefresh < datetime.datetime.now()-datetime.timedelta(seconds=self.getLocksMethodRefreshRate):
							self.logger.debug("Refreshing status from August \"/locks\" method to ensure accuracy (every " + str(self.getLocksMethodRefreshRate) + " seconds).  Previous run: " + str(self.lastForcedServerRefresh))
							
							if self.has_doorbell:
								for doorbellID, doorbellName in self.doorbell_list:
									self.wakeup(doorbellID)

							self.update_all_from_august()

							self.trim_local_cache()

						self.updateVariables()

						if self.lastUpdateCheck < datetime.datetime.now()-datetime.timedelta(hours=DEFAULT_UPDATE_FREQUENCY):
							self.updater.checkForUpdate(str(self.pluginVersion))
							self.lastUpdateCheck = datetime.datetime.now()		

				except Exception as e:
					self.logger.debug(e)
					pass
				self.sleep(int(self.pollingInterval))

		except self.StopThread:
			self.logger.debug("Received StopThread")

	def deviceStopComm(self, dev):
		if "houseID" in dev.pluginProps:
			self.resetHouseList()

	def resetHouseList(self):
		self.house_list = []
		self.has_lock = False

		for dev in [s for s in indigo.devices.iter(filter="self") if s.enabled]:
			self.has_lock = True
			found = False
			for houseID, houseName, activityItemList in self.house_list:
				if houseID == dev.pluginProps["houseID"]:
					found = True
					break

			if not found:
				self.logger.debug("Adding new house: " + dev.pluginProps["houseID"] + " to house cache list")
				self.house_list.append([dev.pluginProps["houseID"], dev.pluginProps["houseName"], []])

		self.configureDoorbells()


	########################################
	# deviceStartComm() is called on application launch for all of our plugin defined
	# devices, and it is called when a new device is created immediately after its
	# UI settings dialog has been validated. This is a good place to force any properties
	# we need the device to have, and to cleanup old properties.
	def deviceStartComm(self, dev):
		self.debugLog(u"deviceStartComm: %s" % (dev.name,))

		props = dev.pluginProps
		propsChanged = False

		if not "lockID" in props:
			self.logger.error("August device '{}' configured with unknown Lock ID. Reconfigure the device to make it active.".format(dev.name))
			props["configured"] = False
			dev.replacePluginPropsOnServer(props)			
			return

		self.has_lock = True

		if not "IsLockSubType" in props:
			props["IsLockSubType"] = True
			propsChanged = True
		elif not props["IsLockSubType"]:
			props["IsLockSubType"] = True
			propsChanged = True

		if not "SupportsBatteryLevel" in props:		
			props["SupportsBatteryLevel"] = True
			propsChanged = True
		elif not props["IsLockSubType"]:
			props["SupportsBatteryLevel"] = True
			propsChanged = True

		if not "houseID" in props or not "houseName" in props:
			house = self.getLockDetails(props["lockID"])
			props["houseID"] = house["HouseID"]
			props["houseName"] = house["HouseName"]
			propsChanged = True
			
		if "SupportsColor" in props:
			del props["SupportsColor"]
			propsChanged = True

		props["configured"] = "houseID" in props and "houseName" in props

		if propsChanged:
			dev.replacePluginPropsOnServer(props)
		
		if props["configured"]:
			serverState = self.getLockStatus(props["lockID"])

			if serverState is not None:
				dev.updateStateOnServer('onOffState', value=serverState)
			else:
				self.forceServerRefresh = True

			self.resetHouseList()


	########################################
	def validateDeviceConfigUi(self, valuesDict, typeId, devId):
		return (True, valuesDict)

	########################################
	# Relay / Dimmer Action callback
	######################
	def actionControlDevice(self, action, dev):
		props = dev.pluginProps

		actionstr = "unknown"
		if action.deviceAction == indigo.kDeviceAction.Lock:
			actionstr = "lock"
		else:
			actionstr = "unlock"

		# First check the server state to ensure properly sync'd
		serverState = self.getLockStatus(dev.pluginProps["lockID"])
		if serverState is not None:
			if dev.onState != serverState:
				if serverState:
						indigo.server.log(u"received \"" + dev.name + "\" was locked")
				else:
						indigo.server.log(u"received \"" + dev.name + "\" was unlocked")

				dev.updateStateOnServer('onOffState', value=serverState)
				self.logger.error("The state of the lock in Indigo was out of sync, " + dev.name + " was already " + actionstr + "ed")
				return

		if (dev.onState and actionstr == "lock") or not dev.onState and actionstr == "unlock":
			indigo.server.log(dev.name + " is already " + actionstr + "ed, no command sent")
			return

		# Command hardware module (dev) to LOCK here:
		indigo.server.log(u"sending \"%s\" %s" % (dev.name, actionstr))

		sendSuccess = self.sendCommand(dev.pluginProps["lockID"], actionstr)

		if sendSuccess:
			# If success then log that the command was successfully sent.
			indigo.server.log(u"sent \"%s\" %s" % (dev.name, actionstr))

			# Update a timestamp of the last time the device was updated by Indigo
			dev.updateStateOnServer("lastSentIndigoUpdateTime", datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

			# And then tell the Indigo Server to update the state.
			dev.updateStateOnServer("onOffState", actionstr=="lock")

			# Update a timestamp of the last time the device was updated
			dev.updateStateOnServer("lastStateChangeTime", datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

		else:
			# Else log failure but do NOT update state on Indigo Server.
			self.logger.error(u"send \"%s\" %s failed" % (dev.name, actionstr))

		self.updateVariables()

	########################################
	# General Action callback
	######################
	def actionControlUniversal(self, action, dev):

		###### STATUS REQUEST ######
		if action.deviceAction == indigo.kUniversalAction.RequestStatus:
			if self.has_doorbell:
				for doorbellID, doorbellName in self.doorbell_list:
					self.wakeup(doorbellID)


			indigo.server.log(u"sent \"%s\" %s" % (dev.name, "status request"))

			lockDetails = self.getLockDetails(dev.pluginProps["lockID"])

			serverState = lockDetails["LockStatus"]["status"] == "locked"

			batteryLevel = int(100*lockDetails["battery"])
			batteryLevelStr = u"%d%%" % (int(batteryLevel))
			dev.updateStateOnServer('batteryLevel', batteryLevel, uiValue=batteryLevelStr)

			if serverState is not None:
				if dev.onState != serverState:
					if serverState:
							indigo.server.log(u"received \"" + dev.name + "\" was locked")
					else:
							indigo.server.log(u"received \"" + dev.name + "\" was unlocked")

					dev.updateStateOnServer('onOffState', value=serverState)

					# Update a timestamp of the last time the device was updated
					dev.updateStateOnServer("lastStateChangeTime", datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
			else:
				indigo.server.log("Had errors while refreshing status from August, will try again in " + str(self.pollingInterval) + " seconds")
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
					"email": login,
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

	def getHouseActivity(self, houseID, numItems = MAXIMUM_ACTIVITY_ITEMS_QUERY):
		# Get Locks
		# GET https://api-production.august.com/houses/<houseID>/activities"

		try:
			response = requests.get(
				url="https://api-production.august.com/houses/" + houseID + "/activities",
				params={
					"limit": numItems,
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

	def getDoorbells(self):
		# GET https://api-production.august.com/users/doorbells/mine
		self.logger.debug("Obtaining a list of doorbells...")

		try:
			response = requests.get(
				url="https://api-production.august.com/users/doorbells/mine",
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
		# GET https://api-production.august.com/locks/<LOCK_ID>/

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

			self.logger.debug('Response HTTP Response Body: {content}'.format(
				content=response.content))

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
		# GET https://api-production.august.com/locks/<LOCK_ID>/status

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
			self.logger.debug('Response HTTP Status Code: {status_code}'.format(
				status_code=response.status_code))
			self.logger.debug('Response HTTP Response Body: {content}'.format(
				content=response.content))

			return response.status_code == 200

		except requests.exceptions.RequestException:
			self.logger.error('HTTP Request failed')
			return False

	def wakeup(self, doorbellID):
		# PUT https://api-production.august.com/doorbells/<doorbellID>/wakeup
		self.logger.debug("Sending a wakeup request")
		try:
			response = requests.put(
				url="https://api-production.august.com/doorbells/" + doorbellID + "/wakeup",
				headers={
					"x-august-access-token": self.access_token,
					"Accept-Version": ACCEPT_VERSION,
					"x-august-api-key": API_KEY,
					"x-kease-api-key": API_KEY,
					"Content-Type": CONTENT_TYPE,
					"User-Agent": USER_AGENT,
				},
			)
			self.logger.debug('Response HTTP Status Code: {status_code}'.format(
				status_code=response.status_code))
			self.logger.debug('Response HTTP Response Body: {content}'.format(
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

		if self.configStatus:
			for key, value in locks.items():
				found = False
				for existing_dev in [s for s in indigo.devices.iter(filter="self") if s.enabled]:
					if key == existing_dev.pluginProps["lockID"]:
						found = True
	
				if not found:	
					locks_list.append((key, value["LockName"]))
		
		if dev and dev.configured:
			locks_list.append((dev.pluginProps["lockID"], dev.name))

		return locks_list

	def resetUnlockTimer(self, pluginAction, dev):		
		# Update a timestamp of the last time the device was updated
		dev.updateStateOnServer("lastStateChangeTime", datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

	########################################
	# Valication callbacks
	########################################
	def validateDeviceConfigUi(self, valuesDict, typeId, devId):
		if devId:
			dev = indigo.devices[devId]
			if dev.pluginProps.get("lockID", None) != valuesDict["lockID"]:
				valuesDict["configured"] = False
		else:
			valuesDict["configured"] = False
		return (True, valuesDict)

	def trim_local_cache(self):
		self.logger.debug("trimming the local activity cache")
		for chk_houseID, chk_houseName, activityItemList in self.house_list:
			if len(activityItemList) > MAXIMUM_ACTIVITY_ITEMS:
				del activityItemList[MAXIMUM_ACTIVITY_ITEMS:]
				self.logger.debug("Trimmed the cache to " + str(len(activityItemList)) + " items")
			
			if self.debug_L2:
				for item in activityItemList:
					self.logger.debug(str(item.activityID) + ", " + str(item.dateTime) + ", " + str(item.action) + ", " + str(item.has_processed))

	def load_activity_logs(self, houseID, initial_load):
		self.logger.debug("Processing activity logs for house ID: " + houseID)

		for chk_houseID, chk_houseName, activityItemList in self.house_list:
			if houseID == chk_houseID:
				######## LOAD NEW ACTIVITY ITEMS
				newItemCount = 0
				houseActivity = None

				if initial_load:
					houseActivity = self.getHouseActivity(houseID, MAXIMUM_ACTIVITY_ITEMS)
				else:
					houseActivity = self.getHouseActivity(houseID)

				if houseActivity is None:
					continue

				for serverActivityItem in houseActivity:
					itemAlreadyExists = False
					for localAcivityItem in activityItemList:
						if localAcivityItem.activityID == serverActivityItem["dateTime"]:
							itemAlreadyExists = True
							break

					if itemAlreadyExists:
						# Since we are going through the list in chronological order from August, we can stop processing once we find one that already exists.
						#break
						# As it turns out, August will sometimes retro-actively add items, though unusual.  The plugin can deal with the out of order events.
						continue
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
							elif action == "onetouchlock":
								callingUSer = "One-Touch Lock"
							else:
								callingUser = "by " + serverActivityItem["callingUser"]["FirstName"] + " " + serverActivityItem["callingUser"]["LastName"]

							if 'remote' in serverActivityItem["info"]:
								if serverActivityItem["info"]["remote"]:
									via = "via August App Remotely"
							elif 'agent' in serverActivityItem["info"]:
								if serverActivityItem["info"]["agent"] == "homekit":
									via = "via HomeKit"
								elif serverActivityItem["info"]["agent"] == "mercury":
									if action == "onetouchlock":
										via = ""
									else:
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
				self.logger.debug(str(item.activityID) + ", " + str(item.dateTime) + ", " + str(item.action) + ", " + str(item.has_processed))

	def update_all_from_august_activity_log(self):
		if self.configStatus:
			had_warnings_processing = False

			for houseID, houseName, activityItemList in self.house_list:

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

									# Process Invalid Code
									if activityItem.action == "invalidcode":
										indigo.server.log("Invalid entry code used on " + dev.name + " at " + activityItem.dateTime.strftime("%Y-%m-%d %H:%M:%S") + " (" + str(int(delta_time.total_seconds())) + " seconds ago)")

										# Process any Invalid code triggers
										for trigger in indigo.triggers.iter("self.invalidCode"):
											self.logger.debug("Checking if trigger: \"" + trigger.name + "\" has occured. Max latency: " + str(trigger.pluginProps["maxLatency"]) + ", Event delta: " + str(delta_time.total_seconds()))
											if int(delta_time.total_seconds()) <= int(trigger.pluginProps["maxLatency"]):
												indigo.trigger.execute(trigger)
										break

									# Check if the activity log item is an action performed by Indigo
									try:
										lastSentIndigoUpdateTime = datetime.datetime.strptime(dev.states["lastSentIndigoUpdateTime"], "%Y-%m-%d %H:%M:%S")
									except ValueError:
										lastSentIndigoUpdateTime = None

									# IDENTIFY ACTIONS IN THE ACTIVITY LOG THAT CAME FROM INDIGO TO AVOID REDUNDANT PROCESSING
									if lastSentIndigoUpdateTime is not None:
										if activityItem.via == "via August App Remotely":
											if activityItem.dateTime - datetime.timedelta(seconds = ACTIVITY_MATCHING_THRESHOLD) <= lastSentIndigoUpdateTime <= activityItem.dateTime + datetime.timedelta(seconds = ACTIVITY_MATCHING_THRESHOLD):
												# SKIP processing this record since it is the activty item that indigo recently performed
												self.logger.debug("MATCHED Indigo Activty record for the device: " + dev.name + ", Delta: " + str(abs((lastSentIndigoUpdateTime - activityItem.dateTime).total_seconds())) + ", Activity Time: " + str(activityItem.dateTime) + ", Indigo Timestamp: " + dev.states["lastSentIndigoUpdateTime"])
												activityItem.is_Indigo_Action = True
												break

									extraText = ""
									if dev.onState == activityItem.onState():
										extraText = " (this event was delayed in the August activity log, so the Indigo lock state had already been updated.)"

									if activityItem.action == "onetouchlock":
										indigo.server.log(u"received \"" + dev.name + "\" was One-Touch Locked at " + activityItem.dateTime.strftime("%Y-%m-%d %H:%M:%S") + " (" + str(int(delta_time.total_seconds())) + " seconds ago) " + activityItem.via + extraText)
									elif activityItem.callingUser == "by Auto Relock":
										indigo.server.log(u"received \"" + dev.name + "\" was Auto-Locked at " + activityItem.dateTime.strftime("%Y-%m-%d %H:%M:%S") + " (" + str(int(delta_time.total_seconds())) + " seconds ago)")									
									elif activityItem.action == "addedpin":
										indigo.server.log(u"received \"" + dev.name + "\" PIN Code was added for a new user (ignored).")
										break										
									else:
										indigo.server.log(u"received \"" + dev.name + "\" was " + activityItem.action + "ed " + activityItem.callingUser + " at " + activityItem.dateTime.strftime("%Y-%m-%d %H:%M:%S") + " (" + str(int(delta_time.total_seconds())) + " seconds ago) " + activityItem.via + extraText)

									if dev.onState != activityItem.onState():									
										dev.updateStateOnServer('onOffState', value=activityItem.onState())

										# Update a timestamp of the last time the device was updated
										dev.updateStateOnServer("lastStateChangeTime", datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
									else:
										had_warnings_processing = True

										self.logger.debug("An out of sync log item was processed, will update device states from August Server to correct.")
										break


							# PROCESS LOCK TRIGGERS
							for trigger in indigo.triggers.iter("self.lockByPerson"):
								self.logger.debug("Checking if trigger: \"" + trigger.name + "\" has occured. Max latency: " + str(trigger.pluginProps["maxLatency"]) + ", Event delta: " + str(delta_time.total_seconds()))
								try:
									if int(delta_time.total_seconds()) <= int(trigger.pluginProps["maxLatency"]):
										if trigger.pluginProps["lockUnlock"] == activityItem.action or trigger.pluginProps["lockUnlock"] == "any":
												if trigger.pluginProps["txtName"].lower() in activityItem.callingUser.lower():
													if activityItem.via == "via August App Remotely" and trigger.pluginProps["chkIncludeRemote"]:
														indigo.trigger.execute(trigger)
													elif activityItem.via == "via HomeKit" and trigger.pluginProps["chkIncludeHomeKit"]:
														indigo.trigger.execute(trigger)
													elif activityItem.via != "via HomeKit" and activityItem.via != "via August App Remotely":
														indigo.trigger.execute(trigger)
									else:
										self.logger.debug("   been too long.")
								except Exception as e:
									self.logger.debug("   error while processing trigger: " + str(e))								

							for trigger in indigo.triggers.iter("self.lockByUnknownPerson"):
								self.logger.debug("Checking if trigger: \"" + trigger.name + "\" has occured. Max latency: " + str(trigger.pluginProps["maxLatency"]) + ", Event delta: " + str(delta_time.total_seconds()))
								try:
									if int(delta_time.total_seconds()) <= int(trigger.pluginProps["maxLatency"]):
										if trigger.pluginProps["lockUnlock"] == activityItem.action or trigger.pluginProps["lockUnlock"] == "any":
												if activityItem.callingUser == "Unknown User" or activityItem.callingUser == "manually":
													indigo.trigger.execute(trigger)
									else:
										self.logger.debug("   been too long.")
								except Exception as e:
									self.logger.debug("   error while processing trigger: " + str(e))

							self.logger.debug("Completed processing lock triggers")
						
						elif activityItem.deviceType == "doorbell":
							if not self.has_doorbell:
								self.has_doorbell = True
							# There is another one called "partner_video_streaming" and "doorbell_calll_initiated" that is unknown
							if activityItem.action == "doorbell_call_missed" or activityItem.action == "doorbell_motion_detected":
								self.last_doorbell_motion = datetime.datetime.now()

								if activityItem.action == "doorbell_call_missed":
									indigo.server.log(u"received missed doorbell call at " + activityItem.deviceName + " at " + activityItem.dateTime.strftime("%Y-%m-%d %H:%M:%S") + " (" + str(int(delta_time.total_seconds())) + " seconds ago)")
								elif activityItem.action == "doorbell_motion_detected":
									indigo.server.log(u"received motion detected event at " + activityItem.deviceName + " at " + activityItem.dateTime.strftime("%Y-%m-%d %H:%M:%S") + " (" + str(int(delta_time.total_seconds())) + " seconds ago)")

								# PROCESS DOORBELL TRIGGERS
								for trigger in indigo.triggers.iter("self.doorbellMotion"):
									self.logger.debug("Checking if trigger: \"" + trigger.name + "\" has occured. Max latency: " + str(trigger.pluginProps["maxLatency"]) + ", Event delta: " + str(delta_time.total_seconds()))
									if delta_time.total_seconds() <= int(trigger.pluginProps["maxLatency"]):
										if trigger.pluginProps["eventType"] == "any":
											indigo.trigger.execute(trigger)
										elif trigger.pluginProps["eventType"] == activityItem.action:
											indigo.trigger.execute(trigger)
									else:
										self.logger.debug("   been too long.")

						
							self.logger.debug("Completed processing doorbell triggers")

						# Finally, marked the item as processed.
						activityItem.has_processed = True
						self.logger.debug("Completed processing activity item")

			self.logger.debug("Completed processing activity logs")

			if had_warnings_processing:
				self.update_all_from_august()

			self.lastServerRefresh = datetime.datetime.now()


	def update_all_from_august(self):
		had_errors = False

		for dev in [s for s in indigo.devices.iter(filter="self") if s.enabled]:
			lockDetails = self.getLockDetails(dev.pluginProps["lockID"])
			serverState = lockDetails["LockStatus"]["status"] == "locked"
			self.logger.debug("Server state for " + dev.name + " is " + str(serverState))

			batteryLevel = int(100*lockDetails["battery"])
			batteryLevelStr = u"%d%%" % (int(batteryLevel))
			dev.updateStateOnServer('batteryLevel', batteryLevel, uiValue=batteryLevelStr)

			if serverState is not None:
				if dev.onState != serverState:

					if serverState:
							indigo.server.log(u"received \"" + dev.name + "\" was locked")
					else:
							indigo.server.log(u"received \"" + dev.name + "\" was unlocked")

					dev.updateStateOnServer('onOffState', value=serverState)
					
					# Update a timestamp of the last time the device was updated
					dev.updateStateOnServer("lastStateChangeTime", datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
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

			self.createVariableFolder(valuesDict[u"indigoVariablesFolderName"])


	def createVariableFolder(self, variableFolderName):
		if variableFolderName is None:
			return

		# CREATE THE Varaible Folder
#		if variableFolderName != self.indigoVariablesFolderName:
		self.indigoVariablesFolderName = variableFolderName

		if self.indigoVariablesFolderName not in indigo.variables.folders:
			self.indigoVariablesFolderID = indigo.variables.folder.create(self.indigoVariablesFolderName).id
			indigo.server.log(self.indigoVariablesFolderName+ u" folder created")
		else:
			self.indigoVariablesFolderID=indigo.variables.folders[self.indigoVariablesFolderName].id

		self.createVariables()

	def createVariables(self):
		if self.indigoVariablesFolderID is not None:
			for dev in [s for s in indigo.devices.iter(filter="self") if s.enabled]:
				varName = dev.name.replace(' ', '_') + "_locked_minutes"
				if not varName in indigo.variables:
					indigo.variable.create(varName,folder=self.indigoVariablesFolderID)

				varName = dev.name.replace(' ', '_') + "_unlocked_minutes"
				if not varName in indigo.variables:
					indigo.variable.create(varName,folder=self.indigoVariablesFolderID)

				self.logger.debug("Created variables for lock " + dev.name)

			if self.has_doorbell:
				for houseID, houseName, activityItemList in self.house_list:
					varName = houseName.replace(' ', '_') + "_last_motion_minutes"
	
					if not varName in indigo.variables:
						indigo.variable.create(varName,folder=self.indigoVariablesFolderID)


		else:
			self.createVariableFolder(self.indigoVariablesFolderName)

	def updateVariables(self):
		self.logger.debug("started variable updates")
		if self.indigoVariablesFolderID is not None:

			if self.has_doorbell:
				for houseID, houseName, activityItemList in self.house_list:
					last_doorbell_motion_since = datetime.datetime.now() - self.last_doorbell_motion
					varName = houseName.replace(' ', '_') + "_last_motion_minutes"
					if varName in indigo.variables:
						indigo.variable.updateValue(varName, str(int(last_doorbell_motion_since.total_seconds() // 60)))
					else:
						self.createVariables()
						indigo.variable.updateValue(varName, str(int(last_doorbell_motion_since.total_seconds() // 60)))

			for dev in [s for s in indigo.devices.iter(filter="self") if s.enabled]:
				deviceTimeLocked = 0
				deviceTimeUnlocked = 0

				if dev.onState:
					deviceTimeUnlocked = 0
					try:
						deviceTimeLocked = datetime.datetime.now() - datetime.datetime.strptime(dev.states["lastStateChangeTime"], "%Y-%m-%d %H:%M:%S")
					except:
						deviceTimeLocked = 0
				elif not dev.onState:
					try:
						deviceTimeUnlocked = datetime.datetime.now() - datetime.datetime.strptime(dev.states["lastStateChangeTime"], "%Y-%m-%d %H:%M:%S")
					except:
						deviceTimeUnlocked = 0
		
					deviceTimeLocked = 0

				varName = dev.name.replace(' ', '_') + "_locked_minutes"
				if type(deviceTimeLocked) is datetime.timedelta:
					if varName in indigo.variables:
						indigo.variable.updateValue(varName, str(int(deviceTimeLocked.total_seconds() // 60)))
					dev.updateStateOnServer("locked_minutes", int(deviceTimeLocked.total_seconds() // 60))
				else:
					if varName in indigo.variables:
						indigo.variable.updateValue(varName, str(deviceTimeLocked))
					dev.updateStateOnServer("locked_minutes", deviceTimeLocked)

				varName = dev.name.replace(' ', '_') + "_unlocked_minutes"
				if type(deviceTimeUnlocked) is datetime.timedelta:
					if varName in indigo.variables:
						indigo.variable.updateValue(varName, str(int(deviceTimeUnlocked.total_seconds() // 60)))
					dev.updateStateOnServer("unlocked_minutes", int(deviceTimeUnlocked.total_seconds() // 60))
				else:
					if varName in indigo.variables:
						indigo.variable.updateValue(varName, str(deviceTimeUnlocked))
					dev.updateStateOnServer("unlocked_minutes", deviceTimeUnlocked)

		self.logger.debug("finished variable updates")

