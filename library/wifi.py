#!/usr/bin/python3
############################################################################
# 									 #
#	IEEE 802.11 Wifi Library 					 #
#	Developper:	Abdulkadir GÜNGÖR (abdulkadirgungor@outlook.com)	 #
#	Date:	07/2020							 #
#	All Rights Reserved (Tüm Hakları Saklıdır)			 #
#                  							 #
############################################################################
import subprocess, time
# ***********************************************************************
# WIFIDevice ==> Wifi Cihazları İçin Sınıf
# WIFIDevice.findWlanDevice() ==> Wifi Cihazlarını bulur
# WIFIDevice.showWlanDevice() ==> Seçilmiş Wifi Cihazını gösterir
# WIFIDevice.showAllWlanDevice() ==> Wifi cihazlarını gösterir.
# WIFIDevice.selectWlanDevice(number) ==> Wifi cihazını seçmek 
# için kullanılır
# *************************************************************************
class WIFIDevice:
	__WIFISelectedDevice=None
	__WIFIList=[]
	@classmethod
	def __addWlanDevice(cls,device):
		cls.__WIFIList.append(device)
	@classmethod
	def __resetWlanDevice(cls):
		cls.__WIFISelectedDevice=None
		cls.__WIFIList.clear()
	@classmethod
	def selectWlanDevice(cls,number=1):
		cihaz_sayisi=len(cls.__WIFIList)
		if cihaz_sayisi!=0:
			temp_number=number-1
			if cihaz_sayisi>temp_number:
				cls.__WIFISelectedDevice=cls.__WIFIList[temp_number]
	@classmethod
	def showWlanDevice(cls):
		if cls.__WIFISelectedDevice != None:
			return [True, cls.__WIFISelectedDevice]
		else:
			return [False, ""]
	@classmethod
	def showAllWlanDevice(cls):
		return cls.__WIFIList
	@classmethod
	def findWlanDevice(cls):
		cls.__resetWlanDevice()
		temp_output = subprocess.check_output("nmcli device show", shell=True)
		time.sleep(0.15)
		shell_output =temp_output.decode('ISO-8859-15')
		if (shell_output.find("wifi")!=-1):
			shell_output_split = shell_output.split("\n")
			for ii in range(1,len(shell_output_split),1):
				if shell_output_split[ii].find("wifi")!=-1:
					cls.__addWlanDevice(shell_output_split[ii-1].split(":")[1].strip())
		cls.selectWlanDevice()
# ***********************************************************************
# WIFIMode ==> Wifi için Manage/Monitor Mode
# WIFIMode.isManageMode() ==> Manage mode'a mı?
# WIFIMode.isMonitorMode() ==> Monitor mode'a mı?
# WIFIMode.manageMode() ==> Wifi yi Monitor mode'a ayarlar. 
# WIFIMode.monitorMode() ==> Wifi yi Manage mode'a ayarlar.
# ***********************************************************************
class WIFIMode:
	__monitor=False
	@classmethod
	def __update(cls):
		iface=WIFIDevice.showWlanDevice()
		if iface[0]:
			temp_output = subprocess.check_output("iwconfig {}".format(iface[1]), shell=True)
			time.sleep(0.15)
			shell_output =temp_output.decode('ISO-8859-15')
			place_number=shell_output.find("Mode")
			if (place_number!=-1):
				shell_output_temp = shell_output[place_number+5:place_number+12:1]
				if shell_output_temp == "Managed":
					cls.__monitor=False
				elif shell_output_temp == "Monitor":
					cls.__monitor=True
				else:
					print("\n\033[1;37;41m\tWIFIMOde Class 'Manage/Monitor' hata oluştu.\033[0;37;39m\n")
					cls.__monitor=False
		else:
			print("\n\033[1;37;41m\tWifi cihazı bulunamadı\033[0;37;39m\t")
			__monitor=False
	@classmethod
	def isManageMode(cls):
		cls.__update()
		return not cls.__monitor
	@classmethod
	def isMonitorMode(cls):
		cls.__update()
		return cls.__monitor
	@classmethod
	def manageMode(cls):
		iface=WIFIDevice.showWlanDevice()
		if iface[0]:
			try:
				subprocess.check_output("ip link set dev {} down".format(iface[1]), shell=True)
				time.sleep(0.10)
				subprocess.check_output("ip link set dev {} down".format(iface[1]), shell=True)
				time.sleep(0.15)
				subprocess.check_output("iwconfig {} mode managed".format(iface[1]), shell=True)
				time.sleep(0.25)
				subprocess.check_output("ip link set dev {} up".format(iface[1]), shell=True)
				time.sleep(0.15)
				subprocess.check_output("ip link set dev {} up".format(iface[1]), shell=True)
				time.sleep(0.10)
				subprocess.check_output("ip link set dev {} up".format(iface[1]), shell=True)
			except:
				pass
		cls.__update()
		return not cls.__monitor
	@classmethod
	def monitorMode(cls):
		iface=WIFIDevice.showWlanDevice()
		if iface[0]:
			try:
				subprocess.check_output("ip link set dev {} down".format(iface[1]), shell=True)
				time.sleep(0.10)
				subprocess.check_output("ip link set dev {} down".format(iface[1]), shell=True)
				time.sleep(0.15)
				subprocess.check_output("iwconfig {} mode monitor".format(iface[1]), shell=True)
				time.sleep(0.25)
				subprocess.check_output("ip link set dev {} up".format(iface[1]), shell=True)
				time.sleep(0.15)
				subprocess.check_output("ip link set dev {} up".format(iface[1]), shell=True)
				ime.sleep(0.10)
				subprocess.check_output("ip link set dev {} up".format(iface[1]), shell=True)
			except:
				pass
		cls.__update()
		return cls.__monitor		
# ***********************************************************************
# WIFIChannel ==> Wifi Channel Ayarlar
# WIFIChannel.setChannel(channel) ==> Kanal ayarlar.
# WIFIChannel.autoChannel() ==> Otomatik kanal ayarlar
# WIFIChannel.showChannel() ==> Kanalı gösterir.
# ***********************************************************************
class WIFIChannel:
	__channel=0
	@classmethod
	def setChannel(cls,channel):
		iface=WIFIDevice.showWlanDevice()
		if iface[0]:
			if WIFIMode.isMonitorMode():
				subprocess.check_output("iwconfig {} channel {}".format(iface[1],channel), shell=True)
				time.sleep(0.005)
				cls.__channel=channel
				return True
			else:
				print("\n\033[1;37;41m\tChannel'i ayarlamak için Wifi 'Monitor mode'a olmalı.\033[0;37;39m\n")
		cls.__channel=0
		return False
	@classmethod
	def autoChannel(cls):
		channel=cls.__channel
		channel +=1
		iface=WIFIDevice.showWlanDevice()
		if (channel>0 and channel<14):
			if iface[0]:
				if WIFIMode.isMonitorMode():
					subprocess.check_output("iwconfig {} channel {}".format(iface[1],channel), shell=True)
					time.sleep(0.005)
					cls.__channel=channel
		else:
			cls.__channel=0
	@classmethod
	def showChannel(cls):
		return cls.__channel
