#!/usr/bin/python3
############################################################################
# 									 #
#	IEEE 802.11 Wifi Library 					 #
#	Developper:	Abdulkadir GÜNGÖR (abdulkadir_gungor@outlook.com)	 #
#	Date:	07/2020							 #
#	All Rights Reserved (Tüm Hakları Saklıdır)			 #
#                  							 #
############################################################################
from library.wifi import WIFIDevice, WIFIMode, WIFIChannel
from scapy.all import *
# **************************************************************************
# findESSID ==>
# findESSID.allESSID(channel,debug=0) => İlgili kanalda geçen tüm essid leri gösterir.	
# findESSID.macESSID(mac,channel,debug=0) => İlgili kanalda ilgili mac adresi içeren tüm essid leri gösterir. 
# findESSID.findESSID(mac,channel,debug=0) ==> (1) AP yayını alır. ESSID uzunluğuna bakar. İlgili kanalda 
# ilgili mac adresi içeren ve ESSID uzunluğuna uygun essid adlarını gösterir.
# findESSID.findESSID2(mac,channel,debug=0) ==> (2) [mantık aynı-fonksiyonda ufak fark var] AP yayını alır.
# ESSID uzunluğuna bakar. İlgili kanalda ilgili mac adresi içeren ve ESSID uzunluğuna uygun essid adlarını gösterir.
# findESSID.__addAP(pkt)  ==> sniff için paket işleme iç statik fonksiyon
# findESSID.__addAP2(pkt) ==> sniff için paket işleme iç statik fonksiyon
# findESSID.__addAP3(pkt) ==> sniff için paket işleme iç statik fonksiyon
# findESSID.__addAP4(pkt) ==> sniff için paket işleme iç statik fonksiyon
# findESSID.reset() ==> Değerleri sıfırlar
# findESSID.returnAllEssid() ==> __all_ESSIDs değerlerini döner
# findESSID.returnMACEssid() ==> __connected_mac_ESSIDs değerlerini döner
# findESSID.returnResultEssid() ==> __result_ESSIDs değerlerini döner
# **************************************************************************
class findESSID:
	__debug=0
	__MAC=""
	__channel=0
	__length_ESSID=0
	__all_ESSIDs=[]
	__connected_mac_ESSIDs=[]
	__result_ESSIDs=[]
	@classmethod
	def allESSID(cls,channel,debug=0):
		device=WIFIDevice.showWlanDevice()
		if device[0]:
			try:
				WIFIMode.monitorMode()
				WIFIChannel.setChannel(channel)
			except:
				print("\n\033[1;37;41m\t Hata Oluştu.\033[0;37;39m\t")
			cls.__channel=channel
			cls.__debug=debug
			print("\033[1;36;38m")
			print("\n\n\t\tTüm ESSID Listesi\t\t<!### Channel={} ###!>".format(channel))
			print("\t"+"-"*85)
			print("\033[0;37;38m")
			sniff(iface=device[1], count=0, prn=cls.__addAP)
			print("\n")
			try:
				WIFIMode.manageMode()
			except:
				print("\n\033[1;37;41m\t Hata Oluştu.\033[0;37;39m\t")
			cls.__channel=0
			cls.__debug=0
	@classmethod
	def macESSID(cls,mac,channel,debug=0):
		device=WIFIDevice.showWlanDevice()
		if device[0]:
			try:
				WIFIMode.monitorMode()
				WIFIChannel.setChannel(channel)
			except:
				print("\n\033[1;37;41m\t Hata Oluştu.\033[0;37;39m\t")
			cls.__channel=channel
			cls.__MAC=mac
			cls.__debug=debug
			print("\033[1;36;38m")
			print("\n\n\t\tESSID Listesi\t\t<!### Channel={} MAC={} ###!>".format(channel,mac))
			print("\t"+"-"*85)
			print("\033[0;37;38m")
			sniff(iface=device[1], count=0, prn=cls.__addAP2)
			print("\n")
			try:
				WIFIMode.manageMode()
			except:
				print("\n\033[1;37;41m\t Hata Oluştu.\033[0;37;39m\t")
			cls.__channel=0
			cls.__debug=0
			cls.__MAC=""
	@classmethod
	def findESSID(cls,mac,channel,debug=0):
		device=WIFIDevice.showWlanDevice()
		if device[0]:
			try:
				WIFIMode.monitorMode()
				WIFIChannel.setChannel(channel)
			except:
				print("\n\033[1;37;41m\t Hata Oluştu.\033[0;37;39m\t")	
			cls.__channel=channel
			cls.__MAC=mac
			cls.__debug=debug
			print("\n\n")
			sniff(iface=device[1], count=0, prn=cls.__addAP3)
			print("\n\n")
			try:
				WIFIMode.manageMode()
			except:
				print("\n\033[1;37;41m\t Hata Oluştu.\033[0;37;39m\t")
			cls.__channel=0
			cls.__debug=0
			cls.__length_ESSID=0
			cls.__MAC=""
	@classmethod
	def findESSID2(cls,mac,channel,debug=0):
		device=WIFIDevice.showWlanDevice()
		if device[0]:
			try:
				WIFIMode.monitorMode()
				WIFIChannel.setChannel(channel)
			except:
				print("\n\033[1;37;41m\t Hata Oluştu.\033[0;37;39m\t")
			cls.__channel=channel
			cls.__MAC=mac
			cls.__debug=debug
			print("\n\n")
			sniff(iface=device[1], count=0, prn=cls.__addAP4)
			print("\n\n")
			try:
				WIFIMode.manageMode()
			except:
				print("\n\033[1;37;41m\t Hata Oluştu.\033[0;37;39m\t")
			cls.__channel=0
			cls.__debug=0
			cls.__length_ESSID=0
			cls.__MAC=""
	@classmethod
	def reset(cls):
		cls.__all_ESSIDs.clear()
		cls.__connected_mac_ESSIDs.clear()
		cls.__result_ESSIDs.clear()
		cls.__channel=0
		cls.__debug=0
		cls.__length_ESSID=0
		cls.__MAC=""
	@classmethod
	def returnAllEssid(cls):
		allESSID=[]
		for tmp in  cls.__all_ESSIDs:
			allESSID.append(tmp)
		return allESSID
	@classmethod
	def returnMACEssid(cls):
		macESSID=[]
		for tmp in  cls.__connected_mac_ESSIDs:
			macESSID.append(tmp)
		return macESSID
	@classmethod
	def returnResultEssid(cls):
		resultESSID=[]
		for tmp in  cls.__result_ESSIDs:
			resultESSID.append(tmp)
		return resultESSID		
	@staticmethod
	def __addAP(pkt):
		if pkt.haslayer(Dot11):
			subtype=pkt.subtype
			if subtype==4 or subtype==5:
					try:
						#essid=(pkt.info).decode('ISO-8859-15')
						essid=(pkt.info).decode('ISO-8859-9')
						addr1=str(pkt.addr1).upper()
						addr2=str(pkt.addr2).upper()
						addr3=str(pkt.addr3).upper()
						if essid != None:
							if essid!="" and essid not in findESSID.__all_ESSIDs:
								findESSID.__all_ESSIDs.append(essid)
								print('\t{:<2})\t<{:<2} karakter>\tESSID="{}"'.format(len(findESSID.__all_ESSIDs),len(essid), essid))
								if findESSID.__debug==1:
									print("\tsubtype="+str(subtype)+" addr1="+addr1+" addr2="+addr2+" addr3="+addr3+"\n")
					except:
						pass
	@staticmethod
	def __addAP2(pkt):
		if pkt.haslayer(Dot11):
			subtype=pkt.subtype
			if subtype==4 or subtype==5:
				try:
					#essid=(pkt.info).decode('ISO-8859-15')
					essid=(pkt.info).decode('ISO-8859-9')
					addr1=str(pkt.addr1).upper()
					addr2=str(pkt.addr2).upper()
					addr3=str(pkt.addr3).upper()
					mac=findESSID.__MAC
					if mac == addr1 or mac == addr2 or mac == addr3:
						if essid != None:
							if essid!="" and essid not in findESSID.__connected_mac_ESSIDs:
								findESSID.__connected_mac_ESSIDs.append(essid)
								print('\t{:<2})\t<{:<2} karakter>\tESSID="{}"'.format(len(findESSID.__connected_mac_ESSIDs),len(essid), essid))
								if findESSID.__debug==1:
									print("\tsubtype="+str(subtype)+" addr1="+addr1+" addr2="+addr2+" addr3="+addr3+"\n")
				except:
					pass
	@staticmethod
	def __addAP3(pkt):
		if pkt.haslayer(Dot11):
			subtype=pkt.subtype
			if findESSID.__length_ESSID==0:
				if pkt.haslayer(Dot11Beacon):
					mac=(pkt.addr2).upper()
					if mac==findESSID.__MAC:
						#essid=(pkt.info).decode('ISO-8859-15')
						essid=(pkt.info).decode('ISO-8859-9')
						str_essid=str(pkt.info)
						if "\\x00" in str_essid:
							length_essid=str_essid.count("x00")
							findESSID.__length_ESSID = length_essid
							print("\033[1;32;38m\tChannel={}\tBSSID={}\tESSID=Gizli <{} karakter>\033[0;37;38m".format(findESSID.__channel,mac,length_essid))
							print("\033[1;32;38m\t"+"-"*85+"\033[0;37;38m\n")
						else:
							length_essid=len(essid)
							findESSID.__length_ESSID = length_essid
							print('\033[1;32;38m\tChannel={}\tBSSID={}\tESSID="{}"\033[0;37;38m'.format(findESSID.__channel,mac,essid))
							print("\033[1;32;38m\t"+"-"*85+"\033[0;37;38m\n")
			else:
				if subtype==4 or subtype==5:
					try:
						#essid=(pkt.info).decode('ISO-8859-15')
						essid=(pkt.info).decode('ISO-8859-9')
						addr1=str(pkt.addr1).upper()
						addr2=str(pkt.addr2).upper()
						addr3=str(pkt.addr3).upper()
						mac=findESSID.__MAC
						if mac == addr1 or mac == addr2 or mac == addr3:
							if essid != None and essid != "":
								if len(essid) == findESSID.__length_ESSID:
									if essid not in findESSID.__result_ESSIDs:
										findESSID.__result_ESSIDs.append(essid)
										print('\t{:<2})\t<{:<2} karakter>\tESSID="{}"'.format(len(findESSID.__result_ESSIDs),len(essid), essid))
										if findESSID.__debug==1:
											print("\tsubtype="+str(subtype)+" addr1="+addr1+" addr2="+addr2+" addr3="+addr3+"\n")
					except:
						pass		
	@staticmethod
	def __addAP4(pkt):
		if pkt.haslayer(Dot11Beacon) and findESSID.__length_ESSID==0:
			mac=(pkt.addr2).upper()
			if mac==findESSID.__MAC:
				essid=(pkt.info).decode('ISO-8859-9')
				#essid=(pkt.info).decode('ISO-8859-15')
				str_essid=str(pkt.info)
				if "\\x00" in str_essid:
					length_essid=str_essid.count("x00")
					findESSID.__length_ESSID = length_essid
					print("\033[1;32;38m\tChannel={}\tBSSID={}\tESSID=Gizli <{} karakter>\033[0;37;38m".format(findESSID.__channel,mac,length_essid))
					print("\033[1;32;38m\t"+"-"*85+"\033[0;37;38m\n")
				else:
					length_essid=len(essid)
					findESSID.__length_ESSID = length_essid
					print('\033[1;32;38m\tChannel={}\tBSSID={}\tESSID="{}"\033[0;37;38m'.format(findESSID.__channel,mac,essid))
					print("\033[1;32;38m\t"+"-"*85+"\033[0;37;38m\n")
		
		if pkt.haslayer(Dot11):
			subtype=pkt.subtype
			if subtype==4 or subtype==5:
				try:
					essid=(pkt.info).decode('ISO-8859-9')
					#essid=(pkt.info).decode('ISO-8859-15')
					addr1=str(pkt.addr1).upper()
					addr2=str(pkt.addr2).upper()
					addr3=str(pkt.addr3).upper()
					mac=findESSID.__MAC
					if mac == addr1 or mac == addr2 or mac == addr3:
						if essid != None and essid != "":
							if len(essid) == findESSID.__length_ESSID:
								if essid not in findESSID.__result_ESSIDs:
									findESSID.__result_ESSIDs.append(essid)
									print('\t{:<2})\t<{:<2} karakter>\tESSID="{}"'.format(len(findESSID.__result_ESSIDs),len(essid), essid))
									if findESSID.__debug==1:
										print("\tsubtype="+str(subtype)+" addr1="+addr1+" addr2="+addr2+" addr3="+addr3+"\n")
				except:
					pass		
