#!/usr/bin/python3
############################################################################
# 									 #
#	IEEE 802.11 Wifi Library 					 #
#	Developper:	Abdulkadir GÜNGÖR (abdulkadirgungor@outlook.com)	 #
#	Date:	07/2020							 #
#	All Rights Reserved (Tüm Hakları Saklıdır)			 #
#                  							 #
############################################################################
from library.wifi import WIFIDevice, WIFIMode, WIFIChannel
from scapy.all import *
import datetime, time
# **************************************************************************
# IfindESSID ==> Otomatik essid leri bulan sınıf
# IfindESSID.findESSID(mac,updateTime=5,debug=0) ==> Sadece ilgili mac adresini dinleyerek essid yi bulmaya çalışır.
# IfindESSID.find1ESSID(mac,updateTime=5,debug=0): ==>AP ile ilgili kanaldaki Tüm mac adreslerinin paketlerini dinleyerek essid yi bulmaya çalışır.
# IfindESSID.reset() ==> Değerleri sıfırlar
# IfindESSID.__addAP(pkt) ==> Sniff için paketleri işleyen iç statik fonksiyon
# IfindESSID.__addAP2(pkt) ==> Sniff için paketleri işleyen iç statik fonksiyon
# IfindESSID.__addBeacon(pkt) ==> AP leri bulmak için Beacon paketleri işleyen iç statik fonksiyon
# IfindESSID.__addAPKTS1(pkt) ==> MAC adreslerini ve essid yi bulmak için paketleri işleyen iç statik fonksiyon
# IfindESSID.__addAPKTS2(pkt) ==> MAC adreslerini ve essid yi bulmak için paketleri işleyen iç statik fonksiyon
# IfindESSID.valReturn() ==> findESSID fonksiyon sonucunu döndürür. [ __result1_ESSIDs ]
# IfindESSID.val1Return()  ==> find1ESSID fonksiyon sonucunu döndürür. [ __result2_ESSIDs ]
# **************************************************************************
class IfindESSID:
	__MAC=""
	__channel=0
	__length_ESSID=0
	__channelSetReturn=1
	__debug=0
	__isFind=0
	__updateTime=5
	__lastSeenTime=datetime.datetime.now() - datetime.timedelta(0,100)
	__result1_ESSIDs=[]
	__result2_ESSIDs=[]
	@classmethod
	def findESSID(cls,mac,updateTime=5,debug=0):
		device=WIFIDevice.showWlanDevice()
		if device[0]:
			try:
				WIFIMode.monitorMode()
				time.sleep(0.05)
			except:
				print("\n\033[1;37;41m\t Hata Oluştu.\033[0;37;39m\t")
			cls.__MAC=mac
			cls.__updateTime=updateTime
			cls.__debug=debug
			print("\033[1;37;38m")
			print("\n\n\t'{}' MAC adresi geçen paketler dinleniyor!".format(mac))		
			print("\t"+"-"*85)
			print("\033[0;37;38m")
			sniff(iface=device[1], count=0, prn=cls.__addAP)
			print("\033[1;37;38m")		
			print("\t"+"-"*85)
			print("\033[0;37;38m")
			print("\n")
			try:
				time.sleep(0.05)
				WIFIMode.manageMode()
			except:
				print("\n\033[1;37;41m\t Hata Oluştu.\033[0;37;39m\t")
			print("\n")
			say=len(cls.__result1_ESSIDs)
			if say > 0:
				print("\033[1;32;38m")
				print("\tToplam {} adet ESSID elde edildi.".format(say))
				print("\t"+"-"*45)
				print("\033[0;37;38m")
				say=1
				for tmp in cls.__result1_ESSIDs:
					print('\t{:<2})\tESSID="{}"\t<{} karakter>'.format(say,tmp,len(tmp)))
					say+=1
			else:
				print("\033[1;31;38m")
				print("\tESSID elde edilemedi.")
			print("\033[0;37;38m")
			print("\n\n")
			cls.__channel=0
			cls.__length_ESSID=0
			cls.__MAC=""
	@classmethod
	def find1ESSID(cls,mac,updateTime=5,debug=0):
		device=WIFIDevice.showWlanDevice()
		if device[0]:
			try:
				WIFIMode.monitorMode()
				time.sleep(0.05)
			except:
				print("\n\033[1;37;41m\t Hata Oluştu.\033[0;37;39m\t")
			cls.__MAC=mac
			cls.__updateTime=updateTime
			cls.__debug=debug
			print("\033[1;37;38m")
			print("\n\n\t'{}' MAC adresi ile aynı kanaldaki tüm paketler dinleniyor!".format(mac))		
			print("\t"+"-"*85)
			print("\033[0;37;38m")
			sniff(iface=device[1], count=0, prn=cls.__addAP2)
			print("\033[1;37;38m")		
			print("\t"+"-"*85)
			print("\033[0;37;38m")
			print("\n")
			try:
				time.sleep(0.05)
				WIFIMode.manageMode()
			except:
				print("\n\033[1;37;41m\t Hata Oluştu.\033[0;37;39m\t")
			print("\n")
			say=len(cls.__result2_ESSIDs)
			if say > 0:
				print("\033[1;32;38m")
				print("\tToplam {} adet ESSID elde edildi.".format(say))
				print("\t"+"-"*45)
				print("\033[0;37;38m")
				say=1
				for tmp in cls.__result2_ESSIDs:
					print('\t{:<2})\tESSID="{}"\t<{} karakter>'.format(say,tmp,len(tmp)))
					say+=1
			else:
				print("\033[1;31;38m")
				print("\tESSID elde edilemedi.")
			print("\033[0;37;38m")
			print("\n\n")
			cls.__channel=0
			cls.__length_ESSID=0
			cls.__MAC=""
	@classmethod
	def reset(cls):
		cls.__result1_ESSIDs.clear()
		cls.__result2_ESSIDs.clear()
		cls.__debug=0
		cls.__channel=0
		cls.__length_ESSID=0
		cls.__MAC=""	
	@classmethod
	def valReturn(cls):
		result=[]
		for tmp in cls.__result1_ESSIDs:
			result.append(tmp)
		return result
	@classmethod
	def val1Return(cls):
		result=[]
		for tmp in cls.__result2_ESSIDs:
			result.append(tmp)
		return result
	@staticmethod
	def __addAP(pkt):
		if datetime.datetime.now()>IfindESSID.__lastSeenTime:
			if IfindESSID.__channelSetReturn==7:
				if  IfindESSID.__channel ==  WIFIChannel.showChannel():	 
					IfindESSID.__channel += 1
					if IfindESSID.__channel>13 or IfindESSID.__channel==0:
						IfindESSID.__channel=1
					WIFIChannel.setChannel(IfindESSID.__channel)
					IfindESSID.__channelSetReturn +=1
					print ("\n\t\033[1;31;38m<MAC={}\tChannel={} cihaz aranıyor.>\033[0;37;38m\n".format(IfindESSID.__MAC,IfindESSID.__channel))
					IfindESSID.__isFind=0
				else:
					IfindESSID.__channel =  WIFIChannel.showChannel()
			else:
				IfindESSID.__channelSetReturn += 1
				if IfindESSID.__channelSetReturn > 8:
					IfindESSID.__channelSetReturn=1
		IfindESSID.__addBeacon(pkt)
		if IfindESSID.__isFind==1:
			IfindESSID.__addAPKTS1(pkt)
	@staticmethod
	def __addAP2(pkt):
		if datetime.datetime.now()>IfindESSID.__lastSeenTime:
			if IfindESSID.__channelSetReturn==7:
				if  IfindESSID.__channel ==  WIFIChannel.showChannel():	 
					IfindESSID.__channel += 1
					if IfindESSID.__channel>13 or IfindESSID.__channel==0:
						IfindESSID.__channel=1
					WIFIChannel.setChannel(IfindESSID.__channel)
					IfindESSID.__channelSetReturn +=1
					print ("\n\t\033[1;31;38m<MAC={}\tChannel={} cihaz aranıyor.>\033[0;37;38m\n".format(IfindESSID.__MAC,IfindESSID.__channel))
					IfindESSID.__isFind=0
				else:
					IfindESSID.__channel =  WIFIChannel.showChannel()
			else:
				IfindESSID.__channelSetReturn += 1
				if IfindESSID.__channelSetReturn > 8:
					IfindESSID.__channelSetReturn=1
		IfindESSID.__addBeacon(pkt)
		if IfindESSID.__isFind==1:
			IfindESSID.__addAPKTS2(pkt)
	@staticmethod
	def __addBeacon(pkt):
		if pkt.haslayer(Dot11Beacon):
			mac=(pkt.addr2).upper()
			if mac == IfindESSID.__MAC:
				IfindESSID.__lastSeenTime=datetime.datetime.now()+datetime.timedelta(0,IfindESSID.__updateTime)	
				channel=int(str(ord( pkt[Dot11Elt:3].info )))
				if IfindESSID.__isFind==0:
					IfindESSID.__isFind=1
					print ("\n\t\033[1;32;38m<MAC={}\tChannel={} cihaz bulundu.>\033[0;37;38m\n".format(mac,channel))
					WIFIChannel.setChannel(channel)
					IfindESSID.__channel=channel
					IfindESSID.__length_ESSID=0
				IfindESSID.__lastSeenTime=datetime.datetime.now()+datetime.timedelta(0,IfindESSID.__updateTime)	
		if pkt.haslayer(Dot11):
			addr1=str(pkt.addr1).upper()
			addr2=str(pkt.addr2).upper()
			addr3=str(pkt.addr3).upper()
			mac = IfindESSID.__MAC
			if mac == addr1 or mac == addr2 or mac == addr3:
				IfindESSID.__lastSeenTime=datetime.datetime.now()+datetime.timedelta(0,IfindESSID.__updateTime)
	@staticmethod
	def __addAPKTS1(pkt):
		if pkt.haslayer(Dot11Beacon) and IfindESSID.__length_ESSID==0:
			mac=(pkt.addr2).upper()
			if mac==IfindESSID.__MAC:
				essid=(pkt.info).decode('ISO-8859-9')
				#essid=(pkt.info).decode('ISO-8859-15')
				str_essid=str(pkt.info)
				channel=int(str(ord( pkt[Dot11Elt:3].info )))
				if "\\x00" in str_essid:
					length_essid=str_essid.count("x00")
					IfindESSID.__length_ESSID = length_essid
					print("\033[1;32;38m\tChannel={}\tBSSID={}\tESSID=Gizli <{} karakter>\033[0;37;38m\n".format(channel,mac,length_essid))
				else:
					length_essid=len(essid)
					IfindESSID.__length_ESSID = length_essid
					print('\033[1;32;38m\tChannel={}\tBSSID={}\tESSID="{}"\033[0;37;38m\n'.format(channel,mac,essid))

		if pkt.haslayer(Dot11) and IfindESSID.__length_ESSID!=0:
			subtype=pkt.subtype
			if subtype==4 or subtype==5:
				try:
					essid=(pkt.info).decode('ISO-8859-9')
					#essid=(pkt.info).decode('ISO-8859-15')
					addr1=str(pkt.addr1).upper()
					addr2=str(pkt.addr2).upper()
					addr3=str(pkt.addr3).upper()
					mac=IfindESSID.__MAC
					if mac == addr1 or mac == addr2 or mac == addr3:
						if essid != None and essid != "":
							if len(essid) == IfindESSID.__length_ESSID:
								if essid not in IfindESSID.__result1_ESSIDs:
									IfindESSID.__result1_ESSIDs.append(essid)
									print('\t{:<2})\t<{:<2} karakter>\tESSID="{}"'.format(len(IfindESSID.__result1_ESSIDs),len(essid), essid))
									if IfindESSID.__debug==1:
										print("\tsubtype="+str(subtype)+" addr1="+addr1+" addr2="+addr2+" addr3="+addr3+"\n")
				except:
					pass					
		if pkt.haslayer(Dot11):
			addr1=str(pkt.addr1).upper()
			addr2=str(pkt.addr2).upper()
			addr3=str(pkt.addr3).upper()
			mac = IfindESSID.__MAC
			if mac == addr1 or mac == addr2 or mac == addr3:
				IfindESSID.__lastSeenTime=datetime.datetime.now()+datetime.timedelta(0,IfindESSID.__updateTime)
	@staticmethod
	def __addAPKTS2(pkt):
		if pkt.haslayer(Dot11Beacon) and IfindESSID.__length_ESSID==0:
			mac=(pkt.addr2).upper()
			if mac==IfindESSID.__MAC:
				essid=(pkt.info).decode('ISO-8859-9')
				#essid=(pkt.info).decode('ISO-8859-15')
				str_essid=str(pkt.info)
				channel=int(str(ord( pkt[Dot11Elt:3].info )))
				if "\\x00" in str_essid:
					length_essid=str_essid.count("x00")
					IfindESSID.__length_ESSID = length_essid
					print("\033[1;32;38m\tChannel={}\tBSSID={}\tESSID=Gizli <{} karakter>\033[0;37;38m\n".format(channel,mac,length_essid))
				else:
					length_essid=len(essid)
					IfindESSID.__length_ESSID = length_essid
					print('\033[1;32;38m\tChannel={}\tBSSID={}\tESSID="{}"\033[0;37;38m\n'.format(channel,mac,essid))

		if pkt.haslayer(Dot11) and IfindESSID.__length_ESSID!=0:
			subtype=pkt.subtype
			if subtype==4 or subtype==5:
				try:
					essid=(pkt.info).decode('ISO-8859-9')
					#essid=(pkt.info).decode('ISO-8859-15')
					addr1=str(pkt.addr1).upper()
					addr2=str(pkt.addr2).upper()
					addr3=str(pkt.addr3).upper()
					if essid != None and essid != "":
						if len(essid) == IfindESSID.__length_ESSID:
							if essid not in IfindESSID.__result2_ESSIDs:
								IfindESSID.__result2_ESSIDs.append(essid)
								print('\t{:<2})\t<{:<2} karakter>\tESSID="{}"'.format(len(IfindESSID.__result2_ESSIDs),len(essid), essid))
								if IfindESSID.__debug==1:
									print("\tsubtype="+str(subtype)+" addr1="+addr1+" addr2="+addr2+" addr3="+addr3+"\n")
				except:
					pass					
		if pkt.haslayer(Dot11):
			addr1=str(pkt.addr1).upper()
			addr2=str(pkt.addr2).upper()
			addr3=str(pkt.addr3).upper()
			mac = IfindESSID.__MAC
			if mac == addr1 or mac == addr2 or mac == addr3:
				IfindESSID.__lastSeenTime=datetime.datetime.now()+datetime.timedelta(0,IfindESSID.__updateTime)
