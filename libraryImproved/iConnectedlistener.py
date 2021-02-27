#!/usr/bin/python3
############################################################################
# 									 #
#	IEEE 802.11 Wifi Library 					 #
#	Developper:	Abdulkadir GÜNGÖR (abdulkadirgungor@outlook.com)	 #
#	Date:	07/2020							 #
#	All Rights Reserved (Tüm Hakları Saklıdır)			 #
#                  							 #
############################################################################
from library.multifunction import eth_multi_mac, subtypeKontrol
from library.wifi import WIFIDevice, WIFIMode, WIFIChannel
from library.macvendor import MACVendor
from scapy.all import *
import datetime, time
# **************************************************************************
# IConnectedListener ==> İlgili cihaza bağlı cihazları bulmak için yazılmış bir sınıf
# IConnectedListener.showConnectedMACs (mac, updateTime=5) ==> İlgili cihaza bağlı cihazları bulan fonksiyon
# IConnectedListener.__show(cls)  ==> Sonuçları gösteren iç fonksiyon
# IConnectedListener.__addAP(pkt)  ==> sniff fonksiyonu paketleri dinleyen iç fonksiyon 
# IConnectedListener.__addBeacon(pkt) ==> özel iç statik fonksiyon
# IConnectedListener.__macKontrol(mac) ==> MAC adresleri vendorlerini bulan özel iç statik fonksiyon
# IConnectedListener.__macTanila(mac) ==> özel iç statik fonksiyon
# IConnectedListener.__macTanila2(mac) ==> özel iç statik fonksiyon
# IConnectedListener.reset() ==> Tüm değerleri sıfırlar
# IConnectedListener.valReturn() ==> __Pkts_MAC_list __Exact_MACs değerlerini döndürür.
# **************************************************************************
class IConnectedListener:
	__MAC=""
	__channel=0
	__channelSetReturn=1
	__isFind=0
	__updateTime=5
	__lastSeenTime=datetime.datetime.now() - datetime.timedelta(0,100)
	__ProbeRes_MAC_List=[]
	__Authentication_MAC_List=[]
	__Pkts_MAC_List=[]
	__Exact_MACs=[]
	@classmethod
	def showConnectedMACs(cls,mac, updateTime=5):
		device=WIFIDevice.showWlanDevice()
		if (device[0]):
			try:
				WIFIMode.monitorMode()
				time.sleep(0.05)
			except:
				print("\n\033[1;37;41m\tMonitor Mode'a ayarlanamadı.\033[0;37;39m\t")
			cls.__MAC=mac
			cls.__updateTime=updateTime
			print("\n\n\033[1;37;38m\t"+"-"*95+"\033[0;37;38m")
			sniff(iface=device[1], count=0, prn=cls.__addAP)
			print("\033[1;37;38m\t"+"-"*95+"\033[0;37;38m\n\n")
			try:
				time.sleep(0.05)
				WIFIMode.manageMode()
			except:
				print("\n\033[1;37;41m\tManaged Mode'a ayarlanamadı.\033[0;37;39m\t")
			cls.__show()
		cls.__MAC=""
		cls.__channel=0
		cls.__channelSetReturn=1
	@classmethod
	def reset(cls):
		cls.__ProbeRes_MAC_List.clear()
		cls.__Authentication_MAC_List.clear()
		cls.__Pkts_MAC_List.clear()
		cls.__Exact_MACs.clear()
		cls.__MAC=""
		cls.__channel=0
		cls.__isFind=0
	@classmethod
	def valReturn(cls):
		result1=[]
		result2=[]
		for tmp in cls.__Pkts_MAC_List:
			result1.append(tmp)
		for tmp in cls.__Exact_MACs:
			result2.append(tmp)
		return [result1, result2]
	@classmethod
	def __show(cls):
		print("\n\n\n")
		print("\033[1;33;38m\t<--- Access Point={}\tChannel={} --->\033[0;37;38m\n\n".format(cls.__MAC, cls.__channel))
		exact_MACs=[]
		if len(cls.__Pkts_MAC_List)>0:
			print("\033[1;36;38m\t(Muhtemel) Bağlı Olan Cihazlar\t\t### {} adet cihaz bulundu. ###".format(len(cls.__Pkts_MAC_List)))
			print("\t"+"-"*95+"\033[0;37;38m")
			for tmp in cls.__Pkts_MAC_List:
				print("\t"+tmp+cls.__macTanila(tmp))
				if tmp in cls.__ProbeRes_MAC_List or tmp in cls.__Authentication_MAC_List:
					exact_MACs.append(tmp)
			print("\n")
			if len(exact_MACs)>0:
				print("\033[1;32;38m\t(Kesin) Bağlı Olan Cihazlar\t\t### {} adet cihaz bulundu. ###".format(len(exact_MACs)))
				print("\t"+"-"*95+"\033[0;37;38m")
				for tmp in exact_MACs:
					print("\t"+tmp+cls.__macTanila2(tmp))
			print("\n")		
		else:
			if len(cls.__Authentication_MAC_List)>0:
				print("\t\033[1;36;38m(Authentication) Yetkilendirme İsteği Olan Cihazlar\t\t### {} adet cihaz bulundu. ###".format(len(cls.__Authentication_MAC_List)))
				print("\t"+"-"*95+"\033[0;37;38m")
				for tmp in cls.__Authentication_MAC_List:
					print("\t"+tmp+cls.__macTanila(tmp))
				print("\n")
			if len(cls.__ProbeRes_MAC_List)>0:
				print("\t\033[1;36;38m(Probe Response) Bağlantı İsteği Olan Cihazlar\t\t### {} adet cihaz bulundu. ###".format(len(cls.__ProbeRes_MAC_List)))
				print("\t"+"-"*95+"\033[0;37;38m")
				for tmp in cls.__ProbeRes_MAC_List:
					print("\t"+tmp+cls.__macTanila(tmp))
				print("\n")
		print("\n")
		cls.__Exact_MACs = exact_MACs
	def __addAP(pkt):
		if datetime.datetime.now()>IConnectedListener.__lastSeenTime:
			if IConnectedListener.__channelSetReturn==7:
				if  IConnectedListener.__channel ==  WIFIChannel.showChannel():	 
					IConnectedListener.__channel += 1
					if IConnectedListener.__channel>13 or IConnectedListener.__channel==0:
						IConnectedListener.__channel=1
					WIFIChannel.setChannel(IConnectedListener.__channel)
					IConnectedListener.__channelSetReturn +=1
					print ("\n\t\033[1;31;38m<MAC={}\tChannel={} cihaz aranıyor.>\033[0;37;38m\n".format(IConnectedListener.__MAC,IConnectedListener.__channel))
					IConnectedListener.__isFind=0
				else:
					IConnectedListener.__channel =  WIFIChannel.showChannel()
			else:
				IConnectedListener.__channelSetReturn += 1
				if IConnectedListener.__channelSetReturn > 8:
					IConnectedListener.__channelSetReturn=1
		IConnectedListener.__addBeacon(pkt)
		if IConnectedListener.__isFind==1:
			IConnectedListener.__addPKTS(pkt)
	@staticmethod
	def __addBeacon(pkt):
		if pkt.haslayer(Dot11Beacon):
			mac=(pkt.addr2).upper()
			if mac == IConnectedListener.__MAC:
				IConnectedListener.__lastSeenTime=datetime.datetime.now()+datetime.timedelta(0,IConnectedListener.__updateTime)	
				channel=int(str(ord( pkt[Dot11Elt:3].info )))
				if IConnectedListener.__isFind==0:
					IConnectedListener.__isFind=1
					print ("\n\t\033[1;32;38m<MAC={}\tChannel={} cihaz bulundu.>\033[0;37;38m\n".format(mac,channel))
					WIFIChannel.setChannel(channel)
					IConnectedListener.__channel=channel
				IConnectedListener.__lastSeenTime=datetime.datetime.now()+datetime.timedelta(0,IConnectedListener.__updateTime)	
		if pkt.haslayer(Dot11):
			addr1=str(pkt.addr1).upper()
			addr2=str(pkt.addr2).upper()
			addr3=str(pkt.addr3).upper()
			mac = IConnectedListener.__MAC
			if mac == addr1 or mac == addr2 or mac == addr3:
				IConnectedListener.__lastSeenTime=datetime.datetime.now()+datetime.timedelta(0,IConnectedListener.__updateTime)
	@staticmethod
	def __addPKTS(pkt):
		if pkt.haslayer(Dot11):
			addr1=str(pkt.addr1).upper()
			addr2=str(pkt.addr2).upper()
			addr3=str(pkt.addr3).upper()
			if addr1==IConnectedListener.__MAC or addr2==IConnectedListener.__MAC or addr3==IConnectedListener.__MAC:
				subtype=pkt.subtype
				subtype_str=subtypeKontrol(subtype)
				addr1_info = IConnectedListener.__macKontrol(addr1)
				addr2_info = IConnectedListener.__macKontrol(addr2)
				addr3_info = IConnectedListener.__macKontrol(addr3)
				if addr1_info or addr2_info or addr3_info:
					color="\033[0;37;38m"
					colordefault="\033[0;37;38m"
					if subtype==5:
						pass
					elif subtype==4:
						color="\033[0;33;38m"
						if addr1_info and addr1 not in IConnectedListener.__ProbeRes_MAC_List:
							IConnectedListener.__ProbeRes_MAC_List.append(addr1)
						if addr2_info and addr2 not in IConnectedListener.__ProbeRes_MAC_List:
							IConnectedListener.__ProbeRes_MAC_List.append(addr2)
						if addr3_info and addr3 not in IConnectedListener.__ProbeRes_MAC_List:
							IConnectedListener.__ProbeRes_MAC_List.append(addr3)
					elif subtype == 11:
						if addr1_info and addr1 not in IConnectedListener.__Authentication_MAC_List:
							IConnectedListener.__Authentication_MAC_List.append(addr1)
						if addr2_info and addr2 not in IConnectedListener.__Authentication_MAC_List:
							IConnectedListener.__Authentication_MAC_List.append(addr2)
						if addr3_info and addr3 not in IConnectedListener.__Authentication_MAC_List:
							IConnectedListener.__Authentication_MAC_List.append(addr3)
						color="\033[0;32;38m"
					else:
						if addr1_info and addr1 not in IConnectedListener.__Pkts_MAC_List:
							IConnectedListener.__Pkts_MAC_List.append(addr1)
						if addr2_info and addr2 not in IConnectedListener.__Pkts_MAC_List:
							IConnectedListener.__Pkts_MAC_List.append(addr2)
						if addr3_info and addr3 not in IConnectedListener.__Pkts_MAC_List:
							IConnectedListener.__Pkts_MAC_List.append(addr3)
					print("\t{}Subtype={}\t'{}'\taddr1={}\taddr2={}\taddr3={}{}".format(color,subtype,subtype_str,addr1,addr2,addr3,colordefault) )
					print("")
				IConnectedListener.__lastSeenTime=datetime.datetime.now()+datetime.timedelta(0,IConnectedListener.__updateTime)
	@staticmethod
	def __macKontrol(mac):
		sonuc=eth_multi_mac(mac)
		if sonuc[0]:
			return False
		else:
			if IConnectedListener.__MAC == mac:
				return False
			elif mac=="NONE":
				return False
			else:
				return True
	@staticmethod
	def __macTanila(mac):
		back=""
		result=MACVendor (mac)
		if result[0]:
			back="\tVendor: "+result[1]
		if IConnectedListener.__MAC[:14] == mac[:14]:
			back=back+"\tInfo: (Probably) Modem's (Ethernet, WLAN, WAN vs.) DHCP MAC Address"
		elif IConnectedListener.__MAC[:8] == mac[:8]:
			back=back+"\t### <Same Vendor> ###"
		if back == "":
			back="\t###<NULL>###"
		return back
	@staticmethod
	def __macTanila2(mac):
		back=""
		result=MACVendor (mac)
		if result[0]:
			back="\tVendor: "+result[1]
		if back == "":
			back="\t###<NULL>###"
		return back
