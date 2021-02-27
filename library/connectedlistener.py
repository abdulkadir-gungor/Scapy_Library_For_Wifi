#!/usr/bin/python3
############################################################################
# 									 #
#	IEEE 802.11 Wifi Library 					 #
#	Developper:	Abdulkadir GÜNGÖR (abdulkadir_gungor@outlook.com)	 #
#	Date:	07/2020							 #
#	All Rights Reserved (Tüm Hakları Saklıdır)			 #
#                  							 #
############################################################################
from library.multifunction import eth_multi_mac, subtypeKontrol
from library.wifi import WIFIDevice, WIFIMode, WIFIChannel
from library.macvendor import MACVendor
from scapy.all import *
# **************************************************************************
# ConnectedListener ==> İlgili cihaza bağlı cihazları bulmak
# amacıyla yapılmış bir sınıf
# ConnectedListener.showConnectedMACs(mac,channel) ==> İlgili cihaza bağlı
# cihazları bulan fonksiyon
# ConnectedListener.__show() ==> İç fonsiyon.
# ConnectedListener.__addAP(pkt) ==> sniff paketleri işlemek için 
# kullanılan iç statik fonksiyon
# ConnectedListener.__macKontrol(mac) ==> iç statik fonksiyon
# ConnectedListener.__macTanila(mac) ==> iç statik fonksiyon
# ConnectedListener.reset() ==> Değerleri sıfırlar
# ConnectedListener.valReturn() ==> __Pkts_MAC_list __Exact_MACs değerlerini döndürür.
# **************************************************************************
class ConnectedListener:
	__MAC=""
	__channel=0
	__ProbeRes_MAC_List=[]
	__Authentication_MAC_List=[]
	__Pkts_MAC_List=[]
	__Exact_MACs=[]
	@classmethod
	def showConnectedMACs(cls,mac,channel):
		device=WIFIDevice.showWlanDevice()
		if (device[0]):
			try:
				WIFIMode.monitorMode()
				WIFIChannel.setChannel(channel)
			except:
				print("\n\033[1;37;41m\t Hata Oluştu.\033[0;37;39m\t")
			cls.__MAC=mac
			cls.__channel=channel
			print("\033[1;37;38m\n\n\t<Channel={}  MAC={}> İlgili cihaza bağlı olan diğer cihazlar tespit ediliyor.\033[0;37;38m".format(channel,mac) )
			print("\033[1;37;38m\t"+"-"*95+"\033[0;37;38m")
			sniff(iface=device[1], count=0, prn=cls.__addAP)
			print("\033[1;37;38m\t"+"-"*95+"\033[0;37;38m")
			try:
				WIFIMode.manageMode()
			except:
				print("\n\033[1;37;41m\t Hata Oluştu.\033[0;37;39m\t")
		if (device[0]):
			cls.__show()
		cls.__MAC=""
		cls.__channel=0
	@classmethod
	def reset(cls):
		cls.__ProbeRes_MAC_List.clear()
		cls.__Authentication_MAC_List.clear()
		cls.__Pkts_MAC_List.clear()
		cls.__MAC=""
		cls.__channel=0	
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
		cls.__Exact_MACs=exact_MACs
	@staticmethod
	def __addAP(pkt):
		if pkt.haslayer(Dot11):
			addr1=str(pkt.addr1).upper()
			addr2=str(pkt.addr2).upper()
			addr3=str(pkt.addr3).upper()
			if addr1==ConnectedListener.__MAC or addr2==ConnectedListener.__MAC or addr3==ConnectedListener.__MAC:
				subtype=pkt.subtype
				subtype_str=subtypeKontrol(subtype)
				addr1_info = ConnectedListener.__macKontrol(addr1)
				addr2_info = ConnectedListener.__macKontrol(addr2)
				addr3_info = ConnectedListener.__macKontrol(addr3)
				if addr1_info or addr2_info or addr3_info:
					color="\033[0;37;38m"
					colordefault="\033[0;37;38m"
					if subtype==5:
						pass
					elif subtype==4:
						color="\033[0;33;38m"
						if addr1_info and addr1 not in ConnectedListener.__ProbeRes_MAC_List:
							ConnectedListener.__ProbeRes_MAC_List.append(addr1)
						if addr2_info and addr2 not in ConnectedListener.__ProbeRes_MAC_List:
							ConnectedListener.__ProbeRes_MAC_List.append(addr2)
						if addr3_info and addr3 not in ConnectedListener.__ProbeRes_MAC_List:
							ConnectedListener.__ProbeRes_MAC_List.append(addr3)
					elif subtype == 11:
						if addr1_info and addr1 not in ConnectedListener.__Authentication_MAC_List:
							ConnectedListener.__Authentication_MAC_List.append(addr1)
						if addr2_info and addr2 not in ConnectedListener.__Authentication_MAC_List:
							ConnectedListener.__Authentication_MAC_List.append(addr2)
						if addr3_info and addr3 not in ConnectedListener.__Authentication_MAC_List:
							ConnectedListener.__Authentication_MAC_List.append(addr3)
						color="\033[0;32;38m"
					else:
						if addr1_info and addr1 not in ConnectedListener.__Pkts_MAC_List:
							ConnectedListener.__Pkts_MAC_List.append(addr1)
						if addr2_info and addr2 not in ConnectedListener.__Pkts_MAC_List:
							ConnectedListener.__Pkts_MAC_List.append(addr2)
						if addr3_info and addr3 not in ConnectedListener.__Pkts_MAC_List:
							ConnectedListener.__Pkts_MAC_List.append(addr3)
					print("\t{}Subtype={}\t'{}'\taddr1={}\taddr2={}\taddr3={}{}".format(color,subtype,subtype_str,addr1,addr2,addr3,colordefault) )
					print("")
	@staticmethod
	def __macKontrol(mac):
		sonuc=eth_multi_mac(mac)
		if sonuc[0]:
			return False
		else:
			if ConnectedListener.__MAC == mac:
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
		if ConnectedListener.__MAC[:14] == mac[:14]:
			back=back+"\tInfo: (Probably) Modem's (Ethernet, WLAN, WAN vs.) DHCP MAC Address"
		elif ConnectedListener.__MAC[:8] == mac[:8]:
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
