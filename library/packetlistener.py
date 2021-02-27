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
from scapy.all import *
# **************************************************************************
# PaketLister ==> İlgili MAC adresinin tüm paketleri dinlemek 
# amacıyla yapılmış bir sınıf
# PaketLister.showAll(mac,channel) ==> İlgili MAC için tüm paketleri 
# gösterir
# PaketLister.showAllReal(mac,channel) ==> İlgili MAC için gerçek adres 
# içeren paketleri gösterir.
# PaketLister.__addAP(pkt) ==> sniff için paket işleme fonksiyonu
# PaketLister.__addAP2(pkt) ==> sniff için paket işleme fonksiyonu
# PaketLister.__macKontrol(mac)==> MAC adreslerini kontrol eden 
# iç fonksiyon
# PaketLister.__macKontrol2(mac): ==> MAC adreslerini kontrol eden
# iç fonksiyon
# **************************************************************************
class PacketListener:
	__MAC=""
	__channel=0
	@classmethod
	def showAll(cls,mac,channel):
		device=WIFIDevice.showWlanDevice()
		if (device[0]):
			try:
				WIFIMode.monitorMode()
				WIFIChannel.setChannel(channel)
			except:
				print("\n\033[1;37;41m\t Hata Oluştu.\033[0;37;39m\t")
			cls.__MAC=mac
			cls.__channel=channel
			print("\033[1;37;38m\n\n\t<Channel={}  MAC={}> Tüm adreslere gönderilen paketler dinleniyor.\033[0;37;38m".format(channel,mac) )
			print("\033[1;37;38m\t"+"-"*95+"\033[0;37;38m")
			sniff(iface=device[1], count=0, prn=cls.__addAP)
			print("\033[1;37;38m\t"+"-"*95+"\033[0;37;38m")
			try:
				WIFIMode.manageMode()
			except:
				print("\n\033[1;37;41m\t Hata Oluştu.\033[0;37;39m\t")
		cls.__MAC=""
	@classmethod
	def showAllReal(cls,mac,channel):
		device=WIFIDevice.showWlanDevice()
		if (device[0]):
			try:
				WIFIMode.monitorMode()
				WIFIChannel.setChannel(channel)
			except:
				print("\n\033[1;37;41m\t Hata Oluştu.\033[0;37;39m\t")
			cls.__MAC=mac
			cls.__channel=channel
			print("\033[1;37;38m\n\n\t<Channel={}  MAC={}> Gerçek olan adreslere gönderilen paketler dinleniyor.\033[0;37;38m".format(channel,mac) )
			print("\033[1;37;38m\t"+"-"*95+"\033[0;37;38m")
			sniff(iface=device[1], count=0, prn=cls.__addAP2)
			print("\033[1;37;38m\t"+"-"*95+"\033[0;37;38m")
			try:
				WIFIMode.manageMode()
			except:
				print("\n\033[1;37;41m\t Hata Oluştu.\033[0;37;39m\t")
		cls.__MAC=""
	@staticmethod
	def __addAP(pkt):
		if pkt.haslayer(Dot11):
			addr1=str(pkt.addr1).upper()
			addr2=str(pkt.addr2).upper()
			addr3=str(pkt.addr3).upper()
			if addr1==PacketListener.__MAC or addr2==PacketListener.__MAC or addr3==PacketListener.__MAC:
				subtype=pkt.subtype
				subtype_str=subtypeKontrol(subtype)
				addr1_info = PacketListener.__macKontrol(addr1)
				addr2_info = PacketListener.__macKontrol(addr2)
				addr3_info = PacketListener.__macKontrol(addr3)
				print("\tSubtype={}\t'{}'\taddr1={}\taddr2={}\taddr3={}".format(subtype,subtype_str,addr1,addr2,addr3) )
				print("\taddr1={}\t {}".format(addr1,addr1_info) )
				print("\taddr2={}\t {}".format(addr2,addr2_info) )
				print("\taddr3={}\t {}".format(addr3,addr3_info) )
				print("")
	@staticmethod
	def __addAP2(pkt):
		if pkt.haslayer(Dot11):
			addr1=str(pkt.addr1).upper()
			addr2=str(pkt.addr2).upper()
			addr3=str(pkt.addr3).upper()
			if addr1==PacketListener.__MAC or addr2==PacketListener.__MAC or addr3==PacketListener.__MAC:
				subtype=pkt.subtype
				subtype_str=subtypeKontrol(subtype)
				addr1_info = PacketListener.__macKontrol2(addr1)
				addr2_info = PacketListener.__macKontrol2(addr2)
				addr3_info = PacketListener.__macKontrol2(addr3)
				if addr1_info[0] or addr2_info[0] or addr3_info[0] :
					color="\033[0;37;38m"
					colordefault="\033[0;37;38m"
					if subtype==4 or subtype ==5:
						color="\033[0;33;38m"
					elif subtype == 11:
						color="\033[0;32;38m"
					elif subtype == 12:
						color="\033[0;31;38m"
					print("\t{}Subtype={}\t'{}'\taddr1={}\taddr2={}\taddr3={}".format(color,subtype,subtype_str,addr1,addr2,addr3) )
					print("\taddr1={}\t {}".format(addr1,addr1_info[1]) )
					print("\taddr2={}\t {}".format(addr2,addr2_info[1]) )
					print("\taddr3={}\t {}{}".format(addr3,addr3_info[1],colordefault) )
					print("")
	@staticmethod
	def __macKontrol(mac):
		sonuc=eth_multi_mac(mac)
		if sonuc[0]:
			return ("Special address\tinfo="+sonuc[1])
		else:
			if PacketListener.__MAC == mac:
				return "Listened the address"
			elif mac=="NONE":
				return "<NULL>"
			elif PacketListener.__MAC[:14] == mac[:14]:
				return "Probably listened the address"
			else:
				return "Probably real address"
	@staticmethod
	def __macKontrol2(mac):
		sonuc=eth_multi_mac(mac)
		if sonuc[0]:
			return [False,("Special address\tinfo="+sonuc[1])]
		else:
			if PacketListener.__MAC == mac:
				return [False,"Listened the address"]
			elif mac=="NONE":
				return [False,"<NULL>"]
			elif PacketListener.__MAC[:14] == mac[:14]:
				return [False,"Probably listened the address"]
			else:
				return [True,"Probably real address"]
