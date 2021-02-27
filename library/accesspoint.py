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
from library.macvendor import MACVendor 
from scapy.all import *
# ***********************************************************************
# AP ==> Ap sınıfı, APFinder sınıfı için bir veri yapısı
# Veri yapısı olduğu için fonksiyon içermez
# ***********************************************************************
class AP:
	def __init__(self,pkt):
		self.mac=(pkt.addr2).upper()
		self.essid=(pkt.info).decode('ISO-8859-9') 
		#self.essid=(pkt.info).decode('ISO-8859-9') ==> Turkish 
		#self.essid=(pkt.info).decode('ISO-8859-15') ==> latin
		self.channel=int(str(ord( pkt[Dot11Elt:3].info )))
		self.signal=int(pkt.dBm_AntSignal)	
		str_essid=str(pkt.info)
		if "\\x00" in str_essid:
			self.length_essid=str_essid.count("x00")
			self.hidden_essid=True
		else:
			self.length_essid=0
			self.hidden_essid=False
# ***********************************************************************
# APFind ==> AP sınıfı, Acces Pointleri bulmak için yazılmış sınıf
# APFind.__addAP() ==> sniff() fonksiyonu için paket işleme fonksiyonu
# APFind.showAP(kayit=0)  ==> Access Pointleri bulan fonksiyon ve kaydeden
# fonksiyondur. Bu fonksiyon çalışmadan showAPList() fonksiyonu
# çalışmaz.
# APFind.showAPList()  ==> Bulunan BSSID lerin MAC adreslerine bakarak
# veritabanından üretici firmaları bulur. showAP() fonksiyonu
# çalışmadan bu fonksiyon çalışmaz.
# APFind.reset() ==> Değerleri sıfırlar
# ***********************************************************************
class APFind:
	mac_list=[]
	ap_list=[]
	pkt_list=[]
	don=0
	ii=0
	@classmethod
	def showAP(cls, kayit=0):
		device=WIFIDevice.showWlanDevice()
		if (device[0]):
			try:
				WIFIMode.monitorMode()
				WIFIChannel.autoChannel()
			except:
				print("\n\033[1;37;41m\t Hata Oluştu.\033[0;37;39m\t")
			print("\033[1;33;38m\n\n\t{:<3}\t{:<20}\t{:<40}\t{:<3}\t{:<4}".format("No","BSSID","ESSID","Ch","Signal") )
			print("\t"+"-"*3+"\t"+"-"*20+"\t"+"-"*40+"\t"+"-"*3+"\t"+"-"*7+"\033[0;37;38m")
			sniff(iface=device[1], count=0, prn=cls.__addAP)
			if kayit!=0:
				wrpcap("AccessPointLog.pcap",APFind.pkt_list)
			print("\033[1;33;38m\t"+"-"*95+"\033[0;37;38m")
			if kayit!=0:
				print('\n\033[1;33;38m\tİlgili paketler "AccessPointLog.pcap" olarak kayit edildi.\033[0;37;38m')
			print("\n\n")
			try:
				WIFIMode.manageMode()
			except:
				print("\n\033[1;37;41m\t Hata Oluştu.\033[0;37;39m\t")
		else:
			print("\n\033[1;37;41m\tWIFI cihazı bulunamadı.\033[0;37;39m\n")	
		APFind.ii=0
		APFind.don=0
	@classmethod
	def reset(cls):
		cls.pkt_list.clear()
		cls.mac_list.clear()
		cls.mac_list.clear()
		cls.ii=0
		cls.don=0	
	@staticmethod
	def __addAP(pkt):
		if pkt.haslayer(Dot11Beacon):
			ap= AP(pkt) 
			mac=ap.mac 
			if (mac not in APFind.mac_list):
				APFind.mac_list.append(mac)
				APFind.ap_list.append(ap)
				APFind.pkt_list.append(pkt)
				APFind.ii+=1
				if (ap.hidden_essid):
					essid='"Gizli <'+str(ap.length_essid)+' karakter>"'
					print("\t{:<3}\t{:<20}\t\033[1;34;38m{:<40}\033[0;37;38m\t{:<3}\t{:<4}".format(APFind.ii,ap.mac,essid,ap.channel,ap.signal) ) 
				else:
					essid='"'+ap.essid+'"'
					print("\t{:<3}\t{:<20}\t{:<40}\t{:<3}\t{:<4}".format(APFind.ii,ap.mac,essid,ap.channel,ap.signal) ) 
		APFind.don+=1
		if APFind.don==7:
			WIFIChannel.autoChannel()
			APFind.don=0
	@staticmethod
	def showAPList():
		uzunluk=len(APFind.ap_list)
		if (uzunluk > 0):
			print("\033[1;33;38m\n\n\t{:<3}\t{:<20}\t{:<40}\t{:<3}\t{:<4}".format("No","BSSID","ESSID","Ch","Signal") )
			print("\t"+"-"*3+"\t"+"-"*20+"\t"+"-"*40+"\t"+"-"*3+"\t"+"-"*7+"\033[0;37;38m")
			for tmp in APFind.ap_list:
				APFind.ii+=1
				info=MACVendor(tmp.mac)
				if info[0]:
					info[1]='"'+info[1]+'"'
				if (tmp.hidden_essid):	
					essid='"Gizli <'+str(tmp.length_essid)+' karakter>"'
					print("\t{:<3}\t{:<20}\t\033[1;31;38m{:<40}\033[0;37;38m\t{:<3}\t{:<4}".format(APFind.ii,tmp.mac,essid,tmp.channel,tmp.signal) ) 
					if info[0]:
						print('\t\tVendor=\033[0;36;38m{}\033[0;37;38m'.format(info[1]) )
				else:
					essid='"'+tmp.essid+'"'
					print("\t{:<3}\t{:<20}\t{:<40}\t{:<3}\t{:<4}".format(APFind.ii,tmp.mac,essid,tmp.channel,tmp.signal) )
					if info[0]:
						print('\t\tVendor=\033[0;36;38m{}\033[0;37;38m'.format(info[1]) )
			print("\033[1;33;38m\t"+"-"*95+"\033[0;37;38m")	
		else:
			print("\n\033[1;37;41m\tAcces Point bulunamadı. (Hata olmuş olabilir.)\033[0;37;39m")
		print("\n\n")	
		APFind.ii=0
		APFind.don=0
