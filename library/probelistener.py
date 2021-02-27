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
# ***********************************************************************
# ProbeListener ==> Probe İsteklerini Dinlemek amacıyla yapılmış
# bir sınıf
# ProbeListener.showAllProbe(channel) ==> Fonksiyon verilen
# kanalı takip ederek tüm probe paketlerini dinler
# ProbeListener.showProbe(mac,channel) ==> verilen mac adresini ve
# verilen kanalda alıp gönderdiği probe paketlerini dinler
# ProbeListener.__addProbe() ==> sniff için paket işleme fonksiyonu
# ProbeListener.__addProbe2() ==> sniff için paket işleme fonksiyonu
# ***********************************************************************
class ProbeListener:
	__channel=0
	__followMAC=""
	@classmethod
	def showAllProbe(cls,channel):
		device=WIFIDevice.showWlanDevice()
		if (device[0]):
			try:
				WIFIMode.monitorMode()
				WIFIChannel.setChannel(channel)
			except:
				print("\n\033[1;37;41m\t Hata Oluştu.\033[0;37;39m\t")
			cls.__channel=channel
			print("\n\n\t\t\t\033[1;37;38m<Channel={}> Tüm Probe Paketleri Dinlemeye Alındı.\033[0;37;38m".format(channel))
			print("\t\033[1;37;38m"+"-"*140+"\033[0;37;38m")
			sniff(iface=device[1], count=0, prn=cls.__addProbe)
			print("\t\033[1;37;38m"+"-"*140+"\033[0;37;38m\n")
			try:
				WIFIMode.manageMode()
			except:
				print("\n\033[1;37;41m\t Hata Oluştu.\033[0;37;39m\t")
		else:
			print("\n\033[1;37;41m\tWIFI cihazı bulunamadı.\033[0;37;39m\n")	
		cls.__channel=0	
	@classmethod
	def showProbe(cls,mac,channel):
		device=WIFIDevice.showWlanDevice()
		if (device[0]):
			try:
				WIFIMode.monitorMode()
				WIFIChannel.setChannel(channel)
			except:
				print("\n\033[1;37;41m\t Hata Oluştu.\033[0;37;39m\t")
			cls.__channel=channel
			cls.__followMAC=mac
			print("\n\n\t\t\t\033[1;37;38m<Channel={} MAC={}> İlgili Cihaz İçin Tüm Probe Paketleri Dinlemeye Alındı.\033[0;37;38m".format(channel,mac))
			print("\t\033[1;37;38m"+"-"*140+"\033[0;37;38m")
			sniff(iface=device[1], count=0, prn=cls.__addProbe2)
			print("\t\033[1;37;38m"+"-"*140+"\033[0;37;38m\n")
			try:
				WIFIMode.manageMode()
			except:
				print("\n\033[1;37;41m\t Hata Oluştu.\033[0;37;39m\t")
		else:
			print("\n\033[1;37;41m\tWIFI cihazı bulunamadı.\033[0;37;39m\n")	
		cls.__channel=0
		cls.__followMAC=""
	@staticmethod
	def __addProbe(pkt):
		if pkt.haslayer(Dot11ProbeReq) :
			destination = (pkt.addr1).upper()
			source = (pkt.addr2).upper()	
			essid= (pkt.info).decode('ISO-8859-9')		
			#essid= (pkt.info).decode('ISO-8859-15')
			channel=ProbeListener.__channel
			if (len(essid)==0 ):
				essid="##<NULL>##"
				length=0
				empty_essid=True
			else:
				length=len(essid)
				empty_essid=False
			if (empty_essid):
				item = '\033[0;32;38m\t<Channel={} Probe_Request>\tSource={}\tDestination={}\tESSID= {}\033[0;37;38m'.format(channel,source,destination,essid)
			else:
				item = '\033[0;32;38m\t<Channel={} Probe_Request>\tSource={}\tDestination={}\tESSID="{}"\t <{} karakter>\033[0;37;38m'.format(channel,source,destination,essid,length)
			print(item)
		elif pkt.haslayer(Dot11ProbeResp):
			destination = (pkt.addr1).upper()
			source = (pkt.addr2).upper()
			essid= (pkt.info).decode('ISO-8859-9')				
			#essid= (pkt.info).decode('ISO-8859-15')
			channel=ProbeListener.__channel
			if (len(essid)==0 ):
				essid="##<NULL>##"
				length=0
				empty_essid=True
			else:
				length=len(essid)
				empty_essid=False
			if (empty_essid):
				item = '\033[0;33;38m\t<Channel={} Probe_Response> \tSource={}\tDestination={}\tESSID= {}\033[0;37;38m'.format(channel,source,destination,essid)
			else:
				item = '\033[0;33;38m\t<Channel={} Probe_Response> \tSource={}\tDestination={}\tESSID="{}"\t <{} karakter>\033[0;37;38m'.format(channel,source,destination,essid,length)
			print(item)
	@staticmethod
	def __addProbe2(pkt):
		if pkt.haslayer(Dot11ProbeReq) :
			mac=ProbeListener.__followMAC
			destination = (pkt.addr1).upper()
			source = (pkt.addr2).upper()	
			if mac==source or mac==destination:
				if mac==source:
					source="\033[0;34;38m"+source+"\033[0;32;38m"
				if mac==destination:
					destination="\033[0;34;38m"+destination+"\033[0;32;38m"		
				essid= (pkt.info).decode('ISO-8859-9')	
				#essid= (pkt.info).decode('ISO-8859-15')
				channel=ProbeListener.__channel
				if (len(essid)==0 ):
					essid="##<NULL>##"
					length=0
					empty_essid=True
				else:
					length=len(essid)
					empty_essid=False
				if (empty_essid):
					item = '\033[0;32;38m\t<Channel={} Probe_Request>\tSource={}\tDestination={}\tESSID= {}\033[0;37;38m'.format(channel,source,destination,essid)
				else:
					item = '\033[0;32;38m\t<Channel={} Probe_Request>\tSource={}\tDestination={}\tESSID="{}"\t <{} karakter>\033[0;37;38m'.format(channel,source,destination,essid,length)
				print(item)
		elif pkt.haslayer(Dot11ProbeResp):
			mac=ProbeListener.__followMAC
			destination = (pkt.addr1).upper()
			source = (pkt.addr2).upper()
			if mac==source or mac==destination:
				if mac==source:
					source="\033[0;34;38m"+source+"\033[0;33;38m"
				if mac==destination:
					destination="\033[0;34;38m"+destination+"\033[0;33;38m"							
				essid= (pkt.info).decode('ISO-8859-9')	
				#essid= (pkt.info).decode('ISO-8859-15')
				channel=ProbeListener.__channel
				if (len(essid)==0 ):
					essid="##<NULL>##"
					length=0
					empty_essid=True
				else:
					length=len(essid)
					empty_essid=False
				if (empty_essid):
					item = '\033[0;33;38m\t<Channel={} Probe_Response> \tSource={}\tDestination={}\tESSID= {}\033[0;37;38m'.format(channel,source,destination,essid)
				else:
					item = '\033[0;33;38m\t<Channel={} Probe_Response> \tSource={}\tDestination={}\tESSID="{}"\t <{} karakter>\033[0;37;38m'.format(channel,source,destination,essid,length)
				print(item)
