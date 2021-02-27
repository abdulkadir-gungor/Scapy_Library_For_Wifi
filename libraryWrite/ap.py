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
import time

def cloneAP(filename="AccessPointLog.pcap", info=0 ,inter=0.1, loop=1):
	try:	
		pkts=rdpcap(filename)
	except:
		print('\n\033[1;37;41m\t"{}" adlı dosya bulunamadı.\033[0;37;39m\t'.format(filename))
		pkts=[]
	number=1
	print("\n\n")
	if len(pkts)>0:
		print("\t\033[1;33;38m{:<2}\t{:<17}\t{:<35}\t{:<2}\033[0;37;38m".format("No","MAC","ESSID","CH"))
		print("\t\033[1;33;38m{:<2}\t{:<17}\t{:<35}\t{:<2}\033[0;37;38m".format("-"*2,"-"*17,"-"*35,"-"*2))
		for pkt in pkts:
			mac=(pkt.addr2).upper()
			essid=(pkt.info).decode('ISO-8859-9') 
			channel=int(str(ord( pkt[Dot11Elt:3].info )))
			#essid=(pkt.info).decode('ISO-8859-9') ==> Turkish 
			#essid=(pkt.info).decode('ISO-8859-15') ==> latin
			str_essid=str(pkt.info)
			if "\\x00" in str_essid:
				essid="Gizli <{} karakter>".format(str_essid.count("x00"))			
			print("\t{:<2})\t{:<17}\t{:<35}\t{:<2}".format(number,mac,essid,channel))
			number+=1
		number=-1
		print("\n\n")
		number=input("\tSeçim :")
	
		if number.isdigit():
			secim=int(number)-1
			if secim>=0 and secim<len(pkts):
				pkt=pkts[secim]
				mac=(pkt.addr2).upper()
				essid=(pkt.info).decode('ISO-8859-9') 
				channel=int(str(ord( pkt[Dot11Elt:3].info )))
				str_essid=str(pkt.info)
				if "\\x00" in str_essid:
					hidden_essid=True
				else:
					hidden_essid=False
				print("\n")
				ap_mac=input("\tAccess Point MAC\t<Default={}> (Enter) =>".format(mac))
				if ap_mac != '':
					ap_mac = ap_mac.lower()
					pkt.addr2=ap_mac
				if not hidden_essid:
					ap_essid=input("\tAccess Point ESSID\t<Default={}> (Enter) =>".format(essid))
					if ap_essid != '':
						pkt.info=ap_essid
						pkt[Dot11Elt].len=len(ap_essid)
				select_channel=input("\tAccess Point Channel\t<Default={}> (Enter) =>".format(channel))
				
				if select_channel != "" and select_channel.isdigit():
					check_channel=int(select_channel)
				else:
					check_channel=13
				if check_channel>0 and check_channel<14:
					ap_channel = check_channel
				else:
					ap_channel = 13
				print("\n")
				if info==1:
					pkt.show()
					print("\n")
				elif info==2:
					pkt.show()
					print("\n")
					hexdump(pkt)
					print("\n")
				WIFIDevice.findWlanDevice()
				time.sleep(0.1)	
				device=WIFIDevice.showWlanDevice()
				if device[0]:
					hata=0
					print("\tAccess point hazırlanıyor. <<<...Lütfen bekleyiniz...>>> ")
					try:
						WIFIMode.monitorMode()
						time.sleep(0.25)
						WIFIChannel.setChannel(ap_channel)
						time.sleep(0.05)
					except:
						print("\n\033[1;37;41m\t Hata Oluştu. Monitor mode'a geçilemedi.\033[0;37;39m\t")
						hata=1
					if hata==0:
						print("\033[1;32;38m\tAccess point yayında!!!\n")
						sendp(pkt, iface=device[1],inter=inter,loop=loop)
						print("\n\033[1;31;38m\tAccess point sonlandı.\033[0;37;38m")
					try:
						time.sleep(0.25)
						WIFIMode.manageMode()
					except:
						print("\n\033[1;37;41m\t Hata Oluştu. Manage mode'a geçilemedi.\033[0;37;39m\t")
					print("\n\n")
				else:
					print("\n\033[1;37;41m\tWifi cihazı bulunamadı.\033[0;37;39m\n\n")
def newAP( cipher=True,info=0 ,inter=0.1, loop=1):	
	print("\n")
	ap_mac=input("\tAccess Point MAC\t (format=>ff:ff:ff:ff:ff:ff) =")
	ap_essid=input("\tAccess Point ESSID\t=")
	select_channel=input("\tAccess Point Channel\t<Default={}> (Enter) =>".format(13))
	if ap_mac != '' and ap_essid !='' :
		ap_mac = ap_mac.lower()	
		# Channel setting
		if select_channel=='':
			select_channel="13"			
		if select_channel.isdigit():
			check_channel=int(select_channel)
		else:
			check_channel=13
		if check_channel>0 and check_channel<14:
			ap_channel = check_channel
		else:
			ap_channel = 13
		# channel setting (end)
		#   --- --- --- pkt tanımı --- --- ---			
		# dot11
		dot11 = Dot11FCS(type=0, subtype=8, addr1='ff:ff:ff:ff:ff:ff',
		addr2=ap_mac, addr3='ff:ff:ff:ff:ff:ff')
		# Dot11Elt
		essid = Dot11Elt(ID='SSID',info=ap_essid, len=len(ap_essid))
		if cipher:
			# beacon
			beacon = Dot11Beacon(cap='ESS+privacy')
			# rsn
			rsn = Dot11Elt(ID='RSNinfo', info=(
			'\x01\x00'                 #RSN Version 1
			'\x00\x0f\xac\x02'         #Group Cipher Suite : 00-0f-ac TKIP
			'\x02\x00'                 #2 Pairwise Cipher Suites (next two lines)
			'\x00\x0f\xac\x04'         #AES Cipher
			'\x00\x0f\xac\x02'         #TKIP Cipher
			'\x01\x00'                 #1 Authentication Key Managment Suite (line below)
			'\x00\x0f\xac\x02'         #Pre-Shared Key
			'\x00\x00'))               #RSN Capabilities (no extra capabilities)
			pkt = RadioTap()/dot11/beacon/essid/rsn	
		else:
			beacon = Dot11Beacon(cap='')	
			pkt = RadioTap()/dot11/beacon/essid	
		#   --- --- --- pkt tanım sonu --- --- ---
		print("\n")
		if info==1:
			pkt.show()
			print("\n")
		elif info==2:
			pkt.show()
			print("\n")
			hexdump(pkt)
			print("\n")	
		WIFIDevice.findWlanDevice()
		time.sleep(0.1)	
		device=WIFIDevice.showWlanDevice()
		if device[0]:
			hata=0
			print("\tAccess point hazırlanıyor. <<<...Lütfen bekleyiniz...>>> ")
			try:
				WIFIMode.monitorMode()
				time.sleep(0.25)
				WIFIChannel.setChannel(ap_channel)
				time.sleep(0.05)
			except:
				print("\n\033[1;37;41m\t Hata Oluştu. Monitor mode'a geçilemedi.\033[0;37;39m\t")
				hata=1
			if hata==0:
				print("\033[1;32;38m\tAccess point yayında!!!\n")
				sendp(pkt, iface=device[1],inter=inter,loop=loop)
				print("\n\033[1;31;38m\tAccess point sonlandı.\033[0;37;38m\n")
			try:
				time.sleep(0.25)
				WIFIMode.manageMode()
			except:
				print("\n\033[1;37;41m\t Hata Oluştu. Manage mode'a geçilemedi.\033[0;37;39m\t")
				print("\n\n")
		else:
			print("\n\033[1;37;41m\tWifi cihazı bulunamadı.\033[0;37;39m\n\n")

def newFuncAP( ap_mac, ap_essid, select_channel="13",cipher=True,info=0 ,inter=0.1, loop=1):	
	print("")
	if ap_mac != '' and ap_essid !='' :
		ap_mac = ap_mac.lower()	
		# Channel setting
		if select_channel=='':
			select_channel="13"			
		if select_channel.isdigit():
			check_channel=int(select_channel)
		else:
			check_channel=13
		if check_channel>0 and check_channel<14:
			ap_channel = check_channel
		else:
			ap_channel = 13
		# channel setting (end)
		#   --- --- --- pkt tanımı --- --- ---			
		# dot11
		dot11 = Dot11FCS(type=0, subtype=8, addr1='ff:ff:ff:ff:ff:ff',
		addr2=ap_mac, addr3='ff:ff:ff:ff:ff:ff')
		# Dot11Elt
		essid = Dot11Elt(ID='SSID',info=ap_essid, len=len(ap_essid))
		if cipher:
			# beacon
			beacon = Dot11Beacon(cap='ESS+privacy')
			# rsn
			rsn = Dot11Elt(ID='RSNinfo', info=(
			'\x01\x00'                 #RSN Version 1
			'\x00\x0f\xac\x02'         #Group Cipher Suite : 00-0f-ac TKIP
			'\x02\x00'                 #2 Pairwise Cipher Suites (next two lines)
			'\x00\x0f\xac\x04'         #AES Cipher
			'\x00\x0f\xac\x02'         #TKIP Cipher
			'\x01\x00'                 #1 Authentication Key Managment Suite (line below)
			'\x00\x0f\xac\x02'         #Pre-Shared Key
			'\x00\x00'))               #RSN Capabilities (no extra capabilities)
			pkt = RadioTap()/dot11/beacon/essid/rsn	
		else:
			beacon = Dot11Beacon(cap='')	
			pkt = RadioTap()/dot11/beacon/essid	
		#   --- --- --- pkt tanım sonu --- --- ---
		print("")
		if info==1:
			pkt.show()
			print("\n")
		elif info==2:
			pkt.show()
			print("\n")
			hexdump(pkt)
			print("\n")	
		WIFIDevice.findWlanDevice()
		time.sleep(0.1)	
		device=WIFIDevice.showWlanDevice()
		if device[0]:
			hata=0
			print('\tMAC={:<17}\tESSID:"{}"'.format(ap_mac.upper(),ap_essid))
			print("\n\tAccess point hazırlanıyor. <<<...Lütfen bekleyiniz...>>> ")
			try:
				WIFIMode.monitorMode()
				time.sleep(0.25)
				WIFIChannel.setChannel(ap_channel)
				time.sleep(0.05)
			except:
				print("\n\033[1;37;41m\t Hata Oluştu. Monitor mode'a geçilemedi.\033[0;37;39m\t")
				hata=1
			if hata==0:
				print("\033[1;32;38m\tAccess point yayında!!!\n")
				sendp(pkt, iface=device[1],inter=inter,loop=loop)
				print("\n\033[1;31;38m\tAccess point sonlandı.\033[0;37;38m\n")
			try:
				time.sleep(0.25)
				WIFIMode.manageMode()
			except:
				print("\n\033[1;37;41m\t Hata Oluştu. Manage mode'a geçilemedi.\033[0;37;39m\t")
				print("\n\n")
		else:
			print("\n\033[1;37;41m\tWifi cihazı bulunamadı.\033[0;37;39m\n\n")


