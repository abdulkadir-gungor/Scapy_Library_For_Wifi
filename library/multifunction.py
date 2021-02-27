#!/usr/bin/python3
############################################################################
# 									 #
#	IEEE 802.11 Wifi Library 					 #
#	Developper:	Abdulkadir GÜNGÖR (abdulkadir_gungor@outlook.com)	 #
#	Date:	07/2020							 #
#	All Rights Reserved (Tüm Hakları Saklıdır)			 #
#                  							 #
############################################################################
# **************************************************************************
#  subtypeKontrol(subtype) ==> Frame türünü döner. (String)
# **************************************************************************
def subtypeKontrol(subtype):
	if subtype==0:
		return "Association Request Frame"
	elif subtype==1:
		return "Association Response Frame"
	elif subtype==2:
		return "ReAssociation Request Frame"
	elif subtype==3:
		return "ReAssociation Response Frame"
	elif subtype==4:
		return "Probe Request Frame"
	elif subtype==5:
		return "Probe Response Frame"
	elif subtype==6:
		return "Measuremnet Pilot Frame"
	elif subtype==7:
		return "Reserved Frame"
	elif subtype==8:
		return "Beacon Frame"
	elif subtype==9:
		return "ATIM Frame"
	elif subtype==10:
		return "DissAssociation Frame"
	elif subtype==11:
		return "Authentication Frame"
	elif subtype==12:
		return "DeAuthentication Frame"
	elif subtype==13:
		return "Action Frame"
	elif subtype==14:
		return "Action No ACK Frame"
	elif subtype==15:
		return "Reserved Frame"
	else:
		return ""
# **************************************************************************
# eth_multi_mac(MAC) ==> Ethernet Multicast Kontrol
# **************************************************************************
def eth_multi_mac(MAC):
	if MAC=='01:00:0C:CC:CC:CC':
		return [True,"Cisco Discovery Protocol (CDP), VLAN Trunking Protocol (VTP), Unidirectional_Link_Detection (UDLD)",""]
	elif MAC=='01:00:0C:CC:CC:CD':
		return [True,"Cisco Shared Spanning Tree Protocol Address",""]
	elif MAC=='01:80:C2:00:00:00':
		return [True,"Spanning Tree Protocol (for bridges) IEEE 802.1D","0x88CC"]
	elif MAC=='01:80:C2:00:00:00' or MAC=='01:80:C2:00:00:03' or MAC=='01:80:C2:00:00:0E':
		return [True,"Link Layer Discovery Protocol","0x88CC"]
	elif MAC=='01:80:C2:00:00:08':
		return [True,"Spanning Tree Protocol (for provider bridges) IEEE 802.1ad","0x0802"]
	elif MAC=='01:80:C2:00:00:01':
		return [True,"Ethernet flow control (pause frame) IEEE 802.3x","0x8808"]
	elif MAC=='01:80:C2:00:00:02':
		return [True,"<Slow Protocols> including Ethernet OAM Protocol (IEEE 802.3ah) and Link Aggregation Control Protocol (LACP)","0x8809"]
	elif MAC=='01:80:C2:00:00:21':
		return [True,"Ethernet CFM Protocol IEEE 802.1ag","0x88F5"]
	elif MAC[:16]=='01:80:C2:00:00:3':
		return [True,"GARP VLAN Registration Protocol (also known as IEEE 802.1q GVRP)","0x8902"]
	elif MAC[:8]=='01:00:5E':
		return [True,"IPv4 Multicast","0x0800"]	
	elif MAC[:5]=='33:33':
		return [True,"IPv6 Multicast","0x86DD"]
	elif MAC[:14]=='01:0C:CD:01:00' or MAC[:14]=='01:0C:CD:01:01':
		return [True,"IEC 61850-8-1 GOOSE Type 1/1A","0x88B8"]
	elif MAC[:14]=='01:0C:CD:02:00' or MAC[:14]=='01:0C:CD:02:01':
		return [True,"GSSE (IEC 61850 8-1)","0x88B9"]
	elif MAC[:14]=='01:0C:CD:04:00' or MAC[:14]=='01:0C:CD:04:01':
		return [True,"Multicast sampled values (IEC 61850 8-1)","0x88BA"]
	elif MAC[:16]=='01:1B:19:00:00:0':
		return [True,"Precision Time Protocol (PTP) version 2 over Ethernet (native layer-2)","0x88F7"]
	elif MAC=='00:00:00:00:00:00' or MAC=='FF:FF:FF:FF:FF:FF':
		return [True,"ARP for a boadcast",""]
	return [False,"",""]
	# return [sonuc,usage,ether_type_code]
	
