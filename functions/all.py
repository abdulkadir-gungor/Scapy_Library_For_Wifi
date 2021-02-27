#!/usr/bin/python3
############################################################################
# 									 #
#	IEEE 802.11 Wifi Library 					 #
#	Developper:	Abdulkadir GÜNGÖR (abdulkadirgungor@outlook.com)	 #
#	Date:	07/2020							 #
#	All Rights Reserved (Tüm Hakları Saklıdır)			 #
#                  							 #
############################################################################
from library.accesspoint import APFind
from library.probelistener import ProbeListener
from library.wifi import WIFIDevice
from library.packetlistener import PacketListener
from library.connectedlistener import ConnectedListener
from library.findessid import findESSID
from libraryImproved.iConnectedlistener import IConnectedListener
from libraryImproved.iFindessid import IfindESSID
import os,time
# ! - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - ! #
# from library.wifi import WIFIDevice
# ***************************************************************************
# WIFIDevice ==> Wifi Cihazları İçin Sınıf
# WIFIDevice.findWlanDevice() ==> Wifi Cihazlarını bulur.
# (Başlangıçata bu fonksiyon çalıştırılmazsa aşağıdaki fonksiyonlar işlevsiz kalır)
# WIFIDevice.showWlanDevice() ==> Seçilmiş Wifi Cihazını gösterir
# WIFIDevice.showAllWlanDevice() ==> Wifi cihazlarını gösterir.
# WIFIDevice.selectWlanDevice(number) ==> Wifi cihazını seçmek için kullanılır
# ***************************************************************************
# ! - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - ! #
# from library.wifi import WIFIMode
# ***************************************************************************
# WIFIMode ==> Wifi için Manage/Monitor Mode ayarlar. (Sınıf)
# WIFIMode.isManageMode() ==> Manage mode'a mı? True or False
# WIFIMode.isMonitorMode() ==> Monitor mode'a mı? True or False
# WIFIMode.manageMode() ==> Wifi yi Monitor mode'a ayarlar. 
# WIFIMode.monitorMode() ==> Wifi yi Manage mode'a ayarlar.
# ***************************************************************************
# ! - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - ! #
# from library.wifi import WIFIChannel
# ***************************************************************************
# WIFIChannel ==> Wifi Channel Ayarlar. (Sınıf)
# WIFIChannel.setChannel(channel) ==> Kanal ayarlar.
# WIFIChannel.autoChannel() ==> Otomatik kanal ayarlar (Kanalı +1 artırır.)
# 13 kanal kullanılır. 14 kanalı desteklemez. [Türkiye'ye özel] 
# WIFIChannel.showChannel() ==> Kanalı gösterir.
# ***************************************************************************
# ! - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - ! #
# from library.macvendor import MACVendor 
# ***************************************************************************
# MACVendor("FF:FF:FF:FF:FF:FF") ==> MAC Adreslerini veritabanında arar. 
# Bulduğu üretici firmayı döner. [False,''] [True, 'Blaa blaa firma']
# ***************************************************************************



# **********************************************
# Kablosuz ağları bulur.
# wifiNetwork() ==> kablosuz ağları kaydetmeden bulur.  
# wifiNetwork(1) ==> kablosuz ağları "AccessPointLog.pcap" olarak kaydeder.
# **********************************************
def wifiNetwork(kayit=0):
	os.system("clear")
	time.sleep(0.005)
	WIFIDevice.findWlanDevice() 
	APFind.showAP(kayit)
	result = APFind.ap_list
	APFind.reset()
	return result
# ***********************************************
# kablosuz ağları bulur. Ayrıca üretici firmaları veritabanından alır.
# Tarama bittikten sonra üretici firmaları ile birlikte gösterir.
# wifiNetworkVendor() ==> kablosuz ağları kaydetmeden bulur.  
# wifiNetworkVendor(1) ==> kablosuz ağları "AccessPointLog.pcap" olarak kaydeder.
# ************************************************
def wifiNetworkVendor(kayit=0):
	os.system("clear")
	time.sleep(0.005)
	WIFIDevice.findWlanDevice() 
	APFind.showAP(kayit)
	result = APFind.ap_list
	os.system("clear")
	time.sleep(0.005)
	APFind.showAPList()
	APFind.reset()
	return result
# ***********************************************
# Probe paketlerini gösterir. 
# Bağlantı talepleri görülür. Bu sayede 
# hem bağlantılar hem de essid adları görülebilir. 
# allProbe(channel) ==> ilgili kanaldaki tüm probe paketlerini dinler 
# ************************************************
def allProbe(channel):
	os.system("clear")
	time.sleep(0.005)
	WIFIDevice.findWlanDevice()
	ProbeListener.showAllProbe(channel)
# ***********************************************
# Probe paketlerini gösterir. 
# Bağlantı talepleri görülür. Bu sayede 
# hem bağlantılar hem de essid adları görülebilir. 
# allProbe(channel) ==> ilgili kanaldaki 
# ilgili mac adresindeki probe paketlerini dinler 
# ************************************************
def macProbe(mac,channel):
	os.system("clear")
	time.sleep(0.005)
	WIFIDevice.findWlanDevice()
	ProbeListener.showProbe(mac, channel)
# ***********************************************
# MAC adresine ait tüm paketlerin adreslerini  gösterir.
# İlgili MAC adresinde bağlantı olup olmadığı, gizli essid
# adının öğrenip öğrenilemeyeceği ya da DeAuthentication saldırıları
# takip edilebilir.
# allpackets(mac,channel) ==> ilgili kanaldaki 
# ilgili mac adresindeki tüm paketlerini dinler 
# ************************************************
def allPackets(mac,channel):
	os.system("clear")
	time.sleep(0.005)
	WIFIDevice.findWlanDevice() 
	PacketListener.showAll(mac,channel)
# ***********************************************
# MAC adresine ait tüm paketlerin adreslerini  gösterir.
# İlgili MAC adresinde bağlantı olup olmadığı, gizli essid
# adının öğrenip öğrenilemeyeceği ya da DeAuthentication saldırıları
# takip edilebilir.
# allpackets(mac,channel) ==> ilgili kanaldaki 
# ilgili mac adresindeki gerçek MAC adreslerini tespit eder.
# Sadece ilgili mac adresini ve  gerçek adresleri içeren paketleri gösterir.
# Multicast, broadcast vb gibi adresleri filtreler.
# ************************************************
def allRealPackets(mac,channel):
	os.system("clear")
	time.sleep(0.005)
	WIFIDevice.findWlanDevice() 
	PacketListener.showAllReal(mac,channel)
# ***********************************************
# Kablosuz ağa bağlı cihazları bulur.
# connectDevices(mac,channel) ==> ilgili mac'e (acces point'e)
# bağlı cihazları bulur
# ***********************************************
def connectDevices(mac,channel):
	os.system("clear")
	time.sleep(0.005)
	WIFIDevice.findWlanDevice() 
	ConnectedListener.showConnectedMACs(mac,channel)
	result = ConnectedListener.valReturn()
	ConnectedListener.reset()
	return result
# ***********************************************
# İlgili channel daki tüm paketleri dinler. ESSID bulmaya çalışır.
# Probe Request (broadcast) paketleri tüm kanallardan yayın yapar. Bunlar ESSID ile 
# Probe Response paketleri (ilgili kanaldaki) paketleri yakalar.
# findChannelESSID(channel, debug=0) ==> İlgili kanaldaki ESSID leri yakalar.
# Aynı ESSID içeren paketleri tekrar göstermez.
# ***********************************************
def findChannelESSID(channel, debug=0):
	os.system("clear")
	time.sleep(0.005)
	WIFIDevice.findWlanDevice() 
	findESSID.allESSID(channel,debug)
	result=findESSID.returnAllEssid()
	findESSID.reset()
	return result
# ***********************************************
# İlgili kanalda ilgili mac adresi içeren tüm essid leri dinler. ESSID bulmaya çalışır.
# İlgili kanalda Probe (Request ve Response) paketleri analiz eder. MAC adresini içeren
# paketlereki ESSID leri gösterir. Hedef odaklı ESSID adlarını bulur.
# findMacESSID(mac, channel, debug=0) ==> İlgili kanaldaki mac adresi içeren ESSID leri yakalar.
# Aynı ESSID içeren paketleri tekrar göstermez.
# ***********************************************
def findMacESSID(mac, channel, debug=0):
	os.system("clear")
	time.sleep(0.005)
	WIFIDevice.findWlanDevice()
	findESSID.macESSID(mac,channel,debug)
	result=findESSID.returnMACEssid()
	findESSID.reset()
	return result
# ***********************************************
# (1) AP (Access Point) yayını alır. ESSID uzunluğuna bakar. İlgili kanalda 
# ilgili mac adresi içeren ve ESSID uzunluğuna uygun essid adlarını gösterir.
# Eğer Acces Pointi bulamazsa sonuç vermez. 
# (Bulduğu zaman yeşil yazıyla access point hakkında bilgiler yayınlar.)
# find1ESSID(mac, channel, debug=0) ==> ESSID leri bulan bir fonksiyon
# Aynı ESSID içeren paketleri tekrar göstermez.
# ***********************************************
def find1ESSID(mac, channel, debug=0):
	os.system("clear")
	time.sleep(0.005)
	WIFIDevice.findWlanDevice()
	findESSID.findESSID(mac,channel,debug)
	result=findESSID.returnResultEssid() 
	findESSID.reset()
	return result
# ***********************************************
# (2) [mantık aynı-fonksiyonda ufak fark var] AP yayını alır.
# ESSID uzunluğuna bakar. İlgili kanalda ilgili mac adresi içeren 
# ve ESSID uzunluğuna uygun essid adlarını gösterir. Daha kesin sonuç verir.
# Eğer Acces Pointi bulamazsa sonuç vermez. 
# (Bulduğu zaman yeşil yazıyla access point hakkında bilgiler yayınlar.)
# find1ESSID(mac, channel, debug=0) ==> ESSID leri bulan bir fonksiyon
# Aynı ESSID içeren paketleri tekrar göstermez.
# ***********************************************
def find2ESSID(mac, channel, debug=0):
	os.system("clear")
	time.sleep(0.005)
	WIFIDevice.findWlanDevice()
	findESSID.findESSID2(mac,channel,debug)
	result=findESSID.returnResultEssid() 
	findESSID.reset()
	return result
# ***********************************************
# Kablosuz ağa bağlı cihazları otomatik bulur. Kanalları kendisi tarar.
# iConnectDevices(mac, updaTime) ==> ilgili mac'e (acces point'e)
# bağlı cihazları bulur. updateTime ile access pointte ait paket yakalayamazsa
# ne kadar süre sonra tekrar kanal taramaya başlayacağını ayarlanabilir. Default olarak
# 5 sn idealdir. Gizli ve sinyali uzak olan acces pointlerde bu süre artırılabilir. Bu tür
# access pointler için 10 sn yapılabilir.
# Eğer Acces Pointi bulamazsa sonuç vermez. 
# iConnectDevices(mac, updateTime=5) ==> Bağlı cihazları bulan fonksiyon
# ***********************************************
def iConnectDevices(mac, updateTime=5):
	os.system("clear")
	time.sleep(0.005)
	WIFIDevice.findWlanDevice() 
	IConnectedListener.showConnectedMACs(mac, updateTime)
	result = IConnectedListener.valReturn()
	IConnectedListener.reset()
	return result
# ***********************************************
# Otomatik essid leri bulur. Sadece ilgili mac adresini dinleyerek essid yi bulmaya çalışır.
# Kesin sonuç verir. "iFind2ESSID" fonksiyonu ile yaklaşık yöntemde kullanılabilir.
# iFind1ESSID(mac, updateTime=5, debug=0) ==> Otomatik essid yi bulmaya çalışır.  
# updateTime ile access pointte ait paket yakalayamazsa
# ne kadar süre sonra tekrar kanal taramaya başlayacağını ayarlanabilir. Default olarak
# 5 sn idealdir. Gizli ve sinyali uzak olan acces pointlerde bu süre artırılabilir. Bu tür
# access pointler için 10 sn yapılabilir.
# debug=0 farklı değerler için mac adresleri gösterilir.
# Eğer Acces Pointi bulamazsa sonuç vermez. 
# Aynı ESSID içeren paketleri tekrar göstermez.
# ***********************************************
def iFind1ESSID(mac, updateTime=5, debug=0):
	os.system("clear")
	time.sleep(0.005)
	WIFIDevice.findWlanDevice()
	IfindESSID.findESSID(mac, updateTime, debug)
	result = IfindESSID.valReturn()
	IfindESSID.reset()
	return result
# ***********************************************
# Otomatik essid leri bulur. 
# [Access Point] AP ile ilgili kanaldaki Tüm mac adreslerinin paketlerini dinleyerek essid yi bulmaya çalışır.
# Gizli AP ile essid uzunluğu hesaplar.Sonra ilgili kanaldaki tüm essid uzunlukları ile karşılaştırır.
# Yaklaşıktır. Kesin sonuç vermez. Kesin sonuç için "iFind1ESSID" kullanılmalıdır. 
# iFind2ESSID(mac, updateTime=5, debug=0) ==> Otomatik essid yi bulmaya çalışır.  
# updateTime ile access pointte ait paket yakalayamazsa
# ne kadar süre sonra tekrar kanal taramaya başlayacağını ayarlanabilir. Default olarak
# 5 sn idealdir. Gizli ve sinyali uzak olan acces pointlerde bu süre artırılabilir. Bu tür
# access pointler için 10 sn yapılabilir.
# debug=0 farklı değerler için mac adresleri gösterilir.
# Eğer Acces Pointi bulamazsa sonuç vermez. 
# Aynı ESSID içeren paketleri tekrar göstermez.
# ***********************************************
def iFind2ESSID(mac, updateTime=5, debug=0):
	os.system("clear")
	time.sleep(0.005)
	WIFIDevice.findWlanDevice()
	IfindESSID.find1ESSID(mac, updateTime, debug)
	result = IfindESSID.val1Return()
	IfindESSID.reset()
	return result


