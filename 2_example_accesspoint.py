#!/usr/bin/python3
############################################################################
# 									 #
#	IEEE 802.11 Wifi Library 					 #
#	Developper:	Abdulkadir GÜNGÖR (abdulkadirgungor@outlook.com)	 #
#	Date:	07/2020							 #
#	All Rights Reserved (Tüm Hakları Saklıdır)			 #
#                  							 #
############################################################################
from libraryWrite.ap import cloneAP, newAP, newFuncAP

print("\n")
input("Devam? ENTER!:")
# Daha önce kaydedilmiş essid lerden yeni bir essid üretir. Tüm özellikleri aynı  olabileceği gibi
# access point mac, access point essid, acces point channel özellikleri de değiştirilebilir.
# filename ==> beacon paketleri kaydedilmiş pcap dosyası. Access Point bu beacon paketlerinden üretilir. 
# info ==> Gönderilecek paket gönderilmeden önce detaylı olarak komut satırından gösterilsin mi?
# info=0 gösterilmesin, info=1 okunur şekilde gösterilsin, info=2 hem okunur hemde heximal olarak gösterilsin
# inter ==> beacon gönderilme aralığı (default olarak 0.1 sn bir tekrar gönderilsin.)
# loop ==> paketler tekrar tekrar gönderilsin mi? 
# loop=0 bir paket gönderir. loop=1 , loop=2 vs. sonsuz sayıda paket gönderir. 
# Paketleri Ctrl+C ile çıkıcaya kadar gönderir.
# cloneAP(filename="AccessPointLog.pcap", info=0 ,inter=0.1, loop=1)
cloneAP()


print("\n")
input("Devam? ENTER!:")
# interaktif sorular  (Access Point MAC, ESSID, Channel) ile Access Point kurar  
# cipher ==> wpa şifre kullanılsın mı1? True or False
# info ==> Gönderilecek paket gönderilmeden önce detaylı olarak komut satırından gösterilsin mi?
# info=0 gösterilmesin, info=1 okunur şekilde gösterilsin, info=2 hem okunur hemde heximal olarak gösterilsin
# inter ==> beacon gönderilme aralığı (default olarak 0.1 sn bir tekrar gönderilsin.)
# loop ==> paketler tekrar tekrar gönderilsin mi? 
# loop=0 bir paket gönderir. loop=1 , loop=2 vs. sonsuz sayıda paket gönderir. 
# Paketleri Ctrl+C ile çıkıcaya kadar gönderir.
# newAP( cipher=True,info=0 ,inter=0.1, loop=1)
newAP(cipher=False)


print("\n")
input("Devam? ENTER!:")
# Herhangi bir interaktif bir soru sormadan doğrudan Access Point kurulabilir.
# ap_mac ==> "Access Point"e ait mac adresi "ff:ff:ff:ff:ff:ff"
# ap_essid ==> Access Point"e ait essid (Wifi ağının adı) -> Türkçe karakter kullanmayınız.
# cipher ==> wpa şifre kullanılsın mı1? True or False
# info ==> Gönderilecek paket gönderilmeden önce detaylı olarak komut satırından gösterilsin mi?
# info=0 gösterilmesin, info=1 okunur şekilde gösterilsin, info=2 hem okunur hemde heximal olarak gösterilsin
# inter ==> beacon gönderilme aralığı (default olarak 0.1 sn bir tekrar gönderilsin.)
# loop ==> paketler tekrar tekrar gönderilsin mi? 
# loop=0 bir paket gönderir. loop=1 , loop=2 vs. sonsuz sayıda paket gönderir. 
# Paketleri Ctrl+C ile çıkıcaya kadar gönderir.
# newFuncAP( app_mac, ap_essid, select_channel="13",cipher=True,info=0 ,inter=0.1, loop=1)
newFuncAP( "ff:ff:ff:ff:ff:ff", "Yerim seni sosis")


