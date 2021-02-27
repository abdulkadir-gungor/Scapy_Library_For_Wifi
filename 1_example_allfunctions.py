#!/usr/bin/python3
############################################################################
# 									 #
#	IEEE 802.11 Wifi Library 					 #
#	Developper:	Abdulkadir GÜNGÖR (abdulkadirgungor@outlook.com)	 #
#	Date:	07/2020							 #
#	All Rights Reserved (Tüm Hakları Saklıdır)			 #
#                  							 #
############################################################################
from functions.all import *


result=[]
# 5C:5A:20:A7:E6:56   	"Dene"  
# 5C:5A:20:72:E6:54   	"Gizli <7 karakter>"
mymac="5C:5A:80:72:E6:54"
channel=2
debug=0
# # #

# (1)
# wifiNetwork(kayit=0) 
# Access Pointleri bulur.
# kayit=0 farklı bir değer için "AccesPointLog.pcap" kayıt yapar. (Acces Pointlerin beacon paketlerini kaydeder.)
# Geriye AP türünden bir list döndürür.
# AP.mac (str), AP.essid (str),AP.channel (int), AP.signal (int), AP.length_essid (int), AP.hidden_essid (boolean)

result = wifiNetwork()

print("\n\n")
input("Alınan Sonuçları Göster? ENTER!:")
print("")

for tmp in result:
	print("\t{}\tGizli:{}\t{}\t{}".format(tmp.mac, tmp.hidden_essid ,tmp.essid, tmp.channel) )

print("\n")
input("Devam? ENTER!:")

result=[]


# (2)
# wifiNetworkVendor(kayit=0) 
# Access Pointleri bulur. Ve üretici firmaları veritabanından sorgular.
# kayit=0 farklı bir değer için "AccesPointLog.pcap" kayıt yapar. (Acces Pointlerin beacon paketlerini kaydeder.)
# Geriye AP türünden bir list döndürür.
# AP.mac (str), AP.essid (str),AP.channel (int), AP.signal (int), AP.length_essid (int), AP.hidden_essid (boolean)


result = wifiNetworkVendor()

print("\n\n")
input("Alınan Sonuçları Göster? ENTER!:")
print("")

for tmp in result:
	print("\t{}\tGizli:{}\t{}\t{}".format(tmp.mac, tmp.hidden_essid ,tmp.essid, tmp.channel) )

print("\n")
input("Devam? ENTER!:")

result=[]


# (3)
# allProbe(channel)
# ilgili kanaldaki tüm probe paketlerini gösterir.
# Geriye veri döndürmez

allProbe(channel)

print("\n")
input("Devam? ENTER!:")


# (4)
# macProbe(mac, channel)
# İlgili kanaldaki ilgili mac adresi içeren probe paketlerini gösterir.
# Geriye veri döndürmez 


macProbe(mymac,channel)

print("\n")
input("Devam? ENTER!:")

# (5)
# allPackets(mac, channel)
# ilgili kanaldaki ilgili mac adresi içeren tüm paketlerin ip adreslerini gösterir.
# Geriye veri döndürmez.

allPackets(mymac,channel)

print("\n")
input("Devam? ENTER!:")

# (6)
# allRealPackets(mac, channel)
# ilgili kanaldaki ilgili mac adresi içeren tüm paketlerin ip adreslerini gösterir.
# Geriye veri döndürmez.

allRealPackets(mymac,channel)

print("\n")
input("Devam? ENTER!:")

# (7)
# connectDevices(mac,channel)
# ilgili Access Point veya mac adresine bağlı cihazları bulur.
# Geriye iki tane list döndürür.
# result = [muhtemel_List, kesin_list]

result = connectDevices(mymac,channel)

print("\n\n")
input("Alınan Sonuçları Göster? ENTER!:")
print("")

print("\n\tMuhtemel\n----------------------------------------------------------")
for tmp in result[0]:
	print("\t{}".format(tmp) )
print("\n")
print("\n\tKesin\n----------------------------------------------------------")
for tmp in result[1]:
	print("\t{}".format(tmp) )
print("\n")

print("\n")
input("Devam? ENTER!:")

result=[]

# (8)
# findChannelESSID(channel, debug=0)
# İlgili kanaldan dinleme yapar. ESSID leri bulur.
# Adresleri de görmek istenirse debug=1 olmalıdır.
# Aynı essid adlarını kaydetmez. İlk bulduğunu kaydeder.
# Geriye bulunan ESSID lerin listesini döndürür.

result = findChannelESSID(channel)

print("\n\n")
input("Alınan Sonuçları Göster? ENTER!:")
print("")

print("\n\tESSID ler\n\t----------------------------------------------------------")
for tmp in result:
	print('\t"{}"'.format(tmp) )
print("\n")

print("\n")
input("Devam? ENTER!:")

result=[]

# (9)
# findMacESSID(mac, channel, debug=0)
# İlgili kanalda ilgili Acces Point yada mac adresini içeren
# paketleri dinler. Bu sayede ESSID adlarını bulur.
# Aynı essid adlarını kaydetmez. İlk bulduğunu kaydeder.
# Geriye bulunan ESSID lerin listesini döndürür.


result = findMacESSID(mymac,channel,debug)

print("\n\n")
input("Alınan Sonuçları Göster? ENTER!:")
print("")

print("\n\tESSID ler\n\t----------------------------------------------------------")
for tmp in result:
	print('\t"{}"'.format(tmp) )
print("\n")

print("\n")
input("Devam? ENTER!:")

result=[]

# (10)
# find1ESSID(mac, channel, debug=0)
# İlgili kanalda ilgili Acces Point yada mac adresini içeren
# paketleri dinler. Bu sayede ESSID adlarını bulur. 
# "find2ESSID" fonksiyonu ile mantık aynı ama
# "find2ESSID" fonksiyonuna göre bir tık algoritması daha iyi.
# Aynı essid adlarını kaydetmez. İlk bulduğunu kaydeder.
# Geriye bulunan ESSID lerin listesini döndürür.


result = find1ESSID(mymac,channel,debug)

print("\n\n")
input("Alınan Sonuçları Göster? ENTER!:")
print("")

print("\n\tESSID ler\n\t----------------------------------------------------------")
for tmp in result:
	print('\t"{}"'.format(tmp) )
print("\n")

print("\n")
input("Devam? ENTER!:")

result=[]

# (10)
# find2ESSID(mac, channel, debug=0)
# İlgili kanalda ilgili Acces Point yada mac adresini içeren
# paketleri dinler. Bu sayede ESSID adlarını bulur. 
# "find1ESSID" fonksiyonu ile mantık aynı ama
# "find1ESSID" fonksiyonuna göre bir tık algoritması daha kötü yazılmış.
# Aynı essid adlarını kaydetmez. İlk bulduğunu kaydeder.
# Geriye bulunan ESSID lerin listesini döndürür.


result = find2ESSID(mymac,channel,debug)

print("\n\n")
input("Alınan Sonuçları Göster? ENTER!:")
print("")

print("\n\tESSID ler\n\t----------------------------------------------------------")
for tmp in result:
	print('\t"{}"'.format(tmp) )
print("\n")

print("\n")
input("Devam? ENTER!:")

result=[]

# (11)
# iConnectDevices(mac, updateTime=5):
# ilgili Access Point veya mac adresine bağlı cihazları bulur.
# Kanal ayarlamasını otomatik yapar. Acces Point kanalı değiştirince algılar.
# Kanalı bulur. updateTime ile kanal arama süresi kısa yada uzun tutulabilir.
# 5 sn normal ancak gizli ve uzak access pointler için bu süre 10 sn yapılabilir.
# Geriye iki tane list döndürür.
# result = [muhtemel_List, kesin_list]

result = iConnectDevices(mymac)

print("\n\n")
input("Alınan Sonuçları Göster? ENTER!:")
print("")

print("\n\tMuhtemel\n\t----------------------------------------------------------")
for tmp in result[0]:
	print('\t"{}"'.format(tmp) )
print("\n")
print("\n\tKesin\n\t----------------------------------------------------------")
for tmp in result[1]:
	print('\t"{}"'.format(tmp) )
print("\n")

print("\n")
input("Devam? ENTER!:")

result=[]


# (11)
# iFind1ESSID(mac, updateTime=5, debug=0)
# Otomatik essid leri bulur. Sadece ilgili mac adresini dinleyerek essid yi bulmaya çalışır.
# Kesin sonuç verir. "iFind2ESSID" fonksiyonu ile yaklaşık yöntemde kullanılabilir.
# debug=0 farklı değerler için mac adresleri gösterilir.
# updateTime ile access pointte ait paket yakalayamazsa
# ne kadar süre sonra tekrar kanal taramaya başlayacağını ayarlanabilir. Default olarak
# 5 sn idealdir. Gizli ve sinyali uzak olan acces pointlerde bu süre artırılabilir. Bu tür
# access pointler için 10 sn yapılabilir.
# Geriye ESSID leri içeren listeyi döndürür.

result = iFind1ESSID(mymac,debug=debug)

print("\n\n")
input("Alınan Sonuçları Göster? ENTER!:")
print("")

print("\n\tESSID ler\n\t----------------------------------------------------------")
for tmp in result:
	print('\t"{}"'.format(tmp) )
print("\n")

print("\n")
input("Devam? ENTER!:")

result=[]

# (12)
# iFind2ESSID(mac, updateTime=5, debug=0)
# Otomatik essid leri bulur. 
# [Access Point] AP ile ilgili kanaldaki Tüm mac adreslerinin paketlerini dinleyerek essid yi bulmaya çalışır.
# Gizli AP ile essid uzunluğu hesaplar.Sonra ilgili kanaldaki tüm essid uzunlukları ile karşılaştırır.
# Yaklaşıktır. Kesin sonuç vermez.Kesin sonuç için "iFind1ESSID" kullanılmalıdır.
# debug=0 farklı değerler için mac adresleri gösterilir.
# updateTime ile access pointte ait paket yakalayamazsa
# ne kadar süre sonra tekrar kanal taramaya başlayacağını ayarlanabilir. Default olarak
# 5 sn idealdir. Gizli ve sinyali uzak olan acces pointlerde bu süre artırılabilir. Bu tür
# access pointler için 10 sn yapılabilir.
# Geriye ESSID leri içeren listeyi döndürür.

result = iFind2ESSID(mymac)

print("\n\n")
input("Alınan Sonuçları Göster? ENTER!:")
print("")

print("\n\tESSID ler\n\t----------------------------------------------------------")
for tmp in result:
	print('\t"{}"'.format(tmp) )
print("\n")

print("\n")
input("Exit? ENTER!:")
print("\n")

result=[]

#
#
# (13)
#
#
