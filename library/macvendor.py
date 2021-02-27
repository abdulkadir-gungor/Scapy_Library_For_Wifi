#!/usr/bin/python3
############################################################################
# 									 #
#	IEEE 802.11 Wifi Library 					 #
#	Developper:	Abdulkadir GÜNGÖR (abdulkadir_gungor@outlook.com)	 #
#	Date:	07/2020							 #
#	All Rights Reserved (Tüm Hakları Saklıdır)			 #
#                  							 #
############################################################################
import sqlite3
# ***********************************************************************
# MACVendor() ==> Veritabanından MAC adresinin ilk 24 bitinden
# (6 karakterinden) üretici firmayı sorgulayan fonksiyon
# ***********************************************************************
def MACVendor(mac):
	if (len(mac)==17):
		mac2 = mac.upper()
		mac3 = mac2[0:2]+mac2[3:5]+mac2[6:8]
		db = sqlite3.connect("mac-vendor.db")
		dbCursor=db.cursor()
		dbCursor.execute("select VENDOR from MAC_VENDOR where MAC='{}'".format(mac3) )
		sorgu=dbCursor.fetchone()
		if(sorgu==None):
			db.close()
			return [False,""]
		else:
			sonuc = [True,(sorgu[0].strip()).upper()]
			db.close()
			return sonuc
	else:
		print("\n\033[1;37;41m\tGönderilen MAC adresi formatı yanlış. MAC='00:00:00:00:00:00' formatında olmalıdır.\033[0;37;39m\n")
		return [False,""]
