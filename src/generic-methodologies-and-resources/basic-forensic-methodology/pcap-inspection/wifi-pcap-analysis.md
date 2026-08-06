# Uchambuzi wa Wifi Pcap

{{#include ../../../banners/hacktricks-training.md}}

## Kukagua BSSIDs

Unapopokea capture ambayo traffic yake kuu ni Wifi ukitumia WireShark, unaweza kuanza kuchunguza SSIDs zote za capture kupitia _Wireless --> WLAN Traffic_:

![Wifi Pcap Analysis - Check BSSIDs: When you receive a capture whose principal traffic is Wifi using WireShark you can start investigating all the SSIDs of the capture with Wireless --...](<../../../images/image (106).png>)

![Wifi Pcap Analysis - Check BSSIDs: When you receive a capture whose principal traffic is Wifi using WireShark you can start investigating all the SSIDs of the capture with Wireless --...](<../../../images/image (492).png>)

### Brute Force

Moja ya columns za skrini hiyo huonyesha ikiwa **authentication yoyote ilipatikana ndani ya pcap**. Ikiwa ndivyo, unaweza kujaribu kufanya Brute force kwa kutumia `aircrack-ng`:
```bash
aircrack-ng -w pwds-file.txt -b <BSSID> file.pcap
```
Kwa mfano, itaretrieve WPA passphrase inayolinda PSK (pre shared-key), ambayo itahitajika kwa ajili ya ku-decrypt traffic baadaye.

## Data katika Beacons / Side Channel

Ikiwa unashuku kuwa **data inaleak ndani ya beacons za mtandao wa Wifi**, unaweza kuangalia beacons za mtandao huo kwa kutumia filter kama hii: `wlan contains <NAMEofNETWORK>`, au `wlan.ssid == "NAMEofNETWORK"` kisha utafute strings zinazotiliwa shaka ndani ya packets zilizofilteriwa.

## Tafuta MAC Addresses Zisizojulikana katika Mtandao wa Wifi

Link ifuatayo itakuwa muhimu kwa kutafuta **machines zinazotuma data ndani ya Mtandao wa Wifi**:

- `((wlan.ta == e8:de:27:16:70:c9) && !(wlan.fc == 0x8000)) && !(wlan.fc.type_subtype == 0x0005) && !(wlan.fc.type_subtype ==0x0004) && !(wlan.addr==ff:ff:ff:ff:ff:ff) && wlan.fc.type==2`

Ikiwa tayari unajua **MAC addresses, unaweza kuziondoa kwenye output** kwa kuongeza checks kama hii: `&& !(wlan.addr==5c:51:88:31:a0:3b)`

Baada ya kugundua **MAC addresses zisizojulikana** zinazowasiliana ndani ya mtandao, unaweza kutumia **filters** kama hii: `wlan.addr==<MAC address> && (ftp || http || ssh || telnet)` ili kufilter traffic yake. Kumbuka kuwa filters za ftp/http/ssh/telnet zinafaa ikiwa ume-decrypt traffic.

## Decrypt Traffic

Edit --> Preferences --> Protocols --> IEEE 802.11--> Edit

![Tafuta MAC Addresses Zisizojulikana katika Mtandao wa Wifi - Decrypt Traffic: Baada ya kugundua MAC addresses zisizojulikana zinazowasiliana ndani ya mtandao, unaweza kutumia filters kama hii:...](<../../../images/image (499).png>)

{{#include ../../../banners/hacktricks-training.md}}
