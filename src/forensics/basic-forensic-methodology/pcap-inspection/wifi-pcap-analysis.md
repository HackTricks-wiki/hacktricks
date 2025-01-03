{{#include ../../../banners/hacktricks-training.md}}

# Angalia BSSIDs

Unapopokea kukamata ambayo trafiki yake kuu ni Wifi ukitumia WireShark unaweza kuanza kuchunguza SSIDs zote za kukamata kwa kutumia _Wireless --> WLAN Traffic_:

![](<../../../images/image (424).png>)

![](<../../../images/image (425).png>)

## Brute Force

Moja ya nguzo za skrini hiyo inaonyesha kama **uthibitisho wowote uligundulika ndani ya pcap**. Ikiwa ndivyo ilivyo unaweza kujaribu kuifanya Brute force kwa kutumia `aircrack-ng`:
```bash
aircrack-ng -w pwds-file.txt -b <BSSID> file.pcap
```
Kwa mfano, itapata WPA passphrase inayolinda PSK (pre shared-key), ambayo itahitajika kufungua trafiki baadaye.

# Data katika Beacons / Channel ya Kando

Ikiwa unashuku kwamba **data inavuja ndani ya beacons za mtandao wa Wifi** unaweza kuangalia beacons za mtandao kwa kutumia chujio kama ifuatavyo: `wlan contains <NAMEofNETWORK>`, au `wlan.ssid == "NAMEofNETWORK"` tafuta ndani ya pakiti zilizochujwa kwa nyuzi za kushangaza.

# Pata Anwani za MAC zisizojulikana katika Mtandao wa Wifi

Kiungo kinachofuata kitakuwa na manufaa kupata **mashine zinazotuma data ndani ya Mtandao wa Wifi**:

- `((wlan.ta == e8:de:27:16:70:c9) && !(wlan.fc == 0x8000)) && !(wlan.fc.type_subtype == 0x0005) && !(wlan.fc.type_subtype ==0x0004) && !(wlan.addr==ff:ff:ff:ff:ff:ff) && wlan.fc.type==2`

Ikiwa tayari unajua **anwani za MAC unaweza kuondoa hizo kutoka kwa matokeo** ukiongeza ukaguzi kama huu: `&& !(wlan.addr==5c:51:88:31:a0:3b)`

Mara tu unapogundua **anwani za MAC zisizojulikana** zinazowasiliana ndani ya mtandao unaweza kutumia **vichujio** kama ifuatavyo: `wlan.addr==<MAC address> && (ftp || http || ssh || telnet)` kuchuja trafiki yake. Kumbuka kwamba vichujio vya ftp/http/ssh/telnet ni vya manufaa ikiwa umepata ufunguo wa trafiki.

# Fungua Trafiki

Hariri --> Mipendeleo --> Protokali --> IEEE 802.11--> Hariri

![](<../../../images/image (426).png>)

{{#include ../../../banners/hacktricks-training.md}}
