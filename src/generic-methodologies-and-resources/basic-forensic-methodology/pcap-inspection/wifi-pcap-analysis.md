# Analyse de Pcap Wifi

{{#include ../../../banners/hacktricks-training.md}}

## Vérifier les BSSID

Lorsque vous recevez une capture dont le trafic principal est du Wifi avec WireShark, vous pouvez commencer par examiner tous les SSID de la capture avec _Wireless --> WLAN Traffic_ :

![Analyse de Pcap Wifi - Vérifier les BSSID : Lorsque vous recevez une capture dont le trafic principal est du Wifi avec WireShark, vous pouvez commencer par examiner tous les SSID de la capture avec Wireless --...](<../../../images/image (106).png>)

![Analyse de Pcap Wifi - Vérifier les BSSID : Lorsque vous recevez une capture dont le trafic principal est du Wifi avec WireShark, vous pouvez commencer par examiner tous les SSID de la capture avec Wireless --...](<../../../images/image (492).png>)

### Brute Force

L'une des colonnes de cet écran indique si **une authentification a été trouvée dans le pcap**. Si c'est le cas, vous pouvez essayer de la Brute force avec `aircrack-ng` :
```bash
aircrack-ng -w pwds-file.txt -b <BSSID> file.pcap
```
Par exemple, il récupérera la phrase secrète WPA protégeant un PSK (pre-shared key), qui sera nécessaire pour déchiffrer le trafic ultérieurement.

## Données dans les Beacons / Side Channel

Si vous soupçonnez que des **données sont exfiltrées à l'intérieur des beacons d'un réseau Wifi**, vous pouvez vérifier les beacons du réseau à l'aide d'un filtre comme le suivant : `wlan contains <NAMEofNETWORK>`, ou rechercher `wlan.ssid == "NAMEofNETWORK"` à l'intérieur des paquets filtrés afin d'y trouver des chaînes suspectes.

## Trouver des adresses MAC inconnues dans un réseau Wifi

Le lien suivant sera utile pour trouver les **machines envoyant des données dans un réseau Wifi** :

- `((wlan.ta == e8:de:27:16:70:c9) && !(wlan.fc == 0x8000)) && !(wlan.fc.type_subtype == 0x0005) && !(wlan.fc.type_subtype ==0x0004) && !(wlan.addr==ff:ff:ff:ff:ff:ff) && wlan.fc.type==2`

Si vous connaissez déjà certaines **adresses MAC, vous pouvez les supprimer des résultats** en ajoutant des vérifications comme celle-ci : `&& !(wlan.addr==5c:51:88:31:a0:3b)`

Une fois que vous avez détecté des **adresses MAC inconnues** communiquant sur le réseau, vous pouvez utiliser des **filtres** comme le suivant : `wlan.addr==<MAC address> && (ftp || http || ssh || telnet)` pour filtrer son trafic. Notez que les filtres ftp/http/ssh/telnet sont utiles si vous avez déchiffré le trafic.

## Déchiffrer le trafic

Edit --> Preferences --> Protocols --> IEEE 802.11--> Edit

![Trouver des adresses MAC inconnues dans un réseau Wifi - Déchiffrer le trafic : Une fois que vous avez détecté des adresses MAC inconnues communiquant sur le réseau, vous pouvez utiliser des filtres comme le suivant :...](<../../../images/image (499).png>)

{{#include ../../../banners/hacktricks-training.md}}
