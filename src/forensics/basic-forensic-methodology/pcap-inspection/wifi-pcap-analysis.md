{{#include ../../../banners/hacktricks-training.md}}

# Vérifiez les BSSIDs

Lorsque vous recevez une capture dont le trafic principal est Wifi en utilisant WireShark, vous pouvez commencer à enquêter sur tous les SSIDs de la capture avec _Wireless --> WLAN Traffic_ :

![](<../../../images/image (424).png>)

![](<../../../images/image (425).png>)

## Brute Force

Une des colonnes de cet écran indique si **une authentification a été trouvée dans le pcap**. Si c'est le cas, vous pouvez essayer de le brute forcer en utilisant `aircrack-ng` :
```bash
aircrack-ng -w pwds-file.txt -b <BSSID> file.pcap
```
Par exemple, il récupérera le mot de passe WPA protégeant un PSK (clé pré-partagée), qui sera nécessaire pour déchiffrer le trafic plus tard.

# Données dans les Beacons / Canal Latéral

Si vous soupçonnez que **des données sont divulguées à l'intérieur des beacons d'un réseau Wifi**, vous pouvez vérifier les beacons du réseau en utilisant un filtre comme celui-ci : `wlan contains <NAMEofNETWORK>`, ou `wlan.ssid == "NAMEofNETWORK"` pour rechercher dans les paquets filtrés des chaînes suspectes.

# Trouver des Adresses MAC Inconnues dans un Réseau Wifi

Le lien suivant sera utile pour trouver les **machines envoyant des données à l'intérieur d'un réseau Wifi** :

- `((wlan.ta == e8:de:27:16:70:c9) && !(wlan.fc == 0x8000)) && !(wlan.fc.type_subtype == 0x0005) && !(wlan.fc.type_subtype ==0x0004) && !(wlan.addr==ff:ff:ff:ff:ff:ff) && wlan.fc.type==2`

Si vous connaissez déjà **les adresses MAC, vous pouvez les supprimer de la sortie** en ajoutant des vérifications comme celle-ci : `&& !(wlan.addr==5c:51:88:31:a0:3b)`

Une fois que vous avez détecté des **adresses MAC inconnues** communiquant à l'intérieur du réseau, vous pouvez utiliser des **filtres** comme celui-ci : `wlan.addr==<MAC address> && (ftp || http || ssh || telnet)` pour filtrer son trafic. Notez que les filtres ftp/http/ssh/telnet sont utiles si vous avez déchiffré le trafic.

# Déchiffrer le Trafic

Éditer --> Préférences --> Protocoles --> IEEE 802.11--> Éditer

![](<../../../images/image (426).png>)

{{#include ../../../banners/hacktricks-training.md}}
