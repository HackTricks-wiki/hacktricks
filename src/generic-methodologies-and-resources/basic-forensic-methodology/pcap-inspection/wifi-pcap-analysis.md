# Analyse d’un Pcap WiFi

{{#include ../../../banners/hacktricks-training.md}}

## Vérifier les BSSID

Avec une capture Wi-Fi ouverte dans Wireshark, sélectionnez _Wireless → WLAN Traffic_ pour résumer les réseaux sans fil observés dans la capture ; chaque ligne représente un réseau sans fil.<sup>[[1]](#references)</sup>

![Analyse d’un Pcap WiFi - Vérifier les BSSID : lorsque vous recevez une capture dont le trafic principal est du WiFi à l’aide de WireShark, vous pouvez commencer à examiner tous les SSID de la capture avec Wireless --...](<../../../images/image (106).png>)

![Analyse d’un Pcap WiFi - Vérifier les BSSID : lorsque vous recevez une capture dont le trafic principal est du WiFi à l’aide de WireShark, vous pouvez commencer à examiner tous les SSID de la capture avec Wireless --...](<../../../images/image (492).png>)

### Brute Force

Pour les captures WPA/WPA2-PSK, `aircrack-ng` nécessite un handshake EAPOL à quatre voies exploitable et teste les phrases secrètes candidates à l’aide d’un dictionnaire. Utilisez `-w` pour fournir la wordlist et `-b` pour cibler le BSSID de l’access point :<sup>[[2]](#references)</sup>
```bash
aircrack-ng -w pwds-file.txt -b <BSSID> file.pcap
```
Si un candidat correspond, Aircrack-ng récupère la clé pré-partagée ; le mot de passe et le SSID correspondants peuvent ensuite être configurés dans les paramètres de déchiffrement 802.11 de Wireshark lorsque la capture et le mode de sécurité le permettent.<sup>[[2]](#references)[[5]](#references)</sup>

## Données dans les Beacons / Side Channel

Si vous pensez que **des données sont leak dans le trafic de side channel des beacons**, commencez avec un display filter tel que `wlan contains "NAMEofNETWORK"` ou `wlan.ssid == "NAMEofNETWORK"`, puis inspectez les frames correspondantes à la recherche de chaînes suspectes. La première forme effectue une recherche large d'octets ; la seconde correspond au champ SSID.<sup>[[3]](#references)[[4]](#references)</sup>

## Trouver les adresses MAC inconnues dans un réseau Wi-Fi

Wireshark expose `wlan.ta` comme adresse de l'émetteur et `wlan.addr` comme adresse matérielle/MAC ; les display filters peuvent combiner ces champs avec des opérateurs logiques :<sup>[[3]](#references)[[4]](#references)</sup>

- `((wlan.ta == e8:de:27:16:70:c9) && !(wlan.fc == 0x8000)) && !(wlan.fc.type_subtype == 0x0005) && !(wlan.fc.type_subtype ==0x0004) && !(wlan.addr==ff:ff:ff:ff:ff:ff) && wlan.fc.type==2`

Si vous connaissez déjà certaines **adresses MAC, supprimez-les de la sortie** en ajoutant des vérifications telles que `&& !(wlan.addr == 5c:51:88:31:a0:3b)`.

Une fois que vous avez détecté des **adresses MAC inconnues** qui communiquent à l'intérieur du réseau, utilisez un filter tel que `wlan.addr == <MAC address> && (ftp || http || ssh || telnet)` pour restreindre son trafic. Les filters FTP, HTTP, SSH et Telnet ne sont utiles que lorsque Wireshark peut dissect le payload déchiffré correspondant.<sup>[[3]](#references)[[5]](#references)</sup>

## Déchiffrer le trafic

Pour ajouter une clé de déchiffrement 802.11 dans Wireshark, ouvrez _Edit → Preferences → Protocols → IEEE 802.11_ et cliquez sur _Edit_ à côté de _Decryption Keys_.<sup>[[5]](#references)</sup>

![Trouver les adresses MAC inconnues dans un réseau Wi-Fi - Déchiffrer le trafic : une fois que vous avez détecté des adresses MAC inconnues qui communiquent à l'intérieur du réseau, vous pouvez utiliser des filters tels que le suivant :...](<../../../images/image (499).png>)

Pour WPA/WPA2, Wireshark a normalement besoin du handshake EAPOL en quatre étapes et du mot de passe/SSID correspondant ; fournir la clé transitoire peut éviter d'avoir à fournir le handshake. Le déchiffrement WPA3 par connexion nécessite le PMK de la connexion.<sup>[[5]](#references)</sup>

## References

- [1] [Guide utilisateur de Wireshark : trafic WLAN](https://www.wireshark.org/docs/wsug_html_chunked/ChWirelessWLANTraffic.html)
- [2] [Aircrack-ng](https://www.aircrack-ng.org/doku.php?id=aircrack-ng)
- [3] [Guide utilisateur de Wireshark : création d'expressions de display filters](https://www.wireshark.org/docs/wsug_html_chunked/ChWorkBuildDisplayFilterSection.html)
- [4] [Référence des display filters de Wireshark : réseau local sans fil IEEE 802.11](https://www.wireshark.org/docs/dfref/w/wlan.html)
- [5] [Guide utilisateur de Wireshark : clés de déchiffrement WLAN IEEE 802.11](https://www.wireshark.org/docs/wsug_html_chunked/Ch80211Keys.html)
{{#include ../../../banners/hacktricks-training.md}}
