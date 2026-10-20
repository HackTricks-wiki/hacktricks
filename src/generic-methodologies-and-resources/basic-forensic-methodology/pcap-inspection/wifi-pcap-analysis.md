# Analyse de capture PCAP Wi-Fi

{{#include ../../../banners/hacktricks-training.md}}

## Vérifier les BSSID

Une capture Wi-Fi ouverte dans Wireshark, sélectionnez _Wireless → WLAN Traffic_ pour récapituler les réseaux sans fil observés dans la capture ; chaque ligne représente un réseau sans fil.<sup>[[1]](#references)</sup>

![Analyse de capture PCAP Wi-Fi - Vérifier les BSSID : lorsque vous recevez une capture dont le trafic principal est du Wi-Fi et que vous utilisez Wireshark, vous pouvez commencer par examiner tous les SSID de la capture avec Wireless --...](<../../../images/image (106).png>)

![Analyse de capture PCAP Wi-Fi - Vérifier les BSSID : lorsque vous recevez une capture dont le trafic principal est du Wi-Fi et que vous utilisez Wireshark, vous pouvez commencer par examiner tous les SSID de la capture avec Wireless --...](<../../../images/image (492).png>)

### Brute Force

Pour les captures WPA/WPA2-PSK, `aircrack-ng` a besoin d'un échange EAPOL à quatre voies exploitable et teste les mots de passe candidats à l'aide d'un dictionnaire. Utilisez `-w` pour fournir la wordlist et `-b` pour cibler le BSSID du point d'accès :<sup>[[2]](#references)</sup>

```bash
aircrack-ng -w pwds-file.txt -b <BSSID> file.pcap
```

Si une candidate correspond, Aircrack-ng récupère la clé prépartagée ; le mot de passe correspondant et le SSID peuvent ensuite être configurés dans les paramètres de déchiffrement 802.11 de Wireshark, si la capture et le mode de sécurité le permettent.<sup>[[2]](#references)[[5]](#references)</sup>

## Données dans les beacons / canal auxiliaire

Si vous soupçonnez que **des données sont divulguées dans le trafic du canal auxiliaire des beacons**, commencez par un filtre d’affichage tel que `wlan contains "NAMEofNETWORK"` ou `wlan.ssid == "NAMEofNETWORK"`, puis inspectez les trames correspondantes à la recherche de chaînes suspectes. La première forme effectue une recherche générale dans les octets ; la seconde correspond au champ SSID.<sup>[[3]](#references)[[4]](#references)</sup>

## Trouver les adresses MAC inconnues sur un réseau Wi-Fi

Wireshark expose `wlan.ta` comme adresse de l’émetteur et `wlan.addr` comme adresse matérielle/MAC ; les filtres d’affichage peuvent combiner ces champs à l’aide d’opérateurs logiques :<sup>[[3]](#references)[[4]](#references)</sup>

- `((wlan.ta == e8:de:27:16:70:c9) && !(wlan.fc == 0x8000)) && !(wlan.fc.type_subtype == 0x0005) && !(wlan.fc.type_subtype ==0x0004) && !(wlan.addr==ff:ff:ff:ff:ff:ff) && wlan.fc.type==2`

Si vous connaissez déjà des **adresses MAC, excluez-les des résultats** en ajoutant des conditions telles que `&& !(wlan.addr == 5c:51:88:31:a0:3b)`.

Une fois que vous avez détecté des adresses **MAC inconnues** qui communiquent sur le réseau, utilisez un filtre tel que `wlan.addr == <MAC address> && (ftp || http || ssh || telnet)` pour isoler leur trafic. Les filtres FTP, HTTP, SSH et Telnet ne sont utiles que si Wireshark peut analyser la charge utile déchiffrée correspondante.<sup>[[3]](#references)[[5]](#references)</sup>

## Déchiffrer le trafic

Pour ajouter une clé de déchiffrement 802.11 dans Wireshark, ouvrez _Édition → Préférences → Protocoles → IEEE 802.11_ et cliquez sur _Modifier_ à côté de _Clés de déchiffrement_.<sup>[[5]](#references)</sup>

![Trouver les adresses MAC inconnues sur un réseau Wi-Fi - Déchiffrer le trafic : une fois que vous avez détecté des adresses MAC inconnues qui communiquent sur le réseau, vous pouvez utiliser des filtres comme celui-ci :...](<../../../images/image (499).png>)

Pour WPA/WPA2, Wireshark a généralement besoin de la poignée de main EAPOL à quatre étapes et du mot de passe/SSID correspondant ; fournir la clé transitoire permet de se passer de la poignée de main. Le déchiffrement WPA3 par connexion nécessite le PMK de la connexion.<sup>[[5]](#references)</sup>

Pour déchiffrer la couche TLS applicative après avoir récupéré le trafic Wi-Fi, consultez [Astuces Wireshark](wireshark-tricks.md#decrypting-tls).

## References

- [1] [Guide de l’utilisateur de Wireshark : trafic WLAN](https://www.wireshark.org/docs/wsug_html_chunked/ChWirelessWLANTraffic.html)
- [2] [Aircrack-ng](https://www.aircrack-ng.org/doku.php?id=aircrack-ng)
- [3] [Guide de l’utilisateur de Wireshark : créer des expressions de filtre d’affichage](https://www.wireshark.org/docs/wsug_html_chunked/ChWorkBuildDisplayFilterSection.html)
- [4] [Référence des filtres d’affichage Wireshark : réseau local sans fil IEEE 802.11](https://www.wireshark.org/docs/dfref/w/wlan.html)
- [5] [Guide de l’utilisateur de Wireshark : clés de déchiffrement WLAN IEEE 802.11](https://www.wireshark.org/docs/wsug_html_chunked/Ch80211Keys.html)
{{#include ../../../banners/hacktricks-training.md}}
