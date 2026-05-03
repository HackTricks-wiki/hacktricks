# Wireshark tricks

{{#include ../../../banners/hacktricks-training.md}}

## Améliorez vos compétences Wireshark

### Tutorials

Les tutoriels suivants sont excellents pour apprendre quelques astuces de base intéressantes :

- [https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/](https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/)
- [https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/](https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/)
- [https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/](https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/)
- [https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/](https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/)

### Information analysée

**Expert Information**

En cliquant sur _**Analyze** --> **Expert Information**_ vous obtiendrez une **vue d'ensemble** de ce qui se passe dans les paquets **analysés** :

![](<../../../images/image (256).png>)

**Resolved Addresses**

Sous _**Statistics --> Resolved Addresses**_ vous pouvez trouver plusieurs **informations** qui ont été "**resolved**" par wireshark, comme port/transport vers protocole, MAC vers le fabricant, etc. Il est intéressant de savoir ce qui est impliqué dans la communication.

![](<../../../images/image (893).png>)

**Protocol Hierarchy**

Sous _**Statistics --> Protocol Hierarchy**_ vous pouvez trouver les **protocols** **impliqués** dans la communication et des données à leur sujet.

![](<../../../images/image (586).png>)

**Conversations**

Sous _**Statistics --> Conversations**_ vous pouvez trouver un **résumé des conversations** dans la communication et des données à leur sujet.

![](<../../../images/image (453).png>)

**Endpoints**

Sous _**Statistics --> Endpoints**_ vous pouvez trouver un **résumé des endpoints** dans la communication et des données sur chacun d'eux.

![](<../../../images/image (896).png>)

**DNS info**

Sous _**Statistics --> DNS**_ vous pouvez trouver des statistiques sur la requête DNS capturée.

![](<../../../images/image (1063).png>)

**I/O Graph**

Sous _**Statistics --> I/O Graph**_ vous pouvez trouver un **graphique de la communication.**

![](<../../../images/image (992).png>)

### Filters

Vous pouvez trouver ici les filtres wireshark selon le protocol : [https://www.wireshark.org/docs/dfref/](https://www.wireshark.org/docs/dfref/)\
Dans la version actuelle de Wireshark, utilisez `tls.*` à la place des anciens noms de filtre `ssl.*`.\
Autres filtres intéressants :

- `(http.request or tls.handshake.type == 1) and !(udp.port eq 1900)`
- Trafic HTTP et HTTPS initial
- `(http.request or tls.handshake.type == 1 or tcp.flags eq 0x0002) and !(udp.port eq 1900)`
- Trafic HTTP et HTTPS initial + TCP SYN
- `(http.request or tls.handshake.type == 1 or tcp.flags eq 0x0002 or dns) and !(udp.port eq 1900)`
- Trafic HTTP et HTTPS initial + TCP SYN + requêtes DNS
- `tls.handshake.extensions_server_name contains "example.com"`
- Pivot sur le SNI envoyé dans le ClientHello même lorsque vous ne pouvez pas déchiffrer le payload
- `tls.handshake.extensions_alpn_str == "h2" or tls.handshake.extensions_alpn_str == "h3"`
- Sépare rapidement les sessions classiques HTTPS, HTTP/2 et HTTP/3
- `quic or http3`
- Trouve le trafic UDP/443 moderne qui sera manqué si vous ne consultez que les conversations TCP

### Search

Si vous voulez **rechercher** du **contenu** à l'intérieur des **paquets** des sessions, appuyez sur _CTRL+f_. Vous pouvez ajouter de nouvelles colonnes à la barre d'information principale (No., Time, Source, etc.) en appuyant sur le bouton droit puis en éditant la colonne.

### Following multiplexed streams

Les versions récentes de Wireshark peuvent suivre directement les flux `TLS`, `HTTP/2` et `QUIC`. Sur des captures bruyantes, c'est généralement plus rapide que d'utiliser uniquement `Follow TCP Stream`, surtout lorsque plusieurs requêtes partagent la même connexion.

### Free pcap labs

**Entraînez-vous avec les défis gratuits de :** [**https://www.malware-traffic-analysis.net/**](https://www.malware-traffic-analysis.net)

## Identifying Domains

Vous pouvez ajouter une colonne qui affiche l'en-tête Host HTTP :

![](<../../../images/image (639).png>)

Et une colonne qui ajoute le nom du serveur d'une connexion HTTPS initiée (**tls.handshake.type == 1**) :

![](<../../../images/image (408) (1).png>)

Si la capture est majoritairement chiffrée, ajouter ces champs comme colonnes accélérera énormément le triage :

- `tls.handshake.extensions_server_name`
- `tls.handshake.extensions_alpn_str`
- `tls.handshake.ja3`
- `tls.handshake.ja4` (Wireshark 4.2+)

Cela permet de regrouper les sessions par nom d'hôte, ALPN (`http/1.1`, `h2`, `h3`, etc.) et empreinte client, même lorsque le payload lui-même reste chiffré. Pour les captures HTTP/2 et HTTP/3 déchiffrées, il est aussi utile d'ajouter `http2.header.value` ou `http3.headers.header.value` comme colonnes et de pivoter sur les paths, authorities et autres métadonnées intéressantes.
```bash
tshark -r capture.pcapng -Y "tls.handshake.type == 1" -T fields \
-e frame.number -e ip.src -e ip.dst \
-e tls.handshake.extensions_server_name \
-e tls.handshake.extensions_alpn_str \
-e tls.handshake.ja3 -e tls.handshake.ja4
```
## Identification des noms d’hôte locaux

### Depuis DHCP

Dans la version actuelle de Wireshark, au lieu de `bootp`, vous devez chercher `DHCP`

![](<../../../images/image (1013).png>)

### Depuis NBNS

![](<../../../images/image (1003).png>)

## Déchiffrement TLS

### Déchiffrer le trafic https avec la clé privée du serveur

_edit > preferences > protocols > tls >_

![](<../../../images/image (1103).png>)

Appuyez sur _Edit_ et ajoutez toutes les données du serveur et de la clé privée (_IP, Port, Protocol, Key file and password_)

Cette méthode ne fonctionne que dans un nombre limité de cas. Pour le trafic TLS 1.3 / ECDHE actuel, la méthode du journal des clés de session ci-dessous est généralement l’option pratique.

### Déchiffrer le trafic https avec des clés de session symétriques

Firefox et Chrome ont tous deux la capacité d’enregistrer les clés de session TLS, qui peuvent être utilisées avec Wireshark pour déchiffrer le trafic TLS. Cela permet une analyse approfondie des communications sécurisées. Plus de détails sur la manière d’effectuer ce déchiffrement peuvent être trouvés dans un guide sur [Red Flag Security](https://redflagsecurity.net/2019/03/10/decrypting-tls-wireshark/). C’est aussi la méthode normale pour déchiffrer les captures modernes TLS 1.3 et QUIC/HTTP/3.

Pour détecter cela, cherchez dans l’environnement la variable `SSLKEYLOGFILE`

Un fichier de clés partagées ressemblera à ceci :

![](<../../../images/image (820).png>)

Si la capture est `pcapng`, vérifiez si elle contient déjà des secrets de déchiffrement intégrés avant de fouiller le système de fichiers de l’hôte :
```bash
editcap --extract-secrets capture.pcapng tls-secrets.txt
```
Pour l'importer dans wireshark allez dans \_edit > preferences > protocols > tls > et importez-le dans (Pre)-Master-Secret log filename :

![](<../../../images/image (989).png>)

## ADB communication

Extraire un APK d'une communication ADB où l'APK a été envoyé :
```python
from scapy.all import *

pcap = rdpcap("final2.pcapng")

def rm_data(data):
splitted = data.split(b"DATA")
if len(splitted) == 1:
return data
else:
return splitted[0]+splitted[1][4:]

all_bytes = b""
for pkt in pcap:
if Raw in pkt:
a = pkt[Raw]
if b"WRTE" == bytes(a)[:4]:
all_bytes += rm_data(bytes(a)[24:])
else:
all_bytes += rm_data(bytes(a))
print(all_bytes)

f = open('all_bytes.data', 'w+b')
f.write(all_bytes)
f.close()
```
## Références

- [Wireshark TLS wiki](https://wiki.wireshark.org/TLS)
- [Decrypting and parsing HTTP/3 traffic in Wireshark](https://blog.elmo.sg/posts/parsing-decrypted-quic-traffic-in-wireshark/)

{{#include ../../../banners/hacktricks-training.md}}
