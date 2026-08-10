# Astuces Wireshark

## Améliorer vos compétences sur Wireshark

### Tutoriels

Les tutoriels suivants sont excellents pour apprendre quelques astuces de base :

- [https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/](https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/)
- [https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/](https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/)
- [https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/](https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/)
- [https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/](https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/)

### Informations analysées

**Informations d'expert**

En cliquant sur _**Analyze** --> **Expert Information**_, vous obtiendrez un **aperçu** de ce qui se passe dans les paquets **analysés** :

![Tutoriels - Informations analysées : en cliquant sur Analyze -- Expert Information, vous obtiendrez un aperçu de ce qui se passe dans les paquets analysés](<../../../images/image (256).png>)

**Adresses résolues**

Sous _**Statistics --> Resolved Addresses**_, vous trouverez plusieurs **informations** "**résolues**" par Wireshark, comme le port/transport vers le protocole, l'adresse MAC vers le fabricant, etc. Il est intéressant de savoir ce qui est impliqué dans la communication.

![Tutoriels - Informations analysées : sous Statistics -- Resolved Addresses, vous trouverez plusieurs informations « résolues » par Wireshark, comme le port/transport vers le protocole, l'adresse MAC vers le...](<../../../images/image (893).png>)

**Hiérarchie des protocoles**

Sous _**Statistics --> Protocol Hierarchy**_, vous trouverez les **protocoles** **impliqués** dans la communication ainsi que des données les concernant.

![Tutoriels - Informations analysées : sous Statistics -- Protocol Hierarchy, vous trouverez les protocoles impliqués dans la communication ainsi que des données les concernant](<../../../images/image (586).png>)

**Conversations**

Sous _**Statistics --> Conversations**_, vous trouverez un **résumé des conversations** de la communication ainsi que des données les concernant.

![Tutoriels - Informations analysées : sous Statistics -- Conversations, vous trouverez un résumé des conversations de la communication ainsi que des données les concernant](<../../../images/image (453).png>)

**Endpoints**

Sous _**Statistics --> Endpoints**_, vous trouverez un **résumé des endpoints** de la communication ainsi que des données concernant chacun d'eux.

![Tutoriels - Informations analysées : sous Statistics -- Endpoints, vous trouverez un résumé des endpoints de la communication ainsi que des données concernant chacun d'eux](<../../../images/image (896).png>)

**Informations DNS**

Sous _**Statistics --> DNS**_, vous trouverez des statistiques sur la requête DNS capturée.

![Tutoriels - Informations analysées : sous Statistics -- DNS, vous trouverez des statistiques sur la requête DNS capturée](<../../../images/image (1063).png>)

**Graphe I/O**

Sous _**Statistics --> I/O Graph**_, vous trouverez un **graphe de la communication.**

![Tutoriels - Informations analysées : sous Statistics -- I/O Graph, vous trouverez un graphe de la communication](<../../../images/image (992).png>)

### Filtres

Vous trouverez ici les filtres Wireshark en fonction du protocole : [https://www.wireshark.org/docs/dfref/](https://www.wireshark.org/docs/dfref/)\
Dans la version actuelle de Wireshark, utilisez `tls.*` à la place des anciens noms de filtres `ssl.*`.<sup>[[1]](#references)</sup>\
Autres filtres intéressants :

- `(http.request or tls.handshake.type == 1) and !(udp.port eq 1900)`
- Trafic HTTP et HTTPS initial
- `(http.request or tls.handshake.type == 1 or tcp.flags eq 0x0002) and !(udp.port eq 1900)`
- Trafic HTTP et HTTPS initial + TCP SYN
- `(http.request or tls.handshake.type == 1 or tcp.flags eq 0x0002 or dns) and !(udp.port eq 1900)`
- Trafic HTTP et HTTPS initial + TCP SYN + requêtes DNS
- `tls.handshake.extensions_server_name contains "example.com"`
- Pivot sur le SNI envoyé dans le ClientHello, même lorsque vous ne pouvez pas déchiffrer le payload
- `tls.handshake.extensions_alpn_str == "h2" or tls.handshake.extensions_alpn_str == "h3"`
- Séparer rapidement les sessions HTTPS classiques, HTTP/2 et HTTP/3 compatibles
- `quic or http3`
- Trouver le trafic UDP/443 moderne qui ne sera pas détecté si vous examinez uniquement les conversations TCP

### Recherche

Si vous souhaitez **rechercher** du **contenu** à l'intérieur des **paquets** des sessions, appuyez sur _CTRL+f_. Vous pouvez ajouter de nouvelles colonnes à la barre d'informations principale (No., Time, Source, etc.) en cliquant sur le bouton droit, puis en modifiant la colonne.

### Suivi des flux multiplexés

Wireshark peut suivre directement les flux `TLS`, `HTTP/2` et `QUIC`. Ses boîtes de dialogue HTTP/2 et QUIC exposent des sélecteurs de connexion et de sous-flux, ce qui aide à isoler les flux multiplexés qui partagent la même connexion de niveau inférieur.<sup>[[4]](#references)</sup>

### Labs PCAP gratuits

**Entraînez-vous avec les challenges gratuits de :** [**https://www.malware-traffic-analysis.net/**](https://www.malware-traffic-analysis.net)

## Identifier les domaines

Vous pouvez ajouter une colonne qui affiche l'en-tête HTTP Host :

![Labs PCAP gratuits - Identifier les domaines : vous pouvez ajouter une colonne qui affiche l'en-tête HTTP Host](<../../../images/image (639).png>)

Ainsi qu'une colonne qui ajoute le nom du Server provenant d'une connexion HTTPS initiatrice (**tls.handshake.type == 1**) :

![Labs PCAP gratuits - Identifier les domaines : ainsi qu'une colonne qui ajoute le nom du Server provenant d'une connexion HTTPS initiatrice ( tls.handshake.type == 1 )](<../../../images/image (408) (1).png>)

Si la capture est principalement chiffrée, l'ajout de ces champs en tant que colonnes accélérera considérablement le triage :

- `tls.handshake.extensions_server_name`
- `tls.handshake.extensions_alpn_str`
- `tls.handshake.ja3`
- `tls.handshake.ja4` (Wireshark 4.2+)

Cela vous permet de regrouper les sessions par nom d'hôte, ALPN (`http/1.1`, `h2`, `h3`, etc.) et empreinte client, même lorsque le payload lui-même reste chiffré. Pour les captures HTTP/2 et HTTP/3 déchiffrées, il est également utile d'ajouter `http2.header.value` ou `http3.headers.header.value` comme colonnes et d'effectuer un pivot sur les chemins, les autorités et autres métadonnées intéressantes.<sup>[[2]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>
```bash
tshark -r capture.pcapng -Y "tls.handshake.type == 1" -T fields \
-e frame.number -e ip.src -e ip.dst \
-e tls.handshake.extensions_server_name \
-e tls.handshake.extensions_alpn_str \
-e tls.handshake.ja3 -e tls.handshake.ja4
```
## Identification des noms d’hôtes locaux

### Depuis DHCP

Dans la version actuelle de Wireshark, au lieu de `bootp`, vous devez rechercher `DHCP`

![Identification des noms d’hôtes locaux - Depuis DHCP : dans la version actuelle de Wireshark, au lieu de bootp, vous devez rechercher DHCP](<../../../images/image (1013).png>)

### Depuis NBNS

![Depuis DHCP - Depuis NBNS : dans la version actuelle de Wireshark, au lieu de bootp, vous devez rechercher DHCP](<../../../images/image (1003).png>)

## Déchiffrement de TLS

### Déchiffrement du trafic https avec la clé privée du serveur

_modifier > preferences > protocols > tls >_

![Déchiffrement de TLS - Déchiffrement du trafic https avec la clé privée du serveur : Déchiffrement du trafic https avec la clé privée du serveur](<../../../images/image (1103).png>)

Appuyez sur _Edit_ et ajoutez toutes les informations du serveur et de la clé privée (_IP, Port, Protocol, Key file et password_)

Cette méthode ne fonctionne que dans un nombre limité de cas. Pour le trafic TLS 1.3 / ECDHE actuel, la méthode de journalisation des clés de session ci-dessous est généralement l’option pratique.<sup>[[1]](#references)</sup>

### Déchiffrement du trafic https avec les clés de session symétriques

Firefox et Chrome peuvent tous deux journaliser les clés de session TLS, qui peuvent être utilisées avec Wireshark pour déchiffrer le trafic TLS. Cela permet une analyse approfondie des communications sécurisées. Vous trouverez plus de détails sur la manière d’effectuer ce déchiffrement dans un guide de [Red Flag Security](https://redflagsecurity.net/2019/03/10/decrypting-tls-wireshark/).<sup>[[3]](#references)</sup> Il s’agit également de la méthode normale pour déchiffrer les captures TLS 1.3 et QUIC/HTTP/3 modernes.<sup>[[2]](#references)</sup>

Pour détecter cela, recherchez la variable `SSLKEYLOGFILE` dans l’environnement.

Un fichier de clés partagées ressemblera à ceci :

![Déchiffrement du trafic https avec la clé privée du serveur - Déchiffrement du trafic https avec les clés de session symétriques : Un fichier de clés partagées ressemblera à ceci](<../../../images/image (820).png>)

Si la capture est au format `pcapng`, vérifiez si elle contient déjà des secrets de déchiffrement intégrés avant de rechercher le système de fichiers de l’hôte :<sup>[[1]](#references)</sup>
```bash
editcap --extract-secrets capture.pcapng tls-secrets.txt
```
Pour l’importer dans wireshark, allez dans \_edit > preferences > protocols > tls > et importez-le dans (Pre)-Master-Secret log filename :

![Déchiffrer le trafic https avec la clé privée du serveur - Déchiffrer le trafic https avec les clés de session symétriques : editcap --extract-secrets capture.pcapng tls-secrets.txt](<../../../images/image (989).png>)

## Communication ADB

Extraire un APK d’une communication ADB dans laquelle l’APK a été envoyé :
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
## References

- [1] [Wireshark TLS wiki](https://wiki.wireshark.org/TLS)
- [2] [Déchiffrement et analyse du trafic HTTP/3 dans Wireshark](https://blog.elmo.sg/posts/parsing-decrypted-quic-traffic-in-wireshark/)
- [3] [Déchiffrer le trafic TLS d'un navigateur avec Wireshark - la méthode facile !](https://redflagsecurity.net/2019/03/10/decrypting-tls-wireshark/)
- [4] [Suivre les flux de protocoles](https://www.wireshark.org/docs/wsug_html_chunked/ChAdvFollowStreamSection.html)
- [5] [Référence des filtres d'affichage : Transport Layer Security](https://www.wireshark.org/docs/dfref/t/tls.html)
- [6] [Référence des filtres d'affichage : HyperText Transfer Protocol 2](https://www.wireshark.org/docs/dfref/h/http2.html)
- [7] [Référence des filtres d'affichage : Hypertext Transfer Protocol Version 3](https://www.wireshark.org/docs/dfref/h/http3.html)
{{#include ../../../banners/hacktricks-training.md}}
