# Astuces Wireshark

{{#include ../../../banners/hacktricks-training.md}}

## Améliorer vos compétences sur Wireshark

### Tutoriels

Les tutoriels suivants sont excellents pour apprendre quelques astuces de base :

- [https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/](https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/)
- [https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/](https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/)
- [https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/](https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/)
- [https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/](https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/)

### Informations analysées

**Informations d'expert**

En cliquant sur _**Analyze** --> **Expert Information**_, vous obtenez une **vue d'ensemble** de ce qui se passe dans les paquets **analysés** :

![Tutoriels - Informations analysées : en cliquant sur Analyze -- Expert Information, vous obtenez une vue d'ensemble de ce qui se passe dans les paquets analysés](<../../../images/image (256).png>)

**Adresses résolues**

Sous _**Statistics --> Resolved Addresses**_, vous trouverez plusieurs **informations** que Wireshark a « **résolues** », comme le port/transport en protocole, l'adresse MAC en fabricant, etc. Cela permet de savoir quels éléments sont impliqués dans la communication.

![Tutoriels - Informations analysées : sous Statistics -- Resolved Addresses, vous trouverez plusieurs informations que Wireshark a « résolues », comme le port/transport en protocole, l'adresse MAC en fabricant, etc.](<../../../images/image (893).png>)

**Hiérarchie des protocoles**

Sous _**Statistics --> Protocol Hierarchy**_, vous trouverez les **protocoles** **impliqués** dans la communication ainsi que des données à leur sujet.

![Tutoriels - Informations analysées : sous Statistics -- Protocol Hierarchy, vous trouverez les protocoles impliqués dans la communication ainsi que des données à leur sujet](<../../../images/image (586).png>)

**Conversations**

Sous _**Statistics --> Conversations**_, vous trouverez un **résumé des conversations** dans la communication ainsi que des données à leur sujet.

![Tutoriels - Informations analysées : sous Statistics -- Conversations, vous trouverez un résumé des conversations dans la communication ainsi que des données à leur sujet](<../../../images/image (453).png>)

**Points de terminaison**

Sous _**Statistics --> Endpoints**_, vous trouverez un **résumé des points de terminaison** dans la communication ainsi que des données sur chacun d'eux.

![Tutoriels - Informations analysées : sous Statistics -- Endpoints, vous trouverez un résumé des points de terminaison dans la communication ainsi que des données sur chacun d'eux](<../../../images/image (896).png>)

**Informations DNS**

Sous _**Statistics --> DNS**_, vous trouverez des statistiques sur les requêtes DNS capturées.

![Tutoriels - Informations analysées : sous Statistics -- DNS, vous trouverez des statistiques sur les requêtes DNS capturées](<../../../images/image (1063).png>)

**Graphique E/S**

Sous _**Statistics --> I/O Graph**_, vous trouverez un **graphique de la communication.**

![Tutoriels - Informations analysées : sous Statistics -- I/O Graph, vous trouverez un graphique de la communication](<../../../images/image (992).png>)

### Filtres

Vous trouverez ici des filtres Wireshark selon le protocole : [https://www.wireshark.org/docs/dfref/](https://www.wireshark.org/docs/dfref/)\
Dans les versions actuelles de Wireshark, utilisez `tls.*` au lieu des anciens noms de filtres `ssl.*`.<sup>[[1]](#references)</sup>\
Autres filtres intéressants :

- `(http.request or tls.handshake.type == 1) and !(udp.port eq 1900)`
  - Trafic HTTP et HTTPS initial
- `(http.request or tls.handshake.type == 1 or tcp.flags eq 0x0002) and !(udp.port eq 1900)`
  - Trafic HTTP et HTTPS initial + TCP SYN
- `(http.request or tls.handshake.type == 1 or tcp.flags eq 0x0002 or dns) and !(udp.port eq 1900)`
  - Trafic HTTP et HTTPS initial + TCP SYN + requêtes DNS
- `tls.handshake.extensions_server_name contains "example.com"`
  - Filtrez selon le SNI envoyé dans le ClientHello, même si vous ne pouvez pas déchiffrer le contenu
- `tls.handshake.extensions_alpn_str == "h2" or tls.handshake.extensions_alpn_str == "h3"`
  - Séparez rapidement les sessions compatibles avec HTTPS classique, HTTP/2 et HTTP/3
- `quic or http3`
  - Repérez le trafic UDP/443 moderne qui vous échapperait si vous n'examiniez que les conversations TCP

### Recherche

Pour **rechercher** du **contenu** dans les **paquets** des sessions, appuyez sur _CTRL+f_. Vous pouvez ajouter de nouvelles colonnes à la barre d'informations principale (No., Time, Source, etc.) en cliquant avec le bouton droit, puis en choisissant l'édition des colonnes.

### Suivre les flux multiplexés

Wireshark peut suivre directement les flux `TLS`, `HTTP/2` et `QUIC`. Ses fenêtres de dialogue HTTP/2 et QUIC proposent des sélecteurs de connexion et de sous-flux, ce qui aide à isoler les flux multiplexés qui partagent la même connexion de niveau inférieur.<sup>[[4]](#references)</sup>

Lorsque les clés de session sont disponibles, identifiez d'abord l'ID du flux de la requête, puis suivez ce sous-flux plutôt que toute la conversation TCP ou UDP. L'exemple `0,1` sélectionne l'ID de flux HTTP/2 1 sur le flux TCP 0 ; pour QUIC, utilisez `follow,quic,utf-8,<connection-number>,<stream-id>`. Le suivi d'un simple quintuplet peut mélanger des requêtes indépendantes ou vous faire manquer une connexion QUIC après une migration.<sup>[[6]](#references)[[7]](#references)[[9]](#references)</sup>

```bash
tshark -r capture.pcapng -o tls.keylog_file:keys.log \
  -Y 'http2.headers.authority || http3.headers.authority' -T fields \
  -e tcp.stream -e http2.streamid -e quic.connection.number \
  -e quic.stream.stream_id -e http2.headers.authority \
  -e http3.headers.authority
tshark -r capture.pcapng -o tls.keylog_file:keys.log \
  -q -z 'follow,http2,utf-8,0,1'
```

### Labs PCAP gratuits

**Entraînez-vous avec les défis gratuits de :** [**https://www.malware-traffic-analysis.net/**](https://www.malware-traffic-analysis.net)

## Identifier les domaines

Vous pouvez ajouter une colonne qui affiche l’en-tête HTTP Host :

![Labs PCAP gratuits - Identifier les domaines : vous pouvez ajouter une colonne qui affiche l’en-tête HTTP Host](<../../../images/image (639).png>)

Et une colonne qui ajoute le nom du serveur à partir d’une connexion HTTPS initiatrice (**tls.handshake.type == 1**) :

![Labs PCAP gratuits - Identifier les domaines : et une colonne qui ajoute le nom du serveur à partir d’une connexion HTTPS initiatrice ( tls.handshake.type == 1 )](<../../../images/image (408) (1).png>)

Si la capture est principalement chiffrée, ajouter ces champs sous forme de colonnes accélérera considérablement le triage :

- `tls.handshake.extensions_server_name`
- `tls.handshake.extensions_alpn_str`
- `tls.handshake.ja3`
- `tls.handshake.ja4` (Wireshark 4.2+)

Cela vous permet de regrouper les sessions par nom d’hôte, ALPN (`http/1.1`, `h2`, `h3`, etc.) et empreinte client, même lorsque le payload reste chiffré. Pour les captures HTTP/2 et HTTP/3 déchiffrées, il est également utile d’ajouter `http2.header.value` ou `http3.headers.header.value` comme colonnes et de pivoter sur les chemins, les autorités et d’autres métadonnées intéressantes.<sup>[[2]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>

```bash
tshark -r capture.pcapng -Y "tls.handshake.type == 1" -T fields \
  -e frame.number -e ip.src -e ip.dst \
  -e tls.handshake.extensions_server_name \
  -e tls.handshake.extensions_alpn_str \
  -e tls.handshake.ja3 -e tls.handshake.ja4
```

### ECH : ne confondez pas le SNI externe avec l’origine

Encrypted ClientHello (ECH) peut placer un nom de couverture public dans le SNI externe visible tout en chiffrant le nom interne. Ainsi, un inventaire des domaines basé uniquement sur le SNI peut attribuer le trafic ECH à la mauvaise origine. La seule présence de l’extension ECH ne prouve pas que ECH a fonctionné : les clients peuvent envoyer une extension ECH GREASE. Sur Wireshark 4.2+, trouvez les offres ECH externes avec le filtre suivant et considérez le SNI indiqué comme un candidat de couverture, et non comme le site demandé.<sup>[[5]](#references)[[8]](#references)</sup>

```bash
tshark -r capture.pcapng \
  -Y 'tls.handshake.type == 1 && tls.ech.client_hello_type == 0' \
  -T fields -e frame.number -e ip.dst \
  -e tls.handshake.extensions_server_name -e tls.ech.config_id
```

Si vous disposez des clés de session client correspondantes, examinez l’autorité HTTP/Host déchiffrée au lieu de déduire l’origine à partir du SNI externe. Sans les clés, recherchez d’autres éléments capturés indiquant l’origine, comme le DNS en clair, mais n’assimilez pas le SNI externe au nom masqué.<sup>[[1]](#references)[[6]](#references)[[7]](#references)[[8]](#references)</sup>

```bash
tshark -r capture.pcapng -o tls.keylog_file:keys.log \
  -Y 'http.host || http2.headers.authority || http3.headers.authority' \
  -T fields -e ip.dst -e http.host \
  -e http2.headers.authority -e http3.headers.authority
```

## Identifier les noms d’hôte locaux

### Depuis DHCP

Dans les versions actuelles de Wireshark, au lieu de `bootp`, vous devez rechercher `DHCP`

![Identifier les noms d’hôte locaux - Depuis DHCP : Dans les versions actuelles de Wireshark, au lieu de bootp, vous devez rechercher DHCP](<../../../images/image (1013).png>)

### Depuis NBNS

![Depuis DHCP - Depuis NBNS : Dans les versions actuelles de Wireshark, au lieu de bootp, vous devez rechercher DHCP](<../../../images/image (1003).png>)

## Déchiffrer TLS

Le déchiffrement de la couche liaison Wi-Fi est distinct du déchiffrement des sessions TLS ; consultez [l’analyse de PCAP Wi-Fi](wifi-pcap-analysis.md) pour connaître les prérequis liés aux clés et à la négociation.

### Déchiffrer le trafic https avec la clé privée du serveur

_modifier > préférences > protocoles > tls >_

![Déchiffrer TLS - Déchiffrer le trafic https avec la clé privée du serveur : Déchiffrer le trafic https avec la clé privée du serveur](<../../../images/image (1103).png>)

Cliquez sur _Modifier_ et ajoutez toutes les données du serveur et de la clé privée (_IP, Port, Protocol, Key file et password_)

Cette méthode ne fonctionne que dans un nombre limité de cas. Pour le trafic TLS 1.3 / ECDHE actuel, la méthode du journal de clés de session ci-dessous est généralement la solution pratique.<sup>[[1]](#references)</sup>

### Déchiffrer le trafic https avec des clés de session symétriques

Firefox et Chrome peuvent tous deux journaliser les clés de session TLS, qui peuvent être utilisées avec Wireshark pour déchiffrer le trafic TLS. Cela permet d’analyser en profondeur les communications sécurisées. Vous trouverez plus de détails sur cette méthode dans un guide de [Red Flag Security](https://redflagsecurity.net/2019/03/10/decrypting-tls-wireshark/).<sup>[[3]](#references)</sup> C’est également la méthode habituelle pour déchiffrer les captures modernes TLS 1.3 et QUIC/HTTP/3.<sup>[[2]](#references)</sup>

Pour détecter cela, recherchez la variable `SSLKEYLOGFILE` dans l’environnement.

Un fichier de clés partagées ressemble à ceci :

![Déchiffrer le trafic https avec la clé privée du serveur - Déchiffrer le trafic https avec des clés de session symétriques : Un fichier de clés partagées ressemble à ceci](<../../../images/image (820).png>)

Si la capture est au format `pcapng`, vérifiez si elle contient déjà des secrets de déchiffrement intégrés avant de fouiller le système de fichiers de l’hôte :<sup>[[1]](#references)</sup>

```bash
editcap --extract-secrets capture.pcapng tls-secrets.txt
```

Pour importer cela dans Wireshark, allez dans \_édition > préférences > protocoles > tls > et importez-le dans le champ Pre-Master-Secret log filename :

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

- [1] [Wiki TLS de Wireshark](https://wiki.wireshark.org/TLS)
- [2] [Déchiffrer et analyser le trafic HTTP/3 dans Wireshark](https://blog.elmo.sg/posts/parsing-decrypted-quic-traffic-in-wireshark/)
- [3] [Déchiffrer le trafic TLS d’un navigateur avec Wireshark – la méthode facile !](https://redflagsecurity.net/2019/03/10/decrypting-tls-wireshark/)
- [4] [Suivre les flux de protocoles](https://www.wireshark.org/docs/wsug_html_chunked/ChAdvFollowStreamSection.html)
- [5] [Référence des filtres d’affichage : Transport Layer Security](https://www.wireshark.org/docs/dfref/t/tls.html)
- [6] [Référence des filtres d’affichage : HyperText Transfer Protocol 2](https://www.wireshark.org/docs/dfref/h/http2.html)
- [7] [Référence des filtres d’affichage : Hypertext Transfer Protocol Version 3](https://www.wireshark.org/docs/dfref/h/http3.html)
- [8] [RFC 9849 : TLS Encrypted Client Hello](https://www.rfc-editor.org/rfc/rfc9849.html)
- [9] [Manuel de TShark](https://www.wireshark.org/docs/man-pages/tshark.html)
{{#include ../../../banners/hacktricks-training.md}}
