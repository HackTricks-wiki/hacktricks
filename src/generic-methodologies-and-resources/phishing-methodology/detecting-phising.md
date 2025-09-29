# Détection du Phishing

{{#include ../../banners/hacktricks-training.md}}

## Introduction

Pour détecter une tentative de phishing, il est important de **comprendre les techniques de phishing utilisées aujourd'hui**. Sur la page parente de ce post, vous pouvez trouver cette information ; si vous n'êtes pas au courant des techniques actuellement utilisées, je vous recommande d'aller sur la page parente et de lire au moins cette section.

Ce post repose sur l'idée que les **attaquants vont essayer d'une manière ou d'une autre de mimer ou d'utiliser le nom de domaine de la victime**. Si votre domaine s'appelle `example.com` et que vous êtes victime d'un phishing en utilisant un nom de domaine complètement différent pour une raison quelconque comme `youwonthelottery.com`, ces techniques ne le découvriront pas.

## Variations de nom de domaine

Il est assez **facile** de **détecter** ces tentatives de **phishing** qui utiliseront un **nom de domaine similaire** à l'intérieur de l'email.\
Il suffit de **générer une liste des noms de phishing les plus probables** qu'un attaquant pourrait utiliser et de **vérifier** s'ils sont **enregistrés** ou simplement vérifier s'il y a une **IP** qui les utilise.

### Trouver des domaines suspects

Pour cela, vous pouvez utiliser n'importe lequel des outils suivants. Notez que ces outils effectueront également automatiquement des requêtes DNS pour vérifier si le domaine a une IP assignée :

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

Astuce : Si vous générez une liste de candidats, alimentez-la également dans vos logs de résolveur DNS pour détecter les recherches **NXDOMAIN depuis l'intérieur de votre organisation** (des utilisateurs essayant d'atteindre une faute de frappe avant que l'attaquant ne l'enregistre réellement). Sinkhole ou pre-block ces domaines si la politique le permet.

### Bitflipping

Vous pouvez trouver une courte explication de cette technique sur la page parente. Ou lisez la recherche originale sur [**https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/**](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

Par exemple, une modification d'1 bit dans le domaine microsoft.com peut le transformer en _windnws.com._\
**Les attaquants peuvent enregistrer autant de domaines bit-flipping que possible liés à la victime pour rediriger les utilisateurs légitimes vers leur infrastructure**.

**Tous les noms de domaine possibles issus du bit-flipping devraient également être surveillés.**

Si vous devez aussi prendre en compte les lookalikes homoglyphes/IDN (par exemple, mélange de caractères Latin/Cyrillique), vérifiez :

{{#ref}}
homograph-attacks.md
{{#endref}}

### Vérifications de base

Une fois que vous avez une liste de noms de domaines potentiellement suspects, vous devriez les **vérifier** (principalement les ports HTTP et HTTPS) pour **voir s'ils utilisent un login form similaire** à celui d'un des domaines de la victime.\
Vous pouvez aussi vérifier le port 3333 pour voir s'il est ouvert et exécute une instance de `gophish`.\
Il est aussi intéressant de savoir **quel âge a chaque domaine suspect découvert** ; plus il est jeune, plus il est risqué.\
Vous pouvez également obtenir des **captures d'écran** de la page HTTP et/ou HTTPS suspecte pour voir si elle est suspecte et, le cas échéant, **y accéder pour l'examiner plus en détail**.

### Vérifications avancées

Si vous voulez aller un cran plus loin, je vous recommande de **surveiller ces domaines suspects et d'en rechercher d'autres** de temps en temps (tous les jours ? ça ne prend que quelques secondes/minutes). Vous devriez aussi **vérifier** les **ports** ouverts des IPs associées et **rechercher des instances de `gophish` ou d'outils similaires** (oui, les attaquants font aussi des erreurs) et **surveiller les pages web HTTP et HTTPS des domaines et sous-domaines suspects** pour voir s'ils ont copié un login form des pages de la victime.\
Pour **automatiser cela**, je recommanderais d'avoir une liste des login forms des domaines de la victime, d'explorer (spider) les pages web suspectes et de comparer chaque login form trouvé dans les domaines suspects avec chaque login form du domaine de la victime en utilisant quelque chose comme `ssdeep`.\
Si vous avez localisé les login forms des domaines suspects, vous pouvez essayer d'**envoyer des credentials bidon** et **vérifier si cela vous redirige vers le domaine de la victime**.

---

### Hunting by favicon and web fingerprints (Shodan/ZoomEye/Censys)

Many phishing kits reuse favicons from the brand they impersonate. Internet-wide scanners compute a MurmurHash3 of the base64-encoded favicon. You can generate the hash and pivot on it:

Exemple Python (mmh3):
```python
import base64, requests, mmh3
url = "https://www.paypal.com/favicon.ico"  # change to your brand icon
b64 = base64.encodebytes(requests.get(url, timeout=10).content)
print(mmh3.hash(b64))  # e.g., 309020573
```
- Interroger Shodan: `http.favicon.hash:309020573`
- Avec des outils : regardez des outils communautaires comme favfreak pour générer des hashes et des dorks pour Shodan/ZoomEye/Censys.

Remarques
- Les favicons sont réutilisés ; considérez les correspondances comme des pistes et validez le contenu et les certs avant d'agir.
- Combinez avec domain-age et des heuristiques par mot-clé pour une meilleure précision.

### Recherche de télémétrie d'URL (urlscan.io)

`urlscan.io` stocke des captures d'écran historiques, le DOM, les requêtes et les métadonnées TLS des URLs soumises. Vous pouvez chasser l'usurpation de marque et les clones :

Exemples de requêtes (UI ou API):
- Trouver des sites ressemblants en excluant vos domaines légitimes : `page.domain:(/.*yourbrand.*/ AND NOT yourbrand.com AND NOT www.yourbrand.com)`
- Trouver des sites hotlinkant vos ressources : `domain:yourbrand.com AND NOT page.domain:yourbrand.com`
- Restreindre aux résultats récents : ajouter `AND date:>now-7d`

Exemple d'API:
```bash
# Search recent scans mentioning your brand
curl -s 'https://urlscan.io/api/v1/search/?q=page.domain:(/.*yourbrand.*/%20AND%20NOT%20yourbrand.com)%20AND%20date:>now-7d' \
-H 'API-Key: <YOUR_URLSCAN_KEY>' | jq '.results[].page.url'
```
Dans le JSON, pivoter sur :
- `page.tlsIssuer`, `page.tlsValidFrom`, `page.tlsAgeDays` pour repérer les certificats très récents utilisés par des lookalikes
- `task.source` valeurs comme `certstream-suspicious` pour associer les découvertes à la surveillance CT

### Âge du domaine via RDAP (scriptable)

RDAP renvoie des événements de création lisibles par machine. Utile pour repérer les **domaines nouvellement enregistrés (NRDs)**.
```bash
# .com/.net RDAP (Verisign)
curl -s https://rdap.verisign.com/com/v1/domain/suspicious-example.com | \
jq -r '.events[] | select(.eventAction=="registration") | .eventDate'

# Generic helper using rdap.net redirector
curl -s https://www.rdap.net/domain/suspicious-example.com | jq
```
Enrichissez votre pipeline en étiquetant les domaines selon des tranches d'âge d'enregistrement (par ex. <7 jours, <30 jours) et priorisez le triage en conséquence.

### Empreintes TLS/JAx pour repérer l'infrastructure AiTM

Le credential-phishing moderne utilise de plus en plus des reverse proxies Adversary-in-the-Middle (AiTM) (par ex. Evilginx) pour voler des session tokens. Vous pouvez ajouter des détections côté réseau :

- Enregistrez les empreintes TLS/HTTP (JA3/JA4/JA4S/JA4H) à l'egress. Certaines builds d'Evilginx ont été observées avec des valeurs JA4 client/server stables. Alarmez sur des empreintes known-bad uniquement comme signal faible et confirmez toujours avec le contenu et le renseignement sur le domaine.
- Enregistrez de manière proactive les métadonnées des certificats TLS (issuer, nombre de SAN, usage de wildcard, validité) pour les hôtes lookalike découverts via CT ou urlscan et corrélez avec l'âge DNS et la géolocalisation.

> Note : Traitez les empreintes comme enrichissement, pas comme unique critère de blocage ; les frameworks évoluent et peuvent randomiser ou obfusquer.

### Domain names using keywords

La page parente mentionne aussi une technique de variation de nom de domaine consistant à insérer le **nom de domaine de la victime à l'intérieur d'un domaine plus grand** (par ex. paypal-financial.com pour paypal.com).

#### Certificate Transparency

Il n'est pas possible d'appliquer l'approche "Brute-Force" précédente mais il est en réalité **possible de déceler de telles tentatives de phishing** aussi grâce à la certificate transparency. Chaque fois qu'un certificat est émis par une CA, les détails sont rendus publics. Cela signifie qu'en lisant la certificate transparency ou même en la surveillant, il est **possible de trouver des domaines qui utilisent un mot-clé à l'intérieur de leur nom**. Par exemple, si un attaquant génère un certificat pour [https://paypal-financial.com](https://paypal-financial.com), en voyant le certificat il est possible de trouver le mot-clé "paypal" et de savoir qu'un domaine suspect est utilisé.

Le post [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/) suggère d'utiliser Censys pour rechercher des certificats contenant un mot-clé précis et filtrer par date (seulement les certificats "new") et par CA issuer "Let's Encrypt":

![https://0xpatrik.com/content/images/2018/07/cert_listing.png](<../../images/image (1115).png>)

Cependant, vous pouvez faire "la même chose" en utilisant le service web gratuit [**crt.sh**](https://crt.sh). Vous pouvez **rechercher le mot-clé** et **filtrer** les résultats **par date et par CA** si vous le souhaitez.

![](<../../images/image (519).png>)

Avec cette dernière option, vous pouvez même utiliser le champ Matching Identities pour voir si une identité du domaine réel correspond à l'un des domaines suspects (notez qu'un domaine suspect peut être un faux positif).

**Une autre alternative** est le projet fantastique [**CertStream**](https://medium.com/cali-dog-security/introducing-certstream-3fc13bb98067). CertStream fournit un flux en temps réel des certificats nouvellement générés que vous pouvez utiliser pour détecter des mots-clés en (quasi) temps réel. En fait, il existe un projet appelé [**phishing_catcher**](https://github.com/x0rz/phishing_catcher) qui fait exactement cela.

Conseil pratique : lors du triage des hits CT, priorisez les NRDs, les registrars non fiables/inconnus, les WHOIS en privacy-proxy, et les certs avec des temps `NotBefore` très récents. Maintenez une allowlist de vos domaines/marques possédés pour réduire le bruit.

#### **New domains**

**Une dernière alternative** est de rassembler une liste de **domaines nouvellement enregistrés** pour certains TLDs ([Whoxy](https://www.whoxy.com/newly-registered-domains/) fournit ce service) et **vérifier la présence de mots-clés dans ces domaines**. Cependant, les domaines longs utilisent souvent un ou plusieurs sous-domaines ; par conséquent le mot-clé n'apparaîtra pas dans le FLD et vous ne pourrez pas trouver le sous-domaine de phishing.

Heuristique additionnelle : traitez certains **file-extension TLDs** (par ex. `.zip`, `.mov`) avec une suspicion accrue dans les alertes. Ceux-ci sont souvent confondus avec des noms de fichiers dans les leurres ; combinez le signal TLD avec des brand keywords et l'âge NRD pour une meilleure précision.

## References

- urlscan.io – Référence de l'API Search: https://urlscan.io/docs/search/
- APNIC Blog – JA4+ network fingerprinting (includes Evilginx example): https://blog.apnic.net/2023/11/22/ja4-network-fingerprinting/

{{#include ../../banners/hacktricks-training.md}}
