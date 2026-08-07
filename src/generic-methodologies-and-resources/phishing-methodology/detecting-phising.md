# Détecter le Phishing

{{#include ../../banners/hacktricks-training.md}}

## Introduction

Pour détecter une tentative de phishing, il est important de **comprendre les techniques de phishing utilisées de nos jours**. Sur la page parent de cet article, vous trouverez ces informations. Si vous ne savez pas quelles techniques sont utilisées actuellement, je vous recommande de consulter la page parent et de lire au moins cette section.

Cet article repose sur l'idée que les **attaquants tenteront d'une manière ou d'une autre d'imiter ou d'utiliser le nom de domaine de la victime**. Si votre domaine s'appelle `example.com` et que vous êtes victime de phishing via un nom de domaine complètement différent, pour une raison quelconque, comme `youwonthelottery.com`, ces techniques ne permettront pas de le découvrir.

## Variations des noms de domaine

Il est assez **facile de **détecter** les tentatives de **phishing** qui utilisent un nom de **domaine similaire** dans l'e-mail.\
Il suffit de **générer une liste des noms de phishing les plus probables** qu'un attaquant pourrait utiliser et de **vérifier** s'ils sont **enregistrés**, ou simplement de vérifier si une **IP** les utilise.

### Recherche de domaines suspects

À cette fin, vous pouvez utiliser l'un des outils suivants. Notez que ces outils effectueront également automatiquement des requêtes DNS pour vérifier si le domaine possède une IP attribuée :

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

Conseil : Si vous générez une liste de candidats, transmettez-la également à vos journaux de résolution DNS afin de détecter les **recherches NXDOMAIN effectuées depuis votre organisation** (des utilisateurs tentent d'accéder à une faute de frappe avant que l'attaquant ne l'enregistre réellement). Mettez ces domaines en sinkhole ou bloquez-les préventivement si la politique l'autorise.

### Bitflipping

**Vous trouverez une brève explication de cette technique sur la page parent. Vous pouvez également consulter la recherche originale à l'adresse** [**https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/**](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)<sup>[[1]](#references)</sup>

Par exemple, la modification d'un seul bit dans le domaine microsoft.com peut le transformer en _windnws.com._\
**Les attaquants peuvent enregistrer autant de domaines issus du bit-flipping que possible et liés à la victime afin de rediriger les utilisateurs légitimes vers leur infrastructure**.<sup>[[1]](#references)</sup>

**Tous les noms de domaine possibles issus du bit-flipping doivent également être surveillés.**

Si vous devez également prendre en compte les homoglyphes/équivalents visuels IDN (par exemple, le mélange de caractères latins et cyrilliques), consultez :

{{#ref}}
homograph-attacks.md
{{#endref}}

### Vérifications de base

Une fois que vous disposez d'une liste de noms de domaine potentiellement suspects, vous devez les **vérifier** (principalement sur les ports HTTP et HTTPS) afin de **voir s'ils utilisent un formulaire de connexion similaire** à celui du domaine de la victime.\
Vous pouvez également vérifier le port 3333 pour voir s'il est ouvert et qu'une instance de `gophish` y est exécutée.\
Il est également intéressant de savoir **depuis combien de temps chaque domaine suspect découvert existe** : plus il est récent, plus le risque est élevé.\
Vous pouvez aussi obtenir des **captures d'écran** des pages web HTTP et/ou HTTPS suspectes afin de voir si elles sont suspectes et, le cas échéant, **d'y accéder pour les examiner plus en détail**.

### Vérifications avancées

Si vous souhaitez aller plus loin, je vous recommande de **surveiller ces domaines suspects et d'en rechercher d'autres** de temps à autre (chaque jour ? Cela ne prend que quelques secondes ou minutes). Vous devriez également **vérifier** les **ports** ouverts des IP associées et **rechercher des instances de `gophish` ou d'outils similaires** (oui, les attaquants font eux aussi des erreurs), ainsi que **surveiller les pages web HTTP et HTTPS des domaines et sous-domaines suspects** afin de voir s'ils ont copié un formulaire de connexion depuis les pages web de la victime.\
Pour **automatiser cela**, je vous recommande de disposer d'une liste des formulaires de connexion des domaines de la victime, d'explorer les pages web suspectes et de comparer chaque formulaire de connexion trouvé sur les domaines suspects avec chaque formulaire de connexion du domaine de la victime à l'aide d'un outil comme `ssdeep`.\
Si vous avez localisé les formulaires de connexion des domaines suspects, vous pouvez essayer **d'envoyer des identifiants factices** et de **vérifier s'ils vous redirigent vers le domaine de la victime**.

---

### Recherche par favicon et empreintes web (Shodan/ZoomEye/Censys)

De nombreux kits de phishing réutilisent les favicons de la marque qu'ils usurpent. Les scanners couvrant tout Internet calculent un MurmurHash3 du favicon encodé en base64. Vous pouvez générer le hash et effectuer un pivot dessus :

Exemple Python (mmh3) :
```python
import base64, requests, mmh3
url = "https://www.paypal.com/favicon.ico"  # change to your brand icon
b64 = base64.encodebytes(requests.get(url, timeout=10).content)
print(mmh3.hash(b64))  # e.g., 309020573
```
- Interroger Shodan : `http.favicon.hash:309020573`
- Avec des outils : consultez des outils communautaires comme favfreak pour générer des hashes et des dorks pour Shodan/ZoomEye/Censys.

Notes
- Les favicons sont réutilisés ; considérez les correspondances comme des pistes et validez le contenu et les certificats avant d'agir.
- Combinez-les avec l'âge du domaine et des heuristiques basées sur les mots-clés pour une meilleure précision.

### Recherche de télémétrie d'URL (urlscan.io)

`urlscan.io` stocke les captures d'écran historiques, le DOM, les requêtes et les métadonnées TLS des URL soumises. Vous pouvez rechercher les abus de marque et les clones :<sup>[[2]](#references)</sup>

Exemples de requêtes (interface ou API) :
- Trouver les sites similaires en excluant vos domaines légitimes : `page.domain:(/.*yourbrand.*/ AND NOT yourbrand.com AND NOT www.yourbrand.com)`
- Trouver les sites qui utilisent vos ressources en hotlinking : `domain:yourbrand.com AND NOT page.domain:yourbrand.com`
- Limiter aux résultats récents : ajoutez `AND date:>now-7d`

Exemple d'API :
```bash
# Search recent scans mentioning your brand
curl -s 'https://urlscan.io/api/v1/search/?q=page.domain:(/.*yourbrand.*/%20AND%20NOT%20yourbrand.com)%20AND%20date:>now-7d' \
-H 'API-Key: <YOUR_URLSCAN_KEY>' | jq '.results[].page.url'
```
Depuis le JSON, utilisez les champs suivants pour repérer les certificats très récents associés à des domaines ressemblants :
- `page.tlsIssuer`, `page.tlsValidFrom`, `page.tlsAgeDays`
- les valeurs de `task.source` comme `certstream-suspicious` pour relier les résultats à la surveillance CT

### Âge du domaine via RDAP (scriptable)

RDAP renvoie des événements de création lisibles par machine. Utile pour signaler les **domaines nouvellement enregistrés (NRDs)**.
```bash
# .com/.net RDAP (Verisign)
curl -s https://rdap.verisign.com/com/v1/domain/suspicious-example.com | \
jq -r '.events[] | select(.eventAction=="registration") | .eventDate'

# Generic helper using rdap.net redirector
curl -s https://www.rdap.net/domain/suspicious-example.com | jq
```
Enrichissez votre pipeline en associant aux domaines des catégories d'ancienneté d'enregistrement (par exemple, <7 jours, <30 jours) et donnez-leur la priorité en conséquence lors du triage.

### Empreintes TLS/JAx pour repérer l'infrastructure AiTM

Le credential-phishing moderne utilise de plus en plus des reverse proxies **Adversary-in-the-Middle (AiTM)** (par exemple, Evilginx) pour voler des jetons de session. Vous pouvez ajouter des détections côté réseau :

- Journalisez les empreintes TLS/HTTP (JA3/JA4/JA4S/JA4H) en sortie. Certaines versions d'Evilginx ont été observées avec des valeurs client/serveur JA4 stables. Déclenchez une alerte uniquement sur les empreintes connues comme malveillantes, car il s'agit d'un signal faible, et confirmez toujours avec le contenu et les renseignements sur le domaine.<sup>[[3]](#references)</sup>
- Enregistrez proactivement les métadonnées des certificats TLS (émetteur, nombre de SAN, utilisation de wildcards, validité) pour les hôtes ressemblants découverts via CT ou urlscan, puis corrélez-les avec l'ancienneté du DNS et la géolocalisation.

> Remarque : considérez les empreintes comme un enrichissement, et non comme des bloqueurs uniques ; les frameworks évoluent et peuvent randomiser ou obfusquer ces éléments.

### Noms de domaine utilisant des mots-clés

La page parente mentionne également une technique de variation de nom de domaine qui consiste à placer le **nom de domaine de la victime à l'intérieur d'un domaine plus grand** (par exemple, paypal-financial.com pour paypal.com).

#### Certificate Transparency

Il n'est pas possible d'adopter l'approche précédente par "Brute-Force", mais il est effectivement **possible de découvrir également de telles tentatives de phishing** grâce à la certificate transparency. Chaque fois qu'un certificat est émis par une CA, ses détails sont rendus publics. Cela signifie qu'en consultant ou même en surveillant la certificate transparency, il est **possible de trouver des domaines qui utilisent un mot-clé dans leur nom**. Par exemple, si un attaquant génère un certificat pour [https://paypal-financial.com](https://paypal-financial.com), l'examen du certificat permet de trouver le mot-clé "paypal" et de savoir qu'un email suspect est utilisé.

L'article [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/) suggère d'utiliser Censys pour rechercher les certificats associés à un mot-clé spécifique et de filtrer par date (uniquement les certificats "new") et par l'émetteur de la CA "Let's Encrypt":<sup>[[4]](#references)</sup>

![https://0xpatrik.com/content/images/2018/07/cert_listing.png](<../../images/image (1115).png>)

Cependant, vous pouvez faire "la même chose" avec le site web gratuit [**crt.sh**](https://crt.sh). Vous pouvez **rechercher le mot-clé** et **filtrer** les résultats **par date et par CA**, si vous le souhaitez.

![Noms de domaine utilisant des mots-clés - Certificate Transparency : Cependant, vous pouvez faire "la même chose" avec le site web gratuit crt.sh . Vous pouvez rechercher le mot-clé et filtrer les résultats par date et...](<../../images/image (519).png>)

Avec cette dernière option, vous pouvez même utiliser le champ Matching Identities pour vérifier si une identité du domaine réel correspond à l'un des domaines suspects (notez qu'un domaine suspect peut être un faux positif).

**Une autre alternative** est le remarquable projet appelé [**CertStream**](https://medium.com/cali-dog-security/introducing-certstream-3fc13bb98067). CertStream fournit un flux en temps réel des certificats nouvellement générés, que vous pouvez utiliser pour détecter des mots-clés spécifiés en temps (presque) réel. En fait, un projet appelé [**phishing_catcher**](https://github.com/x0rz/phishing_catcher) fait exactement cela.

Conseil pratique : lors du triage des résultats CT, donnez la priorité aux NRD, aux bureaux d'enregistrement non approuvés ou inconnus, aux WHOIS utilisant un privacy-proxy et aux certificats dont les heures `NotBefore` sont très récentes. Maintenez une allowlist de vos domaines et marques détenus afin de réduire le bruit.

#### **Nouveaux domaines**

**Une dernière alternative** consiste à recueillir une liste de **domaines nouvellement enregistrés** pour certains TLD ([Whoxy](https://www.whoxy.com/newly-registered-domains/) fournit ce service) et à **vérifier les mots-clés dans ces domaines**. Cependant, les domaines longs utilisent généralement un ou plusieurs sous-domaines ; le mot-clé n'apparaîtra donc pas dans le FLD et vous ne pourrez pas trouver le sous-domaine de phishing.

Heuristique supplémentaire : traitez certains **TLD correspondant à des extensions de fichiers** (par exemple, `.zip`, `.mov`) avec une suspicion accrue dans les alertes. Ils sont souvent confondus avec des noms de fichiers dans les leurres ; combinez le signal du TLD avec les mots-clés de marque et l'ancienneté du NRD pour améliorer la précision.

## References

- [1] [Hijacking traffic to Microsoft's windows.com with bitflipping](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)
- [2] [urlscan.io – Search API Reference](https://urlscan.io/docs/search/)
- [3] [APNIC Blog – JA4+ network fingerprinting](https://blog.apnic.net/2023/11/22/ja4-network-fingerprinting/)
- [4] [Finding Phishing: Tools and Techniques](https://0xpatrik.com/phishing-domains/)

{{#include ../../banners/hacktricks-training.md}}
