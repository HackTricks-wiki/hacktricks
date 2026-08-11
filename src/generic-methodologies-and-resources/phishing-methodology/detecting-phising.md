# Détection du phishing

{{#include ../../banners/hacktricks-training.md}}

## Introduction

Pour détecter une tentative de phishing, il est important de **comprendre les techniques de phishing utilisées כיום**. Sur la page parente de cet article, vous trouverez ces informations. Si vous ne connaissez pas les techniques utilisées כיום, je vous recommande de consulter la page parente et de lire au moins cette section.

Cet article repose sur l'idée que les **attaquants essaieront d'une manière ou d'une autre d'imiter ou d'utiliser le nom de domaine de la victime**. Si votre domaine s'appelle `example.com` et que vous êtes victime de phishing via un nom de domaine complètement différent, pour une raison quelconque, comme `youwonthelottery.com`, ces techniques ne permettront pas de le découvrir.

## Variations des noms de domaine

Il est assez **facile de **détecter** les tentatives de **phishing** qui utilisent un nom de domaine **similaire** dans l'e-mail.\
Il suffit de **générer une liste des noms de phishing les plus probables** qu'un attaquant pourrait utiliser et de **vérifier** s'ils sont **enregistrés**, ou simplement de vérifier si une **IP** les utilise.

### Recherche de domaines suspects

À cette fin, vous pouvez utiliser l'un des outils suivants. Les deux résolvent les domaines candidats afin de vérifier s'ils sont utilisés.<sup>[[3]](#references)[[4]](#references)</sup>

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

Conseil : si vous générez une liste de candidats, injectez-la également dans vos journaux de résolution DNS afin de détecter les **requêtes NXDOMAIN provenant de l'intérieur de votre organisation** (des utilisateurs essayant d'accéder à une faute de frappe avant que l'attaquant ne l'enregistre réellement). Redirigez ces domaines vers un sinkhole ou bloquez-les préventivement si la politique l'autorise.

### Bitflipping

**Pour une brève explication, consultez la page parente ; pour les recherches originales sur le bitsquatting de Windows.com, consultez l'[article de Remy Hax](https://remyhax.xyz/posts/bitsquatting-windows/) et le [rapport de BleepingComputer](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)**.<sup>[[1]](#references)[[2]](#references)</sup>

Par exemple, la modification d'un seul bit dans le domaine microsoft.com peut le transformer en _windnws.com._\
**Les attaquants peuvent enregistrer autant de domaines bit-flipping que possible liés à la victime afin de rediriger les utilisateurs légitimes vers leur infrastructure**.<sup>[[1]](#references)[[2]](#references)</sup>

**Tous les noms de domaine possibles issus du bit-flipping doivent également être surveillés.**

Si vous devez également prendre en compte les homoglyphes et les sosies IDN (par exemple, le mélange de caractères latins et cyrilliques), consultez :

{{#ref}}
homograph-attacks.md
{{#endref}}

### Vérifications de base

Une fois que vous disposez d'une liste de noms de domaine potentiellement suspects, vous devez les **vérifier** (principalement les ports HTTP et HTTPS) afin de **voir s'ils utilisent un formulaire de connexion similaire** à celui d'un domaine de la victime.\
Vous pouvez également vérifier le port 3333 pour voir s'il est ouvert et exécute une instance de `gophish`.\
Il est également intéressant de connaître **l'ancienneté de chaque domaine suspect découvert** : plus il est récent, plus le risque est élevé.\
Vous pouvez aussi obtenir des **captures d'écran** de la page web HTTP et/ou HTTPS suspecte afin de voir si elle est effectivement suspecte et, le cas échéant, **y accéder pour l'examiner plus en détail**.

### Vérifications avancées

Si vous souhaitez aller plus loin, je vous recommande de **surveiller ces domaines suspects et d'en rechercher d'autres** de temps en temps (chaque jour ? Cela ne prend que quelques secondes ou minutes). Vous devez également **vérifier** les **ports** ouverts des IP associées et **rechercher des instances de `gophish` ou d'outils similaires** (oui, les attaquants font aussi des erreurs), ainsi que **surveiller les pages web HTTP et HTTPS des domaines et sous-domaines suspects** afin de vérifier si elles ont copié un formulaire de connexion des pages web de la victime.\
Pour **automatiser cela**, je vous recommande de disposer d'une liste des formulaires de connexion des domaines de la victime, d'explorer les pages web suspectes et de comparer chaque formulaire de connexion trouvé sur les domaines suspects avec chaque formulaire de connexion du domaine de la victime, à l'aide d'un outil comme `ssdeep`.\
Si vous avez localisé les formulaires de connexion des domaines suspects, vous pouvez essayer d'**envoyer des identifiants factices** et de **vérifier si vous êtes redirigé vers le domaine de la victime**.

---

### Recherche à l'aide des favicons et des empreintes web (Shodan/Censys)

De nombreux kits de phishing réutilisent les favicons de la marque qu'ils usurpent. Shodan calcule le hash des données du favicon encodées en base64 avec MurmurHash3, tandis que Censys expose ses propres champs de hash de favicon.<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup> Vous pouvez générer un hash compatible avec Shodan et effectuer une recherche pivot à partir de celui-ci :

Exemple Python (mmh3) :
```python
import base64, requests, mmh3
url = "https://www.paypal.com/favicon.ico"  # change to your brand icon
b64 = base64.encodebytes(requests.get(url, timeout=10).content)
print(mmh3.hash(b64))  # e.g., 309020573
```
- Interroger Shodan : `http.favicon.hash:309020573`
- Avec des outils : examinez des outils communautaires comme favfreak pour calculer des hashes et générer des dorks Shodan.<sup>[[16]](#references)</sup>

Remarques
- Les favicons sont réutilisés ; considérez les correspondances comme des pistes et validez le contenu et les certificats avant d'agir.
- Combinez-les avec l'ancienneté du domaine et des heuristiques basées sur les mots-clés pour améliorer la précision.

### Recherche de télémétrie d'URL (urlscan.io)

`urlscan.io` stocke les captures d'écran historiques, le DOM, les requêtes et les métadonnées TLS des URL soumises. Vous pouvez rechercher les abus de marque et les clones :<sup>[[8]](#references)</sup>

Exemples de requêtes (interface ou API) :
- Trouver les sites ressemblants en excluant vos domaines légitimes : `page.domain:(/.*yourbrand.*/ AND NOT yourbrand.com AND NOT www.yourbrand.com)`
- Trouver les sites qui intègrent vos ressources : `domain:yourbrand.com AND NOT page.domain:yourbrand.com`
- Limiter aux résultats récents : ajoutez `AND date:>now-7d`

Exemple d'API :
```bash
# Search recent scans mentioning your brand
curl -s 'https://urlscan.io/api/v1/search/?q=page.domain:(/.*yourbrand.*/%20AND%20NOT%20yourbrand.com)%20AND%20date:>now-7d' \
-H 'API-Key: <YOUR_URLSCAN_KEY>' | jq '.results[].page.url'
```
Depuis le JSON, pivotez sur :
- `page.tlsIssuer`, `page.tlsValidFrom`, `page.tlsAgeDays` pour repérer les certificats très récents associés à des lookalikes
- les valeurs de `task.source` telles que `certstream-suspicious` pour relier les résultats à la surveillance CT

### Âge du domaine via RDAP (scriptable)

RDAP renvoie des événements d’enregistrement lisibles par machine. Utile pour signaler les **domaines récemment enregistrés (NRD)**.<sup>[[9]](#references)[[10]](#references)</sup>
```bash
# .com/.net RDAP (Verisign)
curl -s https://rdap.verisign.com/com/v1/domain/suspicious-example.com | \
jq -r '.events[] | select(.eventAction=="registration") | .eventDate'

# Generic helper using rdap.net redirector
curl -s https://www.rdap.net/domain/suspicious-example.com | jq
```
Enrichissez votre pipeline en classant les domaines selon des tranches d'ancienneté d'enregistrement (par exemple, <7 jours, <30 jours) et priorisez le triage en conséquence.

### Empreintes TLS/JAx pour repérer une infrastructure AiTM

Le phishing de credentials peut utiliser des reverse proxies **Adversary-in-the-Middle (AiTM)** (par exemple, Evilginx) pour voler des session tokens.<sup>[[11]](#references)</sup> Vous pouvez ajouter des détections côté réseau :

- Consignez les empreintes TLS/HTTP (JA3/JA4/JA4S/JA4H) en sortie. Certaines versions d'Evilginx ont été observées avec des valeurs client/serveur JA4 stables. Déclenchez une alerte sur les empreintes connues comme malveillantes uniquement comme signal faible et confirmez toujours avec le contenu et les informations sur le domaine.<sup>[[12]](#references)</sup>
- Enregistrez de manière proactive les métadonnées des certificats TLS (émetteur, nombre de SAN, utilisation de wildcards, validité) pour les hosts ressemblant à votre domaine, découverts via CT ou urlscan, puis corrélez-les avec l'ancienneté du DNS et la géolocalisation.

> Remarque : considérez les empreintes comme un enrichissement, et non comme des bloqueurs uniques ; les frameworks évoluent et peuvent randomiser ou obfusquer ces empreintes.

### Noms de domaine utilisant des keywords

La page parente mentionne également une technique de variation de nom de domaine qui consiste à placer le **nom de domaine de la victime dans un domaine plus grand** (par exemple, paypal-financial.com pour paypal.com).

#### Certificate Transparency

Les logs de Certificate Transparency (CT) exposent les identités des certificats ; rechercher des keywords de marque dans les noms Subject ou SAN peut révéler des domaines ressemblants (par exemple, un certificat pour `paypal-financial.com` expose le keyword `paypal`). Filtrez les résultats par date d'émission et par CA lorsque cela est utile, puis validez les candidats, car les correspondances de keywords peuvent être des faux positifs.<sup>[[13]](#references)</sup>

Le [write-up original de Patrik Hudak sur la recherche de domaines de phishing](https://0xpatrik.com/phishing-domains/) présente ce workflow dans Censys, avec notamment des filtres sur la date du certificat et l'émetteur, comme Let's Encrypt.<sup>[[13]](#references)</sup>

![Résultats de recherche de certificats Censys utilisés pour identifier des domaines ressemblants](<../../images/image (1115).png>)

Vous pouvez également utiliser le service gratuit [**crt.sh**](https://crt.sh) pour rechercher un keyword et filtrer les résultats par date et par CA.<sup>[[13]](#references)</sup>

![Recherche par keyword dans crt.sh pour identifier des identités de certificats suspectes](<../../images/image (519).png>)

Son champ Matching Identities peut aider à comparer les identités du domaine réel avec celles de domaines suspects, mais considérez les correspondances comme des pistes plutôt que comme des preuves.<sup>[[13]](#references)</sup>

[*CertStream*](https://medium.com/cali-dog-security/introducing-certstream-3fc13bb98067) diffuse les mises à jour CT en quasi-temps réel, et [*phishing_catcher*](https://github.com/x0rz/phishing_catcher) consomme ce flux pour attribuer un score aux noms de certificats suspects.<sup>[[14]](#references)[[15]](#references)</sup>

Conseil pratique : lors du triage des résultats CT, donnez la priorité aux NRD, aux registrars non approuvés ou inconnus, aux WHOIS utilisant un privacy-proxy et aux certificats dont les valeurs `NotBefore` sont très récentes. Maintenez une allowlist de vos domaines/marques détenus afin de réduire le bruit.

#### **Nouveaux domaines**

Une seconde option consiste à collecter les domaines nouvellement enregistrés par TLD (par exemple, via [Whoxy](https://www.whoxy.com/newly-registered-domains/)) et à filtrer les résultats selon des keywords de marque. Cette méthode ne détecte pas le phishing hébergé sur des subdomains lorsque le keyword est absent du domaine enregistré.<sup>[[13]](#references)</sup>

Heuristique supplémentaire : traitez certains **TLD correspondant à des extensions de fichiers** (par exemple, `.zip`, `.mov`) avec une suspicion accrue dans les alertes. Ils sont souvent confondus avec des noms de fichiers dans les leurres ; combinez le signal du TLD avec les keywords de marque et l'ancienneté du NRD pour améliorer la précision.

## References

- [1] [Remy Hax – Bitsquatting Windows.com](https://remyhax.xyz/posts/bitsquatting-windows/)
- [2] [Détournement du trafic vers le windows.com de Microsoft avec du bitflipping](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)
- [3] [dnstwist](https://github.com/elceef/dnstwist)
- [4] [urlcrazy](https://github.com/urbanadventurer/urlcrazy)
- [5] [Analyse approfondie : http.favicon](https://blog.shodan.io/deep-dive-http-favicon/)
- [6] [Documentation de mmh3](https://mmh3.readthedocs.io/en/stable/quickstart.html)
- [7] [Jeu de données des propriétés Web de la plateforme](https://docs.censys.com/docs/platform-web-property-dataset)
- [8] [urlscan.io – Référence de l'API Search](https://urlscan.io/docs/search/)
- [9] [Aide du Registration Data Access Protocol](https://www.verisign.com/news-insights/registration-data-access-protocol/help/)
- [10] [RFC 9083 : réponses JSON pour le Registration Data Access Protocol](https://www.rfc-editor.org/rfc/rfc9083.html)
- [11] [Tactiques liées aux tokens : comment prévenir, détecter et traiter le vol de cloud tokens](https://www.microsoft.com/en-us/security/blog/2022/11/16/token-tactics-how-to-prevent-detect-and-respond-to-cloud-token-theft/)
- [12] [APNIC Blog – Empreintes réseau JA4+](https://blog.apnic.net/2023/11/22/ja4-network-fingerprinting/)
- [13] [Patrik Hudak – Identifier le phishing : outils et techniques](https://0xpatrik.com/phishing-domains/)
- [14] [Ryan Sears – Présentation de CertStream](https://medium.com/cali-dog-security/introducing-certstream-3fc13bb98067)
- [15] [x0rz – Phishing Catcher](https://github.com/x0rz/phishing_catcher)
- [16] [Devansh Batham – FavFreak](https://github.com/devanshbatham/FavFreak)
{{#include ../../banners/hacktricks-training.md}}
