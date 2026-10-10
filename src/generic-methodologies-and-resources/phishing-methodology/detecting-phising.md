# Détection du phishing

{{#include ../../banners/hacktricks-training.md}}

## Introduction

Pour détecter une tentative de phishing, il est important de **comprendre les techniques de phishing utilisées aujourd’hui**. Vous trouverez ces informations sur la page parente de cet article. Si vous ne connaissez pas les techniques utilisées actuellement, je vous recommande de consulter la page parente et de lire au moins cette section.

Cet article part du principe que les **attaquants essaieront d’une manière ou d’une autre d’imiter ou d’utiliser le nom de domaine de la victime**. Si votre domaine est `example.com` et que vous êtes victime d’une tentative de phishing utilisant un nom de domaine complètement différent, comme `youwonthelottery.com`, ces techniques ne permettront pas de la détecter.

## Variations de noms de domaine

Il est assez **facile** de **détecter** les tentatives de **phishing** qui utilisent un **nom de domaine similaire** dans l’e-mail.\
Il suffit de **générer une liste des noms de phishing les plus probables** qu’un attaquant pourrait utiliser et de **vérifier** s’ils sont **enregistrés**, ou simplement de vérifier si une **IP** les utilise.

### Recherche de domaines suspects

À cette fin, vous pouvez utiliser l’un des outils suivants. Ils résolvent tous deux les domaines candidats pour vérifier s’ils sont utilisés.<sup>[[3]](#references)[[4]](#references)</sup>

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

Conseil : si vous générez une liste de domaines candidats, analysez-la également à l’aide des journaux de votre résolveur DNS afin de détecter les **requêtes NXDOMAIN provenant de votre organisation** (des utilisateurs qui essaient d’accéder à une faute de frappe avant que l’attaquant n’enregistre réellement le domaine). Mettez ces domaines en sinkhole ou bloquez-les à l’avance si la politique le permet.

### Bitflipping

**Pour une brève explication, consultez la page parente ; pour les recherches originales sur le bitsquatting de Windows.com, consultez [l’article de Remy Hax](https://remyhax.xyz/posts/bitsquatting-windows/) et [le rapport de BleepingComputer](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)**.<sup>[[1]](#references)[[2]](#references)</sup>

Par exemple, une modification d’un seul bit dans le domaine microsoft.com peut le transformer en _windnws.com._\
**Les attaquants peuvent enregistrer autant de domaines issus du bit-flipping que possible, en lien avec la victime, afin de rediriger les utilisateurs légitimes vers leur infrastructure**.<sup>[[1]](#references)[[2]](#references)</sup>

**Tous les noms de domaine possibles issus du bit-flipping doivent également être surveillés.**

Si vous devez également tenir compte des imitations par homoglyphes/IDN (par exemple, le mélange de caractères latins et cyrilliques), consultez :

{{#ref}}
homograph-attacks.md
{{#endref}}

### Vérifications de base

Une fois que vous disposez d’une liste de noms de domaine potentiellement suspects, vous devriez les **vérifier** (principalement sur les ports HTTP et HTTPS) pour **voir s’ils utilisent un formulaire de connexion similaire à celui d’un domaine de la victime**.\
Vous pouvez également vérifier si le port 3333 est ouvert et héberge une instance de `gophish`.\
Il est également intéressant de connaître **l’ancienneté de chaque domaine suspect découvert** : plus il est récent, plus le risque est élevé.\
Vous pouvez aussi prendre des **captures d’écran** des pages web suspectes en HTTP et/ou HTTPS afin de voir si elles semblent suspectes et, le cas échéant, **y accéder pour les examiner plus en détail**.

### Vérifications avancées

Pour aller plus loin, je vous recommande de **surveiller ces domaines suspects et d’en rechercher d’autres** de temps en temps (tous les jours ? Cela ne prend que quelques secondes ou minutes). Vous devriez également **vérifier** les **ports** ouverts des IP associées et **rechercher des instances de `gophish` ou d’outils similaires** (oui, les attaquants font aussi des erreurs), ainsi que **surveiller les pages web HTTP et HTTPS des domaines et sous-domaines suspects** pour voir s’ils ont copié un formulaire de connexion des pages web de la victime.\
Pour **automatiser cela**, je vous recommande de disposer d’une liste des formulaires de connexion des domaines de la victime, d’explorer les pages web suspectes et de comparer chaque formulaire de connexion trouvé sur les domaines suspects avec chacun des formulaires de connexion du domaine de la victime à l’aide d’un outil comme `ssdeep`.\
Si vous avez repéré les formulaires de connexion des domaines suspects, vous pouvez essayer **d’envoyer des identifiants factices** et de **vérifier si vous êtes redirigé vers le domaine de la victime**.

---

### Recherche par favicon et empreintes web (Shodan/Censys)

De nombreux kits de phishing réutilisent les favicons de la marque qu’ils usurpent. Shodan calcule le hash des données du favicon encodées en base64 avec MurmurHash3, tandis que Censys expose ses propres champs de hash de favicon.<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup> Vous pouvez générer un hash compatible avec Shodan et effectuer une recherche à partir de celui-ci :

Exemple Python (mmh3) :

```python
import base64, requests, mmh3
url = "https://www.paypal.com/favicon.ico"  # change to your brand icon
b64 = base64.encodebytes(requests.get(url, timeout=10).content)
print(mmh3.hash(b64))  # e.g., 309020573
```

- Interrogez Shodan : `http.favicon.hash:309020573`
- Avec des outils : consultez des outils communautaires comme favfreak pour calculer les hashes et générer des dorks Shodan.<sup>[[16]](#references)</sup>

Notes
- Les favicons sont réutilisés ; considérez les correspondances comme des pistes et validez le contenu et les certificats avant d’agir.
- Combinez ces résultats avec l’ancienneté du domaine et des heuristiques basées sur des mots-clés pour gagner en précision.

### Recherche dans la télémétrie des URL (urlscan.io)

`urlscan.io` stocke les captures d’écran, le DOM, les requêtes et les métadonnées TLS historiques des URL soumises. Vous pouvez rechercher des usurpations de marque et des clones :<sup>[[8]](#references)</sup>

Exemples de requêtes (interface utilisateur ou API) :
- Trouver des sites similaires en excluant vos domaines légitimes : `page.domain:(/.*yourbrand.*/ AND NOT yourbrand.com AND NOT www.yourbrand.com)`
- Trouver les sites qui intègrent vos ressources depuis leur site : `domain:yourbrand.com AND NOT page.domain:yourbrand.com`
- Limiter aux résultats récents : ajoutez `AND date:>now-7d`

Exemple d’API :

```bash
# Search recent scans mentioning your brand
curl -s 'https://urlscan.io/api/v1/search/?q=page.domain:(/.*yourbrand.*/%20AND%20NOT%20yourbrand.com)%20AND%20date:>now-7d' \
  -H 'API-Key: <YOUR_URLSCAN_KEY>' | jq '.results[].page.url'
```

À partir du JSON, examinez :
- `page.tlsIssuer`, `page.tlsValidFrom`, `page.tlsAgeDays` pour repérer les certificats très récents associés à des sosies
- les valeurs de `task.source`, comme `certstream-suspicious`, pour relier les résultats à la surveillance CT

### Ancienneté du domaine via RDAP (scriptable)

RDAP renvoie des événements d’enregistrement lisibles par machine. Utile pour repérer les **domaines récemment enregistrés (NRD)**.<sup>[[9]](#references)[[10]](#references)</sup>

```bash
# .com/.net RDAP (Verisign)
curl -s https://rdap.verisign.com/com/v1/domain/suspicious-example.com | \
  jq -r '.events[] | select(.eventAction=="registration") | .eventDate'

# Generic helper using rdap.net redirector
curl -s https://www.rdap.net/domain/suspicious-example.com | jq
```

Enrichissez votre pipeline en classant les domaines par tranches d'ancienneté d'enregistrement (p. ex., <7 jours, <30 jours) et en priorisant le triage en conséquence.

### Empreintes TLS/JAx pour repérer une infrastructure AiTM

Le phishing visant à voler des identifiants peut s'appuyer sur des reverse proxies **Adversary-in-the-Middle (AiTM)** (p. ex., Evilginx) pour dérober des jetons de session.<sup>[[11]](#references)</sup> Vous pouvez ajouter des détections côté réseau :

- Consignez les empreintes TLS/HTTP (JA3/JA4/JA4S/JA4H) au niveau des sorties réseau. Certaines versions d'Evilginx ont été observées avec des valeurs client/serveur JA4 stables. Déclenchez des alertes uniquement sur les empreintes malveillantes connues, car il s'agit d'un signal faible, et confirmez toujours avec le contenu et les renseignements sur les domaines.<sup>[[12]](#references)</sup>
- Enregistrez de manière proactive les métadonnées des certificats TLS (émetteur, nombre de SAN, utilisation de jokers, validité) pour les hôtes ressemblants découverts via CT ou urlscan, puis corrélez-les avec l'ancienneté du DNS et la géolocalisation.

> Remarque : utilisez les empreintes comme enrichissement, et non comme seul moyen de blocage ; les frameworks évoluent et peuvent randomiser ou obfusquer leurs empreintes.

### Noms de domaine contenant des mots-clés

La page parente mentionne également une technique de variation de nom de domaine qui consiste à placer le **nom de domaine de la victime à l'intérieur d'un domaine plus grand** (p. ex., paypal-financial.com pour paypal.com).

#### Certificate Transparency

Les journaux Certificate Transparency (CT) exposent les identités des certificats. Rechercher des mots-clés de marque dans les noms Subject ou SAN peut donc révéler des domaines ressemblants (par exemple, un certificat pour `paypal-financial.com` révèle le mot-clé `paypal`). Au besoin, filtrez les résultats par date d'émission et CA, puis vérifiez les candidats, car les correspondances de mots-clés peuvent produire des faux positifs.<sup>[[13]](#references)</sup>

L'article original de Patrik Hudak sur la [recherche de domaines de phishing](https://0xpatrik.com/phishing-domains/) présente ce workflow dans Censys, avec notamment des filtres sur la date du certificat et son émetteur, tel que Let's Encrypt.<sup>[[13]](#references)</sup>

![Résultats de recherche de certificats dans Censys, utilisés pour identifier des domaines ressemblants](<../../images/image (1115).png>)

Vous pouvez aussi utiliser le service gratuit [**crt.sh**](https://crt.sh) pour rechercher un mot-clé et filtrer les résultats par date et CA.<sup>[[13]](#references)</sup>

![Recherche par mot-clé dans crt.sh pour repérer des identités de certificats suspectes](<../../images/image (519).png>)

Le champ Matching Identities peut aider à comparer les identités du domaine réel à celles de domaines suspects, mais considérez les correspondances comme des pistes, et non comme des preuves.<sup>[[13]](#references)</sup>

[*CertStream*](https://medium.com/cali-dog-security/introducing-certstream-3fc13bb98067) diffuse les mises à jour CT presque en temps réel, et [*phishing_catcher*](https://github.com/x0rz/phishing_catcher) consomme ce flux pour évaluer les noms de certificats suspects.<sup>[[14]](#references)[[15]](#references)</sup>

Conseil pratique : lors du triage des résultats CT, donnez la priorité aux NRD, aux registrars non fiables ou inconnus, aux WHOIS utilisant un proxy de confidentialité et aux certificats dont les dates `NotBefore` sont très récentes. Tenez à jour une liste d'autorisation de vos domaines et marques pour réduire le bruit.

#### **Nouveaux domaines**

Une autre possibilité consiste à collecter les domaines récemment enregistrés par TLD (par exemple, via [Whoxy](https://www.whoxy.com/newly-registered-domains/)), puis à filtrer par mots-clés de marque. Cette méthode ne détecte pas le phishing hébergé sur des sous-domaines lorsque le mot-clé est absent du domaine enregistré.<sup>[[13]](#references)</sup>

Heuristique supplémentaire : traitez certains **TLD d'extension de fichier** (p. ex., `.zip`, `.mov`) avec une suspicion accrue dans les alertes. Ils sont souvent confondus avec des noms de fichiers dans les leurres ; combinez le signal du TLD avec les mots-clés de marque et l'ancienneté du NRD pour améliorer la précision.

## References

- [1] [Remy Hax – Bitsquatting Windows.com](https://remyhax.xyz/posts/bitsquatting-windows/)
- [2] [Détournement du trafic vers windows.com de Microsoft par bit flipping](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)
- [3] [dnstwist](https://github.com/elceef/dnstwist)
- [4] [urlcrazy](https://github.com/urbanadventurer/urlcrazy)
- [5] [Analyse approfondie : http.favicon](https://blog.shodan.io/deep-dive-http-favicon/)
- [6] [Documentation mmh3](https://mmh3.readthedocs.io/en/stable/quickstart.html)
- [7] [Ensemble de données des propriétés Web de la plateforme](https://docs.censys.com/docs/platform-web-property-dataset)
- [8] [urlscan.io – Référence de l'API Search](https://urlscan.io/docs/search/)
- [9] [Aide sur le Registration Data Access Protocol](https://www.verisign.com/news-insights/registration-data-access-protocol/help/)
- [10] [RFC 9083 : réponses JSON pour le Registration Data Access Protocol](https://www.rfc-editor.org/rfc/rfc9083.html)
- [11] [Tactiques liées aux jetons : comment prévenir, détecter et gérer le vol de jetons cloud](https://www.microsoft.com/en-us/security/blog/2022/11/16/token-tactics-how-to-prevent-detect-and-respond-to-cloud-token-theft/)
- [12] [Blog APNIC – Empreintes réseau JA4+](https://blog.apnic.net/2023/11/22/ja4-network-fingerprinting/)
- [13] [Patrik Hudak – Détecter le phishing : outils et techniques](https://0xpatrik.com/phishing-domains/)
- [14] [Ryan Sears – Présentation de CertStream](https://medium.com/cali-dog-security/introducing-certstream-3fc13bb98067)
- [15] [x0rz – Phishing Catcher](https://github.com/x0rz/phishing_catcher)
- [16] [Devansh Batham – FavFreak](https://github.com/devanshbatham/FavFreak)
{{#include ../../banners/hacktricks-training.md}}
