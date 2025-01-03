# Détection du phishing

{{#include ../../banners/hacktricks-training.md}}

## Introduction

Pour détecter une tentative de phishing, il est important de **comprendre les techniques de phishing qui sont utilisées de nos jours**. Sur la page principale de ce post, vous pouvez trouver cette information, donc si vous n'êtes pas au courant des techniques utilisées aujourd'hui, je vous recommande d'aller sur la page principale et de lire au moins cette section.

Ce post est basé sur l'idée que les **attaquants essaieront d'une manière ou d'une autre de mimer ou d'utiliser le nom de domaine de la victime**. Si votre domaine s'appelle `example.com` et que vous êtes phishé en utilisant un nom de domaine complètement différent pour une raison quelconque comme `youwonthelottery.com`, ces techniques ne vont pas le révéler.

## Variations de noms de domaine

Il est assez **facile** de **détecter** ces **tentatives de phishing** qui utiliseront un **nom de domaine similaire** dans l'email.\
Il suffit de **générer une liste des noms de phishing les plus probables** qu'un attaquant pourrait utiliser et de **vérifier** s'ils sont **enregistrés** ou simplement vérifier s'il y a une **IP** qui l'utilise.

### Trouver des domaines suspects

À cette fin, vous pouvez utiliser l'un des outils suivants. Notez que ces outils effectueront également des requêtes DNS automatiquement pour vérifier si le domaine a une IP qui lui est assignée :

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

### Bitflipping

**Vous pouvez trouver une brève explication de cette technique sur la page principale. Ou lire la recherche originale dans** [**https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/**](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

Par exemple, une modification de 1 bit dans le domaine microsoft.com peut le transformer en _windnws.com._\
**Les attaquants peuvent enregistrer autant de domaines de bit-flipping que possible liés à la victime pour rediriger les utilisateurs légitimes vers leur infrastructure**.

**Tous les noms de domaine de bit-flipping possibles devraient également être surveillés.**

### Vérifications de base

Une fois que vous avez une liste de noms de domaine potentiellement suspects, vous devriez **les vérifier** (principalement les ports HTTP et HTTPS) pour **voir s'ils utilisent un formulaire de connexion similaire** à celui du domaine de la victime.\
Vous pourriez également vérifier le port 3333 pour voir s'il est ouvert et exécute une instance de `gophish`.\
Il est également intéressant de savoir **quel âge a chaque domaine suspect découvert**, plus il est jeune, plus il est risqué.\
Vous pouvez également obtenir des **captures d'écran** de la page web suspecte HTTP et/ou HTTPS pour voir si elle est suspecte et dans ce cas **y accéder pour examiner plus en profondeur**.

### Vérifications avancées

Si vous souhaitez aller un peu plus loin, je vous recommande de **surveiller ces domaines suspects et de rechercher d'autres** de temps en temps (tous les jours ? cela ne prend que quelques secondes/minutes). Vous devriez également **vérifier** les **ports** ouverts des IPs associées et **rechercher des instances de `gophish` ou d'outils similaires** (oui, les attaquants font aussi des erreurs) et **surveiller les pages web HTTP et HTTPS des domaines et sous-domaines suspects** pour voir s'ils ont copié un formulaire de connexion des pages web de la victime.\
Pour **automatiser cela**, je vous recommande d'avoir une liste de formulaires de connexion des domaines de la victime, d'explorer les pages web suspectes et de comparer chaque formulaire de connexion trouvé dans les domaines suspects avec chaque formulaire de connexion du domaine de la victime en utilisant quelque chose comme `ssdeep`.\
Si vous avez localisé les formulaires de connexion des domaines suspects, vous pouvez essayer d'**envoyer des identifiants non valides** et **vérifier s'il vous redirige vers le domaine de la victime**.

## Noms de domaine utilisant des mots-clés

La page principale mentionne également une technique de variation de nom de domaine qui consiste à mettre le **nom de domaine de la victime à l'intérieur d'un domaine plus grand** (par exemple, paypal-financial.com pour paypal.com).

### Transparence des certificats

Il n'est pas possible d'adopter l'approche précédente "Brute-Force", mais il est en fait **possible de détecter de telles tentatives de phishing** également grâce à la transparence des certificats. Chaque fois qu'un certificat est émis par une CA, les détails sont rendus publics. Cela signifie qu'en lisant la transparence des certificats ou même en la surveillant, il est **possible de trouver des domaines qui utilisent un mot-clé dans leur nom**. Par exemple, si un attaquant génère un certificat pour [https://paypal-financial.com](https://paypal-financial.com), en voyant le certificat, il est possible de trouver le mot-clé "paypal" et de savoir qu'un email suspect est utilisé.

Le post [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/) suggère que vous pouvez utiliser Censys pour rechercher des certificats affectant un mot-clé spécifique et filtrer par date (uniquement les certificats "nouveaux") et par l'émetteur CA "Let's Encrypt" :

![https://0xpatrik.com/content/images/2018/07/cert_listing.png](<../../images/image (1115).png>)

Cependant, vous pouvez faire "la même chose" en utilisant le web gratuit [**crt.sh**](https://crt.sh). Vous pouvez **rechercher le mot-clé** et **filtrer** les résultats **par date et CA** si vous le souhaitez.

![](<../../images/image (519).png>)

En utilisant cette dernière option, vous pouvez même utiliser le champ Matching Identities pour voir si une identité du domaine réel correspond à l'un des domaines suspects (notez qu'un domaine suspect peut être un faux positif).

**Une autre alternative** est le projet fantastique appelé [**CertStream**](https://medium.com/cali-dog-security/introducing-certstream-3fc13bb98067). CertStream fournit un flux en temps réel de certificats nouvellement générés que vous pouvez utiliser pour détecter des mots-clés spécifiés en (quasi) temps réel. En fait, il existe un projet appelé [**phishing_catcher**](https://github.com/x0rz/phishing_catcher) qui fait exactement cela.

### **Nouveaux domaines**

**Une dernière alternative** est de rassembler une liste de **domaines nouvellement enregistrés** pour certains TLDs ([Whoxy](https://www.whoxy.com/newly-registered-domains/) fournit ce service) et **vérifier les mots-clés dans ces domaines**. Cependant, les longs domaines utilisent généralement un ou plusieurs sous-domaines, donc le mot-clé n'apparaîtra pas dans le FLD et vous ne pourrez pas trouver le sous-domaine de phishing.

{{#include ../../banners/hacktricks-training.md}}
