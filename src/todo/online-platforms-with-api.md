# Plateformes en ligne avec API

{{#include ../banners/hacktricks-training.md}}

Ces services prennent en charge les workflows de reconnaissance, de réputation, de breach ou d'enrichissement. Leurs API, quotas, tarifs et utilisations autorisées changent fréquemment ; vérifiez la documentation actuelle du fournisseur ainsi que l'autorisation de l'engagement avant d'envoyer des identifiants clients ou des données sensibles.

## [Project Honey Pot](https://www.projecthoneypot.org/) <sup>[[1]](#references)</sup>

Vérifier si une adresse IP a été associée à une activité suspecte ou malveillante. L'accès peut nécessiter un compte ou une clé API.

## [**BotScout**](https://botscout.com/api.htm) <sup>[[2]](#references)</sup>

Vérifier si une adresse IP, un nom d'utilisateur ou une adresse e-mail a été associé à une inscription automatisée de compte ou à une autre activité de bot signalée.

## [Hunter](https://hunter.io/) <sup>[[3]](#references)</sup>

Trouver et vérifier des adresses e-mail professionnelles ainsi que des modèles de contact associés à un domaine. Vérifier le plan actuel pour connaître les limites de requêtes et les utilisations autorisées.

## [AlienVault OTX](https://otx.alienvault.com/api) <sup>[[4]](#references)</sup>

Rechercher des indicateurs de threat-intelligence et des activités associés à des adresses IP et à des domaines.

## [Clearbit](https://dashboard.clearbit.com/) <sup>[[5]](#references)</sup>

Enrichir une adresse e-mail, un domaine ou une entreprise avec les données commerciales/profil disponibles. La couverture, l'accès et les contraintes de confidentialité dépendent du produit et du plan actuels.

## [BuiltWith](https://builtwith.com/) <sup>[[6]](#references)</sup>

Identifier les technologies observées sur des sites web et obtenir des données historiques ou relationnelles lorsque le plan sélectionné l'autorise.

## [FraudGuard](https://fraudguard.io/) <sup>[[7]](#references)</sup>

Vérifier si une adresse IP est associée à une activité suspecte ou malveillante. Confirmer les plans et limites API actuels.

## [FortiGuard](https://fortiguard.com/) <sup>[[8]](#references)</sup>

Consulter la catégorisation FortiGuard et les informations de threat-intelligence concernant des domaines, des URL ou des adresses IP. La disponibilité varie selon le service.

## [SpamCop](https://www.spamcop.net/) <sup>[[9]](#references)</sup>

Vérifier si une adresse IP est répertoriée pour une activité de spam signalée.

## [myWOT](https://www.mywot.com/) <sup>[[10]](#references)</sup>

Récupérer la réputation d'un domaine en fonction de la communauté du service et d'autres signaux.

## [IPinfo](https://ipinfo.io/) <sup>[[11]](#references)</sup>

Obtenir la géolocalisation, l'ASN, l'organisation et les métadonnées associées à une adresse IP. Vérifier le plan actuel pour connaître les quotas.

## [SecurityTrails](https://securitytrails.com/app/account) <sup>[[12]](#references)</sup>

Cette plateforme fournit des informations DNS et d'infrastructure, telles que les résolutions historiques, les domaines associés à des IP ou à des serveurs de noms, ainsi que les enregistrements associés. Le DNS historique peut révéler une adresse d'origine antérieure, mais ne permet pas de contourner de manière fiable un CDN et doit être validé.

## [FullContact](https://www.fullcontact.com/) <sup>[[13]](#references)</sup>

Enrichir une adresse e-mail, un domaine ou un nom d'entreprise avec les attributs d'identité et commerciaux disponibles. Traiter les données personnelles conformément aux exigences d'autorisation et de confidentialité.

## RiskIQ / Microsoft Defender Threat Intelligence (legacy transition) <sup>[[14]](#references)</sup>

Les fonctionnalités PassiveTotal de RiskIQ ont été transférées vers Microsoft Defender Threat Intelligence. L'accès au produit, les API et les fonctionnalités conservées ont changé ; utilisez donc la documentation actuelle de Microsoft plutôt que les anciennes hypothèses concernant PassiveTotal.

## [Intelligence X](https://intelx.io/) <sup>[[15]](#references)</sup>

Rechercher des domaines, des adresses IP, des adresses e-mail ainsi que des données historiques ou leak indexées, sous réserve des contrôles d'accès du service.

## [IBM X-Force Exchange](https://exchange.xforce.ibmcloud.com/) <sup>[[16]](#references)</sup>

Rechercher des adresses IP et d'autres indicateurs afin d'obtenir des données de threat-intelligence et de réputation.

## [GreyNoise](https://viz.greynoise.io/) <sup>[[17]](#references)</sup>

Rechercher des adresses IP ou des plages afin d'identifier des observations de scanning Internet et d'activité de services courants. Vérifier les conditions actuelles d'essai et d'accès communautaire.

## [Shodan](https://www.shodan.io/) <sup>[[18]](#references)</sup>

Récupérer des informations de scan Internet et de services pour une adresse IP, un hôte ou une requête de recherche. L'accès à l'API dépend du plan du compte.

## [Censys](https://censys.io/) <sup>[[19]](#references)</sup>

Rechercher dans des jeux de données concernant les hôtes, les certificats, les domaines et les services Internet ; son modèle de données et sa couverture diffèrent de ceux de Shodan.

## [GrayHatWarfare bucket search](https://buckets.grayhatwarfare.com/) <sup>[[20]](#references)</sup>

Rechercher par mot-clé dans l'index du fournisseur contenant des objets et des buckets de cloud-storage observés publiquement.

## [DeHashed](https://www.dehashed.com/data) <sup>[[21]](#references)</sup>

Rechercher dans des données de breach indexées des adresses e-mail, des noms d'utilisateur, des domaines et des enregistrements associés. Utiliser uniquement avec une autorisation et éviter l'exposition inutile de données issues de breach.

## [psbdmp](https://psbdmp.ws/) <sup>[[22]](#references)</sup>

Rechercher dans du contenu de paste indexé les occurrences d'une adresse e-mail ou d'un autre terme. Vérifier que le service est toujours disponible avant de l'intégrer.

## [EmailRep](https://emailrep.io/key) <sup>[[23]](#references)</sup>

Récupérer les signaux de réputation et de risque associés à une adresse e-mail.

## GhostProject (historical) <sup>[[24]](#references)</sup>

A historiquement annoncé des recherches dans des données d'e-mails/mots de passe leakées. Considérer ce service comme un traitement tiers à haut risque et vérifier sa disponibilité, sa légalité et l'autorisation avant toute utilisation.

## [BinaryEdge](https://www.binaryedge.io/) <sup>[[25]](#references)</sup>

Obtenir des données de scan Internet, d'exposition et de threat-intelligence concernant des adresses IP et des actifs associés.

## [Have I Been Pwned](https://haveibeenpwned.com/) <sup>[[26]](#references)</sup>

Vérifier si une adresse e-mail ou un domaine vérifié apparaît dans des breaches connues. Le service distinct Pwned Passwords vérifie les hash de mots de passe par préfixe ; il ne révèle **pas** les mots de passe en clair.

### [IP2Location.io](https://www.ip2location.io/) <sup>[[27]](#references)</sup>

Récupérer la géolocalisation IP, le data-center, l'ASN, les informations de proxy/VPN et les champs d'enrichissement associés. Les quotas dépendent du plan actuel.

### [IPQuery.io](https://www.ipquery.io/) <sup>[[28]](#references)</sup>
Géolocalisation IP et enrichissement orienté OSINT avec certains points de données. Vérifier les conditions actuelles concernant l'utilisation commerciale.


[DNSDumpster](https://dnsdumpster.com/) fournit des résultats de reconnaissance DNS.<sup>[[29]](#references)</sup>

[Netcraft](https://www.netcraft.com/) fournit des informations sur les sites, l'hébergement et l'infrastructure Internet.<sup>[[30]](#references)</sup>

[NMMapper](https://www.nmmapper.com/sys/tools/subdomainfinder/) fournit une interface en ligne de découverte de sous-domaines.<sup>[[31]](#references)</sup>

## References

- [1] [Project Honey Pot](https://www.projecthoneypot.org/)
- [2] [API BotScout](https://botscout.com/api.htm)
- [3] [API Hunter](https://hunter.io/api-documentation)
- [4] [API AlienVault OTX](https://otx.alienvault.com/api)
- [5] [Clearbit](https://dashboard.clearbit.com/)
- [6] [BuiltWith](https://builtwith.com/)
- [7] [FraudGuard](https://fraudguard.io/)
- [8] [FortiGuard Labs](https://www.fortiguard.com/)
- [9] [SpamCop](https://www.spamcop.net/)
- [10] [Web of Trust](https://www.mywot.com/)
- [11] [IPinfo](https://ipinfo.io/)
- [12] [SecurityTrails](https://securitytrails.com/)
- [13] [FullContact](https://www.fullcontact.com/)
- [14] [Microsoft Defender Threat Intelligence](https://learn.microsoft.com/en-us/defender/threat-intelligence/what-is-microsoft-defender-threat-intelligence-defender-ti)
- [15] [Intelligence X](https://intelx.io/)
- [16] [IBM X-Force Exchange](https://exchange.xforce.ibmcloud.com/)
- [17] [GreyNoise](https://www.greynoise.io/)
- [18] [Shodan](https://www.shodan.io/)
- [19] [Censys](https://censys.com/)
- [20] [GrayHatWarfare](https://buckets.grayhatwarfare.com/)
- [21] [DeHashed](https://www.dehashed.com/)
- [22] [psbdmp](https://psbdmp.ws/)
- [23] [EmailRep](https://emailrep.io/)
- [24] [Recherche de Cornell — Protocoles de vérification des identifiants compromis (inclut GhostProject)](https://rist.tech.cornell.edu/papers/c3.pdf)
- [25] [BinaryEdge](https://www.binaryedge.io/)
- [26] [API Have I Been Pwned](https://haveibeenpwned.com/API/v3)
- [27] [IP2Location.io](https://www.ip2location.io/)
- [28] [IPQuery](https://www.ipquery.io/)
- [29] [DNSDumpster](https://dnsdumpster.com/)
- [30] [Netcraft](https://www.netcraft.com/)
- [31] [Recherche de sous-domaines NMMapper](https://www.nmmapper.com/sys/tools/subdomainfinder/)
{{#include ../banners/hacktricks-training.md}}
