# APIs de reconnaissance et de threat intelligence

{{#include ../../banners/hacktricks-training.md}}

Ces services prennent en charge les workflows de reconnaissance, de réputation, de breach ou d’enrichissement. Leurs API, quotas, tarifs et utilisations autorisées changent fréquemment ; consultez la documentation actuelle du fournisseur et vérifiez que l’engagement est autorisé avant d’envoyer des identifiants client ou des données sensibles. Pour connaître la séquence de découverte des actifs, consultez la [méthodologie de reconnaissance externe](README.md).

## [Project Honey Pot](https://www.projecthoneypot.org/) <sup>[[1]](#references)</sup>

Vérifiez si une adresse IP a été associée à une activité suspecte ou malveillante. L’accès peut nécessiter un compte ou une clé API.

## [**BotScout**](https://botscout.com/api.htm) <sup>[[2]](#references)</sup>

Vérifiez si une adresse IP, un nom d’utilisateur ou une adresse e-mail a été associé à des inscriptions automatisées de comptes ou à d’autres activités de bots signalées.

## [Hunter](https://hunter.io/) <sup>[[3]](#references)</sup>

Trouvez et vérifiez des adresses e-mail professionnelles ainsi que des formats de contact associés à un domaine. Consultez l’offre actuelle pour connaître les limites de requêtes et les utilisations autorisées.

## [AlienVault OTX](https://otx.alienvault.com/api) <sup>[[4]](#references)</sup>

Recherchez des indicateurs de threat intelligence et des activités associées à des adresses IP et à des domaines.

## [Clearbit](https://dashboard.clearbit.com/) <sup>[[5]](#references)</sup>

Enrichissez une adresse e-mail, un domaine ou une entreprise avec les données professionnelles/de profil disponibles. La couverture, l’accès et les contraintes de confidentialité dépendent du produit et de l’offre actuels.

## [BuiltWith](https://builtwith.com/) <sup>[[6]](#references)</sup>

Identifiez les technologies observées sur des sites web et obtenez des données historiques ou relationnelles lorsque l’offre choisie le permet.

## [FraudGuard](https://fraudguard.io/) <sup>[[7]](#references)</sup>

Vérifiez si une adresse IP est associée à une activité suspecte ou malveillante. Consultez les offres et limites API actuelles.

## [FortiGuard](https://fortiguard.com/) <sup>[[8]](#references)</sup>

Consultez la catégorisation FortiGuard et les informations de threat intelligence relatives à des domaines, des URL ou des adresses IP. La disponibilité varie selon le service.

## [SpamCop](https://www.spamcop.net/) <sup>[[9]](#references)</sup>

Vérifiez si une adresse IP est répertoriée pour des activités de spam signalées.

## [myWOT](https://www.mywot.com/) <sup>[[10]](#references)</sup>

Récupérez la réputation d’un domaine, établie à partir de la communauté du service et d’autres signaux.

## [IPinfo](https://ipinfo.io/) <sup>[[11]](#references)</sup>

Obtenez la géolocalisation, l’ASN, l’organisation et les métadonnées associées à une adresse IP. Consultez l’offre actuelle pour connaître les quotas.

## [SecurityTrails](https://securitytrails.com/app/account) <sup>[[12]](#references)</sup>

Cette plateforme fournit des renseignements sur le DNS et l’infrastructure, comme les résolutions historiques, les domaines associés à des IP ou à des serveurs de noms, ainsi que les enregistrements associés. Le DNS historique peut révéler une ancienne adresse d’origine, mais ne permet pas de contourner de manière fiable un CDN et doit être vérifié.

## [FullContact](https://www.fullcontact.com/) <sup>[[13]](#references)</sup>

Enrichissez une adresse e-mail, un domaine ou un nom d’entreprise avec les attributs d’identité et professionnels disponibles. Traitez les données personnelles conformément aux exigences d’autorisation et de confidentialité.

## RiskIQ / Microsoft Defender Threat Intelligence (transition historique) <sup>[[14]](#references)</sup>

Les fonctionnalités de RiskIQ PassiveTotal ont été intégrées à Microsoft Defender Threat Intelligence. L’accès au produit, les API et les fonctionnalités conservées ont changé ; consultez donc la documentation actuelle de Microsoft plutôt que de vous fier aux anciennes informations sur PassiveTotal.

## [Intelligence X](https://intelx.io/) <sup>[[15]](#references)</sup>

Recherchez des domaines, des adresses IP, des adresses e-mail et des données historiques indexées ou leaked, sous réserve des contrôles d’accès du service.

## [IBM X-Force Exchange](https://exchange.xforce.ibmcloud.com/) <sup>[[16]](#references)</sup>

Recherchez des adresses IP et d’autres indicateurs pour obtenir des données de threat intelligence et de réputation.

## [GreyNoise](https://viz.greynoise.io/) <sup>[[17]](#references)</sup>

Recherchez des adresses IP ou des plages pour consulter les observations de scans Internet et d’activités courantes sur les services. Consultez les conditions actuelles des offres d’essai et de l’accès communautaire.

## [Shodan](https://www.shodan.io/) <sup>[[18]](#references)</sup>

Récupérez des informations issues des scans Internet et sur les services d’une adresse IP, d’un hôte ou d’une requête de recherche. L’accès à l’API dépend de l’offre du compte.

## [Censys](https://censys.io/) <sup>[[19]](#references)</sup>

Recherchez dans les jeux de données sur les hôtes, les certificats, les domaines et les services Internet ; son modèle de données et sa couverture diffèrent de ceux de Shodan.

## [Recherche de buckets GrayHatWarfare](https://buckets.grayhatwarfare.com/) <sup>[[20]](#references)</sup>

Recherchez par mot-clé dans l’index du fournisseur, qui recense des objets et buckets de stockage cloud observés publiquement.

## [DeHashed](https://www.dehashed.com/data) <sup>[[21]](#references)</sup>

Recherchez des adresses e-mail, des noms d’utilisateur, des domaines et des enregistrements associés dans des données de breach indexées. N’utilisez ce service qu’avec autorisation et évitez toute exposition inutile de données de breach.

## [psbdmp](https://psbdmp.ws/) <sup>[[22]](#references)</sup>

Recherchez la présence d’une adresse e-mail ou d’un autre terme dans des contenus de paste indexés. Vérifiez que le service est toujours disponible avant de l’intégrer.

## [EmailRep](https://emailrep.io/key) <sup>[[23]](#references)</sup>

Récupérez des signaux de réputation et de risque pour une adresse e-mail.

## GhostProject (historique) <sup>[[24]](#references)</sup>

Ce service a historiquement proposé des recherches dans des données d’adresses e-mail et de mots de passe leaked. Considérez-le comme un service tiers à haut risque et vérifiez sa disponibilité, sa légalité et l’autorisation requise avant de l’utiliser.

## [BinaryEdge](https://www.binaryedge.io/) <sup>[[25]](#references)</sup>

Obtenez des données issues de scans Internet, sur l’exposition et de threat intelligence concernant des adresses IP et des actifs associés.

## [Have I Been Pwned](https://haveibeenpwned.com/) <sup>[[26]](#references)</sup>

Vérifiez si une adresse e-mail ou un domaine vérifié apparaît dans des breaches connues. Le service distinct Pwned Passwords vérifie les hash de mots de passe à partir d’un préfixe ; il ne révèle **pas** les mots de passe en clair.

### [IP2Location.io](https://www.ip2location.io/) <sup>[[27]](#references)</sup>

Récupérez la géolocalisation IP, des données sur les centres de données, l’ASN, le proxy/VPN et d’autres champs d’enrichissement associés. Les quotas dépendent de l’offre actuelle.

### [IPQuery.io](https://www.ipquery.io/) <sup>[[28]](#references)</sup>
Géolocalisation IP et enrichissement orienté OSINT avec certains points de données. Consultez les conditions actuelles concernant l’usage commercial.


[DNSDumpster](https://dnsdumpster.com/) fournit des résultats de reconnaissance DNS.<sup>[[29]](#references)</sup>

[Netcraft](https://www.netcraft.com/) fournit des renseignements sur les sites, l’hébergement et l’infrastructure Internet.<sup>[[30]](#references)</sup>

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
- [31] [Outil de recherche de sous-domaines NMMapper](https://www.nmmapper.com/sys/tools/subdomainfinder/)
{{#include ../../banners/hacktricks-training.md}}
