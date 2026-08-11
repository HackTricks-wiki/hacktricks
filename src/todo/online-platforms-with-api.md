# Online-Plattformen mit API

{{#include ../banners/hacktricks-training.md}}

Diese Services unterstützen Reconnaissance-, Reputations-, Breach- oder Enrichment-Workflows. Ihre APIs, Quotas, Preise und zulässigen Verwendungen ändern sich häufig; bestätige die aktuelle Dokumentation des Anbieters und die Autorisierung für das Engagement, bevor du Kundenidentifikatoren oder vertrauliche Daten sendest.

## [Project Honey Pot](https://www.projecthoneypot.org/) <sup>[[1]](#references)</sup>

Prüfe, ob eine IP-Adresse mit verdächtigen oder bösartigen Aktivitäten in Verbindung gebracht wurde. Für den Zugriff kann ein Account oder API-Key erforderlich sein.

## [**BotScout**](https://botscout.com/api.htm) <sup>[[2]](#references)</sup>

Prüfe, ob eine IP-Adresse, ein Benutzername oder eine E-Mail-Adresse mit automatisierter Account-Registrierung oder anderer gemeldeter Bot-Aktivität in Verbindung gebracht wurde.

## [Hunter](https://hunter.io/) <sup>[[3]](#references)</sup>

Finde und verifiziere berufliche E-Mail-Adressen und kontaktbezogene Domain-Muster. Prüfe den aktuellen Plan auf Request-Limits und zulässige Verwendungen.

## [AlienVault OTX](https://otx.alienvault.com/api) <sup>[[4]](#references)</sup>

Suche nach Threat-Intelligence-Indikatoren und Aktivitäten im Zusammenhang mit IP-Adressen und Domains.

## [Clearbit](https://dashboard.clearbit.com/) <sup>[[5]](#references)</sup>

Reichere eine E-Mail-Adresse, Domain oder ein Unternehmen mit verfügbaren Geschäfts-/Profildaten an. Abdeckung, Zugriff und Datenschutzbeschränkungen hängen vom aktuellen Produkt und Plan ab.

## [BuiltWith](https://builtwith.com/) <sup>[[6]](#references)</sup>

Identifiziere auf Websites beobachtete Technologien und erhalte historische oder Beziehungsdaten, sofern der ausgewählte Plan dies erlaubt.

## [FraudGuard](https://fraudguard.io/) <sup>[[7]](#references)</sup>

Prüfe, ob eine IP-Adresse mit verdächtigen oder bösartigen Aktivitäten in Verbindung steht. Bestätige die aktuellen API-Pläne und Limits.

## [FortiGuard](https://fortiguard.com/) <sup>[[8]](#references)</sup>

Rufe die FortiGuard-Kategorisierung und Threat Intelligence für Domains, URLs oder IP-Adressen ab. Die Verfügbarkeit unterscheidet sich je nach Service.

## [SpamCop](https://www.spamcop.net/) <sup>[[9]](#references)</sup>

Prüfe, ob eine IP-Adresse wegen gemeldeter Spam-Aktivitäten gelistet ist.

## [myWOT](https://www.mywot.com/) <sup>[[10]](#references)</sup>

Rufe die Reputation einer Domain ab, basierend auf der Community des Services und anderen Signalen.

## [IPinfo](https://ipinfo.io/) <sup>[[11]](#references)</sup>

Erhalte Geolocation-, ASN-, Organisations- und damit verbundene Metadaten für eine IP-Adresse. Prüfe den aktuellen Plan auf Quotas.

## [SecurityTrails](https://securitytrails.com/app/account) <sup>[[12]](#references)</sup>

Diese Plattform stellt DNS- und Infrastrukturinformationen bereit, etwa historische Auflösungen, mit IPs oder Name-Servern verbundene Domains und zugehörige Records. Historisches DNS kann eine frühere Origin-Adresse offenlegen, umgeht jedoch ein CDN nicht zuverlässig und muss validiert werden.

## [FullContact](https://www.fullcontact.com/) <sup>[[13]](#references)</sup>

Reichere eine E-Mail-Adresse, Domain oder einen Unternehmensnamen mit verfügbaren Identitäts- und Geschäftsattributen an. Verarbeite personenbezogene Daten entsprechend den Anforderungen an Autorisierung und Datenschutz.

## RiskIQ / Microsoft Defender Threat Intelligence (legacy transition) <sup>[[14]](#references)</sup>

Die PassiveTotal-Funktionen von RiskIQ wurden in Microsoft Defender Threat Intelligence überführt. Produktzugriff, APIs und erhaltene Funktionen haben sich geändert. Verwende daher die aktuelle Dokumentation von Microsoft statt veralteter PassiveTotal-Annahmen.

## [Intelligence X](https://intelx.io/) <sup>[[15]](#references)</sup>

Suche nach Domains, IP-Adressen, E-Mail-Adressen sowie indexierten historischen oder geleakten Daten, vorbehaltlich der Zugriffskontrollen des Services.

## [IBM X-Force Exchange](https://exchange.xforce.ibmcloud.com/) <sup>[[16]](#references)</sup>

Suche nach IP-Adressen und anderen Indikatoren, um Threat-Intelligence- und Reputationsdaten abzurufen.

## [GreyNoise](https://viz.greynoise.io/) <sup>[[17]](#references)</sup>

Suche nach IP-Adressen oder Bereichen, um Beobachtungen von Internet-Scanning und Aktivitäten gängiger Services abzurufen. Prüfe die aktuellen Bedingungen für Testversionen und Community-Zugriff.

## [Shodan](https://www.shodan.io/) <sup>[[18]](#references)</sup>

Rufe Internet-Scan- und Serviceinformationen für eine IP-Adresse, einen Host oder eine Suchanfrage ab. Der API-Zugriff hängt vom Account-Plan ab.

## [Censys](https://censys.io/) <sup>[[19]](#references)</sup>

Durchsuche Host-, Zertifikats-, Domain- und Internet-Service-Datensätze. Das Datenmodell und die Abdeckung unterscheiden sich von Shodan.

## [GrayHatWarfare bucket search](https://buckets.grayhatwarfare.com/) <sup>[[20]](#references)</sup>

Durchsuche den Index des Anbieters mit öffentlich beobachteten Cloud-Storage-Objekten und Buckets anhand eines Keywords.

## [DeHashed](https://www.dehashed.com/data) <sup>[[21]](#references)</sup>

Durchsuche indexierte Breach-Daten nach E-Mail-Adressen, Benutzernamen, Domains und zugehörigen Records. Verwende den Service nur mit Autorisierung und vermeide eine unnötige Offenlegung von Breach-Daten.

## [psbdmp](https://psbdmp.ws/) <sup>[[22]](#references)</sup>

Durchsuche indexierte Paste-Inhalte nach dem Vorkommen einer E-Mail-Adresse oder eines anderen Begriffs. Verifiziere vor der Integration, dass der Service noch verfügbar ist.

## [EmailRep](https://emailrep.io/key) <sup>[[23]](#references)</sup>

Rufe Reputations- und Risikosignale für eine E-Mail-Adresse ab.

## GhostProject (historisch) <sup>[[24]](#references)</sup>

Historisch wurden Suchmöglichkeiten für geleakte E-Mail-/Passwortdaten beworben. Behandle den Service als risikoreichen Drittanbieter-Service und prüfe vor der Verwendung seine Verfügbarkeit, Rechtmäßigkeit und Autorisierung.

## [BinaryEdge](https://www.binaryedge.io/) <sup>[[25]](#references)</sup>

Erhalte Internet-Scan-, Exposure- und Threat-Intelligence-Daten für IP-Adressen und zugehörige Assets.

## [Have I Been Pwned](https://haveibeenpwned.com/) <sup>[[26]](#references)</sup>

Prüfe, ob eine E-Mail-Adresse oder verifizierte Domain in bekannten Breaches erscheint. Der separate Service Pwned Passwords prüft Passwort-Hashes anhand eines Präfixes; er gibt **keine** Klartextpasswörter preis.

### [IP2Location.io](https://www.ip2location.io/) <sup>[[27]](#references)</sup>

Rufe IP-Geolocation, Rechenzentrums-, ASN-, Proxy-/VPN- und damit verbundene Enrichment-Felder ab. Quotas hängen vom aktuellen Plan ab.

### [IPQuery.io](https://www.ipquery.io/) <sup>[[28]](#references)</sup>
IP-Geolocation und OSINT-orientiertes Enrichment mit ausgewählten Datenpunkten. Prüfe die aktuellen Bedingungen für die kommerzielle Nutzung.


[DNSDumpster](https://dnsdumpster.com/) stellt DNS-Reconnaissance-Ergebnisse bereit.<sup>[[29]](#references)</sup>

[Netcraft](https://www.netcraft.com/) stellt Informationen zu Websites, Hosting und Internet-Infrastruktur bereit.<sup>[[30]](#references)</sup>

[NMMapper](https://www.nmmapper.com/sys/tools/subdomainfinder/) stellt eine Online-Schnittstelle zur Subdomain-Ermittlung bereit.<sup>[[31]](#references)</sup>

## References

- [1] [Project Honey Pot](https://www.projecthoneypot.org/)
- [2] [BotScout API](https://botscout.com/api.htm)
- [3] [Hunter API](https://hunter.io/api-documentation)
- [4] [AlienVault OTX API](https://otx.alienvault.com/api)
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
- [24] [Cornell-Forschung — Protokolle zur Prüfung kompromittierter Zugangsdaten (einschließlich GhostProject)](https://rist.tech.cornell.edu/papers/c3.pdf)
- [25] [BinaryEdge](https://www.binaryedge.io/)
- [26] [Have I Been Pwned API](https://haveibeenpwned.com/API/v3)
- [27] [IP2Location.io](https://www.ip2location.io/)
- [28] [IPQuery](https://www.ipquery.io/)
- [29] [DNSDumpster](https://dnsdumpster.com/)
- [30] [Netcraft](https://www.netcraft.com/)
- [31] [NMMapper Subdomain Finder](https://www.nmmapper.com/sys/tools/subdomainfinder/)
{{#include ../banners/hacktricks-training.md}}
