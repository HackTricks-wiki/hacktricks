# Reconnaissance- und Threat-Intelligence-APIs

{{#include ../../banners/hacktricks-training.md}}

Diese Dienste unterstützen Reconnaissance-, Reputations-, Breach- oder Enrichment-Workflows. APIs, Kontingente, Preise und zulässige Nutzungsarten ändern sich häufig. Prüfe die aktuelle Dokumentation des Anbieters sowie die Autorisierung für den Auftrag, bevor du Kundenkennungen oder sensible Daten übermittelst. Die Abfolge zur Asset-Erkennung findest du in der [External Recon Methodology](README.md).

## [Project Honey Pot](https://www.projecthoneypot.org/) <sup>[[1]](#references)</sup>

Prüfe, ob eine IP-Adresse mit verdächtigen oder bösartigen Aktivitäten in Verbindung gebracht wurde. Für den Zugriff sind möglicherweise ein Konto oder ein API-Schlüssel erforderlich.

## [**BotScout**](https://botscout.com/api.htm) <sup>[[2]](#references)</sup>

Prüfe, ob eine IP-Adresse, ein Benutzername oder eine E-Mail-Adresse mit automatisierten Kontoanmeldungen oder anderen gemeldeten Bot-Aktivitäten in Verbindung gebracht wurde.

## [Hunter](https://hunter.io/) <sup>[[3]](#references)</sup>

Finde und verifiziere geschäftliche E-Mail-Adressen und domainbezogene Kontaktmuster. Prüfe den aktuellen Tarif auf Anfragelimits und zulässige Nutzungsarten.

## [AlienVault OTX](https://otx.alienvault.com/api) <sup>[[4]](#references)</sup>

Suche nach Threat-Intelligence-Indikatoren und Aktivitäten im Zusammenhang mit IP-Adressen und Domains.

## [Clearbit](https://dashboard.clearbit.com/) <sup>[[5]](#references)</sup>

Reichere eine E-Mail-Adresse, Domain oder ein Unternehmen mit verfügbaren Geschäfts- und Profildaten an. Abdeckung, Zugriff und Datenschutzbeschränkungen hängen vom aktuellen Produkt und Tarif ab.

## [BuiltWith](https://builtwith.com/) <sup>[[6]](#references)</sup>

Ermittle Technologien, die auf Websites beobachtet wurden, und erhalte historische Daten oder Beziehungsdaten, sofern der ausgewählte Tarif dies zulässt.

## [FraudGuard](https://fraudguard.io/) <sup>[[7]](#references)</sup>

Prüfe, ob eine IP-Adresse mit verdächtigen oder bösartigen Aktivitäten in Verbindung steht. Informiere dich über aktuelle API-Tarife und -Limits.

## [FortiGuard](https://fortiguard.com/) <sup>[[8]](#references)</sup>

Rufe FortiGuard-Kategorisierungen und Threat Intelligence zu Domains, URLs oder IP-Adressen ab. Die Verfügbarkeit unterscheidet sich je nach Dienst.

## [SpamCop](https://www.spamcop.net/) <sup>[[9]](#references)</sup>

Prüfe, ob eine IP-Adresse wegen gemeldeter Spam-Aktivitäten gelistet ist.

## [myWOT](https://www.mywot.com/) <sup>[[10]](#references)</sup>

Rufe die Reputation einer Domain ab, die auf der Community des Dienstes und weiteren Signalen basiert.

## [IPinfo](https://ipinfo.io/) <sup>[[11]](#references)</sup>

Rufe Geolokalisierungs-, ASN-, Organisations- und zugehörige Metadaten für eine IP-Adresse ab. Prüfe den aktuellen Tarif auf Kontingente.

## [SecurityTrails](https://securitytrails.com/app/account) <sup>[[12]](#references)</sup>

Diese Plattform bietet DNS- und Infrastrukturinformationen, etwa zu historischen Auflösungen, Domains, die IP-Adressen oder Nameservern zugeordnet sind, sowie zugehörigen Einträgen. Historische DNS-Daten können eine frühere Origin-Adresse offenlegen, umgehen ein CDN jedoch nicht zuverlässig und müssen überprüft werden.

## [FullContact](https://www.fullcontact.com/) <sup>[[13]](#references)</sup>

Reichere eine E-Mail-Adresse, Domain oder einen Unternehmensnamen mit verfügbaren Identitäts- und Unternehmensmerkmalen an. Verarbeite personenbezogene Daten gemäß den Anforderungen an Autorisierung und Datenschutz.

## RiskIQ / Microsoft Defender Threat Intelligence (legacy transition) <sup>[[14]](#references)</sup>

Die PassiveTotal-Funktionen von RiskIQ wurden in Microsoft Defender Threat Intelligence überführt. Produktzugriff, APIs und beibehaltene Funktionen haben sich geändert. Orientiere dich daher an der aktuellen Dokumentation von Microsoft und nicht an früheren Annahmen zu PassiveTotal.

## [Intelligence X](https://intelx.io/) <sup>[[15]](#references)</sup>

Suche nach Domains, IP-Adressen, E-Mail-Adressen und indexierten historischen oder geleakten Daten, vorbehaltlich der Zugriffskontrollen des Dienstes.

## [IBM X-Force Exchange](https://exchange.xforce.ibmcloud.com/) <sup>[[16]](#references)</sup>

Suche nach IP-Adressen und anderen Indikatoren, um Threat-Intelligence- und Reputationsdaten abzurufen.

## [GreyNoise](https://viz.greynoise.io/) <sup>[[17]](#references)</sup>

Suche nach IP-Adressen oder Bereichen, um Beobachtungen zu Internet-Scans und häufigen Dienstaktivitäten abzurufen. Prüfe die aktuellen Bedingungen für Test- und Community-Zugriff.

## [Shodan](https://www.shodan.io/) <sup>[[18]](#references)</sup>

Rufe Informationen zu Internet-Scans und Diensten für eine IP-Adresse, einen Host oder eine Suchanfrage ab. Der API-Zugriff hängt vom Kontotarif ab.

## [Censys](https://censys.io/) <sup>[[19]](#references)</sup>

Durchsuche Host-, Zertifikats-, Domain- und Internetdienst-Datensätze. Das Datenmodell und die Abdeckung unterscheiden sich von Shodan.

## [GrayHatWarfare bucket search](https://buckets.grayhatwarfare.com/) <sup>[[20]](#references)</sup>

Durchsuche den Index des Anbieters mit öffentlich beobachteten Cloud-Storage-Objekten und Buckets anhand von Stichwörtern.

## [DeHashed](https://www.dehashed.com/data) <sup>[[21]](#references)</sup>

Durchsuche indexierte Breach-Daten nach E-Mail-Adressen, Benutzernamen, Domains und zugehörigen Einträgen. Nutze den Dienst nur mit Autorisierung und vermeide die unnötige Offenlegung von Breach-Daten.

## [psbdmp](https://psbdmp.ws/) <sup>[[22]](#references)</sup>

Durchsuche indexierte Paste-Inhalte nach einer E-Mail-Adresse oder einem anderen Begriff. Prüfe vor der Integration, ob der Dienst noch verfügbar ist.

## [EmailRep](https://emailrep.io/key) <sup>[[23]](#references)</sup>

Rufe Reputations- und Risikosignale für eine E-Mail-Adresse ab.

## GhostProject (historisch) <sup>[[24]](#references)</sup>

Der Dienst warb früher mit Suchmöglichkeiten in geleakten E-Mail-/Passwort-Daten. Betrachte ihn als risikoreichen Drittanbieter für die Datenverarbeitung und prüfe vor der Nutzung seine Verfügbarkeit, Rechtmäßigkeit und Autorisierung.

## [BinaryEdge](https://www.binaryedge.io/) <sup>[[25]](#references)</sup>

Rufe Daten zu Internet-Scans, Expositionen und Threat Intelligence für IP-Adressen und zugehörige Assets ab.

## [Have I Been Pwned](https://haveibeenpwned.com/) <sup>[[26]](#references)</sup>

Prüfe, ob eine E-Mail-Adresse oder verifizierte Domain in bekannten Breaches auftaucht. Der separate Dienst Pwned Passwords prüft Passwort-Hashes anhand ihres Präfixes; er gibt **keine** Klartextpasswörter preis.

### [IP2Location.io](https://www.ip2location.io/) <sup>[[27]](#references)</sup>

Rufe Geolokalisierungs-, Rechenzentrums-, ASN-, Proxy-/VPN- und zugehörige Anreicherungsdaten für eine IP-Adresse ab. Die Kontingente hängen vom aktuellen Tarif ab.

### [IPQuery.io](https://www.ipquery.io/) <sup>[[28]](#references)</sup>
Geolokalisierung von IP-Adressen und OSINT-orientierte Anreicherung mit ausgewählten Datenpunkten. Prüfe die aktuellen Nutzungsbedingungen für die kommerzielle Nutzung.


[DNSDumpster](https://dnsdumpster.com/) liefert Ergebnisse zur DNS-Reconnaissance.<sup>[[29]](#references)</sup>

[Netcraft](https://www.netcraft.com/) liefert Informationen zu Websites, Hosting und Internetinfrastruktur.<sup>[[30]](#references)</sup>

[NMMapper](https://www.nmmapper.com/sys/tools/subdomainfinder/) bietet eine Online-Schnittstelle zur Subdomain-Erkennung.<sup>[[31]](#references)</sup>

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
- [24] [Cornell-Forschung — Protokolle zur Überprüfung kompromittierter Zugangsdaten (einschließlich GhostProject)](https://rist.tech.cornell.edu/papers/c3.pdf)
- [25] [BinaryEdge](https://www.binaryedge.io/)
- [26] [Have I Been Pwned API](https://haveibeenpwned.com/API/v3)
- [27] [IP2Location.io](https://www.ip2location.io/)
- [28] [IPQuery](https://www.ipquery.io/)
- [29] [DNSDumpster](https://dnsdumpster.com/)
- [30] [Netcraft](https://www.netcraft.com/)
- [31] [NMMapper Subdomain Finder](https://www.nmmapper.com/sys/tools/subdomainfinder/)
{{#include ../../banners/hacktricks-training.md}}
