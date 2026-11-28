# Aufklärung und Threat-Intelligence-APIs

{{#include ../../banners/hacktricks-training.md}}

Diese Services unterstützen Aufklärungs-, Reputations-, Breach- oder Enrichment-Workflows. APIs, Kontingente, Preise und zulässige Nutzungen ändern sich häufig. Prüfen Sie daher vor der Übermittlung von Kundenkennungen oder sensiblen Daten die aktuelle Dokumentation des Anbieters und die Autorisierung des Auftrags. Die Abfolge zur Asset-Ermittlung finden Sie unter [External Recon Methodology](README.md).

## [Project Honey Pot](https://www.projecthoneypot.org/) <sup>[[1]](#references)</sup>

Prüfen Sie, ob eine IP-Adresse mit verdächtigen oder bösartigen Aktivitäten in Verbindung gebracht wurde. Für den Zugriff sind möglicherweise ein Konto oder ein API-Key erforderlich.

## [**BotScout**](https://botscout.com/api.htm) <sup>[[2]](#references)</sup>

Prüfen Sie, ob eine IP-Adresse, ein Benutzername oder eine E-Mail-Adresse mit automatisierten Konto-Registrierungen oder anderen gemeldeten Bot-Aktivitäten in Verbindung gebracht wurde.

## [Hunter](https://hunter.io/) <sup>[[3]](#references)</sup>

Finden und verifizieren Sie professionelle E-Mail-Adressen und domänenbezogene Kontaktmuster. Prüfen Sie im aktuellen Tarif die Anfrage-Limits und zulässigen Nutzungen.

## [AlienVault OTX](https://otx.alienvault.com/api) <sup>[[4]](#references)</sup>

Suchen Sie nach Threat-Intelligence-Indikatoren und Aktivitäten im Zusammenhang mit IP-Adressen und Domains.

## [Clearbit](https://dashboard.clearbit.com/) <sup>[[5]](#references)</sup>

Reichern Sie eine E-Mail-Adresse, Domain oder ein Unternehmen mit verfügbaren geschäftlichen oder Profil-Daten an. Umfang, Zugriff und Datenschutzbeschränkungen hängen vom aktuellen Produkt und Tarif ab.

## [BuiltWith](https://builtwith.com/) <sup>[[6]](#references)</sup>

Ermitteln Sie Technologien, die auf Websites beobachtet wurden, und beziehen Sie historische Daten oder Beziehungsdaten, sofern der gewählte Tarif dies zulässt.

## [FraudGuard](https://fraudguard.io/) <sup>[[7]](#references)</sup>

Prüfen Sie, ob eine IP-Adresse mit verdächtigen oder bösartigen Aktivitäten in Verbindung gebracht wird. Prüfen Sie die aktuellen API-Tarife und Limits.

## [FortiGuard](https://fortiguard.com/) <sup>[[8]](#references)</sup>

Rufen Sie die FortiGuard-Kategorisierung und Threat Intelligence für Domains, URLs oder IP-Adressen ab. Die Verfügbarkeit hängt vom jeweiligen Service ab.

## [SpamCop](https://www.spamcop.net/) <sup>[[9]](#references)</sup>

Prüfen Sie, ob eine IP-Adresse wegen gemeldeter Spam-Aktivitäten gelistet ist.

## [myWOT](https://www.mywot.com/) <sup>[[10]](#references)</sup>

Rufen Sie die Reputation einer Domain ab, die auf der Community des Services und weiteren Signalen basiert.

## [IPinfo](https://ipinfo.io/) <sup>[[11]](#references)</sup>

Rufen Sie Geolokalisierungs-, ASN-, Organisations- und zugehörige Metadaten für eine IP-Adresse ab. Prüfen Sie die Kontingente des aktuellen Tarifs.

## [SecurityTrails](https://securitytrails.com/app/account) <sup>[[12]](#references)</sup>

Diese Plattform bietet DNS- und Infrastrukturinformationen wie historische Auflösungen, Domains in Verbindung mit IP-Adressen oder Name-Servern sowie zugehörige Einträge. Historische DNS-Daten können eine frühere Origin-IP-Adresse aufdecken, umgehen aber nicht zuverlässig ein CDN und müssen überprüft werden.

## [FullContact](https://www.fullcontact.com/) <sup>[[13]](#references)</sup>

Reichern Sie eine E-Mail-Adresse, Domain oder einen Unternehmensnamen mit verfügbaren Identitäts- und Unternehmensmerkmalen an. Verarbeiten Sie personenbezogene Daten gemäß den Autorisierungs- und Datenschutzanforderungen.

## RiskIQ / Microsoft Defender Threat Intelligence (legacy transition) <sup>[[14]](#references)</sup>

Die PassiveTotal-Funktionen von RiskIQ wurden in Microsoft Defender Threat Intelligence überführt. Produktzugriff, APIs und beibehaltene Funktionen haben sich geändert. Orientieren Sie sich daher an der aktuellen Microsoft-Dokumentation und nicht an überholten Annahmen zu PassiveTotal.

## [Intelligence X](https://intelx.io/) <sup>[[15]](#references)</sup>

Suchen Sie nach Domains, IP-Adressen, E-Mail-Adressen und indizierten historischen oder geleakten Daten. Dabei gelten die Zugriffskontrollen des Services.

## [IBM X-Force Exchange](https://exchange.xforce.ibmcloud.com/) <sup>[[16]](#references)</sup>

Suchen Sie nach IP-Adressen und anderen Indikatoren, um Threat-Intelligence- und Reputationsdaten abzurufen.

## [GreyNoise](https://viz.greynoise.io/) <sup>[[17]](#references)</sup>

Suchen Sie nach IP-Adressen oder -Bereichen, zu denen Beobachtungen von Internet-Scans und üblichen Service-Aktivitäten vorliegen. Prüfen Sie die aktuellen Bedingungen für Testversion und Community-Zugriff.

## [Shodan](https://www.shodan.io/) <sup>[[18]](#references)</sup>

Rufen Sie Informationen zu Internet-Scans und Services für eine IP-Adresse, einen Host oder eine Suchanfrage ab. Der API-Zugriff hängt vom Kontotarif ab.

## [Censys](https://censys.io/) <sup>[[19]](#references)</sup>

Durchsuchen Sie Datensätze zu Hosts, Zertifikaten, Domains und Internet-Services. Datenmodell und Abdeckung unterscheiden sich von denen von Shodan.

## [GrayHatWarfare bucket search](https://buckets.grayhatwarfare.com/) <sup>[[20]](#references)</sup>

Durchsuchen Sie den Index des Anbieters mit öffentlich beobachteten Cloud-Speicherobjekten und Buckets nach Stichworten.

## [DeHashed](https://www.dehashed.com/data) <sup>[[21]](#references)</sup>

Durchsuchen Sie indizierte Breach-Daten nach E-Mail-Adressen, Benutzernamen, Domains und zugehörigen Einträgen. Nutzen Sie den Service nur mit entsprechender Autorisierung und vermeiden Sie die unnötige Offenlegung von Breach-Daten.

## [psbdmp](https://psbdmp.ws/) <sup>[[22]](#references)</sup>

Durchsuchen Sie indizierte Paste-Inhalte nach Vorkommen einer E-Mail-Adresse oder eines anderen Begriffs. Prüfen Sie vor der Integration, ob der Service noch verfügbar ist.

## [EmailRep](https://emailrep.io/key) <sup>[[23]](#references)</sup>

Rufen Sie Reputations- und Risikosignale für eine E-Mail-Adresse ab.

## GhostProject (historisch) <sup>[[24]](#references)</sup>

Der Service bewarb früher die Suche in geleakten E-Mail-/Passwort-Daten. Behandeln Sie ihn als risikoreichen Drittanbieter für die Datenverarbeitung und prüfen Sie vor der Nutzung seine Verfügbarkeit, Rechtmäßigkeit und Autorisierung.

## BinaryEdge (eingestellt) <sup>[[25]](#references)</sup>

Bot Internet-Scan-, Exposure- und Threat-Intelligence-Daten für IP-Adressen und zugehörige Assets an. Die Website leitet jetzt zu einem Hinweis auf die Übernahme durch Coalition weiter und die API lehnt Anfragen ab. Betrachten Sie den Service daher als nicht verfügbar.

## [Have I Been Pwned](https://haveibeenpwned.com/) <sup>[[26]](#references)</sup>

Prüfen Sie, ob eine E-Mail-Adresse oder verifizierte Domain in bekannten Breaches vorkommt. Der separate Service Pwned Passwords prüft Passwort-Hashes anhand ihres Präfixes; er gibt **keine** Klartext-Passwörter preis.

### [IP2Location.io](https://www.ip2location.io/) <sup>[[27]](#references)</sup>

Rufen Sie IP-Geolokalisierung, Rechenzentrums-, ASN-, Proxy-/VPN- und zugehörige Enrichment-Felder ab. Die Kontingente hängen vom aktuellen Tarif ab.

### [IPQuery.io](https://www.ipquery.io/) <sup>[[28]](#references)</sup>
IP-Geolokalisierung und OSINT-orientiertes Enrichment mit ausgewählten Datenpunkten. Prüfen Sie die aktuellen Bedingungen für die kommerzielle Nutzung.

### [NetAPI](https://netapi.com/) <sup>[[32]](#references)</sup>
Rufen Sie Informationen zu einer Domain ab (Registrar, Registrierungs- und Ablaufdaten, Name-Server, Hosting-IP und Land) oder zu einer IP-Adresse (andere darauf gehostete Domains). Prüfen Sie außerdem, ob eine Domain oder IP-Adresse in den kostenlosen Listen kompromittierter Systeme des Services aufgeführt ist: Phishing- und auf Sinkholes umgeleitete Malware-Domains sowie Adressen, die in den letzten 48 Stunden dessen Honeypot-Sensoren angegriffen haben. Für die Web-Abfragen und die API zur Prüfung kompromittierter Systeme ist kein Konto erforderlich. Der API-Zugriff auf die Abfragen erfordert einen kostenpflichtigen Tarif.


[DNSDumpster](https://dnsdumpster.com/) liefert Ergebnisse der DNS-Aufklärung.<sup>[[29]](#references)</sup>

[Netcraft](https://www.netcraft.com/) liefert Informationen zu Websites, Hosting und Internet-Infrastruktur.<sup>[[30]](#references)</sup>

[NMMapper](https://www.nmmapper.com/sys/tools/subdomainfinder/) bietet eine Online-Oberfläche zur Subdomain-Ermittlung.<sup>[[31]](#references)</sup>

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
- [32] [NetAPI API-Dokumentation](https://netapi.com/help/api/)
{{#include ../../banners/hacktricks-training.md}}
