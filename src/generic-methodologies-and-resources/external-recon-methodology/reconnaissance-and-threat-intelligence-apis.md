# API di ricognizione e threat intelligence

{{#include ../../banners/hacktricks-training.md}}

Questi servizi supportano flussi di lavoro di ricognizione, reputazione, breach o arricchimento dei dati. Le API, le quote, i prezzi e gli usi consentiti cambiano frequentemente; prima di inviare identificativi dei clienti o dati sensibili, verifica la documentazione aggiornata del fornitore e l'autorizzazione per l'ingaggio. Per la sequenza di asset discovery, consulta la [External Recon Methodology](README.md).

## [Project Honey Pot](https://www.projecthoneypot.org/) <sup>[[1]](#references)</sup>

Verifica se un indirizzo IP è stato associato ad attività sospette o malevole. L'accesso potrebbe richiedere un account o una API key.

## [**BotScout**](https://botscout.com/api.htm) <sup>[[2]](#references)</sup>

Verifica se un indirizzo IP, un username o un indirizzo email è stato associato alla registrazione automatizzata di account o ad altre attività bot segnalate.

## [Hunter](https://hunter.io/) <sup>[[3]](#references)</sup>

Trova e verifica indirizzi email professionali e modelli di contatto associati a un dominio. Verifica i limiti di richieste e gli usi consentiti del piano attuale.

## [AlienVault OTX](https://otx.alienvault.com/api) <sup>[[4]](#references)</sup>

Cerca indicatori di threat intelligence e attività associate a indirizzi IP e domini.

## [Clearbit](https://dashboard.clearbit.com/) <sup>[[5]](#references)</sup>

Arricchisce un indirizzo email, un dominio o un'azienda con i dati aziendali e di profilo disponibili. Copertura, accesso e vincoli di privacy dipendono dal prodotto e dal piano attuali.

## [BuiltWith](https://builtwith.com/) <sup>[[6]](#references)</sup>

Identifica le tecnologie rilevate sui siti web e fornisce dati storici o sulle relazioni, se consentito dal piano selezionato.

## [FraudGuard](https://fraudguard.io/) <sup>[[7]](#references)</sup>

Verifica se un indirizzo IP è associato ad attività sospette o malevole. Controlla i piani API e i limiti attuali.

## [FortiGuard](https://fortiguard.com/) <sup>[[8]](#references)</sup>

Consulta la classificazione FortiGuard e le informazioni di threat intelligence per domini, URL o indirizzi IP. La disponibilità varia in base al servizio.

## [SpamCop](https://www.spamcop.net/) <sup>[[9]](#references)</sup>

Verifica se un indirizzo IP è presente in una lista per attività di spam segnalate.

## [myWOT](https://www.mywot.com/) <sup>[[10]](#references)</sup>

Recupera la reputazione di un dominio in base alla community del servizio e ad altri segnali.

## [IPinfo](https://ipinfo.io/) <sup>[[11]](#references)</sup>

Ottieni geolocalizzazione, ASN, organizzazione e metadati correlati per un indirizzo IP. Controlla le quote del piano attuale.

## [SecurityTrails](https://securitytrails.com/app/account) <sup>[[12]](#references)</sup>

Questa piattaforma fornisce informazioni su DNS e infrastruttura, come risoluzioni storiche, domini associati a IP o name server e record correlati. Il DNS storico può rivelare un precedente indirizzo origin, ma non consente di aggirare in modo affidabile una CDN e deve essere convalidato.

## [FullContact](https://www.fullcontact.com/) <sup>[[13]](#references)</sup>

Arricchisce un indirizzo email, un dominio o il nome di un'azienda con gli attributi di identità e aziendali disponibili. Gestisci i dati personali in conformità con i requisiti di autorizzazione e privacy.

## RiskIQ / Microsoft Defender Threat Intelligence (transizione legacy) <sup>[[14]](#references)</sup>

Le funzionalità di RiskIQ PassiveTotal sono confluite in Microsoft Defender Threat Intelligence. L'accesso al prodotto, le API e le funzionalità mantenute sono cambiati: consulta la documentazione aggiornata di Microsoft invece di basarti sulle vecchie informazioni su PassiveTotal.

## [Intelligence X](https://intelx.io/) <sup>[[15]](#references)</sup>

Cerca domini, indirizzi IP, indirizzi email e dati storici o leakati indicizzati, nel rispetto dei controlli di accesso del servizio.

## [IBM X-Force Exchange](https://exchange.xforce.ibmcloud.com/) <sup>[[16]](#references)</sup>

Cerca indirizzi IP e altri indicatori per ottenere informazioni di threat intelligence e reputazione.

## [GreyNoise](https://viz.greynoise.io/) <sup>[[17]](#references)</sup>

Cerca indirizzi IP o intervalli per consultare le osservazioni di scansioni Internet e attività comuni dei servizi. Controlla i termini attuali per le versioni di prova e l'accesso community.

## [Shodan](https://www.shodan.io/) <sup>[[18]](#references)</sup>

Recupera informazioni su scansioni Internet e servizi per un indirizzo IP, un host o una query di ricerca. L'accesso API dipende dal piano dell'account.

## [Censys](https://censys.io/) <sup>[[19]](#references)</sup>

Cerca nei dataset di host, certificati, domini e servizi Internet; il modello dei dati e la copertura differiscono da quelli di Shodan.

## [Ricerca di bucket su GrayHatWarfare](https://buckets.grayhatwarfare.com/) <sup>[[20]](#references)</sup>

Cerca per parola chiave nell'indice del provider contenente oggetti e bucket di cloud storage osservati pubblicamente.

## [DeHashed](https://www.dehashed.com/data) <sup>[[21]](#references)</sup>

Cerca nei dati di breach indicizzati indirizzi email, username, domini e record correlati. Usalo solo con autorizzazione ed evita l'esposizione non necessaria di dati di breach.

## [psbdmp](https://psbdmp.ws/) <sup>[[22]](#references)</sup>

Cerca nei contenuti paste indicizzati le occorrenze di un indirizzo email o di un altro termine. Verifica che il servizio sia ancora disponibile prima di integrarlo.

## [EmailRep](https://emailrep.io/key) <sup>[[23]](#references)</sup>

Recupera segnali di reputazione e rischio per un indirizzo email.

## GhostProject (storico) <sup>[[24]](#references)</sup>

In passato pubblicizzava ricerche in dati email/password leakati. Considera il servizio un soggetto terzo ad alto rischio per il trattamento dei dati e, prima di usarlo, verificali disponibilità, legalità e autorizzazione.

## BinaryEdge (discontinuato) <sup>[[25]](#references)</sup>

Offriva dati di scansione Internet, esposizione e threat intelligence per indirizzi IP e asset correlati. Il sito ora reindirizza a un avviso di transizione di Coalition e l'API rifiuta le richieste: consideralo non disponibile.

## [Have I Been Pwned](https://haveibeenpwned.com/) <sup>[[26]](#references)</sup>

Verifica se un indirizzo email o un dominio verificato compare in breach noti. Il servizio separato Pwned Passwords controlla gli hash delle password tramite prefisso; **non** rivela le password in chiaro.

### [IP2Location.io](https://www.ip2location.io/) <sup>[[27]](#references)</sup>

Recupera geolocalizzazione IP, data center, ASN, proxy/VPN e altri campi di arricchimento correlati. Le quote dipendono dal piano attuale.

### [IPQuery.io](https://www.ipquery.io/) <sup>[[28]](#references)</sup>
Geolocalizzazione IP e arricchimento orientato all'OSINT con punti dati selezionati. Controlla i termini attuali per l'uso commerciale.

### [NetAPI](https://netapi.com/) <sup>[[32]](#references)</sup>
Cerca un dominio (registrar, date di registrazione e scadenza, name server, IP di hosting e paese) o un indirizzo IP (gli altri domini ospitati su di esso) e verifica se un dominio o un IP è presente nelle liste gratuite di compromissione: domini di phishing e malware sinkholed e indirizzi che hanno attaccato i sensori honeypot del servizio nelle ultime 48 ore. Le ricerche web e l'API per il controllo delle compromissioni non richiedono un account; l'accesso API alle ricerche richiede un piano a pagamento.


[DNSDumpster](https://dnsdumpster.com/) fornisce risultati di ricognizione DNS.<sup>[[29]](#references)</sup>

[Netcraft](https://www.netcraft.com/) fornisce informazioni su siti, hosting e infrastruttura Internet.<sup>[[30]](#references)</sup>

[NMMapper](https://www.nmmapper.com/sys/tools/subdomainfinder/) fornisce un'interfaccia online per la subdomain discovery.<sup>[[31]](#references)</sup>

## References

- [1] [Project Honey Pot](https://www.projecthoneypot.org/)
- [2] [API di BotScout](https://botscout.com/api.htm)
- [3] [API di Hunter](https://hunter.io/api-documentation)
- [4] [API di AlienVault OTX](https://otx.alienvault.com/api)
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
- [24] [Ricerca Cornell — Protocolli per la verifica di credenziali compromesse (include GhostProject)](https://rist.tech.cornell.edu/papers/c3.pdf)
- [25] [BinaryEdge](https://www.binaryedge.io/)
- [26] [API di Have I Been Pwned](https://haveibeenpwned.com/API/v3)
- [27] [IP2Location.io](https://www.ip2location.io/)
- [28] [IPQuery](https://www.ipquery.io/)
- [29] [DNSDumpster](https://dnsdumpster.com/)
- [30] [Netcraft](https://www.netcraft.com/)
- [31] [Ricerca sottodomini di NMMapper](https://www.nmmapper.com/sys/tools/subdomainfinder/)
- [32] [Documentazione API di NetAPI](https://netapi.com/help/api/)
{{#include ../../banners/hacktricks-training.md}}
