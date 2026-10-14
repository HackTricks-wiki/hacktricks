# API di ricognizione e threat intelligence

{{#include ../../banners/hacktricks-training.md}}

Questi servizi supportano flussi di lavoro di ricognizione, reputazione, violazioni dei dati o arricchimento. API, quote, prezzi e usi consentiti cambiano frequentemente; prima di inviare identificativi dei clienti o dati sensibili, verifica la documentazione aggiornata del fornitore e l'autorizzazione per l'ingaggio. Per la sequenza di asset discovery, consulta la [metodologia di ricognizione esterna](README.md).

## [Project Honey Pot](https://www.projecthoneypot.org/) <sup>[[1]](#references)</sup>

Verifica se un indirizzo IP è stato associato ad attività sospette o dannose. Potrebbe essere necessario un account o una chiave API.

## [**BotScout**](https://botscout.com/api.htm) <sup>[[2]](#references)</sup>

Verifica se un indirizzo IP, un nome utente o un indirizzo email è stato associato alla registrazione automatizzata di account o ad altre attività bot segnalate.

## [Hunter](https://hunter.io/) <sup>[[3]](#references)</sup>

Trova e verifica indirizzi email professionali e modelli di contatto associati ai domini. Controlla il piano attuale per i limiti delle richieste e gli usi consentiti.

## [AlienVault OTX](https://otx.alienvault.com/api) <sup>[[4]](#references)</sup>

Cerca indicatori di threat intelligence e attività associate a indirizzi IP e domini.

## [Clearbit](https://dashboard.clearbit.com/) <sup>[[5]](#references)</sup>

Arricchisce un indirizzo email, un dominio o un'azienda con i dati aziendali o di profilo disponibili. Copertura, accesso e vincoli di privacy dipendono dal prodotto e dal piano attuali.

## [BuiltWith](https://builtwith.com/) <sup>[[6]](#references)</sup>

Identifica le tecnologie rilevate sui siti web e fornisce dati storici o sulle relazioni, se consentito dal piano selezionato.

## [FraudGuard](https://fraudguard.io/) <sup>[[7]](#references)</sup>

Verifica se un indirizzo IP è associato ad attività sospette o dannose. Controlla i piani API e i limiti attuali.

## [FortiGuard](https://fortiguard.com/) <sup>[[8]](#references)</sup>

Consulta la categorizzazione e la threat intelligence di FortiGuard per domini, URL o indirizzi IP. La disponibilità varia in base al servizio.

## [SpamCop](https://www.spamcop.net/) <sup>[[9]](#references)</sup>

Verifica se un indirizzo IP è inserito in una lista per attività di spam segnalate.

## [myWOT](https://www.mywot.com/) <sup>[[10]](#references)</sup>

Recupera la reputazione di un dominio in base alla community del servizio e ad altri segnali.

## [IPinfo](https://ipinfo.io/) <sup>[[11]](#references)</sup>

Ottieni geolocalizzazione, ASN, organizzazione e metadati correlati per un indirizzo IP. Controlla il piano attuale per le quote.

## [SecurityTrails](https://securitytrails.com/app/account) <sup>[[12]](#references)</sup>

Questa piattaforma fornisce informazioni su DNS e infrastruttura, come risoluzioni storiche, domini associati a IP o name server e record correlati. Il DNS storico può rivelare un precedente indirizzo origin, ma non consente di aggirare in modo affidabile una CDN e deve essere verificato.

## [FullContact](https://www.fullcontact.com/) <sup>[[13]](#references)</sup>

Arricchisce un indirizzo email, un dominio o il nome di un'azienda con attributi di identità e aziendali disponibili. Gestisci i dati personali nel rispetto dei requisiti di autorizzazione e privacy.

## RiskIQ / Microsoft Defender Threat Intelligence (transizione legacy) <sup>[[14]](#references)</sup>

Le funzionalità di RiskIQ PassiveTotal sono state integrate in Microsoft Defender Threat Intelligence. L'accesso al prodotto, le API e le funzionalità mantenute sono cambiati: fai riferimento alla documentazione aggiornata di Microsoft, non alle precedenti aspettative su PassiveTotal.

## [Intelligence X](https://intelx.io/) <sup>[[15]](#references)</sup>

Cerca domini, indirizzi IP, indirizzi email e dati storici o leaked indicizzati, nel rispetto dei controlli di accesso del servizio.

## [IBM X-Force Exchange](https://exchange.xforce.ibmcloud.com/) <sup>[[16]](#references)</sup>

Cerca indirizzi IP e altri indicatori per ottenere dati di threat intelligence e reputazione.

## [GreyNoise](https://viz.greynoise.io/) <sup>[[17]](#references)</sup>

Cerca indirizzi IP o intervalli per trovare osservazioni di scansioni Internet e attività comuni dei servizi. Controlla i termini attuali per le prove e l'accesso community.

## [Shodan](https://www.shodan.io/) <sup>[[18]](#references)</sup>

Recupera informazioni su scansioni Internet e servizi per un indirizzo IP, un host o una query di ricerca. L'accesso API dipende dal piano dell'account.

## [Censys](https://censys.io/) <sup>[[19]](#references)</sup>

Cerca nei dataset di host, certificati, domini e servizi Internet; il modello dei dati e la copertura differiscono da quelli di Shodan.

## [Ricerca di bucket GrayHatWarfare](https://buckets.grayhatwarfare.com/) <sup>[[20]](#references)</sup>

Cerca per parola chiave nell'indice del provider, che contiene oggetti e bucket di cloud storage osservati pubblicamente.

## [DeHashed](https://www.dehashed.com/data) <sup>[[21]](#references)</sup>

Cerca nei dati di violazioni indicizzati indirizzi email, nomi utente, domini e record correlati. Usalo solo con autorizzazione ed evita l'esposizione non necessaria dei dati delle violazioni.

## [psbdmp](https://psbdmp.ws/) <sup>[[22]](#references)</sup>

Cerca nei contenuti paste indicizzati le occorrenze di un indirizzo email o di un altro termine. Verifica che il servizio sia ancora disponibile prima di integrarlo.

## [EmailRep](https://emailrep.io/key) <sup>[[23]](#references)</sup>

Recupera segnali di reputazione e rischio per un indirizzo email.

## GhostProject (storico) <sup>[[24]](#references)</sup>

In passato pubblicizzava la ricerca di dati leaked relativi a email e password. Considera il servizio un sistema di gestione di terze parti ad alto rischio e, prima dell'uso, verifica disponibilità, legalità e autorizzazione.

## [BinaryEdge](https://www.binaryedge.io/) <sup>[[25]](#references)</sup>

Ottieni dati su scansioni Internet, esposizione e threat intelligence per indirizzi IP e asset correlati.

## [Have I Been Pwned](https://haveibeenpwned.com/) <sup>[[26]](#references)</sup>

Verifica se un indirizzo email o un dominio verificato compare in violazioni note. Il servizio separato Pwned Passwords controlla gli hash delle password tramite prefisso; **non** rivela password in chiaro.

### [IP2Location.io](https://www.ip2location.io/) <sup>[[27]](#references)</sup>

Recupera geolocalizzazione IP, data center, ASN, proxy/VPN e altri campi di arricchimento correlati. Le quote dipendono dal piano attuale.

### [IPQuery.io](https://www.ipquery.io/) <sup>[[28]](#references)</sup>
Geolocalizzazione IP e arricchimento orientato all'OSINT con una selezione di dati. Controlla i termini attuali per l'uso commerciale.


[DNSDumpster](https://dnsdumpster.com/) fornisce risultati di ricognizione DNS.<sup>[[29]](#references)</sup>

[Netcraft](https://www.netcraft.com/) fornisce informazioni su siti, hosting e infrastruttura Internet.<sup>[[30]](#references)</sup>

[NMMapper](https://www.nmmapper.com/sys/tools/subdomainfinder/) fornisce un'interfaccia online per individuare sottodomini.<sup>[[31]](#references)</sup>

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
- [24] [Ricerca Cornell — protocolli per verificare credenziali compromesse (include GhostProject)](https://rist.tech.cornell.edu/papers/c3.pdf)
- [25] [BinaryEdge](https://www.binaryedge.io/)
- [26] [API di Have I Been Pwned](https://haveibeenpwned.com/API/v3)
- [27] [IP2Location.io](https://www.ip2location.io/)
- [28] [IPQuery](https://www.ipquery.io/)
- [29] [DNSDumpster](https://dnsdumpster.com/)
- [30] [Netcraft](https://www.netcraft.com/)
- [31] [Trova sottodomini di NMMapper](https://www.nmmapper.com/sys/tools/subdomainfinder/)
{{#include ../../banners/hacktricks-training.md}}
