# Piattaforme online con API

{{#include ../banners/hacktricks-training.md}}

Questi servizi supportano workflow di reconnaissance, reputazione, breach o enrichment. Le relative API, quote, prezzi e modalità d'uso consentite cambiano frequentemente; verifica la documentazione corrente del vendor e l'autorizzazione dell'engagement prima di inviare identificativi dei clienti o dati sensibili.

## [Project Honey Pot](https://www.projecthoneypot.org/) <sup>[[1]](#references)</sup>

Verifica se un indirizzo IP è stato associato ad attività sospette o malevole. L'accesso potrebbe richiedere un account o una API key.

## [**BotScout**](https://botscout.com/api.htm) <sup>[[2]](#references)</sup>

Verifica se un indirizzo IP, uno username o un indirizzo email è stato associato alla registrazione automatizzata di account o ad altre attività bot segnalate.

## [Hunter](https://hunter.io/) <sup>[[3]](#references)</sup>

Trova e verifica indirizzi email professionali e pattern di contatto relativi a domini. Verifica il piano corrente per i limiti delle richieste e gli usi consentiti.

## [AlienVault OTX](https://otx.alienvault.com/api) <sup>[[4]](#references)</sup>

Cerca indicatori di threat intelligence e attività associate a indirizzi IP e domini.

## [Clearbit](https://dashboard.clearbit.com/) <sup>[[5]](#references)</sup>

Arricchisce un indirizzo email, un dominio o un'azienda con i dati aziendali e di profilo disponibili. Copertura, accesso e vincoli sulla privacy dipendono dal prodotto e dal piano correnti.

## [BuiltWith](https://builtwith.com/) <sup>[[6]](#references)</sup>

Identifica le tecnologie osservate sui siti web e ottiene dati storici o sulle relazioni, quando consentito dal piano selezionato.

## [FraudGuard](https://fraudguard.io/) <sup>[[7]](#references)</sup>

Verifica se un indirizzo IP è associato ad attività sospette o malevole. Conferma i piani API e i limiti correnti.

## [FortiGuard](https://fortiguard.com/) <sup>[[8]](#references)</sup>

Consulta la categorizzazione e la threat intelligence di FortiGuard per domini, URL o indirizzi IP. La disponibilità varia in base al servizio.

## [SpamCop](https://www.spamcop.net/) <sup>[[9]](#references)</sup>

Verifica se un indirizzo IP è inserito in una lista per attività di spam segnalate.

## [myWOT](https://www.mywot.com/) <sup>[[10]](#references)</sup>

Recupera la reputazione di un dominio in base alla community del servizio e ad altri segnali.

## [IPinfo](https://ipinfo.io/) <sup>[[11]](#references)</sup>

Ottiene geolocalizzazione, ASN, organizzazione e metadati correlati per un indirizzo IP. Verifica le quote del piano corrente.

## [SecurityTrails](https://securitytrails.com/app/account) <sup>[[12]](#references)</sup>

Questa piattaforma fornisce dati di DNS e intelligence sull'infrastruttura, come risoluzioni storiche, domini associati a IP o name server e record correlati. Il DNS storico può rivelare un precedente indirizzo origin, ma non consente di aggirare in modo affidabile una CDN e deve essere verificato.

## [FullContact](https://www.fullcontact.com/) <sup>[[13]](#references)</sup>

Arricchisce un indirizzo email, un dominio o il nome di un'azienda con gli attributi di identità e aziendali disponibili. Gestisci i dati personali in conformità con i requisiti di autorizzazione e privacy.

## RiskIQ / Microsoft Defender Threat Intelligence (legacy transition) <sup>[[14]](#references)</sup>

Le funzionalità PassiveTotal di RiskIQ sono confluite in Microsoft Defender Threat Intelligence. L'accesso al prodotto, le API e le funzionalità mantenute sono cambiate; usa quindi la documentazione corrente di Microsoft anziché basarti sulle precedenti supposizioni relative a PassiveTotal.

## [Intelligence X](https://intelx.io/) <sup>[[15]](#references)</sup>

Cerca domini, indirizzi IP, indirizzi email e dati storici o leaked indicizzati, in base ai controlli di accesso del servizio.

## [IBM X-Force Exchange](https://exchange.xforce.ibmcloud.com/) <sup>[[16]](#references)</sup>

Cerca indirizzi IP e altri indicatori per ottenere dati di threat intelligence e reputazione.

## [GreyNoise](https://viz.greynoise.io/) <sup>[[17]](#references)</sup>

Cerca indirizzi IP o intervalli per individuare osservazioni di scanning Internet e attività di servizi comuni. Verifica i termini correnti per trial e accesso community.

## [Shodan](https://www.shodan.io/) <sup>[[18]](#references)</sup>

Recupera informazioni di internet-scan e sui servizi per un indirizzo IP, un host o una query di ricerca. L'accesso API dipende dal piano dell'account.

## [Censys](https://censys.io/) <sup>[[19]](#references)</sup>

Cerca nei dataset relativi a host, certificati, domini e servizi Internet; il suo modello dati e la sua copertura differiscono da quelli di Shodan.

## [GrayHatWarfare bucket search](https://buckets.grayhatwarfare.com/) <sup>[[20]](#references)</sup>

Cerca per keyword nell'indice del provider relativo a oggetti e bucket di cloud storage osservati pubblicamente.

## [DeHashed](https://www.dehashed.com/data) <sup>[[21]](#references)</sup>

Cerca nei dati di breach indicizzati indirizzi email, username, domini e record correlati. Usalo solo con autorizzazione ed evita l'esposizione non necessaria dei dati di breach.

## [psbdmp](https://psbdmp.ws/) <sup>[[22]](#references)</sup>

Cerca nel contenuto indicizzato dei paste la presenza di un indirizzo email o di un altro termine. Verifica che il servizio sia ancora disponibile prima di integrarlo.

## [EmailRep](https://emailrep.io/key) <sup>[[23]](#references)</sup>

Recupera segnali di reputazione e rischio per un indirizzo email.

## GhostProject (historical) <sup>[[24]](#references)</sup>

In passato pubblicizzava ricerche di dati email/password leaked. Considera il servizio come una gestione da parte di terzi ad alto rischio e verifica disponibilità, liceità e autorizzazione prima dell'uso.

## [BinaryEdge](https://www.binaryedge.io/) <sup>[[25]](#references)</sup>

Ottiene dati di internet-scan, esposizione e threat intelligence per indirizzi IP e asset correlati.

## [Have I Been Pwned](https://haveibeenpwned.com/) <sup>[[26]](#references)</sup>

Verifica se un indirizzo email o un dominio verificato compare in breach noti. Il servizio separato Pwned Passwords verifica gli hash delle password tramite prefisso; **non** rivela le password in chiaro.

### [IP2Location.io](https://www.ip2location.io/) <sup>[[27]](#references)</sup>

Recupera geolocalizzazione IP, data center, ASN, proxy/VPN e campi di enrichment correlati. Le quote dipendono dal piano corrente.

### [IPQuery.io](https://www.ipquery.io/) <sup>[[28]](#references)</sup>
Geolocalizzazione IP ed enrichment orientato all'OSINT con punti dati selezionati. Verifica i termini correnti per l'uso commerciale.


[DNSDumpster](https://dnsdumpster.com/) fornisce risultati di reconnaissance DNS.<sup>[[29]](#references)</sup>

[Netcraft](https://www.netcraft.com/) fornisce intelligence relativa a siti, hosting e infrastruttura Internet.<sup>[[30]](#references)</sup>

[NMMapper](https://www.nmmapper.com/sys/tools/subdomainfinder/) fornisce un'interfaccia online per la discovery dei sottodomini.<sup>[[31]](#references)</sup>

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
- [24] [Ricerca Cornell — Protocolli per la verifica delle credenziali compromesse (include GhostProject)](https://rist.tech.cornell.edu/papers/c3.pdf)
- [25] [BinaryEdge](https://www.binaryedge.io/)
- [26] [API di Have I Been Pwned](https://haveibeenpwned.com/API/v3)
- [27] [IP2Location.io](https://www.ip2location.io/)
- [28] [IPQuery](https://www.ipquery.io/)
- [29] [DNSDumpster](https://dnsdumpster.com/)
- [30] [Netcraft](https://www.netcraft.com/)
- [31] [Trova sottodomini di NMMapper](https://www.nmmapper.com/sys/tools/subdomainfinder/)
{{#include ../banners/hacktricks-training.md}}
