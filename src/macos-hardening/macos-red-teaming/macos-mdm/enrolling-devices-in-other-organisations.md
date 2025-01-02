# Iscrizione dei Dispositivi in Altre Organizzazioni

{{#include ../../../banners/hacktricks-training.md}}

## Introduzione

Come [**commentato in precedenza**](./#what-is-mdm-mobile-device-management)**,** per cercare di iscrivere un dispositivo in un'organizzazione **è necessario solo un Numero di Serie appartenente a quell'Organizzazione**. Una volta che il dispositivo è iscritto, diverse organizzazioni installeranno dati sensibili sul nuovo dispositivo: certificati, applicazioni, password WiFi, configurazioni VPN [e così via](https://developer.apple.com/enterprise/documentation/Configuration-Profile-Reference.pdf).\
Pertanto, questo potrebbe essere un punto di ingresso pericoloso per gli attaccanti se il processo di iscrizione non è correttamente protetto.

**Di seguito è riportato un riepilogo della ricerca [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe). Controllalo per ulteriori dettagli tecnici!**

## Panoramica dell'Analisi Binaria di DEP e MDM

Questa ricerca approfondisce i binari associati al Programma di Iscrizione dei Dispositivi (DEP) e alla Gestione dei Dispositivi Mobili (MDM) su macOS. I componenti chiave includono:

- **`mdmclient`**: Comunica con i server MDM e attiva i check-in DEP su versioni di macOS precedenti a 10.13.4.
- **`profiles`**: Gestisce i Profili di Configurazione e attiva i check-in DEP su versioni di macOS 10.13.4 e successive.
- **`cloudconfigurationd`**: Gestisce le comunicazioni API DEP e recupera i profili di iscrizione dei dispositivi.

I check-in DEP utilizzano le funzioni `CPFetchActivationRecord` e `CPGetActivationRecord` dal framework privato dei Profili di Configurazione per recuperare il Record di Attivazione, con `CPFetchActivationRecord` che coordina con `cloudconfigurationd` tramite XPC.

## Ingegneria Inversa del Protocollo Tesla e dello Schema Absinthe

Il check-in DEP comporta l'invio da parte di `cloudconfigurationd` di un payload JSON firmato e crittografato a _iprofiles.apple.com/macProfile_. Il payload include il numero di serie del dispositivo e l'azione "RequestProfileConfiguration". Lo schema di crittografia utilizzato è internamente denominato "Absinthe". Svelare questo schema è complesso e comporta numerosi passaggi, il che ha portato a esplorare metodi alternativi per inserire numeri di serie arbitrari nella richiesta del Record di Attivazione.

## Proxying delle Richieste DEP

I tentativi di intercettare e modificare le richieste DEP a _iprofiles.apple.com_ utilizzando strumenti come Charles Proxy sono stati ostacolati dalla crittografia del payload e dalle misure di sicurezza SSL/TLS. Tuttavia, abilitare la configurazione `MCCloudConfigAcceptAnyHTTPSCertificate` consente di bypassare la convalida del certificato del server, sebbene la natura crittografata del payload impedisca ancora la modifica del numero di serie senza la chiave di decrittazione.

## Strumentazione dei Binari di Sistema che Interagiscono con DEP

L'istrumentazione dei binari di sistema come `cloudconfigurationd` richiede di disabilitare la Protezione dell'Integrità di Sistema (SIP) su macOS. Con SIP disabilitato, strumenti come LLDB possono essere utilizzati per attaccarsi ai processi di sistema e potenzialmente modificare il numero di serie utilizzato nelle interazioni API DEP. Questo metodo è preferibile poiché evita le complessità delle autorizzazioni e della firma del codice.

**Sfruttare l'Istrumentazione Binaria:**
Modificare il payload della richiesta DEP prima della serializzazione JSON in `cloudconfigurationd` si è rivelato efficace. Il processo ha comportato:

1. Attaccare LLDB a `cloudconfigurationd`.
2. Localizzare il punto in cui viene recuperato il numero di serie del sistema.
3. Iniettare un numero di serie arbitrario nella memoria prima che il payload venga crittografato e inviato.

Questo metodo ha consentito di recuperare profili DEP completi per numeri di serie arbitrari, dimostrando una potenziale vulnerabilità.

### Automazione dell'Istrumentazione con Python

Il processo di sfruttamento è stato automatizzato utilizzando Python con l'API LLDB, rendendo fattibile l'iniezione programmatica di numeri di serie arbitrari e il recupero dei corrispondenti profili DEP.

### Potenziali Impatti delle Vulnerabilità di DEP e MDM

La ricerca ha evidenziato significative preoccupazioni per la sicurezza:

1. **Divulgazione di Informazioni**: Fornendo un numero di serie registrato in DEP, è possibile recuperare informazioni sensibili dell'organizzazione contenute nel profilo DEP.

{{#include ../../../banners/hacktricks-training.md}}
