# Registrazione di dispositivi in altre organizzazioni

{{#include ../../../banners/hacktricks-training.md}}

## Introduzione

Come [**precedentemente commentato**](#what-is-mdm-mobile-device-management)**,** per tentare di registrare un dispositivo in un'organizzazione **è necessario solamente un Serial Number appartenente a tale organizzazione**. Una volta registrato il dispositivo, diverse organizzazioni installeranno dati sensibili sul nuovo dispositivo: certificati, applicazioni, password WiFi, configurazioni VPN [e così via](https://developer.apple.com/enterprise/documentation/Configuration-Profile-Reference.pdf).\
Pertanto, questo potrebbe rappresentare un entrypoint pericoloso per gli attacker se il processo di registrazione non è adeguatamente protetto.

**Quanto segue è un riepilogo della ricerca [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe). Consultala per ulteriori dettagli tecnici!**<sup>[[1]](#references)</sup>

## Panoramica dell'analisi dei binari DEP e MDM

Questa ricerca analizza i binari associati al Device Enrollment Program (DEP) e al Mobile Device Management (MDM) su macOS. I componenti principali includono:

- **`mdmclient`**: comunica con i server MDM e attiva i check-in DEP sulle versioni di macOS precedenti alla 10.13.4.
- **`profiles`**: gestisce i Configuration Profiles e attiva i check-in DEP sulle versioni di macOS 10.13.4 e successive.
- **`cloudconfigurationd`**: gestisce le comunicazioni con le API DEP e recupera i profili Device Enrollment.

I check-in DEP utilizzano le funzioni `CPFetchActivationRecord` e `CPGetActivationRecord` del framework privato Configuration Profiles per recuperare l'Activation Record, mentre `CPFetchActivationRecord` coordina le comunicazioni con `cloudconfigurationd` tramite XPC.<sup>[[1]](#references)</sup>

## Reverse engineering del protocollo Tesla e dello schema Absinthe

Il check-in DEP prevede che `cloudconfigurationd` invii un payload JSON crittografato e firmato a _iprofiles.apple.com/macProfile_. Il payload include il serial number del dispositivo e l'azione "RequestProfileConfiguration". Lo schema di crittografia utilizzato è chiamato internamente "Absinthe". Ricostruire questo schema è complesso e richiede numerosi passaggi; ciò ha portato a esplorare metodi alternativi per inserire serial number arbitrari nella richiesta dell'Activation Record.<sup>[[1]](#references)</sup>

## Proxying delle richieste DEP

I tentativi di intercettare e modificare le richieste DEP verso _iprofiles.apple.com_ utilizzando strumenti come Charles Proxy sono stati ostacolati dalla crittografia del payload e dalle misure di sicurezza SSL/TLS. Tuttavia, abilitando la configurazione `MCCloudConfigAcceptAnyHTTPSCertificate` è possibile aggirare la convalida del certificato del server, anche se la natura crittografata del payload impedisce comunque di modificare il serial number senza la chiave di decrittazione.<sup>[[1]](#references)</sup>

## Instrumentation dei binari di sistema che interagiscono con DEP

L'instrumentation di binari di sistema come `cloudconfigurationd` richiede la disabilitazione del System Integrity Protection (SIP) su macOS. Con SIP disabilitato, è possibile utilizzare strumenti come LLDB per collegarsi ai processi di sistema e modificare potenzialmente il serial number utilizzato nelle interazioni con le API DEP. Questo metodo è preferibile perché evita le complessità relative agli entitlements e alla code signing.<sup>[[1]](#references)</sup>

**Exploiting dell'instrumentation dei binari:**
La modifica del payload della richiesta DEP prima della serializzazione JSON in `cloudconfigurationd` si è dimostrata efficace. Il processo prevedeva:

1. Collegarsi con LLDB a `cloudconfigurationd`.
2. Individuare il punto in cui viene recuperato il serial number di sistema.
3. Iniettare un serial number arbitrario nella memoria prima che il payload venga crittografato e inviato.

Questo metodo ha permesso di recuperare profili DEP completi per serial number arbitrari, dimostrando una potenziale vulnerabilità.<sup>[[1]](#references)</sup>

### Automazione dell'instrumentation con Python

Il processo di exploitation è stato automatizzato utilizzando Python con l'API LLDB, rendendo possibile in modo programmatico l'iniezione di serial number arbitrari e il recupero dei profili DEP corrispondenti.<sup>[[1]](#references)</sup>

### Potenziali impatti delle vulnerabilità DEP e MDM

La ricerca ha evidenziato significativi problemi di sicurezza:

1. **Information Disclosure**: fornendo un serial number registrato in DEP, è possibile recuperare le informazioni sensibili dell'organizzazione contenute nel profilo DEP.<sup>[[1]](#references)</sup>

## Riferimenti

- [1] [Duo Labs — MDM Me Maybe: Device Enrollment Program Security](https://duo.com/labs/research/mdm-me-maybe)

{{#include ../../../banners/hacktricks-training.md}}
