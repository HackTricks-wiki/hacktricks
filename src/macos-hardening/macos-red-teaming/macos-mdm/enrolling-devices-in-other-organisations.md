# Iscrizione dei dispositivi in altre organizzazioni

{{#include ../../../banners/hacktricks-training.md}}

## Introduzione

Apple Automated Device Enrollment (precedentemente DEP) inizia identificando un dispositivo assegnato a un'organizzazione. La ricerca del 2018 qui riassunta ha dimostrato che conoscere un serial number assegnato era sufficiente per recuperare i profili di enrollment di alcune organizzazioni, poiché tali organizzazioni non richiedevano un'autenticazione aggiuntiva adeguata. Si tratta di un risultato storico, non dell'affermazione che ogni MDM attuale possa essere aggiunto utilizzando solo un serial number. I profili possono contenere certificati, applicazioni, segreti Wi-Fi, impostazioni VPN e altre configurazioni sensibili.<sup>[[1]](#references)[[2]](#references)</sup>

**Quanto segue è un riepilogo della ricerca [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe). Consultala per ulteriori dettagli tecnici!**<sup>[[1]](#references)</sup>

## Panoramica dell'analisi binaria di DEP e MDM

La ricerca ha analizzato i binari associati a DEP e MDM nelle versioni di macOS correnti all'epoca. I nomi dei componenti e le responsabilità possono cambiare tra le diverse release:

- **`mdmclient`**: comunica con i server MDM e attiva i check-in DEP nelle versioni di macOS precedenti alla 10.13.4.
- **`profiles`**: gestisce i Profili di configurazione e attiva i check-in DEP nelle versioni di macOS 10.13.4 e successive.
- **`cloudconfigurationd`**: gestisce le comunicazioni con le API DEP e recupera i profili Device Enrollment.

I check-in DEP utilizzano le funzioni `CPFetchActivationRecord` e `CPGetActivationRecord` del framework privato Configuration Profiles per recuperare l'Activation Record, mentre `CPFetchActivationRecord` coordina le operazioni con `cloudconfigurationd` tramite XPC.<sup>[[1]](#references)</sup>

## Reverse Engineering del protocollo Tesla e dello schema Absinthe

Il check-in DEP prevede che `cloudconfigurationd` invii un payload JSON encrypted e signed a _iprofiles.apple.com/macProfile_. Il payload include il serial number del dispositivo e l'azione "RequestProfileConfiguration". Lo schema di encryption utilizzato è indicato internamente come "Absinthe". Ricostruire questo schema è complesso e richiede numerosi passaggi, portando a esplorare metodi alternativi per inserire serial number arbitrari nella richiesta dell'Activation Record.<sup>[[1]](#references)</sup>

## Proxying delle richieste DEP

I tentativi di intercettare e modificare le richieste DEP verso _iprofiles.apple.com_ utilizzando strumenti come Charles Proxy sono stati ostacolati dall'encryption del payload e dalle misure di sicurezza SSL/TLS. Tuttavia, abilitando la configurazione `MCCloudConfigAcceptAnyHTTPSCertificate` è possibile bypassare la validazione del certificato del server, anche se la natura encrypted del payload impedisce comunque di modificare il serial number senza la decryption key.<sup>[[1]](#references)</sup>

## Instrumentation dei binari di sistema che interagiscono con DEP

L'instrumentation di binari di sistema come `cloudconfigurationd` richiede la disabilitazione di System Integrity Protection (SIP) su macOS. Con SIP disabilitato, strumenti come LLDB possono essere utilizzati per collegarsi ai processi di sistema e modificare potenzialmente il serial number utilizzato nelle interazioni con le API DEP. Questo metodo è preferibile perché evita le complessità relative a entitlements e code signing.<sup>[[1]](#references)</sup>

**Exploiting Binary Instrumentation:**
La modifica del payload della richiesta DEP prima della serializzazione JSON in `cloudconfigurationd` si è dimostrata efficace. Il processo prevedeva:

1. Collegarsi con LLDB a `cloudconfigurationd`.
2. Individuare il punto in cui viene recuperato il serial number di sistema.
3. Iniettare un serial number arbitrario nella memoria prima che il payload venga encrypted e inviato.

Questo metodo ha consentito ai ricercatori di recuperare i profili DEP relativi ai serial number forniti e assegnati. Non ha reso valido un serial number arbitrario non assegnato.<sup>[[1]](#references)</sup>

### Automazione dell'Instrumentation con Python

Il processo di exploitation è stato automatizzato utilizzando Python con l'API LLDB, rendendo possibile iniettare programmaticamente serial number arbitrari e recuperare i profili DEP corrispondenti.<sup>[[1]](#references)</sup>

### Potenziali impatti delle vulnerabilità DEP e MDM

La ricerca ha evidenziato importanti problemi di sicurezza:

1. **Information Disclosure**: fornendo un serial number registrato in DEP, è possibile recuperare le informazioni sensibili dell'organizzazione contenute nel profilo DEP.<sup>[[1]](#references)</sup>

## References

- [1] [Duo Labs — MDM Me Maybe: Sicurezza del Device Enrollment Program](https://duo.com/labs/research/mdm-me-maybe)
- [2] [Apple Platform Deployment — Iscrizione automatica dei dispositivi](https://support.apple.com/guide/deployment/automated-device-enrollment-and-mdm-dep73069dd57/web)
{{#include ../../../banners/hacktricks-training.md}}
