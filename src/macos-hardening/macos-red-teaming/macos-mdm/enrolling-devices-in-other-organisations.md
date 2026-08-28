# Enrolling Devices in Other Organisations

{{#include ../../../banners/hacktricks-training.md}}

## Introduzione

Apple Automated Device Enrollment (precedentemente DEP) inizia identificando un dispositivo assegnato a un'organizzazione. La ricerca del 2018 qui riassunta ha mostrato che conoscere un serial number assegnato era sufficiente per recuperare i profili di enrollment di alcune organizzazioni, perché tali organizzazioni non richiedevano un'autenticazione aggiuntiva adeguata. Si tratta di una scoperta storica, non dell'affermazione che ogni MDM attuale possa essere associato utilizzando solo un serial number. I profili possono contenere certificati, applicazioni, segreti Wi-Fi, impostazioni VPN e altre configurazioni sensibili.<sup>[[1]](#references)[[2]](#references)</sup>

**Quanto segue è un riepilogo della ricerca [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe). Consultala per ulteriori dettagli tecnici!**<sup>[[1]](#references)</sup>

## Panoramica dell'analisi dei binari DEP e MDM

La ricerca ha analizzato i binari associati a DEP e MDM nelle versioni di macOS correnti all'epoca. I nomi e le responsabilità dei componenti possono cambiare tra le release:

- **`mdmclient`**: comunica con i server MDM e attiva i check-in DEP nelle versioni di macOS precedenti alla 10.13.4.
- **`profiles`**: gestisce i Configuration Profiles e attiva i check-in DEP nelle versioni di macOS 10.13.4 e successive.
- **`cloudconfigurationd`**: gestisce le comunicazioni con le API DEP e recupera i profili Device Enrollment.

I check-in DEP utilizzano le funzioni `CPFetchActivationRecord` e `CPGetActivationRecord` del framework privato Configuration Profiles per recuperare l'Activation Record, con `CPFetchActivationRecord` che coordina le operazioni con `cloudconfigurationd` tramite XPC.<sup>[[1]](#references)</sup>

## Reverse Engineering del protocollo Tesla e dello schema Absinthe

Il check-in DEP prevede che `cloudconfigurationd` invii un payload JSON crittografato e firmato a _iprofiles.apple.com/macProfile_. Il payload include il serial number del dispositivo e l'azione "RequestProfileConfiguration". Lo schema di crittografia utilizzato è indicato internamente come "Absinthe". Ricostruire questo schema è complesso e richiede numerosi passaggi; ciò ha portato a esplorare metodi alternativi per inserire serial number arbitrari nella richiesta dell'Activation Record.<sup>[[1]](#references)</sup>

## Proxying delle richieste DEP

I tentativi di intercettare e modificare le richieste DEP verso _iprofiles.apple.com_ utilizzando strumenti come Charles Proxy sono stati ostacolati dalla crittografia del payload e dalle misure di sicurezza SSL/TLS. Tuttavia, abilitare la configurazione `MCCloudConfigAcceptAnyHTTPSCertificate` consente di ignorare la validazione del certificato del server, sebbene la natura crittografata del payload impedisca comunque di modificare il serial number senza la chiave di decrittazione.<sup>[[1]](#references)</sup>

## Instrumentation dei binari di sistema che interagiscono con DEP

L'instrumentation di binari di sistema come `cloudconfigurationd` richiede la disabilitazione di System Integrity Protection (SIP) su macOS. Con SIP disabilitato, è possibile utilizzare strumenti come LLDB per collegarsi ai processi di sistema e potenzialmente modificare il serial number utilizzato nelle interazioni con le API DEP. Questo metodo è preferibile perché evita le complessità legate agli entitlements e al code signing.<sup>[[1]](#references)</sup>

**Exploiting Binary Instrumentation:**
La modifica del payload della richiesta DEP prima della serializzazione JSON in `cloudconfigurationd` si è rivelata efficace. Il processo prevedeva:

1. Collegarsi con LLDB a `cloudconfigurationd`.
2. Individuare il punto in cui viene recuperato il serial number di sistema.
3. Inserire un serial number arbitrario nella memoria prima che il payload venga crittografato e inviato.

Questo metodo ha consentito ai ricercatori di recuperare i profili DEP per serial number forniti e assegnati. Non ha reso valido un serial number arbitrario non assegnato.<sup>[[1]](#references)</sup>

### Automating Instrumentation with Python

Il processo di exploitation è stato automatizzato utilizzando Python con l'API LLDB, rendendo possibile inserire programmaticamente serial number arbitrari e recuperare i profili DEP corrispondenti.<sup>[[1]](#references)</sup>

## Revisita del 2025: Rogue Enrollment da una VM

La ricerca presentata al Black Hat Asia 2025 ha dimostrato che il problema originario del trust boundary può essere ancora rilevante a livello **MDM**: invece di patchare `cloudconfigurationd` con LLDB, i ricercatori hanno eseguito macOS sotto QEMU/KVM con OpenCore e fornito l'identità candidata tramite SMBIOS della VM. Lo stack di enrollment macOS non modificato ha quindi eseguito lo scambio crittografato con Apple. Di conseguenza, serial pubblicamente leakati e candidati dall'aspetto valido possono essere testati senza possedere il Mac fisico corrispondente; un risultato positivo richiede comunque che il serial sia assegnato a un'organizzazione e che il relativo percorso di enrollment disponga di un'autenticazione insufficiente.<sup>[[3]](#references)</sup>

Per un dispositivo di laboratorio autorizzato, i valori OpenCore `PlatformInfo` pertinenti includono un product model e un serial (nelle deployment reali anche ROM e UUID devono rimanere coerenti internamente):<sup>[[3]](#references)</sup>
```xml
<key>SystemProductName</key>
<string>iMacPro1,1</string>
<key>SystemSerialNumber</key>
<string>AUTHORIZED_TEST_SERIAL</string>
```
La stessa ricerca ha identificato lo stato `CheckProfilesFetchRateLimit` nel file privato `/var/db/ConfigurationProfiles/Settings/.profilesDEPTimerCheck`. Poiché il controllo veniva mantenuto sul client, modificare i valori temporali memorizzati lo neutralizzava. Questi percorsi non sono documentati e dipendono dalla versione, ma sono utili come punti di partenza per il reversing durante la valutazione di una build macOS attuale:<sup>[[3]](#references)</sup>
```bash
sudo plutil -p /var/db/ConfigurationProfiles/Settings/.profilesDEPTimerCheck 2>/dev/null
sudo plutil -p /var/db/ConfigurationProfiles/Settings/.cloudConfigRecordFound 2>/dev/null
```
Il secondo artifact può divulgare il record di attivazione memorizzato nella cache, incluso se il flusso utilizza una `ConfigurationURL` diretta o una `ConfigurationWebURL` autenticata. Testa sia il flusso pubblicizzato sia eventuali legacy enrollment endpoint specifici di MDM: abilitare SSO solo sul flusso web principale non protegge un endpoint diretto parallelo. Per la sequenza completa del protocollo, consulta la [panoramica di macOS MDM](README.md).<sup>[[3]](#references)</sup>

### Ricerca dei Secret dopo l'Enrollment

Un enrollment rogue è solo il punto di ingresso. Dopo l'enrollment, esamina ogni profilo distribuito, bootstrap policy, configurazione del package repository, script di installazione degli agent e elemento self-service. La ricerca del 2025 ha recuperato esempi di credenziali Wi-Fi, password condivise degli amministratori locali, URL firmati di cloud storage, URL di webhook, dati di attivazione degli agent di sicurezza e credenziali MDM/API. Una credenziale API del tenant presente in uno script distribuito può trasformare un singolo endpoint rogue in un mezzo per controllare altri device gestiti; cerca quindi sia nel filesystem attivo sia nei contenuti delle policy scaricati o memorizzati nella cache.<sup>[[3]](#references)</sup>

Gli obiettivi di revisione utili includono:<sup>[[3]](#references)</sup>

- Payload `.mobileconfig` installati e database Configuration Profiles.
- Script e package PreStage/bootstrap che creano account o installano agent EDR/VPN.
- URL di Munki o di altri package repository, in particolare le query string contenenti firme di tipo bearer/SAS.
- Cataloghi self-service e le relative policy API, incluse le route legacy che potrebbero non applicare la policy SSO dell'enrollment.
- Cronologia della shell e output delle policy memorizzato nella cache per `password`, `token`, `secret`, `Authorization`, hostname dei webhook ed endpoint API dei vendor.

### Rafforzamento del Confine di Trust

Considera un numero di serie come un attributo di inventario/routing, **non** come una prova di possesso. Richiedi l'autenticazione dell'utente per l'enrollment e il self service, genera password uniche per l'amministratore locale di ogni device e non incorporare mai credenziali API del tenant o secret riutilizzabili dell'infrastruttura nei profili o negli script. Mantieni qualsiasi bootstrap token inevitabile con una durata breve e limitato alla singola azione e al device da sottoporre a provisioning.<sup>[[3]](#references)</sup>

Sui Mac Apple silicon che eseguono macOS 14 o versioni successive, Managed Device Attestation può associare crittograficamente l'identità al Secure Enclave. La sua attestazione basata sulla root di Apple può contenere un nonce aggiornato oltre al numero di serie, all'UDID, alla versione del sistema operativo, allo stato di SIP e allo stato del secure boot; ACME può quindi emettere un'identità client associata all'hardware. Utilizza questa identità per proteggere il canale MDM e controllare l'accesso a certificati di alto valore, VPN e altre risorse, mantenendo al contempo un'autenticazione separata dell'utente, perché l'attestazione del device dimostra l'identità del device e non quella dell'operatore.<sup>[[4]](#references)</sup>

## Potenziali impatti delle vulnerabilità DEP e MDM

La ricerca ha evidenziato problemi significativi di sicurezza:

1. **Divulgazione di informazioni**: fornendo un numero di serie registrato in DEP, è possibile recuperare informazioni sensibili dell'organizzazione contenute nel profilo DEP.<sup>[[1]](#references)</sup>



## References

- [1] [Duo Labs — MDM Me Maybe: Sicurezza del Device Enrollment Program](https://duo.com/labs/research/mdm-me-maybe)
- [2] [Apple Platform Deployment — Enrollment automatizzato dei device](https://support.apple.com/guide/deployment/automated-device-enrollment-and-mdm-dep73069dd57/web)
- [3] [Black Hat Asia 2025 — Impostor Syndrome: Hacking degli Apple MDM tramite Rogue Device Enrolments](https://i.blackhat.com/Asia-25/Asia-25-Molnar-Impostor-Syndrome-Hacking-Apple-MDMs.pdf)
- [4] [Apple Platform Security — Managed Device Attestation](https://support.apple.com/guide/security/managed-device-attestation-sec8a37b4cb2/web)
{{#include ../../../banners/hacktricks-training.md}}
