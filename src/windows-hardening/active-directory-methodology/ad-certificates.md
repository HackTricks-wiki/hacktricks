# Certificati AD

{{#include ../../banners/hacktricks-training.md}}

## Introduzione

### Componenti di un certificato

- Il **Subject** del certificato indica il suo proprietario.
- Una **Public Key** è accoppiata con una chiave privata per collegare il certificato al legittimo proprietario.
- Il **Validity Period**, definito dalle date **NotBefore** e **NotAfter**, indica la durata di validità del certificato.
- Un **Serial Number** univoco, fornito dalla Certificate Authority (CA), identifica ogni certificato.
- L'**Issuer** si riferisce alla CA che ha emesso il certificato.
- **SubjectAlternativeName** permette nomi aggiuntivi per il subject, aumentando la flessibilità d'identificazione.
- **Basic Constraints** identificano se il certificato è per una CA o per un'entità finale e definiscono restrizioni d'uso.
- Le **Extended Key Usages (EKUs)** determinano gli scopi specifici del certificato, come code signing o crittografia email, tramite Object Identifiers (OIDs).
- Il **Signature Algorithm** specifica il metodo usato per firmare il certificato.
- La **Signature**, creata con la chiave privata dell'issuer, garantisce l'autenticità del certificato.

### Considerazioni speciali

- Le **Subject Alternative Names (SANs)** estendono l'applicabilità di un certificato a più identità, cruciale per server con domini multipli. Processi di emissione sicuri sono vitali per evitare rischi di impersonificazione da parte di un attacker che manipola la specifica SAN.

### Certificate Authorities (CAs) in Active Directory (AD)

AD CS riconosce i certificati CA in una foresta AD tramite contenitori designati, ognuno con ruoli differenti:

- Il contenitore **Certification Authorities** contiene i certificati root CA fidati.
- Il contenitore **Enrolment Services** dettaglia le Enterprise CAs e i rispettivi certificate templates.
- L'oggetto **NTAuthCertificates** include i certificati CA autorizzati per l'autenticazione AD.
- Il contenitore **AIA (Authority Information Access)** facilita la validazione della catena di certificati con certificati intermediate e cross CA.

### Certificate Acquisition: Client Certificate Request Flow

1. Il processo di richiesta inizia con i client che individuano una Enterprise CA.
2. Viene creato un CSR, contenente una public key e altri dettagli, dopo la generazione della coppia chiave pubblica-privata.
3. La CA valuta il CSR in base ai certificate templates disponibili, emettendo il certificato sulla base dei permessi del template.
4. Una volta approvato, la CA firma il certificato con la sua chiave privata e lo restituisce al client.

### Certificate Templates

Definiti all'interno di AD, questi template descrivono le impostazioni e i permessi per l'emissione dei certificati, inclusi gli EKU permessi e i diritti di enrollment o modifica, critici per gestire l'accesso ai servizi di certificazione.

La versione dello schema del template è importante. I template legacy **v1** (per esempio, il built-in **WebServer**) sono privi di molte moderne leve di enforcement. La ricerca **ESC15/EKUwu** ha mostrato che sui template **v1**, un requester può inserire **Application Policies/EKUs** nel CSR che vengono **preferite rispetto** agli EKU configurati nel template, permettendo certificati client-auth, enrollment agent, o code-signing con soli diritti di enrollment. Preferire template **v2/v3**, rimuovere o sovrascrivere i default v1, e limitare strettamente gli EKU allo scopo previsto.

## Iscrizione dei certificati

Il processo di iscrizione per i certificati è avviato da un amministratore che **crea un certificate template**, che viene poi **pubblicato** da una Enterprise Certificate Authority (CA). Questo rende il template disponibile per l'enrollment dei client, operazione ottenuta aggiungendo il nome del template al campo `certificatetemplates` di un oggetto Active Directory.

Perché un client possa richiedere un certificato, devono essere concessi i **diritti di enrollment**. Questi diritti sono definiti dai security descriptor sul certificate template e sulla Enterprise CA stessa. I permessi devono essere concessi in entrambi i punti affinché la richiesta abbia successo.

### Diritti di enrollment sul template

Questi diritti sono specificati attraverso Access Control Entries (ACE), che descrivono permessi come:

- i diritti **Certificate-Enrollment** e **Certificate-AutoEnrollment**, ciascuno associato a specifici GUID.
- **ExtendedRights**, che consentono tutti i permessi estesi.
- **FullControl/GenericAll**, che forniscono il controllo completo sul template.

### Diritti di enrollment sull'Enterprise CA

I diritti della CA sono delineati nel suo security descriptor, accessibile tramite la console di gestione Certificate Authority. Alcune impostazioni permettono anche l'accesso remoto a utenti con privilegi limitati, il che può rappresentare un problema di sicurezza.

### Controlli aggiuntivi di emissione

Possono applicarsi controlli aggiuntivi, come:

- **Manager Approval**: mette le richieste in stato pending fino all'approvazione da parte di un certificate manager.
- **Enrolment Agents and Authorized Signatures**: specificano il numero di firme richieste su un CSR e gli Application Policy OIDs necessari.

### Metodi per richiedere certificati

I certificati possono essere richiesti tramite:

1. Il **Windows Client Certificate Enrollment Protocol** (MS-WCCE), usando interfacce DCOM.
2. L'**ICertPassage Remote Protocol** (MS-ICPR), attraverso named pipes o TCP/IP.
3. L'**interfaccia web di certificate enrollment**, con il ruolo Certificate Authority Web Enrollment installato.
4. Il **Certificate Enrollment Service** (CES), in combinazione con il servizio Certificate Enrollment Policy (CEP).
5. Il **Network Device Enrollment Service** (NDES) per dispositivi di rete, usando il Simple Certificate Enrollment Protocol (SCEP).

Gli utenti Windows possono anche richiedere certificati tramite GUI (`certmgr.msc` o `certlm.msc`) o strumenti da riga di comando (`certreq.exe` o il comando PowerShell `Get-Certificate`).
```bash
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```
## Autenticazione tramite certificato

Active Directory (AD) supporta l'autenticazione tramite certificati, utilizzando principalmente i protocolli **Kerberos** e **Secure Channel (Schannel)**.

### Processo di autenticazione Kerberos

Nel processo di autenticazione Kerberos, la richiesta dell'utente per un Ticket Granting Ticket (TGT) viene firmata usando la **chiave privata** del certificato dell'utente. Questa richiesta viene sottoposta a diverse verifiche da parte del domain controller, incluse la **validità**, il **path** e lo **stato di revoca** del certificato. Le verifiche includono anche la conferma che il certificato provenga da una fonte attendibile e la presenza dell'emittente nel **NTAUTH certificate store**. Se le verifiche hanno esito positivo, viene emesso un TGT. L'oggetto **`NTAuthCertificates`** in AD, si trova in:
```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```
è centrale per stabilire la fiducia per l'autenticazione basata su certificato.

### Autenticazione Secure Channel (Schannel)

Schannel facilita connessioni TLS/SSL sicure, dove durante l'handshake il client presenta un certificato che, se convalidato con successo, autorizza l'accesso. L'associazione di un certificato a un account AD può coinvolgere la funzione di Kerberos **S4U2Self** o il **Subject Alternative Name (SAN)** del certificato, tra gli altri metodi.

### AD Certificate Services Enumeration

I servizi di certificazione di AD possono essere enumerati tramite query LDAP, rivelando informazioni su **Enterprise Certificate Authorities (CAs)** e le loro configurazioni. Questo è accessibile a qualsiasi utente autenticato nel dominio senza privilegi speciali. Strumenti come **[Certify](https://github.com/GhostPack/Certify)** e **[Certipy](https://github.com/ly4k/Certipy)** vengono usati per l'enumerazione e la valutazione delle vulnerabilità negli ambienti AD CS.

I comandi per utilizzare questi strumenti includono:
```bash
# Enumerate trusted root CA certificates and Enterprise CAs with Certify
Certify.exe cas
# Identify vulnerable certificate templates with Certify
Certify.exe find /vulnerable

# Use Certipy (>=4.0) for enumeration and identifying vulnerable templates
certipy find -vulnerable -dc-only -u john@corp.local -p Passw0rd -target dc.corp.local

# Request a certificate over the web enrollment interface (new in Certipy 4.x)
certipy req -web -target ca.corp.local -template WebServer -upn john@corp.local -dns www.corp.local

# Enumerate Enterprise CAs and certificate templates with certutil
certutil.exe -TCAInfo
certutil -v -dstemplate
```
{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

---

## Recent Vulnerabilities & Security Updates (2022-2025)

| Year | ID / Name | Impact | Key Take-aways |
|------|-----------|--------|----------------|
| 2022 | **CVE-2022-26923** – “Certifried” / ESC6 | *Privilege escalation* by spoofing machine account certificates during PKINIT. | Patch is included in the **May 10 2022** security updates. Auditing & strong-mapping controls were introduced via **KB5014754**; environments should now be in *Full Enforcement* mode.  |
| 2023 | **CVE-2023-35350 / 35351** | *Remote code-execution* in the AD CS Web Enrollment (certsrv) and CES roles. | Public PoCs are limited, but the vulnerable IIS components are often exposed internally. Patch as of **July 2023** Patch Tuesday.  |
| 2024 | **CVE-2024-49019** – “EKUwu” / ESC15 | On **v1 templates**, a requester with enrollment rights can embed **Application Policies/EKUs** in the CSR that are preferred over the template EKUs, producing client-auth, enrollment agent, or code-signing certificates. | Patched as of **November 12, 2024**. Replace or supersede v1 templates (e.g., default WebServer), restrict EKUs to intent, and limit enrollment rights. |

### Microsoft hardening timeline (KB5014754)

Microsoft introduced a three-phase rollout (Compatibility → Audit → Enforcement) to move Kerberos certificate authentication away from weak implicit mappings. As of **February 11 2025**, domain controllers automatically switch to **Full Enforcement** if the `StrongCertificateBindingEnforcement` registry value is not set. Administrators should:

1. Patch all DCs & AD CS servers (May 2022 or later).
2. Monitor Event ID 39/41 for weak mappings during the *Audit* phase.
3. Re-issue client-auth certificates with the new **SID extension** or configure strong manual mappings before February 2025.

---

## Detection & Hardening Enhancements

* **Defender for Identity AD CS sensor (2023-2024)** now surfaces posture assessments for ESC1-ESC8/ESC11 and generates real-time alerts such as *“Domain-controller certificate issuance for a non-DC”* (ESC8) and *“Prevent Certificate Enrollment with arbitrary Application Policies”* (ESC15). Ensure sensors are deployed to all AD CS servers to benefit from these detections.
* Disable or tightly scope the **“Supply in the request”** option on all templates; prefer explicitly defined SAN/EKU values.
* Remove **Any Purpose** or **No EKU** from templates unless absolutely required (addresses ESC2 scenarios).
* Require **manager approval** or dedicated Enrollment Agent workflows for sensitive templates (e.g., WebServer / CodeSigning).
* Restrict web enrollment (`certsrv`) and CES/NDES endpoints to trusted networks or behind client-certificate authentication.
* Enforce RPC enrollment encryption (`certutil -setreg CA\InterfaceFlags +IF_ENFORCEENCRYPTICERTREQUEST`) to mitigate ESC11 (RPC relay). The flag is **on by default**, but is often disabled for legacy clients, which re-opens relay risk.
* Secure **IIS-based enrollment endpoints** (CES/Certsrv): disable NTLM where possible or require HTTPS + Extended Protection to block ESC8 relays.

---



## Riferimenti

- [https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)
- [https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/certificates](https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/certificates)
- [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)
- [https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html](https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html)
- [https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [https://advisory.eventussecurity.com/advisory/critical-vulnerability-in-ad-cs-allows-privilege-escalation/](https://advisory.eventussecurity.com/advisory/critical-vulnerability-in-ad-cs-allows-privilege-escalation/)
{{#include ../../banners/hacktricks-training.md}}
