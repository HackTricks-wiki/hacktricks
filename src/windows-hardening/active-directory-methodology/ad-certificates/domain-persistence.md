# AD CS Domain Persistence

{{#include ../../../banners/hacktricks-training.md}}

**Questa è una sintesi delle tecniche di persistenza nel dominio condivise in [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)**. Consulta il documento per ulteriori dettagli.

## Falsificazione di certificati con certificati CA rubati - DPERSIST1

Come puoi riconoscere che un certificato è un certificato CA?

Si può determinare che un certificato è un certificato CA se sono soddisfatte diverse condizioni:

- Il certificato è memorizzato sul server CA, con la sua chiave privata protetta dal DPAPI della macchina, oppure da hardware come TPM/HSM se il sistema operativo lo supporta.
- I campi Issuer e Subject del certificato corrispondono al distinguished name della CA.
- Un'estensione "CA Version" è presente esclusivamente nei certificati CA.
- Il certificato è privo dei campi Extended Key Usage (EKU).

Per estrarre la chiave privata di questo certificato, lo strumento `certsrv.msc` sul server CA è il metodo supportato tramite l'interfaccia grafica integrata. Tuttavia, questo certificato non differisce dagli altri memorizzati nel sistema; di conseguenza, possono essere applicati metodi come la [THEFT2 technique](certificate-theft.md#user-certificate-theft-via-dpapi-theft2) per l'estrazione.

Il certificato e la chiave privata possono anche essere ottenuti utilizzando Certipy con il seguente comando:
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

Questo certificato falsificato sarà **valido** fino alla data di scadenza specificata e finché il certificato root CA è valido (di solito da 5 a **10+ anni**). È anche valido per le **macchine**, quindi, combinato con **S4U2Self**, un attaccante può **mantenere la persistenza su qualsiasi macchina del dominio** per tutto il periodo di validità del certificato CA.\
Inoltre, i **certificati generati** con questo metodo **non possono essere revocati**, poiché la CA non ne è a conoscenza.

### Operare con Strong Certificate Mapping Enforcement (2025+)

Dal 11 febbraio 2025 (dopo il rollout di KB5014754), i domain controller impostano per default **Full Enforcement** per le mappature dei certificati. In pratica ciò significa che i tuoi certificati falsificati devono o:

- Contenere un legame forte con l'account di destinazione (per esempio, la SID security extension), oppure
- Essere abbinati a una mappatura esplicita e forte nell'attributo `altSecurityIdentities` dell'oggetto di destinazione.

Un approccio affidabile per la persistenza è emettere un certificato falsificato concatenato all'Enterprise CA rubata e poi aggiungere una mappatura esplicita e forte al principal della vittima:
```powershell
# Example: map a forged cert to a target account using Issuer+Serial (strong mapping)
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'           # reverse DN format expected by AD
$SerialR = '1200000000AC11000000002B'                  # serial in reversed byte order
$Map     = "X509:<I>$Issuer<SR>$SerialR"             # strong mapping format
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
Note
- Se puoi creare certificati falsificati che includono l'estensione di sicurezza SID, questi verranno mappati implicitamente anche con Full Enforcement. Altrimenti, preferisci mappature esplicite e robuste. Vedi
[account-persistence](account-persistence.md) per ulteriori informazioni sulle mappature esplicite.
- La revoca non aiuta i difensori qui: i certificati falsificati sono sconosciuti al database CA e quindi non possono essere revocati.

## Trusting Rogue CA Certificates - DPERSIST2

The `NTAuthCertificates` object is defined to contain one or more **certificati CA** within its `cacertificate` attribute, which Active Directory (AD) utilizes. The verification process by the **controller di dominio** involves checking the `NTAuthCertificates` object for an entry matching the **CA specificata** in the Issuer field of the authenticating **certificato**. Authentication proceeds if a match is found.

Un certificato CA self-signed può essere aggiunto all'oggetto `NTAuthCertificates` da un attaccante, a condizione che abbia il controllo su questo oggetto AD. Normalmente, solo i membri del gruppo **Enterprise Admin**, insieme a **Domain Admins** o **Administrators** nel **forest root’s domain**, hanno il permesso di modificare questo oggetto. Possono modificare l'oggetto `NTAuthCertificates` usando `certutil.exe` con il comando `certutil.exe -dspublish -f C:\Temp\CERT.crt NTAuthCA`, oppure impiegando lo [**PKI Health Tool**](https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/import-third-party-ca-to-enterprise-ntauth-store#method-1---import-a-certificate-by-using-the-pki-health-tool).

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
Questa capacità è particolarmente rilevante quando usata insieme a un metodo descritto in precedenza che utilizza ForgeCert per generare dinamicamente certificati.

> Post-2025 mapping considerations: placing a rogue CA in NTAuth only establishes trust in the issuing CA. To use leaf certificates for logon when DCs are in **Full Enforcement**, the leaf must either contain the SID security extension or there must be a strong explicit mapping on the target object (for example, Issuer+Serial in `altSecurityIdentities`). See {{#ref}}account-persistence.md{{#endref}}.

## Configurazione malevola - DPERSIST3

Le opportunità per **persistence** tramite modifiche dei security descriptor dei componenti di **AD CS** sono numerose. Le modifiche descritte nella sezione "[Domain Escalation](domain-escalation.md)" possono essere implementate in modo malevolo da un attacker con accesso elevato. Questo include l'aggiunta di "control rights" (ad es., WriteOwner/WriteDACL/etc.) a componenti sensibili quali:

- L'oggetto **computer AD del CA server**
- Il **server RPC/DCOM del CA server**
- Qualsiasi **oggetto AD discendente o contenitore** in **`CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`** (ad esempio, il Certificate Templates container, il Certification Authorities container, l'oggetto NTAuthCertificates, ecc.)
- **AD groups delegati con diritti di controllo su AD CS** di default o dalla organizzazione (come il gruppo incorporato Cert Publishers e qualsiasi suo membro)

Un esempio di implementazione malevola coinvolgerebbe un attacker, che ha **elevated permissions** nel dominio, che aggiunge il permesso **`WriteOwner`** al template di certificato di default **`User`**, con l'attaccante come principale per il diritto. Per sfruttare ciò, l'attaccante cambierebbe prima la proprietà del template **`User`** su se stesso. Successivamente, la **`mspki-certificate-name-flag`** verrebbe impostata a **1** sul template per abilitare **`ENROLLEE_SUPPLIES_SUBJECT`**, permettendo a un utente di fornire un Subject Alternative Name nella richiesta. In seguito, l'attaccante potrebbe **enroll** usando il **template**, scegliendo come nome alternativo un **domain administrator**, e utilizzare il certificato acquisito per l'autenticazione come DA.

Impostazioni pratiche che un attacker può configurare per la persistence a lungo termine nel dominio (vedi {{#ref}}domain-escalation.md{{#endref}} per dettagli completi e rilevamento):

- Flag di policy della CA che permettono SAN dalle richieste (ad es., abilitare `EDITF_ATTRIBUTESUBJECTALTNAME2`). Questo mantiene percorsi simili a ESC1 sfruttabili.
- DACL del template o impostazioni che permettono issuance con capacità di autenticazione (ad es., aggiungere Client Authentication EKU, abilitare `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`).
- Controllare l'oggetto `NTAuthCertificates` o i container della CA per reintrodurre continuamente issuer rogue se i defenders tentano di pulire.

> [!TIP]
> In ambienti hardenizzati dopo KB5014754, accoppiare queste misconfigurazioni con mappature esplicite e forti (`altSecurityIdentities`) assicura che i certificati emessi o forged rimangano utilizzabili anche quando i DC applicano il strong mapping.



## Riferimenti

- Microsoft KB5014754 – Certificate-based authentication changes on Windows domain controllers (enforcement timeline and strong mappings). https://support.microsoft.com/en-au/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16
- Certipy – Command Reference and forge/auth usage. https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference
{{#include ../../../banners/hacktricks-training.md}}
