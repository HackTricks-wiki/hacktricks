# Persistenza del dominio AD CS

{{#include ../../../banners/hacktricks-training.md}}

**Questa è una sintesi delle tecniche di persistenza del dominio condivise in [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)**. Consultalo per ulteriori dettagli.

## Forging Certificates with Stolen CA Certificates - DPERSIST1

How can you tell that a certificate is a CA certificate?

Si può determinare che un certificato è un certificato CA se sono soddisfatte diverse condizioni:

- Il certificato è memorizzato sul CA server, con la sua chiave privata protetta dal DPAPI della macchina, o da hardware come TPM/HSM se il sistema operativo lo supporta.
- Entrambi i campi Issuer e Subject del certificato corrispondono al distinguished name della CA.
- Un'estensione "CA Version" è presente esclusivamente nei certificati CA.
- Il certificato non contiene campi Extended Key Usage (EKU).

Per estrarre la chiave privata di questo certificato, lo strumento `certsrv.msc` sul CA server è il metodo supportato tramite la GUI integrata. Tuttavia, questo certificato non differisce dagli altri memorizzati nel sistema; pertanto, possono essere applicati metodi come la [THEFT2 technique](certificate-theft.md#user-certificate-theft-via-dpapi-theft2) per l'estrazione.

Il certificato e la chiave privata possono essere ottenuti anche usando Certipy con il seguente comando:
```bash
certipy ca 'corp.local/administrator@ca.corp.local' -hashes :123123.. -backup
```
Dopo aver ottenuto il certificato CA e la sua chiave privata in formato `.pfx`, strumenti come [ForgeCert](https://github.com/GhostPack/ForgeCert) possono essere utilizzati per generare certificati validi:
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
> L'utente preso di mira per la falsificazione del certificato deve essere attivo e in grado di autenticarsi in Active Directory affinché il processo abbia successo. Falsificare un certificato per account speciali come krbtgt non è efficace.

Questo certificato falsificato sarà **valido** fino alla data di scadenza specificata e **finché il certificato root CA rimane valido** (di solito da 5 a **10+ anni**). È inoltre valido per le **macchine**, quindi combinato con **S4U2Self**, un attaccante può **mantenere persistenza su qualsiasi macchina del dominio** per tutto il periodo di validità del certificato CA.\
Inoltre, i **certificati generati** con questo metodo **non possono essere revocati** poiché la CA non è a conoscenza di essi.

### Operare sotto Strong Certificate Mapping Enforcement (2025+)

Dal 11 febbraio 2025 (dopo il rollout di KB5014754), i domain controllers impostano di default **Full Enforcement** per le mappature dei certificati. Praticamente questo significa che i tuoi certificati falsificati devono o:

- Contenere un'associazione forte all'account di destinazione (per esempio, l'estensione di sicurezza SID), oppure
- Essere abbinati a una mappatura esplicita e forte sull'attributo `altSecurityIdentities` dell'oggetto di destinazione.

Un approccio affidabile per la persistenza è emettere un certificato falsificato con catena alla Enterprise CA rubata e poi aggiungere una mappatura esplicita forte al principal vittima:
```powershell
# Example: map a forged cert to a target account using Issuer+Serial (strong mapping)
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'           # reverse DN format expected by AD
$SerialR = '1200000000AC11000000002B'                  # serial in reversed byte order
$Map     = "X509:<I>$Issuer<SR>$SerialR"             # strong mapping format
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
Note
- Se puoi creare certificati contraffatti che includono la SID security extension, questi verranno mappati implicitamente anche sotto Full Enforcement. Altrimenti, preferisci mappature esplicite e robuste. Vedi [account-persistence](account-persistence.md) per maggiori dettagli sulle mappature esplicite.
- La revoca qui non aiuta i difensori: i certificati contraffatti non sono noti al database della CA e quindi non possono essere revocati.

## Fiducia in Rogue CA Certificates - DPERSIST2

L'oggetto `NTAuthCertificates` è definito per contenere uno o più **CA certificates** nel suo attributo `cacertificate`, utilizzato da Active Directory (AD). Il processo di verifica da parte del **domain controller** consiste nel controllare l'oggetto `NTAuthCertificates` per un'entrata che corrisponda alla **CA specified** nel campo Issuer del **certificate** che sta autenticando. L'autenticazione procede se viene trovato un match.

Un certificato CA self-signed può essere aggiunto all'oggetto `NTAuthCertificates` da un attacker, a condizione che abbia il controllo su questo oggetto AD. Normalmente, solo i membri del gruppo **Enterprise Admin**, insieme a **Domain Admins** o **Administrators** nel **forest root’s domain**, hanno il permesso di modificare questo oggetto. Possono modificare l'oggetto `NTAuthCertificates` usando `certutil.exe` con il comando `certutil.exe -dspublish -f C:\Temp\CERT.crt NTAuthCA`, oppure impiegando il [**PKI Health Tool**](https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/import-third-party-ca-to-enterprise-ntauth-store#method-1---import-a-certificate-by-using-the-pki-health-tool).

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
Questa capability è particolarmente rilevante quando utilizzata in combinazione con un metodo descritto in precedenza che impiega ForgeCert per generare dinamicamente certificati.

> Considerazioni sulla mappatura post-2025: inserire una rogue CA in NTAuth stabilisce solo la fiducia nella CA emittente. Per usare certificati leaf per il logon quando i DCs sono in **Full Enforcement**, il leaf deve o contenere l'estensione di sicurezza SID oppure deve esistere una mappatura esplicita forte sull'oggetto target (per esempio, Issuer+Serial in `altSecurityIdentities`). Vedi {{#ref}}account-persistence.md{{#endref}}.

## Misconfigurazione malevola - DPERSIST3

Le opportunità per la **persistenza** tramite modifiche ai descrittori di sicurezza dei componenti di **AD CS** sono numerose. Le modifiche descritte nella sezione "[Domain Escalation](domain-escalation.md)" possono essere implementate in modo malevolo da un attaccante con accesso elevato. Questo include l'aggiunta di "control rights" (ad es., WriteOwner/WriteDACL/etc.) a componenti sensibili come:

- Il **CA server’s AD computer** object
- Il **CA server’s RPC/DCOM server**
- Qualsiasi **descendant AD object or container** in **`CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`** (per esempio, il container Certificate Templates, il container Certification Authorities, l'oggetto NTAuthCertificates, ecc.)
- **AD groups delegated rights to control AD CS** per impostazione predefinita o dall'organizzazione (come il built-in Cert Publishers group e qualunque suo membro)

Un esempio di implementazione malevola coinvolgerebbe un attaccante, con **permissi elevati** nel dominio, che aggiunge il permesso **`WriteOwner`** al template di certificato predefinito **`User`**, rendendo l'attaccante il principal per quel diritto. Per sfruttare ciò, l'attaccante cambierebbe innanzitutto la proprietà del template **`User`** su se stesso. Successivamente, il **`mspki-certificate-name-flag`** verrebbe impostato a **1** sul template per abilitare **`ENROLLEE_SUPPLIES_SUBJECT`**, permettendo a un utente di fornire un Subject Alternative Name nella richiesta. Dopodiché, l'attaccante potrebbe **enroll** usando il **template**, scegliendo un nome di **domain administrator** come alternative name, e utilizzare il certificato ottenuto per autenticarsi come DA.

Impostazioni pratiche che gli attaccanti possono configurare per la persistenza a lungo termine nel dominio (vedi {{#ref}}domain-escalation.md{{#endref}} per dettagli completi e rilevamento):

- CA policy flags che consentono SAN dai richiedenti (es., abilitando `EDITF_ATTRIBUTESUBJECTALTNAME2`). Questo mantiene percorsi simili a ESC1 sfruttabili.
- DACL o impostazioni del template che permettono emissione con capacità di autenticazione (es., aggiungendo Client Authentication EKU, abilitando `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`).
- Controllare l'oggetto `NTAuthCertificates` o i container CA per re-introdurre continuamente issuer rogue se i difensori tentano il cleanup.

> [!TIP]
> Negli ambienti hardenati dopo KB5014754, abbinare queste misconfigurazioni a mappature esplicite forti (`altSecurityIdentities`) garantisce che i certificati emessi o forgiati rimangano utilizzabili anche quando i DCs impongono la mappatura forte.



## Riferimenti

- Microsoft KB5014754 – Modifiche all'autenticazione basata su certificati sui Windows domain controllers (enforcement timeline e strong mappings). https://support.microsoft.com/en-au/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16
- Certipy – Command Reference and forge/auth usage. https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference
{{#include ../../../banners/hacktricks-training.md}}
