# Persistenza di dominio AD CS

{{#include ../../../banners/hacktricks-training.md}}

**Questa è una sintesi delle tecniche di persistenza di dominio condivise in [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)**. Consultalo per ulteriori dettagli.<sup>[[5]](#references)</sup>

## Falsificazione di certificati con certificati CA rubati (Golden Certificate) - DPERSIST1

Come si può determinare se un certificato è un certificato CA?

È possibile determinare che un certificato è un certificato CA se vengono soddisfatte diverse condizioni:<sup>[[5]](#references)</sup>

- Il certificato è archiviato sul server CA, con la relativa chiave privata protetta dal DPAPI della macchina o da hardware come un TPM/HSM, se il sistema operativo lo supporta.
- I campi Issuer e Subject del certificato corrispondono al distinguished name della CA.
- Nei certificati CA è presente esclusivamente un'estensione "CA Version".
- Il certificato non contiene campi Extended Key Usage (EKU).

Per estrarre la chiave privata di questo certificato, lo strumento `certsrv.msc` sul server CA è il metodo supportato tramite la GUI integrata. Tuttavia, questo certificato non differisce dagli altri archiviati nel sistema; pertanto, per l'estrazione è possibile applicare tecniche come la [THEFT2 technique](certificate-theft.md#user-certificate-theft-via-dpapi-theft2).

Il certificato e la chiave privata possono essere ottenuti anche utilizzando Certipy con il seguente comando:<sup>[[2]](#references)</sup>
```bash
certipy ca 'corp.local/administrator@ca.corp.local' -hashes :123123.. -backup
```
Dopo aver ottenuto il certificato CA e la relativa chiave privata in formato `.pfx`, è possibile utilizzare strumenti come [ForgeCert](https://github.com/GhostPack/ForgeCert) per generare certificati validi:
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
> L'utente preso di mira per la falsificazione del certificato deve essere attivo e in grado di autenticarsi in Active Directory affinché il processo abbia esito positivo. Falsificare un certificato per account speciali come krbtgt è inefficace.

Questo certificato falsificato sarà **valido** fino alla data di scadenza specificata e **finché il certificato della CA radice sarà valido** (solitamente da 5 a **oltre 10 anni**). È valido anche per le **macchine**, quindi, combinato con **S4U2Self**, un attacker può **mantenere la persistenza su qualsiasi macchina del dominio** finché il certificato della CA rimane valido.\
Inoltre, i **certificati generati** con questo metodo **non possono essere revocati**, poiché la CA non ne è a conoscenza.

### Operare con Strong Certificate Mapping Enforcement (2025+)

Dal 11 febbraio 2025 (dopo il rollout di KB5014754), i domain controller utilizzano per impostazione predefinita **Full Enforcement** per i certificate mappings. In pratica, ciò significa che i certificati falsificati devono:

- Contenere un strong binding all'account di destinazione (ad esempio, l'estensione SID security), oppure
- Essere associati a un mapping esplicito e strong sull'attributo `altSecurityIdentities` dell'oggetto di destinazione.<sup>[[1]](#references)</sup>

Un approccio affidabile per la persistenza consiste nel generare un certificato falsificato concatenato alla Enterprise CA rubata e quindi aggiungere un mapping esplicito e strong al principal vittima:
```powershell
# Example: map a forged cert to a target account using Issuer+Serial (strong mapping)
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'           # reverse DN format expected by AD
$SerialR = '1200000000AC11000000002B'                  # serial in reversed byte order
$Map     = "X509:<I>$Issuer<SR>$SerialR"             # strong mapping format
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
Note
- Se puoi creare certificati contraffatti che includano l'estensione di sicurezza SID, questi verranno mappati implicitamente anche in modalità Full Enforcement. Altrimenti, preferisci mapping forti espliciti. Consulta [account-persistence](account-persistence.md) per maggiori informazioni sui mapping espliciti.
- La revoca non aiuta i difensori in questo caso: i certificati contraffatti sono sconosciuti al database della CA e pertanto non possono essere revocati.

#### Forging compatibile con Full Enforcement (consapevole del SID)

Gli strumenti aggiornati consentono di incorporare direttamente il SID, mantenendo utilizzabili i golden certificates anche quando i DC rifiutano i mapping deboli:<sup>[[3]](#references)</sup>
```bash
# Certify 2.0 integrates ForgeCert and can embed SID
Certify.exe forge --ca-pfx CORP-DC-CA.pfx --ca-pass Password123! \
--upn administrator@corp.local --sid S-1-5-21-1111111111-2222222222-3333333333-500 \
--outfile administrator_sid.pfx

# Certipy also supports SID in forged certs
certipy forge -ca-pfx CORP-DC-CA.pfx -upn administrator@corp.local \
-sid S-1-5-21-1111111111-2222222222-3333333333-500 -out administrator_sid.pfx
```
Incorporando il SID si evita di dover modificare `altSecurityIdentities`, che potrebbe essere monitorato, continuando comunque a soddisfare i controlli di strong mapping.

## Trusting Rogue CA Certificates - DPERSIST2

L'oggetto `NTAuthCertificates` è definito per contenere uno o più **certificati CA** nel relativo attributo `cacertificate`, utilizzato da Active Directory (AD). Il processo di verifica eseguito dal **domain controller** consiste nel controllare l'oggetto `NTAuthCertificates` alla ricerca di una voce corrispondente alla **CA specificata** nel campo Issuer del **certificato** usato per l'autenticazione. L'autenticazione procede se viene trovata una corrispondenza.<sup>[[5]](#references)</sup>

Un certificato CA self-signed può essere aggiunto da un attacker all'oggetto `NTAuthCertificates`, a condizione che abbia il controllo su questo oggetto AD. Normalmente, solo i membri del gruppo **Enterprise Admin**, insieme ai **Domain Admins** o agli **Administrators** del **dominio root della forest**, dispongono dell'autorizzazione per modificare questo oggetto. Possono modificare l'oggetto `NTAuthCertificates` utilizzando `certutil.exe` con il comando `certutil.exe -dspublish -f C:\Temp\CERT.crt NTAuthCA`, oppure usando il [**PKI Health Tool**](https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/import-third-party-ca-to-enterprise-ntauth-store#method-1---import-a-certificate-by-using-the-pki-health-tool).

Altri comandi utili per questa tecnica:
```bash
# Add/remove and inspect the Enterprise NTAuth store
certutil -enterprise -f -AddStore NTAuth C:\Temp\CERT.crt
certutil -enterprise -viewstore NTAuth
certutil -enterprise -delstore NTAuth <Thumbprint>

# (Optional) publish into AD CA containers to improve chain building across the forest
certutil -dspublish -f C:\Temp\CERT.crt RootCA          # CN=Certification Authorities
certutil -dspublish -f C:\Temp\CERT.crt CA               # CN=AIA
```
Questa capacità è particolarmente rilevante se utilizzata insieme al metodo descritto in precedenza che prevede l'uso di ForgeCert per generare dinamicamente certificati.

> Considerazioni sul mapping successive al 2025: inserire una CA rogue in NTAuth stabilisce solo la fiducia nella CA emittente. Per utilizzare i certificati leaf per il logon quando i DC sono in **Full Enforcement**, il leaf deve contenere l'estensione di sicurezza SID oppure deve esistere un strong mapping esplicito sull'oggetto di destinazione (ad esempio, Issuer+Serial in `altSecurityIdentities`). Vedere {{#ref}}account-persistence.md{{#endref}}.

## Misconfiguration malevola - DPERSIST3

Le opportunità di ottenere **persistence** tramite modifiche ai descrittori di sicurezza dei componenti di AD CS sono numerose. Le modifiche descritte nella sezione "[Domain Escalation](domain-escalation.md)" possono essere implementate in modo malevolo da un attacker con accesso elevato. Ciò include l'aggiunta di "control rights" (ad es. WriteOwner/WriteDACL/ecc.) a componenti sensibili come:<sup>[[5]](#references)</sup>

- L'oggetto **AD computer del server CA**
- Il **server RPC/DCOM del server CA**
- Qualsiasi **oggetto o container AD discendente** in **`CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`** (ad esempio, il container Certificate Templates, il container Certification Authorities, l'oggetto NTAuthCertificates, ecc.)
- I **gruppi AD a cui sono stati delegati diritti per controllare AD CS** per impostazione predefinita o dall'organizzazione (come il gruppo integrato Cert Publishers e qualsiasi suo membro)

Un esempio di implementazione malevola prevederebbe che un attacker, in possesso di **permessi elevati** nel dominio, aggiunga il permesso **`WriteOwner`** al template di certificato predefinito **`User`**, diventando il principal associato al diritto. Per sfruttare questa situazione, l'attacker cambierebbe innanzitutto la proprietà del template **`User`** assegnandola a sé stesso. Successivamente, imposterebbe **`mspki-certificate-name-flag`** su **1** nel template per abilitare **`ENROLLEE_SUPPLIES_SUBJECT`**, consentendo a un utente di fornire un Subject Alternative Name nella richiesta. In seguito, l'attacker potrebbe effettuare l'**enroll** utilizzando il **template**, scegliendo il nome di un **domain administrator** come nome alternativo, e utilizzare il certificato ottenuto per autenticarsi come DA.

Impostazioni pratiche che gli attacker possono configurare per ottenere persistence a lungo termine nel dominio (vedere {{#ref}}domain-escalation.md{{#endref}} per i dettagli completi e il rilevamento):

- Flag delle policy della CA che consentono il SAN fornito dai richiedenti (ad es. abilitando `EDITF_ATTRIBUTESUBJECTALTNAME2`). Ciò mantiene sfruttabili i percorsi simili a ESC1.
- DACL o impostazioni del template che consentono l'emissione abilitata all'autenticazione (ad es. aggiungendo Client Authentication EKU, abilitando `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`).
- Il controllo dell'oggetto `NTAuthCertificates` o dei container della CA per reintrodurre continuamente issuer rogue se i defender tentano una pulizia.

> [!TIP]
> Negli ambienti hardened dopo KB5014754, associare queste misconfiguration a strong mapping espliciti (`altSecurityIdentities`) garantisce che i certificati emessi o forgiati restino utilizzabili anche quando i DC applicano lo strong mapping.

### Abuso del rinnovo dei certificati (ESC14) per la persistence

Se comprometti un certificato abilitato all'autenticazione (o un certificato Enrollment Agent), puoi **rinnovarlo indefinitamente** finché il template emittente rimane pubblicato e la CA continua a fidarsi della catena dell'issuer. Il rinnovo mantiene i binding dell'identità originale ma ne estende la validità, rendendo difficile l'espulsione dell'attacker a meno che il template non venga corretto o la CA non venga ripubblicata.<sup>[[4]](#references)</sup>
```bash
# Renew a stolen user cert to extend validity
certipy req -ca CORP-DC-CA -template User -pfx stolen_user.pfx -renew -out user_renewed_2026.pfx

# Renew an on-behalf-of cert issued via an Enrollment Agent
certipy req -ca CORP-DC-CA -on-behalf-of 'CORP/victim' -pfx agent.pfx -renew -out victim_renewed.pfx
```
Se i domain controller sono in **Full Enforcement**, aggiungi `-sid <victim SID>` (oppure usa un template che includa ancora l'estensione di sicurezza SID), così il certificato leaf rinnovato continuerà a essere mappato in modo strong senza modificare `altSecurityIdentities`. Gli attacker con diritti di amministratore della CA possono anche modificare `policy\RenewalValidityPeriodUnits` per estendere la durata dei certificati rinnovati prima di emettere un certificato a proprio nome.<sup>[[2]](#references)[[4]](#references)</sup>


## References

- [1] [Microsoft KB5014754 – Modifiche all'autenticazione basata su certificati nei domain controller Windows (tempistiche dell'enforcement e strong mappings)](https://support.microsoft.com/en-au/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [2] [Certipy – Riferimento ai comandi e utilizzo di forge/auth](https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference)
- [3] [SpecterOps – Certify 2.0 (forge integrato con supporto SID)](https://specterops.io/blog/2025/08/11/certify-2-0/)
- [4] [Panoramica dell'abuso del rinnovo ESC14](https://www.adcs-security.com/attacks/esc14)
- [5] [SpecterOps – Certified Pre-Owned: Abuso di Active Directory Certificate Services](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)

{{#include ../../../banners/hacktricks-training.md}}
