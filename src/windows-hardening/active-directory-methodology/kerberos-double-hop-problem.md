# Problema del Kerberos "Double Hop"

{{#include ../../banners/hacktricks-training.md}}


## Introduzione

Il problema del Kerberos "Double Hop" si presenta quando un attacker tenta di usare **Kerberos authentication across two** **hops**, per esempio usando **PowerShell**/**WinRM**.

Quando un'**authentication** avviene tramite **Kerberos**, le **credentials** **non** vengono memorizzate nella **memory.** Quindi, se esegui mimikatz non **troverai le credentials** dell'utente sulla macchina anche se sta eseguendo processi.

Questo perché quando ci si connette con Kerberos i passaggi sono:

1. User1 fornisce le credentials e il **domain controller** restituisce un Kerberos **TGT** a User1.
2. User1 usa il **TGT** per richiedere un **service ticket** per **connettersi** a Server1.
3. User1 si **connette** a **Server1** e fornisce il **service ticket**.
4. **Server1** **non** ha in cache le **credentials** di User1 né il **TGT** di User1. Pertanto, quando User1 da Server1 prova ad autenticarsi su un secondo server, non è **in grado di autenticarsi**.

### Unconstrained Delegation

Se la **unconstrained delegation** è abilitata nel PC, questo non accade perché il **Server** riceverà un **TGT** di ogni utente che lo accede. Inoltre, se viene usata unconstrained delegation probabilmente puoi **compromettere il Domain Controller** a partire da essa.\
[**More info in the unconstrained delegation page**](unconstrained-delegation.md).

### CredSSP

Another way to avoid this problem which is [**notably insecure**](https://docs.microsoft.com/en-us/powershell/module/microsoft.wsman.management/enable-wsmancredssp?view=powershell-7) is **Credential Security Support Provider**. Da Microsoft:

> CredSSP authentication delegates the user credentials from the local computer to a remote computer. This practice increases the security risk of the remote operation. If the remote computer is compromised, when credentials are passed to it, the credentials can be used to control the network session.

È altamente raccomandato che **CredSSP** sia disabilitato su sistemi di produzione, reti sensibili e ambienti simili a causa di problemi di sicurezza. Per determinare se **CredSSP** è abilitato, può essere eseguito il comando `Get-WSManCredSSP`. Questo comando permette di verificare lo **stato di CredSSP** e può essere eseguito anche da remoto, a condizione che **WinRM** sia abilitato.
```bash
Invoke-Command -ComputerName bizintel -Credential ta\redsuit -ScriptBlock {
Get-WSManCredSSP
}
```
### Remote Credential Guard (RCG)

**Remote Credential Guard** mantiene il TGT dell'utente sulla workstation di origine pur consentendo alla sessione RDP di richiedere nuovi ticket di servizio Kerberos sul salto successivo. Abilitare **Computer Configuration > Administrative Templates > System > Credentials Delegation > Restrict delegation of credentials to remote servers** e selezionare **Require Remote Credential Guard**, poi connettersi con `mstsc.exe /remoteGuard /v:server1` invece di ricadere su CredSSP.

Microsoft ha rotto RCG per l'accesso multi-hop su Windows 11 22H2+ fino agli **aggiornamenti cumulativi di aprile 2024** (KB5036896/KB5036899/KB5036894). Applica la patch al client e al server intermedio, altrimenti il secondo salto continuerà a fallire. Controllo rapido dell'hotfix:
```powershell
("KB5036896","KB5036899","KB5036894") | ForEach-Object {
Get-HotFix -Id $_ -ErrorAction SilentlyContinue
}
```
Con quelle build installate, l'RDP hop può soddisfare le challenge Kerberos a valle senza esporre segreti riutilizzabili sul primo server.

## Soluzioni alternative

### Invoke Command

Per affrontare il problema del double hop, viene proposto un metodo che prevede un `Invoke-Command` nidificato. Questo non risolve il problema direttamente, ma offre una soluzione alternativa senza richiedere configurazioni speciali. L'approccio permette di eseguire un comando (`hostname`) su un server secondario tramite un comando PowerShell eseguito dalla macchina di attacco iniziale o tramite una `PS-Session` precedentemente stabilita con il primo server. Ecco come viene fatto:
```bash
$cred = Get-Credential ta\redsuit
Invoke-Command -ComputerName bizintel -Credential $cred -ScriptBlock {
Invoke-Command -ComputerName secdev -Credential $cred -ScriptBlock {hostname}
}
```
In alternativa, stabilire una PS-Session con il primo server ed eseguire `Invoke-Command` usando `$cred` è consigliato per centralizzare le attività.

### Register PSSession Configuration

Una soluzione per aggirare il problema del double hop consiste nell'usare `Register-PSSessionConfiguration` con `Enter-PSSession`. Questo metodo richiede un approccio diverso rispetto a `evil-winrm` e permette una sessione che non è soggetta alla limitazione del double hop.
```bash
Register-PSSessionConfiguration -Name doublehopsess -RunAsCredential domain_name\username
Restart-Service WinRM
Enter-PSSession -ConfigurationName doublehopsess -ComputerName TARGET_PC -Credential domain_name\username
klist
```
### PortForwarding

Per amministratori locali su un target intermedio, il port forwarding permette di inviare richieste a un server finale. Usando `netsh`, è possibile aggiungere una regola per il port forwarding, insieme a una regola del Windows firewall per consentire la porta inoltrata.
```bash
netsh interface portproxy add v4tov4 listenport=5446 listenaddress=10.35.8.17 connectport=5985 connectaddress=10.35.8.23
netsh advfirewall firewall add rule name=fwd dir=in action=allow protocol=TCP localport=5446
```
#### winrs.exe

`winrs.exe` può essere usato per inoltrare richieste WinRM, potenzialmente come opzione meno rilevabile se il monitoraggio di PowerShell è una preoccupazione. Il comando seguente ne dimostra l'uso:
```bash
winrs -r:http://bizintel:5446 -u:ta\redsuit -p:2600leet hostname
```
### OpenSSH

Installare OpenSSH sul primo server abilita una soluzione alternativa per il problema del double-hop, particolarmente utile negli scenari con jump box. Questo metodo richiede l'installazione via CLI e la configurazione di OpenSSH per Windows. Quando configurato per Password Authentication, questo permette al server intermediario di ottenere un TGT per conto dell'utente.

#### Passaggi di installazione di OpenSSH

1. Scaricare e spostare l'ultima release zip di OpenSSH sul server di destinazione.
2. Decomprimere ed eseguire lo script `Install-sshd.ps1`.
3. Aggiungere una regola firewall per aprire la porta 22 e verificare che i servizi SSH siano in esecuzione.

Per risolvere gli errori `Connection reset`, potrebbe essere necessario aggiornare i permessi per consentire a Everyone l'accesso in lettura ed esecuzione sulla directory OpenSSH.
```bash
icacls.exe "C:\Users\redsuit\Documents\ssh\OpenSSH-Win64" /grant Everyone:RX /T
```
### LSA Whisperer CacheLogon (Avanzato)

**LSA Whisperer** (2024) espone la chiamata del package `msv1_0!CacheLogon` in modo da poter iniettare un NT hash noto in un *network logon* esistente invece di creare una nuova sessione con `LogonUser`. Iniettando l'hash nella sessione di logon che WinRM/PowerShell ha già aperto sul hop #1, quell'host può autenticarsi all'hop #2 senza memorizzare credenziali esplicite o generare eventi 4624 aggiuntivi.

1. Ottieni esecuzione di codice all'interno di LSASS (disabilitando o abusando di PPL oppure eseguendo su una VM di laboratorio che controlli).
2. Enumera le sessioni di logon (es. `lsa.exe sessions`) e cattura il LUID corrispondente al tuo contesto di remoting.
3. Pre-calcola l'NT hash e fornisci il valore a `CacheLogon`, poi rimuovilo quando hai finito.
```powershell
lsa.exe cachelogon --session 0x3e4 --domain ta --username redsuit --nthash a7c5480e8c1ef0ffec54e99275e6e0f7
lsa.exe cacheclear --session 0x3e4
```
Dopo il cache seed, rieseguire `Invoke-Command`/`New-PSSession` da hop #1: LSASS riutilizzerà l'hash iniettato per soddisfare le challenge Kerberos/NTLM per il secondo hop, bypassando così il vincolo del double hop. Il compromesso è una telemetria più intensa (esecuzione di codice in LSASS), quindi riservalo ad ambienti ad alta frizione dove CredSSP/RCG non sono consentiti.

## Riferimenti

- [https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/understanding-kerberos-double-hop/ba-p/395463?lightbox-message-images-395463=102145i720503211E78AC20](https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/understanding-kerberos-double-hop/ba-p/395463?lightbox-message-images-395463=102145i720503211E78AC20)
- [https://posts.slayerlabs.com/double-hop/](https://posts.slayerlabs.com/double-hop/)
- [https://learn.microsoft.com/en-gb/archive/blogs/sergey_babkins_blog/another-solution-to-multi-hop-powershell-remoting](https://learn.microsoft.com/en-gb/archive/blogs/sergey_babkins_blog/another-solution-to-multi-hop-powershell-remoting)
- [https://4sysops.com/archives/solve-the-powershell-multi-hop-problem-without-using-credssp/](https://4sysops.com/archives/solve-the-powershell-multi-hop-problem-without-using-credssp/)
- [https://support.microsoft.com/en-au/topic/april-9-2024-kb5036896-os-build-17763-5696-efb580f1-2ce4-4695-b76c-d2068a00fb92](https://support.microsoft.com/en-au/topic/april-9-2024-kb5036896-os-build-17763-5696-efb580f1-2ce4-4695-b76c-d2068a00fb92)
- [https://specterops.io/blog/2024/04/17/lsa-whisperer/](https://specterops.io/blog/2024/04/17/lsa-whisperer/)


{{#include ../../banners/hacktricks-training.md}}
