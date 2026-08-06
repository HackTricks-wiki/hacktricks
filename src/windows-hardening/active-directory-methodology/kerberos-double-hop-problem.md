# Problema del Kerberos Double Hop

{{#include ../../banners/hacktricks-training.md}}


## Introduzione

Il problema del Kerberos "Double Hop" si presenta quando un attacker tenta di utilizzare l'**autenticazione Kerberos attraverso due** **hop**, ad esempio usando **PowerShell**/**WinRM**.

Quando avviene un'**autenticazione** tramite **Kerberos**, le **credenziali** **non** vengono memorizzate nella **memoria**. Pertanto, se esegui mimikatz, **non troverai le credenziali** dell'utente sulla macchina, anche se l'utente sta eseguendo dei processi.

Questo accade perché, quando ci si connette con Kerberos, i passaggi sono i seguenti:<sup>[[1]](#references)</sup>

1. L'User1 fornisce le credenziali e il **domain controller** restituisce un **TGT** Kerberos all'User1.
2. L'User1 utilizza il **TGT** per richiedere un **service ticket** per **connettersi** al Server1.
3. L'User1 **si connette** al **Server1** e fornisce il **service ticket**.
4. Il **Server1** **non** dispone delle **credenziali** dell'User1 memorizzate né del **TGT** dell'User1. Pertanto, quando l'User1 dal Server1 tenta di effettuare il login a un secondo server, **non è in grado di autenticarsi**.

### Unconstrained Delegation

Se sul PC è abilitata la **unconstrained delegation**, questo non accadrà, poiché il **Server** **otterrà** un **TGT** di ogni utente che vi accede. Inoltre, se viene utilizzata la unconstrained delegation, probabilmente puoi **compromettere il Domain Controller** da quel sistema.\
[**Ulteriori informazioni nella pagina sulla unconstrained delegation**](unconstrained-delegation.md).

### CredSSP

Un altro modo per evitare questo problema, [**notoriamente insicuro**](https://docs.microsoft.com/en-us/powershell/module/microsoft.wsman.management/enable-wsmancredssp?view=powershell-7), è il **Credential Security Support Provider**. Da Microsoft:

> L'autenticazione CredSSP delega le credenziali dell'utente dal computer locale a un computer remoto. Questa pratica aumenta il rischio per la sicurezza dell'operazione remota. Se il computer remoto è compromesso quando gli vengono passate le credenziali, queste possono essere utilizzate per controllare la sessione di rete.

È altamente consigliato disabilitare **CredSSP** sui sistemi di produzione, sulle reti sensibili e in ambienti simili a causa dei rischi per la sicurezza. Per determinare se **CredSSP** è abilitato, è possibile eseguire il comando `Get-WSManCredSSP`. Questo comando consente di **verificare lo stato di CredSSP** e può persino essere eseguito da remoto, a condizione che **WinRM** sia abilitato.
```bash
Invoke-Command -ComputerName bizintel -Credential ta\redsuit -ScriptBlock {
Get-WSManCredSSP
}
```
### Remote Credential Guard (RCG)

**Remote Credential Guard** mantiene il TGT dell'utente sulla workstation di origine, consentendo comunque alla sessione RDP di richiedere nuovi service ticket Kerberos al next hop. Abilita **Computer Configuration > Administrative Templates > System > Credentials Delegation > Restrict delegation of credentials to remote servers** e seleziona **Require Remote Credential Guard**, quindi connettiti con `mstsc.exe /remoteGuard /v:server1` invece di ricorrere a CredSSP.

Microsoft ha interrotto il funzionamento di RCG per l'accesso multi-hop su Windows 11 22H2+ fino agli **aggiornamenti cumulativi di aprile 2024** (KB5036896/KB5036899/KB5036894). Applica le patch al client e al server intermedio, altrimenti il secondo hop continuerà a non funzionare.<sup>[[5]](#references)</sup> Verifica rapida degli hotfix:
```powershell
("KB5036896","KB5036899","KB5036894") | ForEach-Object {
Get-HotFix -Id $_ -ErrorAction SilentlyContinue
}
```
Con queste build installate, l'hop RDP può soddisfare le richieste Kerberos downstream senza esporre secret riutilizzabili sul primo server.

## Soluzioni alternative

### Invoke Command

Per affrontare il problema del double hop, viene presentato un metodo che utilizza un `Invoke-Command` annidato. Questo non risolve direttamente il problema, ma offre una soluzione alternativa senza richiedere configurazioni speciali. L'approccio consente di eseguire un comando (`hostname`) su un server secondario tramite un comando PowerShell eseguito da una macchina di attacco iniziale o tramite una PS-Session precedentemente stabilita con il primo server. Ecco come procedere:<sup>[[2]](#references)</sup>
```bash
$cred = Get-Credential ta\redsuit
Invoke-Command -ComputerName bizintel -Credential $cred -ScriptBlock {
Invoke-Command -ComputerName secdev -Credential $cred -ScriptBlock {hostname}
}
```
In alternativa, è consigliato stabilire una PS-Session con il primo server ed eseguire `Invoke-Command` utilizzando `$cred` per centralizzare le attività.

### Register PSSession Configuration

Una soluzione per bypassare il problema del double hop consiste nell'utilizzare `Register-PSSessionConfiguration` con `Enter-PSSession`. Questo metodo richiede un approccio diverso rispetto a `evil-winrm` e consente di utilizzare una sessione che non è soggetta alla limitazione del double hop.<sup>[[3]](#references)[[4]](#references)</sup>
```bash
Register-PSSessionConfiguration -Name doublehopsess -RunAsCredential domain_name\username
Restart-Service WinRM
Enter-PSSession -ConfigurationName doublehopsess -ComputerName TARGET_PC -Credential domain_name\username
klist
```
### PortForwarding

Per gli amministratori locali di un target intermedio, il port forwarding consente di inviare richieste a un server finale. Utilizzando `netsh`, è possibile aggiungere una regola per il port forwarding, insieme a una regola del firewall di Windows per consentire la porta inoltrata.<sup>[[2]](#references)</sup>
```bash
netsh interface portproxy add v4tov4 listenport=5446 listenaddress=10.35.8.17 connectport=5985 connectaddress=10.35.8.23
netsh advfirewall firewall add rule name=fwd dir=in action=allow protocol=TCP localport=5446
```
#### winrs.exe

`winrs.exe` può essere utilizzato per inoltrare richieste WinRM, potenzialmente come opzione meno rilevabile se il monitoraggio di PowerShell rappresenta un problema.<sup>[[2]](#references)</sup> Il comando seguente ne dimostra l'utilizzo:
```bash
winrs -r:http://bizintel:5446 -u:ta\redsuit -p:2600leet hostname
```
### OpenSSH

Installare OpenSSH sul primo server abilita una soluzione alternativa al problema del double-hop, particolarmente utile negli scenari con jump box. Questo metodo richiede l'installazione e la configurazione di OpenSSH per Windows tramite CLI. Se configurato con Password Authentication, consente al server intermediario di ottenere un TGT per conto dell'utente.<sup>[[2]](#references)</sup>

#### Passaggi per l'installazione di OpenSSH

1. Scaricare e spostare l'ultima release zip di OpenSSH sul server target.
2. Decomprimere ed eseguire lo script `Install-sshd.ps1`.
3. Aggiungere una regola firewall per aprire la porta 22 e verificare che i servizi SSH siano in esecuzione.

Per risolvere gli errori `Connection reset`, potrebbe essere necessario aggiornare i permessi per consentire a everyone l'accesso in lettura ed esecuzione alla directory OpenSSH.
```bash
icacls.exe "C:\Users\redsuit\Documents\ssh\OpenSSH-Win64" /grant Everyone:RX /T
```
### LSA Whisperer CacheLogon (Advanced)

**LSA Whisperer** (2024) espone la chiamata al package `msv1_0!CacheLogon`, permettendo di inserire un NT hash noto in un *network logon* esistente invece di creare una nuova sessione con `LogonUser`. Iniettando l'hash nella logon session che WinRM/PowerShell ha già aperto sull'hop #1, quell'host può autenticarsi all'hop #2 senza memorizzare credenziali esplicite o generare eventi 4624 aggiuntivi.<sup>[[6]](#references)</sup>

1. Ottieni l'esecuzione di codice all'interno di LSASS (disabilitando/abusando di PPL oppure eseguendo l'operazione su una lab VM sotto il tuo controllo).
2. Enumera le logon session (ad esempio, `lsa.exe sessions`) e acquisisci il LUID corrispondente al tuo contesto di remoting.
3. Pre-calcola l'NT hash e passalo a `CacheLogon`, quindi cancellalo al termine.
```powershell
lsa.exe cachelogon --session 0x3e4 --domain ta --username redsuit --nthash a7c5480e8c1ef0ffec54e99275e6e0f7
lsa.exe cacheclear --session 0x3e4
```
Dopo il cache seed, esegui nuovamente `Invoke-Command`/`New-PSSession` dall'hop #1: LSASS riutilizzerà l'hash iniettato per soddisfare le challenge Kerberos/NTLM per il secondo hop, aggirando efficacemente il vincolo del double hop. Il compromesso consiste in una telemetria più intensa (esecuzione di codice in LSASS), quindi riservalo agli ambienti ad alta frizione in cui CredSSP/RCG non sono consentiti.

## Riferimenti

- [1] [Informazioni sul Kerberos Double Hop - Microsoft Community Hub](https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/understanding-kerberos-double-hop/ba-p/395463?lightbox-message-images-395463=102145i720503211E78AC20)
- [2] [Soluzioni alternative al Kerberos Double-Hop](https://posts.slayerlabs.com/double-hop/)
- [3] [Un'altra soluzione per il PowerShell remoting multi-hop](https://learn.microsoft.com/en-gb/archive/blogs/sergey_babkins_blog/another-solution-to-multi-hop-powershell-remoting)
- [4] [Risolvere il problema del PowerShell multi-hop senza usare CredSSP](https://4sysops.com/archives/solve-the-powershell-multi-hop-problem-without-using-credssp/)
- [5] [9 aprile 2024—KB5036896 (OS Build 17763.5696)](https://support.microsoft.com/en-au/topic/april-9-2024-kb5036896-os-build-17763-5696-efb580f1-2ce4-4695-b76c-d2068a00fb92)
- [6] [LSA Whisperer](https://specterops.io/blog/2024/04/17/lsa-whisperer/)

{{#include ../../banners/hacktricks-training.md}}
