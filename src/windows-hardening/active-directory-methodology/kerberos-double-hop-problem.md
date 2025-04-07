# Kerberos Double Hop Problem

{{#include ../../banners/hacktricks-training.md}}


## Introduzione

Il problema del "Double Hop" di Kerberos si presenta quando un attaccante tenta di utilizzare **l'autenticazione Kerberos attraverso due** **hops**, ad esempio utilizzando **PowerShell**/**WinRM**.

Quando si verifica un'**autenticazione** tramite **Kerberos**, le **credenziali** **non** vengono memorizzate in **memoria.** Pertanto, se esegui mimikatz **non troverai le credenziali** dell'utente nella macchina anche se sta eseguendo processi.

Questo perché, quando ci si connette con Kerberos, questi sono i passaggi:

1. User1 fornisce le credenziali e il **domain controller** restituisce un **TGT** Kerberos a User1.
2. User1 utilizza il **TGT** per richiedere un **service ticket** per **connettersi** a Server1.
3. User1 **si connette** a **Server1** e fornisce il **service ticket**.
4. **Server1** **non** ha le **credenziali** di User1 memorizzate o il **TGT** di User1. Pertanto, quando User1 da Server1 cerca di accedere a un secondo server, **non riesce ad autenticarsi**.

### Delegazione Non Vincolata

Se la **delegazione non vincolata** è abilitata nel PC, questo non accadrà poiché il **Server** **otterrà** un **TGT** di ogni utente che vi accede. Inoltre, se viene utilizzata la delegazione non vincolata, probabilmente puoi **compromettere il Domain Controller** da esso.\
[**Ulteriori informazioni nella pagina sulla delegazione non vincolata**](unconstrained-delegation.md).

### CredSSP

Un altro modo per evitare questo problema, che è [**notevolmente insicuro**](https://docs.microsoft.com/en-us/powershell/module/microsoft.wsman.management/enable-wsmancredssp?view=powershell-7), è il **Credential Security Support Provider**. Da Microsoft:

> L'autenticazione CredSSP delega le credenziali dell'utente dal computer locale a un computer remoto. Questa pratica aumenta il rischio di sicurezza dell'operazione remota. Se il computer remoto viene compromesso, quando le credenziali vengono passate a esso, le credenziali possono essere utilizzate per controllare la sessione di rete.

Si raccomanda vivamente di disabilitare **CredSSP** sui sistemi di produzione, reti sensibili e ambienti simili a causa di preoccupazioni di sicurezza. Per determinare se **CredSSP** è abilitato, è possibile eseguire il comando `Get-WSManCredSSP`. Questo comando consente di **verificare lo stato di CredSSP** e può anche essere eseguito in remoto, a condizione che **WinRM** sia abilitato.
```bash
Invoke-Command -ComputerName bizintel -Credential ta\redsuit -ScriptBlock {
Get-WSManCredSSP
}
```
## Soluzioni alternative

### Invoke Command

Per affrontare il problema del double hop, viene presentato un metodo che coinvolge un `Invoke-Command` annidato. Questo non risolve direttamente il problema, ma offre una soluzione alternativa senza necessitare di configurazioni speciali. L'approccio consente di eseguire un comando (`hostname`) su un server secondario tramite un comando PowerShell eseguito da una macchina di attacco iniziale o attraverso una PS-Session precedentemente stabilita con il primo server. Ecco come si fa:
```bash
$cred = Get-Credential ta\redsuit
Invoke-Command -ComputerName bizintel -Credential $cred -ScriptBlock {
Invoke-Command -ComputerName secdev -Credential $cred -ScriptBlock {hostname}
}
```
In alternativa, si suggerisce di stabilire una PS-Session con il primo server ed eseguire il `Invoke-Command` utilizzando `$cred` per centralizzare i compiti.

### Registrare la Configurazione PSSession

Una soluzione per bypassare il problema del doppio salto prevede l'uso di `Register-PSSessionConfiguration` con `Enter-PSSession`. Questo metodo richiede un approccio diverso rispetto a `evil-winrm` e consente una sessione che non soffre della limitazione del doppio salto.
```bash
Register-PSSessionConfiguration -Name doublehopsess -RunAsCredential domain_name\username
Restart-Service WinRM
Enter-PSSession -ConfigurationName doublehopsess -ComputerName <pc_name> -Credential domain_name\username
klist
```
### PortForwarding

Per gli amministratori locali su un obiettivo intermedio, il port forwarding consente di inviare richieste a un server finale. Utilizzando `netsh`, è possibile aggiungere una regola per il port forwarding, insieme a una regola del firewall di Windows per consentire la porta inoltrata.
```bash
netsh interface portproxy add v4tov4 listenport=5446 listenaddress=10.35.8.17 connectport=5985 connectaddress=10.35.8.23
netsh advfirewall firewall add rule name=fwd dir=in action=allow protocol=TCP localport=5446
```
#### winrs.exe

`winrs.exe` può essere utilizzato per inoltrare richieste WinRM, potenzialmente come un'opzione meno rilevabile se il monitoraggio di PowerShell è una preoccupazione. Il comando qui sotto ne dimostra l'uso:
```bash
winrs -r:http://bizintel:5446 -u:ta\redsuit -p:2600leet hostname
```
### OpenSSH

L'installazione di OpenSSH sul primo server consente una soluzione per il problema del double-hop, particolarmente utile per scenari di jump box. Questo metodo richiede l'installazione e la configurazione di OpenSSH per Windows tramite CLI. Quando configurato per l'autenticazione con password, questo consente al server intermedio di ottenere un TGT per conto dell'utente.

#### Passaggi per l'installazione di OpenSSH

1. Scarica e sposta l'ultima versione zip di OpenSSH sul server di destinazione.
2. Decomprimi ed esegui lo script `Install-sshd.ps1`.
3. Aggiungi una regola del firewall per aprire la porta 22 e verifica che i servizi SSH siano in esecuzione.

Per risolvere gli errori `Connection reset`, potrebbe essere necessario aggiornare i permessi per consentire a tutti l'accesso in lettura ed esecuzione sulla directory di OpenSSH.
```bash
icacls.exe "C:\Users\redsuit\Documents\ssh\OpenSSH-Win64" /grant Everyone:RX /T
```
## Riferimenti

- [https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/understanding-kerberos-double-hop/ba-p/395463?lightbox-message-images-395463=102145i720503211E78AC20](https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/understanding-kerberos-double-hop/ba-p/395463?lightbox-message-images-395463=102145i720503211E78AC20)
- [https://posts.slayerlabs.com/double-hop/](https://posts.slayerlabs.com/double-hop/)
- [https://learn.microsoft.com/en-gb/archive/blogs/sergey_babkins_blog/another-solution-to-multi-hop-powershell-remoting](https://learn.microsoft.com/en-gb/archive/blogs/sergey_babkins_blog/another-solution-to-multi-hop-powershell-remoting)
- [https://4sysops.com/archives/solve-the-powershell-multi-hop-problem-without-using-credssp/](https://4sysops.com/archives/solve-the-powershell-multi-hop-problem-without-using-credssp/)


{{#include ../../banners/hacktricks-training.md}}
