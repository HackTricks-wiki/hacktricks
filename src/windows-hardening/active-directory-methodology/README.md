# Active Directory Methodology

{{#include ../../banners/hacktricks-training.md}}

## Visão geral básica

**Active Directory** serve como uma tecnologia fundamental, permitindo que **network administrators** criem e gerenciem de forma eficiente **domains**, **users** e **objects** dentro de uma rede. Foi projetado para escalar, facilitando a organização de um grande número de usuários em **groups** e **subgroups** gerenciáveis, enquanto controla **access rights** em vários níveis.

A estrutura do **Active Directory** é composta por três camadas principais: **domains**, **trees** e **forests**. Um **domain** engloba uma coleção de objects, como **users** ou **devices**, que compartilham um banco de dados comum. **Trees** são grupos desses domains ligados por uma estrutura compartilhada, e uma **forest** representa a coleção de múltiplas trees, interconectadas através de **trust relationships**, formando a camada superior da estrutura organizacional. Direitos específicos de **access** e **communication** podem ser designados em cada um desses níveis.

Conceitos-chave dentro do **Active Directory** incluem:

1. **Directory** – Abriga todas as informações referentes aos objetos do Active Directory.
2. **Object** – Denota entidades dentro do directory, incluindo **users**, **groups**, ou **shared folders**.
3. **Domain** – Serve como um contêiner para directory objects, com a capacidade de múltiplos domains coexistirem dentro de uma **forest**, cada um mantendo sua própria coleção de objects.
4. **Tree** – Um agrupamento de domains que compartilham um domínio raiz comum.
5. **Forest** – O ponto mais alto da estrutura organizacional no Active Directory, composto por várias trees com **trust relationships** entre elas.

**Active Directory Domain Services (AD DS)** engloba uma gama de serviços críticos para o gerenciamento centralizado e comunicação dentro de uma rede. Esses serviços compreendem:

1. **Domain Services** – Centraliza o armazenamento de dados e gerencia interações entre **users** e **domains**, incluindo **authentication** e funcionalidades de **search**.
2. **Certificate Services** – Supervisiona a criação, distribuição e gerenciamento de **digital certificates** seguros.
3. **Lightweight Directory Services** – Suporta aplicações habilitadas para directory através do **LDAP protocol**.
4. **Directory Federation Services** – Fornece capacidades de **single-sign-on** para autenticar usuários em múltiplas aplicações web em uma única sessão.
5. **Rights Management** – Ajuda a proteger material com direitos autorais regulando sua distribuição e uso não autorizados.
6. **DNS Service** – Crucial para a resolução de **domain names**.

For a more detailed explanation check: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

To learn how to **attack an AD** you need to **understand** really good the **Kerberos authentication process**.\
[**Read this page if you still don't know how it works.**](kerberos-authentication.md)

## Cheat Sheet

Você pode acessar [https://wadcoms.github.io/](https://wadcoms.github.io) para ter uma visão rápida de quais comandos você pode executar para enumerar/explorar um AD.

> [!WARNING]
> Kerberos communication **requires a full qualifid name (FQDN)** for performing actions. If you try to access a machine by the IP address, **it'll use NTLM and not kerberos**.

## Recon Active Directory (No creds/sessions)

Se você apenas tem acesso a um ambiente AD mas não possui credenciais/sessões você poderia:

- **Pentest the network:**
- Escanear a rede, encontrar máquinas e portas abertas e tentar **exploit vulnerabilities** ou **extract credentials** delas (por exemplo, [printers could be very interesting targets](ad-information-in-printers.md)).
- A enumeração de DNS pode fornecer informações sobre servidores chave no domain como web, printers, shares, vpn, media, etc.
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- Dê uma olhada na [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md) geral para encontrar mais informações sobre como fazer isso.
- **Check for null and Guest access on smb services** (isso não funcionará em versões modernas do Windows):
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- Um guia mais detalhado sobre como enumerar um SMB server pode ser encontrado aqui:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Enumerar LDAP**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- Um guia mais detalhado sobre como enumerar LDAP pode ser encontrado aqui (preste **atenção especial ao acesso anônimo**):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Poison the network**
- Coletar credenciais [**impersonating services with Responder**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
- Acessar hosts [**abusing the relay attack**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
- Coletar credenciais **exposing** [**fake UPnP services with evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- Extrair usernames/nomes de documentos internos, redes sociais, serviços (principalmente web) dentro dos ambientes do domain e também dos disponíveis publicamente.
- Se você encontrar os nomes completos dos funcionários da empresa, você pode tentar diferentes convenções de username do AD (**read this**). As convenções mais comuns são: _NameSurname_, _Name.Surname_, _NamSur_ (3letters of each), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 _random letters and 3 random numbers_ (abc123).
- Ferramentas:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### User enumeration

- **Anonymous SMB/LDAP enum:** Veja as páginas [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) e [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md).
- **Kerbrute enum**: Quando um **invalid username is requested** o servidor responderá usando o código de erro do **Kerberos** _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_, permitindo que determinemoss que o username era inválido. **Valid usernames** provocarão ou o **TGT in a AS-REP** como resposta ou o erro _KRB5KDC_ERR_PREAUTH_REQUIRED_, indicando que o usuário é obrigado a realizar pre-authentication.
- **No Authentication against MS-NRPC**: Usando auth-level = 1 (No authentication) contra a interface MS-NRPC (Netlogon) em domain controllers. O método chama a função `DsrGetDcNameEx2` após vincular a interface MS-NRPC para verificar se o usuário ou computador existe sem qualquer credencial. A ferramenta [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) implementa esse tipo de enumeração. A pesquisa pode ser encontrada [here](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **OWA (Outlook Web Access) Server**

Se você encontrar um destes servidores na rede, também pode realizar **user enumeration** contra ele. Por exemplo, você pode usar a ferramenta [**MailSniper**](https://github.com/dafthack/MailSniper):
```bash
ipmo C:\Tools\MailSniper\MailSniper.ps1
# Get info about the domain
Invoke-DomainHarvestOWA -ExchHostname [ip]
# Enumerate valid users from a list of potential usernames
Invoke-UsernameHarvestOWA -ExchHostname [ip] -Domain [domain] -UserList .\possible-usernames.txt -OutFile valid.txt
# Password spraying
Invoke-PasswordSprayOWA -ExchHostname [ip] -UserList .\valid.txt -Password Summer2021
# Get addresses list from the compromised mail
Get-GlobalAddressList -ExchHostname [ip] -UserName [domain]\[username] -Password Summer2021 -OutFile gal.txt
```
> [!WARNING]
> Você pode encontrar listas de usernames em [**this github repo**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names) e neste ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)).
>
> No entanto, você deve ter o **nome das pessoas que trabalham na empresa** a partir da etapa de recon que você deveria ter realizado antes. Com o nome e sobrenome você pode usar o script [**namemash.py**](https://gist.github.com/superkojiman/11076951) para gerar potenciais usernames válidos.

### Knowing one or several usernames

Ok, então você já sabe que tem um username válido, mas sem senhas... Então tente:

- [**ASREPRoast**](asreproast.md): Se um usuário **não tem** o atributo _DONT_REQ_PREAUTH_ você pode **solicitar uma AS_REP message** para esse usuário que conterá alguns dados criptografados por uma derivação da senha do usuário.
- [**Password Spraying**](password-spraying.md): Vamos tentar as senhas mais **comuns** com cada um dos usuários descobertos, talvez algum usuário esteja usando uma senha fraca (lembre-se da policy de senhas!).
- Note que você também pode **spray OWA servers** para tentar obter acesso aos servidores de email dos usuários.


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

Você pode ser capaz de **obter** alguns **hashes de challenge** para quebrar ao **poison** alguns protocolos da **rede**:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Se você conseguiu enumerar o active directory terá **mais emails e um melhor entendimento da rede**. Você pode ser capaz de forçar NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) para obter acesso ao ambiente AD.

### Steal NTLM Creds

Se você consegue **acessar outros PCs ou shares** com o **null or guest user** você poderia **colocar arquivos** (como um SCF file) que se de alguma forma acessados irão t**acionem uma autenticação NTLM contra você** para que você possa **roubar** o **NTLM challenge** para crackear:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

## Enumerating Active Directory WITH credentials/session

Para esta fase você precisa ter **comprometido as credenciais ou uma sessão de uma conta de domínio válida.** Se você tem algumas credenciais válidas ou um shell como um usuário de domínio, **lembre-se que as opções dadas antes ainda são opções para comprometer outros usuários**.

Antes de iniciar a enumeração autenticada você deve saber qual é o **Kerberos double hop problem.**


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeration

Ter comprometido uma conta é um **grande passo para começar a comprometer todo o domínio**, porque você poderá iniciar a **Active Directory Enumeration:**

Em relação ao [**ASREPRoast**](asreproast.md) você agora pode encontrar todo usuário potencialmente vulnerável, e em relação ao [**Password Spraying**](password-spraying.md) você pode obter uma **lista de todos os usernames** e tentar a senha da conta comprometida, senhas vazias e novas senhas promissoras.

- Você poderia usar o [**CMD to perform a basic recon**](../basic-cmd-for-pentesters.md#domain-info)
- Você também pode usar [**powershell for recon**](../basic-powershell-for-pentesters/index.html) que será mais stealthy
- Você também pode [**use powerview**](../basic-powershell-for-pentesters/powerview.md) para extrair informações mais detalhadas
- Outra ferramenta incrível para recon em um active directory é [**BloodHound**](bloodhound.md). Não é **muito stealthy** (dependendo dos métodos de coleta que você usar), mas **se você não se importar** com isso, deveria definitivamente experimentar. Encontre onde usuários podem RDP, caminhos para outros grupos, etc.
- **Outras ferramentas automatizadas de enumeração AD são:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- [**DNS records of the AD**](ad-dns-records.md) pois eles podem conter informação interessante.
- Uma **ferramenta com GUI** que você pode usar para enumerar o diretório é **AdExplorer.exe** do **SysInternal** Suite.
- Você também pode procurar no banco LDAP com **ldapsearch** para procurar credenciais em campos _userPassword_ & _unixUserPassword_, ou mesmo em _Description_. cf. [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) para outros métodos.
- Se você está usando **Linux**, você também pode enumerar o domínio usando [**pywerview**](https://github.com/the-useless-one/pywerview).
- Você também pode tentar ferramentas automatizadas como:
- [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
- [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Extraindo todos os usuários do domínio**

É muito fácil obter todos os usernames do domínio a partir do Windows (`net user /domain` ,`Get-DomainUser` ou `wmic useraccount get name,sid`). No Linux, você pode usar: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` ou `enum4linux -a -u "user" -p "password" <DC IP>`

> Mesmo que esta seção Enumeration pareça pequena, esta é a parte mais importante de todas. Acesse os links (principalmente os de cmd, powershell, powerview e BloodHound), aprenda como enumerar um domínio e pratique até se sentir confortável. Durante uma avaliação, este será o momento chave para encontrar seu caminho até DA ou para decidir que nada pode ser feito.

### Kerberoast

Kerberoasting envolve obter **TGS tickets** usados por serviços ligados a contas de usuário e quebrar sua criptografia — que é baseada nas senhas dos usuários — **offline**.

Mais sobre isso em:


{{#ref}}
kerberoast.md
{{#endref}}

### Remote connexion (RDP, SSH, FTP, Win-RM, etc)

Uma vez que você obteve algumas credenciais você pode checar se tem acesso a alguma **máquina**. Para isso, você poderia usar **CrackMapExec** para tentar conectar em vários servidores com diferentes protocolos, de acordo com seus scans de portas.

### Local Privilege Escalation

Se você comprometeu credenciais ou uma sessão como um usuário comum de domínio e você tem **acesso** com esse usuário a **qualquer máquina no domínio** você deve tentar encontrar um caminho para **escalar privilégios localmente e saquear por credenciais**. Isso porque somente com privilégios de administrador local você será capaz de **dump hashes de outros usuários** na memória (LSASS) e localmente (SAM).

Há uma página completa neste livro sobre [**local privilege escalation in Windows**](../windows-local-privilege-escalation/index.html) e um [**checklist**](../checklist-windows-privilege-escalation.md). Além disso, não esqueça de usar [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite).

### Current Session Tickets

É muito **improvável** que você encontre **tickets** no usuário atual **dando permissão para acessar** recursos inesperados, mas você poderia verificar:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

Se você conseguiu enumerar o active directory terá **mais e-mails e uma melhor compreensão da rede**. Você pode ser capaz de forçar NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**.**

### Looks for Creds in Computer Shares | SMB Shares

Agora que você tem algumas credentials básicas, deve verificar se consegue **encontrar** algum **arquivo interessante sendo compartilhado dentro do AD**. Você poderia fazer isso manualmente, mas é uma tarefa muito chata e repetitiva (e mais ainda se encontrar centenas de docs para checar).

[**Siga este link para aprender sobre ferramentas que você poderia usar.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steal NTLM Creds

Se você consegue **acessar outros PCs ou shares** pode **colocar arquivos** (como um arquivo SCF) que, se de algum modo acessados, vão **disparar uma autenticação NTLM contra você** para que você possa **roubar** o **NTLM challenge** e crackeá-lo:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Essa vulnerabilidade permitia que qualquer usuário autenticado **comprometesse o domain controller**.


{{#ref}}
printnightmare.md
{{#endref}}

## Privilege escalation on Active Directory WITH privileged credentials/session

**Para as técnicas a seguir um usuário de domínio regular não é suficiente — você precisa de algumas privileges/credentials especiais para executar esses ataques.**

### Hash extraction

Idealmente você conseguiu **comprometer alguma conta local admin** usando [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) incluindo relaying, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [escalating privileges locally](../windows-local-privilege-escalation/index.html).\
Então, é hora de extrair todos os hashes da memória e localmente.\
[**Leia esta página sobre diferentes maneiras de obter os hashes.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Uma vez que você tem o hash de um usuário**, pode usá-lo para **se passar** por ele.\
Você precisa usar alguma **ferramenta** que **realize** a **autenticação NTLM usando** esse **hash**, **ou** pode criar um novo **sessionlogon** e **injetar** esse **hash** dentro do **LSASS**, assim quando qualquer **autenticação NTLM for executada**, aquele **hash será usado.** A última opção é o que o mimikatz faz.\
[**Leia esta página para mais informações.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Esse ataque tem como objetivo **usar o NTLM hash do usuário para solicitar tickets Kerberos**, como alternativa ao comum Pass The Hash sobre o protocolo NTLM. Portanto, isso pode ser especialmente **útil em redes onde o protocolo NTLM está desabilitado** e apenas **Kerberos é permitido** como protocolo de autenticação.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

No método de ataque Pass The Ticket (PTT), os atacantes **roubam o ticket de autenticação de um usuário** em vez da sua senha ou valores de hash. Esse ticket roubado é então usado para **se passar pelo usuário**, obtendo acesso não autorizado a recursos e serviços dentro da rede.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Credentials Reuse

Se você tem o **hash** ou **senha** de um **local administrator** deve tentar **logar localmente** em outros **PCs** com ele.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> Note que isto é bastante **ruidoso** e **LAPS** o **mitigaria**.

### Abuso de MSSQL e Links confiáveis

Se um usuário tem privilégios para **acessar instâncias MSSQL**, ele poderá usá-las para **executar comandos** no host MSSQL (se estiver rodando como SA), **roubar** o NetNTLM **hash** ou até executar um **relay attack**.\
Além disso, se uma instância MSSQL for confiável (database link) por outra instância MSSQL diferente, se o usuário tiver privilégios no banco de dados confiável, ele poderá **usar a relação de confiança para executar queries também na outra instância**. Essas relações de confiança podem ser encadeadas e, em algum ponto, o usuário pode encontrar um banco de dados mal configurado onde consiga executar comandos.\
**Os links entre bancos de dados funcionam mesmo através de forest trusts.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### Abuso de plataformas de assets/deployment de TI

Suites terceirizadas de inventário e deployment frequentemente expõem caminhos poderosos para credenciais e execução de código. Veja:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

Se você encontrar qualquer objeto Computer com o atributo [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) e tiver privilégios de domínio na máquina, será capaz de fazer dump dos TGTs da memória de todos os usuários que fizerem login na máquina.\
Assim, se um **Domain Admin logins onto the computer**, você poderá extrair seu TGT e se passar por ele usando [Pass the Ticket](pass-the-ticket.md).\
Graças ao constrained delegation você poderia até **comprometer automaticamente um Print Server** (esperançosamente será um DC).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

Se um usuário ou computador estiver permitido para "Constrained Delegation" ele será capaz de **impersonate any user to access some services in a computer**.\
Então, se você **comprometer o hash** desse usuário/computador você poderá **impersonate any user** (até mesmo domain admins) para acessar alguns serviços.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

Ter privilégio de **WRITE** em um objeto do Active Directory de um computador remoto possibilita obter execução de código com **privilégios elevados**:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Permissions/ACLs Abuse

O usuário comprometido pode ter alguns **privilégios interessantes sobre objetos do domínio** que podem permitir que você **mova** lateralmente/**eleve** privilégios mais tarde.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Abuso do serviço Printer Spooler

Descobrir um **Spool service listening** dentro do domínio pode ser **abusado** para **obter novas credenciais** e **elevar privilégios**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Abuso de sessões de terceiros

Se **outros usuários** **acessarem** a máquina **comprometida**, é possível **coletar credenciais da memória** e até **injetar beacons em seus processos** para se passar por eles.\
Normalmente os usuários acessam o sistema via RDP, então aqui está como realizar alguns ataques sobre sessões RDP de terceiros:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** fornece um sistema para gerenciar a **senha do Administrator local** em computadores ingressados no domínio, garantindo que ela seja **randomizada**, única e frequentemente **alterada**. Essas senhas são armazenadas no Active Directory e o acesso é controlado via ACLs apenas para usuários autorizados. Com permissões suficientes para acessar essas senhas, é possível pivotar para outros computadores.


{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

**Coletar certificados** da máquina comprometida pode ser uma forma de escalar privilégios dentro do ambiente:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Certificate Templates Abuse

Se **templates vulneráveis** estiverem configuradas, é possível abusá-las para escalar privilégios:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploitation com conta de alto privilégio

### Dumping Domain Credentials

Uma vez que você obtenha privilégios de **Domain Admin** ou, ainda melhor, **Enterprise Admin**, você pode **fazer dump** do **banco de dados do domínio**: _ntds.dit_.

[**More information about DCSync attack can be found here**](dcsync.md).

[**More information about how to steal the NTDS.dit can be found here**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc as Persistence

Algumas das técnicas discutidas acima podem ser usadas para persistência.\
Por exemplo, você poderia:

- Make users vulnerable to [**Kerberoast**](kerberoast.md)

```bash
Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
```

- Make users vulnerable to [**ASREPRoast**](asreproast.md)

```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

- Grant [**DCSync**](#dcsync) privileges to a user

```bash
Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
```

### Silver Ticket

O ataque **Silver Ticket** cria um **Ticket Granting Service (TGS) legítimo** para um serviço específico usando o **NTLM hash** (por exemplo, o **hash da conta do PC**). Esse método é empregado para **acessar os privilégios do serviço**.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

Um **Golden Ticket attack** envolve um atacante obtendo acesso ao **NTLM hash da conta krbtgt** em um ambiente Active Directory (AD). Essa conta é especial porque é usada para assinar todos os **Ticket Granting Tickets (TGTs)**, que são essenciais para autenticar dentro da rede AD.

Uma vez que o atacante obtém esse hash, ele pode criar **TGTs** para qualquer conta que escolher (Silver ticket attack).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

São como golden tickets forjados de uma forma que **contorna mecanismos comuns de detecção de golden tickets.**


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

**Ter certificados de uma conta ou ser capaz de solicitá-los** é uma ótima forma de persistir na conta do usuário (mesmo se ele alterar a senha):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**Usar certificados também possibilita persistir com altos privilégios dentro do domínio:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

O objeto **AdminSDHolder** no Active Directory garante a segurança de **grupos privilegiados** (como Domain Admins e Enterprise Admins) aplicando uma **Access Control List (ACL)** padrão a esses grupos para evitar alterações não autorizadas. No entanto, esse recurso pode ser explorado; se um atacante modificar a ACL do AdminSDHolder para dar acesso total a um usuário comum, esse usuário ganha controle extenso sobre todos os grupos privilegiados. Essa medida de segurança, projetada para proteger, pode se reverter, permitindo acesso indevido a menos que seja monitorada de perto.

[**More information about AdminDSHolder Group here.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

Dentro de cada **Domain Controller (DC)** existe uma conta de **administrador local**. Obtendo privilégios de administrador em tal máquina, o hash do Administrator local pode ser extraído usando **mimikatz**. Em seguida, é necessário uma modificação no registro para **habilitar o uso dessa senha**, permitindo acesso remoto à conta Administrator local.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

Você poderia **conceder** algumas **permissões especiais** a um **usuário** sobre objetos específicos do domínio que permitirão que o usuário **eleve privilégios no futuro**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

Os **security descriptors** são usados para **armazenar** as **permissões** que um **objeto** tem **sobre** outro **objeto**. Se você apenas **fizer** uma **pequena alteração** no **security descriptor** de um objeto, pode obter privilégios muito interessantes sobre esse objeto sem precisar ser membro de um grupo privilegiado.


{{#ref}}
security-descriptors.md
{{#endref}}

### Skeleton Key

Alterar **LSASS** na memória para estabelecer uma **senha universal**, concedendo acesso a todas as contas do domínio.


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Learn what is a SSP (Security Support Provider) here.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Você pode criar o seu **próprio SSP** para **capturar** em **clear text** as **credentials** usadas para acessar a máquina.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

Registra um **novo Domain Controller** no AD e o usa para **empurrar atributos** (SIDHistory, SPNs...) em objetos especificados **sem** deixar logs sobre as **modificações**. Você **precisa de DA** privileges e estar dentro do **root domain**.\
Note que se você usar dados errados, logs bem feios irão aparecer.


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

Anteriormente discutimos como escalar privilégios se você tiver **permissão suficiente para ler senhas LAPS**. Entretanto, essas senhas também podem ser usadas para **manter persistência**.\
Veja:


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

A Microsoft vê a **Forest** como o limite de segurança. Isso implica que **comprometer um único domínio pode potencialmente levar à comprometimento de toda a Forest**.

### Basic Information

A [**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) é um mecanismo de segurança que permite que um usuário de um **domínio** acesse recursos em outro **domínio**. Essencialmente cria uma ligação entre os sistemas de autenticação dos dois domínios, permitindo que as verificações de autenticação fluam sem problemas. Quando domínios estabelecem uma trust, eles trocam e retêm chaves específicas dentro de seus **Domain Controllers (DCs)**, que são cruciais para a integridade da trust.

Em um cenário típico, se um usuário pretende acessar um serviço em um **domínio confiável**, ele deve primeiro solicitar um TGT especial conhecido como **inter-realm TGT** do DC de seu próprio domínio. Esse TGT é criptografado com uma **trust key** que ambos os domínios concordaram compartilhar. O usuário então apresenta esse TGT ao **DC do domínio confiável** para obter um service ticket (**TGS**). Após a validação bem-sucedida do inter-realm TGT pelo DC confiável, ele emite um TGS, concedendo ao usuário acesso ao serviço.

**Passos**:

1. Um **client computer** no **Domain 1** inicia o processo usando seu **NTLM hash** para solicitar um **Ticket Granting Ticket (TGT)** ao seu **Domain Controller (DC1)**.
2. DC1 emite um novo TGT se o cliente for autenticado com sucesso.
3. O cliente então solicita um **inter-realm TGT** ao DC1, que é necessário para acessar recursos no **Domain 2**.
4. O inter-realm TGT é criptografado com uma **trust key** compartilhada entre DC1 e DC2 como parte da two-way domain trust.
5. O cliente leva o inter-realm TGT ao **Domain 2's Domain Controller (DC2)**.
6. DC2 verifica o inter-realm TGT usando sua trust key compartilhada e, se válido, emite um **Ticket Granting Service (TGS)** para o servidor no Domain 2 que o cliente deseja acessar.
7. Finalmente, o cliente apresenta esse TGS ao servidor, que está criptografado com o hash da conta do servidor, para obter acesso ao serviço no Domain 2.

### Different trusts

É importante notar que **uma trust pode ser unidirecional ou bidirecional**. Na opção bidirecional, ambos os domínios confiarão um no outro, mas na relação de trust **unidirecional** um dos domínios será o **trusted** e o outro o **trusting**. Neste último caso, **você só poderá acessar recursos dentro do trusting domain a partir do trusted**.

Se o Domain A confia no Domain B, A é o trusting domain e B é o trusted. Além disso, em **Domain A**, isso seria uma **Outbound trust**; e em **Domain B**, isso seria uma **Inbound trust**.

**Diferentes relações de trust**

- **Parent-Child Trusts**: Configuração comum dentro da mesma forest, onde um domain filho automaticamente tem uma two-way transitive trust com seu domain pai. Essencialmente, isso significa que solicitações de autenticação podem fluir sem problemas entre pai e filho.
- **Cross-link Trusts**: Referidas como "shortcut trusts", são estabelecidas entre child domains para agilizar processos de referral. Em forests complexas, os referrals de autenticação normalmente precisam subir até a raiz da forest e depois descer até o domínio alvo. Criando cross-links, essa jornada é encurtada, o que é especialmente útil em ambientes geograficamente dispersos.
- **External Trusts**: São configuradas entre domínios diferentes e não relacionados e são não-transitive por natureza. Segundo a documentação da [Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>), external trusts são úteis para acessar recursos em um domínio fora da forest atual que não esteja conectado por uma forest trust. A segurança é reforçada através de SID filtering com external trusts.
- **Tree-root Trusts**: Essas trusts são automaticamente estabelecidas entre o forest root domain e um novo tree root adicionado. Embora não sejam comumente encontradas, tree-root trusts são importantes para adicionar novas domain trees a uma forest, permitindo que mantenham um nome de domínio único e garantindo transitividade two-way. Mais informações podem ser encontradas no [guia da Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>).
- **Forest Trusts**: Esse tipo de trust é uma two-way transitive trust entre duas forest root domains, também aplicando SID filtering para aumentar medidas de segurança.
- **MIT Trusts**: Essas trusts são estabelecidas com domínios Kerberos não-Windows, compatíveis com [RFC4120](https://tools.ietf.org/html/rfc4120). MIT trusts são um pouco mais especializados e atendem ambientes que requerem integração com sistemas Kerberos fora do ecossistema Windows.

#### Outras diferenças em **trusting relationships**

- Uma relação de trust também pode ser **transitive** (A trust B, B trust C, então A trust C) ou **non-transitive**.
- Uma relação de trust pode ser configurada como **bidirectional trust** (ambos confiam um no outro) ou como **one-way trust** (apenas um confia no outro).

### Attack Path

1. **Enumerar** as relações de confiança
2. Verificar se algum **security principal** (user/group/computer) tem **acesso** a recursos do **outro domínio**, talvez por entradas ACE ou por fazer parte de grupos do outro domínio. Procure por **relações através de domínios** (a trust foi criada provavelmente por isso).
1. kerberoast nesse caso poderia ser outra opção.
3. **Comprometer** as **contas** que podem **pivotar** através de domínios.

Atacantes podem acessar recursos em outro domínio através de três mecanismos principais:

- **Local Group Membership**: Principals podem ser adicionados a grupos locais em máquinas, como o grupo “Administrators” em um servidor, concedendo controle significativo sobre essa máquina.
- **Foreign Domain Group Membership**: Principals também podem ser membros de grupos dentro do domínio estrangeiro. Entretanto, a eficácia desse método depende da natureza da trust e do escopo do grupo.
- **Access Control Lists (ACLs)**: Principals podem ser especificados em uma **ACL**, particularmente como entidades em **ACEs** dentro de uma **DACL**, concedendo-lhes acesso a recursos específicos. Para quem deseja se aprofundar na mecânica de ACLs, DACLs e ACEs, o whitepaper “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” é um recurso valioso.

### Find external users/groups with permissions

Você pode verificar **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** para encontrar foreign security principals no domínio. Esses serão usuários/grupos de **um domínio/forest externo**.

Você pode checar isso no **Bloodhound** ou usando powerview:
```powershell
# Get users that are i groups outside of the current domain
Get-DomainForeignUser

# Get groups inside a domain with users our
Get-DomainForeignGroupMember
```
### Child-to-Parent forest privilege escalation
```bash
# Fro powerview
Get-DomainTrust

SourceName      : sub.domain.local    --> current domain
TargetName      : domain.local        --> foreign domain
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : WITHIN_FOREST       --> WITHIN_FOREST: Both in the same forest
TrustDirection  : Bidirectional       --> Trust direction (2ways in this case)
WhenCreated     : 2/19/2021 1:28:00 PM
WhenChanged     : 2/19/2021 1:28:00 PM
```
Outras formas de enumerar domain trusts:
```bash
# Get DCs
nltest /dsgetdc:<DOMAIN>

# Get all domain trusts
nltest /domain_trusts /all_trusts /v

# Get all trust of a domain
nltest /dclist:sub.domain.local
nltest /server:dc.sub.domain.local /domain_trusts /all_trusts
```
> [!WARNING]
> Existem **2 trusted keys**, uma para _Child --> Parent_ e outra para _Parent_ --> _Child_.\
> Você pode ver qual é usada pelo domínio atual com:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

Escale para Enterprise admin no domínio child/parent abusando da trust com SID-History injection:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

Entender como o Configuration Naming Context (NC) pode ser explorado é crucial. O Configuration NC funciona como um repositório central para dados de configuração em toda uma floresta em ambientes Active Directory (AD). Esses dados são replicados para todos os Domain Controllers (DC) dentro da floresta, sendo que DCs com capacidade de escrita mantêm uma cópia gravável do Configuration NC. Para explorar isso, é necessário ter **privilégios SYSTEM em um DC**, preferencialmente um child DC.

**Link GPO to root DC site**

O container Sites do Configuration NC inclui informações sobre os sites de todos os computadores ingressados no domínio dentro da floresta AD. Operando com privilégios SYSTEM em qualquer DC, um atacante pode vincular GPOs aos sites do root DC. Essa ação pode comprometer o domínio root ao manipular políticas aplicadas a esses sites.

Para informações detalhadas, pode-se consultar a pesquisa sobre [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research).

**Compromise any gMSA in the forest**

Um vetor de ataque envolve mirar em gMSAs privilegiadas dentro do domínio. A KDS Root key, essencial para calcular as senhas de gMSAs, está armazenada dentro do Configuration NC. Com privilégios SYSTEM em qualquer DC, é possível acessar a KDS Root key e calcular as senhas de qualquer gMSA na floresta.

Análises detalhadas e guias passo a passo podem ser encontradas em:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Ataque MSA delegado complementar (BadSuccessor – abusando atributos de migration):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Pesquisa externa adicional: [Golden gMSA Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent).

**Schema change attack**

Esse método requer paciência, aguardando a criação de novos objetos AD privilegiados. Com privilégios SYSTEM, um atacante pode modificar o AD Schema para conceder a qualquer usuário controle total sobre todas as classes. Isso pode levar a acesso e controle não autorizados sobre objetos AD recém-criados.

Leituras adicionais estão disponíveis em [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent).

**From DA to EA with ADCS ESC5**

A vulnerabilidade ADCS ESC5 mira no controle sobre objetos de Public Key Infrastructure (PKI) para criar um template de certificado que permite autenticar-se como qualquer usuário dentro da floresta. Como objetos PKI residem no Configuration NC, comprometer um DC child com capacidade de escrita possibilita a execução de ataques ESC5.

Mais detalhes podem ser lidos em [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c). Em cenários sem ADCS, o atacante tem a capacidade de configurar os componentes necessários, conforme discutido em [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).

### External Forest Domain - One-Way (Inbound) or bidirectional
```bash
Get-DomainTrust
SourceName      : a.domain.local   --> Current domain
TargetName      : domain.external  --> Destination domain
TrustType       : WINDOWS-ACTIVE_DIRECTORY
TrustAttributes :
TrustDirection  : Inbound          --> Inboud trust
WhenCreated     : 2/19/2021 10:50:56 PM
WhenChanged     : 2/19/2021 10:50:56 PM
```
Neste cenário **o seu domínio é confiado** por um domínio externo, concedendo-lhe **permissões indeterminadas** sobre ele. Você precisará descobrir **quais principals do seu domínio têm qual acesso sobre o domínio externo** e então tentar explorá-lo:

{{#ref}}
external-forest-domain-oneway-inbound.md
{{#endref}}

### Domínio de Floresta Externa - Unidirecional (Outbound)
```bash
Get-DomainTrust -Domain current.local

SourceName      : current.local   --> Current domain
TargetName      : external.local  --> Destination domain
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : FOREST_TRANSITIVE
TrustDirection  : Outbound        --> Outbound trust
WhenCreated     : 2/19/2021 10:15:24 PM
WhenChanged     : 2/19/2021 10:15:24 PM
```
In this scenario **seu domínio** está **confiando** alguns **privilégios** a um principal de um **domínio diferente**.

No entanto, quando um **domínio é confiado** pelo domínio que confia, o domínio confiado **cria um usuário** com um **nome previsível** que usa como **senha a senha confiada**. O que significa que é possível **acessar um usuário do domínio que confia para entrar no domínio confiado** para enumerá-lo e tentar escalar mais privilégios:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Outra forma de comprometer o domínio confiado é encontrar um [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) criado na **direção oposta** da relação de confiança entre domínios (o que não é muito comum).

Outra forma de comprometer o domínio confiado é esperar em uma máquina onde um **usuário do domínio confiado possa acessar** para fazer login via **RDP**. Então, o atacante poderia injetar código no processo da sessão RDP e **acessar o domínio de origem da vítima** a partir daí.\
Além disso, se a **vítima montou seu disco rígido**, a partir do processo da **sessão RDP** o atacante poderia armazenar **backdoors** na **pasta de inicialização do disco rígido**. Essa técnica é chamada **RDPInception.**


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Mitigação do abuso de relações de confiança entre domínios

### **SID Filtering:**

- O risco de ataques que aproveitam o atributo SID history através de relações de confiança entre florestas é mitigado pelo SID Filtering, que é ativado por padrão em todas as relações de confiança inter-florestas. Isso se fundamenta na suposição de que as relações de confiança intra-floresta são seguras, considerando a floresta, em vez do domínio, como o limite de segurança segundo a posição da Microsoft.
- Contudo, há um problema: o SID Filtering pode interromper aplicações e o acesso de usuários, levando à sua desativação ocasional.

### **Selective Authentication:**

- Para relações de confiança inter-florestas, empregar Selective Authentication garante que usuários das duas florestas não sejam autenticados automaticamente. Em vez disso, permissões explícitas são requeridas para que usuários acessem domínios e servidores dentro do domínio ou floresta que confia.
- É importante notar que essas medidas não protegem contra a exploração do writable Configuration Naming Context (NC) nem contra ataques à conta de confiança.

[**More information about domain trusts in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## Abuso de AD baseado em LDAP a partir de implants no host

The [LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) re-implements bloodyAD-style LDAP primitives as x64 Beacon Object Files that run entirely inside an on-host implant (e.g., Adaptix C2). Operators compile the pack with `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make`, load `ldap.axs`, and then call `ldap <subcommand>` from the beacon. All traffic rides the current logon security context over LDAP (389) with signing/sealing or LDAPS (636) with auto certificate trust, so no socks proxies or disk artifacts are required.

### Enumeração LDAP no lado do implant

- `get-users`, `get-computers`, `get-groups`, `get-usergroups`, and `get-groupmembers` resolvem nomes curtos/caminhos de OU em DNs completos e exportam os objetos correspondentes.
- `get-object`, `get-attribute`, and `get-domaininfo` buscam atributos arbitrários (incluindo descritores de segurança) além dos metadados da floresta/domínio de `rootDSE`.
- `get-uac`, `get-spn`, `get-delegation`, and `get-rbcd` expõem candidatos a roasting, configurações de delegação e descritores existentes de [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) diretamente do LDAP.
- `get-acl` and `get-writable --detailed` analisam a DACL para listar trustees, rights (GenericAll/WriteDACL/WriteOwner/attribute writes), e herança, fornecendo alvos imediatos para escalada de privilégios via ACL.
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### LDAP write primitives for escalation & persistence

- Object creation BOFs (`add-user`, `add-computer`, `add-group`, `add-ou`) permitem ao operador posicionar novos principals ou machine accounts onde quer que existam direitos sobre OUs. `add-groupmember`, `set-password`, `add-attribute`, e `set-attribute` sequestram diretamente alvos assim que direitos de write-property são encontrados.
- Comandos focados em ACL como `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite`, e `add-dcsync` traduzem WriteDACL/WriteOwner em qualquer objeto AD para resets de senha, controle de membership de grupos ou privilégios de DCSync sem deixar artefatos PowerShell/ADSI. Contrapartes `remove-*` limpam ACEs injetados.

### Delegation, roasting, and Kerberos abuse

- `add-spn`/`set-spn` tornam instantaneamente um usuário comprometido Kerberoastable; `add-asreproastable` (toggle UAC) marca-o para AS-REP roasting sem tocar na senha.
- Macros de delegação (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) reescrevem `msDS-AllowedToDelegateTo`, flags UAC, ou `msDS-AllowedToActOnBehalfOfOtherIdentity` a partir do beacon, habilitando caminhos de ataque constrained/unconstrained/RBCD e eliminando a necessidade de PowerShell remoto ou RSAT.

### sidHistory injection, OU relocation, and attack surface shaping

- `add-sidhistory` injeta SIDs privilegiados no SID history de um principal controlado (ver [SID-History Injection](sid-history-injection.md)), fornecendo herança de acesso furtiva totalmente via LDAP/LDAPS.
- `move-object` altera o DN/OU de computadores ou usuários, permitindo que um atacante arraste assets para OUs onde já existem direitos delegados antes de abusar de `set-password`, `add-groupmember`, ou `add-spn`.
- Comandos de remoção de escopo restrito (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember`, etc.) permitem rollback rápido depois que o operador colhe credenciais ou persistência, minimizando telemetria.

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Some General Defenses

[**Learn more about how to protect credentials here.**](../stealing-credentials/credentials-protections.md)

### **Defensive Measures for Credential Protection**

- **Domain Admins Restrictions**: Recomenda-se que Domain Admins sejam permitidos apenas para login em Domain Controllers, evitando seu uso em outros hosts.
- **Service Account Privileges**: Serviços não devem ser executados com privilégios de Domain Admin (DA) para manter a segurança.
- **Temporal Privilege Limitation**: Para tarefas que exigem privilégios DA, a duração deve ser limitada. Isso pode ser conseguido por: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`

### **Implementing Deception Techniques**

- Implementar deception envolve armar iscas, como usuários ou computadores de engodo, com características como senhas que não expiram ou marcados como Trusted for Delegation. Uma abordagem detalhada inclui criar users com direitos específicos ou adicioná-los a grupos de alto privilégio.
- Um exemplo prático envolve usar ferramentas como: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Mais sobre como implantar técnicas de deception pode ser encontrado em [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception).

### **Identifying Deception**

- **For User Objects**: Indicadores suspeitos incluem ObjectSID atípico, logons raros, datas de criação e contagens baixas de bad password.
- **General Indicators**: Comparar atributos de potenciais objetos de engodo com os de objetos genuínos pode revelar inconsistências. Ferramentas como [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) podem ajudar a identificar tais deceptions.

### **Bypassing Detection Systems**

- **Microsoft ATA Detection Bypass**:
- **User Enumeration**: Evitar enumeração de sessões em Domain Controllers para prevenir detecção pelo ATA.
- **Ticket Impersonation**: Utilizar chaves **aes** para criação de tickets ajuda a evadir detecção ao não degradar para NTLM.
- **DCSync Attacks**: Executar a partir de um host não-DC é aconselhado para evitar detecção pelo ATA, já que execução direta de um Domain Controller acionará alertas.

## References

- [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
- [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [LDAP BOF Collection – In-Memory LDAP Toolkit for Active Directory Exploitation](https://github.com/P0142/LDAP-Bof-Collection)

{{#include ../../banners/hacktricks-training.md}}
