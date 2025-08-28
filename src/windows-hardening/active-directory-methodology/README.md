# Metodologia do Active Directory

{{#include ../../banners/hacktricks-training.md}}

## Visão geral básica

**Active Directory** serve como uma tecnologia fundamental, permitindo que **administradores de rede** criem e gerenciem de forma eficiente **domínios**, **usuários** e **objetos** dentro de uma rede. Ele é projetado para escalar, facilitando a organização de um grande número de usuários em **grupos** e **subgrupos** gerenciáveis, ao mesmo tempo que controla **direitos de acesso** em vários níveis.

A estrutura do **Active Directory** é composta por três camadas principais: **domínios**, **trees**, e **forests**. Um **domain** abrange uma coleção de objetos, como **usuários** ou **dispositivos**, compartilhando um banco de dados comum. **Trees** são grupos desses domínios ligados por uma estrutura compartilhada, e uma **forest** representa a coleção de múltiplas trees, interconectadas através de **trust relationships**, formando a camada superior da estrutura organizacional. Direitos específicos de **acesso** e **comunicação** podem ser designados em cada um desses níveis.

Conceitos-chave dentro do **Active Directory** incluem:

1. **Directory** – Abriga todas as informações referentes aos objetos do Active Directory.
2. **Object** – Denota entidades dentro do diretório, incluindo **usuários**, **grupos**, ou **pastas compartilhadas**.
3. **Domain** – Serve como um contêiner para objetos do diretório, com a capacidade de múltiplos domains coexistirem dentro de uma **forest**, cada um mantendo sua própria coleção de objetos.
4. **Tree** – Um agrupamento de domains que compartilham um domain root comum.
5. **Forest** – O pico da estrutura organizacional no Active Directory, composto por várias trees com **trust relationships** entre elas.

**Active Directory Domain Services (AD DS)** abrange uma gama de serviços críticos para o gerenciamento centralizado e comunicação dentro de uma rede. Esses serviços compreendem:

1. **Domain Services** – Centraliza o armazenamento de dados e gerencia interações entre **usuários** e **domínios**, incluindo **autenticação** e funcionalidades de **busca**.
2. **Certificate Services** – Supervisiona a criação, distribuição e gerenciamento de **certificados digitais** seguros.
3. **Lightweight Directory Services** – Suporta aplicações habilitadas para diretório através do **LDAP protocol**.
4. **Directory Federation Services** – Fornece capacidades de **single-sign-on** para autenticar usuários através de múltiplas aplicações web em uma única sessão.
5. **Rights Management** – Auxilia na proteção de material com direitos autorais regulando sua distribuição e uso não autorizado.
6. **DNS Service** – Crucial para a resolução de **nomes de domínio**.

For a more detailed explanation check: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

To learn how to **attack an AD** you need to **understand** really good the **Kerberos authentication process**.\
[**Read this page if you still don't know how it works.**](kerberos-authentication.md)

## Cheat Sheet

You can take a lot to [https://wadcoms.github.io/](https://wadcoms.github.io) to have a quick view of which commands you can run to enumerate/exploit an AD.

> [!WARNING]
> A comunicação Kerberos **requer um nome totalmente qualificado (FQDN)** para executar ações. Se você tentar acessar uma máquina pelo endereço IP, **vai usar NTLM e não kerberos**.

## Recon Active Directory (Sem creds/sessions)

Se você tem apenas acesso a um ambiente AD mas não possui credenciais/sessões, você poderia:

- **Pentest the network:**
- Escanear a rede, encontrar máquinas e portas abertas e tentar **explorar vulnerabilidades** ou **extrair credenciais** delas (por exemplo, [printers could be very interesting targets](ad-information-in-printers.md)).
- Enumerar DNS pode fornecer informações sobre servidores-chave no domínio como web, printers, shares, vpn, media, etc.
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- Dê uma olhada na [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md) geral para encontrar mais informações sobre como fazer isso.
- **Verificar acesso null e Guest em serviços smb** (isso não funcionará em versões modernas do Windows):
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- Um guia mais detalhado sobre como enumerar um servidor SMB pode ser encontrado aqui:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Enumerar Ldap**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- Um guia mais detalhado sobre como enumerar LDAP pode ser encontrado aqui (preste **atenção especial ao acesso anônimo**):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Poison the network**
- Coletar credenciais [**impersonating services with Responder**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
- Acessar host [**abusando do relay attack**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
- Coletar credenciais **expondo** [**fake UPnP services with evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- Extrair nomes de usuário/nomes a partir de documentos internos, redes sociais, serviços (principalmente web) dentro dos ambientes de domínio e também a partir do que está publicamente disponível.
- Se você encontrar os nomes completos de funcionários da empresa, você pode tentar diferentes convenções de **username** do AD (**[read this**](https://activedirectorypro.com/active-directory-user-naming-convention/)**). As convenções mais comuns são:** _NameSurname_, _Name.Surname_, _NamSur_ (3 letras de cada), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 _letras aleatórias e 3 números aleatórios_ (abc123).
- Ferramentas:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### Enumeração de usuários

- **Anonymous SMB/LDAP enum:** Consulte as páginas de [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) e [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md).
- **Kerbrute enum**: Quando um **username inválido é solicitado** o servidor responderá usando o código de erro **Kerberos** _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_, permitindo-nos determinar que o username é inválido. **Usernames válidos** provocarão ou o **TGT em um AS-REP** ou o erro _KRB5KDC_ERR_PREAUTH_REQUIRED_, indicando que o usuário precisa realizar pre-authentication.
- **No Authentication against MS-NRPC**: Usando auth-level = 1 (No authentication) contra a interface MS-NRPC (Netlogon) em domain controllers. O método chama a função `DsrGetDcNameEx2` após bind da interface MS-NRPC para verificar se o usuário ou computador existe sem qualquer credencial. A ferramenta [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) implementa este tipo de enumeração. A pesquisa pode ser encontrada [aqui](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **OWA (Outlook Web Access) Servidor**

Se encontrar um desses servidores na rede, também pode realizar **enumeração de usuários** nele. Por exemplo, pode usar a ferramenta [**MailSniper**](https://github.com/dafthack/MailSniper):
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
> Você pode encontrar listas de usernames em [**this github repo**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names)  and this one ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)).
>
> Entretanto, você deve ter o **nome das pessoas que trabalham na empresa** a partir da etapa de recon que deveria ter realizado antes disto. Com o nome e sobrenome você poderia usar o script [**namemash.py**](https://gist.github.com/superkojiman/11076951) para gerar potenciais usernames válidos.

### Knowing one or several usernames

Ok, então você já sabe que tem um username válido mas sem senhas... Então tente:

- [**ASREPRoast**](asreproast.md): Se um usuário **não possui** o atributo _DONT_REQ_PREAUTH_ você pode **solicitar uma mensagem AS_REP** para esse usuário que conterá alguns dados criptografados por uma derivação da senha do usuário.
- [**Password Spraying**](password-spraying.md): Vamos tentar as senhas mais **comuns** com cada um dos usuários descobertos, talvez algum usuário esteja usando uma senha fraca (lembre-se da política de senhas!).
- Note que você também pode **spray OWA servers** para tentar acessar os servidores de e-mail dos usuários.


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

Você pode ser capaz de **obter** alguns **hashes** de challenge para quebrar, envenenando alguns protocolos da **rede**:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Se você conseguiu enumerar o Active Directory você terá **mais e-mails e um entendimento melhor da rede**. Você pode ser capaz de forçar NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) para obter acesso ao ambiente AD.

### Steal NTLM Creds

Se você puder **acessar outros PCs ou shares** com o **null ou guest user** você poderia **colocar arquivos** (como um arquivo SCF) que, se de alguma forma acessados, irão **acionar uma autenticação NTLM contra você** para que você possa **roubar** o **challenge NTLM** para quebrá-lo:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

## Enumerating Active Directory WITH credentials/session

Para esta fase você precisa ter **comprometido as credenciais ou uma sessão de uma conta de domínio válida.** Se você tem algumas credenciais válidas ou um shell como um usuário de domínio, **deve lembrar que as opções apresentadas antes ainda são opções para comprometer outros usuários**.

Antes de iniciar a enumeração autenticada você deve conhecer o **problema do Kerberos double hop.**


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeration

Ter comprometido uma conta é um **grande passo para começar a comprometer todo o domínio**, pois você poderá iniciar a **enumeração do Active Directory:**

Em relação ao [**ASREPRoast**](asreproast.md) você agora pode encontrar todos os usuários possivelmente vulneráveis, e em relação ao [**Password Spraying**](password-spraying.md) você pode obter uma **lista de todos os usernames** e tentar a senha da conta comprometida, senhas vazias e novas senhas promissoras.

- Você pode usar o [**CMD to perform a basic recon**](../basic-cmd-for-pentesters.md#domain-info)
- Você também pode usar [**powershell for recon**](../basic-powershell-for-pentesters/index.html) que será mais furtivo
- Você também pode [**use powerview**](../basic-powershell-for-pentesters/powerview.md) para extrair informações mais detalhadas
- Outra ferramenta incrível para recon em um Active Directory é [**BloodHound**](bloodhound.md). Ela é **not very stealthy** (dependendo dos métodos de coleta que você usar), mas **if you don't care** sobre isso, você deveria definitivamente experimentar. Encontre onde usuários podem RDP, encontre caminhos para outros grupos, etc.
- **Other automated AD enumeration tools are:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- [**DNS records of the AD**](ad-dns-records.md) pois eles podem conter informação interessante.
- Uma **tool with GUI** que você pode usar para enumerar o diretório é **AdExplorer.exe** da suíte **SysInternal**.
- Você também pode buscar na base LDAP com **ldapsearch** para procurar credenciais nos campos _userPassword_ & _unixUserPassword_, ou até em _Description_. cf. [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) para outros métodos.
- Se você está usando **Linux**, você também pode enumerar o domínio usando [**pywerview**](https://github.com/the-useless-one/pywerview).
- Você também pode tentar ferramentas automatizadas como:
- [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
- [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Extracting all domain users**

É muito fácil obter todos os usernames do domínio a partir do Windows (`net user /domain` ,`Get-DomainUser` ou `wmic useraccount get name,sid`). No Linux, você pode usar: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` ou `enum4linux -a -u "user" -p "password" <DC IP>`

> Mesmo que esta seção de Enumeração pareça pequena, esta é a parte mais importante de todas. Acesse os links (principalmente os de cmd, powershell, powerview e BloodHound), aprenda como enumerar um domínio e pratique até se sentir confortável. Durante uma avaliação, este será o momento-chave para encontrar seu caminho até DA ou para decidir que nada pode ser feito.

### Kerberoast

Kerberoasting envolve obter **TGS tickets** usados por serviços ligados a contas de usuário e quebrar sua criptografia — que é baseada nas senhas dos usuários — **offline**.

Mais sobre isso em:


{{#ref}}
kerberoast.md
{{#endref}}

### Remote connexion (RDP, SSH, FTP, Win-RM, etc)

Uma vez que você tenha obtido algumas credenciais, você pode verificar se tem acesso a alguma **machine**. Para isso, você pode usar **CrackMapExec** para tentar conectar em vários servidores com diferentes protocolos, de acordo com seus scans de portas.

### Local Privilege Escalation

Se você tem credenciais comprometidas ou uma sessão como um usuário de domínio regular e possui **acesso** com esse usuário a **qualquer máquina do domínio**, você deve tentar encontrar uma forma de **escalar privilégios localmente e saquear credenciais**. Isso porque somente com privilégios de administrador local você será capaz de **extrair hashes de outros usuários** na memória (LSASS) e localmente (SAM).

Há uma página completa neste livro sobre [**local privilege escalation in Windows**](../windows-local-privilege-escalation/index.html) e um [**checklist**](../checklist-windows-privilege-escalation.md). Além disso, não esqueça de usar [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite).

### Current Session Tickets

É muito **improvável** que você encontre **tickets** no usuário atual que **lhe concedam permissão para acessar** recursos inesperados, mas você pode verificar:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

Se você conseguiu enumerar o Active Directory terá **mais e-mails e uma melhor compreensão da rede**. Você pode ser capaz de forçar NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**.**

### Procure Creds em Computer Shares | SMB Shares

Agora que você tem algumas credenciais básicas, deve verificar se consegue **encontrar** quaisquer **arquivos interessantes sendo compartilhados dentro do AD**. Você poderia fazer isso manualmente, mas é uma tarefa muito entediante e repetitiva (ainda mais se encontrar centenas de docs que precisa checar).

[**Siga este link para aprender sobre ferramentas que você pode usar.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steal NTLM Creds

Se você pode **acessar outros PCs ou shares** você poderia **colocar arquivos** (como um SCF file) que se de alguma forma acessados vão **trigger an NTLM authentication against you** para que você possa **steal** o **NTLM challenge** para crackear:

{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Essa vulnerabilidade permitia que qualquer usuário autenticado **comprometesse o domain controller**.

{{#ref}}
printnightmare.md
{{#endref}}

## Privilege escalation on Active Directory WITH privileged credentials/session

**Para as técnicas seguintes um usuário de domínio regular não é suficiente, você precisa de alguns privilégios/credenciais especiais para realizar esses ataques.**

### Hash extraction

Esperançosamente você conseguiu **comprometer alguma conta de admin local** usando [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) incluindo relaying, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [escalating privileges locally](../windows-local-privilege-escalation/index.html).\
Então, é hora de dump all the hashes in memory and locally.\
[**Leia esta página sobre diferentes formas de obter os hashes.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Uma vez que você tenha o hash de um usuário**, você pode usá-lo para **impersonate** o mesmo.\
Você precisa usar alguma **ferramenta** que irá **perform the NTLM authentication using** aquele **hash**, **ou** você pode criar um novo **sessionlogon** e **inject** aquele **hash** dentro do **LSASS**, assim quando qualquer **NTLM authentication is performed**, aquele **hash será usado.** A última opção é o que mimikatz faz.\
[**Leia esta página para mais informações.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Esse ataque tem como objetivo **usar o NTLM hash do usuário para solicitar tickets Kerberos**, como alternativa ao comum Pass The Hash sobre o protocolo NTLM. Portanto, isso pode ser especialmente **útil em redes onde o protocolo NTLM está desabilitado** e apenas **Kerberos é permitido** como protocolo de autenticação.

{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

No método de ataque **Pass The Ticket (PTT)**, os atacantes **roubam o ticket de autenticação de um usuário** em vez de sua senha ou valores de hash. Esse ticket roubado é então usado para **impersonate** o usuário, obtendo acesso não autorizado a recursos e serviços dentro de uma rede.

{{#ref}}
pass-the-ticket.md
{{#endref}}

### Credentials Reuse

Se você tem o **hash** ou **password** de um **administrador local** você deve tentar **login locally** em outros **PCs** com ele.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> Note que isto gera bastante **ruído** e **LAPS** **mitigaria** isto.

### MSSQL Abuse & Trusted Links

Se um usuário tem privilégios para **acessar instâncias MSSQL**, ele pode ser capaz de usá-las para **executar comandos** no host MSSQL (se estiver rodando como SA), **roubar** o **hash** NetNTLM ou até realizar um **relay** **attack**.\
Além disso, se uma instância MSSQL é confiável (database link) por uma instância MSSQL diferente. Se o usuário tem privilégios sobre o database confiável, ele poderá **usar a relação de confiança para executar queries também na outra instância**. Essas trusts podem ser encadeadas e em algum ponto o usuário pode encontrar um database mal configurado onde pode executar comandos.\
**Os links entre databases funcionam mesmo através de forest trusts.**


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

Se você encontrar qualquer objeto Computer com o atributo [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) e você tiver privilégios de domínio na máquina, você será capaz de dumpar TGTs da memória de todo usuário que fizer login naquela máquina.\
Então, se um **Domain Admin fizer login na máquina**, você poderá dumpar seu TGT e se passar por ele usando [Pass the Ticket](pass-the-ticket.md).\
Graças ao constrained delegation você poderia até **comprometer automaticamente um Print Server** (esperançosamente será um DC).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

Se um usuário ou computador está permitido para "Constrained Delegation" ele será capaz de **se passar por qualquer usuário para acessar alguns serviços em um computador**.\
Então, se você **comprometer o hash** desse usuário/computador você poderá **se passar por qualquer usuário** (até domain admins) para acessar certos serviços.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

Ter privilégio de **WRITE** sobre um objeto Active Directory de um computador remoto permite alcançar execução de código com **privilégios elevados**:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Permissions/ACLs Abuse

O usuário comprometido pode ter alguns **privilégios interessantes sobre certos objetos de domínio** que poderiam permitir que você **movimente-se** lateralmente/**eleve** privilégios posteriormente.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler service abuse

Descobrir um **Spool service listening** dentro do domínio pode ser **abusado** para **adquirir novas credenciais** e **escalar privilégios**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Third party sessions abuse

Se **outros usuários** **acessarem** a máquina **comprometida**, é possível **coletar credenciais da memória** e até **injetar beacons nos processos deles** para se passar por eles.\
Geralmente os usuários acessam o sistema via RDP, então aqui está como realizar um par de ataques sobre sessões RDP de terceiros:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** fornece um sistema para gerenciar a **senha do Administrator local** em computadores ingressados no domínio, garantindo que ela seja **randomizada**, única e frequentemente **alterada**. Essas senhas são armazenadas no Active Directory e o acesso é controlado através de ACLs apenas para usuários autorizados. Com permissões suficientes para acessar essas senhas, pivotar para outros computadores torna-se possível.


{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

**Coletar certificados** da máquina comprometida pode ser uma forma de escalar privilégios dentro do ambiente:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Certificate Templates Abuse

Se **templates vulneráveis** estão configurados, é possível abusar deles para escalar privilégios:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploitation with high privilege account

### Dumping Domain Credentials

Uma vez que você obtiver privilégios de **Domain Admin** ou ainda melhor **Enterprise Admin**, você pode **dump** o **database do domínio**: _ntds.dit_.

[**Mais informações sobre o ataque DCSync podem ser encontradas aqui**](dcsync.md).

[**Mais informações sobre como roubar o NTDS.dit podem ser encontradas aqui**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc as Persistence

Algumas das técnicas discutidas antes podem ser usadas para persistência.\
Por exemplo você poderia:

- Tornar usuários vulneráveis a [**Kerberoast**](kerberoast.md)

```bash
Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
```

- Tornar usuários vulneráveis a [**ASREPRoast**](asreproast.md)

```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

- Conceder privilégios de [**DCSync**](#dcsync) a um usuário

```bash
Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
```

### Silver Ticket

O **Silver Ticket attack** cria um **Ticket Granting Service (TGS) ticket legítimo** para um serviço específico usando o **hash NTLM** (por exemplo, o **hash da conta do PC**). Esse método é empregado para **acessar privilégios do serviço**.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

Um **Golden Ticket attack** envolve um atacante obtendo acesso ao **hash NTLM da conta krbtgt** em um ambiente Active Directory (AD). Essa conta é especial porque é usada para assinar todos os **Ticket Granting Tickets (TGTs)**, que são essenciais para autenticação dentro da rede AD.

Uma vez que o atacante obtém esse hash, ele pode criar **TGTs** para qualquer conta que escolher (ataque Silver ticket).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

Estes são como golden tickets forjados de uma forma que **bypasse mecanismos comuns de detecção de golden tickets.**


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

**Ter certificados de uma conta ou ser capaz de solicitá-los** é uma ótima forma de persistir na conta do usuário (mesmo se ele mudar a senha):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**Usar certificados também permite persistir com altos privilégios dentro do domínio:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

O objeto **AdminSDHolder** no Active Directory assegura a segurança de **grupos privilegiados** (como Domain Admins e Enterprise Admins) aplicando uma **ACL** padrão nesses grupos para prevenir mudanças não autorizadas. Contudo, esse recurso pode ser explorado; se um atacante modificar a ACL do AdminSDHolder para dar acesso total a um usuário comum, esse usuário ganha controle extensivo sobre todos os grupos privilegiados. Essa medida de segurança, pensada para proteger, pode portanto se tornar contraproducente, permitindo acesso indevido a menos que seja monitorada de perto.

[**Mais informações sobre o AdminDSHolder Group aqui.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

Dentro de cada **Domain Controller (DC)** existe uma conta de **administrador local**. Ao obter direitos de administrador em tal máquina, o hash do Administrator local pode ser extraído usando **mimikatz**. Em seguida, é necessária uma modificação no registro para **habilitar o uso dessa senha**, permitindo o acesso remoto à conta Administrator local.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

Você pode **conceder** algumas **permissões especiais** a um **usuário** sobre certos objetos de domínio que permitirão ao usuário **escalar privilégios no futuro**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

Os **security descriptors** são usados para **armazenar** as **permissões** que um **objeto** tem **sobre** outro **objeto**. Se você puder apenas **fazer** uma **pequena alteração** no **security descriptor** de um objeto, você pode obter privilégios muito interessantes sobre esse objeto sem precisar ser membro de um grupo privilegiado.


{{#ref}}
security-descriptors.md
{{#endref}}

### Skeleton Key

Altere o **LSASS** na memória para estabelecer uma **senha universal**, concedendo acesso a todas as contas do domínio.


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Learn what is a SSP (Security Support Provider) here.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Você pode criar seu **próprio SSP** para **capturar** em **clear text** as **credenciais** usadas para acessar a máquina.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

Registra um **novo Domain Controller** no AD e o usa para **empurrar atributos** (SIDHistory, SPNs...) em objetos especificados **sem** deixar **logs** sobre as **modificações**. Você **precisa de DA** privilégios e estar dentro do **root domain**.\
Note que se você usar dados errados, logs bem feios aparecerão.


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

Anteriormente discutimos como escalar privilégios se você tiver **permissão suficiente para ler senhas LAPS**. No entanto, essas senhas também podem ser usadas para **manter persistência**.\
Veja:


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

A Microsoft vê a **Forest** como o boundary de segurança. Isso implica que **comprometer um único domínio pode potencialmente levar à divulgação de toda a Forest**.

### Basic Information

Um [**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) é um mecanismo de segurança que permite a um usuário de um **domínio** acessar recursos em outro **domínio**. Essencialmente cria um vínculo entre os sistemas de autenticação dos dois domínios, permitindo que verificações de autenticação fluam sem interrupções. Quando domínios configuram uma trust, eles trocam e mantêm chaves específicas dentro de seus **Domain Controllers (DCs)**, que são cruciais para a integridade da trust.

Em um cenário típico, se um usuário pretende acessar um serviço em um **domínio confiável**, ele deve primeiro solicitar um ticket especial conhecido como **inter-realm TGT** ao DC do seu próprio domínio. Esse TGT é criptografado com uma **key** compartilhada que ambos domínios acordaram. O usuário então apresenta esse TGT ao **DC do domínio confiável** para obter um service ticket (**TGS**). Após a validação bem-sucedida do inter-realm TGT pelo DC do domínio confiável, ele emite um TGS, concedendo ao usuário acesso ao serviço.

**Passos**:

1. Um **cliente** em **Domain 1** inicia o processo usando seu **hash NTLM** para solicitar um **Ticket Granting Ticket (TGT)** ao seu **Domain Controller (DC1)**.
2. DC1 emite um novo TGT se o cliente for autenticado com sucesso.
3. O cliente então solicita um **inter-realm TGT** ao DC1, que é necessário para acessar recursos em **Domain 2**.
4. O inter-realm TGT é criptografado com uma **trust key** compartilhada entre DC1 e DC2 como parte da trust bidirecional.
5. O cliente leva o inter-realm TGT ao **Domain Controller de Domain 2 (DC2)**.
6. DC2 verifica o inter-realm TGT usando sua trust key compartilhada e, se válido, emite um **Ticket Granting Service (TGS)** para o servidor em Domain 2 que o cliente deseja acessar.
7. Finalmente, o cliente apresenta esse TGS ao servidor, que é criptografado com o hash da conta do servidor, para obter acesso ao serviço em Domain 2.

### Different trusts

É importante notar que **uma trust pode ser unidirecional ou bidirecional**. Na opção de 2 ways, ambos domínios confiarão um no outro, mas na relação de **1 way** um dos domínios será o **trusted** e o outro o **trusting**. No último caso, **você só poderá acessar recursos dentro do trusting domain a partir do trusted**.

Se o Domain A confia no Domain B, A é o trusting domain e B é o trusted. Além disso, em **Domain A**, isto seria uma **Outbound trust**; e em **Domain B**, isto seria uma **Inbound trust**.

**Different trusting relationships**

- **Parent-Child Trusts**: Esta é uma configuração comum dentro da mesma forest, onde um child domain automaticamente tem uma trust transitiva bidirecional com seu parent domain. Essencialmente, isso significa que pedidos de autenticação podem fluir sem problemas entre parent e child.
- **Cross-link Trusts**: Referidas como "shortcut trusts", são estabelecidas entre child domains para acelerar processos de referral. Em florestas complexas, referrals de autenticação tipicamente precisam subir até a raiz da forest e depois descer até o domínio alvo. Criando cross-links, a jornada é encurtada, o que é especialmente benéfico em ambientes geograficamente dispersos.
- **External Trusts**: São configuradas entre domínios diferentes e não relacionados e são não-transitivas por natureza. De acordo com a documentação da [Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>), external trusts são úteis para acessar recursos em um domínio fora da forest atual que não está conectado por uma forest trust. A segurança é reforçada através de SID filtering com external trusts.
- **Tree-root Trusts**: Essas trusts são estabelecidas automaticamente entre o forest root domain e uma nova tree root adicionada. Embora não sejam comumente encontradas, tree-root trusts são importantes para adicionar novas domain trees a uma forest, permitindo que mantenham um nome de domínio único e assegurando transitividade bidirecional. Mais informações podem ser encontradas no guia da [Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>).
- **Forest Trusts**: Este tipo de trust é uma trust transitiva bidirecional entre duas forest root domains, também aplicando SID filtering para reforçar medidas de segurança.
- **MIT Trusts**: Essas trusts são estabelecidas com domínios Kerberos não-Windows, compatíveis com [RFC4120](https://tools.ietf.org/html/rfc4120). MIT trusts são um pouco mais especializadas e atendem ambientes que requerem integração com sistemas baseados em Kerberos fora do ecossistema Windows.

#### Other differences in **trusting relationships**

- Uma relação de trust também pode ser **transitiva** (A trust B, B trust C, então A trust C) ou **non-transitive**.
- Uma relação de trust pode ser configurada como **bidirectional trust** (ambos confiam um no outro) ou como **one-way trust** (apenas um confia no outro).

### Attack Path

1. **Enumerar** as relações de confiança
2. Verificar se algum **security principal** (user/group/computer) tem **acesso** a recursos do **outro domínio**, talvez por entradas ACE ou por estar em grupos do outro domínio. Procurar por **relacionamentos entre domínios** (a trust foi criada provavelmente para isso).
1. kerberoast neste caso poderia ser outra opção.
3. **Comprometer** as **contas** que possam **pivotar** entre domínios.

Ataquantes podem acessar recursos em outro domínio através de três mecanismos principais:

- **Local Group Membership**: Principais podem ser adicionados a grupos locais em máquinas, como o grupo “Administrators” em um servidor, concedendo controle significativo sobre essa máquina.
- **Foreign Domain Group Membership**: Principais também podem ser membros de grupos dentro do domínio estrangeiro. Entretanto, a eficácia deste método depende da natureza da trust e do escopo do grupo.
- **Access Control Lists (ACLs)**: Principais podem ser especificados em uma **ACL**, particularmente como entidades em **ACEs** dentro de uma **DACL**, fornecendo-lhes acesso a recursos específicos. Para quem quiser se aprofundar na mecânica de ACLs, DACLs e ACEs, o whitepaper “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” é um recurso inestimável.

### Find external users/groups with permissions

Você pode checar **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** para encontrar foreign security principals no domínio. Estes serão usuários/grupos de **um domínio/forest externo**.

Você pode checar isso no **Bloodhound** ou usando **powerview**:
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
Outras maneiras de enumerar relações de confiança de domínio:
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
> Existem **2 chaves trusted**, uma para _Child --> Parent_ e outra para _Parent_ --> _Child_.\
> Você pode verificar qual está sendo usada pelo domínio atual com:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

Escalar para Enterprise admin no domínio filho/pai abusando da trust com SID-History injection:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

Entender como o Configuration Naming Context (NC) pode ser explorado é crucial. O Configuration NC funciona como um repositório central de dados de configuração em toda a forest em ambientes Active Directory (AD). Esses dados são replicados para todos os Domain Controller (DC) dentro da forest, com DCs graváveis mantendo uma cópia gravável do Configuration NC. Para explorar isso, é necessário ter **privilégios SYSTEM em um DC**, preferencialmente um DC filho.

**Link GPO to root DC site**

O container Sites do Configuration NC inclui informações sobre os sites de todos os computadores ingressados ao domínio dentro da forest AD. Operando com privilégios SYSTEM em qualquer DC, atacantes podem linkar GPOs aos sites do DC raiz. Essa ação pode comprometer o domínio raiz ao manipular políticas aplicadas a esses sites.

For in-depth information, one might explore research on [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research).

**Compromise any gMSA in the forest**

Um vetor de ataque envolve mirar em gMSAs privilegiadas dentro do domínio. A KDS Root key, essencial para calcular as senhas das gMSAs, está armazenada dentro do Configuration NC. Com privilégios SYSTEM em qualquer DC, é possível acessar a KDS Root key e calcular as senhas de qualquer gMSA em toda a forest.

Detailed analysis and step-by-step guidance can be found in:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Complementary delegated MSA attack (BadSuccessor – abusing migration attributes):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Additional external research: [Golden gMSA Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent).

**Schema change attack**

Esse método exige paciência, aguardando a criação de novos objetos AD privilegiados. Com privilégios SYSTEM, um atacante pode modificar o AD Schema para conceder a qualquer usuário controle total sobre todas as classes. Isso pode levar a acesso não autorizado e controle sobre objetos AD recém-criados.

Further reading is available on [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent).

**From DA to EA with ADCS ESC5**

A vulnerabilidade ADCS ESC5 mira no controle de objetos de Public Key Infrastructure (PKI) para criar um template de certificado que permite autenticar-se como qualquer usuário dentro da forest. Como objetos PKI residem no Configuration NC, comprometer um DC filho gravável permite a execução de ataques ESC5.

More details on this can be read in [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c). In scenarios lacking ADCS, the attacker has the capability to set up the necessary components, as discussed in [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).

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
Neste cenário **seu domínio é confiado** por um domínio externo, dando a você **permissões indeterminadas** sobre ele. Você precisará descobrir **quais entidades do seu domínio têm quais acessos sobre o domínio externo** e então tentar explorá-los:


{{#ref}}
external-forest-domain-oneway-inbound.md
{{#endref}}

### Domínio de Floresta Externa - Unidirecional (Saída)
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

No entanto, quando um **domain is trusted** pelo domínio que confia, o domínio confiável **cria um usuário** com um **nome previsível** que usa como **senha a trusted password**. Isso significa que é possível **acessar um usuário do domínio que confia para entrar no domínio confiável** para enumerá-lo e tentar escalar mais privilégios:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Outra forma de comprometer o domínio confiável é encontrar um [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) criado na **direção oposta** da trust de domínio (o que não é muito comum).

Outra forma de comprometer o domínio confiável é aguardar em uma máquina onde um **user from the trusted domain can access** para logar via **RDP**. Então, o atacante poderia injetar código no processo da sessão RDP e **acessar o domínio de origem da vítima** a partir dali.\ 
Além disso, se a **victim mounted his hard drive**, a partir do processo da **RDP session** o atacante poderia armazenar **backdoors** na **startup folder of the hard drive**. Essa técnica é chamada **RDPInception.**


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Mitigação de abuso de confiança de domínio

### **SID Filtering:**

- O risco de ataques que exploram o atributo SID history através de trusts entre florestas é mitigado pelo SID Filtering, que é ativado por padrão em todos os trusts inter-florestais. Isso se baseia na suposição de que os trusts intra-floresta são seguros, considerando a floresta, em vez do domínio, como a fronteira de segurança, conforme a posição da Microsoft.
- No entanto, existe um problema: o SID filtering pode interromper aplicações e o acesso de usuários, levando à sua desativação ocasional.

### **Selective Authentication:**

- Para trusts entre florestas, empregar Selective Authentication garante que usuários das duas florestas não sejam autenticados automaticamente. Em vez disso, permissões explícitas são necessárias para que usuários acessem domínios e servidores dentro do domínio ou floresta que confia.
- É importante notar que essas medidas não protegem contra a exploração do writable Configuration Naming Context (NC) ou ataques na trust account.

[**More information about domain trusts in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Algumas Defesas Gerais

[**Learn more about how to protect credentials here.**](../stealing-credentials/credentials-protections.md)

### **Medidas defensivas para proteção de credenciais**

- **Domain Admins Restrictions**: Recomenda-se que os Domain Admins só possam fazer login em Domain Controllers, evitando seu uso em outros hosts.
- **Service Account Privileges**: Serviços não devem ser executados com privilégios de Domain Admin (DA) para manter a segurança.
- **Temporal Privilege Limitation**: Para tarefas que exigem privilégios de DA, a duração desses privilégios deve ser limitada. Isso pode ser feito com: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`

### **Implementando técnicas de Deception**

- Implementar deception envolve configurar armadilhas, como usuários ou computadores bobos, com características como senhas que não expiram ou marcadas como Trusted for Delegation. Uma abordagem detalhada inclui criar usuários com direitos específicos ou adicioná-los a grupos de alto privilégio.
- Um exemplo prático envolve usar ferramentas como: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Mais sobre deployment de deception pode ser encontrado em [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception).

### **Identificando Deception**

- **For User Objects**: Indicadores suspeitos incluem ObjectSID atípico, logons pouco frequentes, datas de criação e baixo bad password counts.
- **General Indicators**: Comparar atributos de possíveis objetos decoy com os de objetos genuínos pode revelar inconsistências. Ferramentas como [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) podem ajudar a identificar essas deceptions.

### **Contornando sistemas de detecção**

- **Microsoft ATA Detection Bypass**:
- **User Enumeration**: Evitar enumeração de sessões em Domain Controllers para prevenir a detecção pelo ATA.
- **Ticket Impersonation**: Utilizar chaves **aes** para criação de tickets ajuda a evadir a detecção por não rebaixar para NTLM.
- **DCSync Attacks**: Recomenda-se executar a partir de um non-Domain Controller para evitar a detecção do ATA, já que a execução direta de um Domain Controller disparará alertas.

## Referências

- [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
- [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

{{#include ../../banners/hacktricks-training.md}}
