# Metodologia do Active Directory

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Visão geral básica

O Active Directory permite que administradores de rede criem e gerenciem domínios, usuários e objetos dentro de uma rede. Por exemplo, um administrador pode criar um grupo de usuários e dar a eles privilégios de acesso específicos a determinados diretórios no servidor. À medida que uma rede cresce, o Active Directory fornece uma maneira de organizar um grande número de usuários em grupos e subgrupos lógicos, enquanto fornece controle de acesso em cada nível.

A estrutura do Active Directory inclui três camadas principais: 1) domínios, 2) árvores e 3) florestas. Vários objetos (usuários ou dispositivos) que usam o mesmo banco de dados podem ser agrupados em um único domínio. Vários domínios podem ser combinados em um único grupo chamado árvore. Múltiplas árvores podem ser agrupadas em uma coleção chamada floresta. Cada um desses níveis pode ser atribuído a direitos de acesso específicos e privilégios de comunicação.

Principais conceitos de um Active Directory:

1. **Diretório** - Contém todas as informações sobre os objetos do Active Directory
2. **Objeto** - Um objeto faz referência a quase qualquer coisa dentro do diretório (um usuário, grupo, pasta compartilhada...)
3. **Domínio** - Os objetos do diretório estão contidos dentro do domínio. Dentro de uma "floresta", mais de um domínio pode existir e cada um deles terá sua própria coleção de objetos.
4. **Árvore** - Grupo de domínios com a mesma raiz. Exemplo: _dom.local, email.dom.local, www.dom.local_
5. **Floresta** - A floresta é o nível mais alto da hierarquia da organização e é composta por um grupo de árvores. As árvores são conectadas por relacionamentos de confiança.

O Active Directory fornece vários serviços diferentes, que se enquadram no guarda-chuva de "Serviços de Domínio do Active Directory" ou AD DS. Esses serviços incluem:

1. **Serviços de Domínio** - armazena dados centralizados e gerencia a comunicação entre usuários e domínios; inclui autenticação de login e funcionalidade de pesquisa
2. **Serviços de Certificado** - cria, distribui e gerencia certificados seguros
3. **Serviços de Diretório Leve** - suporta aplicativos habilitados para diretório usando o protocolo aberto (LDAP)
4. **Serviços de Federação de Diretório** - fornece logon único (SSO) para autenticar um usuário em vários aplicativos da web em uma única sessão
5. **Gerenciamento de Direitos** - protege informações protegidas por direitos autorais, impedindo o uso e distribuição não autorizados de conteúdo digital
6. **Serviço DNS** - Usado para resolver nomes de domínio.

O AD DS está incluído no Windows Server (incluindo o Windows Server 10) e é projetado para gerenciar sistemas de clientes. Embora os sistemas que executam a versão regular do Windows não tenham os recursos administrativos do AD DS, eles suportam o Active Directory. Isso significa que qualquer computador com Windows pode se conectar a um grupo de trabalho do Windows, desde que o usuário tenha as credenciais de login corretas.\
**De:** [**https://techterms.com/definition/active\_directory**](https://techterms.com/definition/active\_directory)

### **Autenticação Kerberos**

Para aprender como **atacar um AD**, você precisa **entender** muito bem o **processo de autenticação Kerberos**.\
[**Leia esta página se você ainda não sabe como funciona.**](kerberos-authentication.md)

## Cheat Sheet

Você pode acessar [https://wadcoms.github.io/](https://wadcoms.github.io) para ter uma visão rápida dos comandos que você pode executar para enumerar/explorar um AD.

## Reconhecimento do Active Directory (sem credenciais/sessões)

Se você só tem acesso a um ambiente AD, mas não tem credenciais/sessões, você pode:

* **Testar a rede:**
  * Escanear a rede, encontrar máquinas e portas abertas e tentar **explorar vulnerabilidades** ou **extrair credenciais** delas (por exemplo, [impressoras podem ser alvos muito interessantes](ad-information-in-printers.md).
  * Enumerar DNS pode fornecer informações sobre servidores-chave no domínio, como web, impressoras, compartilhamentos, VPN, mídia, etc.
    * `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
  * Dê uma olhada na [**Metodologia de Pentesting Genérica**](../../generic-methodologies-and-resources/pentesting-method
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
```
* **Servidor OWA (Outlook Web Access)**

Se você encontrou um desses servidores na rede, também pode realizar **enumeração de usuários** contra ele. Por exemplo, você pode usar a ferramenta [**MailSniper**](https://github.com/dafthack/MailSniper):
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
{% hint style="warning" %}
Você pode encontrar listas de nomes de usuário neste [**repositório do Github**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names) e neste outro ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)).

No entanto, você deve ter o **nome das pessoas que trabalham na empresa** a partir da etapa de reconhecimento que você deve ter realizado antes disso. Com o nome e sobrenome, você pode usar o script [**namemash.py**](https://gist.github.com/superkojiman/11076951) para gerar possíveis nomes de usuário válidos.
{% endhint %}

### Sabendo um ou vários nomes de usuário

Ok, então você sabe que já tem um nome de usuário válido, mas não tem senhas... Então tente:

* [**ASREPRoast**](asreproast.md): Se um usuário **não tem** o atributo _DONT\_REQ\_PREAUTH_, você pode **solicitar uma mensagem AS\_REP** para esse usuário que conterá alguns dados criptografados por uma derivação da senha do usuário.
* [**Password Spraying**](password-spraying.md): Vamos tentar as senhas mais **comuns** com cada um dos usuários descobertos, talvez algum usuário esteja usando uma senha ruim (lembre-se da política de senhas!).
  * Observe que você também pode **testar servidores OWA** para tentar acessar os servidores de e-mail dos usuários.

{% content-ref url="password-spraying.md" %}
[password-spraying.md](password-spraying.md)
{% endcontent-ref %}

### Envenenamento LLMNR/NBT-NS

Você pode ser capaz de **obter** alguns **hashes** de desafio para quebrar **envenenando** alguns protocolos da **rede**:

{% content-ref url="../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md" %}
[spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
{% endcontent-ref %}

### NTML Relay

Se você conseguiu enumerar o Active Directory, terá **mais e-mails e uma melhor compreensão da rede**. Você pode ser capaz de forçar ataques de **retransmissão NTML** para obter acesso ao ambiente AD.

### Roubar credenciais NTLM

Se você pode **acessar outros PCs ou compartilhamentos** com o usuário **null ou guest**, você pode **colocar arquivos** (como um arquivo SCF) que, se acessados de alguma forma, irão **disparar uma autenticação NTML contra você** para que você possa **roubar** o **desafio NTLM** para quebrá-lo:

{% content-ref url="../ntlm/places-to-steal-ntlm-creds.md" %}
[places-to-steal-ntlm-creds.md](../ntlm/places-to-steal-ntlm-creds.md)
{% endcontent-ref %}

## Enumerando o Active Directory COM credenciais/sessão

Para esta fase, você precisa ter **comprometido as credenciais ou uma sessão de uma conta de domínio válida**. Se você tiver algumas credenciais válidas ou um shell como um usuário de domínio, **lembre-se de que as opções dadas anteriormente ainda são opções para comprometer outros usuários**.

Antes de começar a enumeração autenticada, você deve saber o que é o **problema de duplo salto Kerberos**.

{% content-ref url="kerberos-double-hop-problem.md" %}
[kerberos-double-hop-problem.md](kerberos-double-hop-problem.md)
{% endcontent-ref %}

### Enumeração

Ter comprometido uma conta é um **grande passo para começar a comprometer todo o domínio**, porque você vai ser capaz de começar a **Enumeração do Active Directory**:

Com relação ao [**ASREPRoast**](asreproast.md), agora você pode encontrar todos os usuários vulneráveis possíveis, e com relação ao [**Password Spraying**](password-spraying.md), você pode obter uma **lista de todos os nomes de usuário** e tentar a senha da conta comprometida, senhas vazias e novas senhas promissoras.

* Você pode usar o [**CMD para realizar uma recon básica**](../basic-cmd-for-pentesters.md#domain-info)
* Você também pode usar o [**powershell para recon**](../basic-powershell-for-pentesters/) que será mais furtivo
* Você também pode [**usar o powerview**](../basic-powershell-for-pentesters/powerview.md) para extrair informações mais detalhadas
* Outra ferramenta incrível para recon em um Active Directory é o [**BloodHound**](bloodhound.md). Não é muito furtivo (dependendo dos métodos de coleta que você usa), mas **se você não se importa** com isso, você deve experimentá-lo. Encontre onde os usuários podem RDP, encontre o caminho para outros grupos, etc.
  * **Outras ferramentas automatizadas de enumeração AD são:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
* \*\*\*\*[**Registros DNS do AD**](ad-dns-records.md) \*\*\*\* pois podem conter informações interessantes.
* Uma **ferramenta com GUI** que você pode usar para enumerar o diretório é o **AdExplorer.exe** da **SysInternal** Suite.
* Você também pode pesquisar no banco de dados LDAP com **ldapsearch** para procurar credenciais nos campos _userPassword_ e _unixUserPassword_, ou mesmo em _Description_. cf. [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) para outros métodos.
* Se você estiver usando o **Linux**, também pode enumerar o domínio usando [**pywerview**](https://github.com/the-useless-one/pywerview).
* Você também pode tentar ferramentas automatizadas como:
  * [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
  * [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
*   **Extraindo todos os usuários do domínio**

    É muito fácil obter todos os nomes de usuário do domínio no Windows (`net user /domain`, `Get-DomainUser` ou `wmic useraccount get name,sid`). No Linux, você pode usar: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` ou `enum4linux -a -u "user" -p "password" <DC IP>`

> Mesmo que esta seção de Enumeração pareça pequena, ela é a parte mais importante de todas. Acesse os links (principalmente o de cmd, powershell, powerview e BloodHound), aprenda como enumerar um domínio e pratique até se sentir confortável. Durante uma avaliação, este será o momento chave para encontrar o caminho para DA ou decidir que nada pode ser feito.

### Kerberoast

O objetivo do Kerberoasting é coletar **tickets TGS para serviços que são executados em nome de contas de usuário de domínio**. Parte desses tickets TGS são **criptografados com chaves derivadas de senhas de usuário**. Como consequência, suas credenciais podem ser **quebradas offline**.\
Mais sobre isso em:

{% content-ref url="kerberoast.md" %}
[kerberoast.md](kerberoast.md)
{% endcontent-ref %}

### Conexão remota (RDP, SSH, FTP, Win-RM, etc)

Depois de obter algumas credenciais, você pode verificar se tem acesso a qualquer **máquina**. Para isso, você pode usar o **CrackMapExec** para tentar se conectar em vários servidores com diferentes protocolos, de acordo com suas varreduras de portas
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTML Relay

Se você conseguiu enumerar o Active Directory, terá **mais e-mails e uma melhor compreensão da rede**. Você pode ser capaz de forçar ataques de [**relé NTML**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**.**

### **Procurando Credenciais em Compartilhamentos de Computador**

Agora que você tem algumas credenciais básicas, deve verificar se pode **encontrar** quaisquer **arquivos interessantes compartilhados dentro do AD**. Você poderia fazer isso manualmente, mas é uma tarefa muito chata e repetitiva (e mais ainda se você encontrar centenas de documentos que precisa verificar).

[**Siga este link para aprender sobre as ferramentas que você pode usar.**](../../network-services-pentesting/pentesting-smb.md#domain-shared-folders-search)

### Roubar Credenciais NTLM

Se você pode **acessar outros PCs ou compartilhamentos**, você pode **colocar arquivos** (como um arquivo SCF) que, se acessados de alguma forma, irão **disparar uma autenticação NTML contra você** para que você possa **roubar** o **desafio NTLM** para quebrá-lo:

{% content-ref url="../ntlm/places-to-steal-ntlm-creds.md" %}
[places-to-steal-ntlm-creds.md](../ntlm/places-to-steal-ntlm-creds.md)
{% endcontent-ref %}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Essa vulnerabilidade permitiu que qualquer usuário autenticado **comprometesse o controlador de domínio**.

{% content-ref url="printnightmare.md" %}
[printnightmare.md](printnightmare.md)
{% endcontent-ref %}

## Escalação de privilégios no Active Directory COM credenciais/sessão privilegiada

**Para as seguintes técnicas, um usuário de domínio regular não é suficiente, você precisa de algumas credenciais/privilégios especiais para realizar esses ataques.**

### Extração de Hash

Com sorte, você conseguiu **comprometer alguma conta de administrador local** usando [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) incluindo relaying, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [escalando privilégios localmente](../windows-local-privilege-escalation/).\
Então, é hora de despejar todos os hashes na memória e localmente.\
[**Leia esta página sobre diferentes maneiras de obter os hashes.**](broken-reference)

### Pass the Hash

**Depois de ter o hash de um usuário**, você pode usá-lo para **se passar por ele**.\
Você precisa usar alguma **ferramenta** que irá **realizar** a **autenticação NTLM usando** esse **hash**, **ou** você poderia criar um novo **sessionlogon** e **injetar** esse **hash** dentro do **LSASS**, então quando qualquer **autenticação NTLM for realizada**, esse **hash será usado**. A última opção é o que o mimikatz faz.\
[**Leia esta página para mais informações.**](../ntlm/#pass-the-hash)

### Over Pass the Hash/Pass the Key

Este ataque tem como objetivo **usar o hash NTLM do usuário para solicitar tickets Kerberos**, como uma alternativa ao comum Pass The Hash sobre o protocolo NTLM. Portanto, isso pode ser especialmente **útil em redes onde o protocolo NTLM é desativado** e apenas **Kerberos é permitido** como protocolo de autenticação.

{% content-ref url="over-pass-the-hash-pass-the-key.md" %}
[over-pass-the-hash-pass-the-key.md](over-pass-the-hash-pass-the-key.md)
{% endcontent-ref %}

### Pass the Ticket

Este ataque é semelhante ao Pass the Key, mas em vez de usar hashes para solicitar um ticket, o **próprio ticket é roubado** e usado para autenticar como seu proprietário.

{% content-ref url="pass-the-ticket.md" %}
[pass-the-ticket.md](pass-the-ticket.md)
{% endcontent-ref %}

### Reutilização de Credenciais

Se você tem o **hash** ou **senha** de um **administrador local**, você deve tentar **fazer login localmente** em outros **PCs** com ele.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
{% hint style="warning" %}
Observe que isso é bastante **ruidoso** e o **LAPS** iria **mitigar** isso.
{% endhint %}

### MSSQL Abuse & Trusted Links

Se um usuário tem privilégios para **acessar instâncias MSSQL**, ele pode ser capaz de usá-lo para **executar comandos** no host MSSQL (se estiver em execução como SA), **roubar** o **hash** NetNTLM ou até mesmo realizar um **ataque de relé**.\
Além disso, se uma instância MSSQL é confiável (link de banco de dados) por uma instância MSSQL diferente. Se o usuário tiver privilégios sobre o banco de dados confiável, ele poderá **usar o relacionamento de confiança para executar consultas também na outra instância**. Essas confianças podem ser encadeadas e, em algum momento, o usuário pode ser capaz de encontrar um banco de dados mal configurado onde pode executar comandos.\
**Os links entre bancos de dados funcionam mesmo em confianças de floresta.**

{% content-ref url="abusing-ad-mssql.md" %}
[abusing-ad-mssql.md](abusing-ad-mssql.md)
{% endcontent-ref %}

### Delegação não restrita

Se você encontrar algum objeto de computador com o atributo [ADS\_UF\_TRUSTED\_FOR\_DELEGATION](https://msdn.microsoft.com/en-us/library/aa772300\(v=vs.85\).aspx) e tiver privilégios de domínio no computador, poderá despejar TGTs da memória de todos os usuários que fazem login no computador.\
Portanto, se um **Administrador de Domínio fizer login no computador**, você poderá despejar seu TGT e se passar por ele usando [Pass the Ticket](pass-the-ticket.md).\
Graças à delegação restrita, você pode até mesmo **comprometer automaticamente um servidor de impressão** (esperançosamente será um DC).

{% content-ref url="unconstrained-delegation.md" %}
[unconstrained-delegation.md](unconstrained-delegation.md)
{% endcontent-ref %}

### Delegação restrita

Se um usuário ou computador tiver permissão para "Delegação restrita", ele poderá **se passar por qualquer usuário para acessar alguns serviços em um computador**.\
Então, se você **comprometer o hash** deste usuário / computador, poderá **se passar por qualquer usuário** (até mesmo administradores de domínio) para acessar alguns serviços.

{% content-ref url="constrained-delegation.md" %}
[constrained-delegation.md](constrained-delegation.md)
{% endcontent-ref %}

### Delegação baseada em recursos

É possível obter a execução de código com **privilégios elevados em um computador remoto se você tiver privilégio de gravação** no objeto AD desse computador.

{% content-ref url="resource-based-constrained-delegation.md" %}
[resource-based-constrained-delegation.md](resource-based-constrained-delegation.md)
{% endcontent-ref %}

### Abuso de ACLs

O usuário comprometido pode ter alguns **privilégios interessantes sobre alguns objetos de domínio** que podem permitir que você **se mova** lateralmente / **eleve** privilégios.

{% content-ref url="acl-persistence-abuse/" %}
[acl-persistence-abuse](acl-persistence-abuse/)
{% endcontent-ref %}

### Abuso do serviço de spooler de impressão

Se você puder encontrar algum **serviço de spooler ouvindo** dentro do domínio, poderá **abusar** dele para **obter novas credenciais** e **elevar privilégios**.\
[**Mais informações sobre como abusar dos serviços de spooler aqui.**](printers-spooler-service-abuse.md)

### Abuso de sessões de terceiros

Se **outros usuários acessarem** a **máquina comprometida**, é possível **coletar credenciais da memória** e até mesmo **injetar beacons em seus processos** para se passar por eles.\
Normalmente, os usuários acessarão o sistema via RDP, então aqui você tem como realizar alguns ataques em sessões RDP de terceiros:

{% content-ref url="rdp-sessions-abuse.md" %}
[rdp-sessions-abuse.md](rdp-sessions-abuse.md)
{%
### Diferentes confianças

É importante notar que **uma confiança pode ser de uma via ou de duas vias**. Na opção de duas vias, ambos os domínios confiarão um no outro, mas na relação de confiança de **uma via**, um dos domínios será o **confiável** e o outro o domínio **confiante**. Neste último caso, **você só poderá acessar recursos dentro do domínio confiante a partir do confiável**.

Se o Domínio A confia no Domínio B, A é o domínio confiante e B é o domínio confiável. Além disso, no **Domínio A**, isso seria uma **confiança de saída**; e no **Domínio B**, isso seria uma **confiança de entrada**.

**Diferentes relacionamentos de confiança**

* **Pai-Filho** - parte da mesma floresta - um domínio filho mantém uma confiança transitiva implícita de duas vias com seu pai. Este é provavelmente o tipo mais comum de confiança que você encontrará.
* **Cross-link** - também conhecido como uma confiança "shortcut" entre domínios filhos para melhorar os tempos de referência. Normalmente, as referências em uma floresta complexa têm que filtrar até a raiz da floresta e depois voltar para o domínio de destino, então, para um cenário geograficamente disperso, os cross-links podem fazer sentido para reduzir os tempos de autenticação.
* **Externo** - uma confiança implicitamente não transitiva criada entre domínios díspares. "[As confianças externas fornecem acesso a recursos em um domínio fora da floresta que ainda não foi unido por uma confiança de floresta.](https://technet.microsoft.com/en-us/library/cc773178\(v=ws.10\).aspx)" As confianças externas aplicam a filtragem SID, uma proteção de segurança abordada posteriormente neste post.
* **Raiz da árvore** - uma confiança transitiva implícita de duas vias entre o domínio raiz da floresta e a nova raiz da árvore que você está adicionando. Eu não encontrei confianças de raiz de árvore com muita frequência, mas a partir da [documentação da Microsoft](https://technet.microsoft.com/en-us/library/cc773178\(v=ws.10\).aspx), elas são criadas quando você cria uma nova árvore de domínio em uma floresta. Estas são confianças intra-floresta e elas [preservam a transitividade de duas vias](https://technet.microsoft.com/en-us/library/cc757352\(v=ws.10\).aspx) permitindo que a árvore tenha um nome de domínio separado (em vez de filho.pai.com).
* **Floresta** - uma confiança transitiva entre dois domínios raiz da floresta. As confianças de floresta também aplicam a filtragem SID.
* **MIT** - uma confiança com um domínio Kerberos não-Windows [compatível com RFC4120](https://tools.ietf.org/html/rfc4120). Espero mergulhar mais nas confianças MIT no futuro.

#### Outras diferenças em **relacionamentos de confiança**

* Um relacionamento de confiança também pode ser **transitivo** (A confia em B, B confia em C, então A confia em C) ou **não transitivo**.
* Um relacionamento de confiança pode ser configurado como **confiança bidirecional** (ambos confiam um no outro) ou como **confiança de uma via** (apenas um deles confia no outro).

### Caminho de ataque

1. **Enumerar** os relacionamentos de confiança
2. Verifique se algum **principal de segurança** (usuário/grupo/computador) tem **acesso** a recursos do **outro domínio**, talvez por entradas ACE ou por estar em grupos do outro domínio. Procure por **relacionamentos entre domínios** (a confiança foi criada para isso, provavelmente).
   1. Kerberoast, neste caso, pode ser outra opção.
3. **Comprometer** as **contas** que podem **pivô** através dos domínios.

Existem três maneiras **principais** pelas quais os principais de segurança (usuários/grupos/computadores) de um domínio podem ter acesso a recursos em outro domínio confiável/estrangeiro:

* Eles podem ser adicionados a **grupos locais** em máquinas individuais, ou seja, o grupo local "Administradores" em um servidor.
* Eles podem ser adicionados a **grupos no domínio estrangeiro**. Existem algumas ressalvas dependendo do tipo de confiança e do escopo do grupo, descritos em breve.
* Eles podem ser adicionados como principais em uma **lista de controle de acesso**, mais interessante para nós como principais em **ACEs** em um **DACL**. Para mais informações sobre ACLs/DACLs/ACEs, confira o whitepaper "[An ACE Up The Sleeve](https://specterops.io/assets/resources/an\_ace\_up\_the\_sleeve.pdf)".
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
{% hint style="warning" %}
Existem **2 chaves confiáveis**, uma para _Filho --> Pai_ e outra para _Pai_ --> _Filho_.\
Você pode verificar qual é a usada pelo domínio atual com:
```bash
Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
```
{% endhint %}

#### Injeção de SID-History

Escalando como administrador da empresa para o domínio filho/pai abusando da confiança com a injeção de SID-History:

{% content-ref url="sid-history-injection.md" %}
[sid-history-injection.md](sid-history-injection.md)
{% endcontent-ref %}

#### Explorando a NC de Configuração gravável

A NC de Configuração é o repositório primário de informações de configuração para uma floresta e é replicada para todos os DCs na floresta. Além disso, cada DC gravável (não DCs somente leitura) na floresta possui uma cópia gravável da NC de Configuração. Explorar isso requer a execução como SYSTEM em um DC (filho).

É possível comprometer o domínio raiz de várias maneiras. Exemplos:

* [Vincular GPO ao site do DC raiz](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research)
* [Comprometer gMSA](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent)
* [Ataque de esquema](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent)
* Explorar ADCS - Criar/modificar modelo de certificado para permitir autenticação como qualquer usuário (por exemplo, administradores da empresa)

### Domínio de Floresta Externa - Unidirecional (Entrada) ou bidirecional
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
Neste cenário, **seu domínio é confiável** por um externo, dando a você **permissões indeterminadas** sobre ele. Você precisará descobrir **quais princípios do seu domínio têm acesso ao domínio externo** e, em seguida, tentar explorá-lo:

{% content-ref url="external-forest-domain-oneway-inbound.md" %}
[external-forest-domain-oneway-inbound.md](external-forest-domain-oneway-inbound.md)
{% endcontent-ref %}

### Domínio de Floresta Externa - Apenas um Sentido (Saída)
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
Neste cenário, **seu domínio** está **confiando** alguns **privilégios** a um principal de um **domínio diferente**.

No entanto, quando um **domínio é confiável** pelo domínio confiante, o domínio confiável **cria um usuário** com um **nome previsível** que usa como **senha a senha confiável**. O que significa que é possível **acessar um usuário do domínio confiante para entrar no domínio confiável** para enumerá-lo e tentar escalar mais privilégios:

{% content-ref url="external-forest-domain-one-way-outbound.md" %}
[external-forest-domain-one-way-outbound.md](external-forest-domain-one-way-outbound.md)
{% endcontent-ref %}

Outra maneira de comprometer o domínio confiável é encontrar um [**link confiável SQL**](abusing-ad-mssql.md#mssql-trusted-links) criado na **direção oposta** da confiança do domínio (o que não é muito comum).

Outra maneira de comprometer o domínio confiável é esperar em uma máquina onde um **usuário do domínio confiável pode acessar** para fazer login via **RDP**. Então, o atacante poderia injetar código no processo da sessão RDP e **acessar o domínio de origem da vítima** a partir daí.\
Além disso, se a **vítima montou seu disco rígido**, a partir do processo da sessão RDP, o atacante poderia armazenar **backdoors** na **pasta de inicialização do disco rígido**. Essa técnica é chamada de **RDPInception**.

{% content-ref url="rdp-sessions-abuse.md" %}
[rdp-sessions-abuse.md](rdp-sessions-abuse.md)
{% endcontent-ref %}

### Mitigação de abuso de confiança de domínio

**Filtragem de SID:**

* Evite ataques que abusam do atributo de histórico de SID em confiança entre florestas.
* Habilitado por padrão em todas as confianças inter-florestais. As confianças intra-florestais são consideradas seguras por padrão (a Microsoft considera a floresta e não o domínio como uma fronteira de segurança).
* Mas, como a filtragem de SID tem o potencial de quebrar aplicativos e acesso do usuário, muitas vezes é desativada.
* Autenticação seletiva
  * Em uma confiança inter-florestal, se a Autenticação seletiva estiver configurada, os usuários entre as confianças não serão autenticados automaticamente. O acesso individual a domínios e servidores no domínio/floresta confiante deve ser concedido.
* Não impede a exploração de NC de Configuração gravável e ataque de conta de confiança.

[**Mais informações sobre confiança de domínio em ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## AD -> Nuvem e Nuvem -> AD

{% embed url="https://cloud.hacktricks.xyz/pentesting-cloud/azure-security/az-lateral-movements/azure-ad-connect-hybrid-identity" %}

## Algumas defesas gerais

[**Saiba mais sobre como proteger credenciais aqui.**](../stealing-credentials/credentials-protections.md)\
**Por favor, encontre algumas migrações contra cada técnica na descrição da técnica.**

* Não permita que os administradores de domínio façam login em nenhum outro host além dos controladores de domínio
* Nunca execute um serviço com privilégios de DA
* Se você precisar de privilégios de administrador de domínio, limite o tempo: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`

### Decepção

* A senha não expira
* Confiável para delegação
* Usuários com SPN
* Senha na descrição
* Usuários que são membros de grupos de alta privilégio
* Usuários com direitos de ACL sobre outros usuários, grupos ou contêineres
* Objetos de computador
* ...
* [https://github.com/samratashok/Deploy-Deception](https://github.com/samratashok/Deploy-Deception)
  * `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`

## Como identificar a decepção

**Para objetos de usuário:**

* ObjectSID (diferente do domínio)
* lastLogon, lastlogontimestamp
* Logoncount (número muito baixo é suspeito)
* whenCreated
* Badpwdcount (número muito baixo é suspeito)

**Geral:**

* Algumas soluções preenchem com informações em todos os atributos possíveis. Por exemplo, compare os atributos de um objeto de computador com o atributo de um objeto de computador 100% real como DC. Ou usuários contra o RID 500 (administrador padrão).
* Verifique se algo é bom demais para ser verdade
* [https://github.com/JavelinNetworks/HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster)

### Bypassing Microsoft ATA detection

#### Enumeração de usuário

ATA só reclama quando você tenta enumerar sessões no DC, então se você não procurar sessões no DC, mas no resto dos hosts, provavelmente não será detectado.

#### Criação de impersonação de tickets (Over pass the hash, golden ticket...)

Sempre crie os tickets usando as chaves **aes** também porque o que ATA identifica como malicioso é a degradação para NTLM.

#### DCSync

Se você não executar isso a partir de um Controlador de Domínio, o ATA vai pegar você, desculpe.

## Mais ferramentas

* [Script do Powershell para automação de auditoria de domínio](https://github.com/phillips321/adaudit)
* [Script Python para enumerar o Active Directory](https://github.com/ropnop/windapsearch)
* [Script Python para enumerar o Active Directory](https://github.com/CroweCybersecurity/ad-ldap-enum)

## Referências

* [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>
