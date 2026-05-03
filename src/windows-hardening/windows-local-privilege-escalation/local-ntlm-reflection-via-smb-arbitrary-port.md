# Local NTLM Reflection via SMB Arbitrary Port

{{#include ../../banners/hacktricks-training.md}}

Recent Windows builds introduced **SMB client support for alternative TCP ports**. That feature can be abused to turn **local NTLM authentication** into a **SYSTEM local privilege escalation** when the attacker can:

1. Open an SMB connection to an attacker-controlled listener on a **non-445 port**
2. Keep that TCP connection alive
3. Coerce a **privileged local client** to access the **same SMB share path**
4. Relay the resulting **local NTLM authentication** back to the machine's real SMB service

This is the primitive behind **CVE-2026-24294**, patched in **March 2026**.

## Why it works

The older CMTI / serialized-SPN reflection trick is covered here:

{{#ref}}
../ntlm/README.md
{{#endref}}

This newer variant does **not** need a marshalled hostname. Instead it abuses two SMB client behaviours:

- **Alternative port support** on **Windows 11 24H2** and **Windows Server 2025**, exposed to users with `net use \\host\share /tcpport:<port>`
- **SMB connection reuse / multiplexing**, where multiple authenticated sessions can ride the same TCP connection

That means a low-privileged user can first create a TCP connection from the SMB client to an attacker SMB server on a high port, then coerce a privileged service to access the **exact same UNC path**. If Windows decides to reuse the existing TCP connection, the privileged NTLM exchange is sent over the attacker-controlled transport and can be relayed to the local SMB server.

## Preconditions

- Target supports SMB alternative ports:
- **Windows 11 24H2** or later
- **Windows Server 2025** or later
- The attacker can run a local or remote SMB server on a chosen high port
- The attacker can coerce a privileged service to access a UNC path
- The privileged authentication must be **NTLM local authentication**
- The target must be relayable:
- Synacktiv reported it worked by default on **Windows Server 2025**
- Their chain did **not** work on **Windows 11 24H2** because outbound SMB signing is enforced there by default

## Userland and internals

From the command line the feature looks simple:
```cmd
net use \\192.168.56.3\share /tcpport:12345
```
Programaticamente, o cliente usa `WNetAddConnection4W` com dados `lpUseOptions` não documentados. A opção relevante é `TraP` (transport parameters), que eventualmente chega ao cliente SMB do kernel por meio de um FSCTL e é analisada por `mrxsmb`.

Notas práticas importantes:

- **UNC syntax ainda não tem campo de porta**
- **`net use` é por logon-session**
- O bypass ainda funciona porque **a conexão TCP e a SMB session são objetos separados**
- Reutilizar o **mesmo share path** é obrigatório se o exploit depender de o cliente SMB reutilizar a conexão TCP criada anteriormente

## Exploitation flow

### 1. Crie o transporte SMB controlado pelo atacante

Execute um servidor SMB em uma porta alta e faça o Windows conectar a ele:
```cmd
net use \\192.168.56.3\share /tcpport:12345
```
O servidor pode aceitar qualquer par de credenciais que você controlar, por exemplo `user:user`. O objetivo desta etapa ainda não é privilege escalation, apenas fazer o cliente SMB do Windows abrir e manter uma conexão TCP reutilizável para o seu listener.

### 2. Force um serviço privilegiado para o mesmo caminho UNC

Use um primitive de coercion como **PetitPotam** contra o **mesmo** caminho `\\192.168.56.3\share`. Se o cliente for privilegiado e o nome do alvo for local (`localhost` ou um IP/host local), o Windows realiza **NTLM local authentication**.

Como a conexão TCP é reutilizada, essa troca NTLM privilegiada vai para o serviço SMB do atacante em vez de ir diretamente para o servidor SMB local real.

### 3. Relaye a autenticação privilegiada de volta para o SMB local

O serviço SMB controlado pelo atacante encaminha a troca NTLM privilegiada para `ntlmrelayx.py`, que a relaya para o listener SMB real da máquina e obtém uma sessão como `NT AUTHORITY\SYSTEM`.

Ferramentas típicas do public writeup:

- `smbserver.py` em uma porta personalizada para receber a auth privilegiada pela conexão TCP reutilizada
- `ntlmrelayx.py` para relayer o NTLM capturado para o SMB local
- `PetitPotam.exe` ou outro primitive de coercion para forçar a autenticação privilegiada

## Operator notes

- Esta é uma técnica de **local privilege escalation**, não um truque genérico de relay remoto
- O serviço SMB controlado pelo atacante deve lidar com a autenticação privilegiada na **mesma conexão TCP** originalmente usada para montar o share
- Se o acesso coagido atingir um **caminho de share diferente**, o Windows pode estabelecer outra conexão e a cadeia quebra
- Requisitos de SMB signing podem quebrar o relay mesmo quando a etapa de arbitrary-port funciona
- Se você só tiver material Kerberos ou não conseguir forçar NTLM local, esta variante exata não é suficiente

## Detection and hardening

- Corrija **CVE-2026-24294** do **March 2026 Patch Tuesday**
- Monitore `net use` ou `New-SmbMapping` usando **non-default SMB ports**
- Alerta para SMB de saída incomum de workstations ou servers para **high TCP ports**
- Revise oportunidades de coercion como triggers **EFSRPC / PetitPotam-style**
- Implemente SMB signing quando possível; a Synacktiv observa especificamente que isso bloqueou o relay no Windows 11 24H2

## References

- [Synacktiv - Bypassing Windows authentication reflection mitigations for SYSTEM shells - Part 1](https://www.synacktiv.com/en/publications/bypassing-windows-authentication-reflection-mitigations-for-system-shells-part-1.html)
- [Microsoft Learn - Configure alternative SMB ports for Windows Server 2025](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-ports)
- [Microsoft Learn - WNetAddConnection4W](https://learn.microsoft.com/en-us/windows/win32/api/winnetwk/nf-winnetwk-wnetaddconnection4w)
- [Project Zero - Windows Exploitation Tricks: Trapping Virtual Memory Access (2025 Update)](https://projectzero.google/2025/01/windows-exploitation-tricks-trapping.html)
- [MSRC - CVE-2026-24294](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-24294)

{{#include ../../banners/hacktricks-training.md}}
