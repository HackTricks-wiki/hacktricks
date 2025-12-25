# Kerberos Double Hop Problem

{{#include ../../banners/hacktricks-training.md}}


## はじめに

Kerberosの「Double Hop」問題は、攻撃者が例えば**PowerShell**/**WinRM**を使って**Kerberos認証を2つのホップにまたがって**利用しようとしたときに発生します。

Kerberosを介して**認証**が行われると、**資格情報**は**メモリ**にキャッシュされません。したがって、mimikatzを実行しても、たとえユーザーがプロセスを実行していても、そのユーザーの**資格情報**はマシン上で見つかりません。

これはKerberosで接続する際に次の手順が行われるためです:

1. User1が資格情報を提供すると、**domain controller**はUser1にKerberosの**TGT**を返します。
2. User1は**TGT**を使ってServer1に接続するための**service ticket**を要求します。
3. User1は**Server1**に**接続**し、**service ticket**を提供します。
4. **Server1**はUser1の資格情報やUser1の**TGT**をキャッシュしていません。したがって、Server1からUser1が別のサーバにログインしようとしても、認証できません。

### Unconstrained Delegation

もしPCで**unconstrained delegation**が有効になっていると、この問題は発生しません。**Server**はアクセスする各ユーザーの**TGT**を取得するためです。さらに、unconstrained delegationが使用されていると、それを利用して**Domain Controller**を侵害できる可能性が高いです.\
[**More info in the unconstrained delegation page**](unconstrained-delegation.md).

### CredSSP

この問題を回避する別の方法は（[**notably insecure**](https://docs.microsoft.com/en-us/powershell/module/microsoft.wsman.management/enable-wsmancredssp?view=powershell-7)）、**Credential Security Support Provider**です。Microsoftによれば:

> CredSSP認証は、ユーザーの資格情報をローカルコンピューターからリモートコンピューターに委任します。この挙動はリモート操作のセキュリティリスクを高めます。リモートコンピューターが侵害された場合、資格情報が渡されると、それらの資格情報を使ってネットワークセッションを制御される可能性があります。

セキュリティ上の懸念から、**CredSSP**は本番システム、重要ネットワーク、類似の環境では無効にすることが強く推奨されます。**CredSSP**が有効かどうかを確認するには、`Get-WSManCredSSP`コマンドを実行できます。このコマンドは**CredSSPの状態の確認**を可能にし、**WinRM**が有効であればリモート実行もできます。
```bash
Invoke-Command -ComputerName bizintel -Credential ta\redsuit -ScriptBlock {
Get-WSManCredSSP
}
```
### Remote Credential Guard (RCG)

**Remote Credential Guard** は、ユーザーの TGT を発信元ワークステーションに保持したまま、RDP セッションが次のホップで新しい Kerberos サービスタケットを要求できるようにします。**Computer Configuration > Administrative Templates > System > Credentials Delegation > Restrict delegation of credentials to remote servers** を有効にし、**Require Remote Credential Guard** を選択してから、CredSSP にフォールバックする代わりに `mstsc.exe /remoteGuard /v:server1` で接続してください。

Microsoft は Windows 11 22H2+ のマルチホップアクセスで RCG を破壊しており、**2024年4月の累積更新プログラム** (KB5036896/KB5036899/KB5036894) まで修正されていませんでした。クライアントと中継サーバーにパッチを適用してください。さもないと 2 ホップ目は依然として失敗します。簡単なホットフィックス確認:
```powershell
("KB5036896","KB5036899","KB5036894") | ForEach-Object {
Get-HotFix -Id $_ -ErrorAction SilentlyContinue
}
```
With those builds installed, the RDP hop can satisfy downstream Kerberos challenges without exposing reusable secrets on the first server.

## Workarounds

### Invoke Command

double hop の問題に対処するために、ネストされた `Invoke-Command` を用いる方法が示されています。これは問題を直接解決するものではありませんが、特別な構成を必要とせずに回避策を提供します。このアプローチでは、最初の攻撃マシンから実行する PowerShell コマンド、あるいは最初のサーバーと既に確立された PS-Session を通じて、2次サーバー上でコマンド（`hostname`）を実行できます。実行方法は次のとおりです：
```bash
$cred = Get-Credential ta\redsuit
Invoke-Command -ComputerName bizintel -Credential $cred -ScriptBlock {
Invoke-Command -ComputerName secdev -Credential $cred -ScriptBlock {hostname}
}
```
Alternatively, establishing a PS-Session with the first server and running the `Invoke-Command` using `$cred` is suggested for centralizing tasks.

### Register PSSession Configuration

代わりに、最初のサーバーにPS-Sessionを確立し、`$cred` を使用して `Invoke-Command` を実行することでタスクを集約することが推奨されます。

double hop 問題を回避する解決策のひとつは、`Register-PSSessionConfiguration` を `Enter-PSSession` と共に使用することです。この方法は `evil-winrm` とは異なるアプローチを必要とし、double hop の制約を受けないセッションを可能にします。
```bash
Register-PSSessionConfiguration -Name doublehopsess -RunAsCredential domain_name\username
Restart-Service WinRM
Enter-PSSession -ConfigurationName doublehopsess -ComputerName TARGET_PC -Credential domain_name\username
klist
```
### PortForwarding

中間ターゲット上のローカル管理者は、ポートフォワーディングを使用してリクエストを最終サーバーに送信できます。`netsh` を使用してポートフォワーディングのルールを追加し、転送されたポートを許可するための Windows firewall rule も追加できます。
```bash
netsh interface portproxy add v4tov4 listenport=5446 listenaddress=10.35.8.17 connectport=5985 connectaddress=10.35.8.23
netsh advfirewall firewall add rule name=fwd dir=in action=allow protocol=TCP localport=5446
```
#### winrs.exe

`winrs.exe` は WinRM リクエストを転送するために使用でき、PowerShell の監視が懸念される場合には検出されにくい選択肢となる可能性があります。以下のコマンドはその使用例を示しています:
```bash
winrs -r:http://bizintel:5446 -u:ta\redsuit -p:2600leet hostname
```
### OpenSSH

最初のサーバーに OpenSSH をインストールすると、特に jump box シナリオで double-hop 問題 の回避策が利用可能になります。この方法は CLI を使用して OpenSSH for Windows をインストールおよび設定する必要があります。Password Authentication に設定すると、中継サーバーがユーザーに代わって TGT を取得できるようになります。

#### OpenSSH インストール手順

1. 最新の OpenSSH リリースの zip をダウンロードしてターゲットサーバーに移動します。
2. zip を解凍して `Install-sshd.ps1` スクリプトを実行します。
3. ファイアウォールルールを追加して port 22 を開放し、SSH services が稼働していることを確認します。

`Connection reset` エラーを解決するには、OpenSSH ディレクトリの権限を更新して everyone に読み取りおよび実行アクセスを許可する必要がある場合があります。
```bash
icacls.exe "C:\Users\redsuit\Documents\ssh\OpenSSH-Win64" /grant Everyone:RX /T
```
### LSA Whisperer CacheLogon (上級)

**LSA Whisperer** (2024) は `msv1_0!CacheLogon` パッケージ呼び出しを公開しており、`LogonUser` で新しいセッションを作成する代わりに既存の *network logon* に既知の NT ハッシュを注入してシードできます。ハッシュを hop #1 ですでに開かれている WinRM/PowerShell のログオンセッションに注入することで、そのホストは明示的な資格情報を保存したり追加の 4624 イベントを生成したりせずに hop #2 に認証できます。

1. LSASS 内でコード実行を取得する（PPL を無効化/悪用するか、あなたが管理する lab VM で実行する）。
2. ログオンセッションを列挙する（例: `lsa.exe sessions`）し、リモートコンテキストに対応する LUID を取得する。
3. NT ハッシュを事前に計算し、`CacheLogon` に渡して、完了後にクリアする。
```powershell
lsa.exe cachelogon --session 0x3e4 --domain ta --username redsuit --nthash a7c5480e8c1ef0ffec54e99275e6e0f7
lsa.exe cacheclear --session 0x3e4
```
cache seed の後、ホップ #1 から `Invoke-Command`/`New-PSSession` を再実行します: LSASS は注入されたハッシュを再利用して 2 番目のホップの Kerberos/NTLM チャレンジに応答し、double hop 制約をきれいに回避します。トレードオフはテレメトリの増大（LSASS 内でのコード実行）なので、CredSSP/RCG が禁止されている運用上負荷の高い環境でのみ使用してください。

## 参考文献

- [https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/understanding-kerberos-double-hop/ba-p/395463?lightbox-message-images-395463=102145i720503211E78AC20](https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/understanding-kerberos-double-hop/ba-p/395463?lightbox-message-images-395463=102145i720503211E78AC20)
- [https://posts.slayerlabs.com/double-hop/](https://posts.slayerlabs.com/double-hop/)
- [https://learn.microsoft.com/en-gb/archive/blogs/sergey_babkins_blog/another-solution-to-multi-hop-powershell-remoting](https://learn.microsoft.com/en-gb/archive/blogs/sergey_babkins_blog/another-solution-to-multi-hop-powershell-remoting)
- [https://4sysops.com/archives/solve-the-powershell-multi-hop-problem-without-using-credssp/](https://4sysops.com/archives/solve-the-powershell-multi-hop-problem-without-using-credssp/)
- [https://support.microsoft.com/en-au/topic/april-9-2024-kb5036896-os-build-17763-5696-efb580f1-2ce4-4695-b76c-d2068a00fb92](https://support.microsoft.com/en-au/topic/april-9-2024-kb5036896-os-build-17763-5696-efb580f1-2ce4-4695-b76c-d2068a00fb92)
- [https://specterops.io/blog/2024/04/17/lsa-whisperer/](https://specterops.io/blog/2024/04/17/lsa-whisperer/)


{{#include ../../banners/hacktricks-training.md}}
