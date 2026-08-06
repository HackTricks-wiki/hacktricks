# Kerberos Double Hop 問題

{{#include ../../banners/hacktricks-training.md}}


## はじめに

Kerberos の「Double Hop」問題は、攻撃者が **PowerShell**/**WinRM** などを使用して、**2 つの** **hop** をまたいで **Kerberos authentication** を使用しようとしたときに発生します。

**Kerberos** を介して **authentication** が行われると、**credentials** は **memory** に cache され**ません**。そのため、ユーザーがプロセスを実行中であっても、mimikatz を実行しても、そのマシン上でユーザーの **credentials** を**見つけることはできません**。

これは、Kerberos で接続すると次の手順が行われるためです。<sup>[[1]](#references)</sup>

1. User1 が credentials を提供し、**domain controller** が User1 に Kerberos **TGT** を返します。
2. User1 は **TGT** を使用して、Server1 に **connect** するための **service ticket** を要求します。
3. User1 は Server1 に **connect** し、**service ticket** を提供します。
4. **Server1** には User1 の **credentials** も User1 の **TGT** も cache されて**いません**。そのため、Server1 から User1 が 2 台目のサーバーへの login を試みても、**authenticate できません**。

### Unconstrained Delegation

PC で **unconstrained delegation** が有効になっている場合、この問題は発生しません。**Server** がアクセスする各ユーザーの **TGT** を**取得**するためです。さらに、unconstrained delegation が使用されている場合、そこから **Domain Controller を compromise** できる可能性があります。\
[**unconstrained delegation page の詳細情報**](unconstrained-delegation.md)。

### CredSSP

この問題を回避するもう 1 つの方法で、[**特に insecure**](https://docs.microsoft.com/en-us/powershell/module/microsoft.wsman.management/enable-wsmancredssp?view=powershell-7) なのが **Credential Security Support Provider** です。Microsoft の説明は次のとおりです。

> CredSSP authentication は、local computer から remote computer に user credentials を delegate します。この方法は、remote operation の security risk を高めます。remote computer が compromise された場合、credentials が渡されると、それらの credentials を使用して network session を control できます。

security concerns のため、production systems、sensitive networks、および同様の環境では **CredSSP** を disabled にすることを強く推奨します。**CredSSP** が enabled かどうかを確認するには、`Get-WSManCredSSP` command を実行できます。この command を使用すると、**CredSSP status の checking** が可能で、**WinRM** が enabled であれば remote から実行することもできます。
```bash
Invoke-Command -ComputerName bizintel -Credential ta\redsuit -ScriptBlock {
Get-WSManCredSSP
}
```
### Remote Credential Guard (RCG)

**Remote Credential Guard** は、RDP セッションが次の hop で新しい Kerberos service tickets を要求できる状態を維持しながら、ユーザーの TGT を接続元 workstation 上に保持します。**Computer Configuration > Administrative Templates > System > Credentials Delegation > Restrict delegation of credentials to remote servers** を有効にし、**Require Remote Credential Guard** を選択してから、CredSSP にフォールバックする代わりに `mstsc.exe /remoteGuard /v:server1` で接続します。

Microsoft は、Windows 11 22H2 以降での multi-hop access における RCG を、**April 2024 cumulative updates**（KB5036896/KB5036899/KB5036894）が提供されるまで壊れた状態にしていました。client と intermediary server に patch を適用しないと、second hop は引き続き失敗します。<sup>[[5]](#references)</sup> 簡単な hotfix の確認方法:
```powershell
("KB5036896","KB5036899","KB5036894") | ForEach-Object {
Get-HotFix -Id $_ -ErrorAction SilentlyContinue
}
```
これらのビルドをインストールすると、RDP hop は、最初のサーバー上で再利用可能な secret を公開することなく、下流の Kerberos challenge を満たせるようになります。

## 回避策

### Invoke Command

double hop の問題に対処するため、ネストした `Invoke-Command` を使用する方法が提示されています。これは問題を直接解決するものではありませんが、特別な設定を必要とせずに回避策を提供します。このアプローチでは、最初の攻撃マシンから実行する PowerShell command、または最初のサーバーとの間に確立済みの PS-Session を介して、2 台目のサーバー上で command（`hostname`）を実行できます。手順は次のとおりです。<sup>[[2]](#references)</sup>
```bash
$cred = Get-Credential ta\redsuit
Invoke-Command -ComputerName bizintel -Credential $cred -ScriptBlock {
Invoke-Command -ComputerName secdev -Credential $cred -ScriptBlock {hostname}
}
```
または、最初のサーバーとの PS-Session を確立し、`$cred` を使用して `Invoke-Command` を実行することで、タスクを一元化する方法が推奨されます。

### Register PSSession Configuration

ダブルホップ問題を回避する解決策として、`Enter-PSSession` とともに `Register-PSSessionConfiguration` を使用する方法があります。この方法では `evil-winrm` とは異なるアプローチが必要ですが、ダブルホップの制限を受けないセッションを確立できます。<sup>[[3]](#references)[[4]](#references)</sup>
```bash
Register-PSSessionConfiguration -Name doublehopsess -RunAsCredential domain_name\username
Restart-Service WinRM
Enter-PSSession -ConfigurationName doublehopsess -ComputerName TARGET_PC -Credential domain_name\username
klist
```
### PortForwarding

中継ターゲットの local administrators は、port forwarding を使用して最終サーバーにリクエストを送信できます。`netsh` を使用すると、転送ポートを許可する Windows firewall rule とともに、port forwarding の rule を追加できます。<sup>[[2]](#references)</sup>
```bash
netsh interface portproxy add v4tov4 listenport=5446 listenaddress=10.35.8.17 connectport=5985 connectaddress=10.35.8.23
netsh advfirewall firewall add rule name=fwd dir=in action=allow protocol=TCP localport=5446
```
#### winrs.exe

`winrs.exe` は WinRM リクエストの転送に使用でき、PowerShell の監視が懸念される場合には、検出されにくい選択肢となる可能性があります。<sup>[[2]](#references)</sup> 以下のコマンドは、その使用方法を示しています：
```bash
winrs -r:http://bizintel:5446 -u:ta\redsuit -p:2600leet hostname
```
### OpenSSH

最初のサーバーに OpenSSH をインストールすると、double-hop issue の回避策が利用でき、特に jump box のシナリオで役立ちます。この方法では、Windows 用 OpenSSH を CLI からインストールしてセットアップする必要があります。Password Authentication 用に構成すると、中間サーバーがユーザーに代わって TGT を取得できるようになります。<sup>[[2]](#references)</sup>

#### OpenSSH Installation Steps

1. 最新の OpenSSH リリースの zip ファイルをダウンロードし、対象サーバーに移動します。
2. 解凍し、`Install-sshd.ps1` スクリプトを実行します。
3. ポート 22 を開く firewall rule を追加し、SSH services が実行中であることを確認します。

`Connection reset` エラーを解決するには、OpenSSH ディレクトリへの everyone の read および execute access を許可するよう、permissions の更新が必要になる場合があります。
```bash
icacls.exe "C:\Users\redsuit\Documents\ssh\OpenSSH-Win64" /grant Everyone:RX /T
```
### LSA Whisperer CacheLogon (Advanced)

**LSA Whisperer** (2024) は `msv1_0!CacheLogon` パッケージ呼び出しを公開するため、`LogonUser` で新しいセッションを作成する代わりに、既存の *network logon* に既知の NT hash を注入できます。WinRM/PowerShell が hop #1 ですでに開いた logon session に hash を注入すると、そのホストは明示的な認証情報を保存したり、追加の 4624 イベントを生成したりせずに hop #2 へ authenticate できます。<sup>[[6]](#references)</sup>

1. LSASS 内部で code execution を取得します（PPL を無効化または悪用するか、自分で管理する lab VM 上で実行します）。
2. logon session を列挙し（例: `lsa.exe sessions`）、remoting context に対応する LUID を取得します。
3. NT hash を事前計算して `CacheLogon` に渡し、完了後にクリアします。
```powershell
lsa.exe cachelogon --session 0x3e4 --domain ta --username redsuit --nthash a7c5480e8c1ef0ffec54e99275e6e0f7
lsa.exe cacheclear --session 0x3e4
```
cache seed の後、hop #1 から `Invoke-Command`/`New-PSSession` を再実行します。LSASS は注入された hash を再利用して、2 番目の hop に対する Kerberos/NTLM challenge を処理するため、double hop の制約をきれいに回避できます。代償として telemetry がより重くなります（LSASS 内での code execution）ので、CredSSP/RCG が禁止されている、制約の厳しい環境で使用してください。

## References

- [1] [Kerberos Double Hop の理解 - Microsoft Community Hub](https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/understanding-kerberos-double-hop/ba-p/395463?lightbox-message-images-395463=102145i720503211E78AC20)
- [2] [Kerberos Double-Hop の回避策](https://posts.slayerlabs.com/double-hop/)
- [3] [multi-hop PowerShell remoting への別の解決策](https://learn.microsoft.com/en-gb/archive/blogs/sergey_babkins_blog/another-solution-to-multi-hop-powershell-remoting)
- [4] [CredSSP を使用せずに PowerShell multi-hop の問題を解決する](https://4sysops.com/archives/solve-the-powershell-multi-hop-problem-without-using-credssp/)
- [5] [2024 年 4 月 9 日 — KB5036896 (OS Build 17763.5696)](https://support.microsoft.com/en-au/topic/april-9-2024-kb5036896-os-build-17763-5696-efb580f1-2ce4-4695-b76c-d2068a00fb92)
- [6] [LSA Whisperer](https://specterops.io/blog/2024/04/17/lsa-whisperer/)

{{#include ../../banners/hacktricks-training.md}}
