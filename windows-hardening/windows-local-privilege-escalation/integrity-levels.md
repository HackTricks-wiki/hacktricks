<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)でゼロからヒーローまでのAWSハッキングを学ぶ</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksに広告を掲載したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください。
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションをチェックする
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に**参加する**か、[**テレグラムグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォローする**。
* **HackTricks**と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出して、あなたのハッキングのコツを共有してください。

</details>


# Integrity Levels

Windows Vistaから、**保護されたオブジェクトには整合性レベルがラベル付けされています**。システム上のほとんどのユーザーとシステムファイル、レジストリキーには、デフォルトで「中」の整合性ラベルが付けられています。主な例外は、Internet Explorer 7が低整合性で書き込み可能な特定のフォルダとファイルです。**ほとんどのプロセス**は**標準ユーザー**によって実行される場合、**中整合性**でラベル付けされます（管理者グループ内のユーザーによって開始されたものであっても）、そしてほとんどの**サービス**は**システム整合性**でラベル付けされます。ルートディレクトリは高整合性ラベルで保護されています。\
低整合性レベルのプロセスは、高整合性レベルのオブジェクトに書き込むことはできないことに注意してください。\
整合性レベルにはいくつかのレベルがあります：

* **Untrusted** – 匿名でログオンされたプロセスは自動的にUntrustedとして指定されます。_例: Chrome_
* **Low** – 低整合性レベルは、インターネットとのデフォルトのやり取りに使用されるレベルです。Internet Explorerがデフォルトの状態、保護モードで実行されている限り、それに関連するすべてのファイルとプロセスは低整合性レベルに割り当てられます。**一時インターネットフォルダ**などの一部のフォルダもデフォルトで**低整合性**レベルに割り当てられます。ただし、**低整合性プロセス**は非常に**制限されており**、**レジストリ**に書き込むことはできず、現在のユーザープロファイルの**ほとんどの場所**に書き込むことも制限されています。_例: Internet ExplorerまたはMicrosoft Edge_
* **Medium** – 中整合性は、**ほとんどのオブジェクトが実行されるコンテキスト**です。標準ユーザーは中整合性レベルを受け取り、明示的に低いまたは高い整合性レベルに指定されていないオブジェクトはデフォルトで中整合性です。管理者グループ内のユーザーもデフォルトでは中整合性レベルを使用することに注意してください。
* **High** – **管理者**は高整合性レベルが与えられます。これにより、管理者は中または低整合性レベルに割り当てられたオブジェクトとやり取りし、変更することができるだけでなく、標準ユーザーができない高整合性レベルの他のオブジェクトに対しても行動することができます。_例: "管理者として実行"_
* **System** – 名前が示すように、システム整合性レベルはシステムに予約されています。Windowsカーネルとコアサービスはシステム整合性レベルが与えられます。管理者の高整合性レベルよりもさらに高いことにより、これらのコア機能が管理者によって影響を受けたり、妥協されたりすることから保護されます。例: サービス
* **Installer** – インストーラー整合性レベルは特別なケースであり、すべての整合性レベルの中で最も高いです。他のすべてのWIC整合性レベルと同等またはそれ以上であるため、インストーラー整合性レベルに割り当てられたオブジェクトは、他のすべてのオブジェクトをアンインストールすることもできます。

**Sysinternals**の**Process Explorer**を使用してプロセスの整合性レベルを取得し、プロセスの**プロパティ**にアクセスして"**セキュリティ**"タブを表示することができます：

![](<../../.gitbook/assets/image (318).png>)

また、`whoami /groups`を使用して**現在の整合性レベル**を取得することもできます：

![](<../../.gitbook/assets/image (319).png>)

## ファイルシステム内の整合性レベル

ファイルシステム内のオブジェクトは、**最小の整合性レベル要件**が必要になる場合があり、プロセスがこの整合性プロセスを持っていない場合、それと対話することはできません。\
例えば、**通常のユーザーコンソールから通常のファイルを作成し、権限をチェックしてみましょう**：
```
echo asd >asd.txt
icacls asd.txt
asd.txt BUILTIN\Administrators:(I)(F)
DESKTOP-IDJHTKP\user:(I)(F)
NT AUTHORITY\SYSTEM:(I)(F)
NT AUTHORITY\INTERACTIVE:(I)(M,DC)
NT AUTHORITY\SERVICE:(I)(M,DC)
NT AUTHORITY\BATCH:(I)(M,DC)
```
```markdown
これで、ファイルに最低限の整合性レベル**High**を割り当てましょう。これは**管理者**として実行されている**コンソール**から**行う必要があります**。なぜなら、**通常のコンソール**はMedium Integrityレベルで実行されており、オブジェクトにHigh Integrityレベルを割り当てることが**許可されていない**からです:
```
```
icacls asd.txt /setintegritylevel(oi)(ci) High
processed file: asd.txt
Successfully processed 1 files; Failed processing 0 files

C:\Users\Public>icacls asd.txt
asd.txt BUILTIN\Administrators:(I)(F)
DESKTOP-IDJHTKP\user:(I)(F)
NT AUTHORITY\SYSTEM:(I)(F)
NT AUTHORITY\INTERACTIVE:(I)(M,DC)
NT AUTHORITY\SERVICE:(I)(M,DC)
NT AUTHORITY\BATCH:(I)(M,DC)
Mandatory Label\High Mandatory Level:(NW)
```
ここで面白くなってきます。ユーザー `DESKTOP-IDJHTKP\user` がファイルに対して**完全な権限**を持っていることがわかります（実際にこのファイルを作成したのはこのユーザーでした）。しかし、実装されている最低限の整合性レベルのため、ハイインテグリティレベルで実行していない限り、ファイルを変更することはできません（ただし、読み取りは可能です）：
```
echo 1234 > asd.txt
Access is denied.

del asd.txt
C:\Users\Public\asd.txt
Access is denied.
```
{% hint style="info" %}
**したがって、ファイルに最小の整合性レベルが設定されている場合、それを変更するには少なくともその整合性レベルで実行している必要があります。**
{% endhint %}

## バイナリの整合性レベル

`cmd.exe`のコピーを`C:\Windows\System32\cmd-low.exe`に作成し、**管理者コンソールから低い整合性レベルを設定しました：**
```
icacls C:\Windows\System32\cmd-low.exe
C:\Windows\System32\cmd-low.exe NT AUTHORITY\SYSTEM:(I)(F)
BUILTIN\Administrators:(I)(F)
BUILTIN\Users:(I)(RX)
APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(I)(RX)
APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APP PACKAGES:(I)(RX)
Mandatory Label\Low Mandatory Level:(NW)
```
```markdown
これで、`cmd-low.exe`を実行すると、中間レベルではなく**低整合性レベルで実行されます**：

![](<../../.gitbook/assets/image (320).png>)

興味のある方へ、バイナリに高整合性レベルを割り当てる場合（`icacls C:\Windows\System32\cmd-high.exe /setintegritylevel high`）、自動的に高整合性レベルで実行されるわけではありません（デフォルトでは中間整合性レベルから呼び出された場合、中間整合性レベルで実行されます）。

## プロセスの整合性レベル

すべてのファイルやフォルダに最小の整合性レベルがあるわけではありませんが、**すべてのプロセスはある整合性レベルの下で実行されています**。そして、ファイルシステムと同様に、**プロセスが別のプロセス内に書き込みたい場合、少なくとも同じ整合性レベルを持っている必要があります**。これは、低整合性レベルのプロセスは、中間整合性レベルのプロセスに対して完全アクセス権を持つハンドルを開くことができないことを意味します。

このセクションと前のセクションでコメントされた制限により、セキュリティの観点から、常に**可能な限り低い整合性レベルでプロセスを実行することが推奨されます**。


<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)で<strong>AWSハッキングをゼロからヒーローまで学ぶ</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法：

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションをチェックする
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に**参加する**か、[**テレグラムグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)で**フォロー**する。
* **HackTricks**のGitHubリポジトリにPRを提出して、あなたのハッキングのコツを**共有する**。

</details>
```
