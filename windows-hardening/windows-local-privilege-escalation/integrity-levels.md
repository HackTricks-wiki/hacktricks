<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**最新バージョンのPEASSを入手したり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！

- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。

- [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。

- [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**

- **ハッキングのトリックを共有するには、[hacktricksリポジトリ](https://github.com/carlospolop/hacktricks)と[hacktricks-cloudリポジトリ](https://github.com/carlospolop/hacktricks-cloud)にPRを提出してください**。

</details>


# 完全性レベル

Windows Vista以降、**保護されたオブジェクトは完全性レベルでラベル付け**されます。システム上のほとんどのユーザーおよびシステムファイルやレジストリキーは、デフォルトで「中」の完全性レベルを持ちます。主な例外は、Internet Explorer 7が低完全性で書き込み可能な特定のフォルダとファイルを持っています。**ほとんどの標準ユーザーが実行するプロセス**は、**中の完全性レベル**でラベル付けされます（管理者グループのユーザーが開始したプロセスも同様です）。ほとんどの**サービス**は**システムの完全性レベル**でラベル付けされます。ルートディレクトリは高完全性レベルで保護されています。\
低完全性レベルのプロセスは、高完全性レベルのオブジェクトに書き込むことはできません。\
完全性レベルにはいくつかのレベルがあります：

* **信頼されていない** - 匿名でログオンしたプロセスは自動的に信頼されていないと指定されます。 _例：Chrome_
* **低** - 低完全性レベルは、インターネットとのやり取りにデフォルトで使用されるレベルです。Internet Explorerがデフォルトの状態で実行されている限り、保護モードである限り、それに関連するすべてのファイルとプロセスは低完全性レベルに割り当てられます。一部のフォルダ（例：**一時インターネットフォルダ**）もデフォルトで**低完全性**レベルに割り当てられます。ただし、**低完全性プロセス**は非常に**制限されており**、**レジストリ**に書き込むことはできず、現在のユーザーのプロファイルの**ほとんどの場所**に書き込むことが制限されています。 _例：Internet ExplorerまたはMicrosoft Edge_
* **中** - 中は**ほとんどのオブジェクトが実行されるコンテキスト**です。標準ユーザーは中の完全性レベルを受け取り、明示的に低いまたは高い完全性レベルで指定されていないオブジェクトはデフォルトで中です。ただし、デフォルトでは管理者グループのユーザーも中の完全性レベルを使用します。
* **高** - **管理者**は高完全性レベルを付与されます。これにより、管理者は中または低完全性レベルに割り当てられたオブジェクトとのやり取りや変更が可能になりますが、標準ユーザーはできません。 _例：「管理者として実行」_
* **システム** - システムの完全性レベルは、その名前の通り、システムに予約されています。Windowsカーネルとコアサービスはシステムの完全性レベルを付与されます。管理者の高完全性レベルよりも高いため、これらのコア機能は管理者によっても影響を受けたり侵害されたりすることはありません。例：サービス
* **インストーラ** - インストーラの完全性レベルは特殊なケースであり、すべての完全性レベルよりも高いです。インストーラの完全性レベルと等しいかそれよりも高いため、インストーラの完全性レベルに割り当てられたオブジェクトは他のすべてのオブジェクトをアンインストールすることもできます。

プロセスの完全性レベルは、**Sysinternals**の**Process Explorer**を使用して取得できます。プロセスの**プロパティ**にアクセスし、「**セキュリティ**」タブを表示します：

![](<../../.gitbook/assets/image (318).png>)

`whoami /groups`を使用して、**現在の完全性レベル**を取得することもできます。

![](<../../.gitbook/assets/image (319).png>)

## ファイルシステムの完全性レベル

ファイルシステム内のオブジェクトは、**最小の完全性レベル要件**を必要とする場合があります。プロセスにこの完全性プロセスがない場合、それとは対話できません。\
たとえば、**通常のユーザーコンソールからファイルを作成し、アクセス許可を確認**してみましょう：
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
さて、ファイルに最低の完全性レベルである**High**を割り当てましょう。これは**管理者として実行されるコンソール**から行う必要があります。通常のコンソールは中間完全性レベルで実行されているため、オブジェクトに高い完全性レベルを割り当てることは**許可されません**。
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
ここからが興味深い部分です。ユーザー`DESKTOP-IDJHTKP\user`は、このファイルに対して**完全な特権**を持っていることがわかります（実際、このファイルを作成したユーザーです）。しかし、最小の整合性レベルが実装されているため、彼は高い整合性レベルで実行していない限り、ファイルを変更することはできません（ただし、読み取ることはできます）。
```
echo 1234 > asd.txt
Access is denied.

del asd.txt
C:\Users\Public\asd.txt
Access is denied.
```
{% hint style="info" %}
**したがって、ファイルが最小の整合性レベルを持っている場合、それを変更するためには、少なくともその整合性レベルで実行する必要があります。**
{% endhint %}

## バイナリの整合性レベル

私は`cmd.exe`のコピーを`C:\Windows\System32\cmd-low.exe`に作成し、**管理者コンソールから低い整合性レベルを設定しました:**
```
icacls C:\Windows\System32\cmd-low.exe
C:\Windows\System32\cmd-low.exe NT AUTHORITY\SYSTEM:(I)(F)
BUILTIN\Administrators:(I)(F)
BUILTIN\Users:(I)(RX)
APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(I)(RX)
APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APP PACKAGES:(I)(RX)
Mandatory Label\Low Mandatory Level:(NW)
```
今、`cmd-low.exe`を実行すると、**中間の整合性レベル**ではなく、**低い整合性レベルで実行**されます：

![](<../../.gitbook/assets/image (320).png>)

興味のある人のために、バイナリに高い整合性レベルを割り当てる場合（`icacls C:\Windows\System32\cmd-high.exe /setintegritylevel high`）、自動的に高い整合性レベルで実行されません（デフォルトでは中間の整合性レベルから呼び出される場合、中間の整合性レベルで実行されます）。

## プロセスにおける整合性レベル

すべてのファイルとフォルダには最小の整合性レベルがあるわけではありませんが、**すべてのプロセスは整合性レベルの下で実行されます**。そして、ファイルシステムで起こったことと同様に、**プロセスが別のプロセス内に書き込みを行う場合、少なくとも同じ整合性レベルを持っている必要があります**。つまり、低い整合性レベルを持つプロセスは、中間の整合性レベルを持つプロセスに対して完全なアクセス権を持つハンドルを開くことはできません。

このセクションと前のセクションでコメントされた制限により、セキュリティの観点からは、常に**可能な限り低い整合性レベルでプロセスを実行することが推奨されます**。


<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- **サイバーセキュリティ企業**で働いていますか？ HackTricksであなたの**会社を宣伝**したいですか？または、**PEASSの最新バージョンやHackTricksのPDFをダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！

- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見しましょう。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。

- [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。

- **[💬](https://emojipedia.org/speech-balloon/) Discordグループ**に参加するか、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **ハッキングのトリックを共有するには、[hacktricksリポジトリ](https://github.com/carlospolop/hacktricks)と[hacktricks-cloudリポジトリ](https://github.com/carlospolop/hacktricks-cloud)にPRを提出してください**。

</details>
