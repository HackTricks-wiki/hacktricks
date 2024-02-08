<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>でAWSハッキングをゼロからヒーローまで学ぶ！</strong></summary>

HackTricksをサポートする他の方法：

- **HackTricksで企業を宣伝したい**または**HackTricksをPDFでダウンロードしたい場合は**[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
- [**公式PEASS＆HackTricksスワッグ**](https://peass.creator-spring.com)を入手してください
- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションをご覧ください
- **💬 [Discordグループ](https://discord.gg/hRep4RUj7f)**に参加するか、[telegramグループ](https://t.me/peass)に参加するか、**Twitter**で私をフォローする🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
- **ハッキングトリックを共有するには、[HackTricks](https://github.com/carlospolop/hacktricks)と[HackTricks Cloud](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出してください。**

</details>


# インテグリティレベル

Windows Vista以降では、すべての保護されたアイテムには**インテグリティレベル**タグが付いています。このセットアップでは、ほとんどのファイルとレジストリキーには「中」のインテグリティレベルが割り当てられますが、Internet Explorer 7が低いインテグリティレベルで書き込むことができる特定のフォルダやファイルもあります。標準ユーザーによって開始されたプロセスは通常、中間のインテグリティレベルを持ち、サービスは通常、システムのインテグリティレベルで動作します。高いインテグリティラベルはルートディレクトリを保護します。

重要なルールの1つは、オブジェクトはオブジェクトのレベルよりも低いインテグリティレベルを持つプロセスによって変更されないということです。インテグリティレベルは次のとおりです：

- **信頼されていない**: このレベルは匿名ログインを持つプロセス向けです。 %%%例: Chrome%%%
- **低**: 主にインターネットのやり取りに使用され、特にInternet Explorerの保護モードで影響を受ける関連ファイルやプロセス、および**一時インターネットフォルダ**のような特定のフォルダに影響します。低いインテグリティプロセスは、レジストリの書き込みアクセスがないことや、ユーザープロファイルの書き込みアクセスが制限されていることなど、重要な制限に直面します。
- **中**: ほとんどのアクティビティのデフォルトレベルであり、標準ユーザーや特定のインテグリティレベルを持たないオブジェクトに割り当てられます。管理者グループのメンバーでさえ、デフォルトでこのレベルで動作します。
- **高**: 管理者向けに予約されており、高いインテグリティレベル自体を含む低いインテグリティレベルのオブジェクトを変更できるようにします。
- **システム**: Windowsカーネルとコアサービスのための最高の操作レベルであり、管理者でさえアクセスできないようになっており、重要なシステム機能を保護します。
- **インストーラー**: 他のすべてのレベルを上回るユニークなレベルであり、このレベルのオブジェクトは他のすべてのオブジェクトをアンインストールできるようにします。

プロセスのインテグリティレベルは、**Sysinternals**の**Process Explorer**を使用してプロセスの**プロパティ**にアクセスし、「**セキュリティ**」タブを表示することで取得できます：

![](<../../.gitbook/assets/image (318).png>)

また、`whoami /groups`を使用して**現在のインテグリティレベル**を取得できます。

![](<../../.gitbook/assets/image (319).png>)

## ファイルシステムのインテグリティレベル

ファイルシステム内のオブジェクトは、**最小のインテグリティレベル要件**を必要とする場合があり、プロセスがこのインテグリティプロセスを持っていない場合はそれとやり取りできません。\
たとえば、**通常のユーザーコンソールから通常のファイルを作成し、アクセス許可を確認**してみましょう：
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
今、ファイルに最小整合性レベルを**High**に割り当てましょう。これは**管理者として実行されているコンソール**から行う必要があります。**通常のコンソール**は中間整合性レベルで実行されており、オブジェクトに**High**整合性レベルを割り当てることが**許可されていません**：
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
これが興味深い部分です。ユーザー`DESKTOP-IDJHTKP\user`がファイルに**完全な権限**を持っていることがわかります（実際、このユーザーがファイルを作成したユーザーです）、しかし、実装された最小整合性レベルのため、彼はファイルを変更できなくなります（ただし、読むことはできます）。
```
echo 1234 > asd.txt
Access is denied.

del asd.txt
C:\Users\Public\asd.txt
Access is denied.
```
{% hint style="info" %}
**したがって、ファイルが最小整合性レベルを持っている場合、そのファイルを変更するには、少なくともその整合性レベルで実行する必要があります。**
{% endhint %}

## バイナリの整合性レベル

`cmd.exe`のコピーを`C:\Windows\System32\cmd-low.exe`に作成し、**管理者コンソールからその整合性レベルを低に設定しました:**
```
icacls C:\Windows\System32\cmd-low.exe
C:\Windows\System32\cmd-low.exe NT AUTHORITY\SYSTEM:(I)(F)
BUILTIN\Administrators:(I)(F)
BUILTIN\Users:(I)(RX)
APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(I)(RX)
APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APP PACKAGES:(I)(RX)
Mandatory Label\Low Mandatory Level:(NW)
```
今、`cmd-low.exe`を実行すると、**低完全性レベル**で実行されます。中完全性レベルではありません：

![](<../../.gitbook/assets/image (320).png>)

興味のある人のために、バイナリに高完全性レベルを割り当てると（`icacls C:\Windows\System32\cmd-high.exe /setintegritylevel high`）、自動的に高完全性レベルで実行されません（デフォルトでは中完全性レベルから呼び出された場合、中完全性レベルで実行されます）。

## プロセスの完全性レベル

すべてのファイルとフォルダには最小完全性レベルがありませんが、**すべてのプロセスは完全性レベルで実行されます**。ファイルシステムで起こったことと同様に、**プロセスが別のプロセス内に書き込みたい場合、少なくとも同じ完全性レベルを持っていなければなりません**。つまり、低完全性レベルのプロセスは、中完全性レベルのプロセスに対して完全アクセス権を持つハンドルを開けません。

このセクションと前のセクションでコメントされた制限により、セキュリティの観点からは、常に**可能な限り低い完全性レベルでプロセスを実行することが推奨**されます。
