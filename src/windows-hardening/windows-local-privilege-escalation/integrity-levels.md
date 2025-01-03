# インテグリティレベル

{{#include ../../banners/hacktricks-training.md}}

## インテグリティレベル

Windows Vista以降のバージョンでは、すべての保護されたアイテムには**インテグリティレベル**タグが付いています。この設定では、特定のフォルダーやファイルを除いて、ファイルやレジストリキーに「中」インテグリティレベルが主に割り当てられます。デフォルトの動作は、標準ユーザーによって開始されたプロセスが中インテグリティレベルを持つことであり、サービスは通常、システムインテグリティレベルで動作します。高インテグリティラベルはルートディレクトリを保護します。

重要なルールは、オブジェクトのレベルよりも低いインテグリティレベルを持つプロセスによってオブジェクトが変更されることはできないということです。インテグリティレベルは次のとおりです：

- **信頼されていない**: このレベルは匿名ログインを持つプロセス用です。 %%%例: Chrome%%%
- **低**: 主にインターネットの相互作用、特にInternet Explorerの保護モードで、関連するファイルやプロセス、**一時インターネットフォルダー**のような特定のフォルダーに影響を与えます。低インテグリティプロセスは、レジストリへの書き込みアクセスがないことや、ユーザープロファイルへの書き込みアクセスが制限されるなど、重大な制約に直面します。
- **中**: ほとんどの活動のデフォルトレベルで、標準ユーザーや特定のインテグリティレベルを持たないオブジェクトに割り当てられます。管理者グループのメンバーでさえ、デフォルトではこのレベルで動作します。
- **高**: 管理者専用で、低いインテグリティレベルのオブジェクトを変更できるようにし、高レベル自体のオブジェクトも含まれます。
- **システム**: Windowsカーネルとコアサービスの最高の操作レベルで、管理者でさえ手が届かないため、重要なシステム機能を保護します。
- **インストーラー**: 他のすべてのレベルの上に位置するユニークなレベルで、このレベルのオブジェクトは他の任意のオブジェクトをアンインストールできます。

**Process Explorer**を使用してプロセスのインテグリティレベルを取得できます。**Sysinternals**からプロセスの**プロパティ**にアクセスし、"**セキュリティ**"タブを表示します：

![](<../../images/image (824).png>)

`whoami /groups`を使用して**現在のインテグリティレベル**を取得することもできます。

![](<../../images/image (325).png>)

### ファイルシステムにおけるインテグリティレベル

ファイルシステム内のオブジェクトには**最小インテグリティレベル要件**が必要な場合があり、プロセスがこのインテグリティを持っていない場合、相互作用できません。\
例えば、**通常のユーザーコンソールから通常のファイルを作成し、権限を確認しましょう**:
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
ファイルに**High**の最小整合性レベルを割り当てます。これは**管理者**として実行されている**コンソール**から**行う必要があります**。通常のコンソールは中程度の整合性レベルで実行されており、オブジェクトに高い整合性レベルを割り当てることは**許可されません**。
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
ここが面白くなるところです。ユーザー `DESKTOP-IDJHTKP\user` がファイルに対して **完全な権限** を持っていることがわかります（実際、このユーザーがファイルを作成しました）が、実装された最小の整合性レベルのため、彼は高い整合性レベル内で実行していない限り、ファイルを変更することができません（ただし、読むことはできます）。
```
echo 1234 > asd.txt
Access is denied.

del asd.txt
C:\Users\Public\asd.txt
Access is denied.
```
> [!NOTE]
> **したがって、ファイルに最低限の整合性レベルがある場合、それを変更するには、その整合性レベル以上で実行する必要があります。**

### バイナリの整合性レベル

`cmd.exe`のコピーを`C:\Windows\System32\cmd-low.exe`に作成し、**管理者コンソールから低い整合性レベルを設定しました:**
```
icacls C:\Windows\System32\cmd-low.exe
C:\Windows\System32\cmd-low.exe NT AUTHORITY\SYSTEM:(I)(F)
BUILTIN\Administrators:(I)(F)
BUILTIN\Users:(I)(RX)
APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(I)(RX)
APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APP PACKAGES:(I)(RX)
Mandatory Label\Low Mandatory Level:(NW)
```
今、`cmd-low.exe`を実行すると、**低い整合性レベル**で実行されます。中程度の整合性レベルではありません。

![](<../../images/image (313).png>)

好奇心のある人のために、バイナリに高い整合性レベルを割り当てると（`icacls C:\Windows\System32\cmd-high.exe /setintegritylevel high`）、自動的に高い整合性レベルで実行されるわけではありません（中程度の整合性レベルから呼び出すと、デフォルトで中程度の整合性レベルで実行されます）。

### プロセスの整合性レベル

すべてのファイルやフォルダーには最小整合性レベルがあるわけではありませんが、**すべてのプロセスは整合性レベルの下で実行されています**。ファイルシステムで起こったことと同様に、**プロセスが別のプロセス内に書き込むには、少なくとも同じ整合性レベルを持っている必要があります**。これは、低い整合性レベルのプロセスが中程度の整合性レベルのプロセスに対してフルアクセスのハンドルを開くことができないことを意味します。

このセクションと前のセクションで述べた制限により、セキュリティの観点からは、常に**可能な限り低い整合性レベルでプロセスを実行することが推奨されます**。

{{#include ../../banners/hacktricks-training.md}}
