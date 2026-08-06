# Integrity Levels

{{#include ../../banners/hacktricks-training.md}}

## Integrity Levels

Windows Vista 以降では、すべての保護対象アイテムに **integrity level** タグが付与されます。この仕組みでは通常、ファイルとレジストリキーに「medium」integrity level が割り当てられます。ただし、Internet Explorer 7 が low integrity level で書き込める一部のフォルダーやファイルは例外です。デフォルトでは、標準ユーザーが起動したプロセスは medium integrity level を持ち、サービスは通常 system integrity level で動作します。high-integrity label はルートディレクトリを保護します。

重要なルールとして、オブジェクトの integrity level より低い integrity level のプロセスは、そのオブジェクトを変更できません。integrity level は次のとおりです。

- **Untrusted**: anonymous login を使用するプロセス向けのレベルです。例: Chrome
- **Low**: 主にインターネットとのやり取り、特に Internet Explorer の Protected Mode で使用され、関連するファイルやプロセス、および **Temporary Internet Folder** などの特定のフォルダーに影響します。Low integrity process には、レジストリへの書き込みアクセスがなく、ユーザープロファイルへの書き込みアクセスも制限されるなど、大きな制約があります。
- **Medium**: ほとんどのアクティビティにおけるデフォルトのレベルで、標準ユーザーと、特定の integrity level を持たないオブジェクトに割り当てられます。Administrators group のメンバーであっても、デフォルトではこのレベルで動作します。
- **High**: 管理者向けに予約されたレベルで、管理者は自身の high level を含む、より低い integrity level のオブジェクトを変更できます。
- **System**: Windows kernel と core services 向けの最も高い運用レベルです。管理者であっても到達できず、重要なシステム機能を保護します。
- **Installer**: 他のすべてのレベルより上位に位置する特殊なレベルで、このレベルのオブジェクトは他の任意のオブジェクトをアンインストールできます。

**Process Explorer** from **Sysinternals** を使用し、プロセスの **properties** にアクセスして "**Security**" タブを表示することで、プロセスの integrity level を確認できます。

![Integrity Levels - Integrity Levels: Sysinternals の Process Explorer を使用し、プロセスの properties にアクセスして「...」を表示することで、プロセスの integrity level を確認できます。](<../../images/image (824).png>)

`whoami /groups` を使用して、**current integrity level** を確認することもできます。

![Integrity Levels - Integrity Levels: whoami /groups を使用して current integrity level を確認することもできます。](<../../images/image (325).png>)

### File-system における Integrity Levels

file-system 内のオブジェクトには **minimum integrity level requirement** が設定されている場合があり、プロセスがこの integrity level を持っていなければ、そのオブジェクトとやり取りできません。\
たとえば、**通常のユーザーコンソールから通常のファイルを作成し、権限を確認**してみましょう:
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
次に、ファイルに **High** の最小 Integrity level を割り当てます。これは **administrator** として実行している **コンソール**から行う必要があります。通常のコンソールは Medium Integrity level で実行され、オブジェクトに High Integrity level を割り当てることが **許可されない**ためです：
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
ここからが興味深いところです。ユーザー `DESKTOP-IDJHTKP\user` がファイルに対して **FULL privileges** を持っていることが確認できます（実際、このユーザーがファイルを作成しました）。しかし、実装されている最小 Integrity Level のため、High Integrity Level 内で実行していない限り、このユーザーはファイルを変更できなくなります（なお、読み取りは可能です）。
```
echo 1234 > asd.txt
Access is denied.

del asd.txt
C:\Users\Public\asd.txt
Access is denied.
```
> [!TIP]
> **したがって、ファイルに最低インテグリティ レベルが設定されている場合、そのファイルを変更するには、少なくともそのインテグリティ レベルで実行されている必要があります。**

### バイナリのインテグリティ レベル

`cmd.exe` のコピーを `C:\Windows\System32\cmd-low.exe` として作成し、**administrator console から low のインテグリティ レベルを設定しました:**
```
icacls C:\Windows\System32\cmd-low.exe
C:\Windows\System32\cmd-low.exe NT AUTHORITY\SYSTEM:(I)(F)
BUILTIN\Administrators:(I)(F)
BUILTIN\Users:(I)(RX)
APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(I)(RX)
APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APP PACKAGES:(I)(RX)
Mandatory Label\Low Mandatory Level:(NW)
```
現在、`cmd-low.exe` を実行すると、medium ではなく **low-integrity level で実行されます**。

![File-system の Integrity Levels - Binaries の Integrity Levels: cmd-low.exe を実行すると、medium ではなく low-integrity level で実行されます](<../../images/image (313).png>)

興味のある方へ。バイナリに high integrity level を割り当てても（`icacls C:\Windows\System32\cmd-high.exe /setintegritylevel high`）、自動的に high integrity level で実行されるわけではありません（medium integrity level から --デフォルトでは-- 起動した場合、medium integrity level で実行されます）。

### Processes の Integrity Levels

すべてのファイルやフォルダーに minimum integrity level が設定されているわけではありませんが、**すべての process は integrity level で実行されています**。また、file-system で起きたことと同様に、**ある process が別の process 内に書き込むには、少なくとも同じ integrity level が必要です**。つまり、low integrity level の process は、medium integrity level の process に対して full access の handle を open できません。

このセクションと前のセクションで説明した制限により、security の観点では、常に **可能な限り低い integrity level で process を実行することが推奨されます**。

{{#include ../../banners/hacktricks-training.md}}
