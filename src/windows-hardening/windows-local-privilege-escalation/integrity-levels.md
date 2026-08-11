# Integrity Levels

{{#include ../../banners/hacktricks-training.md}}

## Integrity Levels

Windows Vista 以降では、保護可能なオブジェクトに **integrity level** ラベルを付けられます。ほとんどのオブジェクトは medium integrity として扱われますが、low-integrity アプリケーション向けに設計された特定の場所には low を設定できます。標準ユーザーが起動したプロセスは通常 medium integrity で実行され、昇格されたアプリケーションは high integrity で実行され、多くのサービスは system integrity で実行されます。<sup>[[1]](#references)</sup>

重要なルールとして、オブジェクトのレベルより低い integrity level のプロセスは、そのオブジェクトを変更できません。Windows は、オブジェクトの discretionary access control list (DACL) を評価する前に、この Mandatory Integrity Control (MIC) チェックを適用します。一般的に使用されるレベルは次のとおりです。<sup>[[1]](#references)[[2]](#references)</sup>

- **Untrusted**: 最も低いレベルで、`SECURITY_MANDATORY_UNTRUSTED_RID` によって表されます。実際の例として、Chromium の Windows sandbox は、最初に sandbox の対象へ Low integrity を割り当て、起動後に renderer の対象を Untrusted integrity へ引き下げます。<sup>[[5]](#references)</sup>
- **Low**: 主にインターネットとのやり取りに使用され、特に Internet Explorer の Protected Mode で、関連するファイルやプロセス、および **Temporary Internet Folder** などの特定のフォルダーに影響します。Low integrity のプロセスには、レジストリへの書き込みアクセス不可や、ユーザープロファイルへの書き込みアクセス制限など、大きな制約があります。
- **Medium**: ほとんどの活動におけるデフォルトのレベルで、標準ユーザー、および特定の integrity level が設定されていないオブジェクトに割り当てられます。Administrators グループのメンバーであっても、デフォルトではこのレベルで動作します。
- **High**: administrators 用に予約されたレベルで、低い integrity level のオブジェクトや、high level 自体のオブジェクトを変更できます。
- **System**: Windows kernel と core services 用の最も高い operational level であり、administrators でさえ到達できません。これにより、重要な system functions が保護されます。

Windows では、System より上位に protected-process integrity value も定義されています。ただし、**TrustedInstaller** は独立した MIC level ではなく、Windows service identity です。この identity が保護された operating-system resources を変更できるのは、その identity に付与された permissions によるものです。

**Sysinternals** の **Process Explorer** を使用すると、プロセスのプロパティを開き、**Security** タブを表示して、そのプロセスの integrity level を取得できます。<sup>[[3]](#references)</sup>

![Integrity Levels - Integrity Levels: Sysinternals の Process Explorer を使用し、プロセスのプロパティにアクセスして「...](<../../images/image (824).png>)

`whoami /groups` を使用して、**current integrity level** を取得することもできます。

![Integrity Levels - Integrity Levels: whoami /groups を使用して current integrity level を取得することもできます](<../../images/image (325).png>)

### File System における Integrity Levels

file system 内のオブジェクトには、**minimum integrity-level requirement** が設定されている場合があります。そのレベルを下回るプロセスは、DACL によって本来アクセスが許可される場合でも、オブジェクトの mandatory policy の対象になります。たとえば、standard-user console から通常のファイルを作成し、その permissions を確認します。<sup>[[1]](#references)[[4]](#references)</sup>
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
次に、ファイルに最低整合性レベルとして **High** を割り当てます。これは **administrator** として実行している **console** から行う必要があります。通常の console は Medium 整合性で実行され、オブジェクトに High 整合性を割り当てることが **許可されない** ためです:
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
ユーザー `DESKTOP-IDJHTKP\user` は、そのユーザーがファイルを作成したため、ファイルに対する **FULL privileges** を持っています。ただし、mandatory label により、プロセスが High integrity で実行されていない限り、ユーザーはファイルを変更できません。表示されている mandatory policy が `(NW)`、つまり no-write-up であるため、ユーザーは引き続きファイルを読み取ることができます。
```
echo 1234 > asd.txt
Access is denied.

del asd.txt
C:\Users\Public\asd.txt
Access is denied.
```
> [!TIP]
> **したがって、ファイルに最小完全性レベルが設定されている場合、それを変更するには、少なくともその完全性レベルで実行されている必要があります。**

### バイナリの完全性レベル

以下の例では、`C:\Windows\System32\cmd-low.exe` にある `cmd.exe` のコピーを使用し、**管理者コンソールから Low 完全性レベルを割り当てます**。
```
icacls C:\Windows\System32\cmd-low.exe
C:\Windows\System32\cmd-low.exe NT AUTHORITY\SYSTEM:(I)(F)
BUILTIN\Administrators:(I)(F)
BUILTIN\Users:(I)(RX)
APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(I)(RX)
APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APP PACKAGES:(I)(RX)
Mandatory Label\Low Mandatory Level:(NW)
```
これで、`cmd-low.exe` を実行すると、Medium ではなく **Low-integrity level で実行されます**。

![File-system 内の Integrity Levels - Binaries 内の Integrity Levels: これで、cmd-low.exe を実行すると、Medium ではなく Low-integrity level で実行されます](<../../images/image (313).png>)

バイナリに High integrity label（`icacls C:\Windows\System32\cmd-high.exe /setintegritylevel high`）を割り当てても、自動的に High integrity で実行されるわけではありません。Medium-integrity process から呼び出された場合、新しい process は実行可能ファイルと呼び出し元の integrity level のうち、低い方を受け取るため、Medium integrity で実行されます。<sup>[[1]](#references)</sup>

### Processes 内の Integrity Levels

すべてのファイルとフォルダーに明示的な最小 integrity label が設定されているわけではありませんが、**すべての process は integrity level で実行されます**。File-system object と同様に、**別の process への write access を必要とする process は、少なくとも同じ integrity level を持っている必要があります**。そのため、Low-integrity process は、完全な access 権限で Medium-integrity process を開くことができません。<sup>[[1]](#references)</sup>

これらの制限があるため、最も安全な方法は、**意図した処理を実行できる範囲で、各 process を最も低い integrity level で実行することです**。

## References

- [1] [Microsoft Learn – Mandatory Integrity Control](https://learn.microsoft.com/en-us/windows/win32/secauthz/mandatory-integrity-control)
- [2] [Microsoft Learn – MANDATORY_LEVEL enumeration](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ne-winnt-mandatory_level)
- [3] [Microsoft Sysinternals – Process Explorer](https://learn.microsoft.com/en-us/sysinternals/downloads/process-explorer)
- [4] [Microsoft Learn – icacls](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/icacls)
- [5] [Chromium source – Default Windows sandbox integrity policy](https://github.com/chromium/chromium/blob/main/sandbox/policy/win/sandbox_win.cc#L212-L216)
{{#include ../../banners/hacktricks-training.md}}
