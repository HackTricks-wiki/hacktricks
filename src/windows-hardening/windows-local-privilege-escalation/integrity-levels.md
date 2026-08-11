# Integrity Levels

{{#include ../../banners/hacktricks-training.md}}

## Integrity Levels

Windows Vista以降では、保護可能なオブジェクトに**integrity level**ラベルを付与できます。ほとんどのオブジェクトはmedium integrityとして扱われますが、low-integrityアプリケーション向けに設計された特定の場所にはlowのラベルを付けることができます。標準ユーザーが起動したプロセスは通常medium integrityで実行され、昇格されたアプリケーションはhigh integrityで実行され、多くのサービスはsystem integrityで実行されます。<sup>[[1]](#references)</sup>

重要なルールとして、オブジェクトのレベルより低いintegrity levelのプロセスは、そのオブジェクトを変更できません。Windowsは、オブジェクトのdiscretionary access control list（DACL）を評価する前に、このMandatory Integrity Control（MIC）チェックを適用します。一般的に使用されるレベルは次のとおりです。<sup>[[1]](#references)[[2]](#references)</sup>

- **Untrusted**: 最も低いレベルで、`SECURITY_MANDATORY_UNTRUSTED_RID`によって表されます。
- **Low**: 主にインターネットとのやり取りに使用され、特にInternet ExplorerのProtected Modeで関連するファイルやプロセス、および**Temporary Internet Folder**などの特定のフォルダーに影響します。Low integrityプロセスには大きな制限があり、レジストリへの書き込みアクセスがなく、ユーザープロファイルへの書き込みアクセスも制限されます。
- **Medium**: ほとんどのアクティビティにおけるデフォルトのレベルで、標準ユーザー、および特定のintegrity levelが設定されていないオブジェクトに割り当てられます。Administratorsグループのメンバーであっても、デフォルトではこのレベルで動作します。
- **High**: 管理者向けに予約されたレベルで、管理者はhigh level自体を含む、より低いintegrity levelのオブジェクトを変更できます。
- **System**: Windows kernelおよびコアサービス向けの最も高い運用レベルで、管理者でさえ到達できません。これにより、重要なシステム機能が保護されます。

Windowsは、Systemより上位のprotected-process integrity値も定義しています。ただし、**TrustedInstaller**は独立したMIC levelではなく、Windows service identityです。このidentityが保護されたオペレーティングシステムリソースを変更できるのは、そのidentityに付与された権限によるものです。

**Sysinternals**の**Process Explorer**を使用し、プロセスのプロパティを開いて**Security**タブを表示すると、プロセスのintegrity levelを確認できます。<sup>[[3]](#references)</sup>

![Integrity Levels - Integrity Levels: SysinternalsのProcess Explorerでプロセスのプロパティを開き、...を表示すると、プロセスのintegrity levelを確認できます](<../../images/image (824).png>)

`whoami /groups`を使用して、**現在のintegrity level**を確認することもできます。

![Integrity Levels - Integrity Levels: whoami /groupsを使用して現在のintegrity levelも確認できます](<../../images/image (325).png>)

### Integrity Levels in the File System

ファイルシステム内のオブジェクトには、**minimum integrity-level requirement**が設定されている場合があります。そのレベル未満のプロセスは、DACLによってアクセスが許可される場合でも、オブジェクトのmandatory policyの対象になります。たとえば、標準ユーザーのコンソールから通常のファイルを作成し、その権限を確認します。<sup>[[1]](#references)[[4]](#references)</sup>
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
ここで、ファイルに **High** の最小整合性レベルを割り当てます。これは **administrator** として実行している **コンソール** から行う必要があります。通常のコンソールは Medium 整合性で実行され、オブジェクトに High 整合性を割り当てることが **許可されない** ためです：
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
ユーザー `DESKTOP-IDJHTKP\user` は、このファイルを作成したユーザーであるため、ファイルに対する **FULL privileges** を持っています。ただし、mandatory label により、プロセスが High integrity で実行されていない限り、ユーザーはファイルを変更できません。表示されている mandatory policy が `(NW)`、つまり no-write-up であるため、ユーザーは引き続きファイルを読み取ることができます。
```
echo 1234 > asd.txt
Access is denied.

del asd.txt
C:\Users\Public\asd.txt
Access is denied.
```
> [!TIP]
> **したがって、ファイルに最小整合性レベルが設定されている場合、そのファイルを変更するには、少なくともその整合性レベルで実行されている必要があります。**

### バイナリの整合性レベル

以下の例では、`C:\Windows\System32\cmd-low.exe` にある `cmd.exe` のコピーを使用し、**administrator console から Low integrity level を割り当てます**。
```
icacls C:\Windows\System32\cmd-low.exe
C:\Windows\System32\cmd-low.exe NT AUTHORITY\SYSTEM:(I)(F)
BUILTIN\Administrators:(I)(F)
BUILTIN\Users:(I)(RX)
APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(I)(RX)
APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APP PACKAGES:(I)(RX)
Mandatory Label\Low Mandatory Level:(NW)
```
これで、`cmd-low.exe` を実行すると、Medium ではなく **Low 整合性レベルで実行されます**。

![ファイルシステム内の整合性レベル - バイナリ内の整合性レベル: これで、cmd-low.exe を実行すると、Medium ではなく Low 整合性レベルで実行されます](<../../images/image (313).png>)

バイナリに High 整合性ラベル（`icacls C:\Windows\System32\cmd-high.exe /setintegritylevel high`）を割り当てても、自動的に High 整合性で実行されるわけではありません。Medium 整合性のプロセスから呼び出された場合、新しいプロセスは実行可能ファイルと呼び出し元の整合性レベルのうち、低い方を受け取るため、Medium 整合性で実行されます。<sup>[[1]](#references)</sup>

### プロセスの整合性レベル

すべてのファイルとフォルダーに明示的な最小整合性ラベルが設定されているわけではありませんが、**すべてのプロセスは整合性レベルで実行されます**。ファイルシステムオブジェクトの場合と同様に、**別のプロセスへの書き込みアクセスを必要とするプロセスは、少なくとも同じ整合性レベルを持っている必要があります**。そのため、Low 整合性のプロセスは、完全なアクセス権で Medium 整合性のプロセスを開くことができません。<sup>[[1]](#references)</sup>

これらの制限があるため、最も安全な方法は、**各プロセスを、その目的の作業を実行できる最低限の整合性レベルで実行することです**。

## References

- [1] [Microsoft Learn – 強制整合性制御](https://learn.microsoft.com/en-us/windows/win32/secauthz/mandatory-integrity-control)
- [2] [Microsoft Learn – MANDATORY_LEVEL 列挙](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ne-winnt-mandatory_level)
- [3] [Microsoft Sysinternals – Process Explorer](https://learn.microsoft.com/en-us/sysinternals/downloads/process-explorer)
- [4] [Microsoft Learn – icacls](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/icacls)
{{#include ../../banners/hacktricks-training.md}}
