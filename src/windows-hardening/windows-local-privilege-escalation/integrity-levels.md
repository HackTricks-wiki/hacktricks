# Integrity Levels

{{#include ../../banners/hacktricks-training.md}}

## Integrity Levels

Windows Vista以降では、保護可能なオブジェクトに**integrity level**ラベルを付けることができます。ほとんどのオブジェクトはmedium integrityとして扱われますが、low-integrityアプリケーション向けに設計された特定の場所にはlowラベルを付けることができます。standard userによって起動されたプロセスは通常medium integrityで実行され、昇格されたアプリケーションはhigh integrityで実行され、多くのサービスはsystem integrityで実行されます。<sup>[[1]](#references)</sup>

重要なルールとして、オブジェクトのレベルより低いintegrity levelのプロセスは、そのオブジェクトを変更できません。Windowsは、オブジェクトのdiscretionary access control list (DACL)を評価する前に、このMandatory Integrity Control (MIC)チェックを適用します。一般的に使用されるレベルは次のとおりです。<sup>[[1]](#references)[[2]](#references)</sup>

- **Untrusted**: 最も低いレベルで、`SECURITY_MANDATORY_UNTRUSTED_RID` (`S-1-16-0`)によって表されます。このintegrityラベルを**Anonymous Logon** identity (`S-1-5-7`)と混同しないでください。認証identityとMICラベルは別々のSID namespaceです。実例として、ChromiumのWindows sandboxは、最初にsandbox対象へLow integrityを割り当て、起動後にrenderer対象をUntrusted integrityへ下げます。<sup>[[5]](#references)[[6]](#references)</sup>
- **Low**: 主にinternetとのやり取りに使用され、特にInternet ExplorerのProtected Modeで関連するファイルとプロセス、および**Temporary Internet Folder**などの特定のフォルダーに適用されます。Low integrityプロセスには、registryへの書き込みアクセスがないことや、user profileへの書き込みアクセスが制限されることなど、大きな制約があります。
- **Medium**: ほとんどのアクティビティにおけるデフォルトレベルで、standard userと、特定のintegrity levelを持たないオブジェクトに割り当てられます。Administrators groupのメンバーであっても、デフォルトではこのレベルで動作します。
- **High**: administrators向けに予約されたレベルで、High level自体を含む、より低いintegrity levelのオブジェクトを変更できます。
- **System**: Windows kernelとcore servicesにおける最も高い運用レベルで、administratorsでさえ到達できません。これにより、重要なsystem functionsが保護されます。

Windowsは、Systemより上位のprotected-process integrity valueも定義しています。ただし、**TrustedInstaller**は独立したMIC levelではなく、Windows service identityです。このidentityが保護されたoperating-system resourcesを変更できるのは、そのidentityに付与されたpermissionsによるものです。

system driveのrootなどの場所に、常に固定されたHigh integrity labelが付いていると想定しないでください。`icacls`でeffective DACLと明示的なmandatory labelを確認してください。ラベルのないオブジェクトはMIC上はMediumとして扱われますが、そのDACLとownershipによって、アクセスが独立して制限される場合があります。<sup>[[1]](#references)[[4]](#references)</sup>

**Sysinternals**の**Process Explorer**を使用し、プロセスのpropertiesを開いて**Security**タブを表示すると、プロセスのintegrity levelを取得できます。<sup>[[3]](#references)</sup>

![Integrity Levels - Integrity Levels: SysinternalsのProcess Explorerを使用し、プロセスのpropertiesにアクセスして「...」を表示すると、プロセスのintegrity levelを取得できます](<../../images/image (824).png>)

`whoami /groups`を使用して、**current integrity level**を取得することもできます。

![Integrity Levels - Integrity Levels: whoami /groupsを使用してcurrent integrity levelを取得することもできます](<../../images/image (325).png>)

### File SystemにおけるIntegrity Levels

file system内のオブジェクトには、**minimum integrity-level requirement**が設定されている場合があります。そのレベルを下回るプロセスは、DACLによって本来アクセスが許可されている場合でも、オブジェクトのmandatory policyの対象になります。たとえば、standard-user consoleから通常のファイルを作成し、そのpermissionsを確認します。<sup>[[1]](#references)[[4]](#references)</sup>
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
次に、ファイルに **High** の最小 integrity level を割り当てます。これは **administrator** として実行している **console** から行う必要があります。通常の console は Medium integrity で実行されるため、オブジェクトに High integrity を割り当てることは **許可されません**。
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
ユーザー `DESKTOP-IDJHTKP\user` は、そのファイルを作成したユーザーであるため、ファイルに対する **FULL privileges** を持っています。ただし、mandatory label によって、プロセスが High integrity で実行されていない限り、ユーザーはファイルを変更できません。表示されている mandatory policy が `(NW)`、つまり no-write-up であるため、ユーザーは引き続きファイルを読み取ることができます。
```
echo 1234 > asd.txt
Access is denied.

del asd.txt
C:\Users\Public\asd.txt
Access is denied.
```
> [!TIP]
> **したがって、ファイルに最低整合性レベルが設定されている場合、そのファイルを変更するには、少なくともその整合性レベルで実行されている必要があります。**

### バイナリの整合性レベル

次の例では、`C:\Windows\System32\cmd-low.exe` にある `cmd.exe` のコピーを使用し、**administrator console から Low 整合性レベルを割り当てます**。
```
icacls C:\Windows\System32\cmd-low.exe
C:\Windows\System32\cmd-low.exe NT AUTHORITY\SYSTEM:(I)(F)
BUILTIN\Administrators:(I)(F)
BUILTIN\Users:(I)(RX)
APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(I)(RX)
APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APP PACKAGES:(I)(RX)
Mandatory Label\Low Mandatory Level:(NW)
```
ここで、`cmd-low.exe` を実行すると、中程度の整合性レベルではなく、**低整合性レベルで実行されます**：

![ファイルシステムにおける整合性レベル - バイナリにおける整合性レベル：ここで、cmd-low.exe を実行すると、中程度ではなく低整合性レベルで実行されます](<../../images/image (313).png>)

バイナリに High 整合性ラベル（`icacls C:\Windows\System32\cmd-high.exe /setintegritylevel high`）を割り当てても、自動的に High 整合性で実行されるわけではありません。Medium 整合性のプロセスから起動した場合、新しいプロセスは実行可能ファイルと呼び出し元の整合性レベルのうち、低い方を受け取るため、Medium 整合性で実行されます。<sup>[[1]](#references)</sup>

### プロセスにおける整合性レベル

すべてのファイルとフォルダーに明示的な最小整合性ラベルが設定されているわけではありませんが、**すべてのプロセスは整合性レベルで実行されます**。ファイルシステムオブジェクトの場合と同様に、**別のプロセスへの書き込みアクセスを必要とするプロセスは、少なくとも同じ整合性レベルを持っている必要があります**。したがって、Low 整合性のプロセスは、完全なアクセス権を付与して Medium 整合性のプロセスを開くことができません。<sup>[[1]](#references)</sup>

このような制限があるため、最も安全な方法は、**各プロセスを、意図した処理を実行できる最低限の整合性レベルで実行することです**。

## References

- [1] [Microsoft Learn – Mandatory Integrity Control（必須整合性制御）](https://learn.microsoft.com/en-us/windows/win32/secauthz/mandatory-integrity-control)
- [2] [Microsoft Learn – MANDATORY_LEVEL enumeration（MANDATORY_LEVEL 列挙）](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ne-winnt-mandatory_level)
- [3] [Microsoft Sysinternals – Process Explorer](https://learn.microsoft.com/en-us/sysinternals/downloads/process-explorer)
- [4] [Microsoft Learn – icacls](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/icacls)
- [5] [Chromium source – Default Windows sandbox integrity policy（Windows sandbox のデフォルト整合性ポリシー）](https://github.com/chromium/chromium/blob/main/sandbox/policy/win/sandbox_win.cc#L212-L216)
- [6] [Microsoft Learn – Well-known SIDs（既知の SID）](https://learn.microsoft.com/en-us/windows/win32/secauthz/well-known-sids)
{{#include ../../banners/hacktricks-training.md}}
