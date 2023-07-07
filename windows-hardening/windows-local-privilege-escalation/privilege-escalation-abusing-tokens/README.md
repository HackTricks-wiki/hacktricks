# トークンの悪用

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業で働いていますか？** **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセス**したいですか？または、**HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter**で[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**をフォロー**してください。
* **ハッキングのトリックを共有する**には、[hacktricksリポジトリ](https://github.com/carlospolop/hacktricks)と[hacktricks-cloudリポジトリ](https://github.com/carlospolop/hacktricks-cloud)にPRを提出してください。

</details>

## トークン

**Windowsアクセストークンが何かわからない場合**は、続ける前にこのページを読んでください：

{% content-ref url="../access-tokens.md" %}
[access-tokens.md](../access-tokens.md)
{% endcontent-ref %}

**既に持っているトークンを悪用して特権をエスカレーションすることができるかもしれません**

### SeImpersonatePrivilege（3.1.1）

この特権を持つプロセスは、取得できる**トークン**を**なりすます**ことができます（ただし、作成することはできません）。**Windowsサービス**（DCOM）から**特権のあるトークン**を取得することができます。これにより、エクスプロイトに対して**NTLM認証**を実行し、その後**SYSTEM**としてプロセスを実行できます。[juicy-potato](https://github.com/ohpe/juicy-potato)、[RogueWinRM](https://github.com/antonioCoco/RogueWinRM)（winrmを無効にする必要があります）、[SweetPotato](https://github.com/CCob/SweetPotato)、[PrintSpoofer](https://github.com/itm4n/PrintSpoofer)でエクスプロイトします：

{% content-ref url="../roguepotato-and-printspoofer.md" %}
[roguepotato-and-printspoofer.md](../roguepotato-and-printspoofer.md)
{% endcontent-ref %}

{% content-ref url="../juicypotato.md" %}
[juicypotato.md](../juicypotato.md)
{% endcontent-ref %}

### SeAssignPrimaryPrivilege（3.1.2）

これは**SeImpersonatePrivilege**と非常に似ており、特権のあるトークンを取得するために**同じ方法**を使用します。\
その後、この特権は、新しい/中断されたプロセスに**プライマリトークンを割り当てる**ことができます。特権のあるなりすましトークンを使用して、プライマリトークン（DuplicateTokenEx）を派生させることができます。\
トークンを使用して、'CreateProcessAsUser'で**新しいプロセス**を作成するか、プロセスを中断して**トークンを設定**できます（一般的に、実行中のプロセスのプライマリトークンを変更することはできません）。

### SeTcbPrivilege（3.1.3）

このトークンを有効にしている場合、**KERB\_S4U\_LOGON**を使用して、資格情報を知らなくても他のユーザーの**なりすましトークン**を取得し、**任意のグループ**（admins）をトークンに追加し、トークンの**整合性レベル**を「**medium**」に設定し、このトークンを**現在のスレッド**に割り当てることができます（SetThreadToken）。

### SeBackupPrivilege（3.1.4）

この特権により、システムは任意のファイルに対して**すべての読み取りアクセス**制御を許可します（読み取りのみ）。\
これを使用して、レジストリからローカル管理者アカウントのパスワードハッシュを**読み取り**、その後ハッシュ（PTH）を使用して「**psexec**」または「**wmicexec**」を使用します。\
この攻撃は、ローカル管理者が無効になっている場合、またはリモート接続された場合にローカル管理者が管理者でないように構成されている場合は機能しません。\
次の方法でこの特権を**悪用**できます：

* [https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1](https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1)
* [https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug](https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug)
* [https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab\_channel=IppSec](https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab\_channel=IppSec)で**IppSec**に従う
* または、[https://github.com/carlospolop/hacktricks/blob/master/windows/active-directory-methodology/privileged-groups-and-token-privileges.md](https://github.com/carlospolop/hacktricks/blob/master/windows/active-directory-methodology/privileged-groups-and-token-privileges.md)の**バックアップオペレーターを使用した特権のエスカレーション**セクションで説明されている方法で
### SeRestorePrivilege (3.1.5)

システム上の任意のファイルに対して**書き込みアクセス**制御が可能です。ファイルのACLに関係なく、**サービスの変更**、DLLハイジャッキング、**デバッガの設定**（Image File Execution Options）など、エスカレーションのための多くのオプションがあります。

### SeCreateTokenPrivilege (3.1.6)

このトークンは、ユーザーがトークンを**偽装**できる場合にのみEoPメソッドとして使用できます（SeImpersonatePrivilegeなしでも可能）。\
可能なシナリオでは、ユーザーは、トークンが同じユーザーのものであり、整合性レベルが現在のプロセスの整合性レベル以下である場合にトークンを偽装できます。\
この場合、ユーザーは**偽装トークンを作成**し、特権のあるグループSIDを追加することができます。

### SeLoadDriverPrivilege (3.1.7)

**デバイスドライバのロードとアンロード**が可能です。\
ImagePathとTypeの値を持つレジストリエントリを作成する必要があります。\
HKLMに書き込むアクセス権限がないため、HKCUを**使用する必要があります**。ただし、HKCUはカーネルにとっては意味を持ちません。ここでカーネルを誘導し、ドライバの設定に予想されるパスを使用するためには、パス"\Registry\User\S-1-5-21-582075628-3447520101-2530640108-1003\System\CurrentControlSet\Services\DriverName"（IDは現在のユーザーの**RID**です）を使用する必要があります。\
したがって、HKCU内にそのパス全体を作成し、ImagePath（実行されるバイナリのパス）とType（SERVICE\_KERNEL\_DRIVER 0x00000001）を設定する必要があります。

{% content-ref url="abuse-seloaddriverprivilege.md" %}
[abuse-seloaddriverprivilege.md](abuse-seloaddriverprivilege.md)
{% endcontent-ref %}

### SeTakeOwnershipPrivilege (3.1.8)

この特権は、**SeRestorePrivilege**に非常に似ています。\
WRITE\_OWNERアクセス権を付与することで、プロセスが「**任意のオブジェクトの所有権を取得**することができます。」\
まず、書き込む予定のレジストリキーの**所有権を取得**し、それに書き込むためにDACLを**変更する必要があります**。
```bash
takeown /f 'C:\some\file.txt' #Now the file is owned by you
icacls 'C:\some\file.txt' /grant <your_username>:F #Now you have full access
# Use this with files that might contain credentials such as
%WINDIR%\repair\sam
%WINDIR%\repair\system
%WINDIR%\repair\software
%WINDIR%\repair\security
%WINDIR%\system32\config\security.sav
%WINDIR%\system32\config\software.sav
%WINDIR%\system32\config\system.sav
%WINDIR%\system32\config\SecEvent.Evt
%WINDIR%\system32\config\default.sav
c:\inetpub\wwwwroot\web.config
```
### SeDebugPrivilege (3.1.9)

これにより、ホルダーは**他のプロセスをデバッグ**することができます。これには、その**プロセスのメモリに読み書き**することが含まれます。\
この特権を使用した多くの異なる**メモリインジェクション**戦略があり、これにより、ほとんどのAV/HIPSソリューションを回避することができます。

#### メモリのダンプ

この特権の**乱用の一例**として、[SysInternals](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)の[ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump)を実行して、プロセスのメモリを**ダンプ**することがあります。たとえば、ユーザーがシステムにログオンした後にユーザーの資格情報を格納する**Local Security Authority Subsystem Service (**[**LSASS**](https://en.wikipedia.org/wiki/Local\_Security\_Authority\_Subsystem\_Service)**)**プロセスです。

その後、このダンプをmimikatzに読み込んでパスワードを取得できます。
```
mimikatz.exe
mimikatz # log
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonpasswords
```
#### RCE

`NT SYSTEM` シェルを取得したい場合は、次の方法を使用できます：

* ****[**SeDebugPrivilegePoC**](https://github.com/daem0nc0re/PrivFu/tree/main/PrivilegedOperations/SeDebugPrivilegePoC)****
* ****[**psgetsys.ps1**](https://raw.githubusercontent.com/decoder-it/psgetsystem/master/psgetsys.ps1)****
```powershell
# Get the PID of a process running as NT SYSTEM
import-module psgetsys.ps1; [MyProcess]::CreateProcessFromParent(<system_pid>,<command_to_execute>)
```
## 権限の確認

To check the privileges of the current user, you can use the `whoami /priv` command. This will display a list of privileges assigned to the user.

現在のユーザーの権限を確認するには、`whoami /priv` コマンドを使用します。これにより、ユーザーに割り当てられた権限のリストが表示されます。

```plaintext
C:\> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                  Description                               State
=============================== ========================================= ========
SeShutdownPrivilege             Shut down the system                      Disabled
SeChangeNotifyPrivilege         Bypass traverse checking                  Enabled
SeUndockPrivilege               Remove computer from docking station      Disabled
SeIncreaseWorkingSetPrivilege   Increase a process working set            Disabled
...
```

The output will show the name, description, and state (enabled or disabled) of each privilege.

出力には、各権限の名前、説明、および状態（有効または無効）が表示されます。
```
whoami /priv
```
**無効になっているトークン**は有効にすることができ、実際には_有効_と_無効_のトークンを悪用することができます。

### すべてのトークンを有効にする

[**EnableAllTokenPrivs.ps1**](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1)スクリプトを使用して、すべてのトークンを有効にすることができます。
```powershell
.\EnableAllTokenPrivs.ps1
whoami /priv
```
または、この[投稿](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/)に埋め込まれた**スクリプト**。

## テーブル

完全なトークン特権のチートシートは[https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin)にありますが、以下の要約では、管理者セッションを取得したり、機密ファイルを読み取るために特権を悪用する直接的な方法のみをリストアップします。

| 特権                      | 影響         | ツール                  | 実行経路                                                                                                                                                                                                                                                                                                                                             | 備考                                                                                                                                                                                                                                                                                                                          |
| -------------------------- | ----------- | ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **`SeAssignPrimaryToken`** | _**Admin**_ | サードパーティツール    | _"potato.exe、rottenpotato.exe、juicypotato.exeなどのツールを使用して、ユーザーがトークンをなりすまし、ntシステムに特権昇格することができます"_                                                                                                                                                                                                      | 更新情報を提供してくれた[Aurélien Chalot](https://twitter.com/Defte_)に感謝します。近々、よりレシピのような表現に言い換える予定です。                                                                                                                                                                                        |
| **`SeBackup`**             | **脅威**    | _**組み込みコマンド**_ | `robocopy /b`で機密ファイルを読み取る                                                                                                                                                                                                                                                                                                             | <p>- %WINDIR%\MEMORY.DMPを読み取ることができる場合はさらに興味深いかもしれません<br><br>- `SeBackupPrivilege`（およびrobocopy）は、ファイルを開く際には役に立ちません。<br><br>- robocopyは、/bパラメータを使用するためにはSeBackupとSeRestoreの両方が必要です。</p>                                                                      |
| **`SeCreateToken`**        | _**Admin**_ | サードパーティツール    | `NtCreateToken`を使用して、ローカル管理者権限を含む任意のトークンを作成します。                                                                                                                                                                                                                                                                          |                                                                                                                                                                                                                                                                                                                                |
| **`SeDebug`**              | _**Admin**_ | **PowerShell**          | `lsass.exe`のトークンを複製します。                                                                                                                                                                                                                                                                                                                   | スクリプトは[FuzzySecurity](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Conjure-LSASS.ps1)で見つけることができます。                                                                                                                                                                                                         |
| **`SeLoadDriver`**         | _**Admin**_ | サードパーティツール    | <p>1. `szkg64.sys`などのバグのあるカーネルドライバをロードします<br>2. ドライバの脆弱性を悪用します<br><br>または、`ftlMC`組み込みコマンドを使用してセキュリティ関連のドライバをアンロードするために特権を使用することもできます。例：`fltMC sysmondrv`</p>                                                                           | <p>1. `szkg64`の脆弱性は[CVE-2018-15732](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-15732)としてリストされています<br>2. `szkg64`の[脆弱性の悪用コード](https://www.greyhathacker.net/?p=1025)は[Parvez Anwar](https://twitter.com/parvezghh)によって作成されました</p> |
| **`SeRestore`**            | _**Admin**_ | **PowerShell**          | <p>1. SeRestore特権が存在する状態でPowerShell/ISEを起動します。<br>2. [Enable-SeRestorePrivilege](https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeRestorePrivilege.ps1)を使用して特権を有効にします。<br>3. utilman.exeをutilman.oldに名前を変更します<br>4. cmd.exeをutilman.exeに名前を変更します<br>5. コンソールをロックし、Win+Uを押します</p> | 一部のAVソフトウェアによって攻撃が検出される可能性があります。<p>代替手法は、同じ特権を使用して「Program Files」に格納されたサービスバイナリを置き換えることに依存しています</p>                                                                                                                                                            |
| **`SeTakeOwnership`**      | _**Admin**_ | _**組み込みコマンド**_ | <p>1. <code>takeown.exe /f "%windir%\system32"</code><br>2. <code>icalcs.exe "%windir%\system32" /grant "%username%":F</code><br>3. cmd.exeをutilman.exeに名前を変更します<br>4. コンソールをロックし、Win+Uを押します</p>                                                                                                                                       | 一部のAVソフトウェアによって攻撃が検出される可能性があります。<p>代替手法は、同じ特権を使用して「Program Files」に格納されたサービスバイナリを置き換えることに依存しています。</p>                                                                                                                                                           |
| **`SeTcb`**                | _**Admin**_ | サードパーティツール    | <p>トークンを操作してローカル管理者権限を含める。SeImpersonateが必要な場合があります。</p><p>検証が必要です。</p>                                                                                                                                                                                                                                     |                                                                                                                                                                                                                                                                                                                                |

## 参考

* Windowsトークンを定義するこの表を参照してください：[https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin)
* トークンを使用した特権昇格についての[**この論文**](https://github.com/hatRiot/token-priv/blob/master/abusing\_token\_eop\_1.0.txt)を参照してください。

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンやHackTricksのPDFをダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)、私たちの独占的な[**NFT**](https://opensea.io/collection/the-peass-family)コレクションをご覧ください。
* [**公式PEASS＆HackTricksグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**Telegramグループ**](https://t.me/peass)に参加するか、**Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**をフォローしてください**。
* **ハッキングのトリックを共有するには、[hacktricksリポジトリ](https://github.com/carlospolop/hacktricks)と[hacktricks-cloudリポジトリ](https://github.com/carlospolop/hacktricks-cloud)にPRを提出してください**。

</details>
