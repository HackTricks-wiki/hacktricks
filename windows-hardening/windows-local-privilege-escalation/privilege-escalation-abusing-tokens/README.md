# トークンの悪用

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業**で働いていますか？ **HackTricksで企業を宣伝**したいですか？または、**最新バージョンのPEASSにアクセス**したいですか、またはHackTricksをPDFでダウンロードしたいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[NFTs](https://opensea.io/collection/the-peass-family)のコレクションを見つけてください
* [**公式PEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう
* **[💬](https://emojipedia.org/speech-balloon/) Discordグループ**に参加するか、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter**で私をフォローする**🐦**[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **ハッキングトリックを共有する**には、[hacktricksリポジトリ](https://github.com/carlospolop/hacktricks)と[hacktricks-cloudリポジトリ](https://github.com/carlospolop/hacktricks-cloud)にPRを提出してください。

</details>

## トークン

**Windowsアクセストークン**が何かわからない場合は、続行する前にこのページを読んでください：

{% content-ref url="../access-tokens.md" %}
[access-tokens.md](../access-tokens.md)
{% endcontent-ref %}

**おそらく、すでに持っているトークンを悪用して特権を昇格させることができるかもしれません**

### SeImpersonatePrivilege（3.1.1）

この特権を持つプロセスは、取得できる**トークン**を**偽装**（作成はできません）できます。**Windowsサービス**（DCOM）から**特権トークン**を取得し、**NTLM認証**を使って**システム**としてプロセスを実行できます。[juicy-potato](https://github.com/ohpe/juicy-potato)、[RogueWinRM](https://github.com/antonioCoco/RogueWinRM)（winrmを無効にする必要あり）、[SweetPotato](https://github.com/CCob/SweetPotato)、[PrintSpoofer](https://github.com/itm4n/PrintSpoofer)で悪用できます：

{% content-ref url="../roguepotato-and-printspoofer.md" %}
[roguepotato-and-printspoofer.md](../roguepotato-and-printspoofer.md)
{% endcontent-ref %}

{% content-ref url="../juicypotato.md" %}
[juicypotato.md](../juicypotato.md)
{% endcontent-ref %}

### SeAssignPrimaryPrivilege（3.1.2）

**SeImpersonatePrivilege**と非常に似ており、特権トークンを取得するために**同じ方法**を使用します。\
その後、この特権は、新しい/中断されたプロセスに**プライマリトークンを割り当てる**ことを可能にします。特権偽装トークンを使用してプライマリトークン（DuplicateTokenEx）を派生させることができます。\
トークンを使用して、'CreateProcessAsUser'で**新しいプロセスを作成**したり、プロセスを中断して**トークンを設定**したりできます（一般的に、実行中のプロセスのプライマリトークンを変更することはできません）。

### SeTcbPrivilege（3.1.3）

このトークンを有効にしている場合、**KERB\_S4U\_LOGON**を使用して、資格情報を知らなくても他のユーザーのために**偽装トークン**を取得し、**任意のグループ**（管理者）を追加し、トークンの**整合性レベル**を「**medium**」に設定し、このトークンを**現在のスレッド**に割り当てることができます（SetThreadToken）。

### SeBackupPrivilege（3.1.4）

この特権により、システムは任意のファイルに**読み取りアクセス権**をすべて付与します（読み取りのみ）。\
これを使用して、レジストリからローカル管理者アカウントのパスワードハッシュを**読み取り**、その後、ハッシュ（PTH）を使用して「**psexec**」または「**wmicexec**」を使用できます。\
この攻撃は、ローカル管理者が無効になっている場合、またはリモートで接続されている場合にローカル管理者が管理者でないように構成されている場合には機能しません。\
次の方法でこの特権を**悪用**できます：

* [https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1](https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1)
* [https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug](https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug)
* [https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab\_channel=IppSec](https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab\_channel=IppSec)で**IppSec**に従う
* または、次の方法で**バックアップオペレーターを使用して特権を昇格**するセクションで説明されているように：

{% content-ref url="../../active-directory-methodology/privileged-groups-and-token-privileges.md" %}
[privileged-groups-and-token-privileges.md](../../active-directory-methodology/privileged-groups-and-token-privileges.md)
{% endcontent-ref %}

### SeRestorePrivilege（3.1.5）

システム上の任意のファイルに**書き込みアクセス権**を与えます。\
**サービスの変更**、DLLハイジャック、**デバッガー**の設定（Image File Execution Options）など、昇格するための多くのオプションがあります。

### SeCreateTokenPrivilege（3.1.6）

このトークンは、ユーザーがトークンを**偽装**できる場合にのみEoPメソッドとして**使用できます**（SeImpersonatePrivilegeがなくても）。\
可能なシナリオでは、ユーザーが同じユーザー用のトークンを偽装し、整合性レベルが現在のプロセスの整合性レベル以下である場合に、トークンに特権グループSIDを追加できます。

### SeLoadDriverPrivilege（3.1.7）

**デバイスドライバーの読み込みとアンロード**ができます。\
ImagePathとTypeの値を持つレジストリにエントリを作成する必要があります。\
HKLMに書き込み権限がないため、HKCUを**使用する必要があります**。ただし、HKCUはカーネルにとって意味がないため、カーネルにガイドする方法は、ドライバー構成のための期待されるパスを使用するため、パスを使用することです："\Registry\User\S-1-5-21-582075628-3447520101-2530640108-1003\System\CurrentControlSet\Services\DriverName"（IDは現在のユーザーの**RID**です）。\
したがって、HKCU内にそのパスをすべて作成し、ImagePath（実行されるバイナリのパス）とType（SERVICE\_KERNEL\_DRIVER 0x00000001）を設定する必要があります。

{% content-ref url="abuse-seloaddriverprivilege.md" %}
[abuse-seloaddriverprivilege.md](abuse-seloaddriverprivilege.md)
{% endcontent-ref %}

### SeTakeOwnershipPrivilege（3.1.8）

この特権は**SeRestorePrivilege**に非常に似ています。\
WRITE\_OWNERアクセス権を付与することで、「**任意のオブジェクトの所有権を取得**することができます。\
まず、書き込むレジストリキーの**所有権を取得**し、書き込むことができるようにDACLを**変更**する必要があります。
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

これにより、**他のプロセスをデバッグ**することができます。これには、その**プロセスのメモリに読み書き**することが含まれます。\
この特権を使用すると、AV/HIPS ソリューションの大部分を回避するために使用できるさまざまな**メモリインジェクション**戦略があります。

#### メモリのダンプ

この特権の**乱用の一例**として、[SysInternals](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)から[ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump)を実行して、**プロセスのメモリをダンプ**することが挙げられます。たとえば、ユーザーがシステムにログオンした後にユーザーの資格情報を格納する**Local Security Authority Subsystem Service (**[**LSASS**](https://en.wikipedia.org/wiki/Local\_Security\_Authority\_Subsystem\_Service)**)**プロセスです。

その後、このダンプをmimikatzに読み込んでパスワードを取得できます：
```
mimikatz.exe
mimikatz # log
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonpasswords
```
#### RCE

`NT SYSTEM`のシェルを取得したい場合は、次の方法を使用できます：

- ****[**SeDebugPrivilegePoC**](https://github.com/daem0nc0re/PrivFu/tree/main/PrivilegedOperations/SeDebugPrivilegePoC)****
- ****[**psgetsys.ps1**](https://raw.githubusercontent.com/decoder-it/psgetsystem/master/psgetsys.ps1)****
```powershell
# Get the PID of a process running as NT SYSTEM
import-module psgetsys.ps1; [MyProcess]::CreateProcessFromParent(<system_pid>,<command_to_execute>)
```
## 権限の確認
```
whoami /priv
```
**無効になっているトークン**は有効にできます。実際には、_Enabled_ と _Disabled_ トークンを悪用することができます。

### すべてのトークンを有効にする

[**EnableAllTokenPrivs.ps1**](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1) スクリプトを使用して、すべてのトークンを有効にできます。
```powershell
.\EnableAllTokenPrivs.ps1
whoami /priv
```
または、この[**投稿**](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/)に埋め込まれた**スクリプト**。

## テーブル

完全なトークン特権チートシートは[https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin)にあり、以下の要約は管理者セッションを取得したり機密ファイルを読むための特権を悪用する直接的な方法のみをリストします。

| 特権                      | 影響         | ツール                   | 実行パス                                                                                                                                                                                                                                                                                                                                      | 備考                                                                                                                                                                                                                                                                                                                          |
| -------------------------- | ----------- | ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **`SeAssignPrimaryToken`** | _**Admin**_ | サードパーティーツール       | _"ユーザーがトークンを偽装し、potato.exe、rottenpotato.exe、juicypotato.exeなどのツールを使用してntシステムに昇格することを可能にします"_                                                                                                                                                                                                      | 更新情報を提供してくれた[Aurélien Chalot](https://twitter.com/Defte\_)に感謝します。近々、もう少しレシピのような表現に言い換えてみます。                                                                                                                                                                                        |
| **`SeBackup`**             | **Threat**  | _**組み込みコマンド**_       | `robocopy /b`で機密ファイルを読む                                                                                                                                                                                                                                                                                                             | <p>- %WINDIR%\MEMORY.DMPを読むことができるとさらに興味深いかもしれません<br><br>- <code>SeBackupPrivilege</code>（およびrobocopy）は、ファイルを開く際には役立ちません。<br><br>- Robocopyは/bパラメータを使用する際にはSeBackupとSeRestoreの両方が必要です。</p>                                                                      |
| **`SeCreateToken`**        | _**Admin**_ | サードパーティーツール       | `NtCreateToken`を使用してローカル管理者権限を含む任意のトークンを作成します。                                                                                                                                                                                                                                                                          |                                                                                                                                                                                                                                                                                                                                |
| **`SeDebug`**              | _**Admin**_ | **PowerShell**          | `lsass.exe`トークンを複製します。                                                                                                                                                                                                                                                                                                                   | スクリプトは[FuzzySecurity](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Conjure-LSASS.ps1)で見つけることができます                                                                                                                                                                                                         |
| **`SeLoadDriver`**         | _**Admin**_ | サードパーティーツール       | <p>1. <code>szkg64.sys</code>などのバグのあるカーネルドライバをロードします<br>2. ドライバの脆弱性を悪用します<br><br>また、<code>ftlMC</code>組み込みコマンドを使用してセキュリティ関連のドライバをアンロードするために特権を使用することもできます。例： <code>fltMC sysmondrv</code></p>                                                                           | <p>1. <code>szkg64</code>の脆弱性は<a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-15732">CVE-2018-15732</a>としてリストされています<br>2. <code>szkg64</code>の<a href="https://www.greyhathacker.net/?p=1025">悪用コード</a>は<a href="https://twitter.com/parvezghh">Parvez Anwar</a>によって作成されました</p> |
| **`SeRestore`**            | _**Admin**_ | **PowerShell**          | <p>1. SeRestore特権が存在する状態でPowerShell/ISEを起動します。<br>2. <a href="https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeRestorePrivilege.ps1">Enable-SeRestorePrivilege</a>を使用して特権を有効にします。<br>3. utilman.exeをutilman.oldに名前変更します<br>4. cmd.exeをutilman.exeに名前変更します<br>5. コンソールをロックし、Win+Uを押します</p> | <p>一部のAVソフトウェアによって攻撃が検出される可能性があります。</p><p>代替手法は、同じ特権を使用して「Program Files」に格納されたサービスバイナリを置き換えることに依存します</p>                                                                                                                                                            |
| **`SeTakeOwnership`**      | _**Admin**_ | _**組み込みコマンド**_       | <p>1. <code>takeown.exe /f "%windir%\system32"</code><br>2. <code>icalcs.exe "%windir%\system32" /grant "%username%":F</code><br>3. cmd.exeをutilman.exeに名前変更します<br>4. コンソールをロックし、Win+Uを押します</p>                                                                                                                                       | <p>一部のAVソフトウェアによって攻撃が検出される可能性があります。</p><p>代替手法は、同じ特権を使用して「Program Files」に格納されたサービスバイナリを置き換えることに依存します。</p>                                                                                                                                                           |
| **`SeTcb`**                | _**Admin**_ | サードパーティーツール       | <p>トークンを操作してローカル管理者権限を含める。SeImpersonateが必要な場合があります。</p><p>検証する必要があります。</p>                                                                                                                                                                                                                                     |                                                                                                                                                                                                                                                                                                                                |

## 参考

* Windowsトークンを定義するこのテーブルを参照してください：[https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin)
* トークンを使用した昇格についての[**この論文**](https://github.com/hatRiot/token-priv/blob/master/abusing\_token\_eop\_1.0.txt)をご覧ください。
