# トークンの悪用

<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）</strong>を使って、**ゼロからヒーローまでAWSハッキングを学ぼう**</summary>

* **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**してみたいですか？または、**最新バージョンのPEASSを入手したり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見しましょう。独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式PEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* **💬** [**Discordグループ**](https://discord.gg/hRep4RUj7f)に参加するか、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter**で私をフォローする🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **ハッキングテクニックを共有する**には、[**hacktricksリポジトリ**](https://github.com/carlospolop/hacktricks)と[**hacktricks-cloudリポジトリ**](https://github.com/carlospolop/hacktricks-cloud)にPRを提出してください。

</details>

## トークン

**Windowsアクセストークンが何かわからない**場合は、続行する前にこのページを読んでください：

{% content-ref url="access-tokens.md" %}
[access-tokens.md](access-tokens.md)
{% endcontent-ref %}

**おそらく、すでに持っているトークンを悪用して特権を昇格させることができるかもしれません**

### SeImpersonatePrivilege

これは、任意のプロセスが任意のトークンを模倣（作成ではなく）できる権限であり、それに対するハンドルを取得できる場合には、そのトークンを取得できます。特権のあるトークンは、Windowsサービス（DCOM）から取得でき、それをエクスプロイトに対してNTLM認証を実行させることで、SYSTEM特権でプロセスを実行できるようになります。この脆弱性は、[juicy-potato](https://github.com/ohpe/juicy-potato)、[RogueWinRM](https://github.com/antonioCoco/RogueWinRM)（winrmを無効にする必要があります）、[SweetPotato](https://github.com/CCob/SweetPotato)、[PrintSpoofer](https://github.com/itm4n/PrintSpoofer)などのさまざまなツールを使用して悪用できます。

{% content-ref url="roguepotato-and-printspoofer.md" %}
[roguepotato-and-printspoofer.md](roguepotato-and-printspoofer.md)
{% endcontent-ref %}

{% content-ref url="juicypotato.md" %}
[juicypotato.md](juicypotato.md)
{% endcontent-ref %}

### SeAssignPrimaryPrivilege

**SeImpersonatePrivilege**と非常に似ており、**同じ方法**を使用して特権トークンを取得します。\
その後、この特権は、新しい/中断されたプロセスに**主要トークンを割り当てる**ことを可能にします。特権のある模倣トークンを使用して、主要トークン（DuplicateTokenEx）を派生させることができます。\
トークンを使用して、'CreateProcessAsUser'で**新しいプロセス**を作成したり、プロセスを中断して**トークンを設定**したりできます（一般的に、実行中のプロセスの主要トークンを変更することはできません）。

### SeTcbPrivilege

このトークンを有効にしている場合、**KERB\_S4U\_LOGON**を使用して、他のユーザーの**模倣トークン**を取得したり、資格情報を知らずに**任意のグループ**（管理者）をトークンに追加したり、トークンの**整合性レベル**を「中」に設定したり、このトークンを**現在のスレッド**に割り当てたりできます（SetThreadToken）。

### SeBackupPrivilege

この特権により、システムはこの特権により、任意のファイルに**すべての読み取りアクセス**制御を付与します（読み取り操作に制限されます）。これは、レジストリからローカル管理者のパスワードハッシュを読み取るために使用され、その後、ツール「**psexec**」や「**wmicexec**」をハッシュと共に使用できます（Pass-the-Hash技術）。ただし、この技術は、ローカル管理者アカウントが無効になっている場合や、リモートで接続しているローカル管理者から管理権限を削除するポリシーがある場合には失敗します。\
次のように、この特権を**悪用**できます：

* [https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1](https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1)
* [https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug](https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug)
* [https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab\_channel=IppSec](https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab\_channel=IppSec)で**IppSec**に従う
* または、次のように**バックアップオペレーターで特権を昇格**する方法が説明されています：

{% content-ref url="../active-directory-methodology/privileged-groups-and-token-privileges.md" %}
[privileged-groups-and-token-privileges.md](../active-directory-methodology/privileged-groups-and-token-privileges.md)
{% endcontent-ref %}

### SeRestorePrivilege

この特権により、ファイルの**書き込みアクセス**権限が、ファイルのアクセス制御リスト（ACL）に関係なく提供されます。これにより、**サービスの変更**、DLLハイジャック、および**イメージファイル実行オプション**を介したデバッガーの設定など、さまざまなエスカレーションの可能性が開かれます。

### SeCreateTokenPrivilege

SeCreateTokenPrivilegeは、ユーザーがトークンを模倣できる能力を持っている場合に特に有用な権限ですが、SeImpersonatePrivilegeがない場合でも有用です。この機能は、同じユーザーを表すトークンを模倣し、その整合性レベルが現在のプロセスの整合性レベルを上回らない場合に依存しています。

**主なポイント:**

* **SeImpersonatePrivilegeなしでの模倣:** 特定の条件下でSeCreateTokenPrivilegeを利用して、特定の条件下でトークンを模倣することでEoPを実現できます。
* **トークン模倣の条件:** 成功した模倣には、対象のトークンが同じユーザーに属し、模倣を試みるプロセスの整合性レベルがそのトークンの整合性レベル以下である必要があります。
* **模倣トークンの作成と変更:** ユーザーは模倣トークンを作成し、特権グループのSID（セキュリティ識別子）を追加して強化することができます。

### SeLoadDriverPrivilege

この特権により、`ImagePath`と`Type`の特定の値を持つレジストリエントリを作成して、デバイスドライバーを**ロードおよびアンロード**できます。`HKLM`（HKEY\_LOCAL\_MACHINE）への直接書き込みアクセスが制限されているため、代わりに`HKCU`（HKEY\_CURRENT\_USER）を使用する必要があります。ただし、ドライバーの構成のためにカーネルが`HKCU`を認識できるようにするには、特定のパスをたどる必要があります。

このパスは、`\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName`であり、ここで`<RID>`は現在のユーザーの相対識別子です。`HKCU`内で、このパス全体を作成し、2つの値を設定する必要があります：

* 実行されるバイナリのパスである`ImagePath`
* `SERVICE_KERNEL_DRIVER`（`0x00000001`）の値を持つ`Type`。

**手順:**

1. 制限された書き込みアクセスのため、`HKLM`の代わりに`HKCU`にアクセスします。
2. `HKCU`内に、`<RID>`が現在のユーザーの相対識別子を表す`\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName`のパスを作成します。
3. `ImagePath`をバイナリの実行パスに設定します。
4. `Type`を`SERVICE_KERNEL_DRIVER`（`0x00000001`）に設定します。
```python
# Example Python code to set the registry values
import winreg as reg

# Define the path and values
path = r'Software\YourPath\System\CurrentControlSet\Services\DriverName' # Adjust 'YourPath' as needed
key = reg.OpenKey(reg.HKEY_CURRENT_USER, path, 0, reg.KEY_WRITE)
reg.SetValueEx(key, "ImagePath", 0, reg.REG_SZ, "path_to_binary")
reg.SetValueEx(key, "Type", 0, reg.REG_DWORD, 0x00000001)
reg.CloseKey(key)
```
さらにこの特権を悪用する方法があります [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege)

### SeTakeOwnershipPrivilege

これは **SeRestorePrivilege** に似ています。その主な機能は、**オブジェクトの所有権を取得** することを可能にし、WRITE\_OWNER アクセス権の提供を通じて明示的な自己決定アクセスの要件を回避します。プロセスは、最初に書き込み目的で意図したレジストリキーの所有権を確保し、その後、DACLを変更して書き込み操作を有効にすることを含みます。
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
### SeDebugPrivilege

この特権を使用すると、他のプロセスのデバッグが許可され、メモリ内の読み書きが可能になります。この特権を使用して、ほとんどのアンチウイルスおよびホスト侵入防止ソリューションを回避できるさまざまなメモリインジェクション戦略を適用できます。

#### メモリのダンプ

[ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump)を[SysInternals Suite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)から使用して、プロセスのメモリをキャプチャできます。具体的には、これはユーザーがシステムに正常にログインした後にユーザーの資格情報を保存する**Local Security Authority Subsystem Service (LSASS)**プロセスに適用できます。

その後、このダンプをmimikatzに読み込んでパスワードを取得できます：
```
mimikatz.exe
mimikatz # log
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonpasswords
```
#### RCE

`NT SYSTEM`のシェルを取得したい場合は、次の方法があります：

* [**SeDebugPrivilege-Exploit (C++)**](https://github.com/bruno-1337/SeDebugPrivilege-Exploit)
* [**SeDebugPrivilegePoC (C#)**](https://github.com/daem0nc0re/PrivFu/tree/main/PrivilegedOperations/SeDebugPrivilegePoC)
* [**psgetsys.ps1 (Powershell Script)**](https://raw.githubusercontent.com/decoder-it/psgetsystem/master/psgetsys.ps1)
```powershell
# Get the PID of a process running as NT SYSTEM
import-module psgetsys.ps1; [MyProcess]::CreateProcessFromParent(<system_pid>,<command_to_execute>)
```
## 権限の確認
```
whoami /priv
```
**無効になっているトークン** は有効にできます。実際に _Enabled_ と _Disabled_ トークンを悪用することができます。

### すべてのトークンを有効にする

トークンが無効になっている場合、[**EnableAllTokenPrivs.ps1**](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1) スクリプトを使用してすべてのトークンを有効にできます。
```powershell
.\EnableAllTokenPrivs.ps1
whoami /priv
```
または、この[投稿](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/)に埋め込まれた**スクリプト**。

## テーブル

完全なトークン特権チートシートは[https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin)にあり、以下の要約は管理者セッションを取得したり機密ファイルを読むための直接的な悪用方法のみをリストアップします。

| 特権                      | 影響        | ツール                   | 実行パス                                                                                                                                                                                                                                                                                                                                     | 備考                                                                                                                                                                                                                                                                                                                        |
| -------------------------- | ----------- | ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **`SeAssignPrimaryToken`** | _**Admin**_ | サードパーティーツール    | _"ユーザーがトークンを偽装し、potato.exe、rottenpotato.exe、juicypotato.exeなどのツールを使用してntシステムに昇格することを可能にします"_                                                                                                                                                                                                      | 更新情報を提供してくれた[Aurélien Chalot](https://twitter.com/Defte\_)に感謝します。近々、よりレシピのような表現に言い換えてみます。                                                                                                                                                                                        |
| **`SeBackup`**             | **脅威**    | _**組み込みコマンド**_    | `robocopy /b`で機密ファイルを読む                                                                                                                                                                                                                                                                                                             | <p>- %WINDIR%\MEMORY.DMPを読むことができるかもしれません<br><br>- <code>SeBackupPrivilege</code>（およびrobocopy）はファイルを開く際には役立ちません。<br><br>- Robocopyは/bパラメータとともに動作するためにはSeBackupとSeRestoreの両方が必要です。</p>                                                                      |
| **`SeCreateToken`**        | _**Admin**_ | サードパーティーツール    | `NtCreateToken`を使用してローカル管理者権限を含む任意のトークンを作成します。                                                                                                                                                                                                                                                                          |                                                                                                                                                                                                                                                                                                                                |
| **`SeDebug`**              | _**Admin**_ | **PowerShell**          | `lsass.exe`トークンを複製します。                                                                                                                                                                                                                                                                                                                   | スクリプトは[FuzzySecurity](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Conjure-LSASS.ps1)で見つけることができます。                                                                                                                                                                                                         |
| **`SeLoadDriver`**         | _**Admin**_ | サードパーティーツール    | <p>1. <code>szkg64.sys</code>などのバグのあるカーネルドライバをロードします<br>2. ドライバの脆弱性を悪用します<br><br>また、<code>ftlMC</code>組み込みコマンドを使用してセキュリティ関連のドライバをアンロードするために特権を使用することもできます。例： <code>fltMC sysmondrv</code></p>                                                                           | <p>1. <code>szkg64</code>の脆弱性は<a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-15732">CVE-2018-15732</a>としてリストされています<br>2. <code>szkg64</code>の<a href="https://www.greyhathacker.net/?p=1025">悪用コード</a>は<a href="https://twitter.com/parvezghh">Parvez Anwar</a>によって作成されました</p> |
| **`SeRestore`**            | _**Admin**_ | **PowerShell**          | <p>1. SeRestore特権が存在する状態でPowerShell/ISEを起動します。<br>2. <a href="https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeRestorePrivilege.ps1">Enable-SeRestorePrivilege</a>を使用して特権を有効にします。<br>3. utilman.exeをutilman.oldにリネームします<br>4. cmd.exeをutilman.exeにリネームします<br>5. コンソールをロックし、Win+Uを押します</p> | <p>一部のAVソフトウェアによって攻撃が検出される可能性があります。</p><p>代替手法は、同じ特権を使用して「Program Files」に格納されたサービスバイナリを置き換えることに依存します</p>                                                                                                                                                            |
| **`SeTakeOwnership`**      | _**Admin**_ | _**組み込みコマンド**_    | <p>1. <code>takeown.exe /f "%windir%\system32"</code><br>2. <code>icalcs.exe "%windir%\system32" /grant "%username%":F</code><br>3. cmd.exeをutilman.exeにリネームします<br>4. コンソールをロックし、Win+Uを押します</p>                                                                                                                                       | <p>一部のAVソフトウェアによって攻撃が検出される可能性があります。</p><p>代替手法は、同じ特権を使用して「Program Files」に格納されたサービスバイナリを置き換えることに依存します。</p>                                                                                                                                                           |
| **`SeTcb`**                | _**Admin**_ | サードパーティーツール    | <p>トークンを操作してローカル管理者権限を含めます。SeImpersonateが必要な場合があります。</p><p>検証が必要です。</p>                                                                                                                                                                                                                                     |                                                                                                                                                                                                                                                                                                                                |

## 参考

* Windowsトークンを定義するこのテーブルをご覧ください：[https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin)
* トークンを使用した特権昇格に関する[**この論文**](https://github.com/hatRiot/token-priv/blob/master/abusing\_token\_eop\_1.0.txt)をご覧ください。
