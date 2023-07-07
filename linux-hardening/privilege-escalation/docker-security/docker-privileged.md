# Docker --privileged

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業で働いていますか？** **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricks swag**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **ハッキングのトリックを共有するには、[hacktricks repo](https://github.com/carlospolop/hacktricks)と[hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**にPRを提出してください。

</details>

## 影響

特権付きコンテナを実行すると、次の保護が無効になります：

### /devのマウント

特権付きコンテナでは、すべての**デバイスに`/dev/`でアクセスできます**。したがって、ホストのディスクを**マウント**することで**脱出**することができます。

{% tabs %}
{% tab title="デフォルトのコンテナ内部" %}
```bash
# docker run --rm -it alpine sh
ls /dev
console  fd       mqueue   ptmx     random   stderr   stdout   urandom
core     full     null     pts      shm      stdin    tty      zero
```
{% tab title="特権コンテナ内部" %}
```bash
# docker run --rm --privileged -it alpine sh
ls /dev
cachefiles       mapper           port             shm              tty24            tty44            tty7
console          mem              psaux            stderr           tty25            tty45            tty8
core             mqueue           ptmx             stdin            tty26            tty46            tty9
cpu              nbd0             pts              stdout           tty27            tty47            ttyS0
[...]
```
{% endtab %}
{% endtabs %}

### 読み取り専用のカーネルファイルシステム

カーネルファイルシステムは、**プロセスがカーネルの実行方法を変更するメカニズム**を提供します。デフォルトでは、**コンテナプロセスがカーネルを変更することは望ましくありません**ので、コンテナ内でカーネルファイルシステムを読み取り専用でマウントします。

{% tabs %}
{% tab title="デフォルトのコンテナ内部" %}
```bash
# docker run --rm -it alpine sh
mount | grep '(ro'
sysfs on /sys type sysfs (ro,nosuid,nodev,noexec,relatime)
cpuset on /sys/fs/cgroup/cpuset type cgroup (ro,nosuid,nodev,noexec,relatime,cpuset)
cpu on /sys/fs/cgroup/cpu type cgroup (ro,nosuid,nodev,noexec,relatime,cpu)
cpuacct on /sys/fs/cgroup/cpuacct type cgroup (ro,nosuid,nodev,noexec,relatime,cpuacct)
```
{% tab title="特権コンテナ内部" %}
```bash
# docker run --rm --privileged -it alpine sh
mount  | grep '(ro'
```
{% endtab %}
{% endtabs %}

### カーネルファイルシステムのマスキング

**/proc**ファイルシステムはネームスペースに対応しており、特定の書き込みが許可されるため、読み取り専用でマウントされません。ただし、/procファイルシステムの特定のディレクトリは、書き込みから**保護される必要があり**、一部の場合は**読み取りからも保護される必要があります**。これらの場合、コンテナエンジンは潜在的に危険なディレクトリに対して**tmpfs**ファイルシステムをマウントし、コンテナ内のプロセスがそれらを使用できないようにします。

{% hint style="info" %}
**tmpfs**は、すべてのファイルを仮想メモリに格納するファイルシステムです。tmpfsはハードドライブにファイルを作成しません。したがって、tmpfsファイルシステムをアンマウントすると、それに存在するすべてのファイルが永久に失われます。
{% endhint %}

{% tabs %}
{% tab title="デフォルトのコンテナ内部" %}
```bash
# docker run --rm -it alpine sh
mount  | grep /proc.*tmpfs
tmpfs on /proc/acpi type tmpfs (ro,relatime)
tmpfs on /proc/kcore type tmpfs (rw,nosuid,size=65536k,mode=755)
tmpfs on /proc/keys type tmpfs (rw,nosuid,size=65536k,mode=755)
```
{% tab title="特権コンテナ内部" %}
```bash
# docker run --rm --privileged -it alpine sh
mount  | grep /proc.*tmpfs
```
{% endtab %}
{% endtabs %}

### Linuxの機能

コンテナエンジンは、デフォルトではコンテナ内で何が行われるかを制御するために、**制限された数の機能**でコンテナを起動します。**特権**の場合は、**すべての機能**にアクセスできます。機能については、以下を参照してください。

{% content-ref url="../linux-capabilities.md" %}
[linux-capabilities.md](../linux-capabilities.md)
{% endcontent-ref %}

{% tabs %}
{% tab title="デフォルトのコンテナ内部" %}
```bash
# docker run --rm -it alpine sh
apk add -U libcap; capsh --print
[...]
Current: cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap=eip
Bounding set =cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap
[...]
```
{% tab title="特権コンテナ内部" %}
```bash
# docker run --rm --privileged -it alpine sh
apk add -U libcap; capsh --print
[...]
Current: =eip cap_perfmon,cap_bpf,cap_checkpoint_restore-eip
Bounding set =cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,cap_audit_read
[...]
```
{% endtab %}
{% endtabs %}

`--privileged` mode gives all capabilities to the container, but it is not recommended for security reasons. Instead, you can use the `--cap-add` flag to add specific capabilities to the container and the `--cap-drop` flag to remove specific capabilities.

### Seccomp

**Seccomp**は、コンテナが呼び出すことができる**シスコール**を制限するために役立ちます。Dockerコンテナを実行すると、デフォルトのSeccompプロファイルが有効になりますが、特権モードでは無効になります。Seccompについて詳しくはこちらを参照してください：

{% content-ref url="seccomp.md" %}
[seccomp.md](seccomp.md)
{% endcontent-ref %}

{% tabs %}
{% tab title="デフォルトのコンテナ内部" %}
```bash
# docker run --rm -it alpine sh
grep Seccomp /proc/1/status
Seccomp:	2
Seccomp_filters:	1
```
{% tab title="特権コンテナ内部" %}
```bash
# docker run --rm --privileged -it alpine sh
grep Seccomp /proc/1/status
Seccomp:	0
Seccomp_filters:	0
```
{% endtab %}
{% endtabs %}
```bash
# You can manually disable seccomp in docker with
--security-opt seccomp=unconfined
```
また、Docker（または他のCRIs）が**Kubernetes**クラスターで使用される場合、**seccompフィルターはデフォルトで無効**になっていることに注意してください。

### AppArmor

**AppArmor**は、**コンテナ**を**制限された**一部の**リソース**と**プログラムごとのプロファイル**に制約するためのカーネルの拡張機能です。`--privileged`フラグを使用して実行すると、この保護は無効になります。

{% content-ref url="apparmor.md" %}
[apparmor.md](apparmor.md)
{% endcontent-ref %}
```bash
# You can manually disable seccomp in docker with
--security-opt apparmor=unconfined
```
### SELinux

`--privileged`フラグを使用すると、**SELinuxラベルが無効化**され、コンテナは**コンテナエンジンが実行されたときのラベルで実行**されます。このラベルは通常`unconfined`であり、コンテナエンジンが持つラベルに**完全なアクセス権限**を持ちます。ルートレスモードでは、コンテナは`container_runtime_t`で実行されます。ルートモードでは、`spc_t`で実行されます。

{% content-ref url="../selinux.md" %}
[selinux.md](../selinux.md)
{% endcontent-ref %}
```bash
# You can manually disable selinux in docker with
--security-opt label:disable
```
## 影響を受けないもの

### ネームスペース

ネームスペースは`--privileged`フラグによって**影響を受けません**。セキュリティ制約が有効になっていないため、システム上のすべてのプロセスやホストネットワークを見ることはありません。ユーザーは、**`--pid=host`、`--net=host`、`--ipc=host`、`--uts=host`**のコンテナエンジンフラグを使用して個々のネームスペースを無効にすることができます。

{% tabs %}
{% tab title="デフォルトの特権付きコンテナ内部" %}
```bash
# docker run --rm --privileged -it alpine sh
ps -ef
PID   USER     TIME  COMMAND
1 root      0:00 sh
18 root      0:00 ps -ef
```
{% tab title="ホスト内 --pid=host コンテナ" %}
```bash
# docker run --rm --privileged --pid=host -it alpine sh
ps -ef
PID   USER     TIME  COMMAND
1 root      0:03 /sbin/init
2 root      0:00 [kthreadd]
3 root      0:00 [rcu_gp]ount | grep /proc.*tmpfs
[...]
```
{% endtab %}
{% endtabs %}

### ユーザーネームスペース

コンテナエンジンはデフォルトではユーザーネームスペースを使用しません。ただし、ルートレスコンテナは常にユーザーネームスペースを使用してファイルシステムをマウントし、単一のUID以上を使用します。ルートレスの場合、ユーザーネームスペースは無効にすることはできません。ルートレスコンテナを実行するためには、ユーザーネームスペースが必要です。ユーザーネームスペースは特定の特権を防止し、セキュリティを向上させます。

## 参考文献

* [https://www.redhat.com/sysadmin/privileged-flag-container-engines](https://www.redhat.com/sysadmin/privileged-flag-container-engines)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**テレグラムグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **ハッキングのトリックを共有するには、[hacktricksリポジトリ](https://github.com/carlospolop/hacktricks)と[hacktricks-cloudリポジトリ](https://github.com/carlospolop/hacktricks-cloud)にPRを提出してください。**

</details>
