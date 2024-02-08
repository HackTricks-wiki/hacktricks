# Docker --privileged

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> - <a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**してみたいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[NFTs](https://opensea.io/collection/the-peass-family)コレクションをご覧ください
* [**公式PEASS＆HackTricks swag**](https://peass.creator-spring.com)を手に入れましょう
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**をフォロー**してください。
* **ハッキングトリックを共有するには、[hacktricksリポジトリ](https://github.com/carlospolop/hacktricks)と[hacktricks-cloudリポジトリ](https://github.com/carlospolop/hacktricks-cloud)**にPRを提出してください。

</details>

## 影響

特権付きコンテナを実行すると、次の保護が無効になります：

### /dev をマウント

特権付きコンテナでは、すべての**デバイスに `/dev/` でアクセス**できます。そのため、ホストのディスクを**マウント**して**脱出**することができます。

{% tabs %}
{% tab title="デフォルトコンテナ内部" %}
```bash
# docker run --rm -it alpine sh
ls /dev
console  fd       mqueue   ptmx     random   stderr   stdout   urandom
core     full     null     pts      shm      stdin    tty      zero
```
{% endtab %}

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
### 読み取り専用のカーネルファイルシステム

カーネルファイルシステムは、プロセスがカーネルの動作を変更する仕組みを提供します。ただし、コンテナプロセスの場合、カーネルに変更を加えることを防ぎたいです。したがって、コンテナ内でカーネルファイルシステムを**読み取り専用**でマウントし、コンテナプロセスがカーネルを変更できないようにします。
```bash
# docker run --rm -it alpine sh
mount | grep '(ro'
sysfs on /sys type sysfs (ro,nosuid,nodev,noexec,relatime)
cpuset on /sys/fs/cgroup/cpuset type cgroup (ro,nosuid,nodev,noexec,relatime,cpuset)
cpu on /sys/fs/cgroup/cpu type cgroup (ro,nosuid,nodev,noexec,relatime,cpu)
cpuacct on /sys/fs/cgroup/cpuacct type cgroup (ro,nosuid,nodev,noexec,relatime,cpuacct)
```
{% endtab %}

{% tab title="特権コンテナ内部" %}
```bash
# docker run --rm --privileged -it alpine sh
mount  | grep '(ro'
```
### カーネルファイルシステムのマスキング

**/proc**ファイルシステムは選択的に書き込み可能ですが、セキュリティのため、一部の部分は**tmpfs**でオーバーレイされ、コンテナプロセスが機密領域にアクセスできないように読み書きアクセスが遮断されています。

{% hint style="info" %}
**tmpfs**は仮想メモリにすべてのファイルを保存するファイルシステムです。tmpfsはハードドライブにファイルを作成しません。したがって、tmpfsファイルシステムをアンマウントすると、その中にあるすべてのファイルが永遠に失われます。
{% endhint %}

{% tabs %}
{% tab title="デフォルトコンテナ内部" %}
```bash
# docker run --rm -it alpine sh
mount  | grep /proc.*tmpfs
tmpfs on /proc/acpi type tmpfs (ro,relatime)
tmpfs on /proc/kcore type tmpfs (rw,nosuid,size=65536k,mode=755)
tmpfs on /proc/keys type tmpfs (rw,nosuid,size=65536k,mode=755)
```
{% endtab %}

{% tab title="特権コンテナ内部" %}
```bash
# docker run --rm --privileged -it alpine sh
mount  | grep /proc.*tmpfs
```
### Linuxの機能

コンテナエンジンは、コンテナを**デフォルトで内部で何が起こるかを制御するために、**制限された数の機能**で起動します。**特権**を持つものは、**すべて**の**機能**にアクセスできます。機能について学ぶには、以下を参照してください：

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
{% endtab %}

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

コンテナで利用可能な機能を`--privileged`モードで実行せずに、`--cap-add`および`--cap-drop`フラグを使用して操作することができます。

### Seccomp

**Seccomp**は、コンテナが呼び出すことができる**syscalls**を**制限**するのに役立ちます。 Dockerコンテナを実行する際にはデフォルトでseccompプロファイルが有効になっていますが、特権モードでは無効になります。Seccompについて詳しくはこちらを参照してください：

{% content-ref url="seccomp.md" %}
[seccomp.md](seccomp.md)
{% endcontent-ref %}
```bash
# docker run --rm -it alpine sh
grep Seccomp /proc/1/status
Seccomp:	2
Seccomp_filters:	1
```
{% endtab %}

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
また、Docker（または他のCRIs）が**Kubernetes**クラスターで使用される場合、**seccompフィルターはデフォルトで無効**になります。

### AppArmor

**AppArmor**は、**プログラムごとのプロファイル**を使用して**コンテナ**を**限られた**リソースセットに制限するためのカーネルの拡張機能です。`--privileged`フラグで実行すると、この保護が無効になります。

{% content-ref url="apparmor.md" %}
[apparmor.md](apparmor.md)
{% endcontent-ref %}
```bash
# You can manually disable seccomp in docker with
--security-opt apparmor=unconfined
```
### SELinux

`--privileged` フラグを使用してコンテナを実行すると、**SELinux ラベル**が無効になり、通常 `unconfined` であるコンテナエンジンのラベルを継承し、コンテナエンジンと同様の完全アクセス権限が付与されます。ルートレスモードでは `container_runtime_t` を使用し、ルートモードでは `spc_t` が適用されます。

{% content-ref url="../selinux.md" %}
[selinux.md](../selinux.md)
{% endcontent-ref %}
```bash
# You can manually disable selinux in docker with
--security-opt label:disable
```
## 影響を受けないもの

### 名前空間

名前空間は`--privileged`フラグの影響を受けません。セキュリティ制約が有効になっていないにもかかわらず、**システム上のすべてのプロセスやホストネットワークを見ることはできません**。ユーザーは、**`--pid=host`、`--net=host`、`--ipc=host`、`--uts=host`**のコンテナエンジンフラグを使用して個々の名前空間を無効にできます。

{% tabs %}
{% tab title="デフォルトの特権付きコンテナ内部" %}
```bash
# docker run --rm --privileged -it alpine sh
ps -ef
PID   USER     TIME  COMMAND
1 root      0:00 sh
18 root      0:00 ps -ef
```
{% endtab %}

{% tab title="ホストの--pid=hostコンテナ内部" %}
```bash
# docker run --rm --privileged --pid=host -it alpine sh
ps -ef
PID   USER     TIME  COMMAND
1 root      0:03 /sbin/init
2 root      0:00 [kthreadd]
3 root      0:00 [rcu_gp]ount | grep /proc.*tmpfs
[...]
```
### ユーザー名前空間

**デフォルトでは、コンテナエンジンはユーザー名前空間を利用しません。ただし、ルートレスコンテナでは、ファイルシステムのマウントや複数のUIDの使用に必要とされるため、ユーザー名前空間が使用されます。** ルートレスコンテナには不可欠であり、特権を制限することでセキュリティを大幅に向上させます。

## 参考文献

* [https://www.redhat.com/sysadmin/privileged-flag-container-engines](https://www.redhat.com/sysadmin/privileged-flag-container-engines)
