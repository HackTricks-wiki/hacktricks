# 符号链接、硬链接和文件描述符

{{#include ../../banners/hacktricks-training.md}}

路径在解析时指向一个对象；打开的文件描述符则会在路径名变更后继续引用该对象。这一区别解释了 symlink 竞态、隐藏的硬链接、已删除文件的恢复，以及继承的文件描述符泄露。有关 inode 和挂载的背景信息，请参阅[文件系统、inode 和恢复](filesystem-inodes-and-recovery.md)。

## 检查链接和路径所有权

```bash
namei -l /path/to/privileged/input
stat -c '%D %i %h %U:%G %a %n' /path/to/file
readlink -f /path/to/link
find /path/to/tree -type l -ls 2>/dev/null
find /path/to/tree -type f -links +1 -ls 2>/dev/null
```

符号链接会重定向路径名解析；硬链接则是在同一文件系统上指向同一 inode 的另一个名称。如果特权任务读取或写入用户可写目录中的可预测路径，用户可能就能将该路径重定向到敏感目标。检查每个父目录的所有权和权限，而不只是最终文件。`fs.protected_symlinks` 和 `fs.protected_hardlinks` 可以减少常见的跨用户攻击，但不能让任意可写路径变得安全。

对于使用 shell glob 更改权限的特权任务，要区分展开为**命令行操作数**的链接与稍后在递归遍历中遇到的链接。[GNU `chmod` 会作用于命令行中指定的符号链接所指向的对象](https://www.gnu.org/software/coreutils/manual/html_node/chmod-invocation.html)，而通常会忽略递归过程中遇到的符号链接；仅使用 `-R` 并不会让这两种情况等同。检查实际的计划任务身份和命令、不可信用户能否创建与 glob 匹配的条目、已安装的 `chmod` 的行为和选项，以及目标最终会获得什么访问权限。仅有可写目录或符号链接，并不能证明特权模式会发生改变。在被动枚举期间检查脚本和路径元数据，不要创建链接或触发任务。

即使文件名包含看起来随机的哈希，特权计划任务写入的输出路径仍可能是可预测的：[C `rand()` 在相同 `srand()` 种子下会重复相同序列](https://man7.org/linux/man-pages/man3/rand.3.html)，包括使用已知执行时间生成的种子。如果任务还会读取调用者可写的数据库行来构造文件名，就要核实具体的行到文件名算法、种子和 libc 行为、执行计划、调用者写入行和创建目录的权限，以及特权打开文件前能否放置预先存在的符号链接。[`fopen(..., "w")` 会创建或截断解析后的文件](https://man7.org/linux/man-pages/man3/fopen.3.html)；检查实际实现是否使用防链接的打开标志或原子替换、有效写入身份、目标权限，以及粘滞目录的符号链接策略。仅有可预测的文件名或可写的数据库行，只能作为进一步审查的线索。在被动枚举期间检查代码、计划任务和元数据，不要插入数据库行或运行任务。

对于以另一个用户身份运行的文件转换服务，要检查调用者能否选择输出路径或扩展名，以及转换器是否会跟随预先存在的输出符号链接。有些转换器会根据路径名扩展名选择输出格式；使用受支持扩展名命名的链接，仍然可以指向没有扩展名的敏感目标。要成功实现跨用户写入，必须满足以下条件：服务可访问、调用者能控制路径和链接、转换器会打开该链接进行输出，并且服务身份对目标有写入权限。Linux 的 `fs.protected_symlinks=1` 会限制在**粘滞的全局可写目录**中跟随其他用户的链接；对于普通的用户所有目录中的链接，它并不提供同等保护。得出结论前，先检查解析后的路径和父目录所有权。参见 [calibre 的输出文件行为](https://manual.calibre-ebook.com/generated/en/ebook-convert.html)和 [Linux 符号链接策略](https://www.kernel.org/doc/html/latest/admin-guide/sysctl/fs.html#protected-symlinks)。

如果允许通过 sudo 运行的下载包装器在保留调用者可控工作目录的同时获取调用者选择的数据，也需要审查输出路径。检查实际使用的下载器，以及它选定的基本文件名、冲突处理方式或预先存在的符号链接是否会重定向特权写入；仅有 URL 选择或符号链接并不足以构成问题。[Axel 文档说明了按用户配置的 `~/.axelrc`](https://github.com/axel-download-accelerator/axel/blob/master/doc/axel.txt)，其[示例配置包含 `default_filename` 和 `no_clobber`](https://github.com/axel-download-accelerator/axel/blob/master/doc/axelrc.example)，因此使用 Axel 的包装器也可能继承该文件中的输出名称设置。确认有效的 `HOME`：[sudo 会根据策略重置或保留该变量](https://man7.org/linux/man-pages/man8/sudo.8.html)，只有特权下载器确实会读取用户的 `.axelrc` 时，该文件才相关。在被动枚举期间检查规则、包装器、配置文件路径和权限、最终输出名称及目标文件状态，不要启动下载。

对于允许通过 sudo 运行的 ACL 包装器，要检查它在调用 `setfacl` 前如何验证调用者选择的文件。仅进行词法前缀检查并拒绝 `..`，无法阻止允许目录中的符号链接解析到目录之外；`test -f` 也会跟随链接。确认包装器能以足够的权限执行 ACL 操作、调用者能控制该链接，并且最终 ACL 能赋予目标文件**及其父目录**所需的访问权限。有些使用方会拒绝 ACL 可写或权限过于宽松的文件，因此仅修改 ACL 并不能证明提权路径可行。

## 审查对用户挂载的 FUSE 文件系统进行的特权写入

`/etc/fuse.conf` 中有效的独立 `user_allow_other` 配置行，允许非 root 用户在 FUSE 挂载上请求 `allow_other` 或 `allow_root`。这些挂载选项可能让 root 进程访问由挂载用户实现的文件系统。如果允许通过 sudo 运行的辅助程序会相对于调用者可控的工作目录写入包含机密的日志或其他输出，就要检查该目录是否可能是用户挂载的 FUSE 文件系统。即使生成的文件在普通文件系统上看起来属于 root 所有或权限为 `0600`，FUSE 实现仍可能观察到写入操作。

```bash
grep -n '^[[:space:]]*user_allow_other[[:space:]]*$' /etc/fuse.conf 2>/dev/null
sudo -l
```

这是一个**候选线索**，并非泄露的证据。确认实际的 sudo/run-as 身份和参数、helper 的输出路径及敏感内容、对 `/dev/fuse` 的访问权限、是否能通过 `allow_other` 或 `allow_root` 成功挂载，以及特权进程能否进入该挂载点。常规枚举期间不要运行特权 helper，也不要挂载文件系统。参见 [libfuse policy description](https://github.com/libfuse/libfuse/blob/master/util/fuse.conf) 和 [libfuse access FAQ](https://github.com/libfuse/libfuse/wiki/FAQ#why-dont-other-users-have-access-to-the-mounted-filesystem)。

## 查找路径竞态

危险的模式是：特权程序检查某个路径名，之后又打开同一路径名，却没有安全地保留对已检查对象的引用。能够控制父目录的攻击者可以在这两次操作之间替换文件或符号链接。同类问题也会出现在临时文件、由计时器触发的脚本、归档解压和备份流程中。声称存在影响前，请确认实际的读写操作和目标权限。

归档**创建**也可能导致跨身份泄露。Info-ZIP `zip -r` 通常会跟随源目录树中的符号链接并存储目标内容；`-y`/`--symlinks` 则会存储链接本身。如果低权限用户能在备份目录中添加链接，请检查具体的归档工具和选项、备份任务的读取身份，以及生成的归档是否可被该用户读取。源目录可写或存在符号链接本身并不能证明发生了泄露。检查链接和归档元数据，不要在枚举期间触发备份或解压秘密内容。参见 [Info-ZIP option documentation](https://sources.debian.org/src/zip/3.0-3/man/zip.1/#L1638)。

GNU `tar` 的默认行为不同：它通常将符号链接存储为链接，而 [`-h` / `--dereference` 会在创建归档时跟随链接](https://www.gnu.org/software/tar/manual/html_node/dereference.html)。对于特权定时备份，请检查确切的 `tar` 调用、低权限用户能否在 `tar` 读取输入路径前替换它，以及生成的归档是否可被该用户访问。可写暂存目录中的临时校验和或其他 sidecar 文件，如果在后续 `tar -h` 命令中被明确指定，也可能成为这样的输入。必须核实竞态窗口、任务身份、符号链接策略、该身份对目标的读取权限，以及归档 ACL。被动检查期间不要替换文件、运行任务或解包敏感归档。

当特权任务读取低权限用户可替换的归档时，归档**解压**会跨越另一个权限边界。[GNU tar 由超级用户运行时通常会恢复归档中记录的所有权](https://www.gnu.org/software/tar/manual/html_node/Option-Summary.html)，其[权限恢复选项](https://www.gnu.org/software/tar/manual/html_node/Setting-Access-Permissions.html)会影响解压出的模式位。检查具体的解压工具和标志、归档替换窗口、数字形式的所有者和模式元数据、解压目录权限，以及清理操作是否会使结果仍可被访问。只有在解压后模式得以保留，且目标挂载点和进程策略允许身份变更时，root 所有的 SUID 成员才构成风险；不可信归档或可写暂存路径本身并不能证明这一点。被动枚举期间，检查任务和元数据，不要替换或解压归档。

解压出的符号链接也可能在之后的特权比较过程中泄露受保护文件。[GNU `diff` 比较目录时通常会跟随符号链接](https://www.gnu.org/software/diffutils/manual/html_node/Special-Files.html)，因此，root 运行的 `diff -r` 若针对不可信的解压目录，可能会读取链接目标，并在输出中包含不同的内容。确认归档可以被替换、链接指向比较操作实际会访问的路径、任务身份可以读取目标，以及低权限用户可以读取比较输出或错误日志。链接或归档本身并不能证明发生了泄露；枚举期间检查任务、路径元数据和日志权限，不要运行比较操作或读取受保护内容。

重复的主机端传输可能会使不可信归档成员变成后续操作的输出路径。如果高权限任务从较低信任级别的容器复制归档，解压出名称与下一次传输目标 basename 相同的符号链接，之后又写入该路径，那么后续写入可能会落到链接目标。检查归档成员名称和目标、解压标志和目录、解压工具是否确实会保留该链接、传输实现如何处理已有的目标链接，以及主机任务的有效写入身份。[GNU tar 说明了解压时如何处理已有文件和符号链接](https://www.gnu.org/software/tar/manual/html_section/extract-options.html)；[现代版本的 OpenSSH scp 默认使用 SFTP](https://man.openbsd.org/scp.1)，因此请核实已安装版本的传输行为，不要假定所有版本的 `scp` 都会通过链接写入。容器中可见的 `scp` 进程或可写归档本身，不能证明主机侧会进行解压并随后写入。枚举期间检查任务和路径元数据，不要传输或解压特制归档。

Ansible 的 [`synchronize` module](https://docs.ansible.com/projects/ansible/latest/collections/ansible/posix/synchronize_module.html) 封装了 rsync；`copy_links: true` 会复制符号链接的目标，而非链接本身。对于定时备份，请检查低权限用户能否在确切的源目录树中创建链接、同步身份能否读取其目标，以及生成的副本或归档是否可被该用户读取。playbook、链接位置、run-as 身份和输出权限必须全部吻合；可写上传目录或 `copy_links` 设置本身仅是需要检查的线索。检查元数据和 playbook，不要创建链接或触发任务。

## 检查打开的文件描述符

```bash
ls -l /proc/<PID>/fd 2>/dev/null
lsof -p <PID> 2>/dev/null
lsof +L1 2>/dev/null
```

进程在文件被删除或重命名后，仍可能保留对该文件的访问权限。特权进程也可能通过 Unix socket 传递文件描述符，或者因缺少 close-on-exec 而在 `execve()` 后意外保持文件描述符打开。检查 `/proc/<PID>/fd` 中指向敏感文件、已删除文件、容器内可见的主机路径以及意外 socket 的目标。访问其他进程的文件描述符受内核访问检查限制；能看到符号链接，并不保证能读取其内容。

自定义 SUID helper 可能打开受保护的路径名、放弃其 effective UID，并保持文件描述符打开。如果随后将自身设为可转储，`/proc/<PID>/fd` 的所有权和访问权限可能会改变；应检查确切的凭据转换、[`PR_SET_DUMPABLE`](https://man7.org/linux/man-pages/man2/PR_SET_DUMPABLE.2const.html)、procfs/ptrace 策略以及目标文件的模式。重新打开文件描述符路径，可能绕过无法访问的**父目录**，但如果调用者无权读取该文件，操作仍会失败。仅凭可见的文件描述符目标或 SUID 位，并不能证明存在信息泄露。

崩溃产物是另一条线索：core dump 可能包含进程内存，包括此前以更高身份读取的数据。在 Ubuntu 上，[Apport 通常会将报告放在 `/var/crash`](https://documentation.ubuntu.com/project/contributors/debugging/apport/)；其他系统可能使用不同的 `core_pattern` handler 或 systemd 存储。常规枚举时，只检查报告路径、所有者、模式和可读性。只有当相关进程可转储、崩溃处理程序保留了敏感字节，且当前用户能够访问该报告时，可读报告才有意义。被动枚举时，不要让 helper 崩溃，也不要解包 dump。有关 SUID 和生成 dump 的条件，请参阅 [`core(5)`](https://man7.org/linux/man-pages/man5/core.5.html)。

如果服务使用继承的文件描述符，请先检查其启动链和文件描述符编号，再尝试 shell 重定向或 `/proc/self/fd/<N>`。如果文件已删除但仍处于打开状态，[通过打开的文件描述符恢复已删除文件](filesystem-inodes-and-recovery.md#deleted-file-recovery-through-open-fds)可能有助于保留证据或恢复内容。进行进程级排查时，继续阅读[进程枚举和服务路径](../processes-crontab-systemd-dbus/process-enumeration-and-service-paths.md)。
{{#include ../../banners/hacktricks-training.md}}
