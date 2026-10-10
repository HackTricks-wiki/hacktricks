# 符号链接、硬链接和文件描述符

{{#include ../../banners/hacktricks-training.md}}

路径名指向解析时的对象；打开的文件描述符则会在路径名发生变化后，继续引用该对象。这一区别解释了符号链接竞态、隐藏的硬链接、已删除文件的恢复，以及继承的文件描述符 leaks。有关 inode 和挂载的背景信息，请参阅[文件系统、inode 和恢复](filesystem-inodes-and-recovery.md)。

## 检查链接和路径所有权

```bash
namei -l /path/to/privileged/input
stat -c '%D %i %h %U:%G %a %n' /path/to/file
readlink -f /path/to/link
find /path/to/tree -type l -ls 2>/dev/null
find /path/to/tree -type f -links +1 -ls 2>/dev/null
```

符号链接会重定向路径名解析；硬链接则是在同一文件系统上指向同一 inode 的另一个名称。如果特权任务在用户可写目录中读取或写入一个可预测的路径，用户可能能够将该路径重定向到敏感目标。检查每个父目录的所有权和权限，而不只是最终文件。`fs.protected_symlinks` 和 `fs.protected_hardlinks` 可减少常见的跨用户攻击，但不能让任意可写路径变得安全。

对于使用 shell glob 更改权限的特权任务，要区分展开为**命令行操作数**的链接与递归遍历时才遇到的链接。[GNU `chmod` 会作用于命令行中指定的符号链接所指向的对象](https://www.gnu.org/software/coreutils/manual/html_node/chmod-invocation.html)，而递归过程中遇到的符号链接通常会被忽略；单独使用 `-R` 并不会让这两种情况等同。检查实际的计划任务身份和命令、不受信任的用户能否创建匹配 glob 的目录项、已安装的 `chmod` 的行为和选项，以及拟议目标最终获得的访问权限。可写目录或符号链接本身并不能证明特权模式会被更改。在被动枚举期间，应检查脚本和路径元数据，不要放置链接或触发任务。

特权计划任务的写入路径可能是可预测的，即使文件名中包含看似随机的哈希：[C `rand()` 在相同的 `srand()` 种子下会重复相同序列](https://man7.org/linux/man-pages/man3/rand.3.html)，包括由已知执行时间推导出的种子。如果任务还会读取调用者可写的数据库行来构造该名称，请核实具体的行到名称算法、种子和 libc 行为、计划时间、调用者写入数据库行和创建目录的权限，以及能否在特权打开文件前放置预先存在的符号链接。[`fopen(..., "w")` 会创建或截断解析后的文件](https://man7.org/linux/man-pages/man3/fopen.3.html)；检查实际实现是否使用防链接的打开标志或原子替换、有效写入身份、目标权限，以及粘滞目录的符号链接策略。可预测的名称或可写的数据库行本身都只是进一步审查的线索。在被动枚举期间，应检查代码、计划时间和元数据，不要插入数据库行或运行任务。

对于以另一个用户身份运行的文件转换服务，应检查调用者能否选择输出路径或扩展名，以及转换器是否会跟随预先存在的输出符号链接。一些转换器会根据路径名扩展名选择输出格式；使用受支持扩展名命名的链接仍可能指向一个没有扩展名的敏感目标。要实现跨用户写入，必须满足以下条件：服务可访问、调用者能控制路径和链接、转换器会打开该链接进行输出，并且服务身份拥有写入权限。Linux 的 `fs.protected_symlinks=1` 会限制跟随**粘滞且全局可写目录**中属于其他用户的链接；对于普通用户所有的目录中的链接，它并不提供同等保护。在得出结论前，先检查解析后的路径和父目录所有权。参见 [calibre 的输出文件行为](https://manual.calibre-ebook.com/generated/en/ebook-convert.html)和 [Linux 符号链接策略](https://www.kernel.org/doc/html/latest/admin-guide/sysctl/fs.html#protected-symlinks)。

如果允许通过 sudo 运行的下载包装器在保留调用者控制的工作目录时获取调用者指定的数据，也需要进行相同的输出路径审查。检查实际使用的下载器，以及它选择的基本文件名、冲突处理方式或预先存在的符号链接是否能重定向特权写入；仅有 URL 选择或符号链接并不足以证明存在问题。[Axel 文档说明了按用户配置的 `~/.axelrc`](https://github.com/axel-download-accelerator/axel/blob/master/doc/axel.txt)，其[示例配置包含 `default_filename` 和 `no_clobber`](https://github.com/axel-download-accelerator/axel/blob/master/doc/axelrc.example)，因此使用 Axel 的包装器也可能从该文件继承输出名称设置。确认有效的 `HOME`：[sudo 可根据策略重置或保留它](https://man7.org/linux/man-pages/man8/sudo.8.html)，只有特权下载器实际读取用户的 `.axelrc` 时，该文件才相关。在被动枚举期间，检查规则、包装器、配置路径及其权限、最终输出名称和目标文件状态，不要启动下载。

对于允许通过 sudo 运行的 ACL 包装器，应检查它在调用 `setfacl` 前如何验证调用者指定的文件。仅检查词法前缀并拒绝 `..`，无法阻止允许目录中的符号链接解析到目录外；`test -f` 也会跟随链接。确认包装器能否以足够的特权执行 ACL 操作、调用者是否控制该链接，以及最终 ACL 是否会在目标**及其父目录**上授予所需访问权限。一些使用方会拒绝 ACL 可写或权限过宽的文件，因此仅更改 ACL 并不能证明存在可行的提权路径。

## 审查对用户挂载的 FUSE 文件系统进行的特权写入

`/etc/fuse.conf` 中启用的独立 `user_allow_other` 行允许非 root 用户在 FUSE 挂载时请求 `allow_other` 或 `allow_root`。这些挂载选项可能允许 root 进程访问由挂载用户实现的文件系统。如果允许通过 sudo 运行的辅助程序会在调用者控制的工作目录下写入包含敏感信息的日志或其他输出，应检查该目录是否可能是用户挂载的 FUSE 文件系统。即使生成的文件在普通文件系统上显示为 root 所有或权限为 `0600`，FUSE 实现仍可能观察到写入操作。

```bash
grep -n '^[[:space:]]*user_allow_other[[:space:]]*$' /etc/fuse.conf 2>/dev/null
sudo -l
```

这是一个**候选项**，并非泄露的证明。请确认实际的 sudo/run-as 身份和参数、helper 的输出路径及敏感内容、是否能访问 `/dev/fuse`、是否能通过 `allow_other` 或 `allow_root` 成功挂载，以及特权进程是否能够进入该挂载点。日常枚举时不要运行特权 helper 或挂载文件系统。参见 [libfuse policy description](https://github.com/libfuse/libfuse/blob/master/util/fuse.conf) 和 [libfuse access FAQ](https://github.com/libfuse/libfuse/wiki/FAQ#why-dont-other-users-have-access-to-the-mounted-filesystem)。

## 检查路径竞态

危险模式是：特权程序检查一个路径名，之后又打开同一路径名，却没有安全地保留对已检查对象的引用。控制父目录的攻击者可以在这两次操作之间替换文件或符号链接。临时文件、由定时器触发的脚本、归档解压和备份工作流中也会出现同类问题。在声称存在影响之前，请确认实际的读写操作和目标权限。

归档**创建**也可能跨身份泄露文件。Info-ZIP `zip -r` 通常会跟随放在源目录树中的符号链接，并存储目标内容；而 `-y`/`--symlinks` 会改为存储链接本身。如果低权限用户能在备份目录中添加链接，请检查具体的归档工具及选项、备份任务的读取身份，以及该用户能否读取生成的归档。仅有可写源目录或符号链接并不能证明存在泄露。枚举期间应检查链接和归档元数据，不要触发备份或解压敏感内容。参见 [Info-ZIP option documentation](https://sources.debian.org/src/zip/3.0-3/man/zip.1/#L1638)。

GNU `tar` 的默认行为不同：它通常会将符号链接存储为链接，而在创建归档时，[`-h` / `--dereference` 会跟随链接](https://www.gnu.org/software/tar/manual/html_node/dereference.html)。对于特权定时备份，请检查确切的 `tar` 调用、低权限用户能否在 `tar` 读取输入路径前替换该路径，以及该用户能否访问生成的归档。如果后续 `tar -h` 命令显式指定了可写暂存目录中的临时校验和文件或其他 sidecar，它们也可能成为此类输入。需要核实竞态窗口、任务身份、符号链接策略、该身份对目标的可读性以及归档 ACL。被动检查期间不要替换文件、运行任务或解包敏感归档。

当特权任务读取低权限用户可以替换的归档时，归档**解压**会跨越另一道边界。[GNU tar 以超级用户身份运行时通常会恢复归档中的所有权](https://www.gnu.org/software/tar/manual/html_node/Option-Summary.html)，其[权限恢复选项](https://www.gnu.org/software/tar/manual/html_node/Setting-Access-Permissions.html)会影响解压文件的模式位。请检查具体的解压工具及标志、归档替换窗口、数字形式的所有者和模式元数据、解压目录权限，以及清理操作是否会留下可访问的结果。只有在解压后模式仍然保留，且目标挂载点和进程策略允许身份变更时，root 所有的 SUID 文件才构成隐患；仅有不受信任的归档或可写暂存路径并不能证明存在问题。被动枚举期间应检查任务和元数据，不要替换或解压归档。

解压出的符号链接还可能在后续特权比较中泄露受保护文件。[GNU `diff` 比较目录时通常会跟随符号链接](https://www.gnu.org/software/diffutils/manual/html_node/Special-Files.html)，因此，以 root 身份运行的 `diff -r` 若比较不受信任的解压目录树，可能会读取链接目标，并在输出中包含不同的内容。请确认归档可以被替换、链接指向比较过程实际访问的路径、任务有权限读取目标，以及低权限用户可以读取比较输出或错误日志。仅有链接或归档并不能证明存在泄露；枚举期间应检查任务、路径元数据和日志权限，不要运行比较或读取受保护内容。

重复的主机侧传输可能会使不受信任的归档成员变成后续输出路径。如果高权限任务从低信任容器复制归档，解压出一个名称与下次传输目标文件名相同的符号链接，之后又向同一路径写入内容，那么后续写入可能会到达链接目标。请检查归档成员名称及目标、解压选项和目录、解压工具是否确实会保留该链接、传输实现如何处理已有的目标链接，以及主机任务的有效写入身份。[GNU tar 说明了解压时如何处理现有文件和符号链接](https://www.gnu.org/software/tar/manual/html_section/extract-options.html)；[现代版本默认使用 SFTP 的 OpenSSH scp](https://man.openbsd.org/scp.1)，因此应核实已安装版本的传输行为，而不要假定所有版本的 `scp` 都会跟随链接写入。仅凭容器可见的 `scp` 进程或可写归档，无法证明主机上的解压和后续写入会发生。枚举期间应检查任务和路径元数据，不要传输或解压特制归档。

Ansible 的 [`synchronize` module](https://docs.ansible.com/projects/ansible/latest/collections/ansible/posix/synchronize_module.html) 封装了 rsync；`copy_links: true` 会复制符号链接的指向对象，而不是链接本身。对于定时备份，请检查低权限用户能否在确切的源目录树中创建链接、同步操作所用身份能否读取其目标，以及该用户能否读取生成的副本或归档。playbook、链接位置、run-as 身份和输出权限必须全部吻合；仅有可写上传目录或 `copy_links` 设置，只能作为进一步审查的线索。请检查元数据和 playbook，不要创建链接或触发任务。

## 检查打开的文件描述符

```bash
ls -l /proc/<PID>/fd 2>/dev/null
lsof -p <PID> 2>/dev/null
lsof +L1 2>/dev/null
```

进程在文件被删除或重命名后，仍可能保留对该文件的访问权限。特权进程也可能通过 Unix socket 传递文件描述符，或者在缺少 close-on-exec 设置时，意外地在 `execve()` 后仍保持文件描述符打开。检查 `/proc/<PID>/fd` 指向的目标，留意敏感文件、已删除文件、容器内可见的宿主机路径，以及意外出现的 socket。访问其他进程的文件描述符会受到内核访问检查的限制；能看到符号链接，并不意味着就能读取其内容。

自定义 SUID helper 可能会打开受保护的路径、降低其有效 UID，并让文件描述符保持打开状态。如果随后将自身设为可转储，`/proc/<PID>/fd` 的所有权和访问权限可能会改变；请检查具体的凭据切换过程、[`PR_SET_DUMPABLE`](https://man7.org/linux/man-pages/man2/PR_SET_DUMPABLE.2const.html)、procfs/ptrace 策略，以及目标文件的模式。重新打开文件描述符路径，可能绕过无法访问的**父目录**，但如果调用者无权读取该文件，操作仍会失败。仅凭可见的文件描述符目标或 SUID 位，不能证明数据已泄露。

崩溃产物是另一条线索：核心转储可能包含进程内存，包括此前以更高权限读取的数据。在 Ubuntu 上，[Apport 通常会将报告放在 `/var/crash`](https://documentation.ubuntu.com/project/contributors/debugging/apport/)；其他系统可能使用不同的 `core_pattern` 处理程序或 systemd 存储。常规枚举时，只检查报告路径、所有者、模式和可读性。只有在相关进程可转储、崩溃处理程序保留了敏感字节，且当前用户能够访问报告时，可读报告才有意义。不要在被动枚举期间让 helper 崩溃，也不要解包转储。有关 SUID 和转储生成条件，请参阅 [`core(5)`](https://man7.org/linux/man-pages/man5/core.5.html)。

如果服务使用继承的文件描述符，请先检查其启动链和文件描述符编号，再尝试 shell 重定向或 `/proc/self/fd/<N>`。如果文件已删除但仍保持打开，[通过打开的文件描述符恢复已删除文件](filesystem-inodes-and-recovery.md#deleted-file-recovery-through-open-fds)可能有助于保留证据或恢复内容。进程级排查请继续阅读[进程枚举与服务路径](../processes-crontab-systemd-dbus/process-enumeration-and-service-paths.md)。
{{#include ../../banners/hacktricks-training.md}}
