# 符号链接、硬链接和文件描述符

{{#include ../../banners/hacktricks-training.md}}

路径在解析时指向一个对象；打开的文件描述符会在路径名发生变化后继续引用该对象。这一区别解释了符号链接竞争、隐藏的硬链接、已删除文件的恢复，以及继承的文件描述符 leak。有关 inode 和挂载的背景信息，请参阅[文件系统、inode 和恢复](filesystem-inodes-and-recovery.md)。

## 检查链接和路径所有权

```bash
namei -l /path/to/privileged/input
stat -c '%D %i %h %U:%G %a %n' /path/to/file
readlink -f /path/to/link
find /path/to/tree -type l -ls 2>/dev/null
find /path/to/tree -type f -links +1 -ls 2>/dev/null
```

符号链接会重定向路径名解析；硬链接是在同一文件系统上指向同一 inode 的另一个名称。如果特权任务在用户可写目录中读取或写入可预测的路径，用户可能能够将该路径重定向到敏感目标。检查每个父目录的所有权和权限，而不只是最终文件。`fs.protected_symlinks` 和 `fs.protected_hardlinks` 可减少常见的跨用户攻击，但不能让任意可写路径变得安全。

对于使用 shell glob 更改权限的特权任务，要区分展开为**命令行操作数**的链接与递归遍历过程中遇到的链接。[GNU `chmod` 会作用于命令行中指定的符号链接所指向的文件](https://www.gnu.org/software/coreutils/manual/html_node/chmod-invocation.html)，而通常会忽略递归过程中遇到的符号链接；仅使用 `-R` 并不会让这两种情况等同。检查实际运行身份和命令、不受信任用户能否创建与 glob 匹配的条目、已安装的 `chmod` 行为及选项，以及目标最终获得的访问权限。仅有可写目录或符号链接，并不能证明会发生特权权限更改。在被动枚举期间，应检查脚本和路径元数据，不要创建链接或触发任务。

即使文件名包含看似随机的哈希，特权定时任务仍可能生成可预测的输出路径：[C `rand()` 在相同的 `srand()` 种子下会重复相同序列](https://man7.org/linux/man-pages/man3/rand.3.html)，包括由已知执行时间推导出的种子。如果任务还会读取调用者可写的数据库行来构造文件名，请核实确切的行到名称算法、种子和 libc 行为、执行计划、调用者写入该行及创建目录的权限，以及能否在特权进程打开文件前放置预先存在的符号链接。[`fopen(..., "w")` 会创建或截断解析后的文件](https://man7.org/linux/man-pages/man3/fopen.3.html)；检查实际实现是否使用防链接的打开标志或原子替换、有效写入身份、目标权限，以及粘滞目录的符号链接策略。可预测的名称或可写的行本身都只能作为进一步审查的线索。在被动枚举期间，应检查代码、执行计划和元数据，不要插入行或运行任务。

对于以其他用户身份运行的文件转换服务，应检查调用者能否选择输出路径或扩展名，以及转换器是否会跟随预先存在的输出符号链接。一些转换器会根据路径名扩展名选择输出格式；使用受支持扩展名命名的链接仍可能指向一个没有扩展名的敏感目标。要成功实现跨用户写入，必须有可访问的服务、调用者对路径和链接的控制、转换器打开该链接进行输出，以及服务身份对目标具有写权限。Linux 的 `fs.protected_symlinks=1` 会限制在**粘滞的全局可写目录**中跟随其他用户的链接；它不会为普通的用户所有目录中的链接提供相同保护。得出结论前，先检查解析后的路径及父目录所有权。参见 [calibre 的输出文件行为](https://manual.calibre-ebook.com/generated/en/ebook-convert.html)和 [Linux 符号链接策略](https://www.kernel.org/doc/html/latest/admin-guide/sysctl/fs.html#protected-symlinks)。

如果 sudo 允许的下载包装器在保留调用者可控工作目录的同时获取调用者选择的数据，也需要进行相同的输出路径审查。检查实际使用的下载器，以及它选定的基本文件名、冲突处理方式或预先存在的符号链接是否可能重定向特权写入；仅有 URL 选择或符号链接并不足以证明存在风险。[Axel 文档说明了每用户配置文件 `~/.axelrc`](https://github.com/axel-download-accelerator/axel/blob/master/doc/axel.txt)，其[示例配置包含 `default_filename` 和 `no_clobber`](https://github.com/axel-download-accelerator/axel/blob/master/doc/axelrc.example)，因此使用 Axel 的包装器也可能继承该文件中的输出名称设置。确认有效的 `HOME`：[sudo 会根据策略重置或保留它](https://man7.org/linux/man-pages/man8/sudo.8.html)，只有在特权下载器实际读取用户的 `.axelrc` 时，该文件才相关。在被动枚举期间，检查规则、包装器、配置路径及其权限、最终输出名称和目标文件状态，不要启动下载。

对于 sudo 允许的 ACL 包装器，应检查它在调用 `setfacl` 前如何验证调用者选择的文件。仅检查词法前缀并拒绝 `..`，无法阻止允许目录内的符号链接解析到目录之外；`test -f` 也会跟随链接。确认包装器是否能以足够权限执行 ACL 操作、调用者是否控制该链接，以及生成的 ACL 是否能在目标**及其父目录**上授予所需访问权限。一些使用方会拒绝具有可写 ACL 或宽松模式的文件，因此仅更改 ACL 并不能证明存在可行的权限提升路径。

## 审查写入用户挂载的特权 FUSE 文件系统的操作

`/etc/fuse.conf` 中启用的独立 `user_allow_other` 行允许非 root 用户在 FUSE 挂载上请求 `allow_other` 或 `allow_root`。这些挂载选项可以让 root 进程访问由挂载用户实现的文件系统。如果 sudo 允许的辅助程序会相对于调用者可控的工作目录写入包含机密的日志或其他输出，应检查该目录是否可能是用户挂载的 FUSE 文件系统。即使生成的文件在普通文件系统上看起来属于 root 且权限为 `0600`，FUSE 实现仍能观察写入。

```bash
grep -n '^[[:space:]]*user_allow_other[[:space:]]*$' /etc/fuse.conf 2>/dev/null
sudo -l
```

这是一个**候选线索**，不是信息泄露的证明。确认实际的 sudo/run-as 身份和参数、helper 的输出路径及敏感内容、对 `/dev/fuse` 的访问权限、能否使用 `allow_other` 或 `allow_root` 成功挂载，以及特权进程能否进入该挂载点。常规枚举时，不要运行特权 helper 或挂载文件系统。参见 [libfuse policy description](https://github.com/libfuse/libfuse/blob/master/util/fuse.conf) 和 [libfuse access FAQ](https://github.com/libfuse/libfuse/wiki/FAQ#why-dont-other-users-have-access-to-the-mounted-filesystem)。

## 查找路径竞争

危险模式是：特权程序检查一个路径名，之后又打开同一路径名，却没有保留对已检查对象的安全引用。控制父目录的攻击者可以在这两次操作之间替换文件或 symlink。临时文件、由定时器触发的脚本、归档解压和备份流程中也会出现同样的问题。声称存在影响前，先确认实际的读写操作和目标权限。

归档**创建**也可能导致不同身份之间的信息泄露。Info-ZIP `zip -r` 通常会跟随源目录树中的 symlink，并将目标内容存入归档；`-y`/`--symlinks` 则会存储链接本身。如果低权限用户可以在备份目录中添加链接，应检查实际的归档程序及选项、备份任务的读取身份，以及该用户能否读取生成的归档。源目录可写或存在 symlink 本身并不能证明发生了信息泄露。枚举时应检查链接和归档元数据，不要触发备份，也不要解压秘密内容。参见 [Info-ZIP option documentation](https://sources.debian.org/src/zip/3.0-3/man/zip.1/#L1638)。

GNU `tar` 的默认行为不同：通常会将 symlink 作为链接存储，而 [`-h` / `--dereference` 会在创建归档时跟随链接](https://www.gnu.org/software/tar/manual/html_node/dereference.html)。对于特权定时备份，应检查实际的 `tar` 调用、低权限用户能否在 `tar` 读取输入路径前替换该路径，以及该用户能否访问生成的归档。若临时校验和文件或其他 sidecar 位于可写暂存目录中，且之后的 `tar -h` 命令明确将其列为输入，它就可能成为此类输入。必须核实竞争窗口、任务身份、symlink 策略、目标在该身份下是否可读，以及归档 ACL。被动检查时，不要替换文件、运行任务或解包敏感归档。

当特权任务读取低权限用户可以替换的归档时，归档**解压**会跨越另一道边界。[GNU tar 以超级用户身份运行时通常会恢复归档中记录的所有权](https://www.gnu.org/software/tar/manual/html_node/Option-Summary.html)，而其[权限恢复选项](https://www.gnu.org/software/tar/manual/html_node/Setting-Access-Permissions.html)会影响解压后文件的 mode 位。检查实际的解压程序及标志、归档可被替换的时间窗口、数字形式的所有者和 mode 元数据、解压目录权限，以及清理操作是否会使结果仍可访问。只有当解压后 SUID 文件的 mode 得以保留，且目标挂载点和进程策略允许身份变更时，root 所有的 SUID 文件才构成风险；不可信归档或可写暂存路径本身并不能证明存在此问题。被动枚举时，只检查任务和元数据，不要替换或解压归档。

解压出的 symlink 也可能在后续特权比较过程中泄露受保护文件。[GNU `diff` 比较目录时通常会跟随 symlink](https://www.gnu.org/software/diffutils/manual/html_node/Special-Files.html)，因此，以 root 身份对不可信的解压目录树运行 `diff -r`，可能会读取链接目标，并将不同内容包含在输出中。确认归档能否被替换、链接是否指向比较操作实际遍历的路径、目标对任务是否可读，以及低权限用户能否读取比较输出或错误日志。链接或归档本身并不能证明发生了信息泄露；枚举时应检查任务、路径元数据和日志权限，不要运行比较操作或读取受保护内容。

重复的主机端传输可能使不可信归档成员变成后续的输出路径。如果高权限任务从低信任容器复制归档，解压一个名称与下一次传输目标 basename 相同的 symlink，之后又写入同一路径名，那么后续写入可能会到达该链接目标。检查归档成员名称和目标、解压标志及目录、解压程序是否确实保留了该链接、传输实现如何处理已存在的目标链接，以及主机任务的有效写入身份。[GNU tar 说明了解压时如何处理已存在的文件和 symlink](https://www.gnu.org/software/tar/manual/html_section/extract-options.html)；[现代版本的 OpenSSH scp 默认使用 SFTP](https://man.openbsd.org/scp.1)，因此应核实已安装版本的传输行为，而不要假设所有 `scp` 版本都会跟随链接写入。容器中可见的 `scp` 进程或可写归档本身，不能证明主机执行了解压并进行了后续写入。枚举时只检查任务和路径元数据，不要传输或解压特制归档。

Ansible 的 [`synchronize` module](https://docs.ansible.com/projects/ansible/latest/collections/ansible/posix/synchronize_module.html) 封装了 rsync；`copy_links: true` 会复制 symlink 的目标，而不是链接本身。对于定时备份，应检查低权限用户能否在确切的源目录树中创建链接、同步身份能否读取其目标，以及该用户能否读取生成的副本或归档。playbook、链接位置、run-as 身份和输出权限必须全部吻合；可写上传目录或 `copy_links` 设置本身只能作为进一步审查的线索。检查元数据和 playbook，不要创建链接或触发任务。

## 检查打开的文件描述符

```bash
ls -l /proc/<PID>/fd 2>/dev/null
lsof -p <PID> 2>/dev/null
lsof +L1 2>/dev/null
```

进程在文件被删除或重命名后，仍可能保留对该文件的访问权限。特权进程也可能通过 Unix socket 传递文件描述符，或者因缺少 close-on-exec 设置，在 `execve()` 后意外保持描述符打开。检查 `/proc/<PID>/fd` 的目标，留意敏感文件、已删除文件、容器内可见的主机路径，以及意外出现的 socket。解引用其他进程的描述符受内核访问检查限制；能看到符号链接并不意味着能读取其内容。

自定义的 SUID helper 可能会打开受保护的路径名、放弃其有效 UID，却让描述符保持打开。如果随后它将自身设为可转储状态，`/proc/<PID>/fd` 的所有权和访问权限可能发生变化；应审查具体的凭据转换、[`PR_SET_DUMPABLE`](https://man7.org/linux/man-pages/man2/PR_SET_DUMPABLE.2const.html)、procfs/ptrace 策略，以及目标文件的权限。重新打开描述符路径可能绕过无法访问的**父目录**，但如果调用者无权读取文件，仍会失败。仅凭可见的描述符目标或 SUID 位，不能证明存在信息泄露。

崩溃产物是另一条线索：core dump 可能包含进程内存，包括此前以更高权限读取的数据。在 Ubuntu 上，[Apport 通常会将报告放在 `/var/crash`](https://documentation.ubuntu.com/project/contributors/debugging/apport/)；其他系统可能使用不同的 `core_pattern` handler 或 systemd 存储。例行枚举时，只检查报告路径、所有者、权限和可读性。只有在相关进程处于可转储状态、崩溃处理程序保留了敏感字节，且当前用户能够访问该报告时，可读报告才有意义。不要在被动枚举过程中让 helper 崩溃，也不要解包 dump。有关 SUID 和 dump 生成条件，请参阅 [`core(5)`](https://man7.org/linux/man-pages/man5/core.5.html)。

如果服务使用继承而来的描述符，应先检查其启动链和描述符编号，再尝试 shell 重定向或 `/proc/self/fd/<N>`。如果文件已删除但仍处于打开状态，[deleted-file recovery](filesystem-inodes-and-recovery.md#deleted-file-recovery-through-open-fds) 可能保留证据或恢复内容。进程级排查请继续阅读 [process enumeration and service paths](../processes-crontab-systemd-dbus/process-enumeration-and-service-paths.md)。
{{#include ../../banners/hacktricks-training.md}}
