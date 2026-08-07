# Container Protections Overview

{{#include ../../../../banners/hacktricks-training.md}}

Container hardening における最も重要な考え方は、「container security」という単一の control は存在しないということです。人々が container isolation と呼ぶものは、実際には複数の Linux security および resource-management mechanisms が連携した結果です。ドキュメントがそのうち1つだけを説明すると、読者はその強度を過大評価しがちです。逆に、相互作用を説明せずにすべてを列挙すると、読者は名称の一覧を得るだけで、実際のモデルを理解できません。このセクションでは、その両方の誤りを避けることを目指します。

このモデルの中心にあるのは **namespaces** です。namespaces は workload から見えるものを分離します。これにより、process は filesystem mounts、PIDs、networking、IPC objects、hostnames、user/group mappings、cgroup paths、および一部の clocks について、private または部分的に private な view を持てます。しかし、namespaces だけで process に許可される操作が決まるわけではありません。そこで次の layers が登場します。

**cgroups** は resource usage を管理します。mount または PID namespaces と同じ意味での isolation boundary が主目的ではありませんが、memory、CPU、PIDs、I/O、device access を制限するため、運用上きわめて重要です。また、歴史的な breakout techniques が writable な cgroup features、特に cgroup v1 environments を悪用したため、security 上の意味もあります。

**Capabilities** は、従来のすべての権限を持つ root model を、より小さな privilege units に分割します。多くの workloads は container 内で UID 0 として実行され続けるため、これは containers にとって基本的な仕組みです。したがって問題は単に「process は root か」ではなく、「どの capabilities が、どの namespaces 内で、どの seccomp および MAC restrictions の下で残っているか」です。そのため、ある container の root process は比較的制限されている一方で、別の container の root process は実際には host root とほとんど区別できない場合があります。

**seccomp** は syscalls を filter し、workload に公開される kernel attack surface を縮小します。これは、`unshare`、`mount`、`keyctl` など、breakout chains で使用される明らかに危険な calls を block する mechanism であることが多いです。process が本来なら operation を許可する capability を持っていたとしても、kernel がその syscall を完全に処理する前に、seccomp が syscall path を block する場合があります。

**AppArmor** と **SELinux** は、通常の filesystem および privilege checks の上に Mandatory Access Control を追加します。container が持つべき以上の capabilities を持っている場合でも有効であり続けるため、これらは特に重要です。workload は action を試みる理論上の privilege を持っていても、その label または profile が関連する path、object、operation への access を禁止しているため、実行を阻止されることがあります。

最後に、あまり注目されないものの、実際の attacks で定期的に重要となる追加の hardening layers があります。`no_new_privs`、masked procfs paths、read-only system paths、read-only root filesystems、および慎重に設定された runtime defaults です。これらの mechanisms は、特に attacker が code execution をより広範な privilege gain に変えようとする場合に、compromise の「last mile」を阻止することがよくあります。

この folder の残りでは、これらの mechanisms をそれぞれ詳しく説明します。そこでは、kernel primitive が実際に何を行うのか、local でどのように observe するのか、一般的な runtimes がどのように使用するのか、そして operators がどのように意図せず弱体化させるのかを扱います。

## Read Next

{{#ref}}
namespaces/
{{#endref}}

{{#ref}}
cgroups.md
{{#endref}}

{{#ref}}
capabilities.md
{{#endref}}

{{#ref}}
seccomp.md
{{#endref}}

{{#ref}}
apparmor.md
{{#endref}}

{{#ref}}
selinux.md
{{#endref}}

{{#ref}}
no-new-privileges.md
{{#endref}}

{{#ref}}
masked-paths.md
{{#endref}}

{{#ref}}
read-only-paths.md
{{#endref}}

多くの実際の escapes は、workload に何の host content が mounted されているかにも依存します。そのため、core protections を読んだ後は、次の内容に進むと有用です。

{{#ref}}
../sensitive-host-mounts.md
{{#endref}}

{{#include ../../../../banners/hacktricks-training.md}}
