# Container Protections Overview

{{#include ../../../../banners/hacktricks-training.md}}

コンテナの hardening における最も重要な考え方は、「container security」という単一の control が存在するわけではないということです。人々が container isolation と呼ぶものは、実際には複数の Linux の security および resource-management mechanisms が連携して動作した結果です。ドキュメントがそのうちの1つだけを説明すると、読者はその強度を過大評価しがちです。すべてを列挙しても、それらがどのように相互作用するかを説明しなければ、読者は名前の一覧を得るだけで、実際のモデルを理解できません。このセクションでは、これら両方の誤りを避けることを目指します。

このモデルの中心にあるのは **namespaces** です。namespaces は workload から見えるものを isolate します。これにより、process は filesystem mounts、PIDs、networking、IPC objects、hostnames、user/group mappings、cgroup paths、および一部の clocks について、private または部分的に private な view を持てます。しかし、namespaces だけで process に許可される操作が決まるわけではありません。そこで次の layers が登場します。

**cgroups** は resource usage を管理します。mount または PID namespaces と同じ意味での isolation boundary が主な目的ではありませんが、memory、CPU、PIDs、I/O、および device access を制限するため、運用上極めて重要です。また、過去の breakout techniques が writable な cgroup features、特に cgroup v1 environments を悪用したため、security relevance もあります。

**Capabilities** は、従来のすべての権限を持つ root model を、より小さな privilege units に分割します。これは、多くの workloads が依然として container 内で UID 0 として実行されるため、containers にとって fundamental です。したがって問題は、単に「process は root か」ではなく、「どの capabilities が、どの namespaces 内で、どの seccomp および MAC restrictions のもとで残っているか」です。そのため、ある container 内の root process は比較的制限されている一方で、別の container 内の root process は実際には host root とほとんど区別できない場合があります。

**seccomp** は syscalls を filter し、workload に公開される kernel attack surface を縮小します。これは、`unshare`、`mount`、`keyctl`、その他 breakout chains で使用される syscalls など、明らかに危険な calls を block する mechanism であることが多いです。process が、通常であれば operation を許可する capability を持っていたとしても、kernel が完全に処理する前に seccomp が syscall path を block する可能性があります。

**AppArmor** と **SELinux** は、通常の filesystem および privilege checks の上に Mandatory Access Control を追加します。これらは、container が本来持つべき以上の capabilities を持っている場合でも引き続き有効であるため、特に重要です。workload は action を試みるための theoretical privilege を持っていても、その label または profile が該当する path、object、operation への access を禁止しているため、実行を阻止されることがあります。

最後に、あまり注目されないものの、実際の attacks で定期的に重要となる追加の hardening layers があります。`no_new_privs`、masked procfs paths、read-only system paths、read-only root filesystems、そして慎重に設定された runtime defaults です。これらの mechanisms は、特に attacker が code execution をより広範な privilege gain に変えようとする場合に、compromise の「last mile」を阻止することがよくあります。

この folder の残りでは、これら各 mechanisms についてさらに詳しく説明します。そこでは、kernel primitive が実際に行うこと、local でそれを observe する方法、一般的な runtimes がそれをどのように使用するか、そして operators が誤ってそれを弱める方法を扱います。

## 次に読む

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

実際の多くの escapes は、どの host content が workload に mount されたかにも依存します。そのため、core protections を読んだ後は、次の内容に進むと役立ちます。

{{#ref}}
../sensitive-host-mounts.md
{{#endref}}
{{#include ../../../../banners/hacktricks-training.md}}
