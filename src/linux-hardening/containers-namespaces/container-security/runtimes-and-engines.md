# Container Runtimes, Engines, Builders, And Sandboxes

Jedan od najvećih izvora zabune u container security oblasti jeste to što se nekoliko potpuno različitih komponenti često svodi na istu reč. „Docker“ može označavati format image-a, CLI, daemon, build sistem, runtime stack ili jednostavno opštu ideju container-a. U security radu, ta dvosmislenost predstavlja problem, jer su različiti slojevi odgovorni za različite zaštite. Breakout izazvan lošim bind mount-om nije isto što i breakout izazvan ranjivošću low-level runtime-a, a nijedno od toga nije isto što i greška u cluster policy-ju u Kubernetes-u.

Ova stranica razdvaja ekosistem prema ulozi, tako da ostatak sekcije može precizno da govori o tome gde se određena zaštita ili slabost zapravo nalazi.

## OCI As The Common Language

Moderni Linux container stack-ovi često međusobno rade zato što koriste skup OCI specifikacija. **OCI Image Specification** opisuje kako se image-i i layer-i predstavljaju. **OCI Runtime Specification** opisuje kako runtime treba da pokrene proces, uključujući namespace-ove, mount-ove, cgroup-ove i security podešavanja. **OCI Distribution Specification** standardizuje način na koji registry-ji izlažu sadržaj.

Ovo je važno jer objašnjava zašto image napravljen jednim tool-om često može da se pokrene drugim i zašto više engine-a može da deli isti low-level runtime. Takođe objašnjava zašto security ponašanje može izgledati slično u različitim proizvodima: mnogi od njih konstruišu istu OCI runtime konfiguraciju i prosleđuju je istom malom skupu runtime-a.

## Low-Level OCI Runtimes

Low-level runtime je komponenta koja se nalazi najbliže granici kernel-a. To je deo koji zaista kreira namespace-ove, upisuje cgroup podešavanja, primenjuje capability-je i seccomp filter-e i na kraju poziva `execve()` za container proces. Kada ljudi govore o „container isolation“ na mehaničkom nivou, obično misle upravo na ovaj sloj, čak i kada to ne kažu izričito.

### `runc`

`runc` je referentni OCI runtime i i dalje najpoznatija implementacija. Intenzivno se koristi ispod Docker-a, containerd-a i mnogih Kubernetes deployment-a. Veliki deo javnih istraživanja i exploitation materijala cilja `runc`-style okruženja jednostavno zato što su česta i zato što `runc` definiše osnovu koju mnogi imaju na umu kada zamišljaju Linux container. Razumevanje `runc`-a zato čitaocu pruža dobar mentalni model za klasičnu container isolation.

### `crun`

`crun` je još jedan OCI runtime, napisan u C-u i široko korišćen u modernim Podman okruženjima. Često se ističe zbog dobre cgroup v2 podrške, kvalitetne rootless ergonomije i manjeg overhead-a. Iz security perspektive, važno nije to što je napisan na drugom jeziku, već to što i dalje ima istu ulogu: to je komponenta koja OCI konfiguraciju pretvara u aktivno stablo procesa pod kernel-om. Rootless Podman workflow često deluje bezbednije ne zato što `crun` magično rešava sve probleme, već zato što je širi stack oko njega obično više usmeren na user namespace-ove i least privilege.

### `runsc` From gVisor

`runsc` je runtime koji koristi gVisor. Ovde se granica značajno menja. Umesto da većinu syscall-ova prosleđuje direktno host kernel-u na uobičajen način, gVisor ubacuje userspace kernel sloj koji emulira ili posreduje u velikom delu Linux interfejsa. Rezultat nije običan `runc` container sa nekoliko dodatnih flag-ova; to je drugačiji sandbox dizajn čija je svrha smanjenje attack surface-a host kernel-a. Kompatibilnost i performance tradeoff-i deo su tog dizajna, pa okruženja koja koriste `runsc` treba dokumentovati drugačije od normalnih OCI runtime okruženja.

### `kata-runtime`

Kata Containers pomeraju granicu još dalje tako što workload pokreću unutar lightweight virtual machine-a. Administrativno, ovo i dalje može izgledati kao container deployment, a orchestration layer-i ga mogu i dalje tretirati na isti način, ali je osnovna isolation granica bliža virtualization-u nego klasičnom container-u koji deli host kernel. Zbog toga je Kata koristan kada je potrebna jača tenant isolation bez napuštanja container-centric workflow-a.

## Engines And Container Managers

Ako je low-level runtime komponenta koja direktno komunicira sa kernel-om, engine ili manager je komponenta sa kojom korisnici i operatori obično rade. On upravlja image pull-ovima, metadata podacima, logovima, network-ovima, volume-ima, lifecycle operacijama i izlaganjem API-ja. Ovaj sloj je izuzetno važan jer se mnogi kompromisi iz stvarnog sveta dešavaju upravo ovde: pristup runtime socket-u ili daemon API-ju može biti ekvivalentan kompromitovanju host-a čak i kada je sam low-level runtime potpuno ispravan.

### Docker Engine

Docker Engine je najprepoznatljivija container platforma za developere i jedan od razloga zbog kojih je container terminologija postala toliko oblikovana prema Docker-u. Tipičan put je `docker` CLI do `dockerd`-a, koji zatim koordinira niže komponente kao što su `containerd` i OCI runtime. Istorijski gledano, Docker deployment-i su često bili **rootful**, pa je pristup Docker socket-u zbog toga predstavljao veoma moćan primitive. Zato se veliki deo praktičnog privilege-escalation materijala fokusira na `docker.sock`: ako proces može da zatraži od `dockerd`-a da kreira privileged container, mount-uje host path-ove ili se pridruži host namespace-ovima, možda mu uopšte neće biti potreban kernel exploit.

### Podman

Podman je projektovan oko više daemonless modela. Operativno, ovo pomaže u jačanju ideje da su container-i samo procesi kojima se upravlja kroz standardne Linux mehanizme, a ne kroz jedan dugotrajni privileged daemon. Podman takođe ima mnogo snažniju **rootless** priču od klasičnih Docker deployment-a sa kojima se većina ljudi prvo susrela. To ne znači da je Podman automatski bezbedan, ali značajno menja podrazumevani risk profile, naročito u kombinaciji sa user namespace-ovima, SELinux-om i `crun`-om.

### containerd

containerd je osnovna runtime management komponenta u mnogim modernim stack-ovima. Koristi se ispod Docker-a i jedan je od dominantnih Kubernetes runtime backend-ova. Izlaže moćne API-je, upravlja image-ima i snapshot-ovima i delegira konačno kreiranje procesa low-level runtime-u. Security diskusije o containerd-u treba da naglase da pristup containerd socket-u ili `ctr`/`nerdctl` funkcionalnosti može biti podjednako opasan kao pristup Docker API-ju, čak i kada interfejs i workflow deluju manje „developer friendly“.

### CRI-O

CRI-O je uži od Docker Engine-a. Umesto da bude developer platforma opšte namene, napravljen je tako da čisto implementira Kubernetes Container Runtime Interface. Zbog toga je naročito čest u Kubernetes distribucijama i SELinux-heavy ekosistemima kao što je OpenShift. Iz security perspektive, taj uži scope je koristan jer smanjuje konceptualni nered: CRI-O je veoma jasno deo sloja „run containers for Kubernetes“, a ne platforma za sve.

### Incus, LXD, And LXC

Incus/LXD/LXC sistemi zaslužuju da budu odvojeni od Docker-style application container-a zato što se često koriste kao **system containers**. Od system container-a se obično očekuje da više liči na lightweight machine sa potpunijim userspace-om, dugotrajnim servisima, bogatijim device exposure-om i širom integracijom sa host-om. Isolation mehanizmi su i dalje kernel primitive, ali su operativna očekivanja drugačija. Zbog toga misconfiguration-i ovde često manje liče na „bad app-container defaults“, a više na greške u lightweight virtualization-u ili host delegation-u.

### systemd-nspawn

systemd-nspawn zauzima zanimljivo mesto zato što je systemd-native i veoma koristan za testing, debugging i pokretanje OS-like okruženja. Nije dominantni cloud-native production runtime, ali se dovoljno često pojavljuje u labovima i distro-oriented okruženjima da zaslužuje pomen. Za security analysis, on je još jedan podsetnik da pojam „container“ obuhvata više ekosistema i operativnih stilova.

### Apptainer / Singularity

Apptainer (ranije Singularity) je čest u research i HPC okruženjima. Njegove trust assumptions, user workflow i execution model bitno se razlikuju od Docker/Kubernetes-centric stack-ova. Ova okruženja naročito vode računa o tome da korisnicima omoguće pokretanje packaged workload-a bez davanja širokih privileged container-management ovlašćenja. Ako reviewer pretpostavi da je svako container okruženje praktično „Docker on a server“, ozbiljno će pogrešno razumeti ove deployment-e.

## Build-Time Tooling

Mnoge security diskusije govore samo o runtime-u, ali build-time tooling je takođe važan jer određuje sadržaj image-a, izloženost build secrets-a i količinu trusted context-a koji se ugrađuje u finalni artifact.

**BuildKit** i `docker buildx` su moderni build backend-ovi koji podržavaju funkcije kao što su caching, secret mounting, SSH forwarding i multi-platform builds. To su korisne funkcije, ali iz security perspektive takođe stvaraju mesta na kojima secrets mogu da leak-uju u image layer-e ili gde preširok build context može da izloži fajlove koji nikada nisu smeli biti uključeni. **Buildah** ima sličnu ulogu u OCI-native ekosistemima, naročito oko Podman-a, dok se **Kaniko** često koristi u CI okruženjima koja ne žele da build pipeline-u dodele privileged Docker daemon.

Ključna lekcija je da su kreiranje image-a i izvršavanje image-a različite faze, ali slab build pipeline može da stvori slab runtime posture mnogo pre nego što se container pokrene.

## Orchestration Is Another Layer, Not The Runtime

Kubernetes ne treba mentalno poistovećivati sa samim runtime-om. Kubernetes je orchestrator. On schedule-uje Pod-ove, čuva desired state i izražava security policy kroz workload konfiguraciju. Kubelet zatim komunicira sa CRI implementacijom kao što su containerd ili CRI-O, koja potom poziva low-level runtime kao što su `runc`, `crun`, `runsc` ili `kata-runtime`.

Ovo razdvajanje je važno zato što mnogi pogrešno pripisuju neku zaštitu „Kubernetes-u“, iako je ona zapravo enforced od strane node runtime-a, ili krive „containerd defaults“ za ponašanje koje potiče iz Pod spec-a. U praksi, finalni security posture je kompozicija: orchestrator nešto zahteva, runtime stack to prevodi, a kernel na kraju to enforce-uje.

## Why Runtime Identification Matters During Assessment

Ako rano identifikujete engine i runtime, mnoge kasnije observacije postaju lakše za tumačenje. Rootless Podman container sugeriše da su user namespace-ovi verovatno deo priče. Docker socket mount-ovan u workload sugeriše da je API-driven privilege escalation realan put. CRI-O/OpenShift node bi odmah trebalo da vas navede na razmišljanje o SELinux label-ovima i restricted workload policy-ju. gVisor ili Kata okruženje trebalo bi da vas učini opreznijim pri pretpostavci da će se klasičan `runc` breakout PoC ponašati na isti način.

Zato jedan od prvih koraka u container assessment-u uvek treba da bude odgovor na dva jednostavna pitanja: **koja komponenta upravlja container-om** i **koji runtime je zaista pokrenuo proces**. Kada su ti odgovori jasni, ostatak okruženja obično postaje mnogo lakši za razumevanje.

## Runtime Vulnerabilities

Ne potiče svaki container escape od operator misconfiguration-a. Ponekad je sam runtime ranjiva komponenta. Ovo je važno zato što workload može da radi sa konfiguracijom koja deluje pažljivo podešeno, a da i dalje bude izložen low-level runtime flaw-u.

Klasičan primer je **CVE-2019-5736** u `runc`-u, gde je malicious container mogao da overwrite-uje host `runc` binary i zatim sačeka da kasniji `docker exec` ili slična runtime invocation pokrene attacker-controlled code. Exploit path se veoma razlikuje od jednostavne bind-mount ili capability greške zato što zloupotrebljava način na koji runtime ponovo ulazi u prostor container procesa tokom exec handling-a.<sup>[[1]](#references)</sup>

Minimalni reproduction workflow iz red-team perspektive je:
```bash
go build main.go
./main
```
Zatim, sa hosta:
```bash
docker exec -it <container-name> /bin/sh
```
Ključna pouka nije tačna istorijska implementacija exploita, već implikacija za procenu: ako je verzija runtime-a ranjiva, uobičajeno izvršavanje koda unutar containera može biti dovoljno za kompromitovanje hosta, čak i kada vidljiva konfiguracija containera ne deluje očigledno slabo.

Nedavni runtime CVE-ovi, kao što su `CVE-2024-21626` u `runc`-u, race condition-i pri mountovanju u BuildKit-u i greške pri parsiranju u containerd-u, potvrđuju istu činjenicu. Verzija runtime-a i nivo zakrpa deo su bezbednosne granice, a ne samo nevažni detalji održavanja.

## References

- [1] [Izlazak iz Docker-a preko runC-a – objašnjenje CVE-2019-5736](https://unit42.paloaltonetworks.com/breaking-docker-via-runc-explaining-cve-2019-5736/)
{{#include ../../../banners/hacktricks-training.md}}
