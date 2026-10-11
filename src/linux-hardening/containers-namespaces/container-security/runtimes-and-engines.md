# Container Runtimes, Engines, Builders, And Sandboxes

{{#include ../../../banners/hacktricks-training.md}}

Jedan od najvećih izvora zabune u bezbednosti kontejnera jeste to što se nekoliko potpuno različitih komponenti često svodi na isti naziv. „Docker“ može da se odnosi na format image-a, CLI, daemon, sistem za buildovanje, runtime stack ili jednostavno na opšti pojam kontejnera. U bezbednosnom radu ta dvosmislenost predstavlja problem, jer su različiti slojevi odgovorni za različite zaštite. Breakout izazvan pogrešno podešenim bind mount-om nije isto što i breakout izazvan greškom u low-level runtime-u, a nijedno od toga nije isto što i greška u Kubernetes cluster policy-ju.

Ova stranica razdvaja ekosistem prema ulozi, kako bi ostatak odeljka mogao precizno da govori o tome gde se određena zaštita ili slabost zapravo nalazi.

## OCI As The Common Language

Moderni Linux container stack-ovi često mogu međusobno da sarađuju zato što koriste skup OCI specifikacija. **OCI Image Specification** opisuje kako su image-i i slojevi predstavljeni. **OCI Runtime Specification** opisuje kako runtime treba da pokrene proces, uključujući namespaces, mount-ove, cgroups i bezbednosna podešavanja. **OCI Distribution Specification** standardizuje način na koji registries izlažu sadržaj.

Ovo je važno jer objašnjava zašto image napravljen jednim alatom često može da se pokrene drugim i zašto nekoliko engine-a može da koristi isti low-level runtime. Takođe objašnjava zašto bezbednosno ponašanje može da deluje slično u različitim proizvodima: mnogi od njih prave istu OCI runtime konfiguraciju i prosleđuju je istom malom broju runtime-ova.

## Low-Level OCI Runtimes

Low-level runtime je komponenta najbliža granici kernel-a. To je deo koji zaista kreira namespaces, podešava cgroups, primenjuje capabilities i seccomp filtere i na kraju poziva `execve()` za pokretanje procesa u kontejneru. Kada se govori o „izolaciji kontejnera“ na mehaničkom nivou, obično se misli na ovaj sloj, čak i ako se to ne kaže izričito.

### `runc`

`runc` je referentni OCI runtime i ostaje najpoznatija implementacija. Široko se koristi ispod Docker-a, containerd-a i mnogih Kubernetes deployment-a. Veliki deo javno dostupnih istraživanja i materijala o eksploataciji usmeren je na okruženja tipa `runc`, jednostavno zato što su česta i zato što `runc` definiše osnovu koju mnogi zamišljaju kada pomisle na Linux kontejner. Zato razumevanje `runc`-a daje čitaocu dobar mentalni model klasične izolacije kontejnera.

### `crun`

`crun` je još jedan OCI runtime, napisan u C-u i široko korišćen u modernim Podman okruženjima. Često se hvali zbog dobre podrške za cgroup v2, lakšeg korišćenja u rootless okruženjima i manjeg overheada. Sa bezbednosne tačke gledišta, važno nije to što je napisan drugim jezikom, već to što ima istu ulogu: pretvara OCI konfiguraciju u pokrenuto stablo procesa pod kernel-om. Rootless Podman workflow često deluje bezbednije ne zato što `crun` magično rešava sve, već zato što se širi stack oko njega obično više oslanja na user namespaces i princip najmanjih privilegija.

### `runsc` From gVisor

`runsc` je runtime koji koristi gVisor. Ovde se granica značajno menja. Umesto da većinu syscall-ova prosleđuje direktno host kernel-u na uobičajen način, gVisor uvodi userspace kernel sloj koji emulira ili posreduje u velikom delu Linux interfejsa. Rezultat nije običan `runc` kontejner sa nekoliko dodatnih flag-ova; to je drugačiji sandbox dizajn čija je svrha da smanji površinu za napad host kernel-a. Kompromisi u kompatibilnosti i performansama deo su tog dizajna, pa okruženja koja koriste `runsc` treba dokumentovati drugačije od okruženja sa uobičajenim OCI runtime-om.

### `kata-runtime`

Kata Containers idu korak dalje tako što pokreću workload unutar lake virtuelne mašine. Administrativno, ovo i dalje može da izgleda kao deployment kontejnera, a orchestration slojevi ga i dalje mogu tretirati kao takav, ali je osnovna granica izolacije bliža virtuelizaciji nego klasičnom kontejneru koji deli host kernel. Zbog toga je Kata koristan kada se želi snažnija izolacija između tenant-a, a da se pritom ne napuste workflow-i zasnovani na kontejnerima.

## Engines And Container Managers

Ako je low-level runtime komponenta koja direktno komunicira sa kernel-om, engine ili manager je komponenta sa kojom korisnici i operateri obično rade. On upravlja preuzimanjem image-a, metapodacima, logovima, mrežama, volume-ima, operacijama životnog ciklusa i izlaganjem API-ja. Ovaj sloj je izuzetno važan jer se mnogi kompromisi u praksi događaju upravo ovde: pristup runtime socket-u ili daemon API-ju može da bude ekvivalentan kompromitovanju host-a, čak i ako je sam low-level runtime potpuno ispravan.

### Docker Engine

Docker Engine je najprepoznatljivija platforma za kontejnere među developer-ima i jedan od razloga zašto je terminologija vezana za kontejnere poprimila oblik vezan za Docker. Uobičajeni tok ide od `docker` CLI-ja do `dockerd`-a, koji zatim koordinira niže komponente kao što su `containerd` i OCI runtime. Istorijski gledano, Docker deployment-i su često bili **rootful**, pa je pristup Docker socket-u bio veoma moćan primitive. Zato se veliki deo praktičnog materijala o eskalaciji privilegija fokusira na `docker.sock`: ako proces može da zatraži od `dockerd`-a da kreira privileged kontejner, mount-uje host putanje ili se pridruži host namespace-ovima, možda mu uopšte nije potreban kernel exploit.

Upoređujte brojeve izdanja po major, minor i patch komponentama, umesto da uklanjate tačke: `18.09.1` je stariji i od `18.09.2` i od `18.09.4`, uprkos minor komponenti sa nulom na početku. Docker-ove [beleške o izdanju 18.09](https://docs.docker.com/engine/release-notes/18.09/) navode uključenu `runc` ispravku za CVE-2019-5736 u verziji 18.09.2 i ispravku build-reference problema za CVE-2019-13139 u verziji 18.09.4. Ovo su tragovi za proveru verzije, a ne dokaz da je exploit dostupan. Iste beleške upozoravaju da se daemon, client i runtime pakuju zasebno, pa uz verziju daemon-a proverite i instalirani runtime i ispravke koje je dodao distributer; build-reference problem takođe zahteva pristup pogođenom build workflow-u i ulazne podatke koje kontroliše napadač.

### Podman

Podman je osmišljen prema modelu koji ne zahteva daemon. Operativno, to pomaže da se učvrsti ideja da su kontejneri samo procesi kojima se upravlja standardnim Linux mehanizmima, a ne preko jednog dugovečnog privileged daemon-a. Podman takođe ima znatno bolju podršku za **rootless** rad od klasičnih Docker deployment-a koje su mnogi prvo upoznali. To ne znači da je Podman automatski bezbedan, ali značajno menja podrazumevani profil rizika, posebno u kombinaciji sa user namespace-ovima, SELinux-om i `crun`-om.

### containerd

containerd je osnovna komponenta za upravljanje runtime-om u mnogim modernim stack-ovima. Koristi se ispod Docker-a i jedan je od dominantnih Kubernetes runtime backend-ova. Izlaže moćne API-je, upravlja image-ima i snapshot-ovima i prepušta konačno kreiranje procesa low-level runtime-u. U bezbednosnim diskusijama o containerd-u treba naglasiti da pristup containerd socket-u ili funkcionalnosti `ctr`/`nerdctl` može biti jednako opasan kao pristup Docker API-ju, čak i ako interfejs i workflow deluju manje „prilagođeni developer-ima“.

### CRI-O

CRI-O ima uži fokus od Docker Engine-a. Umesto da bude razvojna platforma opšte namene, napravljen je tako da jasno implementira Kubernetes Container Runtime Interface. Zbog toga je naročito čest u Kubernetes distribucijama i ekosistemima koji se intenzivno oslanjaju na SELinux, kao što je OpenShift. Sa bezbednosne tačke gledišta, taj uži opseg je koristan jer smanjuje konceptualnu zbrku: CRI-O je jasno deo sloja „pokretanja kontejnera za Kubernetes“, a ne univerzalna platforma.

Kada Kubernetes node koristi CRI-O, proverite **aktivno CRI-O izdanje na node-u**, kao i da li trenutni identitet može da kreira Pods u namespace-u koji se raspoređuje na tom node-u. [CVE-2022-0811](https://github.com/cri-o/cri-o/security/advisories/GHSA-6x2m-w449-qwx7) omogućavao je da posebno napravljene Pod sysctl vrednosti promene parametar host kernel-a i omoguće izvršavanje kao host-root u pogođenim izdanjima. Upstream savetodavno obaveštenje navodi zakrpljena izdanja i zaobilazna rešenja. Lokalni `crio --version` može da propusti runtime ugnježden unutar Minikube-a ili drugog node kontejnera; čitljiv Minikube startup log može da pruži trag o verziji, ali to je istorijski dokaz, a ne potvrda aktivnog runtime-a ili njegovog stanja zakrpljenosti. Potvrdite stvarni node runtime, dozvole za kreiranje Pod-ova, admission pravila i relevantne seccomp i user namespace granice pre nego što ovo smatrate dostupnim putem za eskalaciju.

Postoji i direktan lokalni put za proveru `pinns`-a: [istraživači napominju da Kubernetes nije neophodan za pozivanje ranjivog pomoćnog programa](https://www.crowdstrike.com/en-us/blog/cr8escape-new-vulnerability-discovered-in-cri-o-container-engine-cve-2022-0811/). Proverite da li trenutni nalog može da izvrši `pinns` u vlasništvu root-a sa setuid bitom, da li NoNewPrivs ili `nosuid` mount blokira taj prelaz i da li instalirani **build pomoćnog programa** nema ispravku. [Upstream savetodavno obaveštenje](https://github.com/cri-o/cri-o/security/advisories/GHSA-6x2m-w449-qwx7) navodi zakrpljene verzije izdanja, ali verzija koju prikazuje daemon sama po sebi ne potvrđuje koji je pomoćni binary instaliran, a ispravke distributera mogu da promene izloženost. Setuid fajl je samo kandidat; proverite poreklo pomoćnog programa, konfiguraciju i ponašanje host sysctl-a, bez njegovog pokretanja tokom rutinskog prikupljanja podataka.

### Incus, LXD, And LXC

Incus/LXD/LXC sisteme vredi odvojiti od kontejnera za aplikacije tipa Docker, jer se često koriste kao **system containers**. Od system kontejnera se obično očekuje da više liče na lake mašine sa potpunijim userspace-om, dugotrajno pokrenutim servisima, širim izlaganjem uređaja i opsežnijom integracijom sa host-om. Mehanizmi izolacije i dalje su kernel primitive, ali su operativna očekivanja drugačija. Zbog toga pogrešne konfiguracije ovde često više liče na greške u lakoj virtuelizaciji ili delegiranju host resursa nego na „loše podrazumevane postavke kontejnera za aplikaciju“.

### systemd-nspawn

systemd-nspawn zauzima zanimljivo mesto zato što je nativan za systemd i veoma koristan za testiranje, otklanjanje grešaka i pokretanje okruženja nalik operativnom sistemu. Nije dominantan runtime za cloud-native produkciju, ali se dovoljno često pojavljuje u laboratorijskim i distribucijama orijentisanim okruženjima da zaslužuje pomen. Za bezbednosnu analizu, ovo je još jedan podsetnik da pojam „kontejner“ obuhvata više ekosistema i operativnih stilova.

### Apptainer / Singularity

Apptainer (ranije Singularity) čest je u istraživačkim i HPC okruženjima. Njegove pretpostavke o poverenju, korisnički workflow i model izvršavanja značajno se razlikuju od stack-ova usmerenih na Docker/Kubernetes. Ova okruženja naročito vode računa o tome da korisnicima omoguće pokretanje upakovanih workload-a bez davanja širokih privilegija za upravljanje kontejnerima. Ako recenzent pretpostavi da je svako okruženje sa kontejnerima u suštini „Docker na serveru“, ozbiljno će pogrešno razumeti ova deployment okruženja.

## Build-Time Tooling

Mnoge bezbednosne diskusije bave se samo izvršavanjem, ali važni su i alati za buildovanje jer određuju sadržaj image-a, izloženost build tajni i koliko se pouzdanog konteksta ugrađuje u konačni artefakt.

**BuildKit** i `docker buildx` su moderni build backend-ovi koji podržavaju funkcije kao što su caching, montiranje tajni, SSH prosleđivanje i multi-platform build-ovi. Te funkcije su korisne, ali sa bezbednosne tačke gledišta stvaraju i mesta na kojima tajne mogu da procure u image slojeve ili gde preširok build context može da izloži fajlove koji nikada nisu smeli da budu uključeni. **Buildah** ima sličnu ulogu u OCI-native ekosistemima, naročito uz Podman, dok se **Kaniko** često koristi u CI okruženjima koja ne žele da daju privileged Docker daemon build pipeline-u.

Ključna pouka je da su kreiranje image-a i njegovo izvršavanje različite faze, ali slab build pipeline može da stvori slab bezbednosni položaj u runtime-u mnogo pre nego što se kontejner pokrene.

## Orchestration Is Another Layer, Not The Runtime

Kubernetes ne treba poistovećivati sa samim runtime-om. Kubernetes je orchestrator. On raspoređuje Pods, čuva željeno stanje i izražava bezbednosnu policy kroz konfiguraciju workload-a. Kubelet zatim komunicira sa CRI implementacijom, kao što su containerd ili CRI-O, koja potom poziva low-level runtime, kao što su `runc`, `crun`, `runsc` ili `kata-runtime`.

Ova razlika je važna zato što mnogi pogrešno pripisuju neku zaštitu „Kubernetes-u“, iako je zapravo sprovodi node runtime, ili okrivljuju „podrazumevane postavke containerd-a“ za ponašanje koje potiče iz Pod spec-a. U praksi, konačni bezbednosni položaj predstavlja kombinaciju: orchestrator nešto zatraži, runtime stack to prevede, a kernel na kraju sprovodi.

## Why Runtime Identification Matters During Assessment

Ako rano identifikujete engine i runtime, kasnija zapažanja biće lakša za tumačenje. Rootless Podman kontejner ukazuje na to da su user namespace-ovi verovatno deo priče. Docker socket montiran u workload ukazuje na to da je eskalacija privilegija preko API-ja realan put. CRI-O/OpenShift node odmah treba da vas navede da razmišljate o SELinux oznakama i ograničenoj policy za workload-e. gVisor ili Kata okruženje trebalo bi da vas učini opreznijim pri pretpostavci da će se klasični `runc` breakout PoC ponašati na isti način.

Zato jedan od prvih koraka u proceni kontejnera uvek treba da bude odgovor na dva jednostavna pitanja: **koja komponenta upravlja kontejnerom** i **koji runtime ga je zaista pokrenuo**. Kada su odgovori jasni, obično je mnogo lakše razumeti ostatak okruženja.

## Runtime Vulnerabilities

Ne potiče svaki container escape iz pogrešne konfiguracije operatera. Ponekad je ranjiva komponenta sam runtime. Ovo je važno zato što workload može da koristi naizgled pažljivo podešenu konfiguraciju, a ipak bude izložen zbog greške u low-level runtime-u.

Klasičan primer je **CVE-2019-5736** u `runc`-u, gde je zlonameran kontejner mogao da prepiše host `runc` binary, a zatim sačeka da kasniji `docker exec` ili slično pozivanje runtime-a pokrene kod koji kontroliše napadač. Putanja eksploatacije znatno se razlikuje od jednostavne greške u bind mount-u ili capabilities podešavanju, jer zloupotrebljava način na koji runtime ponovo ulazi u prostor procesa kontejnera tokom obrade exec zahteva.<sup>[[1]](#references)</sup>

Minimalni workflow za reprodukciju iz red-team perspektive je:

```bash
go build main.go
./main
```

Zatim, sa hosta:

```bash
docker exec -it <container-name> /bin/sh
```

Ključna pouka nije tačna implementacija istorijskog exploita, već implikacija za procenu: ako je verzija runtime-a ranjiva, obično izvršavanje koda unutar containera može biti dovoljno da se kompromituje host, čak i kada vidljiva konfiguracija containera ne deluje očigledno slabo.

Nedavni runtime CVE-ovi, kao što su `CVE-2024-21626` u `runc`, utrke pri mountovanju u BuildKit-u i greške u parsiranju u containerd-u, potvrđuju isto. Verzija runtime-a i nivo zakrpa deo su bezbednosne granice, a ne samo nebitni detalji održavanja.

## References

- [1] [Izlazak iz Docker-a pomoću runC – objašnjenje CVE-2019-5736](https://unit42.paloaltonetworks.com/breaking-docker-via-runc-explaining-cve-2019-5736/)
{{#include ../../../banners/hacktricks-training.md}}
