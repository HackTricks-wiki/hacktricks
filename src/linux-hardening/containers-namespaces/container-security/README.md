# Bezbednost kontejnera

{{#include ../../../banners/hacktricks-training.md}}

## Šta Kontejner Zapravo Jeste

Praktičan način da se definiše kontejner jeste sledeći: kontejner je **regularno Linux stablo procesa** koje je pokrenuto pod posebnom konfiguracijom u OCI stilu, tako da vidi kontrolisani filesystem, kontrolisani skup kernel resursa i ograničeni model privilegija. Proces može verovati da je PID 1, može verovati da ima sopstveni network stack, može verovati da poseduje sopstveni hostname i IPC resurse, a može se čak izvršavati kao root unutar sopstvenog user namespace-a. Ali ispod svega toga on je i dalje host proces koji kernel raspoređuje kao i svaki drugi.

Zbog toga je bezbednost kontejnera zapravo proučavanje načina na koji se ta iluzija konstruiše i načina na koji ona otkazuje. Ako je mount namespace slab, proces može videti host filesystem. Ako user namespace ne postoji ili je onemogućen, root unutar kontejnera može biti previše direktno mapiran na root na hostu. Ako je seccomp unconfined, a skup capabilities preširok, proces može doći do syscall-ova i privilegovanih kernel funkcija koje su morale ostati nedostupne. Ako je runtime socket montiran unutar kontejnera, kontejneru možda uopšte nije potreban kernel breakout, jer može jednostavno zatražiti od runtime-a da pokrene moćniji susedni kontejner ili direktno montira host root filesystem.

## Kako Se Kontejneri Razlikuju Od Virtualnih Mašina

VM obično ima sopstveni kernel i granicu hardverske apstrakcije. To znači da guest kernel može da se sruši, izazove panic ili bude kompromitovan, a da to automatski ne podrazumeva direktnu kontrolu nad host kernelom. Kod kontejnera workload ne dobija zaseban kernel. Umesto toga, dobija pažljivo filtriran i namespaced prikaz istog kernela koji koristi host. Zbog toga su kontejneri obično lakši, brže se pokreću, jednostavnije ih je gusto rasporediti na mašini i pogodniji su za kratkotrajni deployment aplikacija. Cena toga je što granica izolacije mnogo direktnije zavisi od ispravne konfiguracije hosta i runtime-a.

To ne znači da su kontejneri "nebezbedni", a VM-ovi "bezbedni". To znači da je security model drugačiji. Dobro konfigurisan container stack sa rootless izvršavanjem, user namespace-ovima, podrazumevanim seccomp-om, strogim skupom capabilities, bez deljenja host namespace-ova i sa snažnim SELinux ili AppArmor enforcement-om može biti veoma robustan. Nasuprot tome, kontejner pokrenut sa `--privileged`, deljenjem host PID/network prostora, Docker socket-om montiranim unutar njega i writable bind mount-om `/` funkcionalno je mnogo bliži pristupu host root-u nego bezbedno izolovanom application sandbox-u. Razlika potiče od slojeva koji su uključeni ili onemogućeni.

Postoji i sredina koju bi čitaoci trebalo da razumeju, jer se sve češće pojavljuje u realnim okruženjima. **Sandboxed container runtimes** kao što su **gVisor** i **Kata Containers** namerno dodatno ojačavaju granicu u odnosu na klasični `runc` kontejner. gVisor postavlja userspace kernel layer između workload-a i mnogih host kernel interfejsa, dok Kata pokreće workload unutar lagane virtualne mašine. Oni se i dalje koriste kroz container ekosisteme i orchestration workflow-e, ali se njihove security karakteristike razlikuju od običnih OCI runtime-ova i ne bi ih trebalo mentalno svrstavati sa "normalnim Docker kontejnerima", kao da se sve ponaša isto.

## Container Stack: Više Slojeva, Ne Samo Jedan

Kada neko kaže "ovaj kontejner je nebezbedan", korisno dodatno pitanje glasi: **koji sloj ga je učinio nebezbednim?** Containerized workload je obično rezultat zajedničkog rada više komponenti.

Na vrhu se često nalazi **image build layer**, kao što su BuildKit, Buildah ili Kaniko, koji kreira OCI image i metadata podatke. Iznad low-level runtime-a može postojati **engine ili manager**, kao što su Docker Engine, Podman, containerd, CRI-O, Incus ili systemd-nspawn. U cluster okruženjima može postojati i **orchestrator**, kao što je Kubernetes, koji kroz workload konfiguraciju određuje zahtevani security posture. Konačno, **kernel** je ono što zaista enforcement-uje namespaces, cgroups, seccomp i MAC policy.

Ovaj layered model je važan za razumevanje podrazumevanih vrednosti. Ograničenje može biti zatraženo od strane Kubernetes-a, prevedeno kroz CRI pomoću containerd-a ili CRI-O-a, konvertovano u OCI spec pomoću runtime wrapper-a i tek tada enforcement-ovano od strane `runc`, `crun`, `runsc` ili drugog runtime-a nad kernelom. Kada se podrazumevane vrednosti razlikuju između okruženja, često je razlog to što je jedan od ovih slojeva promenio konačnu konfiguraciju. Isti mehanizam se zato može pojaviti u Docker-u ili Podman-u kao CLI flag, u Kubernetes-u kao Pod ili `securityContext` polje, a u low-level runtime stack-ovima kao OCI konfiguracija generisana za workload. Zbog toga CLI primere u ovom odeljku treba čitati kao **runtime-specific sintaksu za opšti container koncept**, a ne kao univerzalne flag-ove koje podržava svaki alat.

## Stvarna Granica Bezbednosti Kontejnera

U praksi, bezbednost kontejnera potiče od **preklapajućih kontrola**, a ne od jedne savršene kontrole. Namespaces ograničavaju vidljivost. cgroups upravljaju korišćenjem resursa i ograničavaju ga. Capabilities smanjuju ono što proces koji izgleda privilegovano zapravo može da uradi. seccomp blokira opasne syscall-ove pre nego što stignu do kernela. AppArmor i SELinux dodaju Mandatory Access Control preko uobičajenih DAC provera. `no_new_privs`, maskirani procfs path-ovi i system path-ovi samo za čitanje otežavaju uobičajene chain-ove zloupotrebe privilegija i proc/sys mehanizama. I sam runtime je važan, jer odlučuje kako se kreiraju mount-ovi, socket-i, label-e i namespace join-ovi.

Zbog toga veliki deo dokumentacije o bezbednosti kontejnera deluje repetitivno. Isti escape chain često zavisi od više mehanizama istovremeno. Na primer, writable host bind mount je loš, ali postaje mnogo gori ako se kontejner takođe izvršava kao stvarni root na hostu, ima `CAP_SYS_ADMIN`, nije ograničen seccomp-om i nije ograničen SELinux-om ili AppArmor-om. Slično tome, deljenje host PID prostora predstavlja ozbiljnu izloženost, ali postaje dramatično korisnije attacker-u kada se kombinuje sa `CAP_SYS_PTRACE`, slabim procfs zaštitama ili alatima za ulazak u namespace, kao što je `nsenter`. Zbog toga je ispravan način dokumentovanja ove teme da se ne ponavlja isti napad na svakoj stranici, već da se objasni šta svaki sloj doprinosi konačnoj granici.

## Kako Čitati Ovaj Odeljak

Odeljak je organizovan od najopštijih ka najkonkretnijim konceptima.

Počnite sa pregledom runtime-a i ekosistema:

{{#ref}}
runtimes-and-engines.md
{{#endref}}

Zatim pregledajte control plane-ove i supply-chain površine koje često odlučuju da li je attacker-u uopšte potreban kernel escape:

{{#ref}}
runtime-api-and-daemon-exposure.md
{{#endref}}

{{#ref}}
authorization-plugins.md
{{#endref}}

{{#ref}}
image-security-and-secrets.md
{{#endref}}

{{#ref}}
assessment-and-hardening.md
{{#endref}}

Zatim pređite na protection model:

{{#ref}}
protections/
{{#endref}}

Namespace stranice pojedinačno objašnjavaju kernel isolation primitive:

{{#ref}}
protections/namespaces/
{{#endref}}

Stranice o cgroups, capabilities, seccomp, AppArmor-u, SELinux-u, `no_new_privs`, maskiranim path-ovima i system path-ovima samo za čitanje objašnjavaju mehanizme koji se obično postavljaju preko namespace-ova:

{{#ref}}
protections/cgroups.md
{{#endref}}

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/seccomp.md
{{#endref}}

{{#ref}}
protections/apparmor.md
{{#endref}}

{{#ref}}
protections/selinux.md
{{#endref}}

{{#ref}}
protections/no-new-privileges.md
{{#endref}}

{{#ref}}
protections/masked-paths.md
{{#endref}}

{{#ref}}
protections/read-only-paths.md
{{#endref}}

{{#ref}}
distroless.md
{{#endref}}

{{#ref}}
privileged-containers.md
{{#endref}}

{{#ref}}
sensitive-host-mounts.md
{{#endref}}

## Dobar Početni Mindset Za Enumeration

Prilikom procene containerized target-a, mnogo je korisnije postaviti mali skup preciznih tehničkih pitanja nego odmah preći na poznate escape PoC-ove. Prvo identifikujte **stack**: Docker, Podman, containerd, CRI-O, Incus/LXC, systemd-nspawn, Apptainer ili nešto specijalizovanije. Zatim identifikujte **runtime**: `runc`, `crun`, `runsc`, `kata-runtime` ili drugu OCI-kompatibilnu implementaciju. Nakon toga proverite da li je okruženje **rootful ili rootless**, da li su **user namespaces** aktivni, da li se dele neki **host namespaces**, koje su **capabilities** preostale, da li je **seccomp** omogućen, da li se **MAC policy** zaista enforcement-uje, da li postoje **opasni mount-ovi ili socket-i** i da li proces može da komunicira sa container runtime API-jem.

Ovi odgovori govore mnogo više o stvarnom security posture-u nego što će to ikada govoriti naziv base image-a. U mnogim assessment-ima možete predvideti verovatnu breakout familiju pre nego što pročitate ijedan application file, samo na osnovu razumevanja konačne container konfiguracije.

## Coverage

Ovaj odeljak obuhvata stari Docker-focused materijal u organizaciji usmerenoj na kontejnere: runtime i daemon exposure, authorization plugins, image trust i build secrets, sensitive host mounts, distroless workloads, privileged containers i kernel protections koje se obično postavljaju oko izvršavanja kontejnera.

{{#include ../../../banners/hacktricks-training.md}}
