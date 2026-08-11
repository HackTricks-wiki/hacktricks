# Bezbednost kontejnera

## Šta je kontejner zapravo

Praktičan način da se definiše kontejner jeste sledeći: kontejner je **obično stablo Linux procesa** pokrenuto pod posebnom konfiguracijom u OCI stilu, tako da vidi kontrolisani filesystem, kontrolisani skup kernel resursa i ograničeni model privilegija. Proces može verovati da je PID 1, može verovati da ima sopstveni network stack, može verovati da poseduje sopstveni hostname i IPC resurse, pa čak može raditi kao root unutar sopstvenog user namespace-a. Ali ispod svega toga, on je i dalje host proces koji kernel raspoređuje kao i svaki drugi.

Zato se bezbednost kontejnera zapravo bavi načinom na koji se ta iluzija konstruiše i načinom na koji ona može da zakaže. Ako je mount namespace slab, proces može videti host filesystem. Ako user namespace ne postoji ili je onemogućen, root unutar kontejnera može biti previše direktno mapiran na root nalog na hostu. Ako je seccomp unconfined, a skup capabilities preširok, proces može pristupiti syscall-ovima i privilegovanim kernel funkcijama koje su trebalo da ostanu nedostupne. Ako je runtime socket montiran unutar kontejnera, kontejneru možda uopšte nije potreban kernel breakout, jer može jednostavno zatražiti od runtime-a da pokrene moćniji susedni kontejner ili direktno montirati host root filesystem.

## Kako se kontejneri razlikuju od virtualnih mašina

VM obično ima sopstveni kernel i granicu hardverske apstrakcije. To znači da guest kernel može da se sruši, izazove panic ili bude kompromitovan, a da to automatski ne znači direktnu kontrolu nad host kernelom. U kontejnerima workload ne dobija zaseban kernel. Umesto toga, dobija pažljivo filtriran i namespaced prikaz istog kernela koji host koristi. Zbog toga su kontejneri obično lakši, brže se pokreću, jednostavnije ih je gusto rasporediti na mašini i pogodniji su za kratkotrajno deploymentovanje aplikacija. Cena toga jeste što granica izolacije mnogo direktnije zavisi od ispravne konfiguracije hosta i runtime-a.

To ne znači da su kontejneri "nebezbedni", a VM-ovi "bezbedni". To znači da je bezbednosni model drugačiji. Dobro podešen container stack sa rootless izvršavanjem, user namespace-ovima, podrazumevanim seccomp-om, strogim skupom capabilities, bez deljenja host namespace-ova i uz snažno SELinux ili AppArmor sprovođenje pravila može biti veoma robustan. Suprotno tome, kontejner pokrenut sa `--privileged`, deljenjem host PID/network prostora, montiranim Docker socket-om i writable bind mount-om direktorijuma `/` funkcionalno je mnogo bliži pristupu host root-u nego bezbedno izolovanom application sandbox-u. Razlika potiče od slojeva koji su omogućeni ili onemogućeni.

Postoji i srednja opcija koju bi čitaoci trebalo da razumeju, jer se sve češće pojavljuje u realnim okruženjima. **Sandboxed container runtimes**, kao što su **gVisor** i **Kata Containers**, namerno dodatno ojačavaju granicu iznad klasičnog `runc` kontejnera. gVisor postavlja userspace kernel sloj između workload-a i mnogih host kernel interfejsa, dok Kata pokreće workload unutar lagane virtualne mašine. Oni se i dalje koriste kroz container ekosisteme i orchestration workflow-e, ali se njihove bezbednosne karakteristike razlikuju od običnih OCI runtime-ova i ne treba ih mentalno svrstavati sa "normalnim Docker kontejnerima", kao da se sve ponaša na isti način.

## Container stack: više slojeva, a ne jedan

Kada neko kaže "ovaj kontejner je nebezbedan", korisno dopunsko pitanje jeste: **koji sloj ga je učinio nebezbednim?** Containerized workload je obično rezultat zajedničkog rada više komponenti.

Na vrhu se često nalazi **image build layer**, kao što su BuildKit, Buildah ili Kaniko, koji kreira OCI image i metadata-u. Iznad low-level runtime-a može postojati **engine ili manager**, kao što su Docker Engine, Podman, containerd, CRI-O, Incus ili systemd-nspawn. U cluster okruženjima može postojati i **orchestrator**, kao što je Kubernetes, koji kroz workload konfiguraciju određuje traženi security posture. Na kraju, **kernel** je taj koji stvarno sprovodi namespaces, cgroups, seccomp i MAC policy.

Ovaj layered model je važan za razumevanje podrazumevanih podešavanja. Restrikciju može zatražiti Kubernetes, zatim je kroz CRI prevesti containerd ili CRI-O, wrapper za runtime je može pretvoriti u OCI spec, a tek potom je `runc`, `crun`, `runsc` ili drugi runtime sprovodi nad kernelom. Kada se podrazumevane vrednosti razlikuju između okruženja, često je razlog to što je jedan od ovih slojeva promenio konačnu konfiguraciju. Isti mehanizam se zato može pojaviti u Docker-u ili Podman-u kao CLI flag, u Kubernetes-u kao Pod ili `securityContext` polje, a u low-level runtime stack-ovima kao OCI konfiguracija generisana za workload. Zbog toga primere CLI komandi u ovom odeljku treba čitati kao **runtime-specific syntax za opšti container koncept**, a ne kao univerzalne flag-ove koje podržava svaki alat.

## Stvarna granica bezbednosti kontejnera

U praksi, bezbednost kontejnera potiče od **preklapajućih kontrola**, a ne od jedne savršene kontrole. Namespaces ograničavaju vidljivost. cgroups upravljaju korišćenjem resursa i ograničavaju ga. Capabilities smanjuju ono što proces koji izgleda privilegovano zaista može da uradi. seccomp blokira opasne syscall-ove pre nego što stignu do kernela. AppArmor i SELinux dodaju Mandatory Access Control povrh uobičajenih DAC provera. `no_new_privs`, masked procfs paths i read-only system paths otežavaju uobičajene lance zloupotrebe privilegija i proc/sys mehanizama. Sam runtime je takođe važan, jer odlučuje kako se kreiraju mount-ovi, socket-i, label-e i namespace join-ovi.

Zato mnogi dokumenti o bezbednosti kontejnera deluju repetitivno. Isti escape chain često zavisi od više mehanizama istovremeno. Na primer, writable host bind mount je loš, ali postaje mnogo opasniji ako kontejner takođe radi kao stvarni root na hostu, ima `CAP_SYS_ADMIN`, nije ograničen seccomp-om i nije restrikovan SELinux-om ili AppArmor-om. Slično tome, deljenje host PID prostora predstavlja ozbiljnu izloženost, ali postaje dramatično korisnije napadaču kada se kombinuje sa `CAP_SYS_PTRACE`, slabim procfs zaštitama ili alatima za ulazak u namespace, kao što je `nsenter`. Ispravan način dokumentovanja ove teme zato nije ponavljanje istog napada na svakoj stranici, već objašnjavanje doprinosa svakog sloja konačnoj granici.

## Kako čitati ovaj odeljak

Odeljak je organizovan od najopštijih koncepata ka najkonkretnijim.

Počnite pregledom runtime-a i ekosistema:

{{#ref}}
runtimes-and-engines.md
{{#endref}}

Zatim pregledajte control plane-ove i supply-chain površine koje često odlučuju da li je napadaču uopšte potreban kernel escape:

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

Stranice o cgroups, capabilities, seccomp, AppArmor, SELinux, `no_new_privs`, masked paths i read-only system paths objašnjavaju mehanizme koji se obično postavljaju povrh namespace-ova:

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

## Dobar početni mindset za enumeraciju

Prilikom procene containerized target-a, mnogo je korisnije postaviti mali skup preciznih tehničkih pitanja nego odmah preći na poznate escape PoC-ove. Najpre identifikujte **stack**: Docker, Podman, containerd, CRI-O, Incus/LXC, systemd-nspawn, Apptainer ili nešto specijalizovanije. Zatim identifikujte **runtime**: `runc`, `crun`, `runsc`, `kata-runtime` ili drugu OCI-kompatibilnu implementaciju. Nakon toga proverite da li je okruženje **rootful ili rootless**, da li su aktivni **user namespace-ovi**, da li se dele neki **host namespace-ovi**, koje **capabilities** su preostale, da li je **seccomp** omogućen, da li se **MAC policy** zaista primenjuje, da li postoje **opasni mount-ovi ili socket-i** i da li proces može da komunicira sa container runtime API-jem.

Ti odgovori govore mnogo više o stvarnom security posture-u nego što će ime base image-a ikada moći. U mnogim assessment-ima možete predvideti verovatnu breakout familiju pre nego što pročitate ijedan application file, samo na osnovu razumevanja konačne konfiguracije kontejnera.

## Obuhvat

Ovaj odeljak obuhvata stari materijal fokusiran na Docker, sada organizovan oko kontejnera: izloženost runtime-a i daemon-a, authorization plugins, poverenje u image-e i build secrets, osetljive host mount-ove, distroless workload-e, privilegovane kontejnere i kernel protections koje se uobičajeno postavljaju oko izvršavanja kontejnera.

{{#include ../../../banners/hacktricks-training.md}}
