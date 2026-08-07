# Bezbednost kontejnera

{{#include ../../../banners/hacktricks-training.md}}

## Šta je kontejner zapravo

Praktičan način da se definiše kontejner jeste sledeći: kontejner je **obično stablo Linux procesa** pokrenuto pod specifičnom OCI-style konfiguracijom, tako da vidi kontrolisani filesystem, kontrolisani skup kernel resursa i ograničeni model privilegija. Proces može verovati da je PID 1, može verovati da ima sopstveni network stack, može verovati da poseduje sopstveni hostname i IPC resurse, a može se čak izvršavati kao root unutar sopstvenog user namespace-a. Međutim, ispod svega toga i dalje je reč o host procesu koji kernel raspoređuje kao i svaki drugi.

Zato se bezbednost kontejnera zapravo bavi proučavanjem načina na koji je ta iluzija konstruisana i načina na koji ona može da se naruši. Ako je mount namespace slab, proces može videti filesystem hosta. Ako user namespace ne postoji ili je onemogućen, root unutar kontejnera može biti previše direktno mapiran na root na hostu. Ako je seccomp unconfined, a skup capabilities preširok, proces može pristupiti syscall-ovima i privilegovanim kernel funkcijama koje su trebalo da ostanu nedostupne. Ako je runtime socket montiran unutar kontejnera, kontejneru možda uopšte nije potreban kernel breakout, jer može jednostavno zatražiti od runtime-a da pokrene privilegovaniji susedni kontejner ili da direktno montira root filesystem hosta.

## Kako se kontejneri razlikuju od virtuelnih mašina

VM obično ima sopstveni kernel i granicu hardverske apstrakcije. To znači da guest kernel može da se sruši, izazove panic ili bude exploited bez automatskog podrazumevanja direktne kontrole nad kernelom hosta. U kontejnerima workload ne dobija poseban kernel. Umesto toga, dobija pažljivo filtriran i namespaced prikaz istog kernela koji koristi host. Zbog toga su kontejneri obično lakši, brže se pokreću, omogućavaju gušće pakovanje na mašini i pogodniji su za kratkotrajno deployment-ovanje aplikacija. Cena toga je da granica izolacije mnogo direktnije zavisi od ispravne konfiguracije hosta i runtime-a.

To ne znači da su kontejneri "nebezbedni", a VM-ovi "bezbedni". To znači da je bezbednosni model drugačiji. Dobro konfigurisani container stack sa rootless izvršavanjem, user namespace-ovima, podrazumevanim seccomp-om, strogim skupom capabilities, bez deljenja host namespace-ova i uz snažno SELinux ili AppArmor sprovođenje može biti veoma robustan. Suprotno tome, kontejner pokrenut sa `--privileged`, deljenjem host PID/network prostora, Docker socket-om montiranim unutar njega i writable bind mount-om `/` funkcionalno je mnogo bliži pristupu host root-u nego bezbedno izolovanom application sandbox-u. Razlika potiče od slojeva koji su uključeni ili onemogućeni.

Postoji i srednji pristup koji bi čitaoci trebalo da razumeju, jer se sve češće pojavljuje u realnim okruženjima. **Sandboxed container runtimes** kao što su **gVisor** i **Kata Containers** namerno dodatno ojačavaju granicu u odnosu na klasični `runc` kontejner. gVisor postavlja userspace kernel sloj između workload-a i mnogih interfejsa kernela hosta, dok Kata pokreće workload unutar lightweight virtuelne mašine. Ovi runtime-i se i dalje koriste kroz container ekosisteme i orchestration workflow-e, ali se njihove bezbednosne karakteristike razlikuju od običnih OCI runtime-a i ne bi ih trebalo mentalno svrstavati sa "normalnim Docker kontejnerima", kao da se sve ponaša isto.

## Container stack: nekoliko slojeva, a ne jedan

Kada neko kaže "ovaj kontejner je nebezbedan", korisno dodatno pitanje jeste: **koji sloj ga je učinio nebezbednim?** Containerized workload je obično rezultat zajedničkog rada nekoliko komponenti.

Na vrhu se često nalazi **image build layer**, kao što su BuildKit, Buildah ili Kaniko, koji kreira OCI image i metadata podatke. Iznad low-level runtime-a može postojati **engine ili manager**, kao što su Docker Engine, Podman, containerd, CRI-O, Incus ili systemd-nspawn. U cluster okruženjima može postojati i **orchestrator**, kao što je Kubernetes, koji kroz workload konfiguraciju određuje zahtevani security posture. Konačno, **kernel** je taj koji zaista sprovodi namespaces, cgroups, seccomp i MAC policy.

Ovaj layered model je važan za razumevanje podrazumevanih vrednosti. Restrikciju može zatražiti Kubernetes, zatim je kroz CRI prevesti containerd ili CRI-O, wrapper runtime-a je može pretvoriti u OCI spec, a tek je onda `runc`, `crun`, `runsc` ili drugi runtime sprovodi nad kernelom. Kada se podrazumevane vrednosti razlikuju između okruženja, često je razlog to što je jedan od ovih slojeva promenio konačnu konfiguraciju. Isti mehanizam se zato u Docker-u ili Podman-u može pojaviti kao CLI flag, u Kubernetes-u kao Pod ili `securityContext` polje, a u low-level runtime stack-ovima kao OCI konfiguracija generisana za workload. Zbog toga CLI primere u ovom odeljku treba čitati kao **runtime-specific sintaksu za opšti container koncept**, a ne kao univerzalne flag-ove koje podržava svaki alat.

## Stvarna bezbednosna granica kontejnera

U praksi, bezbednost kontejnera potiče od **preklapajućih kontrola**, a ne od jedne savršene kontrole. Namespaces izoluju vidljivost. cgroups upravljaju korišćenjem resursa i ograničavaju ga. Capabilities smanjuju ono što proces koji izgleda privilegovano zapravo može da uradi. seccomp blokira opasne syscall-ove pre nego što stignu do kernela. AppArmor i SELinux dodaju Mandatory Access Control preko uobičajenih DAC provera. `no_new_privs`, masked procfs putanje i read-only sistemske putanje otežavaju uobičajene lance zloupotrebe privilegija i proc/sys mehanizama. I sam runtime je važan, jer određuje način kreiranja mount-ova, socket-a, label-a i namespace join-ova.

Zato veliki deo dokumentacije o bezbednosti kontejnera deluje repetitivno. Isti escape chain često zavisi od više mehanizama istovremeno. Na primer, writable host bind mount je loš, ali postaje mnogo gori ako se kontejner takođe izvršava kao stvarni root na hostu, ima `CAP_SYS_ADMIN`, nije ograničen seccomp-om i nije zaštićen SELinux-om ili AppArmor-om. Isto tako, deljenje host PID prostora predstavlja ozbiljnu izloženost, ali napadaču postaje dramatično korisnije kada je kombinovano sa `CAP_SYS_PTRACE`, slabim procfs zaštitama ili alatima za ulazak u namespace, kao što je `nsenter`. Ispravan način dokumentovanja ove teme zato nije ponavljanje istog napada na svakoj stranici, već objašnjavanje doprinosa svakog sloja konačnoj granici.

## Kako čitati ovaj odeljak

Odeljak je organizovan od najopštijih koncepata ka najspecifičnijim.

Počnite pregledom runtime-a i ekosistema:

{{#ref}}
runtimes-and-engines.md
{{#endref}}

Zatim pregledajte control plane-ove i supply-chain površine koje često određuju da li je napadaču uopšte potreban kernel escape:

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

Stranice o namespace-ovima pojedinačno objašnjavaju primitive kernel izolacije:

{{#ref}}
protections/namespaces/
{{#endref}}

Stranice o cgroups, capabilities, seccomp, AppArmor-u, SELinux-u, `no_new_privs`, masked putanjama i read-only sistemskim putanjama objašnjavaju mehanizme koji se obično dodaju preko namespace-ova:

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

## Dobar početni način enumeracije

Prilikom procene containerized target-a mnogo je korisnije postaviti mali skup preciznih tehničkih pitanja nego odmah preći na poznate escape PoC-ove. Najpre identifikujte **stack**: Docker, Podman, containerd, CRI-O, Incus/LXC, systemd-nspawn, Apptainer ili nešto specijalizovanije. Zatim identifikujte **runtime**: `runc`, `crun`, `runsc`, `kata-runtime` ili drugu OCI-kompatibilnu implementaciju. Nakon toga proverite da li je okruženje **rootful ili rootless**, da li su **user namespace-ovi** aktivni, da li se dele neki **host namespace-ovi**, koje su **capabilities** preostale, da li je **seccomp** omogućen, da li se **MAC policy** zaista primenjuje, da li postoje **opasni mount-ovi ili socket-i** i da li proces može da komunicira sa container runtime API-jem.

Ti odgovori govore mnogo više o stvarnom security posture-u nego što će naziv base image-a ikada moći. U mnogim procenama možete predvideti verovatnu breakout kategoriju pre nego što pročitate ijedan application fajl, samo na osnovu razumevanja konačne konfiguracije kontejnera.

## Obuhvat

Ovaj odeljak obuhvata stari Docker-focused materijal organizovan prema container konceptima: izloženost runtime-a i daemon-a, authorization plugins, poverenje u image-e i build secrets, osetljive mount-ove hosta, distroless workload-e, privileged kontejnere i kernel protections koje se obično dodaju izvršavanju kontejnera.

{{#include ../../../banners/hacktricks-training.md}}
