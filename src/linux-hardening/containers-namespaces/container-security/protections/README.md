# Pregled zaštita kontejnera

{{#include ../../../../banners/hacktricks-training.md}}

Najvažnija ideja u hardeningu kontejnera jeste da ne postoji jedna kontrola koja se zove „container security“. Ono što ljudi nazivaju izolacijom kontejnera zapravo je rezultat zajedničkog rada nekoliko Linux mehanizama za bezbednost i upravljanje resursima. Ako dokumentacija opisuje samo jedan od njih, čitaoci imaju tendenciju da precene njegovu snagu. Ako dokumentacija navede sve mehanizme bez objašnjenja njihove međusobne interakcije, čitaoci dobijaju katalog naziva, ali ne i stvarni model. Ovaj odeljak pokušava da izbegne obe greške.

U središtu modela nalaze se **namespaces**, koji izoluju ono što workload može da vidi. Oni procesu daju privatni ili delimično privatni prikaz mount-ova fajl sistema, PID-ova, mreže, IPC objekata, hostname-ova, mapiranja korisnika/grupa, cgroup putanja i nekih satova. Međutim, sami namespaces ne određuju šta proces sme da uradi. Tu stupaju na scenu sledeći slojevi.

**cgroups** upravljaju korišćenjem resursa. Oni prvenstveno nisu granica izolacije u istom smislu kao mount ili PID namespaces, ali su operativno ključni jer ograničavaju memoriju, CPU, PID-ove, I/O i pristup uređajima. Takođe su bezbednosno relevantni zato što su istorijske breakout tehnike zloupotrebljavale funkcije cgroup-a sa mogućnošću upisivanja, naročito u cgroup v1 okruženjima.

**Capabilities** dele stari, svemoćni model root-a na manje jedinice privilegija. To je fundamentalno za kontejnere jer mnogi workload-i i dalje rade kao UID 0 unutar kontejnera. Zato pitanje nije samo „da li je proces root?“, već pre „koje capabilities su preživele, unutar kojih namespaces, pod kojim seccomp i MAC ograničenjima?“ Zbog toga root proces u jednom kontejneru može biti relativno ograničen, dok se root proces u drugom kontejneru u praksi može gotovo ne razlikovati od root-a na hostu.

**seccomp** filtrira syscalls i smanjuje kernel attack surface izložen workload-u. To je često mehanizam koji blokira očigledno opasne pozive kao što su `unshare`, `mount`, `keyctl` ili drugi syscalls koji se koriste u breakout lancima. Čak i ako proces ima capability koja bi mu inače omogućila neku operaciju, seccomp i dalje može blokirati syscall putanju pre nego što je kernel u potpunosti obradi.

**AppArmor** i **SELinux** dodaju Mandatory Access Control preko uobičajenih provera fajl sistema i privilegija. Oni su posebno važni zato što nastavljaju da budu relevantni čak i kada kontejner ima više capabilities nego što bi trebalo. Workload može posedovati teorijsku privilegiju da pokuša neku radnju, ali i dalje može biti sprečen da je izvrši zato što njegov label ili profile zabranjuje pristup relevantnoj putanji, objektu ili operaciji.

Na kraju, postoje dodatni slojevi hardeninga kojima se posvećuje manje pažnje, ali koji su redovno važni u stvarnim napadima: `no_new_privs`, maskirane procfs putanje, putanje sistema samo za čitanje, root fajl sistemi samo za čitanje i pažljivo podešeni runtime podrazumevani parametri. Ovi mehanizmi često zaustavljaju „poslednju deonicu“ kompromitovanja, naročito kada napadač pokušava da pretvori izvršavanje koda u šire povećanje privilegija.

Ostatak ovog foldera detaljnije objašnjava svaki od ovih mehanizama, uključujući ono što kernel primitive zapravo radi, kako ga lokalno posmatrati, kako ga uobičajeni runtime-i koriste i kako ga operatori slučajno oslabljuju.

## Pročitajte sledeće

{{#ref}}
namespaces/
{{#endref}}

{{#ref}}
cgroups.md
{{#endref}}

{{#ref}}
capabilities.md
{{#endref}}

{{#ref}}
seccomp.md
{{#endref}}

{{#ref}}
apparmor.md
{{#endref}}

{{#ref}}
selinux.md
{{#endref}}

{{#ref}}
no-new-privileges.md
{{#endref}}

{{#ref}}
masked-paths.md
{{#endref}}

{{#ref}}
read-only-paths.md
{{#endref}}

Mnogi stvarni escapes takođe zavise od toga koji je sadržaj sa hosta mount-ovan u workload, pa je nakon čitanja osnovnih zaštita korisno nastaviti sa:

{{#ref}}
../sensitive-host-mounts.md
{{#endref}}

{{#include ../../../../banners/hacktricks-training.md}}
