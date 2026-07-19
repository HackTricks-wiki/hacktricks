# Pregled zaštita kontejnera

{{#include ../../../../banners/hacktricks-training.md}}

Najvažnija ideja u hardeningu kontejnera jeste da ne postoji jedna kontrola koja se zove "container security". Ono što ljudi nazivaju izolacijom kontejnera zapravo je rezultat zajedničkog rada nekoliko Linux mehanizama za bezbednost i upravljanje resursima. Ako dokumentacija opisuje samo jedan od njih, čitaoci imaju tendenciju da precene njegovu snagu. Ako dokumentacija navede sve njih bez objašnjenja načina na koji međusobno deluju, čitaoci dobijaju katalog naziva, ali ne i stvarni model. Ovaj odeljak pokušava da izbegne obe greške.

U središtu modela nalaze se **namespaces**, koji izoluju ono što workload može da vidi. Oni procesu pružaju privatni ili delimično privatni prikaz mountova fajl sistema, PID-ova, umrežavanja, IPC objekata, hostname-ova, mapiranja korisnika/grupa, cgroup putanja i nekih časovnika. Ali sami namespaces ne odlučuju šta proces sme da uradi. Tu na scenu stupaju sledeći slojevi.

**cgroups** upravljaju korišćenjem resursa. Oni prvenstveno nisu granica izolacije u istom smislu kao mount ili PID namespaces, ali su operativno ključni jer ograničavaju memoriju, CPU, PID-ove, I/O i pristup uređajima. Takođe su relevantni za bezbednost zato što su istorijske breakout tehnike zloupotrebljavale funkcije cgroup-a sa dozvolom upisivanja, naročito u cgroup v1 okruženjima.

**Capabilities** dele stari model root-a sa svim privilegijama na manje jedinice privilegija. Ovo je fundamentalno za kontejnere jer mnogi workload-i i dalje rade kao UID 0 unutar kontejnera. Pitanje zato nije samo "da li je proces root?", već "koje capabilities su preživele, unutar kojih namespaces, pod kojim seccomp i MAC ograničenjima?" Zbog toga root proces u jednom kontejneru može biti relativno ograničen, dok se root proces u drugom kontejneru u praksi može gotovo razlikovati od host root-a.

**seccomp** filtrira syscalls i smanjuje attack surface kernela izložen workload-u. To je često mehanizam koji blokira očigledno opasne pozive kao što su `unshare`, `mount`, `keyctl` ili drugi syscalls koji se koriste u breakout lancima. Čak i ako proces poseduje capability koja bi inače omogućila neku operaciju, seccomp i dalje može blokirati putanju syscall-a pre nego što kernel u potpunosti obradi poziv.

**AppArmor** i **SELinux** dodaju Mandatory Access Control na normalne provere fajl sistema i privilegija. Ovo je naročito važno zato što ostaju relevantni čak i kada kontejner ima više capabilities nego što bi trebalo. Workload može posedovati teorijsku privilegiju da pokuša neku radnju, ali i dalje može biti sprečen da je izvrši zato što njegov label ili profile zabranjuje pristup relevantnoj putanji, objektu ili operaciji.

Na kraju, postoje dodatni slojevi hardeninga kojima se posvećuje manje pažnje, ali koji redovno imaju značaj u stvarnim napadima: `no_new_privs`, maskirane procfs putanje, putanje sistema sa dozvolom samo za čitanje, root fajl sistemi samo za čitanje i pažljivo podešeni podrazumevani runtime parametri. Ovi mehanizmi često zaustavljaju "poslednju milju" kompromitovanja, naročito kada napadač pokuša da izvršavanje koda pretvori u šire povećanje privilegija.

Ostatak ovog foldera detaljnije objašnjava svaki od ovih mehanizama, uključujući šta kernel primitive zapravo rade, kako ih lokalno posmatrati, kako ih uobičajeni runtime-i koriste i na koje načine ih operatori slučajno oslabljuju.

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

Mnogi stvarni escapes takođe zavise od toga koji je sadržaj host-a mountovan u workload, pa je nakon čitanja osnovnih zaštita korisno nastaviti sa:

{{#ref}}
../sensitive-host-mounts.md
{{#endref}}
{{#include ../../../../banners/hacktricks-training.md}}
