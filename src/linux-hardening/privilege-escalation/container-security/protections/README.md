# Pregled zaštite kontejnera

{{#include ../../../../banners/hacktricks-training.md}}

Najvažnija ideja u hardenovanju kontejnera je da ne postoji jedinstvena kontrola zvana "container security". Ono što ljudi nazivaju izolacijom kontejnera zapravo je rezultat saradnje više Linux sigurnosnih i mehanizama za upravljanje resursima. Ako dokumentacija opiše samo jedan od njih, čitaoci obično precenjuju njegovu snagu. Ako dokumentacija nabroji sve bez objašnjenja kako međusobno deluju, čitaoci dobiju katalog imena ali bez stvarnog modela. Ovaj odeljak pokušava da izbegne obe greške.

U centru modela su **namespaces**, koje izolju ono što workload može da vidi. One daju procesu privatni ili delimično privatni prikaz filesystem mounts, PIDs, networking, IPC objekata, hostnames, user/group mappings, cgroup paths i nekih clocks. Ali same namespaces ne odlučuju šta proces sme da radi. Tu ulaze sledeći slojevi.

**cgroups** upravljaju korišćenjem resursa. Oni nisu pretežno granica izolacije u istom smislu kao mount ili PID namespaces, ali su ključni operativno zato što ograničavaju memory, CPU, PIDs, I/O i pristup uređajima. Takođe imaju sigurnosni značaj jer su istorijske tehnike za breakout zloupotrebljavale writable cgroup funkcije, posebno u cgroup v1 okruženjima.

**Capabilities** dele stari sve-moćni root model na manje jedinice privilegija. Ovo je fundamentalno za kontejnere jer mnogi workload-i i dalje rade kao UID 0 unutar kontejnera. Pitanje stoga nije samo "is the process root?", već "which capabilities survived, inside which namespaces, under which seccomp and MAC restrictions?" Zato root proces u jednom kontejneru može biti relativno ograničen dok root proces u drugom kontejneru može u praksi biti skoro neprimetno istovetan host root-u.

**seccomp** filtrira syscalls i smanjuje kernel attack surface izložen workload-u. Ovo je često mehanizam koji blokira očigledno opasne pozive kao što su `unshare`, `mount`, `keyctl`, ili drugi syscalls koji se koriste u breakout lancima. Čak i ako proces ima capability koji bi inače dozvolio operaciju, seccomp može i dalje blokirati syscall putanju pre nego što kernel u potpunosti obradi zahtev.

**AppArmor** i **SELinux** dodaju Mandatory Access Control preko normalnih filesystem i privilege provera. Ovo je posebno važno jer i dalje ima značaja čak i kada kontejner ima više capabilities nego što bi trebalo. Workload može posedovati teorijsku privilegiju da pokuša akciju, ali i dalje može biti sprečen da je izvrši zato što mu label ili profile zabranjuju pristup relevantnom putu, objektu ili operaciji.

Na kraju, postoje dodatni slojevi hardenovanja koji dobijaju manje pažnje ali su redovno bitni u stvarnim napadima: `no_new_privs`, masked procfs paths, read-only system paths, read-only root filesystems i pažljivo runtime defaults. Ovi mehanizmi često zaustavljaju "last mile" kompromitacije, posebno kada napadač pokuša da pretvori izvršenje koda u širi dobitak privilegija.

Ostatak ovog foldera objašnjava svaki od ovih mehanizama detaljnije, uključujući šta kernel primitive zaista radi, kako ga posmatrati lokalno, kako common runtimes koriste i kako operateri slučajno oslabe njegovu zaštitu.

## Dalje za čitanje

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

Mnogi stvarni escapes takođe zavise od toga koji je host sadržaj mount-ovan u workload, pa je nakon čitanja osnovnih zaštita korisno nastaviti sa:

{{#ref}}
../sensitive-host-mounts.md
{{#endref}}
{{#include ../../../../banners/hacktricks-training.md}}
