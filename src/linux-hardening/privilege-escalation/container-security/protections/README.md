# Pregled zaštite kontejnera

{{#include ../../../../banners/hacktricks-training.md}}

Najvažnija ideja u hardeningu kontejnera je da ne postoji jedinstvena kontrola koja se zove "container security". Ono što ljudi nazivaju izolacijom kontejnera zapravo je rezultat više Linux sigurnosnih i mehanizama za upravljanje resursima koji rade zajedno. Ako dokumentacija opisuje samo jedan od njih, čitaoci imaju tendenciju da precene njegovu snagu. Ako dokumentacija nabraja sve bez objašnjenja kako međusobno deluju, čitaoci dobiju katalog imena ali bez stvarnog modela. Ovaj odeljak pokušava da izbegne obe greške.

U centru modela su **namespaces**, koji izoluju šta workload može da vidi. Oni daju procesu privatni ili delimično privatni pogled na mount-ove fajl sistema, PIDs, networking, IPC objekte, hostnames, user/group mapiranja, cgroup putanje i neke satove. Ali sami namespaces ne odlučuju šta procesu je dozvoljeno da radi. Tu ulaze sledeći slojevi.

**cgroups** upravljaju korišćenjem resursa. One nisu primarno granica izolacije u istom smislu kao mount ili PID namespaces, ali su operativno ključne jer ograničavaju memoriju, CPU, PIDs, I/O i pristup uređajima. One takođe imaju bezbednosnu relevantnost jer su istorijske tehnike bekstva zloupotrebljavale writable cgroup funkcije, naročito u cgroup v1 okruženjima.

**Capabilities** dele stari svemoćni root model na manje jedinice privilegija. Ovo je fundamentalno za kontejnere jer mnogi workload-ovi i dalje rade kao UID 0 unutar kontejnera. Pitanje stoga nije samo "da li je proces root?", već "koje su capabilities preživele, unutar kojih namespaces, pod kojim seccomp i MAC ograničenjima?" Zato root proces u jednom kontejneru može biti relativno ograničen dok root proces u drugom kontejneru u praksi može biti skoro nedistinguibilan od host root-a.

**seccomp** filtrira syscalle i smanjuje kernel attack surface izložen workload-u. Ovo je često mehanizam koji blokira očigledno opasne pozive kao što su `unshare`, `mount`, `keyctl` ili drugi syscalls koji se koriste u breakout lancima. Čak i ako proces ima capability koja bi inače dozvolila operaciju, seccomp i dalje može blokirati syscall putanju pre nego što kernel to u potpunosti obradi.

**AppArmor** i **SELinux** dodaju Mandatory Access Control preko normalnih filesystem i privilege provera. Ovo je naročito važno jer i dalje ima efekt čak i kada kontejner ima više capabilities nego što bi trebalo. Workload može posedovati teorijsku privilegiju da pokuša akciju, ali i dalje biti sprečen u izvršenju zato što mu label ili profile zabranjuju pristup relevantnom putu, objektu ili operaciji.

Na kraju, postoje dodatni hardening slojevi koji dobijaju manje pažnje ali redovno znače u pravim napadima: `no_new_privs`, masked procfs paths, read-only system paths, read-only root filesystems i pažljive runtime podrazumevane postavke. Ovi mehanizmi često zaustave "poslednju milju" kompromitovanja, naročito kada napadač pokuša da pretvori izvršenje koda u širi dobitak privilegija.

Ostatak ovog foldera objašnjava svaki od ovih mehanizama detaljnije, uključujući šta kernel primitiv zapravo radi, kako ga posmatrati lokalno, kako ga common runtimes koriste i kako operatori slučajno slabe njegovu zaštitu.

## Pročitaj sledeće

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

Mnogi realni escape-ovi takođe zavise od toga koji je host sadržaj mount-ovan u workload, tako da je, nakon čitanja osnovnih zaštita, korisno nastaviti sa:

{{#ref}}
../sensitive-host-mounts.md
{{#endref}}
