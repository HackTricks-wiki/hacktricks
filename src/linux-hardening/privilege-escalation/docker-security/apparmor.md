# AppArmor

{{#include ../../../banners/hacktricks-training.md}}

## Osnovne informacije

AppArmor je **poboljšanje jezgra dizajnirano da ograniči resurse dostupne programima kroz profile po programu**, efikasno implementirajući Obaveznu Kontrolu Pristupa (MAC) vezujući atribute kontrole pristupa direktno za programe umesto za korisnike. Ovaj sistem funkcioniše tako što **učitava profile u jezgro**, obično tokom pokretanja, a ovi profili određuju koje resurse program može da pristupi, kao što su mrežne veze, pristup sirovim soketima i dozvole za datoteke.

Postoje dva operativna moda za AppArmor profile:

- **Režim sprovođenja**: Ovaj režim aktivno sprovodi politike definisane unutar profila, blokirajući radnje koje krše te politike i beležeći sve pokušaje da ih se prekrši putem sistema kao što su syslog ili auditd.
- **Režim žalbe**: Za razliku od režima sprovođenja, režim žalbe ne blokira radnje koje su protiv politike profila. Umesto toga, beleži ove pokušaje kao kršenja politike bez sprovođenja ograničenja.

### Komponente AppArmor-a

- **Modul jezgra**: Odgovoran za sprovođenje politika.
- **Politike**: Specifikuju pravila i ograničenja za ponašanje programa i pristup resursima.
- **Parser**: Učitava politike u jezgro za sprovođenje ili izveštavanje.
- **Alati**: Ovo su programi u korisničkom režimu koji pružaju interfejs za interakciju i upravljanje AppArmor-om.

### Putanja profila

AppArmor profili se obično čuvaju u _**/etc/apparmor.d/**_\
Sa `sudo aa-status` moći ćete da navedete binarne datoteke koje su ograničene nekim profilom. Ako možete da promenite karakter "/" u tačku u putanji svake navedene binarne datoteke, dobićete ime AppArmor profila unutar pomenutog foldera.

Na primer, **AppArmor** profil za _/usr/bin/man_ biće lociran u _/etc/apparmor.d/usr.bin.man_

### Komande
```bash
aa-status     #check the current status
aa-enforce    #set profile to enforce mode (from disable or complain)
aa-complain   #set profile to complain mode (from diable or enforcement)
apparmor_parser #to load/reload an altered policy
aa-genprof    #generate a new profile
aa-logprof    #used to change the policy when the binary/program is changed
aa-mergeprof  #used to merge the policies
```
## Kreiranje profila

- Da biste označili pogođeni izvršni fajl, **apsolutne putanje i džokeri** su dozvoljeni (za globovanje fajlova) za specificiranje fajlova.
- Da biste označili pristup koji će binarni fajl imati nad **fajlovima**, mogu se koristiti sledeće **kontrole pristupa**:
- **r** (čitati)
- **w** (pisati)
- **m** (mapiranje u memoriju kao izvršno)
- **k** (zaključavanje fajlova)
- **l** (kreiranje tvrdih linkova)
- **ix** (izvršiti drugi program sa novim programom koji nasleđuje politiku)
- **Px** (izvršiti pod drugim profilom, nakon čišćenja okruženja)
- **Cx** (izvršiti pod detetom profilom, nakon čišćenja okruženja)
- **Ux** (izvršiti bez ograničenja, nakon čišćenja okruženja)
- **Promenljive** se mogu definisati u profilima i mogu se manipulisati izvan profila. Na primer: @{PROC} i @{HOME} (dodajte #include \<tunables/global> u fajl profila)
- **Pravila odbijanja su podržana da bi nadjačala pravila dozvole**.

### aa-genprof

Da biste lako započeli kreiranje profila, apparmor vam može pomoći. Moguće je da **apparmor ispita radnje koje izvršava binarni fajl i zatim vam omogući da odlučite koje radnje želite da dozvolite ili odbijete**.\
Samo treba da pokrenete:
```bash
sudo aa-genprof /path/to/binary
```
Zatim, u drugoj konzoli izvršite sve radnje koje će binarni fajl obično izvesti:
```bash
/path/to/binary -a dosomething
```
Zatim, u prvoj konzoli pritisnite "**s**" i zatim u zabeleženim radnjama označite da li želite da ignorišete, dozvolite ili nešto drugo. Kada završite, pritisnite "**f**" i novi profil će biti kreiran u _/etc/apparmor.d/path.to.binary_

> [!NOTE]
> Koristeći tastere sa strelicama možete izabrati šta želite da dozvolite/odbacite/šta god

### aa-easyprof

Takođe možete kreirati šablon apparmor profila binarne datoteke sa:
```bash
sudo aa-easyprof /path/to/binary
# vim:syntax=apparmor
# AppArmor policy for binary
# ###AUTHOR###
# ###COPYRIGHT###
# ###COMMENT###

#include <tunables/global>

# No template variables specified

"/path/to/binary" {
#include <abstractions/base>

# No abstractions specified

# No policy groups specified

# No read paths specified

# No write paths specified
}
```
> [!NOTE]
> Imajte na umu da po default-u u kreiranom profilu ništa nije dozvoljeno, tako da je sve odbijeno. Moraćete da dodate linije poput `/etc/passwd r,` da biste omogućili binarnom čitanje `/etc/passwd`, na primer.

Možete zatim **sprovoditi** novi profil sa
```bash
sudo apparmor_parser -a /etc/apparmor.d/path.to.binary
```
### Modifikovanje profila iz logova

Sledeći alat će pročitati logove i pitati korisnika da li želi da dozvoli neke od otkrivenih zabranjenih akcija:
```bash
sudo aa-logprof
```
> [!NOTE]
> Koristeći tastere sa strelicama možete odabrati šta želite da dozvolite/odbacite/šta god

### Upravljanje profilom
```bash
#Main profile management commands
apparmor_parser -a /etc/apparmor.d/profile.name #Load a new profile in enforce mode
apparmor_parser -C /etc/apparmor.d/profile.name #Load a new profile in complain mode
apparmor_parser -r /etc/apparmor.d/profile.name #Replace existing profile
apparmor_parser -R /etc/apparmor.d/profile.name #Remove profile
```
## Logs

Primer **AUDIT** i **DENIED** logova iz _/var/log/audit/audit.log_ izvršnog fajla **`service_bin`**:
```bash
type=AVC msg=audit(1610061880.392:286): apparmor="AUDIT" operation="getattr" profile="/bin/rcat" name="/dev/pts/1" pid=954 comm="service_bin" requested_mask="r" fsuid=1000 ouid=1000
type=AVC msg=audit(1610061880.392:287): apparmor="DENIED" operation="open" profile="/bin/rcat" name="/etc/hosts" pid=954 comm="service_bin" requested_mask="r" denied_mask="r" fsuid=1000 ouid=0
```
Možete takođe dobiti ove informacije koristeći:
```bash
sudo aa-notify -s 1 -v
Profile: /bin/service_bin
Operation: open
Name: /etc/passwd
Denied: r
Logfile: /var/log/audit/audit.log

Profile: /bin/service_bin
Operation: open
Name: /etc/hosts
Denied: r
Logfile: /var/log/audit/audit.log

AppArmor denials: 2 (since Wed Jan  6 23:51:08 2021)
For more information, please see: https://wiki.ubuntu.com/DebuggingApparmor
```
## Apparmor u Dockeru

Obratite pažnju na to kako se profil **docker-profile** dockera učitava po defaultu:
```bash
sudo aa-status
apparmor module is loaded.
50 profiles are loaded.
13 profiles are in enforce mode.
/sbin/dhclient
/usr/bin/lxc-start
/usr/lib/NetworkManager/nm-dhcp-client.action
/usr/lib/NetworkManager/nm-dhcp-helper
/usr/lib/chromium-browser/chromium-browser//browser_java
/usr/lib/chromium-browser/chromium-browser//browser_openjdk
/usr/lib/chromium-browser/chromium-browser//sanitized_helper
/usr/lib/connman/scripts/dhclient-script
docker-default
```
Podrazumevano **Apparmor docker-default profil** se generiše iz [https://github.com/moby/moby/tree/master/profiles/apparmor](https://github.com/moby/moby/tree/master/profiles/apparmor)

**docker-default profil Sažetak**:

- **Pristup** svim **mrežama**
- **Nema sposobnosti** definisane (Međutim, neke sposobnosti će doći iz uključivanja osnovnih pravila i.e. #include \<abstractions/base>)
- **Pisanje** u bilo koju **/proc** datoteku **nije dozvoljeno**
- Ostali **poddirektorijumi**/**datoteke** u /**proc** i /**sys** imaju **zabranjen** read/write/lock/link/execute pristup
- **Montiranje** **nije dozvoljeno**
- **Ptrace** se može pokrenuti samo na procesu koji je ograničen **istim apparmor profilom**

Kada **pokrenete docker kontejner** trebali biste videti sledeći izlaz:
```bash
1 processes are in enforce mode.
docker-default (825)
```
Napomena da **apparmor čak blokira privilegije sposobnosti** dodeljene kontejneru po defaultu. Na primer, biće u mogućnosti da **blokira dozvolu za pisanje unutar /proc čak i ako je dodeljena SYS_ADMIN sposobnost** jer po defaultu docker apparmor profil odbija ovaj pristup:
```bash
docker run -it --cap-add SYS_ADMIN --security-opt seccomp=unconfined ubuntu /bin/bash
echo "" > /proc/stat
sh: 1: cannot create /proc/stat: Permission denied
```
Morate da **onemogućite apparmor** da biste zaobišli njena ograničenja:
```bash
docker run -it --cap-add SYS_ADMIN --security-opt seccomp=unconfined --security-opt apparmor=unconfined ubuntu /bin/bash
```
Napomena da će po defaultu **AppArmor** takođe **zabraniti kontejneru da montira** foldere iznutra čak i sa SYS_ADMIN sposobnošću.

Napomena da možete **dodati/ukloniti** **sposobnosti** kontejneru (to će i dalje biti ograničeno zaštitnim metodama kao što su **AppArmor** i **Seccomp**):

- `--cap-add=SYS_ADMIN` dodeljuje `SYS_ADMIN` sposobnost
- `--cap-add=ALL` dodeljuje sve sposobnosti
- `--cap-drop=ALL --cap-add=SYS_PTRACE` uklanja sve sposobnosti i dodeljuje samo `SYS_PTRACE`

> [!NOTE]
> Obično, kada **otkrijete** da imate **privilegovanu sposobnost** dostupnu **unutar** **docker** kontejnera **ali** neki deo **eksploatacije ne funkcioniše**, to će biti zato što **apparmor docker sprečava**.

### Primer

(Primer iz [**ovde**](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-2docker-engine/))

Da ilustrujem funkcionalnost AppArmor-a, kreirao sam novi Docker profil “mydocker” sa sledećom linijom dodatom:
```
deny /etc/* w,   # deny write for all files directly in /etc (not in a subdir)
```
Da bismo aktivirali profil, potrebno je da uradimo sledeće:
```
sudo apparmor_parser -r -W mydocker
```
Da bismo naveli profile, možemo izvršiti sledeću komandu. Komanda ispod navodi moj novi AppArmor profil.
```
$ sudo apparmor_status  | grep mydocker
mydocker
```
Kao što je prikazano u nastavku, dobijamo grešku kada pokušavamo da promenimo “/etc/” jer AppArmor profil sprečava pisanje u “/etc”.
```
$ docker run --rm -it --security-opt apparmor:mydocker -v ~/haproxy:/localhost busybox chmod 400 /etc/hostname
chmod: /etc/hostname: Permission denied
```
### AppArmor Docker Bypass1

Možete saznati koji **apparmor profil pokreće kontejner** koristeći:
```bash
docker inspect 9d622d73a614 | grep lowpriv
"AppArmorProfile": "lowpriv",
"apparmor=lowpriv"
```
Zatim možete pokrenuti sledeću liniju da **pronađete tačan profil koji se koristi**:
```bash
find /etc/apparmor.d/ -name "*lowpriv*" -maxdepth 1 2>/dev/null
```
U čudnom slučaju možete **modifikovati apparmor docker profil i ponovo ga učitati.** Možete ukloniti ograničenja i "obići" ih.

### AppArmor Docker Bypass2

**AppArmor je zasnovan na putanjama**, to znači da čak i ako možda **štiti** datoteke unutar direktorijuma kao što je **`/proc`**, ako možete **konfigurisati kako će kontejner biti pokrenut**, možete **montirati** proc direktorijum hosta unutar **`/host/proc`** i on **više neće biti zaštićen od strane AppArmor-a**.

### AppArmor Shebang Bypass

U [**ovoj grešci**](https://bugs.launchpad.net/apparmor/+bug/1911431) možete videti primer kako **čak i ako sprečavate da se perl pokrene sa određenim resursima**, ako jednostavno kreirate shell skriptu **specifikujući** u prvom redu **`#!/usr/bin/perl`** i **izvršite datoteku direktno**, moći ćete da izvršite šta god želite. Na primer:
```perl
echo '#!/usr/bin/perl
use POSIX qw(strftime);
use POSIX qw(setuid);
POSIX::setuid(0);
exec "/bin/sh"' > /tmp/test.pl
chmod +x /tmp/test.pl
/tmp/test.pl
```
{{#include ../../../banners/hacktricks-training.md}}
