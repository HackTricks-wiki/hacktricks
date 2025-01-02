# AppArmor

{{#include ../../../banners/hacktricks-training.md}}

## Basiese Inligting

AppArmor is 'n **kernverbetering wat ontwerp is om die hulpbronne wat beskikbaar is vir programme deur middel van per-program profiele te beperk**, wat effektief Verpligte Toegangbeheer (MAC) implementeer deur toegangbeheer eienskappe direk aan programme te koppel eerder as aan gebruikers. Hierdie stelsel werk deur **profiele in die kern te laai**, gewoonlik tydens opstart, en hierdie profiele bepaal watter hulpbronne 'n program kan toegang hê, soos netwerkverbindinge, rou sokkettoegang, en lêer toestemmings.

Daar is twee operasionele modi vir AppArmor profiele:

- **Handhaving Modus**: Hierdie modus handhaaf aktief die beleide wat binne die profiel gedefinieer is, en blokkeer aksies wat hierdie beleide oortree en log enige pogings om dit te oortree deur stelsels soos syslog of auditd.
- **Klagte Modus**: Anders as handhaving modus, blokkeer klagte modus nie aksies wat teen die profiel se beleide gaan nie. In plaas daarvan, log dit hierdie pogings as beleids oortredings sonder om beperkings af te dwing.

### Komponente van AppArmor

- **Kernmodule**: Verantwoordelik vir die handhaving van beleide.
- **Beleide**: Spesifiseer die reëls en beperkings vir programgedrag en hulpbron toegang.
- **Parser**: Laai beleide in die kern vir handhaving of verslagdoening.
- **Hulpmiddels**: Dit is gebruikersmodus programme wat 'n koppelvlak bied om met en die bestuur van AppArmor te kommunikeer.

### Profiele pad

Apparmor profiele word gewoonlik gestoor in _**/etc/apparmor.d/**_\
Met `sudo aa-status` sal jy in staat wees om die binaire te lys wat deur 'n profiel beperk word. As jy die karakter "/" kan verander in 'n punt in die pad van elke gelys binêre, sal jy die naam van die apparmor profiel binne die genoemde gids verkry.

Byvoorbeeld, 'n **apparmor** profiel vir _/usr/bin/man_ sal geleë wees in _/etc/apparmor.d/usr.bin.man_

### Opdragte
```bash
aa-status     #check the current status
aa-enforce    #set profile to enforce mode (from disable or complain)
aa-complain   #set profile to complain mode (from diable or enforcement)
apparmor_parser #to load/reload an altered policy
aa-genprof    #generate a new profile
aa-logprof    #used to change the policy when the binary/program is changed
aa-mergeprof  #used to merge the policies
```
## Skep 'n profiel

- Om die aangetaste uitvoerbare lêer aan te dui, **absolute paaie en wildcard** is toegelaat (vir lêer globbing) om lêers te spesifiseer.
- Om die toegang wat die binêre oor **lêers** sal hê aan te dui, kan die volgende **toegangbeheer** gebruik word:
- **r** (lees)
- **w** (skryf)
- **m** (geheuekaart as uitvoerbaar)
- **k** (lêer sluiting)
- **l** (skepping harde skakels)
- **ix** (om 'n ander program uit te voer met die nuwe program wat die beleid erfen)
- **Px** (uitvoer onder 'n ander profiel, na die omgewing skoongemaak is)
- **Cx** (uitvoer onder 'n kindprofiel, na die omgewing skoongemaak is)
- **Ux** (uitvoer onbepaal, na die omgewing skoongemaak is)
- **Veranderlikes** kan in die profiele gedefinieer word en kan van buite die profiel gemanipuleer word. Byvoorbeeld: @{PROC} en @{HOME} (voeg #include \<tunables/global> by die profiel lêer)
- **Weier reëls word ondersteun om toelaat reëls te oorskry**.

### aa-genprof

Om maklik te begin om 'n profiel te skep, kan apparmor jou help. Dit is moontlik om **apparmor die aksies wat deur 'n binêre uitgevoer word te laat ondersoek en dan jou te laat besluit watter aksies jy wil toelaat of weier**.\
Jy moet net die volgende uitvoer:
```bash
sudo aa-genprof /path/to/binary
```
Dan, in 'n ander konsole, voer al die aksies uit wat die binêre gewoonlik sal uitvoer:
```bash
/path/to/binary -a dosomething
```
Dan, druk in die eerste konsole "**s**" en dui dan in die opgeneemde aksies aan of jy wil ignoreer, toelaat, of wat ook al. Wanneer jy klaar is, druk "**f**" en die nuwe profiel sal geskep word in _/etc/apparmor.d/path.to.binary_

> [!NOTE]
> Met die pyle sleutels kan jy kies wat jy wil toelaat/weier/whatever

### aa-easyprof

Jy kan ook 'n sjabloon van 'n apparmor-profiel van 'n binêre met:
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
> Let daarop dat niks standaard in 'n geskepte profiel toegelaat word nie, so alles word geweier. Jy sal lyne soos `/etc/passwd r,` moet byvoeg om die binêre lees `/etc/passwd` toe te laat, byvoorbeeld.
  
Jy kan dan die **enforce** van die nuwe profiel met
```bash
sudo apparmor_parser -a /etc/apparmor.d/path.to.binary
```
### Wysigting 'n profiel vanaf logs

Die volgende hulpmiddel sal die logs lees en die gebruiker vra of hy sommige van die gedetecteerde verbode aksies wil toelaat:
```bash
sudo aa-logprof
```
> [!NOTE]
> Deur die pyl sleutels te gebruik, kan jy kies wat jy wil toelaat/weier/wat ook al

### Bestuur van 'n Profiel
```bash
#Main profile management commands
apparmor_parser -a /etc/apparmor.d/profile.name #Load a new profile in enforce mode
apparmor_parser -C /etc/apparmor.d/profile.name #Load a new profile in complain mode
apparmor_parser -r /etc/apparmor.d/profile.name #Replace existing profile
apparmor_parser -R /etc/apparmor.d/profile.name #Remove profile
```
## Logs

Voorbeeld van **AUDIT** en **DENIED** logs van _/var/log/audit/audit.log_ van die uitvoerbare **`service_bin`**:
```bash
type=AVC msg=audit(1610061880.392:286): apparmor="AUDIT" operation="getattr" profile="/bin/rcat" name="/dev/pts/1" pid=954 comm="service_bin" requested_mask="r" fsuid=1000 ouid=1000
type=AVC msg=audit(1610061880.392:287): apparmor="DENIED" operation="open" profile="/bin/rcat" name="/etc/hosts" pid=954 comm="service_bin" requested_mask="r" denied_mask="r" fsuid=1000 ouid=0
```
Jy kan ook hierdie inligting verkry deur:
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
## Apparmor in Docker

Let op hoe die profiel **docker-profile** van docker standaard gelaai word:
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
Deur die standaard **Apparmor docker-default profiel** word gegenereer vanaf [https://github.com/moby/moby/tree/master/profiles/apparmor](https://github.com/moby/moby/tree/master/profiles/apparmor)

**docker-default profiel Samevatting**:

- **Toegang** tot alle **netwerk**
- **Geen vermoë** is gedefinieer (Ehowever, sommige vermoëns sal kom van die insluiting van basiese basisreëls i.e. #include \<abstractions/base>)
- **Skryf** na enige **/proc** lêer is **nie toegelaat** nie
- Ander **subgidsen**/**lêers** van /**proc** en /**sys** het **weier** lees/skryf/slot/skakel/uitvoer toegang
- **Monteer** is **nie toegelaat** nie
- **Ptrace** kan slegs op 'n proses wat deur **dieselfde apparmor profiel** beperk is, uitgevoer word

Sodra jy 'n **docker-container** **hardloop**, behoort jy die volgende uitvoer te sien:
```bash
1 processes are in enforce mode.
docker-default (825)
```
Let wel, **apparmor sal selfs vermoënsprivileges blokkeer** wat aan die houer standaard toegeken word. Byvoorbeeld, dit sal in staat wees om **toestemming te blokkeer om binne /proc te skryf selfs as die SYS_ADMIN vermoë toegeken is** omdat die docker apparmor-profiel hierdie toegang standaard weier:
```bash
docker run -it --cap-add SYS_ADMIN --security-opt seccomp=unconfined ubuntu /bin/bash
echo "" > /proc/stat
sh: 1: cannot create /proc/stat: Permission denied
```
U moet **apparmor deaktiveer** om sy beperkings te omseil:
```bash
docker run -it --cap-add SYS_ADMIN --security-opt seccomp=unconfined --security-opt apparmor=unconfined ubuntu /bin/bash
```
Let wel dat **AppArmor** standaard ook **die houer sal verbied om** vouers van binne te monteer, selfs met SYS_ADMIN vermoë.

Let wel dat jy **vermoëns** aan die docker houer kan **byvoeg/verwyder** (dit sal steeds beperk wees deur beskermingsmetodes soos **AppArmor** en **Seccomp**):

- `--cap-add=SYS_ADMIN` gee `SYS_ADMIN` vermoë
- `--cap-add=ALL` gee alle vermoëns
- `--cap-drop=ALL --cap-add=SYS_PTRACE` verwyder alle vermoëns en gee slegs `SYS_PTRACE`

> [!NOTE]
> Gewoonlik, wanneer jy **vind** dat jy 'n **bevoorregte vermoë** beskikbaar het **binne** 'n **docker** houer **maar** 'n deel van die **ontploffing werk nie**, sal dit wees omdat docker **apparmor dit sal voorkom**.

### Voorbeeld

(Voorbeeld van [**hier**](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-2docker-engine/))

Om AppArmor se funksionaliteit te illustreer, het ek 'n nuwe Docker-profiel “mydocker” geskep met die volgende lyn bygevoeg:
```
deny /etc/* w,   # deny write for all files directly in /etc (not in a subdir)
```
Om die profiel te aktiveer, moet ons die volgende doen:
```
sudo apparmor_parser -r -W mydocker
```
Om die profiele te lys, kan ons die volgende opdrag uitvoer. Die onderstaande opdrag lys my nuwe AppArmor-profiel.
```
$ sudo apparmor_status  | grep mydocker
mydocker
```
Soos hieronder getoon, kry ons 'n fout wanneer ons probeer om “/etc/” te verander aangesien die AppArmor-profiel skryftoegang tot “/etc” voorkom.
```
$ docker run --rm -it --security-opt apparmor:mydocker -v ~/haproxy:/localhost busybox chmod 400 /etc/hostname
chmod: /etc/hostname: Permission denied
```
### AppArmor Docker Bypass1

Jy kan vind watter **apparmor-profiel 'n houer uitvoer** deur:
```bash
docker inspect 9d622d73a614 | grep lowpriv
"AppArmorProfile": "lowpriv",
"apparmor=lowpriv"
```
Dan kan jy die volgende lyn uitvoer om **die presiese profiel wat gebruik word** te **vind**:
```bash
find /etc/apparmor.d/ -name "*lowpriv*" -maxdepth 1 2>/dev/null
```
In die vreemde geval kan jy **die apparmor docker-profiel wysig en dit herlaai.** Jy kan die beperkings verwyder en "omseil" hulle.

### AppArmor Docker Bypass2

**AppArmor is pad-gebaseerd**, dit beteken dat selfs al mag dit **lêers** binne 'n gids soos **`/proc`** beskerm, as jy kan **konfigureer hoe die houer gaan loop**, kan jy die proc-gids van die gasheer binne **`/host/proc`** **monteer** en dit **sal nie meer deur AppArmor beskerm word** nie.

### AppArmor Shebang Bypass

In [**hierdie fout**](https://bugs.launchpad.net/apparmor/+bug/1911431) kan jy 'n voorbeeld sien van hoe **selfs al voorkom jy dat perl met sekere hulpbronne uitgevoer word**, as jy net 'n skulp-skrip **specifiseer** in die eerste lyn **`#!/usr/bin/perl`** en jy **voer die lêer direk uit**, sal jy in staat wees om te voer wat jy wil. Byvoorbeeld:
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
