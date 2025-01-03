# AppArmor

{{#include ../../../banners/hacktricks-training.md}}

## Basic Information

AppArmor ni **kuimarisha kernel iliyoundwa kupunguza rasilimali zinazopatikana kwa programu kupitia wasifu wa kila programu**, kwa ufanisi ikitekeleza Udhibiti wa Ufikiaji wa Lazima (MAC) kwa kufunga sifa za udhibiti wa ufikiaji moja kwa moja kwa programu badala ya watumiaji. Mfumo huu unafanya kazi kwa **kuchaji wasifu kwenye kernel**, kawaida wakati wa kuanzisha, na wasifu hawa huamua ni rasilimali zipi programu inaweza kufikia, kama vile muunganisho wa mtandao, ufikiaji wa socket mbichi, na ruhusa za faili.

Kuna njia mbili za uendeshaji kwa wasifu wa AppArmor:

- **Enforcement Mode**: Njia hii inatekeleza kwa nguvu sera zilizofafanuliwa ndani ya wasifu, ikizuia vitendo vinavyokiuka sera hizi na kuandika jaribio lolote la kuvunja sheria kupitia mifumo kama syslog au auditd.
- **Complain Mode**: Tofauti na njia ya utekelezaji, njia ya malalamiko haisitishi vitendo vinavyokwenda kinyume na sera za wasifu. Badala yake, inaandika jaribio hizi kama ukiukaji wa sera bila kutekeleza vizuizi.

### Components of AppArmor

- **Kernel Module**: Inawajibika kwa utekelezaji wa sera.
- **Policies**: Zinabainisha sheria na vizuizi kwa tabia ya programu na ufikiaji wa rasilimali.
- **Parser**: Inachaji sera kwenye kernel kwa utekelezaji au ripoti.
- **Utilities**: Hizi ni programu za hali ya mtumiaji zinazotoa kiolesura cha kuingiliana na kusimamia AppArmor.

### Profiles path

Wasifu wa AppArmor kawaida huhifadhiwa katika _**/etc/apparmor.d/**_\
Kwa kutumia `sudo aa-status` utaweza kuorodhesha binaries ambazo zimepunguziliwa mbali na wasifu fulani. Ikiwa unaweza kubadilisha herufi "/" kuwa nukta katika njia ya kila binary iliyoorodheshwa, utapata jina la wasifu wa apparmor ndani ya folda iliyoelezwa.

Kwa mfano, wasifu wa **apparmor** kwa _/usr/bin/man_ utawekwa katika _/etc/apparmor.d/usr.bin.man_

### Commands
```bash
aa-status     #check the current status
aa-enforce    #set profile to enforce mode (from disable or complain)
aa-complain   #set profile to complain mode (from diable or enforcement)
apparmor_parser #to load/reload an altered policy
aa-genprof    #generate a new profile
aa-logprof    #used to change the policy when the binary/program is changed
aa-mergeprof  #used to merge the policies
```
## Kuunda wasifu

- Ili kuonyesha executable iliyoathirika, **njia za moja kwa moja na wildcards** zinakubaliwa (kwa ajili ya kufafanua faili).
- Ili kuonyesha ufikiaji ambao binary itakuwa nao juu ya **faili**, **udhibiti wa ufikiaji** zifuatazo zinaweza kutumika:
- **r** (kusoma)
- **w** (kuandika)
- **m** (ramani ya kumbukumbu kama executable)
- **k** (kufunga faili)
- **l** (kuunda viungo vigumu)
- **ix** (kutekeleza programu nyingine na programu mpya ikirithi sera)
- **Px** (kutekeleza chini ya wasifu mwingine, baada ya kusafisha mazingira)
- **Cx** (kutekeleza chini ya wasifu wa mtoto, baada ya kusafisha mazingira)
- **Ux** (kutekeleza bila vizuizi, baada ya kusafisha mazingira)
- **Vigezo** vinaweza kufafanuliwa katika wasifu na vinaweza kubadilishwa kutoka nje ya wasifu. Kwa mfano: @{PROC} na @{HOME} (ongeza #include \<tunables/global> kwenye faili la wasifu)
- **Sheria za kukataa zinasaidiwa kubadilisha sheria za kuruhusu**.

### aa-genprof

Ili kuanza kwa urahisi kuunda wasifu, apparmor inaweza kukusaidia. Inawezekana kufanya **apparmor ikague vitendo vilivyofanywa na binary kisha kukuruhusu uamue ni vitendo vipi unavyotaka kuruhusu au kukataa**.\
Unahitaji tu kukimbia:
```bash
sudo aa-genprof /path/to/binary
```
Kisha, katika console tofauti fanya vitendo vyote ambavyo binary kawaida hufanya:
```bash
/path/to/binary -a dosomething
```
Kisha, katika console ya kwanza bonyeza "**s**" na kisha katika vitendo vilivyorekodiwa onyesha kama unataka kupuuza, kuruhusu, au chochote. Unapomaliza bonyeza "**f**" na wasifu mpya utaundwa katika _/etc/apparmor.d/path.to.binary_

> [!NOTE]
> Kwa kutumia funguo za mshale unaweza kuchagua unachotaka kuruhusu/kukataa/chochote

### aa-easyprof

Unaweza pia kuunda kiolezo cha wasifu wa apparmor wa binary kwa kutumia:
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
> Kumbuka kwamba kwa kawaida katika wasifu ulioundwa hakuna kitu kinachoruhusiwa, hivyo kila kitu kinakataliwa. Itabidi uongeze mistari kama `/etc/passwd r,` ili kuruhusu binary kusoma `/etc/passwd` kwa mfano.

Unaweza kisha **kulazimisha** wasifu mpya na
```bash
sudo apparmor_parser -a /etc/apparmor.d/path.to.binary
```
### Kubadilisha wasifu kutoka kwa kumbukumbu

Zana ifuatayo itasoma kumbukumbu na kumuuliza mtumiaji kama anataka kuruhusu baadhi ya vitendo vilivyogunduliwa ambavyo ni marufuku:
```bash
sudo aa-logprof
```
> [!NOTE]
> Kwa kutumia funguo za mshale unaweza kuchagua kile unachotaka kuruhusu/kukataa/chochote

### Kusimamia Profaili
```bash
#Main profile management commands
apparmor_parser -a /etc/apparmor.d/profile.name #Load a new profile in enforce mode
apparmor_parser -C /etc/apparmor.d/profile.name #Load a new profile in complain mode
apparmor_parser -r /etc/apparmor.d/profile.name #Replace existing profile
apparmor_parser -R /etc/apparmor.d/profile.name #Remove profile
```
## Logs

Mfano wa **AUDIT** na **DENIED** logs kutoka _/var/log/audit/audit.log_ ya executable **`service_bin`**:
```bash
type=AVC msg=audit(1610061880.392:286): apparmor="AUDIT" operation="getattr" profile="/bin/rcat" name="/dev/pts/1" pid=954 comm="service_bin" requested_mask="r" fsuid=1000 ouid=1000
type=AVC msg=audit(1610061880.392:287): apparmor="DENIED" operation="open" profile="/bin/rcat" name="/etc/hosts" pid=954 comm="service_bin" requested_mask="r" denied_mask="r" fsuid=1000 ouid=0
```
Unaweza pia kupata taarifa hii kwa kutumia:
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
## Apparmor katika Docker

Kumbuka jinsi profaili **docker-profile** ya docker inavyopakiwa kwa default:
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
Kwa default **Apparmor docker-default profile** inatengenezwa kutoka [https://github.com/moby/moby/tree/master/profiles/apparmor](https://github.com/moby/moby/tree/master/profiles/apparmor)

**Muhtasari wa docker-default profile**:

- **Upatikanaji** wa **mtandao** wote
- **Hakuna uwezo** ulioelezwa (Hata hivyo, baadhi ya uwezo utaweza kuja kutokana na kuingiza sheria za msingi i.e. #include \<abstractions/base>)
- **Kuandika** kwenye faili yoyote ya **/proc** **hakuruhusiwi**
- **Madirisha**/**faili** mengine ya /**proc** na /**sys** **yanakataliwa** upatikanaji wa kusoma/kuandika/kufunga/kuunganisha/kutekeleza
- **Kuweka** **hakuruhusiwi**
- **Ptrace** inaweza kuendeshwa tu kwenye mchakato ambao umekandamizwa na **profil ya apparmor** sawa

Mara tu unapofanya **kazi na kontena la docker** unapaswa kuona matokeo yafuatayo:
```bash
1 processes are in enforce mode.
docker-default (825)
```
Kumbuka kwamba **apparmor hata itazuia uwezo wa haki** uliotolewa kwa kontena kwa default. Kwa mfano, itakuwa na uwezo wa **kuzuia ruhusa ya kuandika ndani ya /proc hata kama uwezo wa SYS_ADMIN umepatiwa** kwa sababu kwa default profaili ya apparmor ya docker inakataa ufikiaji huu:
```bash
docker run -it --cap-add SYS_ADMIN --security-opt seccomp=unconfined ubuntu /bin/bash
echo "" > /proc/stat
sh: 1: cannot create /proc/stat: Permission denied
```
Unahitaji **kuondoa apparmor** ili kupita vizuizi vyake:
```bash
docker run -it --cap-add SYS_ADMIN --security-opt seccomp=unconfined --security-opt apparmor=unconfined ubuntu /bin/bash
```
Kumbuka kwamba kwa kawaida **AppArmor** pia **itakataza kontena kuunganisha** folda kutoka ndani hata na uwezo wa SYS_ADMIN.

Kumbuka kwamba unaweza **kuongeza/kuondoa** **uwezo** kwa kontena la docker (hii bado itakuwa na mipaka kutokana na mbinu za ulinzi kama **AppArmor** na **Seccomp**):

- `--cap-add=SYS_ADMIN` toa uwezo wa `SYS_ADMIN`
- `--cap-add=ALL` toa uwezo wote
- `--cap-drop=ALL --cap-add=SYS_PTRACE` ondoa uwezo wote na toa tu `SYS_PTRACE`

> [!NOTE]
> Kwa kawaida, unapokuwa **unapata** kwamba una **uwezo wa kipaumbele** upatikanaji **ndani** ya **kontena** la **docker** **lakini** sehemu fulani ya **exploit haifanyi kazi**, hii itakuwa kwa sababu docker **apparmor itakuwa inazuia**.

### Mfano

(Mfano kutoka [**hapa**](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-2docker-engine/))

Ili kuonyesha kazi ya AppArmor, niliumba profaili mpya ya Docker "mydocker" na mstari ufuatao umeongezwa:
```
deny /etc/* w,   # deny write for all files directly in /etc (not in a subdir)
```
Ili kuamsha wasifu, tunahitaji kufanya yafuatayo:
```
sudo apparmor_parser -r -W mydocker
```
Ili orodhesha wasifu, tunaweza kufanya amri ifuatayo. Amri iliyo hapa chini inoorodhesha wasifu wangu mpya wa AppArmor.
```
$ sudo apparmor_status  | grep mydocker
mydocker
```
Kama inavyoonyeshwa hapa chini, tunapata kosa tunapojaribu kubadilisha “/etc/” kwani profaili ya AppArmor inazuia ufikiaji wa kuandika kwenye “/etc”.
```
$ docker run --rm -it --security-opt apparmor:mydocker -v ~/haproxy:/localhost busybox chmod 400 /etc/hostname
chmod: /etc/hostname: Permission denied
```
### AppArmor Docker Bypass1

Unaweza kupata ni **profil ya apparmor ipi inayoendesha kontena** kwa kutumia:
```bash
docker inspect 9d622d73a614 | grep lowpriv
"AppArmorProfile": "lowpriv",
"apparmor=lowpriv"
```
Kisha, unaweza kukimbia mstari ufuatao ili **kupata wasifu halisi unaotumika**:
```bash
find /etc/apparmor.d/ -name "*lowpriv*" -maxdepth 1 2>/dev/null
```
Katika hali ya ajabu unaweza **kubadilisha profaili ya apparmor docker na kuipakia upya.** Unaweza kuondoa vizuizi na "kuvuka" hizo.

### AppArmor Docker Bypass2

**AppArmor ni msingi wa njia**, hii inamaanisha kwamba hata kama inaweza kuwa **inalinda** faili ndani ya directory kama **`/proc`** ikiwa unaweza **kuweka jinsi kontena litakavyokuwa linaendeshwa**, unaweza **kuunganisha** directory ya proc ya mwenyeji ndani ya **`/host/proc`** na haitakuwa **inalindwa na AppArmor tena**.

### AppArmor Shebang Bypass

Katika [**bug hii**](https://bugs.launchpad.net/apparmor/+bug/1911431) unaweza kuona mfano wa jinsi **hata kama unazuia perl kuendeshwa na rasilimali fulani**, ikiwa tu unaunda script ya shell **ukitaja** katika mstari wa kwanza **`#!/usr/bin/perl`** na un **atekeleza faili moja kwa moja**, utaweza kutekeleza chochote unachotaka. Mfano:
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
