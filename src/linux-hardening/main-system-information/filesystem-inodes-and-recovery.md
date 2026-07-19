# Dosya Sistemi, Inode'lar ve Kurtarma

{{#include ../../banners/hacktricks-training.md}}

Dosya sistemi abuse işlemleri çoğunlukla görünür bir path ile arkasındaki nesne arasındaki ilişkinin karıştırılmasıyla ilgilidir. Disk image'ları başka bir dosya sistemini gizleyebilir, writable mount'lar privileged job'lar tarafından tüketilebilir, hardlink'ler aynı inode'a farklı bir ad üzerinden erişilmesini sağlayabilir ve silinmiş dosyalar açık bir file descriptor üzerinden hâlâ okunabilir.

Bu sayfa belirli bir lab veya target yerine tekniğe odaklanır.

## Disk Image'ları ve Loop Mount'lar

Normal bir file, eksiksiz bir dosya sistemi içerebilir. Bu nedenle backup image'ları, kopyalanmış block device'lar, VM artifact'leri veya yeniden adlandırılmış blob'lar; dışarıdan yararlı görünmeseler bile credential'ları, script'leri, SSH key'lerini, configuration file'larını veya flag'leri içerebilir.

Olası image'ları belirleyin:
```bash
file ./candidate
ls -lh ./candidate
blkid ./candidate 2>/dev/null
strings -a ./candidate | head -n 50
```
Mount işlemine izin veriliyorsa, bilinmeyen image'ları önce salt okunur olarak mount edin:
```bash
mkdir -p /tmp/imgmnt
sudo mount -o loop,ro ./candidate /tmp/imgmnt
find /tmp/imgmnt -maxdepth 3 -type f -ls 2>/dev/null
sudo umount /tmp/imgmnt
```
Mount işlemi kullanılamıyorsa dosya sistemi meta verilerini doğrudan inceleyin:
```bash
debugfs -R 'ls -l /' ./candidate 2>/dev/null
debugfs -R 'stat /' ./candidate 2>/dev/null
```
Bu teknik kullanışlıdır çünkü normal görünümlü bir dosyayı ikinci bir filesystem ağacına dönüştürür. Bunu kendi başına bir privilege escalation yöntemi olarak değil, gizli verileri kurtarmanın bir yolu olarak değerlendirin.

## Writable Mount Abuse

Writable bir mount, daha ayrıcalıklı bir context daha sonra içindeki bir şeye güvendiğinde tehlikeli hale gelir. Önemli soru yalnızca "buraya yazabilir miyim?" değil, aynı zamanda "daha sonra buradan kim okur, çalıştırır, import eder veya yükler?" sorusudur.

Writable mount'ları ve şüpheli consumer'ları bulun:
```bash
findmnt -o TARGET,SOURCE,FSTYPE,OPTIONS
find /mnt /media /srv /opt -xdev -type d -writable -ls 2>/dev/null
find /mnt /media /srv /opt -xdev -type f -writable -ls 2>/dev/null | head -n 50
grep -RniE 'cron|systemd|ExecStart|backup|hook|plugin|sh |bash |python' /mnt /media /srv /opt 2>/dev/null | head -n 50
```
Yaygın kötüye kullanım kalıpları:

- Ayrıcalıklı bir cron veya systemd unit'i, mount üzerinden yazılabilir bir script çalıştırır.
- Ayrıcalıklı bir servis, mount üzerinden plugin'ler, config dosyaları, template'ler veya yardımcı binary'ler yükler.
- Bir mount, SUID dosyaları içerir ve bunların değiştirilmesine, değiştirilerek yerine konulmasına veya path manipülasyonuna izin verir.
- Bir container veya chroot, kısıtlı ortamdan yazılabilir olan host-backed bir path sunar.

Genel doğrulama kalıbı:
```bash
find /mnt /media /srv /opt -xdev -perm -4000 -type f -ls 2>/dev/null
find /mnt /media /srv /opt -xdev -type f -writable -ls 2>/dev/null | head -n 50
```
Yetkili bir lab ortamında etkiyi kanıtlarken payload'ı gözlemlenebilir ve minimal tutun; örneğin `id` çıktısını geçici bir dosyaya yazın. Temel teknik, güvenilir ve yazılabilir bir konum üzerinden gecikmeli yürütmedir.

## Inode'lar ve Yol Karışıklığı

Bir inode, filesystem nesnesidir; path ise yalnızca ona işaret eden bir addır. Bu önemlidir, çünkü iki farklı path aynı inode'a işaret edebilir ve silinmiş bir pathname her zaman verilerin yok olduğu anlamına gelmez.

Dosyaları inode ve device üzerinden karşılaştırın:
```bash
ls -li /path/a /path/b
stat -c 'dev=%d inode=%i links=%h mode=%A owner=%U:%G path=%n' /path/a /path/b
```
Aynı inode için görünen tüm yolları bulun:
```bash
find / -xdev -samefile /path/to/file -ls 2>/dev/null
```
Yalnızca metadata'ya sahip olduğunuzda doğrudan inode numarasına göre arayın:
```bash
find / -xdev -inum <inode_number> -ls 2>/dev/null
```
Bu teknik, bir dosya beklenmeyen bir adla göründüğünde, bir uygulama bir yolu doğrulayıp başka bir yolu kullandığında veya ayrıcalıklı bir wrapper başka bir yerden de erişilebilen bir inode ile etkileşime girdiğinde kullanışlıdır.

## Hardlink Abuse

Hardlink'ler aynı inode için birden fazla ad oluşturur. Symlink'lerin yaptığı gibi bir hedef yola işaret etmezler; aynı dosya nesnesi için eşdeğer adlardır.

Birden fazla hardlink'e sahip SUID dosyalarını bulun:
```bash
find / -xdev -perm -4000 -type f -links +1 -ls 2>/dev/null
```
Şüpheli bir dosyayı inceleyin:
```bash
stat /path/to/suspicious
find / -xdev -samefile /path/to/suspicious -ls 2>/dev/null
```
Neden önemli:

- Hassas bir dosyaya daha az belirgin bir yol üzerinden erişilebilir.
- Bir SUID wrapper, ayrıcalıklı görünmeyen bir adın arkasına gizlenmiş olabilir.
- Bir pathname'i kaldıran cleanup işlemi, başka bir hardlink'i erişilebilir durumda bırakabilir.

Modern kernel'lar ve mount seçenekleri, bu tür kötüye kullanımları azaltmak için hardlink oluşturmayı kısıtlayabilir; ancak mevcut hardlink'ler yine de incelenmeye değerdir.

## Açık FD'ler Üzerinden Silinmiş Dosya Kurtarma

Bir process bir dosyayı açık tuttuğunda, pathname silindikten sonra bile dosya verileri erişilebilir durumda kalabilir. Linux, bu açık descriptor'ları `/proc/<pid>/fd/` altında gösterir.

Silinmiş açık dosyaları bulun:
```bash
ls -l /proc/*/fd/* 2>/dev/null | grep ' (deleted)' | head -n 50
lsof 2>/dev/null | grep deleted | head -n 50
```
İzinler elverdiğinde verileri kurtarın:
```bash
readlink /proc/<pid>/fd/<fd>
cp /proc/<pid>/fd/<fd> /tmp/recovered-file
file /tmp/recovered-file
```
Bu, silinmiş log'ları, geçici secret'ları, bırakılmış binary'leri, rotate edilmiş dosyaları veya çalıştırıldıktan sonra silinen script'leri kurtarmaya yönelik pratik bir tekniktir.

## ext Recovery With debugfs

ext filesystem'lerinde `debugfs`, inode metadata'sını inceleyebilir ve bazen bir filesystem image'ından dosya içeriklerini dump edebilir. Mümkün olduğunda bir kopya veya read-only image üzerinde çalışın.

Entry'leri listeleyin ve inode'ları inceleyin:
```bash
debugfs -R 'ls -l /' ./disk.img
debugfs -R 'stat <inode_number>' ./disk.img
debugfs -R 'ncheck <inode_number>' ./disk.img
```
Bilinen bir inode'un dökümünü al:
```bash
debugfs -R 'dump <inode_number> /tmp/recovered.bin' ./disk.img
file /tmp/recovered.bin
```
Bu, kurtarmanın garanti edildiği anlamına gelmez. Bu durum dosya sistemi durumuna, blokların yeniden kullanılıp kullanılmadığına ve metadata'nın hâlâ mevcut olup olmadığına bağlıdır. Teknik, normal path traversal'a güvenmeden inode düzeyindeki durumu incelemenizi sağladığı için yine de değerlidir.

## Inode Tükenmesi ve Sıralama

Inode tükenmesi, boş disk alanı kalmış olsa bile bir dosya sistemi dosya nesnelerinin tükenmesiyle gerçekleşir. Genellikle güvenilirlik sorunlarına neden olur, ancak incident response veya lab triage sırasında görülen garip davranışları da açıklayabilir.

Inode baskısını kontrol edin:
```bash
df -h
df -i
find /var /tmp /home -xdev -printf '%h\n' 2>/dev/null | sort | uniq -c | sort -n | tail
```
Inode numaraları ve zaman damgaları, basit lab ortamlarında etkinliğin yeniden oluşturulmasına da yardımcı olabilir:
```bash
find /path -xdev -printf '%i %TY-%Tm-%Td %TH:%TM %p\n' 2>/dev/null | sort -n | tail -n 50
find /path -xdev -newermt '2026-01-01' -ls 2>/dev/null
```
Sıralamayı kanıt olarak değil, ipucu olarak değerlendirin. Copy işlemleri, arşiv çıkarma, filesystem türü, geri yüklemeler ve eşzamanlı yazma işlemleri allocation kalıplarını değiştirebilir.

## Savunma Notları

- Analiz sırasında bilinmeyen image'ları read-only olarak mount edin.
- Privileged script'leri, service unit'lerini, plugin'leri ve helper path'lerini user-writable mount'ların dışında tutun.
- Operasyonel olarak uygun olduğunda `nosuid`, `nodev` ve `noexec` kullanın; ancak bunları eksiksiz bir sınır olarak değerlendirmeyin.
- Mümkün olduğunda `/proc/<pid>/fd` erişimini, process metadata'sını ve kullanıcılar arası process incelemesini kısıtlayın.
- Writable mount point'leri, privileged file'lara yönlendiren beklenmeyen hardlink'leri ve silinmiş ancak açık hassas file'ları izleyin.
