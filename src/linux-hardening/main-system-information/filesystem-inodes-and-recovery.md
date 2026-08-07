# Dosya Sistemi, Inode'lar ve Kurtarma

{{#include ../../banners/hacktricks-training.md}}

Filesystem abuse genellikle görünür bir path ile arkasındaki nesne arasındaki ilişkiyi karıştırmaya dayanır. Disk image'ları başka bir filesystem gizleyebilir, writable mount'lar privileged job'lar tarafından tüketilebilir, hardlink'ler aynı inode'a farklı bir ad üzerinden erişim sağlayabilir ve silinmiş dosyalar açık bir file descriptor üzerinden hâlâ okunabilir.

Bu sayfa belirli bir lab veya target yerine tekniğe odaklanır.

## Disk Image'ları ve Loop Mount'lar

Normal bir dosya eksiksiz bir filesystem içerebilir. Bu nedenle backup image'ları, kopyalanmış block device'lar, VM artifact'leri veya yeniden adlandırılmış blob'lar; dışarıdan kullanışlı görünmeseler bile credential'lar, script'ler, SSH key'leri, configuration file'ları veya flag'ler içerebilir.

Olası image'ları belirleyin:
```bash
file ./candidate
ls -lh ./candidate
blkid ./candidate 2>/dev/null
strings -a ./candidate | head -n 50
```
Mount işlemine izin veriliyorsa, bilinmeyen imajları önce salt okunur olarak mount edin:
```bash
mkdir -p /tmp/imgmnt
sudo mount -o loop,ro ./candidate /tmp/imgmnt
find /tmp/imgmnt -maxdepth 3 -type f -ls 2>/dev/null
sudo umount /tmp/imgmnt
```
Mount işlemi kullanılamıyorsa, filesystem metadata'sını doğrudan inceleyin:
```bash
debugfs -R 'ls -l /' ./candidate 2>/dev/null
debugfs -R 'stat /' ./candidate 2>/dev/null
```
Teknik, normal görünümlü bir dosyayı ikinci bir filesystem ağacına dönüştürdüğü için kullanışlıdır. Bunu kendi başına bir privilege escalation yöntemi olarak değil, gizli verileri kurtarmanın bir yolu olarak değerlendirin.

## Writable Mount Abuse

Daha ayrıcalıklı bir context daha sonra içindeki bir şeye güvendiğinde, writable bir mount tehlikeli hâle gelir. Önemli soru yalnızca "buraya yazabilir miyim?" değil, aynı zamanda "buradan daha sonra kim okur, execute eder, import eder veya yükler?" sorusudur.

Writable mount'ları ve şüpheli consumer'ları bulun:
```bash
findmnt -o TARGET,SOURCE,FSTYPE,OPTIONS
find /mnt /media /srv /opt -xdev -type d -writable -ls 2>/dev/null
find /mnt /media /srv /opt -xdev -type f -writable -ls 2>/dev/null | head -n 50
grep -RniE 'cron|systemd|ExecStart|backup|hook|plugin|sh |bash |python' /mnt /media /srv /opt 2>/dev/null | head -n 50
```
Yaygın abuse kalıpları:

- Privileged bir cron veya systemd unit'i mount içindeki writable bir script'i çalıştırır.
- Privileged bir servis, mount içinden plugin'ler, config dosyaları, template'ler veya helper binary'leri yükler.
- Bir mount, SUID dosyaları içerir ve modification, replacement veya path manipulation işlemlerine izin verir.
- Bir container veya chroot, restricted environment içinden writable olan host-backed bir path'i açığa çıkarır.

Genel validation kalıbı:
```bash
find /mnt /media /srv /opt -xdev -perm -4000 -type f -ls 2>/dev/null
find /mnt /media /srv /opt -xdev -type f -writable -ls 2>/dev/null | head -n 50
```
Yetkili bir laboratuvarda etkiyi kanıtlarken payload'u gözlemlenebilir ve minimal tutun; örneğin `id` çıktısını geçici bir dosyaya yazın. Temel teknik, güvenilen ve yazılabilir bir konum üzerinden gecikmeli çalıştırmadır.

## Inode'lar ve Yol Karışıklığı

Bir inode, filesystem nesnesidir; path ise yalnızca ona işaret eden bir addır. Bu önemlidir, çünkü iki farklı path aynı inode'a işaret edebilir ve silinmiş bir pathname her zaman verilerin yok olduğu anlamına gelmez.

Dosyaları inode ve device'a göre karşılaştırın:
```bash
ls -li /path/a /path/b
stat -c 'dev=%d inode=%i links=%h mode=%A owner=%U:%G path=%n' /path/a /path/b
```
Aynı inode için görünen tüm pathname'leri bulun:
```bash
find / -xdev -samefile /path/to/file -ls 2>/dev/null
```
Yalnızca metadata'ya sahip olduğunuzda doğrudan inode numarasına göre arayın:
```bash
find / -xdev -inum <inode_number> -ls 2>/dev/null
```
Bu technique, bir dosya beklenmedik bir adla göründüğünde, bir uygulama bir path'i doğrulayıp başka bir path'i kullandığında veya ayrıcalıklı bir wrapper başka bir yerden de erişilebilen bir inode ile etkileşime girdiğinde kullanışlıdır.

## Hardlink Abuse

Hardlinks, aynı inode için birden fazla ad oluşturur. Symlink'lerde olduğu gibi bir hedef path'i göstermezler; aynı dosya nesnesi için eşdeğer adlardır.

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

- Hassas bir dosyaya daha az belirgin bir path üzerinden erişilebilir.
- Bir SUID wrapper, privileged görünmeyen bir adın arkasına gizlenmiş olabilir.
- Bir pathname'i kaldıran cleanup işlemi, başka bir hardlink'i etkin durumda bırakabilir.

Modern kernel'ler ve mount seçenekleri, bu tür abuse'ları azaltmak için hardlink oluşturmayı kısıtlayabilir; ancak mevcut hardlink'ler yine de incelenmeye değerdir.

## Open FD'ler Üzerinden Silinmiş Dosya Kurtarma

Bir process bir dosyayı açık tuttuğunda, pathname silindikten sonra bile dosya verileri kullanılabilir durumda kalabilir. Linux, bu açık descriptor'ları `/proc/<pid>/fd/` altında sunar.

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
Bu, silinen log'ları, geçici secret'ları, bırakılmış binary dosyaları, rotate edilmiş dosyaları veya çalıştırıldıktan sonra kaldırılan script'leri kurtarmaya yönelik pratik bir tekniktir.

## debugfs ile ext Kurtarma

ext filesystem'lerinde `debugfs`, inode metadata'sını inceleyebilir ve bazen bir filesystem image'ından dosya içeriklerini dökebilir. Mümkün olduğunda bir kopya veya read-only image üzerinde çalışın.

Girdileri listeleyin ve inode'ları inceleyin:
```bash
debugfs -R 'ls -l /' ./disk.img
debugfs -R 'stat <inode_number>' ./disk.img
debugfs -R 'ncheck <inode_number>' ./disk.img
```
Bilinen bir inode'u dök:
```bash
debugfs -R 'dump <inode_number> /tmp/recovered.bin' ./disk.img
file /tmp/recovered.bin
```
Bu, kurtarmanın garanti edildiği anlamına gelmez. Bu durum dosya sisteminin durumuna, blokların yeniden kullanılıp kullanılmadığına ve metadata'nın hâlâ mevcut olup olmadığına bağlıdır. Bu teknik yine de değerlidir; çünkü normal path traversal'a güvenmeden inode düzeyindeki durumu incelemenizi sağlar.

## Inode Tükenmesi ve Sıralama

Inode tükenmesi, boş disk alanı kalmış olsa bile dosya sisteminin dosya nesneleri tükendiğinde meydana gelir. Genellikle güvenilirlik sorunlarına yol açar, ancak incident response veya lab triage sırasında garip davranışları açıklamaya da yardımcı olabilir.

Inode baskısını kontrol edin:
```bash
df -h
df -i
find /var /tmp /home -xdev -printf '%h\n' 2>/dev/null | sort | uniq -c | sort -n | tail
```
Inode numaraları ve zaman damgaları, basit laboratuvar ortamlarındaki etkinlikleri yeniden oluşturmaya da yardımcı olabilir:
```bash
find /path -xdev -printf '%i %TY-%Tm-%Td %TH:%TM %p\n' 2>/dev/null | sort -n | tail -n 50
find /path -xdev -newermt '2026-01-01' -ls 2>/dev/null
```
Sıralamayı kanıt olarak değil, ipucu olarak değerlendirin. Kopyalama işlemleri, archive çıkarma, filesystem türü, geri yüklemeler ve eşzamanlı yazma işlemleri allocation patterns'lerini değiştirebilir.

## Savunma Notları

- Bilinmeyen image'ları analiz sırasında read-only olarak mount edin.
- Privileged script'leri, service unit'lerini, plugin'leri ve helper path'lerini user-writable mount'ların dışında tutun.
- Operasyonel olarak uygun olduğunda `nosuid`, `nodev` ve `noexec` kullanın; ancak bunları eksiksiz bir boundary olarak değerlendirmeyin.
- `/proc/<pid>/fd` erişimini, process metadata'sını ve mümkün olduğunda user'lar arası process inspection'ı kısıtlayın.
- Writable mount point'leri, privileged file'lara giden beklenmedik hardlink'leri ve silinmiş ancak açık durumdaki hassas file'ları monitor edin.

{{#include ../../banners/hacktricks-training.md}}
