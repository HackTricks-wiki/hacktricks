# Dosya Sistemi, Inode'lar ve Kurtarma

{{#include ../../banners/hacktricks-training.md}}

Dosya sistemi abuse işlemleri genellikle görünür bir path ile arkasındaki nesne arasındaki ilişkinin karıştırılmasıyla ilgilidir. Disk imajları başka bir dosya sistemini gizleyebilir, yazılabilir mount'lar privileged job'lar tarafından tüketilebilir, hardlink'ler aynı inode'a farklı bir ad üzerinden erişim sağlayabilir ve silinmiş dosyalar açık bir file descriptor üzerinden hâlâ okunabilir.

Bu sayfa belirli bir lab veya target yerine tekniğe odaklanır.

## Disk İmajları ve Loop Mount'ları

Normal bir file, eksiksiz bir dosya sistemi içerebilir. Bu nedenle backup imajları, kopyalanmış block device'lar, VM artifact'leri veya yeniden adlandırılmış blob'lar; dışarıdan yararlı görünmeseler bile credential'lar, script'ler, SSH key'leri, configuration file'ları veya flag'ler içerebilir.

Olası imajları belirleyin:
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
Mount işlemi kullanılamıyorsa, dosya sistemi meta verilerini doğrudan inceleyin:
```bash
debugfs -R 'ls -l /' ./candidate 2>/dev/null
debugfs -R 'stat /' ./candidate 2>/dev/null
```
Bu teknik, normal görünümlü bir dosyayı ikinci bir filesystem tree'ye dönüştürdüğü için kullanışlıdır. Bunu, kendi başına bir privilege escalation yöntemi olarak değil, gizli verileri kurtarmanın bir yolu olarak değerlendirin.

## Writable Mount Abuse

Daha ayrıcalıklı bir context, içindeki bir şeye daha sonra güvendiğinde writable mount tehlikeli hâle gelir. Önemli soru yalnızca "buraya yazabilir miyim?" değil, "daha sonra buradan kim okur, çalıştırır, import eder veya yükler?" sorusudur.

Writable mount'ları ve şüpheli tüketicileri bulun:
```bash
findmnt -o TARGET,SOURCE,FSTYPE,OPTIONS
find /mnt /media /srv /opt -xdev -type d -writable -ls 2>/dev/null
find /mnt /media /srv /opt -xdev -type f -writable -ls 2>/dev/null | head -n 50
grep -RniE 'cron|systemd|ExecStart|backup|hook|plugin|sh |bash |python' /mnt /media /srv /opt 2>/dev/null | head -n 50
```
Yaygın kötüye kullanım kalıpları:

- Ayrıcalıklı bir cron veya systemd unit, mount içindeki yazılabilir bir betiği çalıştırır.
- Ayrıcalıklı bir servis, mount içinden plugin'ler, yapılandırmalar, şablonlar veya yardımcı binary'ler yükler.
- Bir mount, SUID dosyaları içerir ve bunların değiştirilmesine, değiştirilerek başka dosyayla yer değiştirilmesine veya yol manipülasyonuna izin verir.
- Bir container veya chroot, kısıtlı ortamdan yazılabilen host-backed bir yolu açığa çıkarır.

Genel doğrulama kalıbı:
```bash
find /mnt /media /srv /opt -xdev -perm -4000 -type f -ls 2>/dev/null
find /mnt /media /srv /opt -xdev -type f -writable -ls 2>/dev/null | head -n 50
```
Yetkili bir lab ortamında etkiyi kanıtlarken payload'ı gözlemlenebilir ve minimal tutun; örneğin `id` çıktısını geçici bir dosyaya yazın. Temel teknik, güvenilir ve yazılabilir bir konum üzerinden gecikmeli çalıştırmadır.

## Inode'lar ve Path Confusion

Bir inode, filesystem nesnesidir; path ise yalnızca ona işaret eden bir addır. Bu önemlidir çünkü iki farklı path aynı inode'a işaret edebilir ve silinmiş bir pathname her zaman verilerin yok olduğu anlamına gelmez.

Dosyaları inode ve device bilgilerine göre karşılaştırın:
```bash
ls -li /path/a /path/b
stat -c 'dev=%d inode=%i links=%h mode=%A owner=%U:%G path=%n' /path/a /path/b
```
Aynı inode için görünen her pathname'i bulun:
```bash
find / -xdev -samefile /path/to/file -ls 2>/dev/null
```
Yalnızca meta veriye sahip olduğunuzda doğrudan inode numarasına göre arayın:
```bash
find / -xdev -inum <inode_number> -ls 2>/dev/null
```
Bu teknik, bir dosya beklenmeyen bir adla göründüğünde, bir uygulama bir path'i doğrulayıp başka bir path'i kullandığında veya ayrıcalıklı bir wrapper başka bir yerde de erişilebilen bir inode ile etkileşime girdiğinde kullanışlıdır.

## Hardlink Abuse

Hardlink'ler aynı inode için birden fazla ad oluşturur. Symlink'ler gibi bir hedef path'e işaret etmezler; aynı dosya nesnesi için eşdeğer adlardır.

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
- Bir pathname'i kaldıran temizlik işlemi, başka bir hardlink'i etkin durumda bırakabilir.

Modern kernel'ler ve mount seçenekleri, bu tür kötüye kullanımları azaltmak için hardlink oluşturmayı kısıtlayabilir; ancak mevcut hardlink'ler yine de incelenmeye değerdir.

## Açık FD'ler Üzerinden Silinmiş Dosya Kurtarma

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
Bu, silinen logları, geçici secret'ları, bırakılmış binary'leri, rotate edilmiş dosyaları veya çalıştırıldıktan sonra kaldırılan script'leri kurtarmaya yönelik pratik bir tekniktir.

## ext Kurtarma With debugfs

ext dosya sistemlerinde `debugfs`, inode metadata'sını inceleyebilir ve bazen bir filesystem image'ından dosya içeriklerini dökebilir. Mümkün olduğunda bir kopya veya read-only image üzerinde çalışın.

Girdileri listeleyin ve inode'ları inceleyin:
```bash
debugfs -R 'ls -l /' ./disk.img
debugfs -R 'stat <inode_number>' ./disk.img
debugfs -R 'ncheck <inode_number>' ./disk.img
```
Bilinen bir inode'un dökümünü alın:
```bash
debugfs -R 'dump <inode_number> /tmp/recovered.bin' ./disk.img
file /tmp/recovered.bin
```
Bu, kurtarmanın garanti edildiği anlamına gelmez. Sonuç; filesystem durumuna, blokların yeniden kullanılıp kullanılmadığına ve metadata'nın hâlâ mevcut olup olmadığına bağlıdır. Bu teknik yine de değerlidir; çünkü normal path traversal'a güvenmeden inode düzeyindeki durumu incelemenizi sağlar.

## Inode Tükenmesi ve Sıralama

Inode tükenmesi, boş disk alanı kalmış olsa bile bir filesystem dosya nesneleri tükendiğinde meydana gelir. Genellikle reliability hatalarına neden olur, ancak incident response veya lab triage sırasında görülen garip davranışları da açıklayabilir.

Inode baskısını kontrol edin:
```bash
df -h
df -i
find /var /tmp /home -xdev -printf '%h\n' 2>/dev/null | sort | uniq -c | sort -n | tail
```
Inode numaraları ve zaman damgaları, basit laboratuvar ortamlarında etkinliğin yeniden oluşturulmasına da yardımcı olabilir:
```bash
find /path -xdev -printf '%i %TY-%Tm-%Td %TH:%TM %p\n' 2>/dev/null | sort -n | tail -n 50
find /path -xdev -newermt '2026-01-01' -ls 2>/dev/null
```
Sıralamayı kanıt olarak değil, bir ipucu olarak değerlendirin. Kopyalama işlemleri, arşiv çıkarma, dosya sistemi türü, geri yüklemeler ve eşzamanlı yazma işlemleri tahsis kalıplarını değiştirebilir.

## Savunma Notları

- Analiz sırasında bilinmeyen imajları salt okunur olarak mount edin.
- Ayrıcalıklı script'leri, service unit'lerini, eklentileri ve yardımcı yolları kullanıcı tarafından yazılabilir mount'ların dışında tutun.
- Operasyonel açıdan uygun olduğunda `nosuid`, `nodev` ve `noexec` kullanın; ancak bunları eksiksiz bir sınır olarak değerlendirmeyin.
- Mümkün olduğunda `/proc/<pid>/fd` erişimini, process metadata'sını ve kullanıcılar arası process incelemesini kısıtlayın.
- Yazılabilir mount noktalarını, ayrıcalıklı dosyalara işaret eden beklenmedik hardlink'leri ve silinmiş ancak açık durumdaki hassas dosyaları izleyin.
{{#include ../../banners/hacktricks-training.md}}
