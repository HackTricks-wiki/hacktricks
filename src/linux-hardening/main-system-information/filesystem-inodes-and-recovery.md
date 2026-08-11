# Dosya Sistemi, Inode'lar ve Kurtarma

{{#include ../../banners/hacktricks-training.md}}

Dosya sistemi abuse'u çoğu zaman görünür bir yol ile arkasındaki nesne arasındaki ilişkiyi karıştırmaya dayanır.

Disk image'ları başka bir dosya sistemini gizleyebilir.<sup>[[1]](#references)</sup> Writable mount'lar privileged job'lar tarafından tüketilebilir.

Hardlink'ler aynı inode'u farklı bir ad üzerinden açığa çıkarabilir.<sup>[[3]](#references)</sup> Silinmiş dosyalar, açık bir file descriptor üzerinden hâlâ okunabilir olabilir.<sup>[[5]](#references)[[6]](#references)</sup>

Bu sayfa, belirli bir lab veya target yerine tekniğe odaklanır.

## Disk Image'ları ve Loop Mount'lar

Normal bir dosya eksiksiz bir dosya sistemi içerebilir; bu nedenle bir disk image mount edildiğinde ikinci bir dosya sistemi ağacını açığa çıkarabilir.<sup>[[1]](#references)</sup>

Backup image'ları, kopyalanmış block device'lar, VM artifact'leri veya yeniden adlandırılmış blob'lar; dışarıdan yararlı görünmeseler bile credential'lar, script'ler, SSH key'leri, configuration file'ları veya flag'ler içerebilir.

Olası image'ları sınıflandırmak için `file`, tanınan dosya sistemi metadata'sını incelemek için `blkid` ve dosyanın tamamını yazdırılabilir diziler açısından taramak için `strings -a` kullanın.<sup>[[10]](#references)[[11]](#references)[[12]](#references)</sup>
```bash
file ./candidate
ls -lh ./candidate
blkid ./candidate 2>/dev/null
strings -a ./candidate | head -n 50
```
Mounting işlemine izin verildiğinde, imajın salt okunur olarak bağlanması için `ro` ile bir loop mount kullanın; aşağıdaki `find` komutu inceleme derinliğini ve dosya türünü sınırlar.<sup>[[1]](#references)[[4]](#references)</sup>
```bash
mkdir -p /tmp/imgmnt
sudo mount -o loop,ro ./candidate /tmp/imgmnt
find /tmp/imgmnt -maxdepth 3 -type f -ls 2>/dev/null
sudo umount /tmp/imgmnt
```
Mounting kullanılamıyorsa ve image ext2/ext3/ext4 ise metadata'sını `debugfs` ile doğrudan inceleyin.<sup>[[2]](#references)</sup>
```bash
debugfs -R 'ls -l /' ./candidate 2>/dev/null
debugfs -R 'stat /' ./candidate 2>/dev/null
```
Teknik, normal görünümlü bir dosyayı ikinci bir dosya sistemi ağacına dönüştürdüğü için kullanışlıdır.<sup>[[1]](#references)</sup> Bunu, kendi başına bir privilege escalation olarak değil, gizli verileri kurtarmanın bir yolu olarak değerlendirin.

## Writable Mount Abuse

Yazılabilir bir mount, daha ayrıcalıklı bir context daha sonra içindeki bir şeye güvendiğinde tehlikeli hâle gelir. Önemli soru yalnızca "buraya yazabilir miyim?" değil, "buradan daha sonra kim okur, çalıştırır, import eder veya yükler?" sorusudur.

Bağlı dosya sistemlerini ve seçeneklerini incelemek için `findmnt` kullanın.<sup>[[9]](#references)</sup>

Belgelenmiş `find` permission, type ve filesystem-boundary predicate'lerini kullanarak yazılabilir mount'ları ve şüpheli tüketicileri bulun; ardından olası tüketici yapılandırmalarını aramak için recursive `grep` kullanın.<sup>[[4]](#references)[[20]](#references)</sup>
```bash
findmnt -o TARGET,SOURCE,FSTYPE,OPTIONS
find /mnt /media /srv /opt -xdev -type d -writable -ls 2>/dev/null
find /mnt /media /srv /opt -xdev -type f -writable -ls 2>/dev/null | head -n 50
grep -RniE 'cron|systemd|ExecStart|backup|hook|plugin|sh |bash |python' /mnt /media /srv /opt 2>/dev/null | head -n 50
```
Yaygın kötüye kullanım kalıpları:

- Bir cron job veya systemd service, mount üzerinden yazılabilir bir script çalıştırır.<sup>[[13]](#references)[[14]](#references)</sup>
- Privileged bir service, mount üzerinden plugin'ler, config dosyaları, template'ler veya yardımcı binary'ler yükler.
- Bir mount, SUID dosyaları içerir ve bunların değiştirilmesine, değiştirilerek yerlerine başka dosyalar konulmasına veya path manipülasyonuna izin verir.
- Bir container veya chroot, restricted environment içinden yazılabilen host-backed bir path sunar. Mount namespaces, birbirinden farklı mount hiyerarşileri sağlarken `chroot()` yalnızca pathname çözümlemesini değiştirir ve tam bir sandbox değildir.<sup>[[15]](#references)[[16]](#references)</sup>

Aynı `find` predicates'lerini kullanan generic validation pattern'i.<sup>[[4]](#references)</sup>
```bash
find /mnt /media /srv /opt -xdev -perm -4000 -type f -ls 2>/dev/null
find /mnt /media /srv /opt -xdev -type f -writable -ls 2>/dev/null | head -n 50
```
Yetkili bir lab ortamında impact'i kanıtlarken payload'ı gözlemlenebilir ve minimal tutun; örneğin `id` çıktısını geçici bir dosyaya yazın.<sup>[[23]](#references)</sup> Temel teknik, trusted writable location üzerinden gecikmeli çalıştırmadır.

## Inodes and Path Confusion

inode, filesystem nesnesidir; path ise yalnızca ona işaret eden bir addır. Device ve inode metadata'sı, dosya sistemleri arasındaki nesneleri ayırt etmenizi sağlarken link count'ları birden fazla hard link'i ortaya çıkarır.<sup>[[3]](#references)</sup> Bir process dosyayı hâlâ açık tuttuğu sürece silinmiş bir pathname, verilerin her zaman yok olduğu anlamına gelmez.<sup>[[5]](#references)</sup>

Aşağıdaki `find` predicate'leri inode identity'sini, link count'larını, device boundaries'lerini ve timestamp'leri karşılaştırır.<sup>[[4]](#references)</sup>

`ls -i` ve `stat` metadata format'larını kullanarak dosyaları inode ve device'a göre karşılaştırın.<sup>[[17]](#references)[[18]](#references)</sup>
```bash
ls -li /path/a /path/b
stat -c 'dev=%d inode=%i links=%h mode=%A owner=%U:%G path=%n' /path/a /path/b
```
Aynı inode için görünen tüm path adlarını `find -samefile` ile bulun.<sup>[[4]](#references)</sup>
```bash
find / -xdev -samefile /path/to/file -ls 2>/dev/null
```
Yalnızca meta veriye sahip olduğunuzda `find -inum` ile doğrudan inode numarasına göre arama yapın.<sup>[[4]](#references)</sup>
```bash
find / -xdev -inum <inode_number> -ls 2>/dev/null
```
Bu teknik, bir dosya beklenmeyen bir adla göründüğünde, bir uygulama bir yolu doğrulayıp başka bir yolu kullandığında veya ayrıcalıklı bir wrapper başka bir yerden de erişilebilen bir inode ile etkileşime girdiğinde kullanışlıdır.

## Hardlink Abuse

Hardlink'ler aynı inode için birden fazla ad oluşturur. Symlink'lerde olduğu gibi bir hedef yola işaret etmezler; aynı dosya nesnesi için eşdeğer adlardır.<sup>[[3]](#references)</sup>

`find` komutunun izin ve bağlantı sayısı yüklemlerini kullanarak birden fazla hardlink'i olan SUID dosyalarını bulun.<sup>[[4]](#references)</sup>
```bash
find / -xdev -perm -4000 -type f -links +1 -ls 2>/dev/null
```
Bir şüpheli dosyayı `stat` ve `find -samefile` ile inceleyin.<sup>[[4]](#references)[[17]](#references)</sup>
```bash
stat /path/to/suspicious
find / -xdev -samefile /path/to/suspicious -ls 2>/dev/null
```
Neden önemli:

- Hassas bir dosyaya daha az belirgin bir yol üzerinden erişilebilir.
- Bir SUID wrapper, ayrıcalıklı görünmeyen bir adın arkasına gizlenmiş olabilir.
- Bir pathname'i kaldıran temizlik işlemi, başka bir hardlink'i aktif bırakabilir.

Linux'un `fs.protected_hardlinks` sysctl'i, ayrıcalık sınırları arasındaki hardlink oluşturmayı kısıtlayabilir.<sup>[[7]](#references)</sup> Mevcut hardlink'ler yine de incelenmelidir.

## Açık FD'ler Üzerinden Silinmiş Dosya Kurtarma

Bir process bir dosyayı açık tuttuğunda, son pathname'ini kaldırmak dosyanın son descriptor kapanana kadar varlığını sürdürmesine neden olur; Linux bu descriptor'ları `/proc/<pid>/fd/` altında sunar.<sup>[[5]](#references)[[6]](#references)</sup>

`/proc` descriptor'larını listeleyip açık dosya çıktısını filtreleyerek silinmiş açık dosyaları bulun.<sup>[[5]](#references)[[6]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>
```bash
ls -l /proc/*/fd/* 2>/dev/null | grep ' (deleted)' | head -n 50
lsof 2>/dev/null | grep deleted | head -n 50
```
Bu bağlantılar üzerinden kurtarma, `/proc/<pid>/fd` başvurusunun ptrace erişim kontrollerine ve dosya izinlerine tabi olması nedeniyle izinlere bağlıdır.<sup>[[6]](#references)</sup>

İzin verildiğinde `readlink`, descriptor hedefini gösterir ve `cp` içeriğini kopyalar.<sup>[[21]](#references)[[22]](#references)</sup>
```bash
readlink /proc/<pid>/fd/<fd>
cp /proc/<pid>/fd/<fd> /tmp/recovered-file
file /tmp/recovered-file
```
Bu, silinmiş logları, geçici secret'ları, bırakılmış binary'leri, rotate edilmiş dosyaları veya çalıştırıldıktan sonra kaldırılmış script'leri kurtarmaya yönelik pratik bir tekniktir.

## ext Recovery With debugfs

ext2/ext3/ext4 dosya sistemlerinde `debugfs`, bir block device veya image üzerinden inode metadata'sını inceleyebilir ve inode içeriklerini dökebilir; `-w` olmadan dosya sistemini salt okunur olarak açar.<sup>[[2]](#references)</sup> Mümkün olduğunda bir kopya veya salt okunur bir image üzerinde çalışın.

Directory listing'leri, inode durumunu ve inode-to-path kontrollerini almak için `debugfs` istekleriyle girdileri listeleyin ve inode'ları inceleyin.<sup>[[2]](#references)</sup>
```bash
debugfs -R 'ls -l /' ./disk.img
debugfs -R 'stat <inode_number>' ./disk.img
debugfs -R 'ncheck <inode_number>' ./disk.img
```
Bilinen bir inode'u `debugfs dump` komutuyla dump edin, ardından kurtarılan çıktıyı `file` ile sınıflandırın.<sup>[[2]](#references)[[10]](#references)</sup>
```bash
debugfs -R 'dump <inode_number> /tmp/recovered.bin' ./disk.img
file /tmp/recovered.bin
```
Bu, kurtarmanın garanti edildiği anlamına gelmez. Bu durum dosya sisteminin durumuna, blokların yeniden kullanılıp kullanılmadığına ve metadata'nın hâlâ mevcut olup olmadığına bağlıdır. ext3/ext4 için `debugfs` kılavuzu, serbest bırakılan inode veri blokları artık kullanılamadığından silinmiş inode kurtarmanın başarısız olabileceğini belirtir.<sup>[[2]](#references)</sup> Bu teknik yine de değerlidir; çünkü normal yol traversal'ına güvenmeden inode düzeyindeki durumu incelemenizi sağlar.

## Inode Exhaustion and Ordering

Inode tükenmesi, boş disk alanı kalmış olsa bile bir dosya sisteminin dosya düğümlerini tüketmesiyle gerçekleşir.<sup>[[8]](#references)[[17]](#references)</sup> Bu durum genellikle güvenilirlik sorunlarına yol açar; ancak olay müdahalesi veya lab triyajı sırasında görülen garip davranışları da açıklayabilir.

Blok kullanımını değil, inode bilgilerini raporlamak için `df -i` kullanın.<sup>[[8]](#references)</sup>

`df` ve dizin üst öğelerinin `find` ile sayımını kullanarak inode baskısını kontrol edin.<sup>[[4]](#references)[[8]](#references)</sup>
```bash
df -h
df -i
find /var /tmp /home -xdev -printf '%h\n' 2>/dev/null | sort | uniq -c | sort -n | tail
```
Inode numaraları ve zaman damgaları, basit lab ortamlarında etkinliklerin yeniden oluşturulmasına da yardımcı olabilir.

Aşağıdaki `find` biçim yönergeleri bu alanları ortaya çıkarır.<sup>[[4]](#references)</sup>
```bash
find /path -xdev -printf '%i %TY-%Tm-%Td %TH:%TM %p\n' 2>/dev/null | sort -n | tail -n 50
find /path -xdev -newermt '2026-01-01' -ls 2>/dev/null
```
Sıralamayı bir ipucu olarak değerlendirin, kanıt olarak değil. Copy işlemleri, archive çıkarma, filesystem türü, geri yüklemeler ve eşzamanlı yazma işlemleri allocation pattern'lerini değiştirebilir.

## Defensive Notes

- Bilinmeyen image'ları analiz sırasında read-only olarak mount edin.<sup>[[1]](#references)</sup>
- Privileged script'leri, service unit'lerini, plugin'leri ve helper path'lerini user-writable mount'ların dışında tutun.
- Operasyonel olarak uygun olduğunda `nosuid`, `nodev` ve `noexec` kullanın; bu seçenekler mount üzerindeki set-ID/capability execution'ını, device yorumlamasını veya doğrudan binary execution'ını devre dışı bırakır.<sup>[[1]](#references)</sup> Bunları eksiksiz bir boundary olarak değerlendirmeyin.
- `/proc/<pid>/fd` erişimini kısıtlayın; bu link'lerin dereference edilmesi ptrace access check'leri ve file permission'ları tarafından kontrol edilir.<sup>[[6]](#references)</sup> Daha geniş process metadata'sını ve kullanıcılar arası inspection'ı mümkün olduğunca kısıtlayın.
- Writable mount point'lerini, privileged file'lara işaret eden beklenmedik hardlink'leri ve silinmiş ancak açık durumdaki hassas file'ları monitor edin.

## References

- [1] [mount(8) — Linux manual page](https://man7.org/linux/man-pages/man8/mount.8.html)
- [2] [debugfs(8) — Linux manual page](https://man7.org/linux/man-pages/man8/debugfs.8.html)
- [3] [inode(7) — Linux manual page](https://man7.org/linux/man-pages/man7/inode.7.html)
- [4] [find(1) — Linux manual page](https://man7.org/linux/man-pages/man1/find.1.html)
- [5] [unlink(2) — Linux manual page](https://man7.org/linux/man-pages/man2/unlink.2.html)
- [6] [proc_pid_fd(5) — Linux manual page](https://man7.org/linux/man-pages/man5/proc_pid_fd.5.html)
- [7] [/proc/sys/fs/ için Documentation — Linux Kernel documentation](https://www.kernel.org/doc/html/latest/admin-guide/sysctl/fs.html)
- [8] [df(1) — Linux manual page](https://man7.org/linux/man-pages/man1/df.1.html)
- [9] [findmnt(8) — Linux manual page](https://man7.org/linux/man-pages/man8/findmnt.8.html)
- [10] [file(1) — Linux manual page](https://man7.org/linux/man-pages/man1/file.1.html)
- [11] [blkid(8) — Linux manual page](https://man7.org/linux/man-pages/man8/blkid.8.html)
- [12] [strings(1) — Linux manual page](https://man7.org/linux/man-pages/man1/strings.1.html)
- [13] [crontab(5) — Linux manual page](https://man7.org/linux/man-pages/man5/crontab.5.html)
- [14] [systemd.service(5) — Linux manual page](https://man7.org/linux/man-pages/man5/systemd.service.5.html)
- [15] [mount_namespaces(7) — Linux manual page](https://man7.org/linux/man-pages/man7/mount_namespaces.7.html)
- [16] [chroot(2) — Linux manual page](https://man7.org/linux/man-pages/man2/chroot.2.html)
- [17] [stat(1) — Linux manual page](https://man7.org/linux/man-pages/man1/stat.1.html)
- [18] [ls(1) — Linux manual page](https://man7.org/linux/man-pages/man1/ls.1.html)
- [19] [lsof(8) — Linux manual page](https://man7.org/linux/man-pages/man8/lsof.8.html)
- [20] [grep(1) — Linux manual page](https://man7.org/linux/man-pages/man1/grep.1.html)
- [21] [readlink(1) — Linux manual page](https://man7.org/linux/man-pages/man1/readlink.1.html)
- [22] [cp(1) — Linux manual page](https://man7.org/linux/man-pages/man1/cp.1.html)
- [23] [id(1) — Linux manual page](https://man7.org/linux/man-pages/man1/id.1.html)
{{#include ../../banners/hacktricks-training.md}}
