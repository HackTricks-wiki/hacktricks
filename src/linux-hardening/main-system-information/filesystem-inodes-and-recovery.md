# Dosya Sistemi, Inode'lar ve Kurtarma

Filesystem abuse genellikle görünür bir yol ile arkasındaki nesne arasındaki ilişkiyi karıştırmaya dayanır.

Disk image'ları başka bir filesystem gizleyebilir.<sup>[[1]](#references)</sup> Yazılabilir mount'lar, ayrıcalıklı işler tarafından tüketilebilir.

Hardlink'ler aynı inode'u farklı bir ad üzerinden açığa çıkarabilir.<sup>[[3]](#references)</sup> Silinmiş dosyalar, açık bir file descriptor üzerinden hâlâ okunabilir olabilir.<sup>[[5]](#references)[[6]](#references)</sup>

Bu sayfa belirli bir lab veya hedef yerine tekniğe odaklanır.

## Disk Image'ları ve Loop Mount'ları

Normal bir dosya eksiksiz bir filesystem içerebilir; bu nedenle bir disk image mount edildiğinde ikinci bir filesystem ağacını açığa çıkarabilir.<sup>[[1]](#references)</sup>

Backup image'ları, kopyalanmış block device'lar, VM artifact'leri veya yeniden adlandırılmış blob'lar; dışarıdan kullanışlı görünmeseler bile credential'lar, script'ler, SSH key'leri, configuration file'ları veya flag'ler içerebilir.

Olası image'ları sınıflandırmak için `file`, tanınan filesystem metadata'sını incelemek için `blkid` ve dosyanın tamamını yazdırılabilir diziler açısından taramak için `strings -a` kullanın.<sup>[[10]](#references)[[11]](#references)[[12]](#references)</sup>
```bash
file ./candidate
ls -lh ./candidate
blkid ./candidate 2>/dev/null
strings -a ./candidate | head -n 50
```
Bağlama işlemine izin verildiğinde, imajın salt okunur olarak eklenmesi için `ro` ile bir loop mount kullanın; aşağıdaki `find` komutu inceleme derinliğini ve dosya türünü sınırlar.<sup>[[1]](#references)[[4]](#references)</sup>
```bash
mkdir -p /tmp/imgmnt
sudo mount -o loop,ro ./candidate /tmp/imgmnt
find /tmp/imgmnt -maxdepth 3 -type f -ls 2>/dev/null
sudo umount /tmp/imgmnt
```
Mount işlemi kullanılamıyorsa ve image ext2/ext3/ext4 ise metadata'sını doğrudan `debugfs` ile inceleyin.<sup>[[2]](#references)</sup>
```bash
debugfs -R 'ls -l /' ./candidate 2>/dev/null
debugfs -R 'stat /' ./candidate 2>/dev/null
```
Teknik, normal görünümlü bir dosyayı ikinci bir filesystem ağacına dönüştürdüğü için kullanışlıdır.<sup>[[1]](#references)</sup> Bunu kendi başına bir privilege escalation yöntemi olarak değil, gizli verileri kurtarmanın bir yolu olarak değerlendirin.

## Writable Mount Abuse

Daha yüksek ayrıcalıklara sahip bir context daha sonra içindeki bir şeye güvendiğinde, writable bir mount tehlikeli hâle gelir. Önemli soru yalnızca "buraya yazabilir miyim?" değil, aynı zamanda "daha sonra buradan kim okur, çalıştırır, import eder veya yükler?" sorusudur.

Mount edilmiş filesystem'leri ve seçeneklerini incelemek için `findmnt` kullanın.<sup>[[9]](#references)</sup>

Belgelenmiş `find` permission, type ve filesystem-boundary predicate'lerini kullanarak writable mount'ları ve şüpheli consumer'ları bulun; ardından olası consumer configuration'larını aramak için recursive `grep` kullanın.<sup>[[4]](#references)[[20]](#references)</sup>
```bash
findmnt -o TARGET,SOURCE,FSTYPE,OPTIONS
find /mnt /media /srv /opt -xdev -type d -writable -ls 2>/dev/null
find /mnt /media /srv /opt -xdev -type f -writable -ls 2>/dev/null | head -n 50
grep -RniE 'cron|systemd|ExecStart|backup|hook|plugin|sh |bash |python' /mnt /media /srv /opt 2>/dev/null | head -n 50
```
Yaygın kötüye kullanım kalıpları:

- Bir cron job veya systemd service, mount üzerinden yazılabilir bir script çalıştırır.<sup>[[13]](#references)[[14]](#references)</sup>
- Privileged bir service, mount üzerinden plugin'ler, config dosyaları, template'ler veya yardımcı binary'ler yükler.
- Bir mount, SUID dosyaları içerir ve bunların değiştirilmesine, değiştirilerek yerine konmasına veya path manipulation yapılmasına izin verir.
- Bir container veya chroot, restricted environment içinden yazılabilen host-backed bir path'i açığa çıkarır. Mount namespace'leri farklı mount hiyerarşileri sağlarken, `chroot()` yalnızca pathname çözümlemesini değiştirir ve tam bir sandbox değildir.<sup>[[15]](#references)[[16]](#references)</sup>

Aynı `find` predicates kullanılarak uygulanan generic validation pattern.<sup>[[4]](#references)</sup>
```bash
find /mnt /media /srv /opt -xdev -perm -4000 -type f -ls 2>/dev/null
find /mnt /media /srv /opt -xdev -type f -writable -ls 2>/dev/null | head -n 50
```
Yetkili bir lab ortamında impact'i kanıtlarken payload'ı gözlemlenebilir ve minimal tutun; örneğin `id` çıktısını geçici bir dosyaya yazın.<sup>[[23]](#references)</sup> Temel teknik, trusted writable location üzerinden gecikmeli çalıştırmadır.

## Inodes ve Path Confusion

Bir inode, filesystem nesnesidir; path ise yalnızca ona işaret eden bir addır. Device ve inode metadata'sı, filesystem'ler arasındaki nesneleri ayırt etmenizi sağlarken link count'lar birden fazla hard link'i ortaya çıkarır.<sup>[[3]](#references)</sup> Bir process dosyayı hâlâ açık tuttuğu sürece silinmiş bir pathname, verilerin her zaman yok olduğu anlamına gelmez.<sup>[[5]](#references)</sup>

Aşağıdaki `find` predicate'leri inode identity'sini, link count'ları, device sınırlarını ve timestamp'leri karşılaştırır.<sup>[[4]](#references)</sup>

`ls -i` ve `stat` metadata format'larını kullanarak dosyaları inode ve device'a göre karşılaştırın.<sup>[[17]](#references)[[18]](#references)</sup>
```bash
ls -li /path/a /path/b
stat -c 'dev=%d inode=%i links=%h mode=%A owner=%U:%G path=%n' /path/a /path/b
```
Aynı inode için `find -samefile` ile görünen tüm pathname'leri bulun.<sup>[[4]](#references)</sup>
```bash
find / -xdev -samefile /path/to/file -ls 2>/dev/null
```
Yalnızca metadata'ya sahip olduğunuzda `find -inum` ile doğrudan inode numarasına göre arama yapın.<sup>[[4]](#references)</sup>
```bash
find / -xdev -inum <inode_number> -ls 2>/dev/null
```
Bu teknik, bir dosya beklenmedik bir adla göründüğünde, bir uygulama bir yolu doğrulayıp başka bir yolu kullandığında veya ayrıcalıklı bir wrapper başka bir yerden de erişilebilen bir inode ile etkileşime girdiğinde kullanışlıdır.

## Hardlink Abuse

Hardlink'ler aynı inode için birden fazla ad oluşturur. Symlink'lerde olduğu gibi bir hedef yola işaret etmezler; aynı dosya nesnesi için eşdeğer adlardır.<sup>[[3]](#references)</sup>

`find` komutunun izin ve bağlantı sayısı predicate'lerini kullanarak birden fazla hardlink'i olan SUID dosyalarını bulun.<sup>[[4]](#references)</sup>
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
- Bir pathname'i kaldıran temizleme işlemi, başka bir hardlink'i etkin durumda bırakabilir.

Linux'un `fs.protected_hardlinks` sysctl'i, ayrıcalık sınırları arasındaki hardlink oluşturma işlemlerini kısıtlayabilir.<sup>[[7]](#references)</sup> Mevcut hardlink'ler yine de incelenmelidir.

## Açık FD'ler Üzerinden Silinmiş Dosya Kurtarma

Bir process bir dosyayı açık tuttuğunda, dosyanın son pathname'ini kaldırmak dosyayı son descriptor kapanana kadar etkin durumda bırakır; Linux bu descriptor'ları `/proc/<pid>/fd/` altında sunar.<sup>[[5]](#references)[[6]](#references)</sup>

`/proc` descriptor'larını listeleyip açık dosya çıktısını filtreleyerek silinmiş açık dosyaları bulun.<sup>[[5]](#references)[[6]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>
```bash
ls -l /proc/*/fd/* 2>/dev/null | grep ' (deleted)' | head -n 50
lsof 2>/dev/null | grep deleted | head -n 50
```
Bu bağlantılar üzerinden kurtarma, `/proc/<pid>/fd` başvurularının ptrace erişim denetimlerine ve dosya izinlerine tabi olması nedeniyle izne bağlıdır.<sup>[[6]](#references)</sup>

İzin verildiğinde `readlink` descriptor hedefini gösterir ve `cp` içeriğini kopyalar.<sup>[[21]](#references)[[22]](#references)</sup>
```bash
readlink /proc/<pid>/fd/<fd>
cp /proc/<pid>/fd/<fd> /tmp/recovered-file
file /tmp/recovered-file
```
Bu, silinen log'ları, geçici secret'ları, bırakılmış binary'leri, rotate edilmiş dosyaları veya çalıştırıldıktan sonra kaldırılan script'leri kurtarmaya yönelik pratik bir tekniktir.

## debugfs ile ext Recovery

ext2/ext3/ext4 filesystem'lerinde `debugfs`, inode metadata'sını inceleyebilir ve bir block device veya image üzerinden inode içeriklerini dökebilir; `-w` olmadan filesystem'i read-only olarak açar.<sup>[[2]](#references)</sup> Mümkün olduğunda bir kopya veya read-only image üzerinde çalışın.

Directory listing'leri, inode durumunu ve inode-to-path kontrollerini gerçekleştirmek için `debugfs` istekleriyle entry'leri listeleyin ve inode'ları inceleyin.<sup>[[2]](#references)</sup>
```bash
debugfs -R 'ls -l /' ./disk.img
debugfs -R 'stat <inode_number>' ./disk.img
debugfs -R 'ncheck <inode_number>' ./disk.img
```
Bilinen bir inode'u `debugfs dump` komutuyla dökün, ardından kurtarılan çıktıyı `file` ile sınıflandırın.<sup>[[2]](#references)[[10]](#references)</sup>
```bash
debugfs -R 'dump <inode_number> /tmp/recovered.bin' ./disk.img
file /tmp/recovered.bin
```
Bu, kurtarmanın garanti edildiği anlamına gelmez. Dosya sistemi durumuna, blokların yeniden kullanılıp kullanılmadığına ve metadata'nın hâlâ mevcut olup olmadığına bağlıdır. ext3/ext4 için `debugfs` kılavuzu, serbest bırakılan inode veri blokları artık kullanılamadığından silinmiş inode kurtarmanın başarısız olabileceğini belirtir.<sup>[[2]](#references)</sup> Bu teknik, normal path traversal'a güvenmeden inode düzeyindeki durumu incelemenize olanak tanıdığı için yine de değerlidir.

## Inode Tükenmesi ve Sıralama

Inode tükenmesi, boş disk alanı kalmış olsa bile bir dosya sisteminin dosya düğümlerini tüketmesiyle gerçekleşir.<sup>[[8]](#references)[[17]](#references)</sup> Genellikle güvenilirlik sorunlarına yol açar, ancak incident response veya lab triage sırasında görülen garip davranışları da açıklayabilir.

Blok kullanımını değil, inode bilgilerini raporlamak için `df -i` kullanın.<sup>[[8]](#references)</sup>

`df` ve dizin üst öğelerinin sayısını almak için `find` kullanarak inode baskısını kontrol edin.<sup>[[4]](#references)[[8]](#references)</sup>
```bash
df -h
df -i
find /var /tmp /home -xdev -printf '%h\n' 2>/dev/null | sort | uniq -c | sort -n | tail
```
Inode numaraları ve zaman damgaları, basit laboratuvar ortamlarında etkinliklerin yeniden oluşturulmasına da yardımcı olabilir.

Aşağıdaki `find` biçim yönergeleri bu alanları ortaya çıkarır.<sup>[[4]](#references)</sup>
```bash
find /path -xdev -printf '%i %TY-%Tm-%Td %TH:%TM %p\n' 2>/dev/null | sort -n | tail -n 50
find /path -xdev -newermt '2026-01-01' -ls 2>/dev/null
```
Sıralamayı kanıt olarak değil, bir ipucu olarak değerlendirin. Kopyalama işlemleri, arşiv çıkarma, filesystem türü, geri yüklemeler ve eşzamanlı yazma işlemleri tahsis düzenlerini değiştirebilir.

## Savunma Notları

- Analiz sırasında bilinmeyen imajları read-only olarak mount edin.<sup>[[1]](#references)</sup>
- Ayrıcalıklı script'leri, service unit'lerini, plugin'leri ve helper path'lerini kullanıcı tarafından yazılabilir mount'ların dışında tutun.
- Operasyonel olarak uygun olduğunda `nosuid`, `nodev` ve `noexec` kullanın; bu seçenekler mount üzerindeki set-ID/capability çalıştırmayı, aygıt yorumlamayı veya doğrudan binary çalıştırmayı devre dışı bırakır.<sup>[[1]](#references)</sup> Bunları tam bir sınır olarak değerlendirmeyin.
- `/proc/<pid>/fd` erişimini kısıtlayın; bu link'lerin dereference edilmesi ptrace erişim kontrolleri ve dosya izinleri tarafından denetlenir.<sup>[[6]](#references)</sup> Daha geniş process metadata erişimini ve kullanıcılar arası incelemeyi mümkün olduğunca kısıtlayın.
- Yazılabilir mount noktalarını, ayrıcalıklı dosyalara işaret eden beklenmeyen hardlink'leri ve silinmiş ancak açık durumdaki hassas dosyaları izleyin.

## References

- [1] [mount(8) — Linux manual page](https://man7.org/linux/man-pages/man8/mount.8.html)
- [2] [debugfs(8) — Linux manual page](https://man7.org/linux/man-pages/man8/debugfs.8.html)
- [3] [inode(7) — Linux manual page](https://man7.org/linux/man-pages/man7/inode.7.html)
- [4] [find(1) — Linux manual page](https://man7.org/linux/man-pages/man1/find.1.html)
- [5] [unlink(2) — Linux manual page](https://man7.org/linux/man-pages/man2/unlink.2.html)
- [6] [proc_pid_fd(5) — Linux manual page](https://man7.org/linux/man-pages/man5/proc_pid_fd.5.html)
- [7] [Documentation for /proc/sys/fs/ — The Linux Kernel documentation](https://www.kernel.org/doc/html/latest/admin-guide/sysctl/fs.html)
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
