# macOS Shell Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## `BASH_ENV`

Bash, bir script veya `-c` komutunu çalıştırmak için etkileşimli olmayan şekilde başlatıldığında, `BASH_ENV` değerini genişletir ve istenen komutu çalıştırmadan önce ortaya çıkan dosyayı source eder. Bash bu dosyayı bulmak için `PATH` kullanmaz. Bu nedenle, etrafları attacker-controlled environment variables tarafından kontrol edilen etkileşimli olmayan Bash'i başlatan bir process, önce okunabilir bir shell payload'ını çalıştırmaya zorlanabilir.<sup>[[1]](#references)</sup>
```bash
cat >/tmp/bash-startup-hook.sh <<'EOF'
#!/bin/bash
/usr/bin/touch /tmp/bash-env-executed
EOF

BASH_ENV=/tmp/bash-startup-hook.sh /bin/bash -c '/usr/bin/true'
test -e /tmp/bash-env-executed && echo 'BASH_ENV executed'
```
Hook yalnızca hedef gerçekten Bash'i başlattığında çalışır; başka bir platformdaki `/bin/sh` veya shell kullanmadan bir komut çalıştıran bir program bunu mutlaka dikkate almaz. Bash privileged mode'da `BASH_ENV` değişkenini yok sayar. Effective ve real user/group ID'leri farklı olduğunda Bash ayrıca startup dosyalarını atlar ve `-p` belirtilmediği sürece effective ID'leri sıfırlar; `-p` ile privileged mode etkin kalır ve `BASH_ENV` yine yok sayılır.<sup>[[1]](#references)[[2]](#references)</sup>

macOS'ta `launchd` job'ları miras alınan veya job'a özel environment variable'lar tanımlayabilir; bu nedenle privileged script'lere ortam sağlayan plist'leri ve launch context'lerini inceleyin. Interpreter variable'larını temizlemek için yalnızca SIP'ye güvenmeyin: minimal bir environment (`env -i`) kullanın, `BASH_ENV` değişkenini açıkça unset edin, amaçlanan interpreter'ı absolute path ile çağırın ve writable startup dosyalarından kaçının.

## zsh `ZDOTDIR`

zsh, non-interactive shell'ler dahil her normal shell için `$ZDOTDIR/.zshenv` dosyasını okur; `ZDOTDIR` unset ise `HOME` kullanılır. Bu nedenle `ZDOTDIR`'yi writable bir directory'ye yönlendirmek, `zsh -c` komutundan veya script'ten önce `.zshenv` dosyasını çalıştırır.<sup>[[3]](#references)</sup>
```bash
mkdir -p /tmp/zsh-startup
echo '/usr/bin/touch /tmp/zshenv-executed' > /tmp/zsh-startup/.zshenv
ZDOTDIR=/tmp/zsh-startup /bin/zsh -c /usr/bin/true
```
`zsh -f`, `RCS` seçeneğini kaldırır ve bu kullanıcı başlangıç dosyasını atlar. Global `/etc/zshenv` dosyası yine okunur; bu nedenle güvenilir ve minimal tutulmalıdır.

## fish `XDG_CONFIG_HOME`

fish, her shell'in başlangıcında, yalnızca interactive veya login shell'lerde değil, `$XDG_CONFIG_HOME/fish/conf.d/*.fish` ve `$XDG_CONFIG_HOME/fish/config.fish` dosyalarını okur. Ayrıca `XDG_DATA_DIRS` içindeki girdilerin altında bulunan `fish/vendor_conf.d/*.fish` dosyalarını da çalıştırır. Bu nedenle bu değişkenlerden birini ve okunabilir bir dizini kontrol eden bir saldırgan, bir fish script'i veya `-c` komutu çalıştırılmadan önce kod çalıştırabilir.<sup>[[4]](#references)</sup>
```bash
mkdir -p /tmp/fish-startup/fish
echo 'touch /tmp/fish-config-executed' > /tmp/fish-startup/fish/config.fish
XDG_CONFIG_HOME=/tmp/fish-startup fish -c true

# Vendor configuration variant
mkdir -p /tmp/fish-vendor/fish/vendor_conf.d
echo 'touch /tmp/fish-vendor-executed' > /tmp/fish-vendor/fish/vendor_conf.d/10-hook.fish
XDG_DATA_DIRS=/tmp/fish-vendor fish -c true
```
Güvenilir bir çağrı için `fish --no-config` kullanın ve güvenilmeyen XDG path değişkenlerini temizleyin.

## References

- [1] [Bash Başlangıç Dosyaları](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files)
- [2] [Bash'i Çağırma](https://www.gnu.org/software/bash/manual/html_node/Invoking-Bash.html)
- [3] [zsh Başlangıç/Kapatma Dosyaları](https://zsh.sourceforge.io/Doc/Release/Files.html#Startup_002fShutdown-Files)
- [4] [fish Yapılandırma dosyaları](https://fishshell.com/docs/current/language.html#configuration-files)
{{#include ../../../banners/hacktricks-training.md}}
