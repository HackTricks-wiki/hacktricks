# Shell Başlangıcı, Alias'lar ve Geçmiş

{{#include ../../banners/hacktricks-training.md}}

Bir shell komutu, alias, function, startup file veya environment variable çalışma şeklini değiştirirse aynı ada sahip executable'dan farklı davranabilir. Bir komutun çıktısına güvenmeden veya bir script'in etkileşimli oturumla aynı PATH'i kullandığını varsaymadan önce bunları kontrol edin.

## Mevcut shell'i inceleyin

```bash
printf '%s\n' "$SHELL" "$PATH"
type -a ls sudo curl 2>/dev/null
alias
command -V python3
history | tail -50
```

`type` ve `command -V`, bir adın alias, function, builtin veya dosya olarak çözümlenip çözümlenmediğini gösterir. `command -v` ve `which`, alias ve function'lar için aynı sonucu vermeyebilir. Shell history, komutları veya kimlik bilgilerini açığa çıkarabilir; ancak eksik olabilir, devre dışı bırakılmış olabilir ya da oturum sona erene kadar bellekte tutulabilir.

## Başlangıç ve history dosyalarını inceleyin

```bash
ls -la ~/.bashrc ~/.bash_profile ~/.profile ~/.zshrc ~/.zprofile ~/.bash_history ~/.zsh_history 2>/dev/null
ls -ld /etc/profile /etc/profile.d /etc/bash.bashrc 2>/dev/null
printenv HISTFILE HISTSIZE HISTCONTROL BASH_ENV ENV 2>/dev/null
```

Kullanıcının yazabildiği bir başlangıç dosyası, sonraki bir shell açılışında komut çalıştırabilir. Daha düşük yetkili bir hesap sistem genelindeki bir başlangıç dosyasını veya ayrıcalıklı bir kullanıcının başlangıç dosyasını değiştirebiliyorsa, bu dosya daha hassastır. Etkileşimsiz Bash, `BASH_ENV` tarafından belirtilen dosyayı da okuyabilir; [environment variables](linux-environment-variables.md#bash_env--env) sayfasında bu davranış ve diğer interpreter kancaları açıklanır. Bir persistence yolu olduğunu öne sürmeden önce, gerçek shell'in login, interactive ve non-interactive oturumlarda hangi dosyaları okuduğunu doğrulayın.

Global bir başlangıç dosyasının kaynak olarak eklediği dosyaları da inceleyin. Örneğin, `/etc/bash.bashrc` içindeki `source /opt/app/venv/bin/activate` satırı, shell bu başlangıç dosyasını gerçekten okuduğunda aktivasyon dosyasını shell kodu olarak çalıştırır. Aktivasyon dosyasını, symlink ve üst dizin izinlerini ve ACL'leri inceleyin; düşük yetkili bir kullanıcının ayrıcalıklı bir shell'i etkileyebilmesi için o shell'in veya ayrıcalıklı bir görevin daha sonra bu dosyayı kaynak olarak eklemesi gerekir. Yazma erişimi `sudoedit` kullanımına bağlıysa önce tam sudoers kuralını ve kurulu, vendor tarafından yamalanmış sudo paketini doğrulayın; tek başına upstream sürüm dizesi, [sudoedit argument-injection exposure](../main-system-information/linux-privilege-escalation-checklist.md#sudo-and-suid-commands) olduğunu kanıtlamaz.

[users and sessions](../user-information/user-and-session-triage.md) sayfasında açıklandığı şekilde history dosyalarında, dotfile'larda ve yedeklerde sır olup olmadığını kontrol edin. Ayrıcalıklı bir script komutları ada göre çözümlüyorsa bu incelemeyi [PATH hijacking guidance](linux-environment-variables.md#path) ile birlikte değerlendirin.

## Zsh başlangıç yönlendirmesi ve derlenmiş dosyalar

Varsayılan `RCS` ayarlarıyla zsh, `zsh -c` ve script'ler dahil olmak üzere normal çalıştırmalardan önce `$ZDOTDIR/.zshenv` dosyasını okur; `ZDOTDIR` ayarlanmamışsa `$HOME` kullanılır. Bir command runner ortam değişkenleri haritasını kabul ediyorsa, bu değişkenlerden herhangi birini ayrıcalıklı bir zsh sürecine aktarıp aktarmadığını test edin. Böylece yazılabilir bir `.zshenv`, runner'ın kontrol ettiği veya izin listesine aldığı komut gövdesinden **önce** çalışabilir. Bunun için ayrıcalıklı sürecin yönlendirilmiş dizini devralması gerekir; `zsh -f` kullanıcı başlangıç dosyalarını atlar, ancak global `zshenv` dosyasını atlamaz (bu dosya genellikle `/etc/zshenv` konumundadır, ancak dağıtım yolları değişebilir). [macOS zsh injection page](../../macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-bash-applications-injection.md#zsh-zdotdir) sayfasında minimal bir `ZDOTDIR` örneği bulunur.<sup>[[1]](#references)[[2]](#references)</sup>

Daha yeni ve geçerli bir `.zshenv.zwc` veya `.zshrc.zwc`, düz metin başlangıç dosyası yerine çalıştırılır. Başlangıç dizinine yazabiliyorsanız, değiştirilmiş bir dosyayı derleyip ardından zararsız görünen düz metin dosyasını geri yüklemek, derlenmiş kopyada çalıştırılabilir kod bırakabilir. Bu, şifreleme değil, gizlemedir. Aşağıdaki geçici test, yalnızca metin dosyasını incelemenin neden yetersiz olduğunu gösterir; gerçek bir home dizinine dokunmaz.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

```bash
lab=$(mktemp -d)
printf '%s\n' 'print -r -- compiled > "$ZDOTDIR/result"' > "$lab/.zshenv"
zsh -f -c 'zcompile -R "$1"' _ "$lab/.zshenv"
printf '%s\n' 'print -r -- plaintext > "$ZDOTDIR/result"' > "$lab/.zshenv"
touch -d '2 minutes ago' "$lab/.zshenv"  # ensure the .zwc is newer
ZDOTDIR="$lab" zsh -c :
cat "$lab/result"  # compiled
zsh -f -c 'zcompile -t "$1"' _ "$lab/.zshenv.zwc"
```

Gerçek bir hedefte, etkin `ZDOTDIR`/`HOME` değerlerini belirleyin, hem metin dosyalarını hem de `.zwc` dosyalarını inceleyin ve zaman damgalarını, sahipliği ve yazılabilir üst dizinleri kontrol edin. Bir `.zwc` dosyasının öncelik kazanması için kaynak dosyayla eşleşmesi ve kaynak dosyadan daha yeni olması gerekir.<sup>[[1]](#references)[[3]](#references)</sup>



## References

- [1] [Zsh başlangıç ve kapanış dosyaları](https://zsh.sourceforge.io/Doc/Release/Files.html)
- [2] [Shell başlangıç ortamı enjeksiyonu güvenlik duyurusu](https://github.com/openclaw/openclaw/security/advisories/GHSA-xgf2-vxv2-rrmg)
- [3] [Zsh shell yerleşik komutları: zcompile](https://zsh.sourceforge.io/Doc/Release/Shell-Builtin-Commands.html)
- [4] [Kontrol Etmeyi Unuttuğunuz .zshrc.zwc](https://dfir.ch/posts/compiled_zsh/)
{{#include ../../banners/hacktricks-training.md}}
