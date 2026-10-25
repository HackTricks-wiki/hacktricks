# Shell Başlangıcı, Alias'lar ve Geçmiş

{{#include ../../banners/hacktricks-training.md}}

Bir shell komutu; bir alias, function, startup file veya environment variable çalışma biçimini değiştiriyorsa, aynı ada sahip executable'dan farklı davranabilir. Bir komutun çıktısına güvenmeden veya bir script'in etkileşimli oturumla aynı PATH'i kullandığını varsaymadan önce bunları kontrol edin.

## Mevcut shell'i inceleyin

```bash
printf '%s\n' "$SHELL" "$PATH"
type -a ls sudo curl 2>/dev/null
alias
command -V python3
history | tail -50
```

`type` ve `command -V`, bir adın alias, function, builtin veya file olarak çözümlenip çözümlenmediğini gösterir. `command -v` ve `which`, alias ve function’lar için aynı sonucu vermeyebilir. Shell history, komutları veya kimlik bilgilerini açığa çıkarabilir; ancak eksik olabilir, devre dışı bırakılmış olabilir ya da oturum sona erene kadar bellekte tutulabilir.

Değiştirilmiş bir `.bashrc`, parola istemini taklit eden, yanıtı kaydeden ve gerçek komuta ileten bir `sudo` alias’ı tanımlayabilir. Bu, `sudo` executable’ını veya `PATH`’i değiştirmeden kimlik bilgilerinin ele geçirilmesini gizleyebilir.<sup>[[5]](#references)</sup> Shell’in değiştirilmiş startup file’ı okuması ve alias’ı genişletmesi gerekir.<sup>[[7]](#references)</sup> Varsayılan olarak, `expand_aliases` etkinleştirilmediği sürece non-interactive Bash alias’ları genişletmez.<sup>[[6]](#references)</sup>

## Startup ve history dosyalarını inceleyin

```bash
ls -la ~/.bashrc ~/.bash_profile ~/.profile ~/.zshrc ~/.zprofile ~/.bash_history ~/.zsh_history 2>/dev/null
ls -ld /etc/profile /etc/profile.d /etc/bash.bashrc 2>/dev/null
printenv HISTFILE HISTSIZE HISTCONTROL BASH_ENV ENV 2>/dev/null
```

Kullanıcının yazabildiği bir başlangıç dosyası, sonraki bir shell açılışında komut çalıştırabilir. Sistem genelindeki bir başlangıç dosyası veya ayrıcalıklı bir kullanıcının başlangıç dosyası, düşük ayrıcalıklı bir hesap tarafından değiştirilebiliyorsa daha hassastır. Etkileşimsiz Bash, `BASH_ENV` tarafından belirtilen dosyayı da okuyabilir; [environment variables](linux-environment-variables.md#bash_env--env) sayfasında bu davranış ve diğer interpreter hook'ları açıklanır. Bir persistence path olduğunu öne sürmeden önce, gerçek shell'in login, etkileşimli ve etkileşimsiz oturumlarda hangi dosyaları okuduğunu doğrulayın.

Genel bir başlangıç dosyasının kaynakladığı dosyaları da inceleyin. Örneğin, `/etc/bash.bashrc` içindeki `source /opt/app/venv/bin/activate` ifadesi, shell söz konusu başlangıç dosyasını gerçekten okuduğunda aktivasyon dosyasını shell kodu olarak çalıştırır. Aktivasyon dosyasını, symlink ve üst dizin izinlerini, ayrıca ACL'leri inceleyin; düşük ayrıcalıklı bir kullanıcının yazma erişimi, ayrıcalıklı bir shell'i ancak o shell veya daha sonra çalışan ayrıcalıklı bir görev bu dosyayı kaynaklarsa etkileyebilir. Yazma erişimi `sudoedit`'e bağlıysa önce sudoers kuralını ve yüklü, satıcı tarafından yamalanmış sudo paketini doğrulayın; yalnızca upstream sürüm dizesi, [sudoedit argument-injection açığını](../main-system-information/linux-privilege-escalation-checklist.md#sudo-and-suid-commands) kanıtlamaz.

[users and sessions](../user-information/user-and-session-triage.md) bölümünde açıklandığı gibi history dosyalarında, dotfile'larda ve yedeklerde sır olup olmadığını kontrol edin. Ayrıcalıklı bir script komutları adına göre çözümlüyorsa bu incelemeyi [PATH hijacking yönergeleri](linux-environment-variables.md#path) ile birleştirin.

## Zsh başlangıç yönlendirmesi ve derlenmiş dosyalar

Varsayılan `RCS` ayarlarıyla zsh, `zsh -c` ve script'ler de dahil olmak üzere normal çağrılardan önce `$ZDOTDIR/.zshenv` dosyasını okur; `ZDOTDIR` ayarlanmamışsa `$HOME` kullanılır. Bir command runner ortam değişkeni haritası kabul ediyorsa, bu değişkenlerden herhangi birini ayrıcalıklı bir zsh sürecine iletip iletmediğini test edin. Böylece yazılabilir bir `.zshenv`, runner'ın denetlediği veya izin listesine aldığı komut gövdesinden **önce** çalışabilir. Bunun için ayrıcalıklı sürecin yönlendirilmiş dizini devralması gerekir; `zsh -f` kullanıcı başlangıç dosyalarını atlar, ancak genel `zshenv` dosyasını atlamaz (genellikle `/etc/zshenv` olur, ancak dağıtım yolları değişebilir). [macOS zsh injection sayfasında](../../macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-bash-applications-injection.md#zsh-zdotdir) minimal bir `ZDOTDIR` örneği bulunur.<sup>[[1]](#references)[[2]](#references)</sup>

Daha yeni ve geçerli bir `.zshenv.zwc` veya `.zshrc.zwc`, düz metin başlangıç dosyasının yerine çalıştırılır. Başlangıç dizinine yazabiliyorsanız, değiştirilmiş bir dosyayı derleyip ardından zararsız görünen düz metin dosyasını geri yüklemek, derlenmiş kopyada çalıştırılabilir kod bırakabilir. Bu, şifreleme değil, gizlemedir. Aşağıdaki geçici test, yalnızca metin dosyasını incelemenin neden yetersiz olduğunu gösterir; gerçek bir home dizinine dokunmaz.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

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

Gerçek bir hedefte etkin `ZDOTDIR`/`HOME` değerlerini belirleyin, hem metin dosyalarını hem de `.zwc` dosyalarını inceleyin ve zaman damgalarını, sahipliği ve yazılabilir üst dizinleri kontrol edin. Bir `.zwc` dosyası, kaynak dosyayla eşleşmeli ve öncelik kazanması için kaynak dosyadan daha yeni olmalıdır.<sup>[[1]](#references)[[3]](#references)</sup>



## References

- [1] [Zsh başlangıç ve kapanış dosyaları](https://zsh.sourceforge.io/Doc/Release/Files.html)
- [2] [Shell başlangıç ortamı enjeksiyonu güvenlik duyurusu](https://github.com/openclaw/openclaw/security/advisories/GHSA-xgf2-vxv2-rrmg)
- [3] [Zsh shell yerleşik komutları: zcompile](https://zsh.sourceforge.io/Doc/Release/Shell-Builtin-Commands.html)
- [4] [Kontrol Etmeyi Unuttuğunuz .zshrc.zwc](https://dfir.ch/posts/compiled_zsh/)
- [5] [Yapay Zeka Destekli Casusluk Kampanyası Devlet Kurumlarının Linux Altyapısını Hedef Alıyor](https://unit42.paloaltonetworks.com/ai-campaign-targets-linux-infrastructure/)
- [6] [Bash kılavuzu: Takma adlar](https://www.gnu.org/software/bash/manual/html_node/Aliases.html)
- [7] [Bash kılavuzu: Bash başlangıç dosyaları](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files)
{{#include ../../banners/hacktricks-training.md}}
