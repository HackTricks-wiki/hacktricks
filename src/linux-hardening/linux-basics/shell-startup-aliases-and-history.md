# Shell Başlangıcı, Alias'lar ve Geçmiş

{{#include ../../banners/hacktricks-training.md}}

Bir shell komutu, bir alias, function, startup file veya environment variable çalışma şeklini değiştiriyorsa aynı ada sahip executable'dan farklı davranabilir. Bir komutun çıktısına güvenmeden veya bir script'in etkileşimli oturumla aynı PATH'i kullandığını varsaymadan önce bunları kontrol edin.

## Mevcut shell'i inceleyin

```bash
printf '%s\n' "$SHELL" "$PATH"
type -a ls sudo curl 2>/dev/null
alias
command -V python3
history | tail -50
```

`type` ve `command -V`, bir adın alias, fonksiyon, yerleşik komut veya dosyaya çözümlenip çözümlenmediğini gösterir. `command -v` ve `which`, alias ve fonksiyonlar için aynı sonucu vermeyebilir. Shell geçmişi komutları veya kimlik bilgilerini açığa çıkarabilir; ancak eksik olabilir, devre dışı bırakılmış olabilir ya da oturum sona erene kadar bellekte tutulabilir.

## Başlangıç ve geçmiş dosyalarını inceleyin

```bash
ls -la ~/.bashrc ~/.bash_profile ~/.profile ~/.zshrc ~/.zprofile ~/.bash_history ~/.zsh_history 2>/dev/null
ls -ld /etc/profile /etc/profile.d /etc/bash.bashrc 2>/dev/null
printenv HISTFILE HISTSIZE HISTCONTROL BASH_ENV ENV 2>/dev/null
```

Kullanıcının yazabildiği bir başlangıç dosyası, sonraki bir shell açılışında komut çalıştırabilir. Düşük yetkili bir hesap sistem genelindeki bir başlangıç dosyasını veya ayrıcalıklı bir kullanıcının başlangıç dosyasını değiştirebiliyorsa, bu dosyalar daha hassastır. Etkileşimsiz Bash, `BASH_ENV` tarafından belirtilen dosyayı da okuyabilir; [environment variables](linux-environment-variables.md#bash_env--env) sayfasında bu davranış ve diğer interpreter hook’ları açıklanmaktadır. Bir persistence yolu olduğunu öne sürmeden önce, gerçek shell’in login, interaktif ve etkileşimsiz oturumlarda hangi dosyaları okuduğunu doğrulayın.

Ayrıca global bir başlangıç dosyasının kaynak olarak aldığı dosyaları da inceleyin. Örneğin, `/etc/bash.bashrc` içindeki doğrudan `source /opt/app/venv/bin/activate` satırı, shell bu başlangıç dosyasını gerçekten okuduğunda etkinleştirme dosyasını shell kodu olarak çalıştırır. Etkinleştirme dosyasını, symlink ve üst dizin izinlerini, ayrıca ACL’leri inceleyin; düşük yetkili bir kullanıcı, ancak ayrıcalıklı bir shell veya ayrıcalıklı bir görev daha sonra bu dosyayı kaynak olarak alırsa onu etkileyebilir. Yazma erişimi `sudoedit`'e bağlıysa önce tam sudoers kuralını ve yüklenmiş, satıcı tarafından yamalanmış sudo paketini doğrulayın; tek başına upstream sürüm dizesi [sudoedit argument-injection exposure](../main-system-information/linux-privilege-escalation-checklist.md#sudo-and-suid-commands) olduğunu kanıtlamaz.

[users and sessions](../user-information/user-and-session-triage.md) sayfasında açıklandığı gibi, geçmiş kayıtlarında, dotfile’larda ve yedeklerde sır olup olmadığını kontrol edin. Ayrıcalıklı bir script komutları ada göre buluyorsa, bu incelemeyi [PATH hijacking guidance](linux-environment-variables.md#path) ile birlikte yürütün.
{{#include ../../banners/hacktricks-training.md}}
