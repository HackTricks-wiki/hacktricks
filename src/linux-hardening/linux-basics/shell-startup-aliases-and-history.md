# Shell Başlangıcı, Takma Adlar ve Geçmiş

{{#include ../../banners/hacktricks-training.md}}

Bir kabuk komutu; bir takma ad, işlev, başlangıç dosyası veya ortam değişkeni çalıştırılma biçimini değiştirirse aynı adlı yürütülebilir dosyadan farklı davranabilir. Bir komutun çıktısına güvenmeden veya bir betiğin etkileşimli oturumla aynı PATH değerini kullandığını varsaymadan önce bunları kontrol edin.

## Geçerli kabuğu inceleyin

```bash
printf '%s\n' "$SHELL" "$PATH"
type -a ls sudo curl 2>/dev/null
alias
command -V python3
history | tail -50
```

`type` ve `command -V`, bir adın alias, function, builtin veya dosya olarak çözümlenip çözümlenmediğini gösterir. `command -v` ve `which`, alias ve function’lar için aynı sonucu vermeyebilir. Shell history, komutları veya kimlik bilgilerini açığa çıkarabilir; ancak eksik olabilir, devre dışı bırakılmış olabilir ya da oturum sona erene kadar bellekte tutulabilir.

## Başlangıç ve history dosyalarını inceleyin

```bash
ls -la ~/.bashrc ~/.bash_profile ~/.profile ~/.zshrc ~/.zprofile ~/.bash_history ~/.zsh_history 2>/dev/null
ls -ld /etc/profile /etc/profile.d /etc/bash.bashrc 2>/dev/null
printenv HISTFILE HISTSIZE HISTCONTROL BASH_ENV ENV 2>/dev/null
```

Kullanıcının yazabildiği bir başlangıç dosyası, sonraki bir shell başlatıldığında komut çalıştırabilir. Daha düşük ayrıcalıklı bir hesap sistem genelindeki bir başlangıç dosyasını veya ayrıcalıklı bir kullanıcının başlangıç dosyasını değiştirebiliyorsa bu dosya daha hassastır. Etkileşimli olmayan Bash, `BASH_ENV` tarafından belirtilen dosyayı da okuyabilir; [environment variables](linux-environment-variables.md#bash_env--env) sayfasında bu davranış ve diğer interpreter hook'ları açıklanır. Bir kalıcılık yolu olduğunu öne sürmeden önce gerçek shell'in login, etkileşimli ve etkileşimli olmayan oturumlarda hangi dosyaları okuduğunu doğrulayın.

Genel bir başlangıç dosyasının kaynak olarak çalıştırdığı dosyaları da inceleyin. Örneğin, `/etc/bash.bashrc` içindeki `source /opt/app/venv/bin/activate` satırı, shell bu başlangıç dosyasını gerçekten okuduğunda aktivasyon dosyasını shell kodu olarak çalıştırır. Aktivasyon dosyasını, symlink ve üst dizin izinlerini ve ACL'leri gözden geçirin; daha düşük ayrıcalıklı bir kullanıcı, ayrıcalıklı bir shell veya ayrıcalıklı bir görev bu dosyayı sonradan kaynak olarak çalıştırırsa ancak o zaman onu etkileyebilir. Yazma erişimi `sudoedit`'e bağlıysa önce tam sudoers kuralını ve kurulu, vendor tarafından yamalanmış sudo paketini doğrulayın; yalnızca upstream sürüm dizesi, [sudoedit argument-injection exposure](../main-system-information/linux-privilege-escalation-checklist.md#sudo-and-suid-commands) olduğunu kanıtlamaz.

[users and sessions](../user-information/user-and-session-triage.md) sayfasında açıklandığı gibi history, dotfile'lar ve yedeklerde sır olup olmadığını kontrol edin. Ayrıcalıklı bir script komutları ada göre çözümlüyorsa bu incelemeyi [PATH hijacking guidance](linux-environment-variables.md#path) ile birlikte yürütün.
{{#include ../../banners/hacktricks-training.md}}
