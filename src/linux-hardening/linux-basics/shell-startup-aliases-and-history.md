# Shell Başlangıcı, Takma Adlar ve Geçmiş

{{#include ../../banners/hacktricks-training.md}}

Bir shell komutu; bir takma ad, işlev, başlangıç dosyası veya ortam değişkeni çalışma biçimini değiştirdiğinde, aynı adlı yürütülebilir dosyadan farklı davranabilir. Bir komutun çıktısına güvenmeden veya bir betiğin etkileşimli oturumla aynı PATH'i kullandığını varsaymadan önce bunları kontrol edin.

## Geçerli shell'i inceleme

```bash
printf '%s\n' "$SHELL" "$PATH"
type -a ls sudo curl 2>/dev/null
alias
command -V python3
history | tail -50
```

`type` ve `command -V`, bir adın alias, function, builtin veya file olarak çözümlenip çözümlenmediğini gösterir. `command -v` ve `which`, alias ve function'lar için aynı sonucu vermeyebilir. Shell history, komutları veya kimlik bilgilerini açığa çıkarabilir; ancak eksik olabilir, devre dışı bırakılmış olabilir ya da oturum sona erene kadar bellekte tutulabilir.

## Başlangıç ve history dosyalarını inceleyin

```bash
ls -la ~/.bashrc ~/.bash_profile ~/.profile ~/.zshrc ~/.zprofile ~/.bash_history ~/.zsh_history 2>/dev/null
ls -ld /etc/profile /etc/profile.d /etc/bash.bashrc 2>/dev/null
printenv HISTFILE HISTSIZE HISTCONTROL BASH_ENV ENV 2>/dev/null
```

Kullanıcının yazabildiği bir başlangıç dosyası, sonraki bir shell açılışında komut çalıştırabilir. Daha düşük ayrıcalıklı bir hesap sistem genelindeki bir başlangıç dosyasını veya ayrıcalıklı bir kullanıcının başlangıç dosyasını değiştirebiliyorsa, bu dosya daha hassastır. Etkileşimli olmayan Bash, `BASH_ENV` tarafından belirtilen dosyayı da okuyabilir; [environment variables](linux-environment-variables.md#bash_env--env) sayfasında bu davranış ve diğer yorumlayıcı kancaları açıklanmaktadır. Bir kalıcılık yolu olduğunu ileri sürmeden önce, gerçek shell'in oturum açma, etkileşimli ve etkileşimli olmayan oturumlarda hangi dosyaları okuduğunu doğrulayın.

Ayrıca, genel bir başlangıç dosyasının kaynak olarak dahil ettiği dosyaları da inceleyin. Örneğin, `/etc/bash.bashrc` içindeki `source /opt/app/venv/bin/activate` ifadesi, shell bu başlangıç dosyasını gerçekten okuduğunda aktivasyon dosyasını shell kodu olarak çalıştırır. Aktivasyon dosyasını, sembolik bağlantı ve üst dizin izinlerini ve ACL'leri inceleyin; daha düşük ayrıcalıklı bir kullanıcının ayrıcalıklı bir shell'i etkileyebilmesi için, o shell'in veya ayrıcalıklı bir görevin dosyayı daha sonra kaynak olarak dahil etmesi gerekir. Yazma erişimi `sudoedit`'e bağlıysa, önce tam sudoers kuralını ve kurulu, üretici tarafından yamalanmış sudo paketini doğrulayın; yalnızca upstream sürüm numarası, [sudoedit argüman enjeksiyonuna maruz kalındığını](../main-system-information/linux-privilege-escalation-checklist.md#sudo-and-suid-commands) göstermez.

[users and sessions](../user-information/user-and-session-triage.md) bölümünde açıklandığı gibi, geçmişi, dotfile'ları ve yedekleri gizli bilgiler açısından kontrol edin. Ayrıcalıklı bir betik komutları ada göre çözümlüyorsa, bu incelemeyi [PATH hijacking rehberi](linux-environment-variables.md#path) ile birleştirin.
{{#include ../../banners/hacktricks-training.md}}
