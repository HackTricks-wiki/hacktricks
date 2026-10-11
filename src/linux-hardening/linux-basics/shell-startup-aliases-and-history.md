# Shell Başlangıcı, Takma Adlar ve Geçmiş

{{#include ../../banners/hacktricks-training.md}}

Bir shell komutu; bir alias, function, başlangıç dosyası veya environment variable çalışma şeklini değiştirdiğinde, aynı adlı executable'dan farklı davranabilir. Bir komutun çıktısına güvenmeden veya bir script'in etkileşimli bir oturumla aynı PATH'i kullandığını varsaymadan önce bunları kontrol edin.

## Geçerli shell'i inceleyin

```bash
printf '%s\n' "$SHELL" "$PATH"
type -a ls sudo curl 2>/dev/null
alias
command -V python3
history | tail -50
```

`type` ve `command -V`, bir adın alias, function, builtin veya dosyaya karşılık gelip gelmediğini gösterir. `command -v` ve `which`, alias ve function'lar için aynı sonucu vermeyebilir. Shell history komutları veya kimlik bilgilerini açığa çıkarabilir; ancak eksik olabilir, devre dışı bırakılmış olabilir ya da oturum sona erene kadar bellekte tutulabilir.

## Başlangıç ve history dosyalarını inceleyin

```bash
ls -la ~/.bashrc ~/.bash_profile ~/.profile ~/.zshrc ~/.zprofile ~/.bash_history ~/.zsh_history 2>/dev/null
ls -ld /etc/profile /etc/profile.d /etc/bash.bashrc 2>/dev/null
printenv HISTFILE HISTSIZE HISTCONTROL BASH_ENV ENV 2>/dev/null
```

Kullanıcının yazabildiği bir startup dosyası, sonraki bir shell başlatıldığında komut çalıştırabilir. Düşük ayrıcalıklı bir hesap sistem genelindeki bir startup dosyasını veya ayrıcalıklı bir kullanıcının startup dosyasını değiştirebiliyorsa bu dosya daha hassastır. Etkileşimli olmayan Bash, `BASH_ENV` tarafından belirtilen dosyayı da okuyabilir; [ortam değişkenleri](linux-environment-variables.md#bash_env--env) sayfasında bu davranış ve diğer yorumlayıcı kancaları açıklanır. Bir persistence yolu olduğunu öne sürmeden önce, gerçek shell'in login, etkileşimli ve etkileşimli olmayan oturumlarda hangi dosyaları okuduğunu doğrulayın.

Ayrıca global bir startup dosyasının kaynak olarak dahil ettiği dosyaları da inceleyin. Örneğin, `/etc/bash.bashrc` içindeki `source /opt/app/venv/bin/activate` ifadesi, shell ilgili startup dosyasını gerçekten okuduğunda aktivasyon dosyasını shell kodu olarak çalıştırır. Aktivasyon dosyasını, symlink ve üst dizin izinlerini, ayrıca ACL'leri inceleyin; düşük ayrıcalıklı bir kullanıcının ayrıcalıklı bir shell'i etkilemesi ancak bu shell veya ayrıcalıklı bir görev daha sonra ilgili dosyayı kaynak olarak dahil ederse mümkündür. Yazma erişimi `sudoedit` kullanımına bağlıysa önce sudoers kuralını ve kurulu, tedarikçi tarafından yamalanmış sudo paketini doğrulayın; yalnızca upstream sürüm dizesi, [sudoedit argüman enjeksiyonu açıklığını](../main-system-information/linux-privilege-escalation-checklist.md#sudo-and-suid-commands) kanıtlamaz.

[users and sessions](../user-information/user-and-session-triage.md) bölümünde açıklandığı gibi, geçmişi, dotfile'ları ve yedekleri sırlar açısından kontrol edin. Ayrıcalıklı bir script komutları ada göre buluyorsa, bu incelemeyi [PATH hijacking kılavuzuyla](linux-environment-variables.md#path) birlikte yürütün.
{{#include ../../banners/hacktricks-training.md}}
