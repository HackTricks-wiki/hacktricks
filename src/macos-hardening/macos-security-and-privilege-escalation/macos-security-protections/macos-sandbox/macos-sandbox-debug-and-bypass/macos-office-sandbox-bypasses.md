# macOS Office Sandbox Bypasses

{{#include ../../../../../banners/hacktricks-training.md}}

### Word Sandbox bypass via Launch Agents

Uygulama, **`com.apple.security.temporary-exception.sbpl`** entitlement'ını kullanan **özel bir Sandbox** kullanır ve bu özel sandbox, dosya adı `~$` ile başladığı sürece dosyaların herhangi bir yere yazılmasına izin verir: `(require-any (require-all (vnode-type REGULAR-FILE) (regex #"(^|/)~$[^/]+$")))`

Bu nedenle, `~/Library/LaunchAgents/~$escape.plist` konumuna bir **`plist`** LaunchAgent yazmak yeterliydi.

[**Orijinal rapora buradan**](https://www.mdsec.co.uk/2018/08/escaping-the-sandbox-microsoft-office-on-macos/) bakın.<sup>[[1]](#references)</sup>

### Word Sandbox bypass via Login Items and zip

İlk bypass'tan sonra Word'ün, adı `~$` ile başlayan rastgele dosyaları yazabildiğini; ancak önceki vuln'un patch'lenmesinden sonra `/Library/Application Scripts` veya `/Library/LaunchAgents` içine yazmanın mümkün olmadığını hatırlayın.

Sandbox içinden bir **Login Item** (kullanıcı giriş yaptığında çalıştırılacak uygulamalar) oluşturulabileceği keşfedildi. Ancak bu uygulamalar **notarized** olmadıkça çalışmaz ve **argüman eklemek mümkün değildir** (bu nedenle **`bash`** kullanarak doğrudan bir reverse shell çalıştırılamaz).

Önceki Sandbox bypass'tan sonra Microsoft, `~/Library/LaunchAgents` içine dosya yazma seçeneğini devre dışı bıraktı. Ancak, bir **zip file**'ı **Login Item** olarak eklediğinizde `Archive Utility`'nin dosyayı bulunduğu konuma **unzip** ettiği keşfedildi. Bu nedenle, `~/Library` içindeki `LaunchAgents` klasörü varsayılan olarak oluşturulmadığından, `LaunchAgents/~$escape.plist` konumundaki bir **plist**'i **zip**'lemek ve zip dosyasını **`~/Library`** içine yerleştirmek mümkün oldu; böylece dosya decompress edildiğinde persistence hedefine ulaşıyordu.

[**Orijinal rapora buradan**](https://objective-see.org/blog/blog_0x4B.html) bakın.<sup>[[2]](#references)</sup>

### Word Sandbox bypass via Login Items and .zshenv

(İlk escape'ten sonra Word'ün, adı `~$` ile başlayan rastgele dosyaları yazabildiğini hatırlayın.)

Ancak önceki tekniğin bir sınırlaması vardı: **`~/Library/LaunchAgents`** klasörü başka bir yazılım tarafından oluşturulmuşsa teknik başarısız oluyordu. Bu nedenle bunun için farklı bir Login Items chain keşfedildi.

Bir attacker, çalıştırılacak payload'u içeren **`.bash_profile`** ve **`.zshenv`** dosyalarını oluşturabilir, ardından bunları zip'leyip zip dosyasını victim'ın user klasörüne yazabilirdi: **`~/~$escape.zip`**.

Daha sonra zip dosyası **Login Items**'a ve ardından **`Terminal`** uygulamasına eklenirdi. User yeniden login olduğunda zip dosyası user'ın home klasöründe açılır, **`.bash_profile`** ve **`.zshenv`** dosyalarının üzerine yazılır ve böylece terminal, kullanılan shell'e (bash veya zsh) bağlı olarak bu dosyalardan birini çalıştırırdı.

[**Orijinal rapora buradan**](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c) bakın.<sup>[[3]](#references)</sup>

### Word Sandbox Bypass with Open and env variables

Sandbox'lanmış process'lerden **`open`** utility'si kullanılarak başka process'ler hâlâ çağrılabilir. Ayrıca bu process'ler **kendi sandbox'ları içinde** çalışır.

`open` utility'sinin bir uygulamayı **belirli env** variables ile çalıştırmak için **`--env`** seçeneğine sahip olduğu keşfedildi. Bu nedenle, **sandbox** içindeki bir klasörde **`.zshenv` dosyası** oluşturmak ve `Terminal` uygulamasını açarken `--env` ile **`HOME` variable**'ını bu klasöre ayarlamak mümkün oldu; böylece `Terminal` uygulaması `.zshenv` dosyasını çalıştırıyordu (bir nedenden dolayı `__OSINSTALL_ENVIROMENT` variable'ını ayarlamak da gerekiyordu).

[**Orijinal rapora buradan**](https://perception-point.io/blog/technical-analysis-of-cve-2021-30864/) bakın.<sup>[[4]](#references)</sup>

### Word Sandbox Bypass with Open and stdin

**`open`** utility'si ayrıca **`--stdin`** parametresini destekliyordu (önceki bypass'tan sonra artık `--env` kullanılamıyordu).

Sorun şu ki, **`python`** Apple tarafından imzalanmış olsa bile **`quarantine`** attribute'una sahip bir script'i **çalıştırmaz**. Ancak bir script'i stdin üzerinden geçirmek mümkündü; bu durumda script'in quarantine edilip edilmediği kontrol edilmezdi:

1. Rastgele Python komutları içeren bir **`~$exploit.py`** dosyası bırakın.
2. _open_ **`–stdin='~$exploit.py' -a Python`** komutunu çalıştırın; bu komut, bıraktığımız dosyayı standard input olarak kullanarak Python uygulamasını çalıştırır. Python kodumuzu sorunsuzca çalıştırır ve _launchd_'nin child process'i olduğundan Word'ün sandbox kurallarına bağlı değildir.<sup>[[5]](#references)</sup>

## References

- [1] [Escaping the Sandbox – Microsoft Office on macOS](https://www.mdsec.co.uk/2018/08/escaping-the-sandbox-microsoft-office-on-macos/)
- [2] [Office Drama on macOS](https://objective-see.org/blog/blog_0x4B.html)
- [3] [Office365 MacOS Sandbox Escape](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c)
- [4] [Technical Analysis of CVE-2021-30864](https://perception-point.io/blog/technical-analysis-of-cve-2021-30864/)
- [5] [Uncovering a macOS App Sandbox escape vulnerability: A deep dive into CVE-2022-26706 - Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2022/07/13/uncovering-a-macos-app-sandbox-escape-vulnerability-a-deep-dive-into-cve-2022-26706/)

{{#include ../../../../../banners/hacktricks-training.md}}
