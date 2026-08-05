# macOS Office Sandbox Bypasses

{{#include ../../../../../banners/hacktricks-training.md}}

### Word Sandbox bypass via Launch Agents

Uygulama, **`com.apple.security.temporary-exception.sbpl`** entitlement'ını kullanan **özel bir Sandbox** kullanır ve bu özel sandbox, dosya adı `~$` ile başladığı sürece dosyaların herhangi bir yere yazılmasına izin verir: `(require-any (require-all (vnode-type REGULAR-FILE) (regex #"(^|/)~$[^/]+$")))`

Bu nedenle escape işlemi, **`~/Library/LaunchAgents/~$escape.plist`** konumuna bir **`plist`** LaunchAgent yazmak kadar kolaydı.

[**Orijinal rapora buradan**](https://www.mdsec.co.uk/2018/08/escaping-the-sandbox-microsoft-office-on-macos/) bakın.<sup>[1]</sup>

### Word Sandbox bypass via Login Items and zip

İlk escape işleminden, Word'ün adı `~$` ile başlayan rastgele dosyaları yazabildiğini hatırlayın; ancak önceki zafiyetin patch'lenmesinden sonra `/Library/Application Scripts` veya `/Library/LaunchAgents` içine yazmak mümkün değildi.

Sandbox içinden bir **Login Item** (kullanıcı giriş yaptığında çalıştırılacak uygulamalar) oluşturmanın mümkün olduğu keşfedildi. Ancak bu uygulamalar **notarized olmadıkça çalışmaz** ve **argüman eklemek mümkün değildir** (dolayısıyla **`bash`** kullanarak doğrudan bir reverse shell çalıştıramazsınız).

Önceki Sandbox bypass işleminden sonra Microsoft, `~/Library/LaunchAgents` içine dosya yazma seçeneğini devre dışı bıraktı. Ancak bir **zip dosyasını Login Item olarak eklerseniz**, `Archive Utility`'nin dosyayı bulunduğu konumda doğrudan **unzip** ettiği keşfedildi. Bu nedenle, varsayılan olarak `~/Library` içindeki `LaunchAgents` klasörü oluşturulmadığından, **`LaunchAgents/~$escape.plist`** içindeki bir **plist'i zip'lemek** ve zip dosyasını **`~/Library`** içine yerleştirmek mümkün oldu; böylece dosya açıldığında persistence hedefine ulaşacaktı.

[**Orijinal rapora buradan**](https://objective-see.org/blog/blog_0x4B.html) bakın.<sup>[2]</sup>

### Word Sandbox bypass via Login Items and .zshenv

(İlk escape işleminden, Word'ün adı `~$` ile başlayan rastgele dosyaları yazabildiğini hatırlayın.)

Ancak önceki tekniğin bir kısıtlaması vardı: **`~/Library/LaunchAgents`** klasörü başka bir yazılım tarafından oluşturulmuşsa işlem başarısız oluyordu. Bu nedenle bunun için farklı bir Login Items zinciri keşfedildi.

Bir attacker, çalıştırılacak payload'u içeren **`.bash_profile`** ve **`.zshenv`** dosyalarını oluşturabilir, ardından bunları zip'leyip zip dosyasını victim'ın kullanıcı klasörüne yazabilirdi: **`~/~$escape.zip`**.

Daha sonra zip dosyası **Login Items** içine ve ardından **`Terminal`** uygulaması eklenirdi. Kullanıcı yeniden login olduğunda zip dosyası kullanıcının dosyaları arasına açılır, **`.bash_profile`** ve **`.zshenv`** dosyalarının üzerine yazılırdı; bunun sonucunda Terminal, bash veya zsh kullanılmasına bağlı olarak bu dosyalardan birini çalıştırırdı.

[**Orijinal rapora buradan**](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c) bakın.<sup>[3]</sup>

### Word Sandbox Bypass with Open and env variables

Sandbox'lanmış process'lerden **`open`** utility'sini kullanarak başka process'leri çağırmak hâlâ mümkündür. Ayrıca bu process'ler kendi sandbox'ları içinde çalışır.

`open` utility'sinin bir uygulamayı **belirli env** değişkenleriyle çalıştırmak için **`--env`** seçeneğine sahip olduğu keşfedildi. Bu nedenle, **sandbox** içindeki bir klasörün içinde **`.zshenv` dosyası** oluşturmak ve `open` komutunu, **`HOME` değişkenini** bu klasöre ayarlayacak şekilde `--env` ile kullanarak `Terminal` uygulamasını açmak mümkün oldu; bu işlem `.zshenv` dosyasını çalıştırırdı (bazı nedenlerle `__OSINSTALL_ENVIROMENT` değişkenini ayarlamak da gerekiyordu).

[**Orijinal rapora buradan**](https://perception-point.io/blog/technical-analysis-of-cve-2021-30864/) bakın.<sup>[4]</sup>

### Word Sandbox Bypass with Open and stdin

**`open`** utility'si ayrıca **`--stdin`** parametresini destekliyordu (önceki bypass işleminden sonra artık `--env` kullanılamıyordu).

Sorun şu ki **`python`** Apple tarafından imzalanmış olsa bile **`quarantine`** attribute'una sahip bir script'i **execute etmez**. Ancak bir script'i stdin üzerinden geçirmek mümkündü; böylece dosyanın quarantine durumunu kontrol etmezdi:

1. Rastgele Python komutları içeren bir **`~$exploit.py`** dosyası bırakın.
2. _open_ **`–stdin='~$exploit.py' -a Python`** komutunu çalıştırın; bu, bıraktığımız dosyayı standard input olarak kullanarak Python uygulamasını çalıştırır. Python kodumuzu sorunsuzca çalıştırır ve _launchd_'nin child process'i olduğu için Word'ün sandbox kurallarına tabi değildir.

## References

- [1] [Escaping the Sandbox – Microsoft Office on macOS](https://www.mdsec.co.uk/2018/08/escaping-the-sandbox-microsoft-office-on-macos/)
- [2] [Office Drama on macOS](https://objective-see.org/blog/blog_0x4B.html)
- [3] [Office365 MacOS Sandbox Escape](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c)
- [4] [Technical Analysis of CVE-2021-30864](https://perception-point.io/blog/technical-analysis-of-cve-2021-30864/)

{{#include ../../../../../banners/hacktricks-training.md}}
