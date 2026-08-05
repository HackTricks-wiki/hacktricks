# macOS Office Sandbox Bypass'leri

{{#include ../../../../../banners/hacktricks-training.md}}

### Launch Agents üzerinden Word Sandbox bypass'i

Uygulama, **`com.apple.security.temporary-exception.sbpl`** entitlement'ini kullanarak **custom Sandbox** uygular ve bu custom sandbox, dosya adı `~$` ile başladığı sürece herhangi bir yere dosya yazılmasına izin verir: `(require-any (require-all (vnode-type REGULAR-FILE) (regex #"(^|/)~$[^/]+$")))`

Bu nedenle escape işlemi, `~/Library/LaunchAgents/~$escape.plist` konumuna bir **`plist`** LaunchAgent **yazmak** kadar kolaydı.

[**Orijinal rapora buradan**](https://www.mdsec.co.uk/2018/08/escaping-the-sandbox-microsoft-office-on-macos/) göz atın.<sup>[[1]](#references)</sup>

### Login Items ve zip üzerinden Word Sandbox bypass'i

İlk escape işleminden, Word'ün adı `~$` ile başlayan rastgele dosyalar yazabildiğini; ancak önceki vuln için yayımlanan patch sonrasında `/Library/Application Scripts` veya `/Library/LaunchAgents` konumlarına yazmanın mümkün olmadığını hatırlayın.

Sandbox içinden bir **Login Item** (kullanıcı login olduğunda çalıştırılacak uygulamalar) oluşturmanın mümkün olduğu keşfedildi. Ancak bu uygulamalar **notarized** olmadıkları sürece **çalışmaz** ve **argüman eklemek mümkün değildir** (dolayısıyla **`bash`** kullanarak doğrudan bir reverse shell çalıştıramazsınız).

Önceki Sandbox bypass'inden sonra Microsoft, `~/Library/LaunchAgents` konumuna dosya yazma seçeneğini devre dışı bıraktı. Ancak bir **zip dosyasını Login Item** olarak koyarsanız `Archive Utility` dosyayı bulunduğu konumda doğrudan **unzip** eder. Bu nedenle, varsayılan olarak `~/Library` altındaki `LaunchAgents` klasörü oluşturulmadığından, bir **plist'i `LaunchAgents/~$escape.plist` konumunda zip'lemek** ve zip dosyasını **`~/Library`** içine **yerleştirmek** mümkün oldu; böylece dosya açıldığında persistence hedefine ulaşacaktı.

[**Orijinal rapora buradan**](https://objective-see.org/blog/blog_0x4B.html) göz atın.<sup>[[2]](#references)</sup>

### Login Items ve .zshenv üzerinden Word Sandbox bypass'i

(İlk escape işleminden Word'ün adı `~$` ile başlayan rastgele dosyalar yazabildiğini hatırlayın.)

Ancak önceki tekniğin bir sınırlaması vardı: **`~/Library/LaunchAgents`** klasörü başka bir software tarafından oluşturulmuşsa teknik başarısız oluyordu. Bu nedenle bunun için farklı bir Login Items zinciri keşfedildi.

Bir attacker, çalıştırılacak payload'u içeren **`.bash_profile`** ve **`.zshenv`** dosyalarını oluşturabilir, ardından bunları zip'leyerek zip dosyasını kurban kullanıcının klasörüne **`~/~$escape.zip`** olarak **yazabilirdi**.

Daha sonra zip dosyası **Login Items**'a ve ardından **`Terminal`** uygulaması eklenirdi. Kullanıcı yeniden login olduğunda zip dosyası kullanıcının klasöründe açılır, **`.bash_profile`** ve **`.zshenv`** dosyalarının üzerine yazılır ve bu nedenle terminal, kullanılan shell'in bash veya zsh olmasına bağlı olarak bu dosyalardan birini çalıştırırdı.

[**Orijinal rapora buradan**](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c) göz atın.<sup>[[3]](#references)</sup>

### Open ve env değişkenleri ile Word Sandbox Bypass

Sandboxed process'lerden **`open`** utility'sini kullanarak başka process'ler invoke etmek hâlâ mümkündür. Ayrıca bu process'ler kendi sandbox'ları içinde çalışır.

`open` utility'sinin bir uygulamayı **specific env** değişkenleriyle çalıştırmak için **`--env`** seçeneğine sahip olduğu keşfedildi. Bu nedenle, **sandbox** içindeki bir klasörde **`.zshenv` dosyası** oluşturmak ve `Terminal` uygulamasını açarken **`HOME`** değişkenini bu klasöre ayarlayarak `open` kullanmak mümkün oldu; `Terminal` uygulaması da `.zshenv` dosyasını çalıştıracaktı (nedense **`__OSINSTALL_ENVIROMENT`** değişkenini ayarlamak da gerekliydi).

[**Orijinal rapora buradan**](https://perception-point.io/blog/technical-analysis-of-cve-2021-30864/) göz atın.<sup>[[4]](#references)</sup>

### Open ve stdin ile Word Sandbox Bypass

**`open`** utility'si ayrıca **`--stdin`** parametresini destekliyordu (önceki bypass sonrasında **`--env`** kullanmak artık mümkün değildi).

Sorun şu ki **`python`** Apple tarafından imzalanmış olsa bile **`quarantine`** attribute'una sahip bir script'i **çalıştırmaz**. Ancak bir script'i stdin üzerinden geçirmek mümkündü; böylece dosyanın quarantine edilip edilmediğini kontrol etmezdi:

1. Rastgele Python komutları içeren bir **`~$exploit.py`** dosyası bırakın.
2. _open_ **`–stdin='~$exploit.py' -a Python`** komutunu çalıştırın. Bu komut, bıraktığımız dosyayı standard input olarak kullanarak Python uygulamasını çalıştırır. Python kodumuzu sorunsuzca çalıştırır ve bu process'in parent'ı **_launchd_** olduğu için Word'ün sandbox kurallarına tabi değildir.

## References

- [1] [Escaping the Sandbox – Microsoft Office on macOS](https://www.mdsec.co.uk/2018/08/escaping-the-sandbox-microsoft-office-on-macos/)
- [2] [Office Drama on macOS](https://objective-see.org/blog/blog_0x4B.html)
- [3] [Office365 MacOS Sandbox Escape](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c)
- [4] [Technical Analysis of CVE-2021-30864](https://perception-point.io/blog/technical-analysis-of-cve-2021-30864/)

{{#include ../../../../../banners/hacktricks-training.md}}
