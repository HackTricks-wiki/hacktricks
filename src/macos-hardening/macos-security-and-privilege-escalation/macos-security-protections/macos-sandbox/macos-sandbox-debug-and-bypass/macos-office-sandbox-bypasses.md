# macOS Office Sandbox Bypasses

{{#include ../../../../../banners/hacktricks-training.md}}

### Word Sandbox bypass via Launch Agents

Uygulama, **`com.apple.security.temporary-exception.sbpl`** yetkisini kullanarak **özel bir Sandbox** kullanıyor ve bu özel sandbox, dosya adının `~$` ile başlaması koşuluyla her yere dosya yazılmasına izin veriyor: `(require-any (require-all (vnode-type REGULAR-FILE) (regex #"(^|/)~$[^/]+$")))`

Bu nedenle, kaçış yapmak **`~/Library/LaunchAgents/~$escape.plist`** içinde bir **`plist`** LaunchAgent yazmak kadar kolaydı.

[**orijinal raporu buradan kontrol edin**](https://www.mdsec.co.uk/2018/08/escaping-the-sandbox-microsoft-office-on-macos/).

### Word Sandbox bypass via Login Items and zip

İlk kaçıştan hatırlayın, Word `~$` ile başlayan rastgele dosyalar yazabilir, ancak önceki güvenlik açığının yamanmasından sonra `/Library/Application Scripts` veya `/Library/LaunchAgents` dizinlerine yazmak mümkün değildi.

Sandbox içinde bir **Login Item** (kullanıcı giriş yaptığında çalıştırılacak uygulamalar) oluşturmanın mümkün olduğu keşfedildi. Ancak, bu uygulamalar **notarize edilmedikçe** **çalışmayacak** ve **argüman eklemek mümkün değil** (yani sadece **`bash`** kullanarak bir ters shell çalıştıramazsınız).

Önceki Sandbox kaçışından sonra, Microsoft `~/Library/LaunchAgents` dizinine dosya yazma seçeneğini devre dışı bıraktı. Ancak, bir **zip dosyasını Login Item olarak** koyarsanız, `Archive Utility` onu mevcut konumunda **açacaktır**. Bu nedenle, varsayılan olarak `~/Library` içindeki `LaunchAgents` klasörü oluşturulmadığı için, **`LaunchAgents/~$escape.plist`** içinde bir plist'i **zipleyip** **`~/Library`** içine yerleştirmek mümkün oldu, böylece açıldığında kalıcılık hedefine ulaşacaktır.

[**orijinal raporu buradan kontrol edin**](https://objective-see.org/blog/blog_0x4B.html).

### Word Sandbox bypass via Login Items and .zshenv

(İlk kaçıştan hatırlayın, Word `~$` ile başlayan rastgele dosyalar yazabilir).

Ancak, önceki tekniğin bir sınırlaması vardı; eğer **`~/Library/LaunchAgents`** dizini başka bir yazılım tarafından oluşturulmuşsa, bu başarısız olurdu. Bu nedenle, bunun için farklı bir Login Items zinciri keşfedildi.

Bir saldırgan, çalıştırılacak yük ile **`.bash_profile`** ve **`.zshenv`** dosyalarını oluşturabilir ve ardından bunları zipleyip **kurbanın** kullanıcı klasörüne yazabilir: **`~/~$escape.zip`**.

Sonra, zip dosyasını **Login Items**'a ekleyip ardından **`Terminal`** uygulamasını ekleyin. Kullanıcı tekrar giriş yaptığında, zip dosyası kullanıcı dosyasında açılacak, **`.bash_profile`** ve **`.zshenv`** dosyalarını üzerine yazacak ve dolayısıyla terminal bu dosyalardan birini çalıştıracaktır (bash veya zsh kullanılıp kullanılmadığına bağlı olarak).

[**orijinal raporu buradan kontrol edin**](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c).

### Word Sandbox Bypass with Open and env variables

Sandboxed süreçlerden, **`open`** aracını kullanarak diğer süreçleri çağırmak hala mümkündür. Dahası, bu süreçler **kendi sandbox'larında** çalışacaktır.

Open aracının **belirli env** değişkenleri ile bir uygulama çalıştırmak için **`--env`** seçeneğine sahip olduğu keşfedildi. Bu nedenle, **sandbox** içinde bir klasör içinde **`.zshenv` dosyası** oluşturmak ve `open` komutunu `--env` ile kullanarak **`HOME` değişkenini** o klasöre ayarlamak mümkündü, bu da `Terminal` uygulamasını açacak ve `.zshenv` dosyasını çalıştıracaktır (bir sebepten dolayı `__OSINSTALL_ENVIROMENT` değişkenini de ayarlamak gerekiyordu).

[**orijinal raporu buradan kontrol edin**](https://perception-point.io/blog/technical-analysis-of-cve-2021-30864/).

### Word Sandbox Bypass with Open and stdin

**`open`** aracı ayrıca **`--stdin`** parametresini destekliyordu (ve önceki kaçıştan sonra `--env` kullanmak artık mümkün değildi).

Şu durum var ki, **`python`** Apple tarafından imzalanmış olsa da, **`quarantine`** niteliğine sahip bir betiği **çalıştırmaz**. Ancak, stdin'den bir betik geçirebiliriz, böylece karantinada olup olmadığını kontrol etmeyecektir:

1. Rastgele Python komutları içeren bir **`~$exploit.py`** dosyası bırakın.
2. _open_ **`–stdin='~$exploit.py' -a Python`** komutunu çalıştırın, bu Python uygulamasını standart girdi olarak bıraktığımız dosya ile çalıştırır. Python, kodumuzu memnuniyetle çalıştırır ve çünkü bu _launchd_'nin bir çocuk süreci olduğundan, Word'ün sandbox kurallarına bağlı değildir.

{{#include ../../../../../banners/hacktricks-training.md}}
