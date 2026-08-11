# macOS Office Sandbox Bypasses

{{#include ../../../../../banners/hacktricks-training.md}}

Aşağıdakiler **tarihsel Microsoft Office for Mac sandbox escape** örnekleridir. Yeniden kullanılabilir trust-boundary hatalarını belgeler; ancak tam sürüm ve policy yeniden üretilmeden, patched Office/macOS kombinasyonlarının vulnerable olduğu varsayılmamalıdır.

### LaunchAgents üzerinden Word sandbox bypass

Etkilenen application, `com.apple.security.temporary-exception.sbpl` üzerinden custom sandbox rule kullanıyordu. Basename'i `~$` ile başlayan regular file'lara izin veriyordu: `(require-any (require-all (vnode-type REGULAR-FILE) (regex #"(^|/)~$[^/]+$")))`.<sup>[[1]](#references)</sup>

Bu nedenle escape işlemi, `~/Library/LaunchAgents/~$escape.plist` konumuna bir **`plist`** LaunchAgent **yazmak** kadar kolaydı.

[**Orijinal rapora buradan**](https://www.mdsec.co.uk/2018/08/escaping-the-sandbox-microsoft-office-on-macos/) bakabilirsiniz.<sup>[[1]](#references)</sup>

### Login Items ve zip üzerinden Word Sandbox bypass

İlk escape'ten itibaren Word'ün adı `~$` ile başlayan arbitrary file'lar yazabildiğini, ancak önceki vuln'un patch'lenmesinden sonra `/Library/Application Scripts` veya `/Library/LaunchAgents` içine yazmanın mümkün olmadığını unutmayın.

Etkilenen sandbox, user login yaptığında launch edilen bir **Login Item** oluşturulmasına izin veriyordu. Gösterilen path, uygun şekilde signed/notarized bir application gerektiriyor ve arbitrary arguments'a izin vermiyordu; bu nedenle reverse-shell argument'ı ile `bash` eklemek yeterli değildi.<sup>[[2]](#references)</sup>

Önceki Sandbox bypass'tan sonra Microsoft, `~/Library/LaunchAgents` içine file yazma seçeneğini devre dışı bıraktı. Ancak **zip file'ı Login Item olarak koyarsanız**, `Archive Utility`'nin onu bulunduğu location'a **unzip** ettiği keşfedildi. Bu nedenle, `~/Library` içindeki `LaunchAgents` folder'ı default olarak oluşturulmadığından, `LaunchAgents/~$escape.plist` içindeki bir **plist'i zip'lemek** ve zip file'ı **`~/Library` içine yerleştirmek** mümkündü; böylece decompress edildiğinde persistence destination'a ulaşacaktı.

[**Orijinal rapora buradan**](https://objective-see.org/blog/blog_0x4B.html) bakabilirsiniz.<sup>[[2]](#references)</sup>

### Login Items ve .zshenv üzerinden Word Sandbox bypass

(İlk escape'ten itibaren Word'ün adı `~$` ile başlayan arbitrary file'lar yazabildiğini unutmayın.)

Ancak önceki technique'in bir limitation'ı vardı: başka bir software `**~/Library/LaunchAgents`** folder'ını oluşturmuşsa başarısız oluyordu. Bu nedenle bunun için farklı bir Login Items chain keşfedildi.

Bir attacker payload içeren **`.bash_profile`** ve **`.zshenv`** file'ları oluşturup bunları archive'leyebilir ve ZIP'i **victim'ın** home directory'sine **`~/~$escape.zip`** olarak yazabilirdi.

Ardından ZIP'i ve **Terminal**'i Login Items olarak ekleyin. Sonraki login sırasında Archive Utility dotfile'ları user's home directory'sine extract eder ve Terminal'in shell'i applicable startup file'ı (`.bash_profile` for the demonstrated Bash path or `.zshenv` for Zsh) evaluate eder.<sup>[[3]](#references)</sup>

[**Orijinal rapora buradan**](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c) bakabilirsiniz.<sup>[[3]](#references)</sup>

### Open ve env variables ile Word Sandbox Bypass

Sandboxed process'ler **`open`** üzerinden application launch request'leri göndermeye devam edebiliyordu. Launch edilen application, Word'ün exact sandbox profile'ını inherit etmek yerine kendi security context'i içinde çalışıyordu.<sup>[[4]](#references)</sup>

Etkilenen `open` utility'si environment variables sağlamak için bir **`--env`** option'ına sahipti. Exploit, sandbox içinde `.zshenv` oluşturuyor, `HOME`'u bu directory'ye ayarlıyor ve Zsh'in bunu evaluate etmesi için Terminal'i launch ediyordu. Report edilen chain ayrıca yanlış yazılmış private variable olan `__OSINSTALL_ENVIROMENT`'ı da ayarlıyordu; historical PoC yeniden üretilirken bu exact spelling korunmalıdır.<sup>[[4]](#references)</sup>

[**Orijinal rapora buradan**](https://perception-point.io/blog/technical-analysis-of-cve-2021-30864/) bakabilirsiniz.<sup>[[4]](#references)</sup>

### Open ve stdin ile Word Sandbox Bypass

**`open`** utility'si ayrıca **`--stdin`** param'ını da destekliyordu (önceki bypass'tan sonra `--env` kullanmak artık mümkün değildi).

Apple'ın Python application'ı quarantined bir script file'ını reddetse de vulnerable workflow, file-based quarantine check'ini atlayarak aynı script'i standard input üzerinden gönderebiliyordu:<sup>[[5]](#references)</sup>

1. Arbitrary Python commands içeren bir **`~$exploit.py`** file'ı bırakın.
2. `open --stdin='~$exploit.py' -a Python` komutunu çalıştırın. Launch edilen Python application, bırakılan code'u standard input üzerinden alır ve vulnerable version'larda Word'ün sandbox'ı dışında çalışır; bunun nedeni LaunchServices'ın application'ı `launchd` altında oluşturmasıdır.<sup>[[5]](#references)</sup>

## References

- [1] [Sandbox'tan kaçış – macOS üzerinde Microsoft Office](https://www.mdsec.co.uk/2018/08/escaping-the-sandbox-microsoft-office-on-macos/)
- [2] [macOS üzerinde Office Dramı](https://objective-see.org/blog/blog_0x4B.html)
- [3] [Office365 MacOS Sandbox Escape](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c)
- [4] [CVE-2021-30864 Teknik Analizi](https://perception-point.io/blog/technical-analysis-of-cve-2021-30864/)
- [5] [Bir macOS App Sandbox escape açığının ortaya çıkarılması: CVE-2022-26706'ya derinlemesine bakış - Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2022/07/13/uncovering-a-macos-app-sandbox-escape-vulnerability-a-deep-dive-into-cve-2022-26706/)
{{#include ../../../../../banners/hacktricks-training.md}}
