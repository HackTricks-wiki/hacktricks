# Tehdit Modellemesi ve Kimlik Ayrımı

{{#include ../banners/hacktricks-training.md}}

En yaygın anonymity failure nedeni bozuk cryptography değildir. Sorun **linkage**'dır: ayrı tutulması gereken iki bağlamı birbirine bağlayan tek bir identifier, zamanlama örüntüsü, cihaz, hesap, ödeme, dosya veya insan alışkanlığı.

## Bir privacy threat model oluşturun

EFF'nin altı soruluk security planı güçlü bir temeldir: neyin, kimden korunması gerektiği; failure etkisi ve olasılığı; mevcut çaba; ve yardımcı olabilecek müttefikler.<sup>[[1]](#references)</sup> Bunu küçük bir tabloyla uygulanabilir hale getirin:

| Asset/action | Observer | Observable data | Correlation route | Control | Residual risk |
|---|---|---|---|---|---|
| Bir client'ı araştırma | ISP | Destination/timing metadata | Home subscriber record | Tor Browser | Tor kullanımı görünür; end-to-end correlation |
| Pseudonymous account | Platform | IP, browser, recovery data | Reused phone/email/photo | Dedicated context and alias | Writing/social graph correlation |
| Online purchase | Merchant | Account, delivery, tokenized card | Address and account history | Guest checkout, minimal fields, virtual card | Issuer and carrier retain records |
| Red-team traffic | Target/client | Source IP and behavior | Provider/engagement records | Dedicated authorized egress | Deliberately attributable under escalation |

Location, provider, device, counterpart veya sonuçlar değiştiğinde tabloyu gözden geçirin.

## Linkability graph çizin

Her identity'yi ayrı bir node olarak ele alın. Paylaşılan her attribute için bir edge ekleyin:

- email veya recovery address;
- phone number veya contact-book upload;
- username, avatar, photo, bio veya writing/code style;
- password, passkey-sync account veya recovery question;
- device, advertising ID, browser profile, cookies, fonts veya extensions;
- IP address, time zone, language, schedule veya simultaneous online status;
- bank card, exchange account, wallet cluster, shipping address veya loyalty program;
- document author fields, EXIF location, printer marks veya cloud-share owner;
- colleague, group membership ve social graph.

Bir edge otomatik olarak ölümcül değildir, ancak hangi observer'ın bağlantıyı kurabileceğini gösterir. EFF özellikle phone numbers, email addresses ve yeniden kullanılan photograph'ların profilleri birbirine bağlayabileceği konusunda uyarır.<sup>[[2]](#references)</sup>

## Adım adım compartment oluşturun

1. **Bağlamı ve yasaklanan bağlantıları adlandırın.** Örnek: `client-red-2026`; personal email, home browser profiles, personal payment methods ve ilgisiz client'larla bağlantı yasak.
2. **Isolation boundary'yi seçin.** Güç sırasıyla: separate browser profile → separate OS account → separate VM/qube → dedicated device. Ayrı bir tab veya private window security boundary değildir.
3. **Bu boundary içinde fresh identifier'lar oluşturun.** Context-specific email/alias, username, password-manager vault veya collection ve authentication keys kullanın. Provider'dan unlinkability önemliyse personal recovery channel eklemeyin.
4. **Tek bir network policy seçin.** Context'in her zaman client VPN, engagement VPS, trusted VPN veya Tor kullanıp kullanmayacağına karar verin. Mümkün olduğunda fail-closed routing uygulayın.
5. **Bir payment policy seçin.** Payment method observer modeline uygun olmalıdır; virtual card PAN'ı merchant'tan gizleyebilir, ancak customer'ı issuer'a yine de tanımlar.
6. **Data-transfer kurallarını belirleyin.** Dar kapsamlı ve bilinçli transferleri tercih edin. Clipboard, shared folders, USB devices, cloud sync, printers ve screenshots'u olası bridge'ler olarak değerlendirin.
7. **Oluşturma ve teardown tarihlerini kaydedin.** Contract/tax/compliance için hangi evidence'ın saklanması gerektiğini ve hangi transient data'nın süresinin dolması gerektiğini tanımlayın.
8. **Kullanmadan önce bağlantı testi yapın.** Account settings, recovery fields, public profile, IP/DNS, browser state, file metadata ve provider dashboards'u inceleyin.

{% hint style="warning" %}
Bir service veya law doğru identification gerektiriyorsa identity information uydurmayın. Privacy compartment; identity fraud veya customer due diligence bypass etmekle değil, data minimization ve separation ile ilgilidir.
{% endhint %}

## Endpoint ve account baseline

- Supported hardware kullanın ve OS, browser, wallet ve firmware updates'ı zamanında yükleyin.
- Device encryption'ı etkinleştirin ve güçlü bir device passcode kullanın. Encryption at rest, powered-off bir device kaybolduğunda veya el konulduğunda yardımcı olur; ancak malware veya unlocked session data okuyabildiğinde yardımcı olmaz.<sup>[[3]](#references)</sup>
- Password manager içinde unique ve randomly generated passwords kullanın.
- Threat model, recovery/sync modeline izin veriyorsa WebAuthn/passkeys veya hardware security keys gibi phishing-resistant authentication yöntemlerini tercih edin. NIST, manually entered OTP'lerin phishing-resistant olmadığını belirtir; çünkü bir impostor bunları relay edebilir.<sup>[[4]](#references)</sup>
- Recovery codes'ları offline ve endpoint'ten ayrı tutun. Synced passkey account'ın ayrı kalması gereken identities'leri birleştirip birleştirmediğini gözden geçirin.
- Gereksiz location, contacts, microphone, camera, Bluetooth, advertising-ID ve background permissions'larını devre dışı bırakın.
- Personal cloud sync, browser sync, password-manager accounts veya app stores'u high-separation context'e dahil etmeyin.

## Browser privacy

Browser fingerprinting; observable configuration, device, environment ve behavior kullanarak bir user'ı tanımlar veya onunla correlation kurar. Cookies'leri temizlemek veya IP addresses'leri değiştirmek bunu güvenilir biçimde engellemez; W3C, yaygın olarak kullanılan yöntemlerle bunun tamamen teknik olarak ortadan kaldırılmasını olası görmemektedir.<sup>[[5]](#references)</sup>

Ordinary privacy için:

1. HTTPS-only mode ve güçlü tracking protection içeren, maintained bir browser kullanın.
2. Third-party tracking'i engelleyin ve desteklendiği yerlerde state'i partition edin.
3. Gerçekten ayrı context'ler için separate browser profiles kullanın.
4. Gereksiz permissions'ları devre dışı bırakın ve site data'yı belirlenmiş bir schedule'a göre temizleyin.
5. İlgisiz sensitive research yaparken identity-rich accounts'a login olmaktan kaçının.

Web anonymity için **Tor Browser'ı standard configuration ile kullanın**. Normal bir browser'ı Tor üzerinden proxy'lemeyin: Tor Project, ordinary browsers'ın DNS/WebRTC, persistent state, fonts, plugins ve fingerprint differences üzerinden leak edebileceği konusunda uyarır.<sup>[[6]](#references)</sup> Browser'ı öne çıkaran extra extensions, unusual window sizes, custom fonts ve preferences'lardan kaçının.<sup>[[7]](#references)</sup>

## Communications ve metadata

Metadata, message content encrypted olsa bile sender, recipient, time, location ve diğer context bilgilerini içerir.<sup>[[8]](#references)</sup>

- Pratik olduğunda minimized server-side metadata ve open protocols/clients içeren end-to-end-encrypted tools'u tercih edin.
- Sensitive contacts'ı bağımsız bir channel veya yüz yüze doğrulayın. Signal safety numbers bu kontrol için tasarlanmıştır.<sup>[[9]](#references)</sup>
- Signal usernames, phone number paylaşmadan contact başlatabilir; ancak register olmak için phone number hâlâ gereklidir. Phone-number visibility/discoverability ayarlarını bilinçli biçimde yapılandırın.<sup>[[9]](#references)</sup>
- Disappearing messages, saklanan copies'leri azaltır; recipients yine de içeriğin fotoğrafını çekebilir, kopyalayabilir, forward edebilir veya archive edebilir.
- Email normalde routing metadata'yı açığa çıkarır. Privacy-focused providers bile karşı taraf ordinary email kullanıyorsa bir message'ı end-to-end encrypted hale getiremez; bunun için her iki tarafın da compatible bir E2EE method kullanması gerekir. Örneğin Proton, diğer providers'a gönderilen ordinary mail'in TLS kullandığını ve receiving provider tarafından okunabilir kaldığını belgelendirir.<sup>[[10]](#references)</sup>
- Address books'ı ayırın ve personal contacts'ı pseudonymous account'a upload etmeyin.

## Files, photos ve authorship

Tails, photographs'ların camera ve location data içerebileceği, office documents'ın ise author ve creation-time fields barındırabileceği konusunda uyarır.<sup>[[11]](#references)</sup>

Paylaşmadan önce:
```bash
# Inspect recursively; do not assume the extension tells the whole story
exiftool -a -u -g1 path/to/file

# Create a cleaned copy. Verify the copy before publishing.
exiftool -all= -o cleaned-file path/to/file
```
Ardından temizlenmiş kopyayı izole bir görüntüleyicide yeniden açın ve şunları kontrol edin:

- belge özellikleri, yorumlar, izlenen değişiklikler, gizli sayfalar/slaytlar, küçük resimler ve ekler;
- EXIF/XMP/IPTC, GPS, zaman damgaları, cihaz/yazılım adları ve benzersiz kimlikler;
- görünür yansımalar, bilinen yapılar, ekran içerikleri, sesler, yüzler ve arka plan sesleri;
- dosya adı, arşiv yolları, cloud-share sahibi, imzalama sertifikası ve revizyon geçmişi.

Sanitization, kanıta veya özgünlüğe zarar verebilir. Muhafaza zinciri veya daha sonra doğrulama önemliyse şifrelenmiş bir orijinali saklayın. Stylometry ve coding style da authorship ile bağlantı kurabilir; metadata kaldırma, insan stilini değiştirmez.

## Yaygın hata kalıpları

- “anonymous” bir bağlantı üzerinden kişisel bir hesaba giriş yapmak.
- Bir recovery phone, avatar, username, public key, wallet veya donation address'i yeniden kullanmak.
- Correlated context'lerden aynı anda iki identity işletmek.
- Metinleri/dosyaları kişisel bir cloud clipboard veya shared folder üzerinden kopyalamak.
- Ayırt edici Tor Browser extensions yüklemek veya birçok default ayarı değiştirmek.
- Ne kaydedildiğini, ne kadar süreyle saklandığını ve hangi subcontractors tarafından kaydedildiğini anlamadan “no logs” iddiasına güvenmek.
- İkincil bir telefonun kişisel telefonla birlikte hareket ederken anonymous olduğunu varsaymak. EFF, cellular location ve co-travel bilgilerinin cihazları ilişkilendirebileceğini belirtiyor.<sup>[[3]](#references)</sup>
- Encryption'ı deletion olarak değerlendirmek; endpoints ve recipients plaintext'i saklayabilir.

## Verification checklist

- [ ] Context içinde kasıtlı olarak kabul edilmedikçe kişisel recovery address, phone, sync account veya yeniden kullanılan media bulunmuyor.
- [ ] Amaçlanan network path aktif ve fails closed durumunda.
- [ ] Browser/device time zone, locale, extensions ve permissions planla eşleşiyor.
- [ ] Compartment içinde kişisel hesaplar açık değil.
- [ ] Dosyalar incelendi ve sanitized edildi; orijinaller ayrı şekilde işleniyor.
- [ ] Contacts, second channel üzerinden authenticated ediliyor.
- [ ] Provider-visible metadata ve retention period anlaşılmış durumda.
- [ ] Teardown, evidence retention ve account-recovery procedures belgelenmiş durumda.

## References

- [1] [EFF Surveillance Self-Defense — Güvenlik Planınız](https://ssd.eff.org/module/your-security-plan)
- [2] [EFF Surveillance Self-Defense — Social Networks'te Kendinizi Koruma](https://ssd.eff.org/module/protecting-yourself-social-networks)
- [3] [EFF Surveillance Self-Defense — Bir Protestoya Katılma](https://ssd.eff.org/module/attending-protest)
- [4] [NIST SP 800-63B-4 — Authentication ve Authenticator Management](https://pages.nist.gov/800-63-4/sp800-63b.html)
- [5] [W3C — Web Specifications'ta Browser Fingerprinting'i Azaltma](https://www.w3.org/TR/fingerprinting-guidance/)
- [6] [Tor Project — Tor'u diğer browser'larla kullanma](https://support.torproject.org/tor-browser/security/using-tor-with-other-browsers/)
- [7] [Tor Project — Tor Browser'da Plugins ve Add-ons](https://support.torproject.org/tor-browser/features/plugins/)
- [8] [EFF Surveillance Self-Defense — Communication Metadata Neden Önemlidir](https://ssd.eff.org/module/why-metadata-matters)
- [9] [Signal — Phone Number Privacy ve Usernames: Daha Derin İnceleme](https://support.signal.org/hc/en-us/articles/6829998083994-Phone-Number-Privacy-and-Usernames-Deeper-Dive)
- [10] [Proton — Proton Mail içinde neler encrypted durumdadır?](https://proton.me/support/what-is-encrypted-within-protonmail)
- [11] [Tails — Warnings: Tails güvenlidir ama sihirli değildir](https://tails.net/doc/about/warnings/index.en.html)
{{#include ../banners/hacktricks-training.md}}
