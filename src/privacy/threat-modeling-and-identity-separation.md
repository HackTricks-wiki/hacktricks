# Threat Modeling & Identity Separation

En yaygın anonimlik başarısızlığı bozuk cryptography değildir. Sorun **linkage**'dır: ayrı kalması gereken iki context'i birbirine bağlayan tek bir identifier, zamanlama pattern'i, device, account, payment, file veya insan alışkanlığı.

## Bir privacy threat model oluşturun

EFF'nin altı soruluk security planı güçlü bir temeldir: neyin korunması gerektiği, kimden korunacağı, başarısızlığın etkisi ve olasılığı, mevcut çaba ve yardımcı olabilecek müttefikler.<sup>[[1]](#references)</sup> Küçük bir tabloyla bunu operasyonel hale getirin:

| Asset/action | Observer | Observable data | Correlation route | Control | Residual risk |
|---|---|---|---|---|---|
| Bir client'ı araştırma | ISP | Destination/timing metadata | Home subscriber record | Tor Browser | Tor kullanımının görünür olması; uçtan uca correlation |
| Pseudonymous account | Platform | IP, browser, recovery data | Reused phone/email/photo | Dedicated context and alias | Writing/social graph correlation |
| Online purchase | Merchant | Account, delivery, tokenized card | Address and account history | Guest checkout, minimal fields, virtual card | Issuer ve carrier kayıtları saklar |
| Red-team traffic | Target/client | Source IP and behavior | Provider/engagement records | Dedicated authorized egress | Escalation altında kasıtlı olarak attributable |

Location, provider, device, counterpart veya consequences değiştiğinde tabloyu gözden geçirin.

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

Bir edge otomatik olarak ölümcül değildir, ancak bağlantıyı hangi observer'ın kurabileceğini gösterir. EFF özellikle phone number'ların, email address'lerin ve yeniden kullanılan photograph'ların profilleri birbirine bağlayabileceği konusunda uyarır.<sup>[[2]](#references)</sup>

## Adım adım bir compartment oluşturun

1. **Context'i ve yasaklanan bağlantıları adlandırın.** Örnek: `client-red-2026`; personal email, home browser profiles, personal payment methods ve ilgisiz client'larla bağlantı yasak.
2. **Isolation boundary'yi seçin.** Artan güç sırasıyla: separate browser profile → separate OS account → separate VM/qube → dedicated device. Separate tab veya private window bir security boundary değildir.
3. **Bu boundary içinde fresh identifier'lar oluşturun.** Context-specific email/alias, username, password-manager vault veya collection ve authentication keys kullanın. Provider'dan unlinkability önemliyse personal recovery channel eklemeyin.
4. **Tek bir network policy seçin.** Context'in her zaman client VPN, engagement VPS, trusted VPN veya Tor kullanıp kullanmayacağına karar verin. Mümkünse fail-closed routing uygulayın.
5. **Bir payment policy seçin.** Payment method observer model'ine uygun olmalıdır; virtual card PAN'ı merchant'tan gizleyebilir, ancak customer'ı yine issuer'a tanımlar.
6. **Data-transfer kuralları belirleyin.** Dar kapsamlı ve bilinçli transferleri tercih edin. Clipboard, shared folders, USB devices, cloud sync, printers ve screenshots'ı olası bridge'ler olarak değerlendirin.
7. **Oluşturma ve teardown tarihlerini kaydedin.** Contracts/tax/compliance için hangi evidence'ın saklanması gerektiğini ve hangi transient data'nın süresinin dolması gerektiğini tanımlayın.
8. **Kullanmadan önce bağlantı testleri yapın.** Account settings, recovery fields, public profile, IP/DNS, browser state, file metadata ve provider dashboards'ı inceleyin.

{% hint style="warning" %}
Bir service veya law doğru identification gerektiriyorsa identity bilgisi uydurmayın. Privacy compartment, identity fraud veya customer due diligence'ı bypass etmekle değil, data minimization ve separation ile ilgilidir.
{% endhint %}

## Endpoint ve account baseline

- Supported hardware kullanın ve OS, browser, wallet ve firmware updates'ı gecikmeden yükleyin.
- Device encryption'ı etkinleştirin ve güçlü bir device passcode kullanın. At-rest encryption, powered-off bir device kaybolduğunda veya seized olduğunda yardımcı olur, ancak malware veya unlocked session data'yı okuyabildiğinde koruma sağlamaz.<sup>[[3]](#references)</sup>
- Bir password manager içinde unique, randomly generated passwords kullanın.
- Threat model izin veriyorsa WebAuthn/passkeys veya hardware security keys gibi phishing-resistant authentication yöntemlerini, bunların recovery/sync model'ini dikkate alarak tercih edin. NIST, manually entered OTP'lerin phishing-resistant olmadığını; çünkü bir impostor'ın bunları relay edebileceğini belirtir.<sup>[[4]](#references)</sup>
- Recovery codes'ları offline ve endpoint'ten ayrı tutun. Synced passkey account'ın ayrı kalması gereken identity'leri birleştirip birleştirmediğini gözden geçirin.
- Gereksiz location, contacts, microphone, camera, Bluetooth, advertising-ID ve background permissions'larını devre dışı bırakın.
- Personal cloud sync, browser sync, password-manager accounts veya app stores'ı high-separation context'e dahil etmeyin.

## Browser privacy

Browser fingerprinting, bir user'ı tanımlamak veya correlate etmek için gözlemlenebilir configuration, device, environment ve behavior kullanır. Cookies'leri temizlemek veya IP address'leri değiştirmek bunu güvenilir biçimde engellemez ve W3C, yaygın biçimde deploy edilmiş yöntemlerle tamamen teknik olarak ortadan kaldırılmasını gerçekçi bulmaz.<sup>[[5]](#references)</sup>

Sıradan privacy için:

1. HTTPS-only mode ve güçlü tracking protection içeren, bakımı sürdürülen bir browser kullanın.
2. Third-party tracking'i engelleyin ve destekleniyorsa state'i partition edin.
3. Gerçekten ayrı context'ler için separate browser profiles kullanın.
4. Gereksiz permissions'ları devre dışı bırakın ve site data'yı belirlenmiş bir schedule'a göre temizleyin.
5. İlgisiz sensitive research yaparken identity-rich accounts'a login olmaktan kaçının.

Web anonymity için **Tor Browser'ın standard configuration'ını** kullanın. Normal bir browser'ı Tor üzerinden proxy'lemeyin: Tor Project, ordinary browser'ların DNS/WebRTC, persistent state, fonts, plugins ve fingerprint differences üzerinden leak edebileceği konusunda uyarır.<sup>[[6]](#references)</sup> Browser'ı öne çıkaran extra extensions, unusual window sizes, custom fonts ve preferences kullanmaktan kaçının.<sup>[[7]](#references)</sup>

## Communications ve metadata

Metadata, message content encrypted olsa bile sender, recipient, time, location ve diğer context bilgilerini içerir.<sup>[[8]](#references)</sup>

- Pratik olduğu durumlarda minimized server-side metadata'ya ve open protocols/clients'a sahip end-to-end-encrypted tools'ları tercih edin.
- Sensitive contacts'ları bağımsız bir channel üzerinden veya yüz yüze doğrulayın. Signal safety numbers bu check için tasarlanmıştır.<sup>[[9]](#references)</sup>
- Signal usernames, phone number paylaşmadan contact başlatabilir, ancak register olmak için phone number hâlâ gereklidir; phone-number visibility/discoverability ayarlarını bilinçli biçimde yapılandırın.<sup>[[9]](#references)</sup>
- Disappearing messages, saklanan copies'leri azaltır; recipients yine de içeriği photograph edebilir, copy, forward veya archive edebilir.
- Email normalde routing metadata'yı açığa çıkarır. Privacy-focused providers bile karşı taraf ordinary email kullanıyorsa message'ı end-to-end encrypted hale getiremez; her iki tarafın da compatible E2EE method kullanması gerekir. Örneğin Proton, diğer provider'lara gönderilen ordinary mail'in TLS kullandığını ve receiving provider tarafından okunabilir kaldığını açıklar.<sup>[[10]](#references)</sup>
- Address books'ı ayırın ve personal contacts'ı pseudonymous account'a upload etmeyin.

## Files, photos ve authorship

Tails, photographs'ların camera ve location data içerebileceği; office documents'ın ise author ve creation-time fields barındırabileceği konusunda uyarır.<sup>[[11]](#references)</sup>

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
- görünür yansımalar, belirgin yerler, ekran içerikleri, sesler, yüzler ve arka plan sesleri;
- dosya adı, arşiv yolları, cloud-share sahibi, imzalama sertifikası ve revizyon geçmişi.

Sanitization kanıta veya özgünlüğe zarar verebilir. Zilyetlik zinciri veya daha sonra doğrulama önemliyse şifrelenmiş bir orijinali koruyun. Stylometry ve coding style da authorship ile bağlantı kurabilir; metadata removal insan stilini değiştirmez.

## Yaygın hata kalıpları

- “anonymous” bir bağlantı üzerinden kişisel bir hesaba giriş yapmak.
- Bir recovery phone, avatar, username, public key, wallet veya donation address'i yeniden kullanmak.
- İki identity'yi aynı anda, birbiriyle ilişkilendirilebilecek context'lerden işletmek.
- Metinleri/dosyaları kişisel bir cloud clipboard veya paylaşılan klasör üzerinden kopyalamak.
- Ayırt edici Tor Browser extensions yüklemek veya birçok varsayılanı değiştirmek.
- Nelerin, ne kadar süreyle ve hangi subcontractors tarafından loglandığını anlamadan “no logs” iddiasına güvenmek.
- İkincil bir telefonun kişisel telefonun yanında seyahat ederken anonymous olduğunu varsaymak. EFF, cellular location ve co-travel bilgilerinin cihazları ilişkilendirebileceğini belirtiyor.<sup>[[3]](#references)</sup>
- Encryption'ı deletion olarak değerlendirmek; endpoints ve recipients plaintext'i saklayabilir.

## Doğrulama kontrol listesi

- [ ] Context'te kişisel recovery address, phone, sync account veya yeniden kullanılan media yoktur; bunlar bilerek kabul edilmedikçe.
- [ ] Amaçlanan network path aktiftir ve fails closed.
- [ ] Browser/device time zone, locale, extensions ve permissions planla uyumludur.
- [ ] Compartment içinde hiçbir kişisel hesap açık değildir.
- [ ] Files incelenmiş ve sanitized edilmiştir; originals ayrı şekilde ele alınır.
- [ ] Contacts, ikinci bir channel üzerinden authenticated edilmiştir.
- [ ] Provider-visible metadata ve retention period anlaşılmıştır.
- [ ] Teardown, evidence retention ve account-recovery procedures belgelenmiştir.

## References

- [1] [EFF Surveillance Self-Defense — Güvenlik Planınız](https://ssd.eff.org/module/your-security-plan)
- [2] [EFF Surveillance Self-Defense — Social Networks'te Kendinizi Koruma](https://ssd.eff.org/module/protecting-yourself-social-networks)
- [3] [EFF Surveillance Self-Defense — Bir Protestoya Katılma](https://ssd.eff.org/module/attending-protest)
- [4] [NIST SP 800-63B-4 — Authentication ve Authenticator Management](https://pages.nist.gov/800-63-4/sp800-63b.html)
- [5] [W3C — Web Specifications'ta Browser Fingerprinting'i Azaltma](https://www.w3.org/TR/fingerprinting-guidance/)
- [6] [Tor Project — Tor'u diğer browser'larla kullanma](https://support.torproject.org/tor-browser/security/using-tor-with-other-browsers/)
- [7] [Tor Project — Tor Browser'da Plugins ve add-ons](https://support.torproject.org/tor-browser/features/plugins/)
- [8] [EFF Surveillance Self-Defense — Communication Metadata Neden Önemlidir](https://ssd.eff.org/module/why-metadata-matters)
- [9] [Signal — Phone Number Privacy ve Usernames: Daha Derin İnceleme](https://support.signal.org/hc/en-us/articles/6829998083994-Phone-Number-Privacy-and-Usernames-Deeper-Dive)
- [10] [Proton — Proton Mail içinde neler encrypted durumdadır?](https://proton.me/support/what-is-encrypted-within-protonmail)
- [11] [Tails — Warnings: Tails güvenlidir ancak magic değildir](https://tails.net/doc/about/warnings/index.en.html)
