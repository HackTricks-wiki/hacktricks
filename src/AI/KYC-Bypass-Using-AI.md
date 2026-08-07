# AI Kullanarak KYC Bypass

{{#include ../banners/hacktricks-training.md}}

Üretken modeller, **browser tabanlı KYC, yaş doğrulama ve biyometrik liveness iş akışlarını bypass etmek** için kullanılabilir. Zayıf nokta çoğu zaman **transport veya cloud liveness sağlayıcısı değil**, **kamera güven sınırıdır**: bir desktop browser genellikle `getUserMedia()` tarafından webcam olarak sunulan herhangi bir cihaza güvenir.<sup>[[1]](#references)</sup>

## Pratik Saldırı Zinciri

1. Bir source actor ve victim reference image kullanarak video-to-video modeliyle **challenge'a uygun medya oluşturun**.<sup>[[1]](#references)</sup>
2. **Sahte stream'i signing veya upload işleminden önce enjekte edin**; örneğin `v4l2loopback` ile oluşturulan ve OBS veya FFmpeg tarafından beslenen bir Linux virtual camera kullanın.<sup>[[3]](#references)</sup>
3. Browser ve vendor SDK'nın (WebRTC, AWS vb.) **attacker-controlled frame'leri gerçek bir webcam'den geliyormuş gibi capture etmesine, sign etmesine ve upload etmesine** izin verin.<sup>[[2]](#references)</sup>

Bu, assessment'lar sırasında önemlidir; çünkü signed WebSocket chunk'ları veya proprietary SDK framing, **network-layer tampering'i** pratik olmaktan çıkarabilirken **camera-layer injection** hâlâ çalışabilir.<sup>[[1]](#references)</sup>

## Yüksek Değerli Test Yaklaşımları

- **Virtual webcam kabulü**: akış bir desktop browser üzerinden çalışıyorsa OBS, `v4l2loopback` veya vendor virtual camera'ların normal peripheral'lar olarak kabul edilip edilmediğini test edin.<sup>[[1]](#references)</sup>
- **Mobile'da camera API yönlendirmesi**: Frida camera API'lerini hook'layıp sensor buffer'larını bir MP4'ten veya emulator-backed virtual camera'dan alınan frame'lerle değiştirdiğinde native mobile akışları hâlâ vulnerable olabilir.
- **Constraint'lerin zayıflatılması**: tam `deviceId`, `frameRate`, `width`, `height` veya `facingMode` gerektiren sayfalar, bazen `navigator.mediaDevices.getUserMedia` monkeypatch edilerek ve strict constraint'ler daha geniş aralıklarla değiştirilerek bypass edilebilir.<sup>[[4]](#references)</sup>
- **Düşük kaliteli generation ve post-processing**: modelin güvenilir şekilde render edebildiği en ucuz videoyu oluşturun, ardından capture gereksinimlerini karşılamak için FFmpeg upscaling veya frame interpolation kullanın.
- **Öngörülebilir active challenge'lar**: tekrarlanan head-movement veya light-flash sequence'larını kaydetmek ve generative workflow üzerinden yeniden oynatmak değerlendirilmeye değerdir.
- **Zayıf replay detection**: crop veya position shift'leri, overlay değişiklikleri veya hafif motion gibi basit scene perturbation'lar, anti-replay mantığı yalnızca yüzeysel frame similarity kontrolü yapıyorsa yeterli olabilir.<sup>[[1]](#references)</sup>

## Mobile ve Desktop Güven Farkları

Native mobile app'ler, aşağıdakilerle attacker'ın maliyetini artırabilir:<sup>[[1]](#references)</sup>

- camera buffer'ları için **sensor veya Secure Element attestation**;
- **Play Integrity** veya **App Attest** gibi **execution-integrity** sinyalleri;
- video ile accelerometer veya gyroscope telemetry arasındaki **motion correlation**.

Desktop web akışlarında genellikle eşdeğer bir camera chain of trust bulunmaz; bu nedenle bunlar genellikle en düşük dirençli yoldur.<sup>[[1]](#references)</sup>

## Defensive Review Notları

Bir KYC veya liveness integration'ını incelerken aşağıdakileri doğrulayın:<sup>[[1]](#references)</sup>

- yalnızca mobile capture için threat-model oluşturulmuş bir workflow için **desktop-browser fallback** sunup sunmadığını;
- şüpheli session'lar için güçlü human escalation olmadan çoğunlukla **algorithmic liveness**'a güvenip güvenmediğini;
- önceden kaydedilip bir generation pipeline'a beslenebilecek **stable veya predictable challenge**'lar kullanıp kullanmadığını;
- **`getUserMedia` monkeypatching**, virtual camera'lar, tutarsız browser hardware telemetry'si veya eksik device attestation tespit edip etmediğini.<sup>[[1]](#references)</sup>

## References

- [1] [Synacktiv - KYC: Bypass age verification using generative video models](https://www.synacktiv.com/en/publications/kyc-bypass-age-verification-using-generative-video-models.html)
- [2] [Amazon Rekognition Face Liveness](https://docs.aws.amazon.com/rekognition/latest/dg/face-liveness.html)
- [3] [v4l2loopback](https://github.com/v4l2loopback/v4l2loopback)
- [4] [MDN - MediaDevices.getUserMedia()](https://developer.mozilla.org/en-US/docs/Web/API/MediaDevices/getUserMedia)

{{#include ../banners/hacktricks-training.md}}
