# AI Kullanarak KYC Bypass

{{#include ../banners/hacktricks-training.md}}

Generative modeller, **browser tabanlı KYC, yaş doğrulama ve biyometrik liveness iş akışlarını bypass etmek** için kullanılabilir. Zayıf nokta çoğu zaman **transport veya cloud liveness provider değil**, **kamera trust boundary**'sidir: bir desktop browser genellikle `getUserMedia()` tarafından webcam olarak sunulan her cihaza güvenir.<sup>[[1]](#references)</sup>

## Pratik Attack Chain

1. Bir source actor ve victim reference image kullanarak video-to-video modeliyle **challenge-compliant media üretin**.
2. **Forged stream'i signing veya upload işleminden önce inject edin**; örneğin `v4l2loopback` ile oluşturulan ve OBS veya FFmpeg tarafından beslenen bir Linux virtual camera aracılığıyla.
3. Browser'ın ve vendor SDK'nın (WebRTC, AWS vb.) **attacker-controlled frame'leri gerçek bir webcam'den geliyormuş gibi capture etmesine, sign etmesine ve upload etmesine** izin verin.

Bu, assessment'lar sırasında önemlidir; çünkü signed WebSocket chunk'ları veya proprietary SDK framing, **network-layer tampering** işlemini pratik olmaktan çıkarabilirken **camera-layer injection** hâlâ çalışabilir.<sup>[[1]](#references)</sup>

## High-Value Testing Angles

- **Virtual webcam acceptance**: Akış bir desktop browser'dan çalışıyorsa OBS, `v4l2loopback` veya vendor virtual camera'ların normal peripheral olarak kabul edilip edilmediğini test edin.
- **Mobile'da Camera API redirection**: Native mobile akışları, Frida'nın camera API'lerini hook'layıp sensor buffer'larını bir MP4'ten veya emulator-backed virtual camera'dan gelen frame'lerle değiştirmesi durumunda hâlâ vulnerable olabilir.
- **Constraint weakening**: Tam `deviceId`, `frameRate`, `width`, `height` veya `facingMode` gerektiren sayfalar, bazen `navigator.mediaDevices.getUserMedia` monkeypatch edilerek ve strict constraint'ler daha geniş range'lerle değiştirilerek bypass edilebilir.
- **Low-quality generation plus post-processing**: Modelin güvenilir şekilde render edebildiği en düşük maliyetli videoyu üretin, ardından capture gereksinimlerini karşılamak için FFmpeg upscaling veya frame interpolation kullanın.
- **Predictable active challenges**: Tekrarlanan head-movement veya light-flash sequence'larını kaydetmek ve generative workflow üzerinden replay etmek değerlendirilmeye değerdir.
- **Weak replay detection**: Crop veya position shift'leri, overlay değişiklikleri ya da hafif motion gibi basit scene perturbation'lar, anti-replay logic yalnızca yüzeysel frame similarity kontrolü yaptığında yeterli olabilir.<sup>[[1]](#references)</sup>

## Mobile ve Desktop Trust Farkları

Native mobile app'ler saldırganın maliyetini şu yöntemlerle artırabilir:

- camera buffer'ları için **sensor veya Secure Element attestation**;
- **Play Integrity** veya **App Attest** gibi **execution-integrity** sinyalleri;
- video ile accelerometer veya gyroscope telemetry arasındaki **motion correlation**.

Desktop web akışlarında genellikle eşdeğer bir camera chain of trust bulunmaz; bu nedenle bunlar genellikle en düşük dirençli yoldur.<sup>[[1]](#references)</sup>

## Defensive Review Notes

Bir KYC veya liveness integration'ını incelerken şunları doğrulayın:

- yalnızca mobile capture için threat-modeled edilmiş bir workflow için **desktop-browser fallback** sunup sunmadığını;
- suspicious session'lar için güçlü human escalation olmadan çoğunlukla **algorithmic liveness**'a dayanıp dayanmadığını;
- pre-record edilip bir generation pipeline'a aktarılabilecek **stable veya predictable challenge**'lar kullanıp kullanmadığını;
- **`getUserMedia` monkeypatching**, virtual camera'lar, inconsistent browser hardware telemetry veya eksik device attestation tespit edip etmediğini.<sup>[[1]](#references)</sup>

## References

- [1] [Synacktiv - KYC: Bypass age verification using generative video models](https://www.synacktiv.com/en/publications/kyc-bypass-age-verification-using-generative-video-models.html)
- [2] [Amazon Rekognition Face Liveness](https://docs.aws.amazon.com/rekognition/latest/dg/face-liveness.html)
- [3] [v4l2loopback](https://github.com/v4l2loopback/v4l2loopback)
- [4] [MDN - MediaDevices.getUserMedia()](https://developer.mozilla.org/en-US/docs/Web/API/MediaDevices/getUserMedia)

{{#include ../banners/hacktricks-training.md}}
