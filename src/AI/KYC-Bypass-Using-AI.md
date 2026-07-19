# AI Kullanarak KYC Bypass

{{#include ../banners/hacktricks-training.md}}

Generative models, **browser-based KYC, age-verification ve biometric liveness workflow'larını bypass etmek** için kullanılabilir. Zayıf nokta çoğu zaman **transport veya cloud liveness provider değil**, **camera trust boundary**'dir: Bir desktop browser genellikle `getUserMedia()` tarafından webcam olarak sunulan herhangi bir cihaza güvenir.

## Practical Attack Chain

1. Bir source actor ve victim reference image kullanarak video-to-video model ile **challenge-uyumlu medya üretin**.
2. Forged stream'i signing veya upload işleminden önce inject edin; örneğin `v4l2loopback` ile oluşturulan ve OBS veya FFmpeg tarafından beslenen bir Linux virtual camera kullanın.
3. Browser ve vendor SDK'nın (WebRTC, AWS vb.) **attacker-controlled frame'leri gerçek bir webcam'den geliyormuş gibi capture etmesine, sign etmesine ve upload etmesine** izin verin.

Bu, assessment'lar sırasında önemlidir; çünkü signed WebSocket chunk'ları veya proprietary SDK framing, **network-layer tampering** işlemini pratik olmaktan çıkarabilirken **camera-layer injection** hâlâ çalışabilir.

## High-Value Testing Angles

- **Virtual webcam acceptance**: Flow bir desktop browser üzerinden çalışıyorsa OBS, `v4l2loopback` veya vendor virtual camera'ların normal peripheral olarak kabul edilip edilmediğini test edin.
- **Camera API redirection on mobile**: Native mobile flow'lar, Frida camera API'lerini hook edip sensor buffer'larını MP4'ten alınan frame'lerle veya emulator-backed virtual camera ile değiştirdiğinde hâlâ vulnerable olabilir.
- **Constraint weakening**: Exact `deviceId`, `frameRate`, `width`, `height` veya `facingMode` gerektiren sayfalar, `navigator.mediaDevices.getUserMedia` monkeypatch edilerek ve strict constraint'ler daha geniş range'lerle değiştirilerek bazen bypass edilebilir.
- **Low-quality generation plus post-processing**: Modelin güvenilir şekilde render edebildiği en düşük maliyetli videoyu üretin, ardından capture gereksinimlerini karşılamak için FFmpeg upscaling veya frame interpolation kullanın.
- **Predictable active challenges**: Tekrarlanan head-movement veya light-flash sequence'larını kaydetmek ve generative workflow üzerinden replay etmek değerlendirilmeye değerdir.
- **Weak replay detection**: Crop veya position shift, overlay değişiklikleri ya da slight motion gibi basit scene perturbation'lar, anti-replay logic yalnızca yüzeysel frame similarity kontrol ettiğinde yeterli olabilir.

## Mobile vs. Desktop Trust Differences

Native mobile app'ler, aşağıdakilerle attacker'ın maliyetini artırabilir:

- Camera buffer'ları için **sensor veya Secure Element attestation**;
- **Play Integrity** veya **App Attest** gibi **execution-integrity** sinyalleri;
- Video ile accelerometer veya gyroscope telemetry arasındaki **motion correlation**.

Desktop web flow'larında genellikle eşdeğer bir camera chain of trust bulunmaz; bu nedenle bunlar genellikle en düşük dirençli yoldur.

## Defensive Review Notes

Bir KYC veya liveness integration'ını incelerken aşağıdakilerin mevcut olup olmadığını doğrulayın:

- Yalnızca mobile capture için threat-modeling yapılmış bir workflow için **desktop-browser fallback**'e izin veriyor mu?
- Şüpheli session'lar için güçlü human escalation olmadan çoğunlukla **algorithmic liveness**'a mı güveniyor?
- Önceden kaydedilip generation pipeline'a aktarılabilecek **stable veya predictable challenge**'lar mı kullanıyor?
- **`getUserMedia` monkeypatching**, virtual camera'lar, tutarsız browser hardware telemetry'si veya eksik device attestation tespit ediliyor mu?

## References

- [Synacktiv - KYC: Bypass age verification using generative video models](https://www.synacktiv.com/en/publications/kyc-bypass-age-verification-using-generative-video-models.html)
- [Amazon Rekognition Face Liveness](https://docs.aws.amazon.com/rekognition/latest/dg/face-liveness.html)
- [v4l2loopback](https://github.com/v4l2loopback/v4l2loopback)
- [MDN - MediaDevices.getUserMedia()](https://developer.mozilla.org/en-US/docs/Web/API/MediaDevices/getUserMedia)

{{#include ../banners/hacktricks-training.md}}
