# KYC Using AI ile Bypass

{{#include ../banners/hacktricks-training.md}}

Generative models, **browser tabanlı KYC, yaş doğrulama ve biyometrik canlılık iş akışlarını bypass etmek** için kullanılabilir. Zayıf nokta çoğu zaman **transport veya cloud liveness provider değil**, **kamera güven sınırıdır**: bir desktop browser genellikle `getUserMedia()` tarafından webcam olarak sunulan herhangi bir cihaza güvenir.<sup>[[1]](#references)</sup>

## Practical Attack Chain

1. Bir source actor ve victim reference image kullanarak video-to-video model ile **challenge-compliant medya oluşturun**.<sup>[[1]](#references)</sup>
2. **Sahte stream'i signing veya upload işleminden önce enjekte edin**; örneğin `v4l2loopback` ile oluşturulan ve OBS veya FFmpeg tarafından beslenen bir Linux virtual camera aracılığıyla.<sup>[[3]](#references)</sup>
3. Browser ve vendor SDK'nın (WebRTC, AWS vb.) **saldırgan tarafından kontrol edilen frame'leri gerçek bir webcam'den geliyormuş gibi capture etmesine, sign etmesine ve upload etmesine** izin verin.<sup>[[2]](#references)</sup>

Bu, assessment'lar sırasında önemlidir; çünkü signed WebSocket chunk'ları veya proprietary SDK framing, **network-layer tampering** işlemini pratik olmaktan çıkarabilirken **camera-layer injection** hâlâ çalışabilir.<sup>[[1]](#references)</sup>

## High-Value Testing Angles

- **Virtual webcam kabulü**: flow bir desktop browser üzerinden çalışıyorsa OBS, `v4l2loopback` veya vendor virtual camera'ların normal peripheral'lar olarak kabul edilip edilmediğini test edin.<sup>[[1]](#references)</sup>
- **Mobile'da camera API redirection**: runtime instrumentation, örneğin Frida, camera API'lerini hook'layıp sensor buffer'larını bir MP4 file'dan veya emulator-backed virtual camera'dan alınan frame'lerle değiştirdiğinde native flow'lar hâlâ vulnerable olabilir. Bu, client execution environment üzerinde kontrol gerektirir ve root/jailbreak ile application-integrity sinyalleriyle birlikte değerlendirilmelidir.<sup>[[1]](#references)</sup>
- **Constraint weakening**: tam `deviceId`, `frameRate`, `width`, `height` veya `facingMode` gerektiren sayfalar, bazen `navigator.mediaDevices.getUserMedia` üzerinde monkeypatching yapılarak ve strict constraint'ler daha geniş range'lerle değiştirilerek bypass edilebilir.<sup>[[4]](#references)</sup>
- **Low-quality generation plus post-processing**: düşük maliyetli generated video'nun capture constraint'lerini karşılayacak düzeye ulaşması için FFmpeg ile upscale edilip edilemeyeceğini veya frame interpolation uygulanıp uygulanamayacağını test edin.<sup>[[1]](#references)</sup>
- **Predictable active challenges**: tekrarlanan head-movement veya light-flash sequence'ları kaydetmeye ve generative workflow üzerinden replay etmeye değerdir.
- **Weak replay detection**: crop veya position shift'leri, overlay değişiklikleri ya da küçük motion gibi basit scene perturbation'ları, anti-replay logic yalnızca yüzeysel frame similarity kontrol ettiğinde yeterli olabilir.<sup>[[1]](#references)</sup>

## Mobile vs. Desktop Trust Differences

Native mobile app'ler saldırganın maliyetini şu yöntemlerle artırabilir:<sup>[[1]](#references)</sup>

- **hardware-backed provenance veya attestation sinyalleri**; platform ve capture stack bunları gerçekten sunuyorsa Secure Element-backed evidence dâhil;
- **execution-integrity** sinyalleri; **Play Integrity** veya **App Attest** gibi;<sup>[[5]](#references)[[6]](#references)</sup>
- video ile accelerometer veya gyroscope telemetry arasındaki **motion correlation**.

Desktop web flow'larında genellikle eşdeğer bir camera chain of trust bulunmaz; bu nedenle bunlar genellikle en düşük dirençli yoldur.<sup>[[1]](#references)</sup>

## Defensive Review Notes

Bir KYC veya liveness integration'ını incelerken şunları doğrulayın:<sup>[[1]](#references)</sup>

- yalnızca mobile capture için threat-modeled edilmiş bir workflow için **desktop-browser fallback** sunup sunmadığını;
- şüpheli session'lar için güçlü human escalation olmadan çoğunlukla **algorithmic liveness** kullanıp kullanmadığını;
- önceden kaydedilip generation pipeline'a beslenebilecek **stable veya predictable challenge**'lar kullanıp kullanmadığını;
- **`getUserMedia` monkeypatching**, virtual camera'lar, tutarsız browser hardware telemetry veya eksik device attestation tespit edip etmediğini.<sup>[[1]](#references)</sup>

## References

- [1] [Synacktiv - Generative video models kullanarak yaş doğrulamayı bypass etme](https://www.synacktiv.com/en/publications/kyc-bypass-age-verification-using-generative-video-models.html)
- [2] [Amazon Rekognition Face Liveness](https://docs.aws.amazon.com/rekognition/latest/dg/face-liveness.html)
- [3] [v4l2loopback](https://github.com/v4l2loopback/v4l2loopback)
- [4] [MDN - MediaDevices.getUserMedia()](https://developer.mozilla.org/en-US/docs/Web/API/MediaDevices/getUserMedia)
- [5] [Android Developers — Play Integrity API](https://developer.android.com/google/play/integrity)
- [6] [Apple Developer — App Attest](https://developer.apple.com/documentation/devicecheck/establishing-your-app-s-integrity)
{{#include ../banners/hacktricks-training.md}}
