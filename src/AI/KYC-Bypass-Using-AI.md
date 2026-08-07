# Обхід KYC за допомогою AI

{{#include ../banners/hacktricks-training.md}}

Generative models можна використовувати для **обходу KYC у браузері, перевірки віку та workflows біометричної liveness**. Слабким місцем часто є **не transport або cloud-провайдер liveness, а межа довіри до камери**: браузер на desktop зазвичай довіряє будь-якому пристрою, який `getUserMedia()` надає як webcam.<sup>[[1]](#references)</sup>

## Практичний ланцюжок атаки

1. **Згенерувати media, що відповідає challenge**, за допомогою video-to-video model, використовуючи source actor і reference image жертви.<sup>[[1]](#references)</sup>
2. **Інжектувати підроблений stream до підписання або upload**, наприклад через Linux virtual camera, створену за допомогою `v4l2loopback` і підключену через OBS або FFmpeg.<sup>[[3]](#references)</sup>
3. Дозволити браузеру та vendor SDK (WebRTC, AWS тощо) **захопити, підписати й завантажити frames, контрольовані атакувальником, так, ніби вони надійшли зі справжньої webcam**.<sup>[[2]](#references)</sup>

Це важливо під час assessments, оскільки підписані WebSocket chunks або proprietary SDK framing можуть зробити **tampering на network layer** непрактичним, тоді як **інжекція на camera layer** усе ще працює.<sup>[[1]](#references)</sup>

## Найцінніші напрямки тестування

- **Прийняття virtual webcam**: якщо flow працює в desktop browser, перевірте, чи приймаються OBS, `v4l2loopback` або vendor virtual cameras як звичайні периферійні пристрої.<sup>[[1]](#references)</sup>
- **Перенаправлення Camera API на mobile**: native mobile flows усе ще можуть бути вразливими, коли Frida перехоплює camera APIs і замінює sensor buffers frames із MP4 або virtual camera на базі emulator.
- **Послаблення constraints**: сторінки, які вимагають точних `deviceId`, `frameRate`, `width`, `height` або `facingMode`, іноді можна обійти, monkeypatching `navigator.mediaDevices.getUserMedia` і замінивши strict constraints на ширші ranges.<sup>[[4]](#references)</sup>
- **Генерація низької якості плюс post-processing**: згенеруйте найдешевше відео, яке model може надійно render, а потім використайте FFmpeg upscaling або frame interpolation для відповідності вимогам capture.
- **Передбачувані active challenges**: повторювані послідовності рухів голови або спалахів світла варто записувати й повторно відтворювати через generative workflow.
- **Слабке replay detection**: простих змін сцени, таких як crop або зміщення позиції, зміни overlay чи незначний рух, може бути достатньо, якщо anti-replay logic перевіряє лише поверхневу схожість frames.<sup>[[1]](#references)</sup>

## Відмінності довіри між Mobile та Desktop

Native mobile apps можуть підвищити вартість атаки для атакувальника за допомогою:<sup>[[1]](#references)</sup>

- **attestation sensor або Secure Element** для camera buffers;
- сигналів **execution-integrity**, таких як **Play Integrity** або **App Attest**;
- **кореляції руху** між відео та telemetry акселерометра або гіроскопа.

Desktop web flows зазвичай не мають еквівалентного ланцюжка довіри до камери, тому загалом є шляхом найменшого опору.<sup>[[1]](#references)</sup>

## Примітки щодо defensive review

Під час перевірки KYC або liveness integration переконайтеся, чи вона:<sup>[[1]](#references)</sup>

- дозволяє **fallback через desktop browser** для workflow, threat model якого передбачав лише mobile capture;
- переважно покладається на **algorithmic liveness** без належної human escalation для підозрілих sessions;
- використовує **стабільні або передбачувані challenges**, які можна попередньо записати та подати в generation pipeline;
- виявляє **monkeypatching `getUserMedia`**, virtual cameras, невідповідну browser hardware telemetry або відсутність device attestation.<sup>[[1]](#references)</sup>

## References

- [1] [Synacktiv - Обхід перевірки віку за допомогою generative video models](https://www.synacktiv.com/en/publications/kyc-bypass-age-verification-using-generative-video-models.html)
- [2] [Amazon Rekognition Face Liveness](https://docs.aws.amazon.com/rekognition/latest/dg/face-liveness.html)
- [3] [v4l2loopback](https://github.com/v4l2loopback/v4l2loopback)
- [4] [MDN - MediaDevices.getUserMedia()](https://developer.mozilla.org/en-US/docs/Web/API/MediaDevices/getUserMedia)

{{#include ../banners/hacktricks-training.md}}
