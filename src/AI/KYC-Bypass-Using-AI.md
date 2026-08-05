# Обхід KYC за допомогою AI

{{#include ../banners/hacktricks-training.md}}

Generative models можна використовувати для **обходу KYC у браузері, перевірки віку та biometric liveness workflows**. Слабким місцем часто є **не transport і не cloud liveness provider, а межа довіри до камери**: браузер на desktop зазвичай довіряє будь-якому пристрою, який `getUserMedia()` надає як вебкамеру.<sup>[[1]](#references)</sup>

## Практичний ланцюжок атаки

1. **Згенерувати media, що відповідає викликам**, за допомогою video-to-video model, використовуючи source actor і reference image жертви.
2. **Інжектити підроблений stream до підписування або upload**, наприклад через Linux virtual camera, створену за допомогою `v4l2loopback` і наповнену через OBS або FFmpeg.
3. Дозволити браузеру та vendor SDK (WebRTC, AWS тощо) **захопити, підписати й завантажити кадри, контрольовані атакувальником, так, ніби вони надійшли зі справжньої вебкамери**.

Це важливо під час assessments, оскільки підписані WebSocket chunks або proprietary SDK framing можуть зробити **tampering на network layer** непрактичним, тоді як **інжекція на camera layer** усе ще працює.<sup>[[1]](#references)</sup>

## Напрями тестування з високою цінністю

- **Прийняття virtual webcam**: якщо flow працює з браузера на desktop, перевірте, чи приймаються OBS, `v4l2loopback` або vendor virtual cameras як звичайні периферійні пристрої.
- **Перенаправлення Camera API на mobile**: native mobile flows усе ще можуть бути вразливими, коли Frida підміняє camera APIs і замінює sensor buffers кадрами з MP4 або virtual camera на базі emulator.
- **Послаблення constraints**: сторінки, що вимагають точних `deviceId`, `frameRate`, `width`, `height` або `facingMode`, іноді можна обійти, monkeypatching `navigator.mediaDevices.getUserMedia` і замінивши strict constraints на ширші ranges.
- **Генерація низької якості плюс post-processing**: згенеруйте найдешевше video, яке model може надійно відрендерити, а потім використайте upscaling через FFmpeg або frame interpolation, щоб відповідати вимогам capture.
- **Передбачувані active challenges**: повторювані послідовності рухів голови або спалахів світла варто записувати й відтворювати через generative workflow.
- **Слабке виявлення replay**: простих змін сцени, таких як crop або зміщення позиції, зміни overlay чи незначний рух, може бути достатньо, якщо anti-replay logic перевіряє лише поверхневу схожість кадрів.<sup>[[1]](#references)</sup>

## Відмінності довіри на Mobile і Desktop

Native mobile apps можуть підвищити вартість атаки за допомогою:

- **attestation сенсорів або Secure Element** для camera buffers;
- сигналів **execution-integrity**, таких як **Play Integrity** або **App Attest**;
- **кореляції руху** між video та telemetry акселерометра або гіроскопа.

Desktop web flows зазвичай не мають еквівалентного camera chain of trust, тому вони загалом є шляхом найменшого опору.<sup>[[1]](#references)</sup>

## Нотатки щодо defensive review

Під час перевірки KYC або liveness integration з’ясуйте, чи вона:

- дозволяє **fallback у desktop browser** для workflow, threat model якого передбачав лише mobile capture;
- переважно покладається на **algorithmic liveness** без належної human escalation для підозрілих sessions;
- використовує **стабільні або передбачувані challenges**, які можна попередньо записати й подати до generation pipeline;
- виявляє **monkeypatching `getUserMedia`**, virtual cameras, невідповідні browser hardware telemetry або відсутність device attestation.<sup>[[1]](#references)</sup>

## References

- [1] [Synacktiv - KYC: Bypass age verification using generative video models](https://www.synacktiv.com/en/publications/kyc-bypass-age-verification-using-generative-video-models.html)
- [2] [Amazon Rekognition Face Liveness](https://docs.aws.amazon.com/rekognition/latest/dg/face-liveness.html)
- [3] [v4l2loopback](https://github.com/v4l2loopback/v4l2loopback)
- [4] [MDN - MediaDevices.getUserMedia()](https://developer.mozilla.org/en-US/docs/Web/API/MediaDevices/getUserMedia)

{{#include ../banners/hacktricks-training.md}}
