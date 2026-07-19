# Обхід KYC за допомогою AI

{{#include ../banners/hacktricks-training.md}}

Генеративні моделі можна використовувати для **обходу KYC у браузері, перевірки віку та workflow біометричної перевірки життєздатності**. Слабким місцем часто є **не транспорт або cloud-провайдер liveness, а межа довіри до камери**: браузер на desktop зазвичай довіряє будь-якому пристрою, який `getUserMedia()` надає як вебкамеру.

## Практичний ланцюжок атаки

1. **Згенерувати media, що відповідає challenge**, за допомогою video-to-video моделі, використовуючи відео вихідного актора та еталонне зображення жертви.
2. **Інжектити підроблений stream до підписування або upload**, наприклад через віртуальну камеру Linux, створену за допомогою `v4l2loopback` і наповнену через OBS або FFmpeg.
3. Дозволити браузеру та vendor SDK (WebRTC, AWS тощо) **захопити, підписати й завантажити контрольовані атакувальником кадри так, ніби вони надходять зі справжньої вебкамери**.

Це важливо під час assessments, оскільки підписані WebSocket chunks або proprietary SDK framing можуть ускладнити **маніпуляції на мережевому рівні**, тоді як **інжекція на рівні камери** все ще працює.

## Найцінніші напрямки тестування

- **Прийняття віртуальних вебкамер**: якщо workflow працює з браузера на desktop, перевірте, чи приймаються OBS, `v4l2loopback` або vendor virtual cameras як звичайні периферійні пристрої.
- **Перенаправлення Camera API на mobile**: native mobile workflows можуть залишатися вразливими, коли Frida hooks API камери та замінюють sensor buffers кадрами з MP4 або віртуальної камери на базі емулятора.
- **Послаблення constraints**: сторінки, які вимагають точних `deviceId`, `frameRate`, `width`, `height` або `facingMode`, іноді можна обійти за допомогою monkeypatching `navigator.mediaDevices.getUserMedia` і заміни strict constraints на ширші діапазони.
- **Генерація низької якості з post-processing**: згенеруйте найдешевше відео, яке модель може надійно відтворити, а потім використайте FFmpeg upscaling або frame interpolation для відповідності вимогам захоплення.
- **Передбачувані active challenges**: повторювані послідовності рухів головою або спалахів світла варто записувати та відтворювати через generative workflow.
- **Слабке виявлення replay**: простих змін сцени, таких як crop або зміщення позиції, зміни overlay чи незначний рух, може бути достатньо, якщо anti-replay логіка перевіряє лише поверхневу схожість кадрів.

## Відмінності довіри на mobile та desktop

Native mobile apps можуть підвищити вартість атаки за допомогою:

- **attestation сенсорів або Secure Element** для camera buffers;
- сигналів **цілісності виконання**, таких як **Play Integrity** або **App Attest**;
- **кореляції руху** між відео та telemetry акселерометра або гіроскопа.

Desktop web workflows зазвичай не мають еквівалентного ланцюжка довіри до камери, тому загалом є найпростішим шляхом для атаки.

## Нотатки щодо defensive review

Під час перевірки KYC або liveness integration з’ясуйте, чи вона:

- дозволяє **fallback у desktop-браузері** для workflow, threat model якого передбачав лише mobile capture;
- переважно покладається на **algorithmic liveness** без належної human escalation для підозрілих сесій;
- використовує **стабільні або передбачувані challenges**, які можна заздалегідь записати та подати в generation pipeline;
- виявляє **monkeypatching `getUserMedia`**, віртуальні камери, невідповідні browser hardware telemetry або відсутність device attestation.

## References

- [Synacktiv - KYC: Bypass age verification using generative video models](https://www.synacktiv.com/en/publications/kyc-bypass-age-verification-using-generative-video-models.html)
- [Amazon Rekognition Face Liveness](https://docs.aws.amazon.com/rekognition/latest/dg/face-liveness.html)
- [v4l2loopback](https://github.com/v4l2loopback/v4l2loopback)
- [MDN - MediaDevices.getUserMedia()](https://developer.mozilla.org/en-US/docs/Web/API/MediaDevices/getUserMedia)

{{#include ../banners/hacktricks-training.md}}
