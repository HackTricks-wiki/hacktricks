# Обхід KYC за допомогою AI

{{#include ../banners/hacktricks-training.md}}

Генеративні моделі можна використовувати для **обходу KYC у браузері, перевірки віку та процедур біометричної перевірки життєздатності**. Слабким місцем часто є **не транспорт або cloud-провайдер liveness, а межа довіри до камери**: настільний браузер зазвичай довіряє будь-якому пристрою, який `getUserMedia()` надає як вебкамеру.<sup>[[1]](#references)</sup>

## Практичний ланцюжок атаки

1. **Згенерувати медіа, що відповідає виклику**, за допомогою video-to-video моделі, використовуючи відео актора-джерела та референсне зображення жертви.<sup>[[1]](#references)</sup>
2. **Інжектити підроблений потік до підписання або завантаження**, наприклад через Linux virtual camera, створену за допомогою `v4l2loopback` і підключену через OBS або FFmpeg.<sup>[[3]](#references)</sup>
3. Дозволити браузеру та vendor SDK (WebRTC, AWS тощо) **захопити, підписати й завантажити контрольовані атакувальником кадри так, ніби вони надійшли зі справжньої вебкамери**.<sup>[[2]](#references)</sup>

Це важливо під час оцінювань, оскільки підписані фрагменти WebSocket або proprietary SDK framing можуть зробити **втручання на мережевому рівні** непрактичним, тоді як **інжекція на рівні камери** все ще працює.<sup>[[1]](#references)</sup>

## Важливі напрямки тестування

- **Прийняття virtual webcam**: якщо процес працює з настільного браузера, перевірте, чи приймаються OBS, `v4l2loopback` або vendor virtual cameras як звичайні периферійні пристрої.<sup>[[1]](#references)</sup>
- **Перенаправлення Camera API на mobile**: native-процеси все ще можуть бути вразливими, коли runtime instrumentation, наприклад Frida, підміняє camera APIs і замінює sensor buffers кадрами з MP4-файлу або virtual camera, що працює через emulator. Для цього потрібен контроль над середовищем виконання клієнта; оцінювання слід проводити разом із перевірками root/jailbreak та application integrity.<sup>[[1]](#references)</sup>
- **Послаблення обмежень**: сторінки, що вимагають точних значень `deviceId`, `frameRate`, `width`, `height` або `facingMode`, іноді можна обійти, monkeypatching `navigator.mediaDevices.getUserMedia` і замінивши суворі обмеження ширшими діапазонами.<sup>[[4]](#references)</sup>
- **Генерація низької якості плюс post-processing**: перевірте, чи можна достатньо підвищити роздільність або застосувати frame interpolation до недорогого згенерованого відео за допомогою FFmpeg, щоб воно відповідало capture constraints.<sup>[[1]](#references)</sup>
- **Передбачувані active challenges**: повторювані послідовності рухів голови або спалахів світла варто записувати та відтворювати через generative workflow.
- **Слабке виявлення replay**: простих змін сцени, таких як crop або зміщення позиції, зміни overlay чи незначний рух, може бути достатньо, якщо anti-replay логіка перевіряє лише поверхневу схожість кадрів.<sup>[[1]](#references)</sup>

## Відмінності довіри між Mobile та Desktop

Native mobile apps можуть підвищити вартість атаки для атакувальника за допомогою:<sup>[[1]](#references)</sup>

- **сигналів походження або attestation, захищених апаратним забезпеченням**, зокрема доказів на основі Secure Element, якщо платформа та capture stack фактично їх надають;
- сигналів **execution integrity**, таких як **Play Integrity** або **App Attest**;<sup>[[5]](#references)[[6]](#references)</sup>
- **кореляції руху** між відео та telemetry акселерометра або гіроскопа.

Desktop web-процеси зазвичай не мають еквівалентного ланцюжка довіри до камери, тому загалом є шляхом найменшого опору.<sup>[[1]](#references)</sup>

## Примітки щодо defensive review

Під час перевірки інтеграції KYC або liveness з’ясуйте, чи вона:<sup>[[1]](#references)</sup>

- дозволяє **fallback у desktop browser** для процесу, модель загроз якого передбачала лише mobile capture;
- переважно покладається на **algorithmic liveness** без належної ескалації до людини для підозрілих сесій;
- використовує **стабільні або передбачувані challenges**, які можна попередньо записати та передати в generation pipeline;
- виявляє **monkeypatching `getUserMedia`**, virtual cameras, невідповідні browser hardware telemetry або відсутність device attestation.<sup>[[1]](#references)</sup>

## References

- [1] [Synacktiv - Обхід перевірки віку за допомогою генеративних відеомоделей](https://www.synacktiv.com/en/publications/kyc-bypass-age-verification-using-generative-video-models.html)
- [2] [Amazon Rekognition Face Liveness](https://docs.aws.amazon.com/rekognition/latest/dg/face-liveness.html)
- [3] [v4l2loopback](https://github.com/v4l2loopback/v4l2loopback)
- [4] [MDN - MediaDevices.getUserMedia()](https://developer.mozilla.org/en-US/docs/Web/API/MediaDevices/getUserMedia)
- [5] [Android Developers — Play Integrity API](https://developer.android.com/google/play/integrity)
- [6] [Apple Developer — App Attest](https://developer.apple.com/documentation/devicecheck/establishing-your-app-s-integrity)
{{#include ../banners/hacktricks-training.md}}
