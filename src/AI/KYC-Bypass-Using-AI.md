# Bypass KYC przy użyciu AI

{{#include ../banners/hacktricks-training.md}}

Modele generatywne mogą być używane do **omijania opartych na przeglądarce procesów KYC, weryfikacji wieku i biometrycznego wykrywania żywotności**. Słabym punktem często **nie jest warstwa transportowa ani chmurowy dostawca liveness, lecz granica zaufania kamery**: przeglądarka desktopowa zwykle ufa dowolnemu urządzeniu, które `getUserMedia()` udostępnia jako webcam.<sup>[[1]](#references)</sup>

## Praktyczny łańcuch ataku

1. **Wygeneruj media spełniające wymagania challenge** za pomocą modelu video-to-video, korzystając ze źródłowego aktora i referencyjnego obrazu ofiary.
2. **Wstrzyknij sfałszowany strumień przed podpisaniem lub uploadem**, na przykład za pomocą wirtualnej kamery Linux utworzonej przez `v4l2loopback` i zasilanej przez OBS lub FFmpeg.
3. Pozwól przeglądarce i SDK dostawcy (WebRTC, AWS itd.) **przechwycić, podpisać i przesłać kontrolowane przez atakującego klatki tak, jakby pochodziły z prawdziwej kamery**.

Jest to istotne podczas assessmentów, ponieważ podpisane fragmenty WebSocket lub formatowanie zastrzeżonego SDK mogą sprawiać, że **manipulowanie na warstwie sieciowej** jest niepraktyczne, podczas gdy **wstrzyknięcie na warstwie kamery** nadal działa.<sup>[[1]](#references)</sup>

## Najważniejsze obszary testów

- **Akceptowanie wirtualnych webcamów**: jeśli proces działa w przeglądarce desktopowej, sprawdź, czy OBS, `v4l2loopback` lub wirtualne kamery dostawcy są akceptowane jako zwykłe urządzenia peryferyjne.
- **Przekierowanie Camera API na urządzeniach mobilnych**: natywne procesy mobilne mogą nadal być podatne na atak, gdy Frida hookuje API kamery i zastępuje bufory sensora klatkami z pliku MP4 lub wirtualnej kamery opartej na emulatorze.
- **Osłabianie constraints**: strony wymagające dokładnych wartości `deviceId`, `frameRate`, `width`, `height` lub `facingMode` można czasami ominąć przez monkeypatching `navigator.mediaDevices.getUserMedia` i zastąpienie ścisłych constraints szerszymi zakresami.
- **Generowanie niskiej jakości połączone z post-processingiem**: wygeneruj najtańszy film, jaki model może niezawodnie wyrenderować, a następnie użyj upscalingu FFmpeg lub interpolacji klatek, aby spełnić wymagania capture.
- **Przewidywalne aktywne challenges**: powtarzające się sekwencje ruchów głową lub błysków światła warto nagrać i odtworzyć w ramach workflow generatywnego.
- **Słabe wykrywanie replay**: proste modyfikacje sceny, takie jak przycięcie lub przesunięcie pozycji, zmiany overlayu albo niewielki ruch, mogą wystarczyć, gdy logika anti-replay sprawdza jedynie powierzchowne podobieństwo klatek.<sup>[[1]](#references)</sup>

## Różnice w poziomie zaufania między urządzeniami mobilnymi a desktopowymi

Natywne aplikacje mobilne mogą zwiększać koszt ataku poprzez:

- **attestation sensora lub Secure Element** dla buforów kamery;
- sygnały **execution-integrity**, takie jak **Play Integrity** lub **App Attest**;
- **korelację ruchu** między obrazem wideo a telemetrią akcelerometru lub żyroskopu.

Desktopowe procesy webowe zwykle nie mają równoważnego łańcucha zaufania kamery, dlatego ogólnie stanowią ścieżkę o najmniejszym oporze.<sup>[[1]](#references)</sup>

## Uwagi dotyczące przeglądu zabezpieczeń

Podczas przeglądu integracji KYC lub liveness sprawdź, czy:

- umożliwia ona **fallback do przeglądarki desktopowej** w procesie, dla którego threat modeling obejmował wyłącznie capture na urządzeniu mobilnym;
- opiera się głównie na **algorytmicznym liveness** bez silnej eskalacji do człowieka w przypadku podejrzanych sesji;
- używa **stabilnych lub przewidywalnych challenges**, które można nagrać wcześniej i przekazać do pipeline'u generatywnego;
- wykrywa **monkeypatching `getUserMedia`**, wirtualne kamery, niespójne dane telemetryczne sprzętu przeglądarki lub brak device attestation.<sup>[[1]](#references)</sup>

## Referencje

- [1] [Synacktiv - KYC: Bypass age verification using generative video models](https://www.synacktiv.com/en/publications/kyc-bypass-age-verification-using-generative-video-models.html)
- [2] [Amazon Rekognition Face Liveness](https://docs.aws.amazon.com/rekognition/latest/dg/face-liveness.html)
- [3] [v4l2loopback](https://github.com/v4l2loopback/v4l2loopback)
- [4] [MDN - MediaDevices.getUserMedia()](https://developer.mozilla.org/en-US/docs/Web/API/MediaDevices/getUserMedia)

{{#include ../banners/hacktricks-training.md}}
