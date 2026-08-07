# Omijanie KYC przy użyciu AI

{{#include ../banners/hacktricks-training.md}}

Modele generatywne mogą być używane do **omijania opartych na przeglądarce procesów KYC, weryfikacji wieku i biometrycznej weryfikacji żywotności**. Słabym punktem często **nie jest warstwa transportowa ani dostawca cloud liveness**, lecz **granica zaufania kamery**: przeglądarka desktopowa zwykle ufa dowolnemu urządzeniu, które `getUserMedia()` udostępnia jako kamerę internetową.<sup>[[1]](#references)</sup>

## Praktyczny łańcuch ataku

1. **Wygeneruj media zgodne z wyzwaniami** za pomocą modelu video-to-video, wykorzystując aktora źródłowego i obraz referencyjny ofiary.<sup>[[1]](#references)</sup>
2. **Wstrzyknij sfałszowany strumień przed podpisaniem lub uploadem**, na przykład za pośrednictwem wirtualnej kamery Linux utworzonej przy użyciu `v4l2loopback` i zasilanej przez OBS lub FFmpeg.<sup>[[3]](#references)</sup>
3. Pozwól przeglądarce i vendor SDK (WebRTC, AWS itd.) **przechwycić, podpisać i uploadować kontrolowane przez atakującego klatki tak, jakby pochodziły z prawdziwej kamery internetowej**.<sup>[[2]](#references)</sup>

Jest to istotne podczas assessmentów, ponieważ podpisane fragmenty WebSocket lub framing własnościowego SDK mogą sprawiać, że **manipulacja na warstwie sieciowej** jest niepraktyczna, podczas gdy **wstrzykiwanie na warstwie kamery** nadal działa.<sup>[[1]](#references)</sup>

## Najważniejsze obszary testów

- **Akceptowanie wirtualnych kamer internetowych**: jeśli proces działa z poziomu przeglądarki desktopowej, sprawdź, czy OBS, `v4l2loopback` lub wirtualne kamery dostawcy są akceptowane jako zwykłe urządzenia peryferyjne.<sup>[[1]](#references)</sup>
- **Przekierowanie Camera API na urządzeniach mobilnych**: natywne procesy mobilne nadal mogą być podatne na atak, gdy Frida hookuje Camera API i zastępuje bufory sensora klatkami z MP4 lub wirtualnej kamery obsługiwanej przez emulator.
- **Osłabianie constraints**: strony wymagające dokładnych wartości `deviceId`, `frameRate`, `width`, `height` lub `facingMode` można czasami ominąć, wykonując monkeypatching `navigator.mediaDevices.getUserMedia` i zastępując ścisłe constraints szerszymi zakresami.<sup>[[4]](#references)</sup>
- **Generowanie materiału niskiej jakości oraz post-processing**: wygeneruj najtańszy film, jaki model potrafi niezawodnie wyrenderować, a następnie użyj upscalingu FFmpeg lub interpolacji klatek, aby spełnić wymagania przechwytywania.
- **Przewidywalne aktywne wyzwania**: powtarzalne sekwencje ruchów głową lub błysków światła warto nagrać i odtworzyć w ramach workflow generatywnego.
- **Słabe wykrywanie replay**: proste modyfikacje sceny, takie jak przycięcie lub przesunięcie pozycji, zmiany overlayu albo niewielki ruch, mogą wystarczyć, gdy logika anti-replay sprawdza wyłącznie powierzchowne podobieństwo klatek.<sup>[[1]](#references)</sup>

## Różnice w granicy zaufania między urządzeniami mobilnymi a desktopowymi

Natywne aplikacje mobilne mogą zwiększać koszt ataku dla atakującego dzięki:<sup>[[1]](#references)</sup>

- **attestation sensora lub Secure Element** dla buforów kamery;
- sygnałom **integrity wykonania**, takim jak **Play Integrity** lub **App Attest**;
- **korelacji ruchu** między obrazem wideo a telemetrią akcelerometru lub żyroskopu.

Desktopowe procesy webowe zazwyczaj nie mają równoważnego łańcucha zaufania kamery, dlatego na ogół stanowią ścieżkę najmniejszego oporu.<sup>[[1]](#references)</sup>

## Uwagi dotyczące przeglądu zabezpieczeń

Podczas przeglądu integracji KYC lub liveness sprawdź, czy:<sup>[[1]](#references)</sup>

- dopuszcza **fallback do przeglądarki desktopowej** w procesie, który był modelowany pod kątem zagrożeń wyłącznie dla przechwytywania mobilnego;
- opiera się głównie na **algorytmicznej weryfikacji żywotności** bez silnej eskalacji do człowieka w przypadku podejrzanych sesji;
- używa **stabilnych lub przewidywalnych wyzwań**, które można wcześniej nagrać i przekazać do pipeline'u generatywnego;
- wykrywa **monkeypatching `getUserMedia`**, wirtualne kamery, niespójną telemetrię sprzętową przeglądarki lub brak device attestation.<sup>[[1]](#references)</sup>

## References

- [1] [Synacktiv - Omijanie weryfikacji wieku KYC przy użyciu generatywnych modeli wideo](https://www.synacktiv.com/en/publications/kyc-bypass-age-verification-using-generative-video-models.html)
- [2] [Amazon Rekognition Face Liveness](https://docs.aws.amazon.com/rekognition/latest/dg/face-liveness.html)
- [3] [v4l2loopback](https://github.com/v4l2loopback/v4l2loopback)
- [4] [MDN - MediaDevices.getUserMedia()](https://developer.mozilla.org/en-US/docs/Web/API/MediaDevices/getUserMedia)

{{#include ../banners/hacktricks-training.md}}
