# Obejście KYC przy użyciu AI

{{#include ../banners/hacktricks-training.md}}

Modele generatywne mogą być używane do **omijania opartych na przeglądarce procesów KYC, weryfikacji wieku i biometrycznej kontroli żywotności**. Słabym punktem często **nie jest transport ani dostawca cloud liveness, lecz granica zaufania kamery**: przeglądarka desktopowa zwykle ufa dowolnemu urządzeniu, które `getUserMedia()` udostępnia jako webcam.<sup>[[1]](#references)</sup>

## Praktyczny łańcuch ataku

1. **Wygeneruj multimedia spełniające wymagania challenge** za pomocą modelu video-to-video, korzystając ze źródłowego aktora i referencyjnego obrazu ofiary.<sup>[[1]](#references)</sup>
2. **Wstrzyknij sfałszowany strumień przed podpisaniem lub uploadem**, na przykład za pomocą wirtualnej kamery Linux utworzonej przez `v4l2loopback` i zasilanej przez OBS lub FFmpeg.<sup>[[3]](#references)</sup>
3. Pozwól przeglądarce i SDK dostawcy (WebRTC, AWS itd.) **przechwycić, podpisać i przesłać kontrolowane przez atakującego klatki tak, jakby pochodziły z prawdziwej kamery internetowej**.<sup>[[2]](#references)</sup>

Jest to istotne podczas assessmentów, ponieważ podpisane fragmenty WebSocket lub framing własnościowego SDK mogą sprawiać, że **manipulacja na poziomie sieci** będzie niepraktyczna, podczas gdy **wstrzyknięcie na poziomie kamery** nadal zadziała.<sup>[[1]](#references)</sup>

## Najważniejsze obszary testów

- **Akceptowanie wirtualnej kamery**: jeśli proces działa w przeglądarce desktopowej, sprawdź, czy OBS, `v4l2loopback` lub wirtualne kamery dostawcy są akceptowane jako zwykłe urządzenia peryferyjne.<sup>[[1]](#references)</sup>
- **Przekierowanie Camera API na urządzeniach mobilnych**: natywne procesy mogą być nadal podatne, gdy instrumentacja runtime, taka jak Frida, hookuje Camera API i zastępuje bufory sensora klatkami z pliku MP4 lub wirtualnej kamery obsługiwanej przez emulator. Wymaga to kontroli nad środowiskiem wykonywania klienta i powinno być oceniane łącznie z sygnałami root/jailbreak oraz integralności aplikacji.<sup>[[1]](#references)</sup>
- **Osłabianie ograniczeń**: strony wymagające dokładnych wartości `deviceId`, `frameRate`, `width`, `height` lub `facingMode` można czasami obejść, monkeypatchując `navigator.mediaDevices.getUserMedia` i zastępując ścisłe ograniczenia szerszymi zakresami.<sup>[[4]](#references)</sup>
- **Generowanie materiału niskiej jakości i post-processing**: sprawdź, czy niedrogi wygenerowany materiał wideo można wystarczająco poprawić za pomocą upscalingu lub interpolacji klatek w FFmpeg, aby spełnić ograniczenia przechwytywania.<sup>[[1]](#references)</sup>
- **Przewidywalne aktywne challenge**: powtarzalne sekwencje ruchów głową lub błysków światła warto nagrywać i odtwarzać w ramach workflow generatywnego.
- **Słabe wykrywanie replay**: proste modyfikacje sceny, takie jak zmiana kadrowania lub pozycji, zmiany overlayu albo niewielki ruch, mogą wystarczyć, gdy logika anti-replay sprawdza jedynie powierzchowne podobieństwo klatek.<sup>[[1]](#references)</sup>

## Różnice w poziomie zaufania: urządzenia mobilne a desktop

Natywne aplikacje mobilne mogą zwiększać koszt ataku poprzez:<sup>[[1]](#references)</sup>

- **sprzętowo zabezpieczone sygnały pochodzenia lub attestation**, w tym dowody wspierane przez Secure Element, jeśli platforma i łańcuch przechwytywania faktycznie je udostępniają;
- sygnały **integralności wykonywania**, takie jak **Play Integrity** lub **App Attest**;<sup>[[5]](#references)[[6]](#references)</sup>
- **korelację ruchu** między obrazem wideo a telemetrią akcelerometru lub żyroskopu.

Procesy webowe na desktopie zazwyczaj nie mają równoważnego łańcucha zaufania kamery, dlatego ogólnie stanowią ścieżkę najmniejszego oporu.<sup>[[1]](#references)</sup>

## Uwagi dotyczące przeglądu zabezpieczeń

Podczas przeglądu integracji KYC lub liveness sprawdź, czy:<sup>[[1]](#references)</sup>

- dopuszcza **awaryjny tryb w przeglądarce desktopowej** dla procesu, którego model zagrożeń obejmował wyłącznie przechwytywanie mobilne;
- opiera się głównie na **algorytmicznym liveness** bez silnej eskalacji do człowieka w przypadku podejrzanych sesji;
- używa **stabilnych lub przewidywalnych challenge**, które można wcześniej nagrać i przekazać do pipeline'u generatywnego;
- wykrywa **monkeypatching `getUserMedia`**, wirtualne kamery, niespójną telemetrię sprzętową przeglądarki lub brak device attestation.<sup>[[1]](#references)</sup>

## References

- [1] [Synacktiv - Obejście weryfikacji wieku KYC za pomocą generatywnych modeli wideo](https://www.synacktiv.com/en/publications/kyc-bypass-age-verification-using-generative-video-models.html)
- [2] [Amazon Rekognition Face Liveness](https://docs.aws.amazon.com/rekognition/latest/dg/face-liveness.html)
- [3] [v4l2loopback](https://github.com/v4l2loopback/v4l2loopback)
- [4] [MDN - MediaDevices.getUserMedia()](https://developer.mozilla.org/en-US/docs/Web/API/MediaDevices/getUserMedia)
- [5] [Android Developers — Play Integrity API](https://developer.android.com/google/play/integrity)
- [6] [Apple Developer — App Attest](https://developer.apple.com/documentation/devicecheck/establishing-your-app-s-integrity)
{{#include ../banners/hacktricks-training.md}}
