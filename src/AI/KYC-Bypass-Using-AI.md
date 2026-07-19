# Bypass KYC za pomocą AI

{{#include ../banners/hacktricks-training.md}}

Modele generatywne mogą być używane do **omijania opartych na przeglądarce procesów KYC, weryfikacji wieku i biometrycznego wykrywania żywotności**. Słabym punktem często **nie jest transport ani dostawca cloud liveness, lecz granica zaufania kamery**: przeglądarka desktopowa zwykle ufa każdemu urządzeniu, które `getUserMedia()` udostępnia jako webcam.

## Praktyczny łańcuch ataku

1. **Wygeneruj media zgodne z wyzwaniami** za pomocą modelu video-to-video, wykorzystując aktora źródłowego i referencyjny obraz ofiary.
2. **Wstrzyknij sfałszowany strumień przed podpisaniem lub uploadem**, na przykład przez wirtualną kamerę Linux utworzoną za pomocą `v4l2loopback` i zasilaną przez OBS lub FFmpeg.
3. Pozwól przeglądarce i SDK dostawcy (WebRTC, AWS itd.) **przechwycić, podpisać i przesłać kontrolowane przez atakującego klatki tak, jakby pochodziły z prawdziwej kamery internetowej**.

Jest to istotne podczas assessmentów, ponieważ podpisane fragmenty WebSocket lub framing własnościowego SDK mogą sprawiać, że **modyfikacja na warstwie sieciowej** jest niepraktyczna, podczas gdy **wstrzykiwanie na warstwie kamery** nadal działa.

## Najważniejsze kierunki testów

- **Akceptacja wirtualnej kamery**: jeśli proces działa z poziomu przeglądarki desktopowej, sprawdź, czy OBS, `v4l2loopback` lub wirtualne kamery dostawcy są akceptowane jako zwykłe urządzenia peryferyjne.
- **Przekierowanie Camera API na urządzeniach mobilnych**: natywne procesy mobilne mogą nadal być podatne na atak, gdy hooki Frida przechwytują Camera API i zastępują bufory z sensora klatkami z MP4 lub wirtualnej kamery obsługiwanej przez emulator.
- **Osłabianie constraints**: strony wymagające dokładnych wartości `deviceId`, `frameRate`, `width`, `height` lub `facingMode` można czasami obejść przez monkeypatching `navigator.mediaDevices.getUserMedia` i zastąpienie ścisłych constraints szerszymi zakresami.
- **Generowanie materiału niskiej jakości oraz post-processing**: wygeneruj najtańszy materiał wideo, który model może niezawodnie wyrenderować, a następnie użyj upscalingu FFmpeg lub interpolacji klatek, aby spełnić wymagania dotyczące przechwytywania.
- **Przewidywalne aktywne wyzwania**: powtarzalne sekwencje ruchów głową lub błysków światła warto nagrać i odtworzyć za pomocą generative workflow.
- **Słabe wykrywanie replay**: proste perturbacje sceny, takie jak zmiana kadru lub pozycji, zmiany overlayu albo niewielki ruch, mogą wystarczyć, gdy logika anti-replay sprawdza wyłącznie powierzchowne podobieństwo klatek.

## Różnice w granicy zaufania między urządzeniami mobilnymi a desktopowymi

Natywne aplikacje mobilne mogą podnieść koszt ataku dzięki:

- **attestation sensora lub Secure Element** dla buforów kamery;
- sygnałom **execution-integrity**, takim jak **Play Integrity** lub **App Attest**;
- **korelacji ruchu** między obrazem wideo a telemetrią akcelerometru lub żyroskopu.

Desktopowe procesy webowe zwykle nie mają równoważnego łańcucha zaufania kamery, dlatego zazwyczaj stanowią ścieżkę najmniejszego oporu.

## Uwagi dotyczące przeglądu zabezpieczeń

Podczas przeglądu integracji KYC lub liveness sprawdź, czy:

- umożliwia **fallback do przeglądarki desktopowej** dla procesu, który był modelowany pod kątem zagrożeń wyłącznie dla przechwytywania mobilnego;
- opiera się głównie na **algorytmicznym liveness** bez silnej eskalacji do człowieka w przypadku podejrzanych sesji;
- używa **stabilnych lub przewidywalnych wyzwań**, które można wcześniej nagrać i dostarczyć do pipeline'u generowania;
- wykrywa **monkeypatching `getUserMedia`**, wirtualne kamery, niespójne dane telemetryczne dotyczące sprzętu przeglądarki lub brak device attestation.

## Referencje

- [Synacktiv - KYC: Bypass age verification using generative video models](https://www.synacktiv.com/en/publications/kyc-bypass-age-verification-using-generative-video-models.html)
- [Amazon Rekognition Face Liveness](https://docs.aws.amazon.com/rekognition/latest/dg/face-liveness.html)
- [v4l2loopback](https://github.com/v4l2loopback/v4l2loopback)
- [MDN - MediaDevices.getUserMedia()](https://developer.mozilla.org/en-US/docs/Web/API/MediaDevices/getUserMedia)

{{#include ../banners/hacktricks-training.md}}
