# macOS Kernel & System Extensions

{{#include ../../../banners/hacktricks-training.md}}

## Jądro XNU

**Rdzeniem macOS jest XNU**, co oznacza „X is Not Unix”. To jądro składa się przede wszystkim z **mikrojądra Mach** (omówionego później) **oraz** elementów Berkeley Software Distribution (**BSD**). XNU zapewnia również platformę dla **kernel drivers za pośrednictwem systemu I/O Kit**. Jądro XNU jest częścią projektu open source Darwin, co oznacza, że **jego kod źródłowy jest publicznie dostępny**.

Z perspektywy security researchera lub developera Unix **macOS** może wydawać się dość **podobny** do systemu **FreeBSD**, wyposażonego w elegancki GUI i zestaw niestandardowych aplikacji. Większość aplikacji opracowanych dla BSD skompiluje się i uruchomi w macOS bez konieczności wprowadzania modyfikacji, ponieważ wszystkie znane użytkownikom Unix narzędzia command-line są dostępne w macOS. Jednak ponieważ jądro XNU zawiera Mach, występują istotne różnice między tradycyjnym systemem unixopodobnym a macOS; różnice te mogą powodować potencjalne problemy lub zapewniać unikalne możliwości.

Open source version of XNU: [https://opensource.apple.com/source/xnu/](https://opensource.apple.com/source/xnu/)

### Mach

Mach to **mikrojądro** zaprojektowane jako zgodne z **UNIX**. Jedną z jego kluczowych zasad projektowych było **zminimalizowanie** ilości **kodu** działającego w przestrzeni **jądra** i umożliwienie, aby wiele typowych funkcji jądra, takich jak system plików, networking i I/O, **działało jako zadania na poziomie użytkownika**.

W XNU Mach odpowiada za **wiele krytycznych operacji niskopoziomowych**, które zwykle obsługuje jądro, takich jak scheduling procesora, multitasking i zarządzanie pamięcią wirtualną.

### BSD

Jądro XNU zawiera również znaczną ilość kodu pochodzącego z projektu **FreeBSD**. Kod ten **działa jako część jądra razem z Mach**, w tej samej przestrzeni adresowej. Kod FreeBSD obecny w XNU może jednak znacznie różnić się od oryginalnego kodu FreeBSD, ponieważ konieczne były modyfikacje zapewniające jego zgodność z Mach. FreeBSD dostarcza wiele funkcji jądra, w tym:

- Zarządzanie procesami
- Obsługa sygnałów
- Podstawowe mechanizmy bezpieczeństwa, w tym zarządzanie użytkownikami i grupami
- Infrastruktura wywołań systemowych
- Stos TCP/IP i sockets
- Firewall i filtrowanie pakietów

Zrozumienie interakcji między BSD i Mach może być skomplikowane ze względu na ich odmienne modele pojęciowe. Na przykład BSD używa procesów jako podstawowej jednostki wykonawczej, podczas gdy Mach działa w oparciu o threads. Ta rozbieżność jest uzgadniana w XNU poprzez **powiązanie każdego procesu BSD z zadaniem Mach**, które zawiera dokładnie jeden thread Mach. Gdy używane jest wywołanie systemowe fork(), kod BSD znajdujący się w jądrze wykorzystuje funkcje Mach do utworzenia zadania i struktury threada.

Ponadto **Mach i BSD utrzymują różne modele bezpieczeństwa**: model bezpieczeństwa **Mach** opiera się na **port rights**, natomiast model bezpieczeństwa BSD działa w oparciu o **własność procesu**. Rozbieżności między tymi modelami sporadycznie prowadziły do podatności umożliwiających local privilege escalation. Oprócz typowych wywołań systemowych istnieją również **Mach traps, które pozwalają programom w przestrzeni użytkownika komunikować się z jądrem**. Wszystkie te elementy razem tworzą wieloaspektową, hybrydową architekturę jądra macOS.

### I/O Kit - Drivers

I/O Kit to open-source, obiektowo zorientowany **framework device-driverów** w jądrze XNU, który obsługuje **dynamicznie ładowane device drivers**. Umożliwia on dodawanie modularnego kodu do jądra on-the-fly, zapewniając obsługę różnorodnego hardware.


{{#ref}}
macos-iokit.md
{{#endref}}

### Coprocessors in macOS Architecture

Platformy Apple korzystają z kilku coprocessorów, aby przenieść zadania wrażliwe na opóźnienia poza główne rdzenie oraz odizolować funkcje krytyczne z punktu widzenia bezpieczeństwa.

- **Secure Enclave Processor (SEP)**: Dedykowany rdzeń ARM z własnym mikrojądrem i secure boot chain, zazwyczaj działający na poziomie **EL3/secure world**. Komunikacja odbywa się za pośrednictwem mailbox drivers w macOS na poziomie EL1.
- Attack surface: aktualizacje firmware SEP oraz daemony user-space (`seputil`, `securityd`), które przekazują żądania.
- Impact of compromise: leak long-term keys, obejście biometric gating oraz złamanie zabezpieczeń FileVault lub Apple Pay.
- **System Management Controller (SMC)**: Działa na proprietary firmware w mikrokontrolerze poza poziomami wyjątków ARM. macOS (EL1) komunikuje się z nim za pośrednictwem user clients I/O Kit.
- Attack surface: komunikaty USB-C power delivery, interfejsy zarządzania wentylatorami i baterią oraz ścieżki aktualizacji firmware.
- Impact of compromise: obejście limitów termicznych, wstrzykiwanie fałszywych danych z sensorów, odcięcie zasilania lub umieszczenie persistent NVRAM backdoors.
- **T1/T2 Security Chips**: Uruchamiają bridgeOS (wywodzący się z watchOS), głównie na poziomach EL1/EL3, na własnych rdzeniach ARM. macOS komunikuje się z nimi za pośrednictwem kanałów podobnych do PCIe/USB, obsługiwanych przez IOKit.
- Attack surface: ścieżki DFU/restore, endpointy IPC udostępniane przez usługi takie jak `tccd` oraz media pipelines połączone z T2.
- Impact of compromise: wyłączenie secure boot, odszyfrowanie zawartości SSD, przejęcie kontroli nad camera/mic gating lub emulowanie HID input w celu uzyskania stealth persistence.
- **Display Coprocessor (DCP)**: Uruchamia firmware na poziomie EL1 w izolowanej przestrzeni adresowej chronionej przez DART (IOMMU firmy Apple).
- Attack surface: interfejsy `DCPAVService`, współdzielone descriptor buffers oraz parsowanie firmware image.
- Impact of compromise: wstrzykiwanie dowolnych frames, podsłuchiwanie framebufferów lub zablokowanie display pipeline w celu przeprowadzenia DoS.
- **Apple Neural Engine (ANE)**: Uruchamia microcode na dedykowanym klastrze ML (bez poziomów ARM EL). macOS planuje zadania za pośrednictwem `ANECompilerService` i IOKit.
- Attack surface: skompilowane pliki binarne modeli (`.ane`), API Core ML zasilające custom kernels oraz firmware loaders.
- Impact of compromise: manipulowanie modelami ML lub ich exfiltration, leak przetwarzanych danych audio/video albo sabotaż on-device inference.
- **AGX GPU**: Firmware działa na custom GPU cores z schedulerem; EL0 przesyła komendy Metal, które są weryfikowane przez EL1.
- Attack surface: Metal shader compiler, API shared buffer mapping oraz interfejsy ioctl `com.apple.AGXFirmware`.
- Impact of compromise: dostęp DMA do pamięci systemowej, sandbox escapes za pośrednictwem GPU drivers lub persistent firmware implants.
- **Apple Video Encoder (AVE)**: Firmware działa w Media Engine w sandboxie podobnym do EL1. macOS komunikuje się z nim za pośrednictwem VideoToolbox i `AppleAVE2`.
- Attack surface: codec bitstreams, parameter sets, buffers dostarczane przez użytkownika oraz firmware update blobs.
- Impact of compromise: leak nieskompresowanych frames, obejście DRM lub uzyskanie code execution z dostępem do DMA engines.
- **Image Signal Processor (ISP)**: Uruchamia secure firmware w klastrze Media Engine; macOS camera drivers działają na poziomie EL1.
- Attack surface: camera HALs, RAW frame descriptors, kolejki konfiguracji ISP oraz aktualizacje firmware.
- Impact of compromise: ciche przechwytywanie raw camera feeds, wyłączenie privacy indicators lub wstrzykiwanie spreparowanego obrazu.
- **AMX Matrix cores**: Działają jako jednostki coprocessora udostępniane na poziomach EL0/EL1 za pośrednictwem nowych instrukcji.
- Attack surface: kernel virtualization stanu AMX (`thread_set_state`, context switches) oraz generowanie kodu user-space.
- Impact of compromise: leak tile registers innych procesów, fingerprinting workloads lub escalation za pośrednictwem kernel memory corruption.

Nowoczesny macOS traktuje te coprocessors jako zaufane komponenty chain of trust. Firmware SEP, SMC i T2 jest podpisywany przez Apple, a handshake protocols (często implementowane za pośrednictwem mailboxów lub rodzin I/O Kit) zawierają challenge-response checks, dzięki czemu tylko uwierzytelniony firmware może obsługiwać żądania.

### IPC - Inter Process Communication

{{#ref}}
../macos-proces-abuse/macos-ipc-inter-process-communication/
{{#endref}}

## macOS Kernel Extensions

macOS jest **bardzo restrykcyjny w kwestii ładowania Kernel Extensions** (.kext), ponieważ kod ten działa z wysokimi uprawnieniami. W praktyce domyślnie jest to niemal niemożliwe (chyba że zostanie znaleziony bypass).

Na poniższej stronie można również zobaczyć, jak odzyskać plik `.kext`, który macOS ładuje do swojego **kernelcache**:

{{#ref}}
macos-kernel-extensions.md
{{#endref}}

### macOS System Extensions

Zamiast używać Kernel Extensions, macOS utworzył System Extensions, które oferują API na poziomie użytkownika do interakcji z jądrem. Dzięki temu developerzy mogą unikać używania kernel extensions.

{{#ref}}
macos-system-extensions.md
{{#endref}}


### Cryptexes & RSR (Rapid Security Response)

- **Cryptex** oznacza **CRYPTographically-sealed EXtension**. Jest to sealed disk image (container) używany przez Apple do przechowywania części systemu operacyjnego (frameworks, shared libraries, apps), które z większym prawdopodobieństwem będą zmieniane między głównymi aktualizacjami systemu operacyjnego.
- W macOS i iOS komponenty umieszczone w cryptexes mogą być **patchowane lub zastępowane** za pośrednictwem RSR bez ponownego sealowania całego system volume.
- Cryptexes znajdują się na woluminie **Preboot**, obok boot firmware, i są graftowane do systemu plików systemu operacyjnego w runtime.
- Ładowanie zawartości cryptex obejmuje walidację: system sprawdza file seals, manifests i root hashes, a następnie montuje lub „graftuje” zawartość cryptex, aby aplikacje w runtime korzystały z wersji znajdujących się w cryptex, jeśli są dostępne.
- W boot logs ładowanie cryptex następuje po inicjalizacji jądra, ale przed uruchomieniem pełnych usług systemowych.


#### Rapid Security Response (RSR)

- **RSR** to mechanizm Apple służący do dostarczania **security patches między regularnymi aktualizacjami systemu operacyjnego**. Jest kierowany do zawartości cryptex w celu aktualizacji podatnych komponentów (np. libraries, frameworks) bez modyfikowania podstawowego system volume.
- Podczas stosowania aktualizacji RSR urządzenie żąda od signing server Apple manifestu **Cryptex1 Image4**. Manifest ten jest kryptograficznie powiązany z urządzeniem i nową zawartością cryptex.
- Istniejący AP boot ticket dla base system **nie jest modyfikowany** przez RSR. Patch działa addytywnie na sealed base OS.
- W macOS niektóre spatchowane komponenty (np. Safari) stają się aktywne natychmiast po ponownym uruchomieniu aplikacji; pełny restart systemu nie zawsze jest wymagany.
- RSR są **usuwalne**: każda aktualizacja zawiera zarówno patch, jak i „antipatch”, który może przywrócić wersję base OS. Po usunięciu zawartość cryptex zostaje cofnięta.
- Aktualizacje RSR są zazwyczaj znacznie mniejsze niż pełne aktualizacje systemu operacyjnego i wymagają niższego poziomu baterii do instalacji.


## References

- [1] [The Mac Hacker's Handbook](https://www.amazon.com/-/es/Charlie-Miller-ebook-dp-B004U7MUMU/dp/B004U7MUMU/ref=mt_other?_encoding=UTF8&me=&qid=)
- [2] [The Art of Mac Malware, Vol. 1 — Analysis](https://taomm.org/vol1/analysis.html)

{{#include ../../../banners/hacktricks-training.md}}
