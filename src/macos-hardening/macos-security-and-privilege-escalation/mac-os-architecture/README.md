# Jądro i rozszerzenia systemowe macOS

{{#include ../../../banners/hacktricks-training.md}}

## Jądro XNU

**Rdzeniem macOS jest XNU**, co oznacza „X is Not Unix”. Jądro to składa się przede wszystkim z **mikrojądra Mach** (omówionego później) **oraz** elementów Berkeley Software Distribution (**BSD**). XNU zapewnia również platformę dla **sterowników jądra za pośrednictwem systemu I/O Kit**. Jądro XNU jest częścią projektu open source Darwin, co oznacza, że **jego kod źródłowy jest publicznie dostępny**.

Z perspektywy badacza bezpieczeństwa lub dewelopera systemów Unix, **macOS** może wydawać się dość **podobny** do systemu **FreeBSD**, wyposażonego w elegancki interfejs graficzny i zestaw niestandardowych aplikacji. Większość aplikacji opracowanych dla BSD skompiluje się i uruchomi w macOS bez konieczności wprowadzania modyfikacji, ponieważ wszystkie znane użytkownikom Uniksa narzędzia wiersza poleceń są obecne w macOS. Jednak ponieważ jądro XNU zawiera Mach, istnieją istotne różnice między tradycyjnym systemem uniksopodobnym a macOS, a różnice te mogą powodować potencjalne problemy lub zapewniać unikalne możliwości.

Open source version of XNU: [https://opensource.apple.com/source/xnu/](https://opensource.apple.com/source/xnu/)

### Mach

Mach to **mikrojądro** zaprojektowane jako **zgodne z UNIX-em**. Jedną z jego kluczowych zasad projektowych było **ograniczenie** ilości **kodu** działającego w przestrzeni **jądra**, a zamiast tego umożliwienie wykonywania wielu typowych funkcji jądra, takich jak system plików, obsługa sieci i operacje wejścia/wyjścia, **jako zadań na poziomie użytkownika**.

W XNU Mach **odpowiada za wiele krytycznych operacji niskiego poziomu**, które zwykle obsługuje jądro, takich jak planowanie procesora, wielozadaniowość i zarządzanie pamięcią wirtualną.

### BSD

**Jądro** XNU zawiera również znaczną ilość kodu wywodzącego się z projektu **FreeBSD**. Kod ten **działa jako część jądra wraz z Machem**, w tej samej przestrzeni adresowej. Kod FreeBSD zawarty w XNU może jednak znacząco różnić się od oryginalnego kodu FreeBSD, ponieważ konieczne były modyfikacje zapewniające jego zgodność z Machem. FreeBSD odpowiada za wiele operacji jądra, w tym:

- Zarządzanie procesami
- Obsługa sygnałów
- Podstawowe mechanizmy bezpieczeństwa, w tym zarządzanie użytkownikami i grupami
- Infrastruktura wywołań systemowych
- Stos TCP/IP i gniazda
- Zapora sieciowa i filtrowanie pakietów

Zrozumienie interakcji między BSD a Machem może być trudne ze względu na ich różne modele koncepcyjne. Na przykład BSD używa procesów jako podstawowej jednostki wykonawczej, podczas gdy Mach działa w oparciu o wątki. Ta rozbieżność jest rozwiązywana w XNU poprzez **powiązanie każdego procesu BSD z zadaniem Mach**, które zawiera dokładnie jeden wątek Mach. Gdy używane jest wywołanie systemowe fork() BSD, kod BSD znajdujący się w jądrze korzysta z funkcji Mach w celu utworzenia zadania i struktury wątku.

Ponadto **Mach i BSD utrzymują odrębne modele bezpieczeństwa**: model bezpieczeństwa **Macha** opiera się na **prawach do portów**, natomiast model bezpieczeństwa BSD działa w oparciu o **własność procesów**. Różnice między tymi modelami okazjonalnie prowadziły do podatności umożliwiających lokalne podniesienie uprawnień. Oprócz typowych wywołań systemowych istnieją również **pułapki Mach (Mach traps)**, które pozwalają programom w przestrzeni użytkownika komunikować się z jądrem. Wszystkie te elementy razem tworzą wieloaspektową, hybrydową architekturę jądra macOS.<sup>[[1]](#references)</sup>

### I/O Kit - Sterowniki

I/O Kit to open-source, obiektowo zorientowany **framework sterowników urządzeń** w jądrze XNU, który obsługuje **dynamicznie ładowane sterowniki urządzeń**. Umożliwia on dodawanie modularnego kodu do jądra w locie i obsługuje różnorodny sprzęt.


{{#ref}}
macos-iokit.md
{{#endref}}

### Koprocesory w architekturze macOS

Platformy Apple korzystają z kilku koprocesorów, aby przenosić zadania wrażliwe na opóźnienia poza główne rdzenie oraz izolować funkcje krytyczne dla bezpieczeństwa.

- **Secure Enclave Processor (SEP)**: Dedykowany rdzeń ARM z własnym mikrojądrem i łańcuchem secure boot, działający zazwyczaj w **EL3/secure world**. Komunikacja odbywa się za pośrednictwem sterowników mailbox w macOS na poziomie EL1.
- Powierzchnia ataku: aktualizacje firmware SEP oraz demony w przestrzeni użytkownika (`seputil`, `securityd`), które pośredniczą w żądaniach.
- Skutki kompromitacji: Leak kluczy długoterminowych, obejście kontroli biometrycznej oraz złamanie zabezpieczeń FileVault lub Apple Pay.
- **System Management Controller (SMC)**: Uruchamia proprietary firmware na mikrokontrolerze poza poziomami wyjątków ARM. macOS (EL1) uzyskuje do niego dostęp za pośrednictwem klientów użytkownika I/O Kit.
- Powierzchnia ataku: komunikaty USB-C power delivery, interfejsy zarządzania wentylatorami i baterią oraz ścieżki aktualizacji firmware.
- Skutki kompromitacji: obejście limitów termicznych, wstrzykiwanie fałszywych danych z czujników, odcięcie zasilania lub umieszczenie trwałych backdoorów w NVRAM.
- **Układy bezpieczeństwa T1/T2**: Uruchamiają bridgeOS (wywodzący się z watchOS), głównie na poziomach EL1/EL3, na własnych rdzeniach ARM. macOS komunikuje się z nimi za pośrednictwem kanałów podobnych do PCIe/USB, obsługiwanych przez IOKit.
- Powierzchnia ataku: ścieżki DFU/restore, punkty końcowe IPC udostępniane przez usługi takie jak `tccd` oraz pipeline’y multimedialne połączone z T2.
- Skutki kompromitacji: wyłączenie secure boot, odszyfrowanie zawartości SSD, przejęcie kontroli nad dostępem kamery/mikrofonu lub emulowanie wejścia HID w celu uzyskania stealth persistence.
- **Display Coprocessor (DCP)**: Wykonuje firmware na poziomie EL1 w izolowanej przestrzeni adresowej chronionej przez DART (IOMMU firmy Apple).
- Powierzchnia ataku: interfejsy `DCPAVService`, współdzielone bufory deskryptorów oraz parsowanie obrazów firmware.
- Skutki kompromitacji: wstrzykiwanie dowolnych klatek, podsłuchiwanie framebufferów lub wyłączenie pipeline’u wyświetlania w celu przeprowadzenia DoS.
- **Apple Neural Engine (ANE)**: Uruchamia microcode w dedykowanym klastrze ML (bez poziomów ARM EL). macOS planuje zadania za pośrednictwem `ANECompilerService` i IOKit.
- Powierzchnia ataku: skompilowane pliki modeli (`.ane`), API Core ML dostarczające niestandardowe kernele oraz loadery firmware.
- Skutki kompromitacji: modyfikacja lub exfiltracja modeli ML, Leak przetwarzanych danych audio/wideo lub sabotowanie inference na urządzeniu.
- **AGX GPU**: Firmware działa na niestandardowych rdzeniach GPU z schedulerem; EL0 wysyła polecenia Metal, które EL1 waliduje.
- Powierzchnia ataku: kompilator shaderów Metal, API mapowania współdzielonych buforów oraz interfejsy ioctl `com.apple.AGXFirmware`.
- Skutki kompromitacji: dostęp DMA do pamięci systemowej, sandbox escapes za pośrednictwem sterowników GPU lub trwałe implanty firmware.
- **Apple Video Encoder (AVE)**: Firmware wykonuje się w Media Engine, w sandboxie podobnym do EL1. macOS komunikuje się za pośrednictwem VideoToolbox i `AppleAVE2`.
- Powierzchnia ataku: strumienie bitów kodeków, zestawy parametrów, bufory dostarczane przez użytkownika oraz blob’y aktualizacji firmware.
- Skutki kompromitacji: Leak nieskompresowanych klatek, obejście DRM lub uzyskanie code execution z dostępem do silników DMA.
- **Image Signal Processor (ISP)**: Uruchamia secure firmware w klastrze Media Engine; sterowniki kamery macOS działają na poziomie EL1.
- Powierzchnia ataku: HAL kamery, deskryptory klatek RAW, kolejki konfiguracji ISP oraz aktualizacje firmware.
- Skutki kompromitacji: ciche przechwytywanie surowego obrazu z kamery, wyłączenie wskaźników prywatności lub wstrzykiwanie sfałszowanego obrazu.
- **Rdzenie macierzy AMX**: Działają jako jednostki koprocesora udostępniane na poziomach EL0/EL1 za pośrednictwem nowych instrukcji.
- Powierzchnia ataku: wirtualizacja stanu AMX przez jądro (`thread_set_state`, przełączanie kontekstu) oraz generowanie kodu w przestrzeni użytkownika.
- Skutki kompromitacji: Leak rejestrów kafelków innych procesów, fingerprinting obciążeń lub eskalacja za pośrednictwem uszkodzenia pamięci jądra.

Współczesny macOS traktuje te koprocesory jako zaufane komponenty łańcucha zaufania. Firmware SEP, SMC i T2 jest podpisywany przez Apple, a protokoły handshake (często implementowane za pośrednictwem mailboxów lub rodzin I/O Kit) zawierają mechanizmy challenge-response, dzięki czemu tylko uwierzytelniony firmware może obsługiwać żądania.

### IPC - Komunikacja międzyprocesowa

{{#ref}}
../macos-proces-abuse/macos-ipc-inter-process-communication/
{{#endref}}

## Rozszerzenia jądra macOS

macOS jest **bardzo restrykcyjny w kwestii ładowania Kernel Extensions** (.kext), ponieważ kod ten działa z wysokimi uprawnieniami. W rzeczywistości domyślnie jest to praktycznie niemożliwe (chyba że zostanie znaleziony bypass).

Na poniższej stronie można również zobaczyć, jak odzyskać `.kext`, który macOS ładuje wewnątrz swojego **kernelcache**:

{{#ref}}
macos-kernel-extensions.md
{{#endref}}

### Rozszerzenia systemowe macOS

Zamiast korzystać z Kernel Extensions, macOS utworzył System Extensions, które oferują API działające na poziomie użytkownika i umożliwiające interakcję z jądrem. Dzięki temu deweloperzy mogą uniknąć używania rozszerzeń jądra.

{{#ref}}
macos-system-extensions.md
{{#endref}}


### Cryptexes i RSR (Rapid Security Response)

- **Cryptex** oznacza **CRYPTographically-sealed EXtension**. Jest to zapieczętowany obraz dysku (kontener) używany przez Apple do przechowywania części systemu operacyjnego (frameworków, bibliotek współdzielonych, aplikacji), które z większym prawdopodobieństwem zmieniają się między głównymi aktualizacjami systemu operacyjnego.
- W macOS i iOS komponenty umieszczone w cryptexes mogą być **patchowane lub zastępowane** za pośrednictwem RSR bez ponownego pieczętowania całego woluminu systemowego.
- Cryptexes znajdują się na woluminie **Preboot**, obok firmware’u rozruchowego, i są dołączane do systemu plików systemu operacyjnego w czasie działania.
- Ładowanie zawartości cryptex obejmuje walidację: system sprawdza pieczęcie plików, manifesty i hashe główne, a następnie montuje lub „dołącza” zawartość cryptex, aby aplikacje w czasie działania korzystały z wersji cryptex, jeśli są dostępne.
- W logach rozruchowych ładowanie cryptex odbywa się po inicjalizacji jądra, ale przed uruchomieniem pełnych usług systemowych.


#### Rapid Security Response (RSR)

- **RSR** to mechanizm Apple służący do dostarczania **security patches pomiędzy regularnymi aktualizacjami systemu operacyjnego**. Kieruje on poprawki do zawartości cryptex, aby aktualizować podatne elementy (np. biblioteki i frameworki) bez modyfikowania podstawowego woluminu systemowego.
- Podczas stosowania aktualizacji RSR urządzenie żąda od serwera podpisującego Apple manifestu **Cryptex1 Image4**. Manifest ten jest kryptograficznie powiązany z urządzeniem i nową zawartością cryptex.
- Istniejący AP boot ticket dla systemu bazowego **nie jest modyfikowany** przez RSR. Patch działa addytywnie na zapieczętowanym systemie bazowym.
- W macOS niektóre spatchowane komponenty (np. Safari) stają się aktywne natychmiast po ponownym uruchomieniu aplikacji; pełny restart systemu nie zawsze jest wymagany.
- RSR-y są **usuwalne**: każda aktualizacja zawiera zarówno patch, jak i „antipatch”, który może przywrócić wersję systemu bazowego. Po usunięciu zawartość cryptex zostaje przywrócona.
- Aktualizacje RSR są zazwyczaj znacznie mniejsze niż pełne aktualizacje systemu operacyjnego i wymagają niższego poziomu baterii do instalacji.


## References

- [1] [The Mac Hacker's Handbook](https://www.amazon.com/-/es/Charlie-Miller-ebook-dp-B004U7MUMU/dp/B004U7MUMU/ref=mt_other?_encoding=UTF8&me=&qid=)
- [2] [The Art of Mac Malware, Vol. 1 — Analysis](https://taomm.org/vol1/analysis.html)

{{#include ../../../banners/hacktricks-training.md}}
