# Fizyczne Ataki

{{#include ../banners/hacktricks-training.md}}

## Odzyskiwanie Hasła BIOS i Bezpieczeństwo Systemu

**Resetowanie BIOS** można osiągnąć na kilka sposobów. Większość płyt głównych zawiera **baterię**, która, gdy zostanie usunięta na około **30 minut**, zresetuje ustawienia BIOS, w tym hasło. Alternatywnie, **jumper na płycie głównej** można dostosować, aby zresetować te ustawienia, łącząc określone piny.

W sytuacjach, gdy dostosowania sprzętowe nie są możliwe lub praktyczne, **narzędzia programowe** oferują rozwiązanie. Uruchomienie systemu z **Live CD/USB** z dystrybucjami takimi jak **Kali Linux** zapewnia dostęp do narzędzi takich jak **_killCmos_** i **_CmosPWD_**, które mogą pomóc w odzyskiwaniu hasła BIOS.

W przypadkach, gdy hasło BIOS jest nieznane, wprowadzenie go błędnie **trzy razy** zazwyczaj skutkuje kodem błędu. Kod ten można wykorzystać na stronach takich jak [https://bios-pw.org](https://bios-pw.org), aby potencjalnie odzyskać użyteczne hasło.

### Bezpieczeństwo UEFI

Dla nowoczesnych systemów korzystających z **UEFI** zamiast tradycyjnego BIOS, narzędzie **chipsec** może być wykorzystane do analizy i modyfikacji ustawień UEFI, w tym wyłączania **Secure Boot**. Można to osiągnąć za pomocą następującego polecenia:
```bash
python chipsec_main.py -module exploits.secure.boot.pk
```
---

## Analiza RAM i ataki Cold Boot

RAM przechowuje dane krótko po odcięciu zasilania, zazwyczaj przez **1 do 2 minut**. Ta trwałość może być wydłużona do **10 minut** poprzez zastosowanie zimnych substancji, takich jak azot ciekły. W tym wydłużonym okresie można stworzyć **zrzut pamięci** za pomocą narzędzi takich jak **dd.exe** i **volatility** do analizy.

---

## Ataki Direct Memory Access (DMA)

**INCEPTION** to narzędzie zaprojektowane do **manipulacji pamięcią fizyczną** przez DMA, kompatybilne z interfejsami takimi jak **FireWire** i **Thunderbolt**. Umożliwia ominięcie procedur logowania poprzez patchowanie pamięci, aby akceptowała dowolne hasło. Jednak jest nieskuteczne przeciwko systemom **Windows 10**.

---

## Live CD/USB do uzyskania dostępu do systemu

Zmiana binarnych plików systemowych, takich jak **_sethc.exe_** lub **_Utilman.exe_**, na kopię **_cmd.exe_** może zapewnić dostęp do wiersza poleceń z uprawnieniami systemowymi. Narzędzia takie jak **chntpw** mogą być używane do edytowania pliku **SAM** instalacji Windows, co pozwala na zmianę haseł.

**Kon-Boot** to narzędzie, które ułatwia logowanie do systemów Windows bez znajomości hasła, tymczasowo modyfikując jądro Windows lub UEFI. Więcej informacji można znaleźć na [https://www.raymond.cc](https://www.raymond.cc/blog/login-to-windows-administrator-and-linux-root-account-without-knowing-or-changing-current-password/).

---

## Obsługa funkcji zabezpieczeń Windows

### Skróty do uruchamiania i odzyskiwania

- **Supr**: Dostęp do ustawień BIOS.
- **F8**: Wejście w tryb odzyskiwania.
- Naciśnięcie **Shift** po banerze Windows może ominąć autologowanie.

### Urządzenia BAD USB

Urządzenia takie jak **Rubber Ducky** i **Teensyduino** służą jako platformy do tworzenia urządzeń **bad USB**, zdolnych do wykonywania zdefiniowanych ładunków po podłączeniu do docelowego komputera.

### Kopia zapasowa woluminu

Uprawnienia administratora pozwalają na tworzenie kopii wrażliwych plików, w tym pliku **SAM**, za pomocą PowerShell.

---

## Ominięcie szyfrowania BitLocker

Szyfrowanie BitLocker może być potencjalnie ominięte, jeśli **hasło odzyskiwania** zostanie znalezione w pliku zrzutu pamięci (**MEMORY.DMP**). Narzędzia takie jak **Elcomsoft Forensic Disk Decryptor** lub **Passware Kit Forensic** mogą być wykorzystane w tym celu.

---

## Inżynieria społeczna w celu dodania klucza odzyskiwania

Nowy klucz odzyskiwania BitLocker może być dodany za pomocą taktyk inżynierii społecznej, przekonując użytkownika do wykonania polecenia, które dodaje nowy klucz odzyskiwania składający się z zer, co upraszcza proces deszyfrowania.

---

## Wykorzystanie przełączników intruzji obudowy / konserwacji do resetowania BIOS do ustawień fabrycznych

Wiele nowoczesnych laptopów i komputerów stacjonarnych o małych rozmiarach zawiera **przełącznik intruzji obudowy**, który jest monitorowany przez Kontroler Wbudowany (EC) oraz oprogramowanie BIOS/UEFI. Głównym celem przełącznika jest podniesienie alertu, gdy urządzenie jest otwierane, jednak dostawcy czasami implementują **nieudokumentowany skrót do odzyskiwania**, który jest wyzwalany, gdy przełącznik jest przełączany w określony sposób.

### Jak działa atak

1. Przełącznik jest podłączony do **przerwania GPIO** na EC.
2. Oprogramowanie działające na EC śledzi **czas i liczbę naciśnięć**.
3. Gdy rozpoznany zostanie twardo zakodowany wzór, EC wywołuje rutynę *resetowania płyty głównej*, która **czyści zawartość NVRAM/CMOS systemu**.
4. Przy następnym uruchomieniu BIOS ładuje wartości domyślne – **hasło administratora, klucze Secure Boot i wszystkie niestandardowe konfiguracje są usuwane**.

> Gdy Secure Boot jest wyłączony, a hasło firmware jest usunięte, atakujący może po prostu uruchomić dowolny zewnętrzny obraz systemu operacyjnego i uzyskać nieograniczony dostęp do wewnętrznych dysków.

### Przykład z życia – Laptop Framework 13

Skrót do odzyskiwania dla Framework 13 (11. / 12. / 13. generacja) to:
```text
Press intrusion switch  →  hold 2 s
Release                 →  wait 2 s
(repeat the press/release cycle 10× while the machine is powered)
```
Po dziesiątym cyklu EC ustawia flagę, która instruuje BIOS do wyczyszczenia NVRAM przy następnym uruchomieniu. Cała procedura zajmuje ~40 s i wymaga **tylko śrubokrętu**.

### Ogólna procedura eksploatacji

1. Włącz lub wznowić działanie celu, aby EC działał.
2. Zdejmij dolną pokrywę, aby odsłonić przełącznik intruzji/konserwacji.
3. Powtórz specyficzny dla dostawcy wzór przełączania (skonsultuj się z dokumentacją, forami lub przeanalizuj oprogramowanie układowe EC).
4. Złóż ponownie i uruchom – zabezpieczenia oprogramowania układowego powinny być wyłączone.
5. Uruchom live USB (np. Kali Linux) i wykonaj zwykłe czynności po eksploatacji (zrzut poświadczeń, eksfiltracja danych, implantacja złośliwych binariów EFI itp.).

### Wykrywanie i łagodzenie

* Rejestruj zdarzenia intruzji obudowy w konsoli zarządzania systemem operacyjnym i koreluj z niespodziewanymi resetami BIOS.
* Używaj **uszczelnień zabezpieczających** na śrubach/pokrywach, aby wykryć otwarcie.
* Przechowuj urządzenia w **fizycznie kontrolowanych obszarach**; zakładaj, że dostęp fizyczny oznacza pełne przejęcie.
* Gdzie to możliwe, wyłącz funkcję „reset przełącznika konserwacyjnego” dostawcy lub wymagaj dodatkowej autoryzacji kryptograficznej dla resetów NVRAM.

---

## Odniesienia

- [Pentest Partners – “Framework 13. Press here to pwn”](https://www.pentestpartners.com/security-blog/framework-13-press-here-to-pwn/)
- [FrameWiki – Przewodnik po resecie płyty głównej](https://framewiki.net/guides/mainboard-reset)

{{#include ../banners/hacktricks-training.md}}
