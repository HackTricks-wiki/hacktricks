# macOS Kernel & System Extensions

{{#include ../../../banners/hacktricks-training.md}}

## XNU Kernel

**Rdzeń macOS to XNU**, co oznacza "X nie jest Unixem". Ten kernel składa się zasadniczo z **mikrokernela Mach** (omówionego później) **i** elementów z Berkeley Software Distribution (**BSD**). XNU zapewnia również platformę dla **sterowników jądra za pośrednictwem systemu zwanego I/O Kit**. Kernel XNU jest częścią projektu open source Darwin, co oznacza, że **jego kod źródłowy jest ogólnodostępny**.

Z perspektywy badacza bezpieczeństwa lub dewelopera Unix, **macOS** może wydawać się dość **podobny** do systemu **FreeBSD** z eleganckim interfejsem graficznym i wieloma niestandardowymi aplikacjami. Większość aplikacji opracowanych dla BSD skompiluje się i uruchomi na macOS bez potrzeby modyfikacji, ponieważ narzędzia wiersza poleceń znane użytkownikom Unix są obecne w macOS. Jednakże, ponieważ kernel XNU zawiera Mach, istnieją istotne różnice między tradycyjnym systemem podobnym do Unixa a macOS, a te różnice mogą powodować potencjalne problemy lub zapewniać unikalne zalety.

Otwartoźródłowa wersja XNU: [https://opensource.apple.com/source/xnu/](https://opensource.apple.com/source/xnu/)

### Mach

Mach to **mikrokernel** zaprojektowany w celu **kompatybilności z UNIX**. Jedną z jego kluczowych zasad projektowych było **minimalizowanie** ilości **kodu** działającego w **przestrzeni jądra** i zamiast tego pozwolenie wielu typowym funkcjom jądra, takim jak system plików, sieci i I/O, na **działanie jako zadania na poziomie użytkownika**.

W XNU, Mach jest **odpowiedzialny za wiele krytycznych operacji niskiego poziomu**, które typowo obsługuje kernel, takich jak planowanie procesora, wielozadaniowość i zarządzanie pamięcią wirtualną.

### BSD

Kernel XNU **zawiera** również znaczną ilość kodu pochodzącego z projektu **FreeBSD**. Ten kod **działa jako część jądra razem z Machem**, w tej samej przestrzeni adresowej. Jednak kod FreeBSD w XNU może znacznie różnić się od oryginalnego kodu FreeBSD, ponieważ wymagane były modyfikacje, aby zapewnić jego zgodność z Machem. FreeBSD przyczynia się do wielu operacji jądra, w tym:

- Zarządzanie procesami
- Obsługa sygnałów
- Podstawowe mechanizmy bezpieczeństwa, w tym zarządzanie użytkownikami i grupami
- Infrastruktura wywołań systemowych
- Stos TCP/IP i gniazda
- Zapora ogniowa i filtrowanie pakietów

Zrozumienie interakcji między BSD a Machem może być skomplikowane, z powodu ich różnych ram koncepcyjnych. Na przykład, BSD używa procesów jako swojej podstawowej jednostki wykonawczej, podczas gdy Mach działa na podstawie wątków. Ta rozbieżność jest uzgadniana w XNU poprzez **powiązanie każdego procesu BSD z zadaniem Mach**, które zawiera dokładnie jeden wątek Mach. Gdy używane jest wywołanie systemowe fork() w BSD, kod BSD w jądrze używa funkcji Mach do utworzenia struktury zadania i wątku.

Ponadto, **Mach i BSD utrzymują różne modele bezpieczeństwa**: model bezpieczeństwa **Macha** oparty jest na **prawach portów**, podczas gdy model bezpieczeństwa BSD działa na podstawie **własności procesów**. Różnice między tymi dwoma modelami czasami prowadziły do lokalnych luk w podnoszeniu uprawnień. Oprócz typowych wywołań systemowych, istnieją również **pułapki Mach, które pozwalają programom w przestrzeni użytkownika na interakcję z jądrem**. Te różne elementy razem tworzą wieloaspektową, hybrydową architekturę jądra macOS.

### I/O Kit - Sterowniki

I/O Kit to otwartoźródłowa, obiektowa **ramka sterowników urządzeń** w jądrze XNU, obsługująca **dynamicznie ładowane sterowniki urządzeń**. Umożliwia dodawanie modułowego kodu do jądra w locie, wspierając różnorodny sprzęt.

{{#ref}}
macos-iokit.md
{{#endref}}

### IPC - Komunikacja między procesami

{{#ref}}
../macos-proces-abuse/macos-ipc-inter-process-communication/
{{#endref}}

## Rozszerzenia jądra macOS

macOS jest **bardzo restrykcyjny w ładowaniu rozszerzeń jądra** (.kext) z powodu wysokich uprawnień, z jakimi kod będzie działał. W rzeczywistości, domyślnie jest to praktycznie niemożliwe (chyba że znajdzie się obejście).

Na następnej stronie można również zobaczyć, jak odzyskać `.kext`, które macOS ładuje wewnątrz swojego **kernelcache**:

{{#ref}}
macos-kernel-extensions.md
{{#endref}}

### Rozszerzenia systemu macOS

Zamiast używać rozszerzeń jądra, macOS stworzył Rozszerzenia Systemu, które oferują API na poziomie użytkownika do interakcji z jądrem. W ten sposób deweloperzy mogą unikać używania rozszerzeń jądra.

{{#ref}}
macos-system-extensions.md
{{#endref}}

## Referencje

- [**Podręcznik hakera Maca**](https://www.amazon.com/-/es/Charlie-Miller-ebook-dp-B004U7MUMU/dp/B004U7MUMU/ref=mt_other?_encoding=UTF8&me=&qid=)
- [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)

{{#include ../../../banners/hacktricks-training.md}}
