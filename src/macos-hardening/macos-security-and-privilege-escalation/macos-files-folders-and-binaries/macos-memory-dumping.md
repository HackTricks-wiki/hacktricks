# macOS Memory Dumping

{{#include ../../../banners/hacktricks-training.md}}

## Memory Artifacts

### Swap Files

Pliki wymiany, takie jak `/private/var/vm/swapfile0`, służą jako **bufory, gdy pamięć fizyczna jest pełna**. Gdy nie ma już miejsca w pamięci fizycznej, jej dane są przenoszone do pliku wymiany, a następnie przywracane do pamięci fizycznej w razie potrzeby. Może być obecnych wiele plików wymiany, o nazwach takich jak swapfile0, swapfile1 i tak dalej.

### Hibernate Image

Plik znajdujący się w `/private/var/vm/sleepimage` jest kluczowy podczas **trybu hibernacji**. **Dane z pamięci są przechowywane w tym pliku, gdy OS X hibernuje**. Po obudzeniu komputera system odzyskuje dane pamięci z tego pliku, umożliwiając użytkownikowi kontynuowanie tam, gdzie przerwał.

Warto zauważyć, że w nowoczesnych systemach MacOS ten plik jest zazwyczaj szyfrowany z powodów bezpieczeństwa, co utrudnia odzyskiwanie.

- Aby sprawdzić, czy szyfrowanie jest włączone dla sleepimage, można uruchomić polecenie `sysctl vm.swapusage`. Pokaże to, czy plik jest szyfrowany.

### Memory Pressure Logs

Innym ważnym plikiem związanym z pamięcią w systemach MacOS jest **dziennik ciśnienia pamięci**. Te dzienniki znajdują się w `/var/log` i zawierają szczegółowe informacje o użyciu pamięci przez system oraz zdarzeniach ciśnienia. Mogą być szczególnie przydatne do diagnozowania problemów związanych z pamięcią lub zrozumienia, jak system zarządza pamięcią w czasie.

## Dumping memory with osxpmem

Aby zrzucić pamięć w maszynie MacOS, można użyć [**osxpmem**](https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip).

**Uwaga**: Poniższe instrukcje będą działać tylko na Macach z architekturą Intel. To narzędzie jest teraz archiwizowane, a ostatnia wersja została wydana w 2017 roku. Pobrany binarny plik za pomocą poniższych instrukcji jest skierowany na chipy Intel, ponieważ Apple Silicon nie istniał w 2017 roku. Może być możliwe skompilowanie binarnego pliku dla architektury arm64, ale będziesz musiał spróbować samodzielnie.
```bash
#Dump raw format
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem

#Dump aff4 format
sudo osxpmem.app/osxpmem -o /tmp/dump_mem.aff4
```
Jeśli napotkasz ten błąd: `osxpmem.app/MacPmem.kext failed to load - (libkern/kext) authentication failure (file ownership/permissions); check the system/kernel logs for errors or try kextutil(8)` Możesz to naprawić, wykonując:
```bash
sudo cp -r osxpmem.app/MacPmem.kext "/tmp/"
sudo kextutil "/tmp/MacPmem.kext"
#Allow the kext in "Security & Privacy --> General"
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
**Inne błędy** mogą być naprawione przez **zezwolenie na załadowanie kext** w "Bezpieczeństwo i prywatność --> Ogólne", po prostu **zezwól** na to.

Możesz również użyć tego **onelinera**, aby pobrać aplikację, załadować kext i zrzucić pamięć:
```bash
sudo su
cd /tmp; wget https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip; unzip osxpmem-2.1.post4.zip; chown -R root:wheel osxpmem.app/MacPmem.kext; kextload osxpmem.app/MacPmem.kext; osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
{{#include ../../../banners/hacktricks-training.md}}
