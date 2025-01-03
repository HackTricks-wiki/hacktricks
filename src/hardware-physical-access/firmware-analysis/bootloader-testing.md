{{#include ../../banners/hacktricks-training.md}}

Zalecane są następujące kroki w celu modyfikacji konfiguracji uruchamiania urządzenia i bootloaderów, takich jak U-boot:

1. **Dostęp do powłoki interpretera bootloadera**:

- Podczas uruchamiania naciśnij "0", spację lub inne zidentyfikowane "kody magiczne", aby uzyskać dostęp do powłoki interpretera bootloadera.

2. **Modyfikacja argumentów uruchamiania**:

- Wykonaj następujące polecenia, aby dodać '`init=/bin/sh`' do argumentów uruchamiania, co umożliwi wykonanie polecenia powłoki:
%%%
#printenv
#setenv bootargs=console=ttyS0,115200 mem=63M root=/dev/mtdblock3 mtdparts=sflash:<partitiionInfo> rootfstype=<fstype> hasEeprom=0 5srst=0 init=/bin/sh
#saveenv
#boot
%%%

3. **Konfiguracja serwera TFTP**:

- Skonfiguruj serwer TFTP, aby ładować obrazy przez lokalną sieć:
%%%
#setenv ipaddr 192.168.2.2 #lokalny adres IP urządzenia
#setenv serverip 192.168.2.1 #adres IP serwera TFTP
#saveenv
#reset
#ping 192.168.2.1 #sprawdź dostęp do sieci
#tftp ${loadaddr} uImage-3.6.35 #loadaddr przyjmuje adres, do którego ma zostać załadowany plik oraz nazwę pliku obrazu na serwerze TFTP
%%%

4. **Wykorzystanie `ubootwrite.py`**:

- Użyj `ubootwrite.py`, aby zapisać obraz U-boot i wprowadzić zmodyfikowane oprogramowanie układowe w celu uzyskania dostępu root.

5. **Sprawdzenie funkcji debugowania**:

- Sprawdź, czy funkcje debugowania, takie jak szczegółowe logowanie, ładowanie dowolnych rdzeni lub uruchamianie z nieznanych źródeł, są włączone.

6. **Ostrożność przy zakłóceniu sprzętowym**:

- Bądź ostrożny podczas łączenia jednego pinu z masą i interakcji z chipami SPI lub NAND flash podczas sekwencji uruchamiania urządzenia, szczególnie przed dekompresją jądra. Skonsultuj się z kartą katalogową chipu NAND flash przed skracaniem pinów.

7. **Konfiguracja nieuczciwego serwera DHCP**:
- Skonfiguruj nieuczciwy serwer DHCP z złośliwymi parametrami, które urządzenie ma przyjąć podczas uruchamiania PXE. Wykorzystaj narzędzia takie jak serwer pomocniczy DHCP Metasploit (MSF). Zmodyfikuj parametr 'FILENAME' za pomocą poleceń wstrzykiwania, takich jak `'a";/bin/sh;#'`, aby przetestować walidację wejścia dla procedur uruchamiania urządzenia.

**Uwaga**: Kroki związane z fizyczną interakcją z pinami urządzenia (\*oznaczone gwiazdkami) należy podejmować z najwyższą ostrożnością, aby uniknąć uszkodzenia urządzenia.

## References

- [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)

{{#include ../../banners/hacktricks-training.md}}
