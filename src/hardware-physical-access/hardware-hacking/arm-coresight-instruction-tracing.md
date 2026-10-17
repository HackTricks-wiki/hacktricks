# Śledzenie instrukcji ARM CoreSight przez SWO

{{#include ../../banners/hacktricks-training.md}}

Dostępny [port debugowania SWD/JTAG](jtag.md) może posłużyć do włączenia śledzenia wykonywania kodu Cortex-M na żywo, bez instrumentacji firmware'u. Wymaga to MCU z ETM i TPIU, dostępnej linii SWO, kopii dokładnie tego firmware'u do dekodowania oraz analizatora logicznego o wystarczającej szybkości dla wybranej szybkości transmisji SWO. W przeciwieństwie do [pomiarów side-channel opartych na poborze mocy lub emisji elektromagnetycznej](side_channel_analysis.md), ETM to ślad debugowania; rejestrowanie obu rodzajów danych pozwala powiązać zaobserwowany wyciek z wykonywanym kodem. To samo powiązanie może pomóc w synchronizacji [fault injection](fault_injection_attacks.md).<sup>[[1]](#references)</sup>

ETM emituje skompresowane zdarzenia przepływu sterowania, a nie bajty instrukcji. Dekoder odtwarza przebieg wykonania na podstawie zgodnego obrazu firmware'u. ITM przenosi instrumentację programową, a TPIU ramkuje źródła śladu i steruje wyjściem serial-wire. Przed zastosowaniem jakichkolwiek wartości rejestrów sprawdź komponenty CoreSight i konfigurację pinów w podręczniku referencyjnym układu: poniższy przykład dotyczy STM32F401 i nie jest uniwersalną konfiguracją Cortex-M.<sup>[[1]](#references)</sup>

## Znajdź wyjście śledzenia

W STM32F401 asynchroniczne SWO korzysta z PB3. W badanym kontrolerze PB3 był połączony z rezystorem R15, co zapewniało dostępny punkt pomiarowy. Jeśli obudowa lub połączenie sieciowe są niedostępne, tymczasowo skonfiguruj pin mogący obsługiwać SWO jako GPIO i przełączaj jego stan za pomocą zapisów do pamięci przez SWD. Sprawdź punkty na płytce, szukając pasującego przebiegu, a następnie przywróć konfigurację pinu śledzenia. Podłącz analizator, zapewniając wspólną masę i zgodny poziom napięcia logicznego.<sup>[[1]](#references)</sup>

## Włącz TPIU i ETM za pomocą OpenOCD

Poniższe polecenia należy umieścić w konfiguracji OpenOCD po wybraniu odpowiedniego adaptera i `target/stm32f4x.cfg`. `setbits` zachowuje niepowiązane bity w rejestrach sterujących, natomiast `mww` nadpisuje całe słowo. Najpierw TPIU kieruje ślad asynchroniczny; następnie ETM zostaje odblokowany, skonfigurowany w trybie programowania, otrzymuje identyfikator źródła śledzenia `1` i zostaje uruchomiony. Wartości te pochodzą z działającej konfiguracji STM32F401 autora, więc dostosuj je do mapy rejestrów i drzewa zegarowego danego układu.<sup>[[1]](#references)[[2]](#references)</sup>

<details>
<summary>Konfiguracja rejestrów śledzenia STM32F401 w OpenOCD</summary>

```tcl
proc setbits {addr mask} {
    mem2array value 32 $addr 1
    set value(0) [expr {$value(0) | $mask}]
    array2mem value 32 $addr 1
}
init
reset halt
setbits 0xe0042004 0x20       ;# DBGMCU_CR: trace I/O, async SWO
setbits 0xe000edfc 0x1000000  ;# DEMCR: TRCENA
mww 0xe0040004 1              ;# TPIU_CPSR: port size
mww 0xe0040010 3              ;# TPIU_ACPR: 16 MHz / (3 + 1) = 4 Mbaud
mww 0xe00400f0 2              ;# TPIU_SPPR: async UART framing
mww 0xe0040304 0x102          ;# TPIU_FFCR: formatter
mww 0xe0041fb0 0xC5ACCE55     ;# ETM_LAR: unlock
mww 0xe0041000 0x00201d0e     ;# ETM_CR: programming mode
mww 0xe0041200 1              ;# ETM_TRACEIDR: source ID 1
mww 0xe0041008 0x0000406F     ;# ETM_TER: trigger event
mww 0xe0041020 0x0000006F     ;# ETM_TEE: trace-enable event
mww 0xe0041024 0x00000001     ;# ETM_TSSR: start trace
mww 0xe0041000 0x0000191E     ;# ETM_CR: leave programming mode
```

</details>

Szybkość SWO wynosi `HCLK / (TPIU_ACPR + 1)`. Przy HCLK równym 16 MHz i `ACPR=3` przechwytuj dane z szybkością 4 Mbaud. W PulseView umieść dekoder ETM nad dekoderem UART na kanale analizatora SWO, ustaw rzeczywistą szybkość transmisji na przewodzie UART i użyj skonfigurowanego wcześniej identyfikatora źródła ETM. W przykładzie użyto próbkowania 24 MHz (sześć próbek na bit), wyzwalania zboczem opadającym i przechwytywania 25% danych przed wyzwoleniem. Po konfiguracji zatrzymaj/zresetuj cel, uzbrój przechwytywanie, a następnie wykonaj `resume`; zweryfikuj synchronizację ETM i wiarygodność ścieżki PC w odniesieniu do firmware, zamiast bezkrytycznie ufać wynikom, które tylko wyglądają na zdekodowane.<sup>[[1]](#references)</sup>

## Odzyskiwanie działania po zmianach zegara i multipleksowania pinów

Dwie niezależne czynności firmware mogą zatrzymać poprawny trace. Zmiana PLL zwiększa HCLK, a tym samym szybkość transmisji SWO, gdy `ACPR` pozostaje bez zmian; warstwa UART odzyskuje wtedy nieprawidłowe bajty, a odtwarzanie ETM daje bezsensowne wyniki. Sprawdź konfigurację RCC/PLL w [analizie firmware](../firmware-analysis/) i, w przykładzie ze STM32F401, załaduj obraz Cortex-M pod adres `0x08000000` oraz zaimportuj jego SVD do Ghidra, aby zapisy do rejestrów zegara miały nazwy. Ustaw sprzętowy breakpoint na dwubajtowej instrukcji Thumb *po* inicjalizacji zegara. W przykładzie polecenie `bp 0x080001fa 2 hw`, a następnie `resume`, zatrzymuje program po konfiguracji PLL; gdy rdzeń jest zatrzymany, `mww 0xe0040010 31` ustawia nowy dzielnik. Oblicz i ustaw nową szybkość transmisji UART, uzbrój przechwytywanie, a następnie ponownie wykonaj `resume`. Pozwala to przechwycić ścieżkę po zmianie, ale nie odzyskuje pominiętej zmiany.<sup>[[1]](#references)</sup>

Niezależnie od tego firmware może przełączyć pad SWO na inne urządzenie peryferyjne. W przykładzie konfiguracja alternate-function GPIO przełączyła PB3 na SDA interfejsu I2C2, więc żadne ustawienie dekodera nie mogło przywrócić trace na tym przewodzie. Znajdź w firmware odpowiednią inicjalizację GPIO, a następnie albo zastąp miejsca jej wywołań dopasowanymi rozmiarem instrukcjami Thumb NOP (`0xBF00` na każde półsłowo), albo zatrzymaj rdzeń i przywróć konfigurację pinu zgodną z trace przez SWD. Oba podejścia mogą wyłączyć odłączone urządzenie peryferyjne; zmianę wprowadzoną w czasie działania firmware może też ponownie nadpisać. Przywracając pin podczas działania programu, ustaw dzielnik SWO odpowiedni dla bieżącego HCLK.<sup>[[1]](#references)</sup>

## References

- [1] [Śledzenie instrukcji: śledzenie ARM na żywo za pomocą ETM, ITM i TPIU](https://voidstarsec.com/blog/arm-tracing-etm-itm)
- [2] [wrongbaud/etm-examples: konfiguracja STM32F4 OpenOCD ETM/TPIU](https://github.com/wrongbaud/etm-examples/blob/main/openocd-configs/prescaler.cfg)
{{#include ../../banners/hacktricks-training.md}}
