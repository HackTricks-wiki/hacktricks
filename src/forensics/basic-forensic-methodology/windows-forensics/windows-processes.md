{{#include ../../../banners/hacktricks-training.md}}

## smss.exe

**Menadżer sesji**.\
Sesja 0 uruchamia **csrss.exe** i **wininit.exe** (**usługi** **OS**), podczas gdy Sesja 1 uruchamia **csrss.exe** i **winlogon.exe** (**sesja** **użytkownika**). Jednak powinieneś zobaczyć **tylko jeden proces** tego **binarnego** bez dzieci w drzewie procesów.

Ponadto, sesje inne niż 0 i 1 mogą oznaczać, że występują sesje RDP.

## csrss.exe

**Proces podsystemu klienta/serwera**.\
Zarządza **procesami** i **wątkami**, udostępnia **API** **Windows** dla innych procesów oraz **mapuje litery dysków**, tworzy **pliki tymczasowe** i obsługuje **proces** **zamknięcia**.

Jest jeden **uruchomiony w Sesji 0 i drugi w Sesji 1** (więc **2 procesy** w drzewie procesów). Inny jest tworzony **na każdą nową sesję**.

## winlogon.exe

**Proces logowania Windows**.\
Odpowiada za **logowanie**/**wylogowywanie** użytkowników. Uruchamia **logonui.exe**, aby poprosić o nazwę użytkownika i hasło, a następnie wywołuje **lsass.exe**, aby je zweryfikować.

Następnie uruchamia **userinit.exe**, który jest określony w **`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`** z kluczem **Userinit**.

Ponadto, poprzedni rejestr powinien mieć **explorer.exe** w kluczu **Shell**, w przeciwnym razie może być nadużyty jako **metoda utrzymywania złośliwego oprogramowania**.

## wininit.exe

**Proces inicjalizacji Windows**. \
Uruchamia **services.exe**, **lsass.exe** i **lsm.exe** w Sesji 0. Powinien być tylko 1 proces.

## userinit.exe

**Aplikacja logowania Userinit**.\
Ładuje **ntduser.dat w HKCU** i inicjalizuje **środowisko** **użytkownika** oraz uruchamia **skrypty logowania** i **GPO**.

Uruchamia **explorer.exe**.

## lsm.exe

**Menadżer sesji lokalnej**.\
Współpracuje z smss.exe, aby manipulować sesjami użytkowników: logowanie/wylogowanie, uruchamianie powłoki, blokowanie/odblokowywanie pulpitu itp.

Po W7 lsm.exe został przekształcony w usługę (lsm.dll).

Powinien być tylko 1 proces w W7, a z nich usługa uruchamiająca DLL.

## services.exe

**Menadżer kontroli usług**.\
**Ładuje** **usługi** skonfigurowane jako **auto-start** oraz **sterowniki**.

Jest procesem nadrzędnym dla **svchost.exe**, **dllhost.exe**, **taskhost.exe**, **spoolsv.exe** i wielu innych.

Usługi są definiowane w `HKLM\SYSTEM\CurrentControlSet\Services`, a ten proces utrzymuje bazę danych w pamięci z informacjami o usługach, które można zapytać za pomocą sc.exe.

Zauważ, że **niektóre** **usługi** będą działać w **własnym procesie**, a inne będą **dzielić proces svchost.exe**.

Powinien być tylko 1 proces.

## lsass.exe

**Podsystem lokalnej autoryzacji bezpieczeństwa**.\
Odpowiada za **uwierzytelnianie** użytkowników i tworzenie **tokenów** **bezpieczeństwa**. Używa pakietów uwierzytelniających znajdujących się w `HKLM\System\CurrentControlSet\Control\Lsa`.

Zapisuje do **dziennika** **zdarzeń** **bezpieczeństwa** i powinien być tylko 1 proces.

Pamiętaj, że ten proces jest często atakowany w celu zrzutu haseł.

## svchost.exe

**Ogólny proces hosta usług**.\
Hostuje wiele usług DLL w jednym wspólnym procesie.

Zazwyczaj znajdziesz, że **svchost.exe** jest uruchamiany z flagą `-k`. To uruchomi zapytanie do rejestru **HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Svchost**, gdzie będzie klucz z argumentem wspomnianym w -k, który będzie zawierał usługi do uruchomienia w tym samym procesie.

Na przykład: `-k UnistackSvcGroup` uruchomi: `PimIndexMaintenanceSvc MessagingService WpnUserService CDPUserSvc UnistoreSvc UserDataSvc OneSyncSvc`

Jeśli również użyta jest **flaga `-s`** z argumentem, to svchost jest proszony o **uruchomienie tylko określonej usługi** w tym argumencie.

Będzie kilka procesów `svchost.exe`. Jeśli którykolwiek z nich **nie używa flagi `-k`**, to jest to bardzo podejrzane. Jeśli odkryjesz, że **services.exe nie jest procesem nadrzędnym**, to również jest bardzo podejrzane.

## taskhost.exe

Ten proces działa jako host dla procesów uruchamianych z DLL. Ładuje również usługi, które działają z DLL.

W W8 nazywa się to taskhostex.exe, a w W10 taskhostw.exe.

## explorer.exe

To jest proces odpowiedzialny za **pulpit użytkownika** i uruchamianie plików za pomocą rozszerzeń plików.

**Tylko 1** proces powinien być uruchomiony **na każdego zalogowanego użytkownika.**

Jest uruchamiany z **userinit.exe**, który powinien być zakończony, więc **żaden proces nadrzędny** nie powinien pojawić się dla tego procesu.

# Wykrywanie złośliwych procesów

- Czy działa z oczekiwaną ścieżki? (Żadne binaria Windows nie działają z lokalizacji tymczasowej)
- Czy komunikuje się z dziwnymi adresami IP?
- Sprawdź podpisy cyfrowe (artefakty Microsoftu powinny być podpisane)
- Czy jest poprawnie napisane?
- Czy działa pod oczekiwanym SID?
- Czy proces nadrzędny jest oczekiwany (jeśli w ogóle)?
- Czy procesy potomne są tymi oczekiwanymi? (żadne cmd.exe, wscript.exe, powershell.exe..?)

{{#include ../../../banners/hacktricks-training.md}}
