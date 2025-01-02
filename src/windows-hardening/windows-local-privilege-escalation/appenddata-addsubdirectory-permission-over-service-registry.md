{{#include ../../banners/hacktricks-training.md}}

**Oryginalny post to** [**https://itm4n.github.io/windows-registry-rpceptmapper-eop/**](https://itm4n.github.io/windows-registry-rpceptmapper-eop/)

## Podsumowanie

Znaleziono dwa klucze rejestru, które były zapisywalne przez bieżącego użytkownika:

- **`HKLM\SYSTEM\CurrentControlSet\Services\Dnscache`**
- **`HKLM\SYSTEM\CurrentControlSet\Services\RpcEptMapper`**

Zasugerowano sprawdzenie uprawnień usługi **RpcEptMapper** za pomocą **regedit GUI**, szczególnie zakładki **Efektywne uprawnienia** w oknie **Zaawansowane ustawienia zabezpieczeń**. Takie podejście umożliwia ocenę przyznanych uprawnień dla konkretnych użytkowników lub grup bez potrzeby badania każdego wpisu kontroli dostępu (ACE) z osobna.

Zrzut ekranu pokazał uprawnienia przypisane użytkownikowi o niskich uprawnieniach, wśród których wyróżniało się uprawnienie **Utwórz podklucz**. To uprawnienie, znane również jako **AppendData/AddSubdirectory**, odpowiada ustaleniom skryptu.

Zauważono niemożność bezpośredniej modyfikacji niektórych wartości, ale możliwość tworzenia nowych podkluczy. Przykładem była próba zmiany wartości **ImagePath**, która zakończyła się komunikatem o odmowie dostępu.

Pomimo tych ograniczeń, zidentyfikowano potencjał do eskalacji uprawnień poprzez możliwość wykorzystania podklucza **Performance** w strukturze rejestru usługi **RpcEptMapper**, podklucza, który nie jest obecny domyślnie. Może to umożliwić rejestrację DLL i monitorowanie wydajności.

Skonsultowano dokumentację na temat podklucza **Performance** i jego wykorzystania do monitorowania wydajności, co doprowadziło do opracowania dowodu koncepcji DLL. Ta DLL, demonstrująca implementację funkcji **OpenPerfData**, **CollectPerfData** i **ClosePerfData**, została przetestowana za pomocą **rundll32**, potwierdzając jej operacyjną skuteczność.

Celem było zmuszenie **usługi RPC Endpoint Mapper** do załadowania stworzonych DLL do wydajności. Obserwacje ujawniły, że wykonywanie zapytań klas WMI związanych z danymi wydajnościowymi za pomocą PowerShell skutkowało utworzeniem pliku dziennika, co umożliwiło wykonanie dowolnego kodu w kontekście **LOCAL SYSTEM**, przyznając tym samym podwyższone uprawnienia.

Podkreślono trwałość i potencjalne implikacje tej luki, zwracając uwagę na jej znaczenie dla strategii poeksploatacyjnych, ruchu lateralnego oraz unikania systemów antywirusowych/EDR.

Chociaż luka została początkowo ujawniona przypadkowo za pomocą skryptu, podkreślono, że jej wykorzystanie jest ograniczone do przestarzałych wersji Windows (np. **Windows 7 / Server 2008 R2**) i wymaga dostępu lokalnego.

{{#include ../../banners/hacktricks-training.md}}
