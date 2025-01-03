# PsExec/Winexec/ScExec

{{#include ../../banners/hacktricks-training.md}}

## Jak to działa

Proces jest opisany w poniższych krokach, ilustrując, jak binaria usług są manipulowane w celu osiągnięcia zdalnego wykonania na docelowej maszynie za pośrednictwem SMB:

1. **Kopiowanie binariów usługi do udziału ADMIN$ przez SMB** jest wykonywane.
2. **Tworzenie usługi na zdalnej maszynie** odbywa się poprzez wskazanie na binarium.
3. Usługa jest **uruchamiana zdalnie**.
4. Po zakończeniu usługa jest **zatrzymywana, a binarium jest usuwane**.

### **Proces ręcznego uruchamiania PsExec**

Zakładając, że istnieje ładunek wykonywalny (stworzony za pomocą msfvenom i z obfuskowanym użyciem Veil w celu uniknięcia wykrycia przez oprogramowanie antywirusowe), nazwany 'met8888.exe', reprezentujący ładunek meterpreter reverse_http, podejmowane są następujące kroki:

- **Kopiowanie binarium**: Wykonywalny plik jest kopiowany do udziału ADMIN$ z wiersza poleceń, chociaż może być umieszczony w dowolnym miejscu w systemie plików, aby pozostać ukrytym.
- **Tworzenie usługi**: Wykorzystując polecenie Windows `sc`, które umożliwia zapytania, tworzenie i usuwanie usług Windows zdalnie, tworzona jest usługa o nazwie "meterpreter", wskazująca na przesłane binarium.
- **Uruchamianie usługi**: Ostatni krok polega na uruchomieniu usługi, co prawdopodobnie spowoduje błąd "time-out" z powodu tego, że binarium nie jest prawdziwym binarium usługi i nie zwraca oczekiwanego kodu odpowiedzi. Ten błąd jest nieistotny, ponieważ głównym celem jest wykonanie binarium.

Obserwacja nasłuchiwacza Metasploit ujawni, że sesja została pomyślnie zainicjowana.

[Dowiedz się więcej o poleceniu `sc`](https://technet.microsoft.com/en-us/library/bb490995.aspx).

Znajdź bardziej szczegółowe kroki w: [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

**Możesz również użyć binarium Windows Sysinternals PsExec.exe:**

![](<../../images/image (928).png>)

Możesz również użyć [**SharpLateral**](https://github.com/mertdas/SharpLateral):
```bash
SharpLateral.exe redexec HOSTNAME C:\\Users\\Administrator\\Desktop\\malware.exe.exe malware.exe ServiceName
```
{{#include ../../banners/hacktricks-training.md}}
