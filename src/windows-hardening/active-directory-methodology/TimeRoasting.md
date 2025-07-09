## TimeRoasting

timeRoasting, główną przyczyną jest przestarzały mechanizm uwierzytelniania pozostawiony przez Microsoft w jego rozszerzeniu do serwerów NTP, znanym jako MS-SNTP. W tym mechanizmie klienci mogą bezpośrednio używać dowolnego identyfikatora względnego (RID) konta komputerowego, a kontroler domeny użyje hasha NTLM konta komputerowego (generowanego przez MD4) jako klucza do wygenerowania **Message Authentication Code (MAC)** pakietu odpowiedzi.

Atakujący mogą wykorzystać ten mechanizm do uzyskania równoważnych wartości hash dowolnych kont komputerowych bez uwierzytelnienia. Oczywiście, możemy użyć narzędzi takich jak Hashcat do łamania haseł.

Specyficzny mechanizm można zobaczyć w sekcji 3.1.5.1 "Zachowanie żądania uwierzytelnienia" w [oficjalnej dokumentacji Windows dla protokołu MS-SNTP](https://winprotocoldoc.z19.web.core.windows.net/MS-SNTP/%5bMS-SNTP%5d.pdf).

W dokumencie sekcja 3.1.5.1 dotyczy Zachowania żądania uwierzytelnienia.
![](../../images/Pasted%20image%2020250709114508.png)
Można zauważyć, że gdy element ADM ExtendedAuthenticatorSupported jest ustawiony na `false`, oryginalny format Markdown jest zachowany.

> Cytat z oryginalnego artykułu：
>> Jeśli element ADM ExtendedAuthenticatorSupported jest fałszywy, klient MUSI skonstruować wiadomość żądania NTP klienta. Długość wiadomości żądania NTP klienta wynosi 68 bajtów. Klient ustawia pole Authenticator wiadomości żądania NTP klienta, jak opisano w sekcji 2.2.1, zapisując 31 najmniej znaczących bitów wartości RID w 31 najmniej znaczących bitach podpola identyfikatora klucza, a następnie zapisując wartość selektora klucza w najbardziej znaczącym bicie podpola identyfikatora klucza.

W sekcji 4 dokumentu Przykłady protokołu punkt 3

> Cytat z oryginalnego artykułu：
>> 3. Po otrzymaniu żądania serwer weryfikuje, że rozmiar otrzymanej wiadomości wynosi 68 bajtów. Jeśli nie, serwer albo odrzuca żądanie (jeśli rozmiar wiadomości nie wynosi 48 bajtów), albo traktuje je jako żądanie nieautoryzowane (jeśli rozmiar wiadomości wynosi 48 bajtów). Zakładając, że rozmiar otrzymanej wiadomości wynosi 68 bajtów, serwer wyodrębnia RID z otrzymanej wiadomości. Serwer używa go do wywołania metody NetrLogonComputeServerDigest (jak określono w [MS-NRPC] sekcja 3.5.4.8.2), aby obliczyć sumy kontrolne kryptograficzne i wybrać sumę kontrolną kryptograficzną na podstawie najbardziej znaczącego bitu podpola identyfikatora klucza z otrzymanej wiadomości, jak określono w sekcji 3.2.5. Serwer następnie wysyła odpowiedź do klienta, ustawiając pole identyfikatora klucza na 0, a pole sumy kontrolnej kryptograficznej na obliczoną sumę kontrolną kryptograficzną.

Zgodnie z opisem w powyższym oficjalnym dokumencie Microsoft, użytkownicy nie potrzebują żadnego uwierzytelnienia; muszą tylko wypełnić RID, aby zainicjować żądanie, a następnie mogą uzyskać sumę kontrolną kryptograficzną. Suma kontrolna kryptograficzna jest wyjaśniona w sekcji 3.2.5.1.1 dokumentu.

> Cytat z oryginalnego artykułu：
>> Serwer pobiera RID z 31 najmniej znaczących bitów podpola identyfikatora klucza pola Authenticator wiadomości żądania NTP klienta. Serwer używa metody NetrLogonComputeServerDigest (jak określono w [MS-NRPC] sekcja 3.5.4.8.2), aby obliczyć sumy kontrolne kryptograficzne z następującymi parametrami wejściowymi:
>>>![](../../images/Pasted%20image%2020250709115757.png)

Suma kontrolna kryptograficzna jest obliczana przy użyciu MD5, a konkretny proces można znaleźć w treści dokumentu. Daje nam to możliwość przeprowadzenia ataku roasting.

## jak zaatakować

Cytat do https://swisskyrepo.github.io/InternalAllTheThings/active-directory/ad-roasting-timeroasting/

[SecuraBV/Timeroast](https://github.com/SecuraBV/Timeroast) - skrypty Timeroasting autorstwa Toma Tervoorta
```
sudo ./timeroast.py 10.0.0.42 | tee ntp-hashes.txt
hashcat -m 31300 ntp-hashes.txt
