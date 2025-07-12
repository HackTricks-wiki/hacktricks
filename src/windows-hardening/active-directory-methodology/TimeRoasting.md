# TimeRoasting

{{#include ../../banners/hacktricks-training.md}}

timeRoasting, die Hauptursache ist der veraltete Authentifizierungsmechanismus, den Microsoft in seiner Erweiterung für NTP-Server, bekannt als MS-SNTP, hinterlassen hat. In diesem Mechanismus können Clients die Relative Identifier (RID) eines beliebigen Computeraccounts direkt verwenden, und der Domänencontroller verwendet den NTLM-Hash des Computeraccounts (generiert durch MD4) als Schlüssel, um den **Message Authentication Code (MAC)** des Antwortpakets zu generieren.

Angreifer können diesen Mechanismus ausnutzen, um äquivalente Hash-Werte beliebiger Computeraccounts ohne Authentifizierung zu erhalten. Offensichtlich können wir Tools wie Hashcat zum Brute-Forcing verwenden.

Der spezifische Mechanismus kann in Abschnitt 3.1.5.1 "Authentifizierungsanforderungsverhalten" der [offiziellen Windows-Dokumentation für das MS-SNTP-Protokoll](https://winprotocoldoc.z19.web.core.windows.net/MS-SNTP/%5bMS-SNTP%5d.pdf) eingesehen werden.

Im Dokument behandelt Abschnitt 3.1.5.1 das Authentifizierungsanforderungsverhalten.
![](../../images/Pasted%20image%2020250709114508.png)
Es ist zu sehen, dass, wenn das ExtendedAuthenticatorSupported ADM-Element auf `false` gesetzt ist, das ursprüngliche Markdown-Format beibehalten wird.

> Zitiert im Originalartikel：
>> Wenn das ExtendedAuthenticatorSupported ADM-Element false ist, MUSS der Client eine Client NTP-Anforderungsnachricht konstruieren. Die Länge der Client NTP-Anforderungsnachricht beträgt 68 Bytes. Der Client setzt das Authenticator-Feld der Client NTP-Anforderungsnachricht wie in Abschnitt 2.2.1 beschrieben, indem er die am wenigsten signifikanten 31 Bits des RID-Werts in die am wenigsten signifikanten 31 Bits des Key Identifier-Teilfelds des Authenticators schreibt und dann den Key Selector-Wert in das am meisten signifikante Bit des Key Identifier-Teilfelds schreibt.

Im Dokument Abschnitt 4 Protokollbeispiele Punkt 3

> Zitiert im Originalartikel：
>> 3. Nach Erhalt der Anfrage überprüft der Server, ob die empfangene Nachrichtenlänge 68 Bytes beträgt. Wenn dies nicht der Fall ist, verwirft der Server entweder die Anfrage (wenn die Nachrichtenlänge nicht 48 Bytes beträgt) oder behandelt sie als nicht authentifizierte Anfrage (wenn die Nachrichtenlänge 48 Bytes beträgt). Vorausgesetzt, die empfangene Nachrichtenlänge beträgt 68 Bytes, extrahiert der Server die RID aus der empfangenen Nachricht. Der Server verwendet sie, um die Methode NetrLogonComputeServerDigest (wie in [MS-NRPC] Abschnitt 3.5.4.8.2 angegeben) aufzurufen, um die Krypto-Prüfziffern zu berechnen und die Krypto-Prüfziffer basierend auf dem am meisten signifikanten Bit des Key Identifier-Teilfelds aus der empfangenen Nachricht auszuwählen, wie in Abschnitt 3.2.5 angegeben. Der Server sendet dann eine Antwort an den Client, wobei das Key Identifier-Feld auf 0 und das Crypto-Checksum-Feld auf die berechnete Krypto-Prüfziffer gesetzt wird.

Laut der Beschreibung im obigen offiziellen Microsoft-Dokument benötigen Benutzer keine Authentifizierung; sie müssen nur die RID ausfüllen, um eine Anfrage zu initiieren, und können dann die kryptografische Prüfziffer erhalten. Die kryptografische Prüfziffer wird in Abschnitt 3.2.5.1.1 des Dokuments erklärt.

> Zitiert im Originalartikel：
>> Der Server ruft die RID aus den am wenigsten signifikanten 31 Bits des Key Identifier-Teilfelds des Authenticator-Felds der Client NTP-Anforderungsnachricht ab. Der Server verwendet die Methode NetrLogonComputeServerDigest (wie in [MS-NRPC] Abschnitt 3.5.4.8.2 angegeben), um Krypto-Prüfziffern mit den folgenden Eingabeparametern zu berechnen:
>>>![](../../images/Pasted%20image%2020250709115757.png)

Die kryptografische Prüfziffer wird mit MD5 berechnet, und der spezifische Prozess kann im Inhalt des Dokuments nachgelesen werden. Dies gibt uns die Möglichkeit, einen Roasting-Angriff durchzuführen.

## wie man angreift

Zitat zu https://swisskyrepo.github.io/InternalAllTheThings/active-directory/ad-roasting-timeroasting/

[SecuraBV/Timeroast](https://github.com/SecuraBV/Timeroast) - Timeroasting-Skripte von Tom Tervoort
```
sudo ./timeroast.py 10.0.0.42 | tee ntp-hashes.txt
hashcat -m 31300 ntp-hashes.txt
```
{{#include ../../banners/hacktricks-training.md}}
