# TimeRoasting

{{#include /banners/hacktricks-training.md}}

timeRoasting, die hoofrede is die verouderde verifikasiesisteem wat deur Microsoft in sy uitbreiding na NTP-bedieners gelaat is, bekend as MS-SNTP. In hierdie sisteem kan kliënte enige rekenaarrekening se Relative Identifier (RID) direk gebruik, en die domeinbeheerder sal die rekenaarrekening se NTLM-hash (gegenereer deur MD4) as die sleutel gebruik om die **Message Authentication Code (MAC)** van die responspakket te genereer.

Aanvallers kan hierdie sisteem benut om ekwivalente hashwaardes van arbitrêre rekenaarrekeninge sonder verifikasie te verkry. Duidelik kan ons gereedskap soos Hashcat gebruik vir brute-forcing.

Die spesifieke sisteem kan in afdeling 3.1.5.1 "Authentication Request Behavior" van die [amptelike Windows-dokumentasie vir MS-SNTP-protokol](https://winprotocoldoc.z19.web.core.windows.net/MS-SNTP/%5bMS-SNTP%5d.pdf) gesien word.

In die dokument dek afdeling 3.1.5.1 Authentication Request Behavior.
![](../../images/Pasted%20image%2020250709114508.png)
Dit kan gesien word dat wanneer die ExtendedAuthenticatorSupported ADM-element op `false` gestel is, die oorspronklike Markdown-formaat behou word.

>Gehaal uit die oorspronklike artikel：
>>As die ExtendedAuthenticatorSupported ADM-element vals is, moet die kliënt 'n Client NTP Request-boodskap opstel. Die lengte van die Client NTP Request-boodskap is 68 bytes. Die kliënt stel die Authenticator-veld van die Client NTP Request-boodskap in soos beskryf in afdeling 2.2.1, deur die minste betekenisvolle 31 bits van die RID-waarde in die minste betekenisvolle 31 bits van die Key Identifier-subveld van die authenticator te skryf, en dan die Key Selector-waarde in die mees betekenisvolle bit van die Key Identifier-subveld te skryf.

In dokumentafdeling 4 Protokol Voorbeelde punt 3

>Gehaal uit die oorspronklike artikel：
>>3. Na ontvangs van die versoek, verifieer die bediener dat die ontvangde boodskapgrootte 68 bytes is. As dit nie is nie, laat die bediener of die versoek val (as die boodskapgrootte nie 48 bytes gelyk is nie) of hanteer dit as 'n nie-geverifieerde versoek (as die boodskapgrootte 48 bytes is). Aannemende dat die ontvangde boodskapgrootte 68 bytes is, onttrek die bediener die RID uit die ontvangde boodskap. Die bediener gebruik dit om die NetrLogonComputeServerDigest-metode aan te roep (soos gespesifiseer in [MS-NRPC] afdeling 3.5.4.8.2) om die crypto-checksums te bereken en die crypto-checksum te kies op grond van die mees betekenisvolle bit van die Key Identifier-subveld van die ontvangde boodskap, soos gespesifiseer in afdeling 3.2.5. Die bediener stuur dan 'n respons aan die kliënt, en stel die Key Identifier-veld op 0 en die Crypto-Checksum-veld op die berekende crypto-checksum.

Volgens die beskrywing in die Microsoft amptelike dokument hierbo, hoef gebruikers nie enige verifikasie te hê nie; hulle moet net die RID invul om 'n versoek te begin, en dan kan hulle die kriptografiese checksum verkry. Die kriptografiese checksum word in afdeling 3.2.5.1.1 van die dokument verduidelik.

>Gehaal uit die oorspronklike artikel：
>>Die bediener haal die RID uit die minste betekenisvolle 31 bits van die Key Identifier-subveld van die Authenticator-veld van die Client NTP Request-boodskap. Die bediener gebruik die NetrLogonComputeServerDigest-metode (soos gespesifiseer in [MS-NRPC] afdeling 3.5.4.8.2) om crypto-checksums te bereken met die volgende invoerparameters:
>>>![](../../images/Pasted%20image%2020250709115757.png)

Die kriptografiese checksum word bereken met MD5, en die spesifieke proses kan in die inhoud van die dokument verwys word. Dit gee ons die geleentheid om 'n roasting-aanval uit te voer.

## hoe om aan te val

Citaat na https://swisskyrepo.github.io/InternalAllTheThings/active-directory/ad-roasting-timeroasting/

[SecuraBV/Timeroast](https://github.com/SecuraBV/Timeroast) - Timeroasting-skripte deur Tom Tervoort
```
sudo ./timeroast.py 10.0.0.42 | tee ntp-hashes.txt
hashcat -m 31300 ntp-hashes.txt
```
{{#include /banners/hacktricks-training.md}}
