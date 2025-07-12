# TimeRoasting

{{#include ../../banners/hacktricks-training.md}}

timeRoasting, sababu kuu ni mfumo wa uthibitishaji wa zamani uliowachwa na Microsoft katika nyongeza yake kwa seva za NTP, inayojulikana kama MS-SNTP. Katika mfumo huu, wateja wanaweza kutumia moja kwa moja Kitambulisho cha Uhusiano (RID) cha akaunti yoyote ya kompyuta, na kidhibiti cha eneo litatumia hash ya NTLM ya akaunti ya kompyuta (iliyoundwa na MD4) kama ufunguo wa kuunda **Nambari ya Uthibitishaji wa Ujumbe (MAC)** ya pakiti ya majibu.

Wavamizi wanaweza kutumia mfumo huu kupata thamani sawa za hash za akaunti za kompyuta bila uthibitishaji. Kwa wazi, tunaweza kutumia zana kama Hashcat kwa ajili ya brute-forcing.

Mfumo maalum unaweza kuonekana katika sehemu 3.1.5.1 "Tabia ya Ombi la Uthibitishaji" ya [nyaraka rasmi za Windows kwa itifaki ya MS-SNTP](https://winprotocoldoc.z19.web.core.windows.net/MS-SNTP/%5bMS-SNTP%5d.pdf).

Katika hati hiyo, sehemu 3.1.5.1 inashughulikia Tabia ya Ombi la Uthibitishaji.
![](../../images/Pasted%20image%2020250709114508.png)
Inaweza kuonekana kwamba wakati kipengele cha ExtendedAuthenticatorSupported ADM kimewekwa kuwa `false`, muundo wa asili wa Markdown unahifadhiwa.

>Quoted in the original article：
>>Ikiwa kipengele cha ExtendedAuthenticatorSupported ADM ni false, mteja LAZIMA aunde ujumbe wa Ombi la NTP la Mteja. Urefu wa ujumbe wa Ombi la NTP la Mteja ni byte 68. Mteja anapanga uwanja wa Authenticator wa ujumbe wa Ombi la NTP la Mteja kama ilivyoelezwa katika sehemu 2.2.1, akiandika bits 31 za chini za thamani ya RID katika bits 31 za chini za uwanja wa Kitambulisho cha Ufunguo wa authenticator, na kisha akiandika thamani ya Mchaguzi wa Ufunguzi katika bit ya juu zaidi ya uwanja wa Kitambulisho cha Ufunguzi.

Katika sehemu ya hati 4 Mifano ya Itifaki pointi 3

>Quoted in the original article：
>>3. Baada ya kupokea ombi, seva inathibitisha kwamba saizi ya ujumbe ulipokelewa ni byte 68. Ikiwa si hivyo, seva inatupa ombi (ikiwa saizi ya ujumbe haiwiani na byte 48) au inachukulia kama ombi lisilo na uthibitisho (ikiwa saizi ya ujumbe ni byte 48). Ikiwa tunadhania kwamba saizi ya ujumbe ulipokelewa ni byte 68, seva inachukua RID kutoka kwa ujumbe ulipokelewa. Seva inaitumia kuita njia ya NetrLogonComputeServerDigest (kama ilivyoainishwa katika [MS-NRPC] sehemu 3.5.4.8.2) ili kuhesabu crypto-checksums na kuchagua crypto-checksum kulingana na bit ya juu zaidi ya uwanja wa Kitambulisho cha Ufunguzi kutoka kwa ujumbe ulipokelewa, kama ilivyoainishwa katika sehemu 3.2.5. Seva kisha inatuma jibu kwa mteja, ikipanga uwanja wa Kitambulisho cha Ufunguzi kuwa 0 na uwanja wa Crypto-Checksum kuwa crypto-checksum iliyohesabiwa.

Kulingana na maelezo katika hati rasmi ya Microsoft hapo juu, watumiaji hawahitaji uthibitishaji wowote; wanahitaji tu kujaza RID ili kuanzisha ombi, na kisha wanaweza kupata crypto-checksum. Crypto-checksum inaelezewa katika sehemu 3.2.5.1.1 ya hati.

>Quoted in the original article：
>>Seva inapata RID kutoka bits 31 za chini za uwanja wa Kitambulisho cha Ufunguzi wa ujumbe wa Ombi la NTP la Mteja. Seva inatumia njia ya NetrLogonComputeServerDigest (kama ilivyoainishwa katika [MS-NRPC] sehemu 3.5.4.8.2) ili kuhesabu crypto-checksums kwa vigezo vifuatavyo:
>>>![](../../images/Pasted%20image%2020250709115757.png)

Crypto-checksum inahesabiwa kwa kutumia MD5, na mchakato maalum unaweza kutazamwa katika maudhui ya hati. Hii inatupa fursa ya kufanya shambulio la roasting.

## jinsi ya kushambulia

Quote to https://swisskyrepo.github.io/InternalAllTheThings/active-directory/ad-roasting-timeroasting/

[SecuraBV/Timeroast](https://github.com/SecuraBV/Timeroast) - Timeroasting scripts by Tom Tervoort
```
sudo ./timeroast.py 10.0.0.42 | tee ntp-hashes.txt
hashcat -m 31300 ntp-hashes.txt
```
{{#include ../../banners/hacktricks-training.md}}
