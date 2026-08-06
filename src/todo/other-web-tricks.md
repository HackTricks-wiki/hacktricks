# Ander Web-truuks

{{#include ../banners/hacktricks-training.md}}

### Host header

Die back-end vertrou verskeie kere op die **Host header** om sekere aksies uit te voer. Dit kan byvoorbeeld die waarde daarvan gebruik as die **domein waarheen 'n wagwoordterugstelling gestuur moet word**. Wanneer jy 'n e-pos met 'n skakel ontvang om jou wagwoord terug te stel, is die domein wat gebruik word die een wat jy in die Host header geplaas het. Dan kan jy die wagwoordterstelling van ander gebruikers versoek en die domein verander na een wat deur jou beheer word om hul wagwoordterstellingkodes te steel. [WriteUp](https://medium.com/nassec-cybersecurity-writeups/how-i-was-able-to-take-over-any-users-account-with-host-header-injection-546fff6d0f2).<sup>[[1]](#references)</sup>

> [!WARNING]
> Let daarop dat jy moontlik nie eers hoef te wag totdat die gebruiker op die wagwoordterstelling-skakel klik om die token te kry nie, aangesien **spam filters of ander tussenganger-toestelle/bots moontlik daarop sal klik om dit te ontleed**.

### Sessie-booleans

Soms, wanneer jy 'n verifikasie korrek voltooi, sal die back-end **net 'n boolean met die waarde "True" by 'n sekuriteitskenmerk van jou sessie voeg**. Daarna sal 'n ander endpoint weet of jy daardie kontrole suksesvol geslaag het.\
As jy egter **die kontrole slaag** en jou sessie daardie "True"-waarde in die sekuriteitskenmerk kry, kan jy probeer om **toegang tot ander hulpbronne te verkry** wat **van dieselfde kenmerk afhang**, maar waartoe jy **nie toestemming behoort te hê nie**. [WriteUp](https://medium.com/@ozguralp/a-less-known-attack-vector-second-order-idor-attacks-14468009781a).<sup>[[2]](#references)</sup>

### Registrasie-funksionaliteit

Probeer om as 'n reeds bestaande gebruiker te registreer. Probeer ook ekwivalente karakters gebruik (punte, baie spasies en Unicode).

### Oornamings-e-posse

Registreer 'n e-posadres, en verander die e-posadres voordat jy dit bevestig. As die nuwe bevestigingse-pos dan na die eerste geregistreerde e-posadres gestuur word, kan jy enige e-posadres oorneem. Of, as jy die tweede e-posadres kan aktiveer deur die eerste een te bevestig, kan jy ook enige rekening oorneem.

### Toegang tot interne servicedesk van maatskappye wat atlassian gebruik


{{#ref}}
https://yourcompanyname.atlassian.net/servicedesk/customer/user/login
{{#endref}}

### TRACE method

Ontwikkelaars kan vergeet om verskeie debugging-opsies in die produksie-omgewing te deaktiveer. Die HTTP `TRACE`-metode is byvoorbeeld vir diagnostiese doeleindes ontwerp. Indien dit geaktiveer is, sal die webbediener op versoeke wat die `TRACE`-metode gebruik reageer deur die presiese versoek wat ontvang is in die respons te eggo. Hierdie gedrag is dikwels onskadelik, maar lei soms tot inligtingblootstelling, soos die naam van interne authentication headers wat deur reverse proxies by versoeke gevoeg kan word.![Prent vir plasing](https://miro.medium.com/max/60/1*wDFRADTOd9Tj63xucenvAA.png?q=20)

![Prent vir plasing](https://miro.medium.com/max/1330/1*wDFRADTOd9Tj63xucenvAA.png)

## Verwysings

- [1] [How I was able to take over any user's account with Host Header Injection](https://medium.com/nassec-cybersecurity-writeups/how-i-was-able-to-take-over-any-users-account-with-host-header-injection-546fff6d0f2)
- [2] [A less known attack vector: Second Order IDOR attacks](https://medium.com/@ozguralp/a-less-known-attack-vector-second-order-idor-attacks-14468009781a)

{{#include ../banners/hacktricks-training.md}}
