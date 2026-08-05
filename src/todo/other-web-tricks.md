# Ander Web-truuks

{{#include ../banners/hacktricks-training.md}}

### Host header

Die back-end vertrou verskeie kere op die **Host header** om sekere aksies uit te voer. Dit kan byvoorbeeld die waarde daarvan as die **domein gebruik waarheen 'n wagwoordterugstelling gestuur moet word**. Wanneer jy 'n e-pos met 'n skakel ontvang om jou wagwoord terug te stel, is die domein wat gebruik word die een wat jy in die Host header geplaas het. Vervolgens kan jy die wagwoordterugstelling van ander gebruikers aanvra en die domein verander na een wat deur jou beheer word om hul wagwoordterstellingkodes te steel. [WriteUp](https://medium.com/nassec-cybersecurity-writeups/how-i-was-able-to-take-over-any-users-account-with-host-header-injection-546fff6d0f2).<sup>[[1]](#references)</sup>

> [!WARNING]
> Let daarop dat dit moontlik is dat jy nie eers hoef te wag totdat die gebruiker op die wagwoordterstelskakel klik om die token te kry nie, aangesien **spamfilters of ander tussengangerstoestelle/-bots dalk daarop sal klik om dit te ontleed**.

### Session booleans

Soms, wanneer jy 'n verifikasie korrek voltooi, sal die back-end **net 'n boolean met die waarde "True" by 'n sekuriteitskenmerk van jou sessie voeg**. Dan sal 'n ander endpoint weet of jy daardie kontrole suksesvol geslaag het.\
As jy egter **die kontrole slaag** en jou sessie daardie "True"-waarde in die sekuriteitskenmerk kry, kan jy probeer om **toegang tot ander hulpbronne te verkry** wat **van dieselfde kenmerk afhanklik is**, maar waartoe jy **nie toestemming behoort te hê nie**. [WriteUp](https://medium.com/@ozguralp/a-less-known-attack-vector-second-order-idor-attacks-14468009781a).<sup>[[2]](#references)</sup>

### Register functionality

Probeer om as 'n gebruiker wat reeds bestaan te registreer. Probeer ook ekwivalente karakters gebruik (punte, baie spasies en Unicode).

### Takeover emails

Registreer 'n e-posadres en verander dit voordat jy dit bevestig. As die nuwe bevestigings-e-pos dan na die eerste geregistreerde e-posadres gestuur word, kan jy enige e-posadres oorneem. Of, as jy die tweede e-posadres kan aktiveer deur die eerste een te bevestig, kan jy ook enige rekening oorneem.

### Toegang tot maatskappye se interne servicedesk met atlassian


{{#ref}}
https://yourcompanyname.atlassian.net/servicedesk/customer/user/login
{{#endref}}

### TRACE method

Ontwikkelaars vergeet dalk om verskeie debugging-opsies in die produksie-omgewing te deaktiveer. Die HTTP `TRACE`-metode is byvoorbeeld vir diagnostiese doeleindes ontwerp. Indien dit geaktiveer is, sal die webbediener op versoeke reageer wat die `TRACE`-metode gebruik deur die presiese versoek wat ontvang is in die respons terug te eggo. Hierdie gedrag is dikwels onskadelik, maar lei soms tot inligtingsblootstelling, soos die naam van interne authentication headers wat deur reverse proxies by versoeke gevoeg kan word.![Beeld vir plasing](https://miro.medium.com/max/60/1*wDFRADTOd9Tj63xucenvAA.png?q=20)

![Beeld vir plasing](https://miro.medium.com/max/1330/1*wDFRADTOd9Tj63xucenvAA.png)

## Verwysings

- [1] [How I was able to take over any user's account with Host Header injection](https://medium.com/nassec-cybersecurity-writeups/how-i-was-able-to-take-over-any-users-account-with-host-header-injection-546fff6d0f2)
- [2] [A less known attack vector: Second order IDOR attacks](https://medium.com/@ozguralp/a-less-known-attack-vector-second-order-idor-attacks-14468009781a)

{{#include ../banners/hacktricks-training.md}}
