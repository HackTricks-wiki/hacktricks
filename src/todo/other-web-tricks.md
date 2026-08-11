# Ander Web-truuks

{{#include ../banners/hacktricks-training.md}}

## Host header

Back ends vertrou soms op die HTTP `Host`-veld wanneer absolute skakels saamgestel word. As ’n wagwoordterugstel-e-pos ’n deur ’n aanvaller verskafde host gebruik, kan ’n aanvaller wat ’n terugstelling vir ’n slagoffer aanvra, ’n skakel wat ’n token bevat deur ’n aanvaller-beheerde domein stuur. Toets ook forwarded-host-velde, hantering van duplikaat-Host-velde en versoekteikens in absolute formaat by elke proxy-hop.<sup>[[1]](#references)</sup>

> [!WARNING]
> ’n Gebruikerklik is moontlik nie nodig nie: **e-possekuriteitskandeerders, voorskoudienste of ander tussengangers kan die aanvaller-beheerde skakel outomaties aanvra**, waardeur die reset-token bekend gemaak word.

## Session-booleans

Sommige toepassings teken ’n voltooide verifikasie as ’n boolean in die session aan en laat dan ’n ander endpoint op daardie vlag staatmaak. Nadat jy die kontrole vir een hulpbron wettig geslaag het, toets of dieselfde vlag ’n ander gebruiker, objek of workflow verkeerdelik magtig. Dit is ’n second-order authorization/state-reuse-fout, nie bloot ’n IDOR nie.<sup>[[2]](#references)</sup>

## Registration functionality

Probeer om as ’n reeds bestaande gebruiker te registreer. Probeer ook ekwivalente karakters gebruik (punte, baie spasies en Unicode).

## Email-change state confusion

Registreer ’n e-posadres en verander dit voordat jy dit bevestig. Kontroleer of die bevestiging vir die nuwe adres na die ou adres gestuur word, of of die bevestiging van die ou token die nuwe adres aktiveer. Confirmation-tokens moet aan die presiese account, pending address, doel en huidige state gekoppel wees.

## Exposed Atlassian service desks


{{#ref}}
https://yourcompanyname.atlassian.net/servicedesk/customer/user/login
{{#endref}}

## TRACE method

Die HTTP `TRACE`-metode versoek ’n loop-back van die ontvangde versoek vir diagnostiese doeleindes. RFC 9110 vereis dat ontvangers sensitiewe velde, soos credentials en cookies, uit die weerspieëlde inhoud weglaat, maar onveilige implementerings of deur tussengangers bygevoegde headers kan steeds interne versoektransformasies bekend maak. Browsers verhoed script-gegenereerde TRACE-versoeke, dus hang die historiese cross-site tracing-aanval ook af van ’n aparte manier om beskermde velde in te spuit.<sup>[[3]](#references)</sup>![Image wat ’n TRACE-antwoord wys](https://miro.medium.com/max/60/1*wDFRADTOd9Tj63xucenvAA.png?q=20)

![Beeld vir plasing](https://miro.medium.com/max/1330/1*wDFRADTOd9Tj63xucenvAA.png)

## References

- [1] [Hoe ek enige gebruiker se account met Host Header Injection kon oorneem](https://medium.com/nassec-cybersecurity-writeups/how-i-was-able-to-take-over-any-users-account-with-host-header-injection-546fff6d0f2)
- [2] [’n Minder bekende aanvalsvector: Second Order IDOR attacks](https://medium.com/@ozguralp/a-less-known-attack-vector-second-order-idor-attacks-14468009781a)
- [3] [RFC 9110, afdeling 9.3.8 — TRACE](https://www.rfc-editor.org/rfc/rfc9110.html#name-trace)
{{#include ../banners/hacktricks-training.md}}
