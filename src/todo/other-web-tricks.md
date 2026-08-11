# Mbinu Nyingine za Web

{{#include ../banners/hacktricks-training.md}}

## Host header

Back ends wakati mwingine huamini sehemu ya HTTP `Host` wakati wa kuunda links kamili. Ikiwa email ya kuweka upya password inatumia host iliyotolewa na attacker, kuomba reset kwa victim kunaweza kutuma link yenye token kupitia domain inayodhibitiwa na attacker. Pia test fields za forwarded-host, ushughulikiaji wa Host zinazorudiwa, na request targets za absolute-form katika kila hatua ya proxy.<sup>[[1]](#references)</sup>

> [!WARNING]
> Huenda click ya user isiwe lazima: **mail security scanners, preview services, au intermediaries wengine wanaweza kuomba kiotomatiki link inayodhibitiwa na attacker**, na hivyo kufichua reset token.

## Session booleans

Baadhi ya applications huhifadhi verification iliyokamilika kama boolean katika session, kisha huruhusu endpoint tofauti kutegemea flag hiyo. Baada ya kupita kihalali check ya resource moja, test ikiwa flag hiyo hiyo inaruhusu kimakosa user, object, au workflow tofauti. Hili ni kosa la second-order authorization/state-reuse, si IDOR tu.<sup>[[2]](#references)</sup>

## Registration functionality

Jaribu kujisajili kama user ambaye tayari yupo. Pia jaribu kutumia characters zinazolingana (dots, spaces nyingi na Unicode).

## Email-change state confusion

Sajili email address kisha ibadilishe kabla ya ku-confirm. Kagua ikiwa confirmation ya address mpya inatumwa kwa address ya zamani, au ikiwa ku-confirm token ya zamani kuna-activate address mpya. Confirmation tokens lazima ziunganishwe na account halisi, address inayosubiri, purpose, na state ya sasa.

## Atlassian service desks zilizo wazi


{{#ref}}
https://yourcompanyname.atlassian.net/servicedesk/customer/user/login
{{#endref}}

## TRACE method

HTTP `TRACE` method huomba loop-back ya request iliyopokelewa kwa ajili ya diagnostics. RFC 9110 inawahitaji recipients kuondoa fields nyeti kama credentials na cookies kutoka kwenye content iliyo-reflectiwa, lakini implementations zisizo salama au headers zilizoongezwa na intermediaries bado zinaweza kufichua mabadiliko ya ndani ya request. Browsers huzuia TRACE requests zinazozalishwa na script, hivyo shambulio la kihistoria la cross-site tracing pia hutegemea njia tofauti ya ku-inject fields zilizolindwa.<sup>[[3]](#references)</sup>![Picha inayoonyesha TRACE response](https://miro.medium.com/max/60/1*wDFRADTOd9Tj63xucenvAA.png?q=20)

![Picha ya post](https://miro.medium.com/max/1330/1*wDFRADTOd9Tj63xucenvAA.png)

## References

- [1] [Jinsi nilivyoweza kuchukua udhibiti wa account ya user yeyote kwa kutumia Host Header Injection](https://medium.com/nassec-cybersecurity-writeups/how-i-was-able-to-take-over-any-users-account-with-host-header-injection-546fff6d0f2)
- [2] [Attack vector isiyojulikana sana: Second Order IDOR attacks](https://medium.com/@ozguralp/a-less-known-attack-vector-second-order-idor-attacks-14468009781a)
- [3] [RFC 9110, section 9.3.8 — TRACE](https://www.rfc-editor.org/rfc/rfc9110.html#name-trace)
{{#include ../banners/hacktricks-training.md}}
