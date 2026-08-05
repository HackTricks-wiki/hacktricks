# Mbinu Nyingine za Web

{{#include ../banners/hacktricks-training.md}}

### Host header

Mara kadhaa back-end huamini **Host header** kutekeleza baadhi ya vitendo. Kwa mfano, inaweza kutumia thamani yake kama **domain ya kutuma password reset**. Kwa hiyo unapopokea barua pepe yenye kiungo cha kuweka upya password yako, domain inayotumika ni ile uliyoweka kwenye Host header.Kisha, unaweza kuomba password reset ya watumiaji wengine na kubadilisha domain iwe ile unayodhibiti ili kuiba misimbo yao ya password reset. [WriteUp](https://medium.com/nassec-cybersecurity-writeups/how-i-was-able-to-take-over-any-users-account-with-host-header-injection-546fff6d0f2).<sup>[[1]](#references)</sup>

> [!WARNING]
> Kumbuka kwamba huenda usihitaji hata kusubiri mtumiaji kubofya kiungo cha kuweka upya password ili kupata token, kwa sababu huenda hata **spam filters au vifaa/bots vingine vya kati vikakibofya ili kukichanganua**.

### Session booleans

Wakati mwingine unapokamilisha verification fulani kwa usahihi, back-end **huongeza tu boolean yenye thamani ya "True" kwenye security attribute ya session yako**. Kisha, endpoint tofauti itajua kama umefaulu kupita ukaguzi huo.\
Hata hivyo, uki **faulu ukaguzi** na session yako ikapewa thamani hiyo ya "True" kwenye security attribute, unaweza kujaribu **kufikia resources nyingine** ambazo **hutegemea attribute hiyo hiyo**, lakini **hupaswi kuwa na permissions** za kuzifikia. [WriteUp](https://medium.com/@ozguralp/a-less-known-attack-vector-second-order-idor-attacks-14468009781a).<sup>[[2]](#references)</sup>

### Functionality ya usajili

Jaribu kujisajili kama mtumiaji ambaye tayari yupo. Pia jaribu kutumia characters zenye maana sawa (dots, spaces nyingi na Unicode).

### Emails za takeover

Sajili email, kabla ya kuithibitisha badilisha email hiyo, kisha, ikiwa email mpya ya confirmation itatumwa kwenye email ya kwanza iliyosajiliwa, unaweza kufanya takeover ya email yoyote. Au ikiwa unaweza kuwezesha email ya pili kwa kuthibitisha ya kwanza, unaweza pia kufanya takeover ya account yoyote.

### Kufikia Internal servicedesk ya companies zinazotumia atlassian


{{#ref}}
https://yourcompanyname.atlassian.net/servicedesk/customer/user/login
{{#endref}}

### TRACE method

Developers wanaweza kusahau kuzima options mbalimbali za debugging kwenye production environment. Kwa mfano, HTTP `TRACE` method imeundwa kwa madhumuni ya diagnostic. Ikiwa imewezeshwa, web server itajibu requests zinazotumia `TRACE` method kwa kuonyesha kwenye response request halisi iliyopokelewa. Tabia hii mara nyingi haina madhara, lakini wakati mwingine husababisha information disclosure, kama vile jina la internal authentication headers ambazo zinaweza kuongezwa kwenye requests na reverse proxies.![Picha ya post](https://miro.medium.com/max/60/1*wDFRADTOd9Tj63xucenvAA.png?q=20)

![Picha ya post](https://miro.medium.com/max/1330/1*wDFRADTOd9Tj63xucenvAA.png)

## References

- [1] [How I was able to take over any user's account with Host Header injection](https://medium.com/nassec-cybersecurity-writeups/how-i-was-able-to-take-over-any-users-account-with-host-header-injection-546fff6d0f2)
- [2] [A less known attack vector: Second order IDOR attacks](https://medium.com/@ozguralp/a-less-known-attack-vector-second-order-idor-attacks-14468009781a)

{{#include ../banners/hacktricks-training.md}}
