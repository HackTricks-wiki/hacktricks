# Mbinu Nyingine za Web

{{#include ../banners/hacktricks-training.md}}

### Host header

Mara kadhaa back-end huamini **Host header** ili kutekeleza vitendo fulani. Kwa mfano, inaweza kutumia thamani yake kama **domain ya kutuma password reset**. Kwa hiyo, unapopokea email yenye link ya kuweka upya password yako, domain inayotumika ni ile uliyoweka kwenye Host header. Kisha, unaweza kuomba password reset ya users wengine na kubadilisha domain iwe ile unayoidhibiti ili kuiba misimbo yao ya password reset. [WriteUp](https://medium.com/nassec-cybersecurity-writeups/how-i-was-able-to-take-over-any-users-account-with-host-header-injection-546fff6d0f2).<sup>[[1]](#references)</sup>

> [!WARNING]
> Kumbuka kwamba huenda usihitaji hata kusubiri user abonyeze link ya password reset ili kupata token, kwa sababu huenda hata **spam filters au vifaa/bots wengine wa kati wakaibofya ili kuichanganua**.

### Session booleans

Wakati mwingine unapokamilisha verification fulani kwa usahihi, back-end **huongeza tu boolean yenye thamani ya "True" kwenye security attribute ya session yako**. Kisha, endpoint tofauti itajua ikiwa ulifaulu kupita ukaguzi huo.\
Hata hivyo, ikiwa **umefaulu ukaguzi** na sessions zako zimepewa thamani hiyo ya "True" kwenye security attribute, unaweza kujaribu **kufikia resources nyingine** ambazo **zinategemea attribute hiyo hiyo** lakini ambazo **hupaswi kuwa na permissions** za kuzifikia. [WriteUp](https://medium.com/@ozguralp/a-less-known-attack-vector-second-order-idor-attacks-14468009781a).<sup>[[2]](#references)</sup>

### Register functionality

Jaribu kujisajili kama user ambaye tayari yupo. Pia jaribu kutumia characters zinazolingana (dots, spaces nyingi na Unicode).

### Takeover emails

Register email, kabla ya kuiconfirm, badilisha email hiyo; kisha, ikiwa confirmation email mpya itatumwa kwenye email ya kwanza iliyosajiliwa, unaweza kuchukua udhibiti wa email yoyote. Au ikiwa unaweza kuwezesha email ya pili kwa ku-confirm ya kwanza, unaweza pia kuchukua udhibiti wa account yoyote.

### Fikia Internal servicedesk ya kampuni zinazotumia atlassian


{{#ref}}
https://yourcompanyname.atlassian.net/servicedesk/customer/user/login
{{#endref}}

### TRACE method

Developers wanaweza kusahau kuzima options mbalimbali za debugging katika production environment. Kwa mfano, HTTP `TRACE` method imeundwa kwa madhumuni ya diagnostics. Ikiwa imewezeshwa, web server itajibu requests zinazotumia `TRACE` method kwa ku-echo kwenye response request halisi iliyopokelewa. Tabia hii mara nyingi haina madhara, lakini wakati mwingine husababisha information disclosure, kama vile kufichua jina la internal authentication headers ambazo zinaweza kuongezwa kwenye requests na reverse proxies.![Picha ya post](https://miro.medium.com/max/60/1*wDFRADTOd9Tj63xucenvAA.png?q=20)

![Picha ya post](https://miro.medium.com/max/1330/1*wDFRADTOd9Tj63xucenvAA.png)

## References

- [1] [How I was able to take over any user's account with Host Header Injection](https://medium.com/nassec-cybersecurity-writeups/how-i-was-able-to-take-over-any-users-account-with-host-header-injection-546fff6d0f2)
- [2] [A less known attack vector: Second Order IDOR attacks](https://medium.com/@ozguralp/a-less-known-attack-vector-second-order-idor-attacks-14468009781a)

{{#include ../banners/hacktricks-training.md}}
