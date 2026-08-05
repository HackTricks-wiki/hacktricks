# macOS Authorizations DB & Authd

{{#include ../../../banners/hacktricks-training.md}}

## **Athorizarions DB**

Database iliyoko `/var/db/auth.db` hutumika kuhifadhi permissions za kutekeleza operations nyeti. Operations hizi hutekelezwa kabisa katika **user space** na kwa kawaida hutumiwa na **XPC services** zinazohitaji kuangalia **ikiwa calling client imeidhinishwa** kutekeleza action fulani kwa kukagua database hii.

Hapo awali database hii huundwa kutokana na maudhui ya `/System/Library/Security/authorization.plist`. Kisha, baadhi ya services zinaweza kuongeza au kurekebisha dataabse hii ili kuongeza permissions nyingine.

Rules huhifadhiwa katika table ya `rules` ndani ya database na huwa na columns zifuatazo:

- **id**: Kitambulisho cha kipekee cha kila rule, kinachoongezeka kiotomatiki na kutumika kama primary key.
- **name**: Jina la kipekee la rule linalotumika kuitambua na kuirejelea ndani ya authorization system.
- **type**: Hubainisha aina ya rule, ikiwa na values 1 au 2 pekee zinazoeleza authorization logic yake.
- **class**: Huweka rule katika class maalum, huku ikihakikisha kuwa ni positive integer.
- "allow" kwa allow, "deny" kwa deny, "user" ikiwa group property inaonyesha group ambayo membership yake inaruhusu access, "rule" huonyesha katika array rule inayopaswa kutimizwa, "evaluate-mechanisms" ikifuatiwa na `mechanisms` array ambazo zinaweza kuwa builtins au jina la bundle iliyo ndani ya `/System/Library/CoreServices/SecurityAgentPlugins/` au /Library/Security//SecurityAgentPlugins
- **group**: Huonyesha user group inayohusishwa na rule kwa group-based authorization.
- **kofn**: Inawakilisha parameter ya "k-of-n", inayoamua ni subrules ngapi zinapaswa kutimizwa kati ya jumla fulani.
- **timeout**: Hufafanua muda kwa sekunde kabla ya authorization iliyotolewa na rule ku-expire.
- **flags**: Huwa na flags mbalimbali zinazobadilisha tabia na sifa za rule.
- **tries**: Huweka kikomo cha idadi ya authorization attempts zinazoruhusiwa ili kuimarisha security.
- **version**: Hufuatilia version ya rule kwa ajili ya version control na updates.
- **created**: Hurekodi timestamp wakati rule iliundwa kwa madhumuni ya auditing.
- **modified**: Huhifadhi timestamp ya modification ya mwisho iliyofanywa kwenye rule.
- **hash**: Huwa na hash value ya rule ili kuhakikisha integrity yake na kugundua tampering.
- **identifier**: Hutoa string identifier ya kipekee, kama UUID, kwa external references za rule.
- **requirement**: Huwa na serialized data inayofafanua authorization requirements na mechanisms maalum za rule.
- **comment**: Hutoa maelezo au comment inayoweza kusomeka na binadamu kuhusu rule kwa ajili ya documentation na clarity.

### Example
```bash
# List by name and comments
sudo sqlite3 /var/db/auth.db "select name, comment from rules"

# Get rules for com.apple.tcc.util.admin
security authorizationdb read com.apple.tcc.util.admin
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>class</key>
<string>rule</string>
<key>comment</key>
<string>For modification of TCC settings.</string>
<key>created</key>
<real>701369782.01043606</real>
<key>modified</key>
<real>701369782.01043606</real>
<key>rule</key>
<array>
<string>authenticate-admin-nonshared</string>
</array>
<key>version</key>
<integer>0</integer>
</dict>
</plist>
```
Zaidi ya hayo, katika [https://www.dssw.co.uk/reference/authorization-rights/authenticate-admin-nonshared/](https://www.dssw.co.uk/reference/authorization-rights/authenticate-admin-nonshared/) inawezekana kuona maana ya `authenticate-admin-nonshared`:<sup>[1]</sup>
```json
{
"allow-root": "false",
"authenticate-user": "true",
"class": "user",
"comment": "Authenticate as an administrator.",
"group": "admin",
"session-owner": "false",
"shared": "false",
"timeout": "30",
"tries": "10000",
"version": "1"
}
```
## Authd

Ni `daemon` inayopokea requests za ku-authorize clients kutekeleza actions nyeti. Inafanya kazi kama XPC service iliyofafanuliwa ndani ya folda ya `XPCServices/` na hutumika kuandika logs zake katika `/var/log/authd.log`.

Zaidi ya hayo, kwa kutumia security tool inawezekana ku-test APIs nyingi za `Security.framework`. Kwa mfano, `AuthorizationExecuteWithPrivileges` ikiendeshwa: `security execute-with-privileges /bin/ls`

Hiyo itafanya `fork` na `exec` ya `/usr/libexec/security_authtrampoline /bin/ls` kama root, ambayo itaomba permissions katika prompt ili kutekeleza ls kama root:

<figure><img src="../../../images/image (10).png" alt=""><figcaption></figcaption></figure>

## References

- [1] [authenticate-admin-nonshared - Overview of the macOS Authorization Right](https://www.dssw.co.uk/reference/authorization-rights/authenticate-admin-nonshared/)

{{#include ../../../banners/hacktricks-training.md}}
