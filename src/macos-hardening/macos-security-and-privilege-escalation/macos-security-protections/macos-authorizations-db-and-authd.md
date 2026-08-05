# macOS Authorizations DB & Authd

{{#include ../../../banners/hacktricks-training.md}}

## **DB ya Authorizations**

Database iliyo katika `/var/db/auth.db` ni database inayotumika kuhifadhi permissions za kutekeleza operations nyeti. Operations hizi hutekelezwa kikamilifu kwenye **user space** na kwa kawaida hutumiwa na **XPC services** zinazohitaji kuangalia **ikiwa client anayeita ana authorization** ya kutekeleza action fulani kwa kukagua database hii.

Mwanzoni, database hii huundwa kutokana na maudhui ya `/System/Library/Security/authorization.plist`. Kisha, baadhi ya services zinaweza kuongeza au kurekebisha database hii ili kuongeza permissions nyingine.

Rules huhifadhiwa kwenye table ya `rules` ndani ya database na huwa na columns zifuatazo:

- **id**: Kitambulisho cha kipekee kwa kila rule, kinachoongezwa kiotomatiki na kutumika kama primary key.
- **name**: Jina la kipekee la rule linalotumika kuitambua na kuirejelea ndani ya authorization system.
- **type**: Hubainisha aina ya rule, ikiwa na thamani 1 au 2 pekee za kufafanua authorization logic yake.
- **class**: Huainisha rule kwenye class maalum, huku ikihakikisha kuwa ni integer chanya.
- "allow" kwa allow, "deny" kwa deny, "user" ikiwa property ya group inaonyesha group ambayo membership yake inaruhusu access, "rule" inaonyesha kwenye array rule inayopaswa kutimizwa, "evaluate-mechanisms" ikifuatiwa na array ya `mechanisms` ambazo zinaweza kuwa builtins au jina la bundle ndani ya `/System/Library/CoreServices/SecurityAgentPlugins/` au `/Library/Security//SecurityAgentPlugins`
- **group**: Huonyesha user group inayohusishwa na rule kwa ajili ya group-based authorization.
- **kofn**: Huonyesha parameter ya "k-of-n", inayoamua ni subrules ngapi zinapaswa kutimizwa kati ya jumla iliyopo.
- **timeout**: Hufafanua muda kwa sekunde kabla ya authorization iliyotolewa na rule ku-expire.
- **flags**: Huwa na flags mbalimbali zinazorekebisha tabia na sifa za rule.
- **tries**: Hupunguza idadi ya authorization attempts zinazoruhusiwa ili kuongeza security.
- **version**: Hufuatilia version ya rule kwa ajili ya version control na updates.
- **created**: Huhifadhi timestamp ya rule ilipoundwa kwa ajili ya auditing.
- **modified**: Huhifadhi timestamp ya marekebisho ya mwisho yaliyofanywa kwenye rule.
- **hash**: Huhifadhi hash value ya rule ili kuhakikisha integrity yake na kugundua tampering.
- **identifier**: Hutoa string identifier ya kipekee, kama UUID, kwa ajili ya external references za rule.
- **requirement**: Huwa na serialized data inayofafanua authorization requirements na mechanisms maalum za rule.
- **comment**: Hutoa maelezo au comment inayoweza kusomwa na binadamu kuhusu rule kwa ajili ya documentation na ufafanuzi.

### Mfano
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
Zaidi ya hayo, katika [https://www.dssw.co.uk/reference/authorization-rights/authenticate-admin-nonshared/](https://www.dssw.co.uk/reference/authorization-rights/authenticate-admin-nonshared/) inawezekana kuona maana ya `authenticate-admin-nonshared`:<sup>[[1]](#references)</sup>
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

Ni daemon inayopokea maombi ya kuidhinisha clients kutekeleza vitendo nyeti. Hufanya kazi kama huduma ya XPC iliyofafanuliwa ndani ya folda ya `XPCServices/` na hutumika kuandika logs zake katika `/var/log/authd.log`.

Zaidi ya hayo, kwa kutumia security tool inawezekana kujaribu APIs nyingi za `Security.framework`. Kwa mfano, kuendesha `AuthorizationExecuteWithPrivileges`: `security execute-with-privileges /bin/ls`

Hilo litafanya fork na exec `/usr/libexec/security_authtrampoline /bin/ls` kama root, ambayo itaomba ruhusa kupitia prompt ili kutekeleza ls kama root:

<figure><img src="../../../images/image (10).png" alt=""><figcaption></figcaption></figure>

## References

- [1] [authenticate-admin-nonshared - Overview of the macOS Authorization Right](https://www.dssw.co.uk/reference/authorization-rights/authenticate-admin-nonshared/)

{{#include ../../../banners/hacktricks-training.md}}
