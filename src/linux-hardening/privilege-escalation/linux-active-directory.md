# Linux Active Directory

{{#include ../../banners/hacktricks-training.md}}

Mashine ya linux inaweza pia kuwepo ndani ya mazingira ya Active Directory.

Mashine ya linux katika AD inaweza kuwa **ikiweka tiketi tofauti za CCACHE ndani ya faili. Tiketi hizi zinaweza kutumika na kutumiwa vibaya kama tiketi nyingine za kerberos**. Ili kusoma tiketi hizi utahitaji kuwa mmiliki wa tiketi au **root** ndani ya mashine.

## Enumeration

### AD enumeration kutoka linux

Ikiwa una ufikiaji juu ya AD katika linux (au bash katika Windows) unaweza kujaribu [https://github.com/lefayjey/linWinPwn](https://github.com/lefayjey/linWinPwn) ili kuhesabu AD.

Unaweza pia kuangalia ukurasa ufuatao kujifunza **njia nyingine za kuhesabu AD kutoka linux**:

{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

### FreeIPA

FreeIPA ni **mbadala** wa chanzo wazi kwa Microsoft Windows **Active Directory**, hasa kwa mazingira ya **Unix**. Inachanganya **LDAP directory** kamili na Kituo cha Usambazaji wa Funguo za MIT **Kerberos** kwa usimamizi unaofanana na Active Directory. Inatumia Mfumo wa **Cheti** wa Dogtag kwa usimamizi wa cheti za CA & RA, inasaidia **uthibitishaji wa hatua nyingi**, ikiwa ni pamoja na kadi za smart. SSSD imeunganishwa kwa michakato ya uthibitishaji wa Unix. Jifunze zaidi kuhusu hilo katika:

{{#ref}}
../freeipa-pentesting.md
{{#endref}}

## Kucheza na tiketi

### Pass The Ticket

Katika ukurasa huu utapata maeneo tofauti ambapo unaweza **kupata tiketi za kerberos ndani ya mwenyeji wa linux**, katika ukurasa ufuatao unaweza kujifunza jinsi ya kubadilisha muundo wa tiketi hizi za CCache kuwa Kirbi (muundo unaohitajika kutumika katika Windows) na pia jinsi ya kufanya shambulio la PTT:

{{#ref}}
../../windows-hardening/active-directory-methodology/pass-the-ticket.md
{{#endref}}

### CCACHE tiketi matumizi kutoka /tmp

Faili za CCACHE ni muundo wa binary kwa **kuhifadhi akidi za Kerberos** ambazo kawaida huhifadhiwa na ruhusa 600 katika `/tmp`. Faili hizi zinaweza kutambulika kwa **muundo wa jina lao, `krb5cc_%{uid}`,** inayohusiana na UID ya mtumiaji. Kwa uthibitishaji wa tiketi, **kigezo cha mazingira `KRB5CCNAME`** kinapaswa kuwekwa kwenye njia ya faili ya tiketi inayotakiwa, kuruhusu matumizi yake tena.

Orodhesha tiketi ya sasa inayotumika kwa uthibitishaji kwa `env | grep KRB5CCNAME`. Muundo ni wa kubebeka na tiketi inaweza **kutumika tena kwa kuweka kigezo cha mazingira** kwa `export KRB5CCNAME=/tmp/ticket.ccache`. Muundo wa jina la tiketi ya Kerberos ni `krb5cc_%{uid}` ambapo uid ni UID ya mtumiaji.
```bash
# Find tickets
ls /tmp/ | grep krb5cc
krb5cc_1000

# Prepare to use it
export KRB5CCNAME=/tmp/krb5cc_1000
```
### CCACHE ticket reuse from keyring

**Tiketi za Kerberos zilizohifadhiwa katika kumbukumbu ya mchakato zinaweza kutolewa**, hasa wakati ulinzi wa ptrace wa mashine umezimwa (`/proc/sys/kernel/yama/ptrace_scope`). Chombo chenye manufaa kwa kusudi hili kinapatikana kwenye [https://github.com/TarlogicSecurity/tickey](https://github.com/TarlogicSecurity/tickey), ambacho kinasaidia kutoa tiketi kwa kuingiza katika vikao na kutupa tiketi kwenye `/tmp`.

Ili kuunda na kutumia chombo hiki, hatua zilizo hapa chini zinafuatwa:
```bash
git clone https://github.com/TarlogicSecurity/tickey
cd tickey/tickey
make CONF=Release
/tmp/tickey -i
```
Hii taratibu itajaribu kuingiza katika vikao mbalimbali, ikionyesha mafanikio kwa kuhifadhi tiketi zilizopatikana katika `/tmp` kwa muundo wa majina `__krb_UID.ccache`.

### CCACHE tiketi matumizi tena kutoka SSSD KCM

SSSD inashikilia nakala ya hifadhidata katika njia `/var/lib/sss/secrets/secrets.ldb`. Funguo inayohusiana inahifadhiwa kama faili iliyofichwa katika njia `/var/lib/sss/secrets/.secrets.mkey`. Kwa kawaida, funguo hiyo inaweza kusomwa tu ikiwa una ruhusa za **root**.

Kuita **`SSSDKCMExtractor`** na vigezo --database na --key vitachambua hifadhidata na **kufichua siri**.
```bash
git clone https://github.com/fireeye/SSSDKCMExtractor
python3 SSSDKCMExtractor.py --database secrets.ldb --key secrets.mkey
```
**Kikundi cha akiba ya sifa za Kerberos kinaweza kubadilishwa kuwa faili ya Kerberos CCache inayoweza kutumika** ambayo inaweza kupitishwa kwa Mimikatz/Rubeus.

### Urejeleaji wa tiketi ya CCACHE kutoka kwa keytab
```bash
git clone https://github.com/its-a-feature/KeytabParser
python KeytabParser.py /etc/krb5.keytab
klist -k /etc/krb5.keytab
```
### Extract accounts from /etc/krb5.keytab

Hifadhi za akaunti za huduma, muhimu kwa huduma zinazofanya kazi na ruhusa za mzizi, zimehifadhiwa kwa usalama katika faili za **`/etc/krb5.keytab`**. Hifadhi hizi, kama nywila za huduma, zinahitaji faragha kali.

Ili kukagua maudhui ya faili la keytab, **`klist`** inaweza kutumika. Zana hii imeundwa kuonyesha maelezo ya hifadhi, ikiwa ni pamoja na **NT Hash** kwa uthibitishaji wa mtumiaji, hasa wakati aina ya hifadhi inatambulika kama 23.
```bash
klist.exe -t -K -e -k FILE:C:/Path/to/your/krb5.keytab
# Output includes service principal details and the NT Hash
```
Kwa watumiaji wa Linux, **`KeyTabExtract`** inatoa kazi ya kutoa hash ya RC4 HMAC, ambayo inaweza kutumika kwa ajili ya matumizi tena ya hash ya NTLM.
```bash
python3 keytabextract.py krb5.keytab
# Expected output varies based on hash availability
```
Katika macOS, **`bifrost`** hutumika kama chombo cha uchambuzi wa faili za keytab.
```bash
./bifrost -action dump -source keytab -path /path/to/your/file
```
Kwa kutumia taarifa za akaunti na hash zilizopatikana, muunganisho na seva zinaweza kuanzishwa kwa kutumia zana kama **`crackmapexec`**.
```bash
crackmapexec 10.XXX.XXX.XXX -u 'ServiceAccount$' -H "HashPlaceholder" -d "YourDOMAIN"
```
## Marejeleo

- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [https://github.com/TarlogicSecurity/tickey](https://github.com/TarlogicSecurity/tickey)
- [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#linux-active-directory](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#linux-active-directory)

{{#include ../../banners/hacktricks-training.md}}
