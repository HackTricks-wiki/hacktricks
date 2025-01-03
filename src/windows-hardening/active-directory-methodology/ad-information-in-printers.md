{{#include ../../banners/hacktricks-training.md}}

Kuna blogu kadhaa kwenye Mtandao ambazo **zinasisitiza hatari za kuacha printers zikiwa zimewekwa na LDAP zikiwa na** akauti za kuingia za kawaida/dhaifu.\
Hii ni kwa sababu mshambuliaji anaweza **kudanganya printer kujiunga na seva ya LDAP isiyo halali** (kawaida `nc -vv -l -p 444` inatosha) na kukamata **akauti za printer kwa maandiko wazi**.

Pia, printers kadhaa zitakuwa na **logs zenye majina ya watumiaji** au zinaweza hata kuwa na uwezo wa **kupakua majina yote ya watumiaji** kutoka kwa Domain Controller.

Taarifa hii **nyeti** na **ukosefu wa usalama** wa kawaida inafanya printers kuwa za kuvutia sana kwa washambuliaji.

Baadhi ya blogu kuhusu mada hii:

- [https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)
- [https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)

## Mipangilio ya Printer

- **Mahali**: Orodha ya seva ya LDAP inapatikana kwenye: `Network > LDAP Setting > Setting Up LDAP`.
- **Tabia**: Kiolesura kinaruhusu mabadiliko ya seva ya LDAP bila kuingiza tena akauti, ikilenga urahisi wa mtumiaji lakini ikileta hatari za usalama.
- **Kuvunja**: Kuvunja kunahusisha kuelekeza anwani ya seva ya LDAP kwenye mashine iliyo chini ya udhibiti na kutumia kipengele cha "Test Connection" kukamata akauti.

## Kukamata Akauti

**Kwa hatua za kina zaidi, rejea kwenye [chanzo](https://grimhacker.com/2018/03/09/just-a-printer/).**

### Njia 1: Netcat Listener

Listener rahisi ya netcat inaweza kutosha:
```bash
sudo nc -k -v -l -p 386
```
Hata hivyo, mafanikio ya mbinu hii yanatofautiana.

### Method 2: Full LDAP Server with Slapd

Njia ya kuaminika zaidi inahusisha kuanzisha seva kamili ya LDAP kwa sababu printer inafanya bind ya null ikifuatiwa na uchunguzi kabla ya kujaribu kuunganisha akidi.

1. **LDAP Server Setup**: Mwongozo unafuata hatua kutoka [this source](https://www.server-world.info/en/note?os=Fedora_26&p=openldap).
2. **Key Steps**:
- Sakinisha OpenLDAP.
- Sanidi nenosiri la admin.
- Ingiza mifano ya msingi.
- Weka jina la kikoa kwenye DB ya LDAP.
- Sanidi LDAP TLS.
3. **LDAP Service Execution**: Mara tu inapoanzishwa, huduma ya LDAP inaweza kuendeshwa kwa kutumia:
```bash
slapd -d 2
```
## Marejeleo

- [https://grimhacker.com/2018/03/09/just-a-printer/](https://grimhacker.com/2018/03/09/just-a-printer/)

{{#include ../../banners/hacktricks-training.md}}
