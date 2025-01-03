# AD Certificates

{{#include ../../banners/hacktricks-training.md}}

## Introduction

### Components of a Certificate

- **Mada** ya cheti inaonyesha mmiliki wake.
- **Funguo za Umma** zimeunganishwa na funguo za kibinafsi ili kuunganisha cheti na mmiliki wake halali.
- **Muda wa Uhalali**, ulioainishwa na tarehe za **NotBefore** na **NotAfter**, unaashiria muda wa ufanisi wa cheti.
- Nambari ya **Serial** ya kipekee, inayotolewa na Mamlaka ya Cheti (CA), inatambulisha kila cheti.
- **Mtoaji** inahusisha CA ambayo imetoa cheti.
- **SubjectAlternativeName** inaruhusu majina ya ziada kwa mada, ikiongeza kubadilika kwa utambulisho.
- **Misingi ya Msingi** inatambua ikiwa cheti ni kwa CA au kitengo cha mwisho na inaweka vikwazo vya matumizi.
- **Matumizi ya Funguo Yaliyoongezwa (EKUs)** yanabainisha madhumuni maalum ya cheti, kama vile kusaini msimbo au usimbaji wa barua pepe, kupitia Vitambulisho vya Kitu (OIDs).
- **Algorithimu ya Sahihi** inaelezea njia ya kusaini cheti.
- **Sahihi**, iliyoundwa kwa funguo ya kibinafsi ya mtoaji, inahakikisha uhalali wa cheti.

### Special Considerations

- **Majina Alternatif ya Mada (SANs)** yanapanua matumizi ya cheti kwa vitambulisho vingi, muhimu kwa seva zenye maeneo mengi. Mchakato wa usambazaji salama ni muhimu ili kuepuka hatari za kujifanya kwa washambuliaji wanaoshughulikia spesifikesheni ya SAN.

### Certificate Authorities (CAs) in Active Directory (AD)

AD CS inatambua cheti za CA katika msitu wa AD kupitia vyombo vilivyotengwa, kila kimoja kikihudumu majukumu ya kipekee:

- **Mamlaka za Cheti** chombo kinashikilia cheti za CA za mizizi zinazotegemewa.
- **Huduma za Usajili** chombo kinaelezea CA za Biashara na templeti zao za cheti.
- **NTAuthCertificates** kitu kinajumuisha cheti za CA zilizoidhinishwa kwa uthibitishaji wa AD.
- **AIA (Upatikanaji wa Taarifa za Mamlaka)** chombo kinasaidia uthibitishaji wa mnyororo wa cheti na cheti za CA za kati na za msalaba.

### Certificate Acquisition: Client Certificate Request Flow

1. Mchakato wa ombi huanza na wateja wakitafuta CA ya Biashara.
2. CSR inaundwa, ikiwa na funguo ya umma na maelezo mengine, baada ya kuunda jozi ya funguo ya umma na ya kibinafsi.
3. CA inakagua CSR dhidi ya templeti za cheti zilizopo, ikitoa cheti kulingana na ruhusa za templeti.
4. Baada ya idhini, CA inasaini cheti kwa funguo yake ya kibinafsi na kuirudisha kwa mteja.

### Certificate Templates

Zimeainishwa ndani ya AD, templeti hizi zinaelezea mipangilio na ruhusa za kutoa cheti, ikiwa ni pamoja na EKUs zinazoruhusiwa na haki za usajili au mabadiliko, muhimu kwa usimamizi wa ufikiaji wa huduma za cheti.

## Certificate Enrollment

Mchakato wa usajili wa cheti huanzishwa na msimamizi ambaye **anaunda templeti ya cheti**, ambayo kisha **inasambazwa** na Mamlaka ya Cheti ya Biashara (CA). Hii inafanya templeti ipatikane kwa usajili wa mteja, hatua inayofikiwa kwa kuongeza jina la templeti kwenye uwanja wa `certificatetemplates` wa kitu cha Active Directory.

Ili mteja aombe cheti, **haki za usajili** lazima zipewe. Haki hizi zinaainishwa na waelekezi wa usalama kwenye templeti ya cheti na CA ya Biashara yenyewe. Ruhusa lazima zipewe katika maeneo yote mawili ili ombi liwe na mafanikio.

### Template Enrollment Rights

Haki hizi zinaelezwa kupitia Kuingilia kwa Udhibiti wa Ufikiaji (ACEs), zikielezea ruhusa kama:

- Haki za **Usajili wa Cheti** na **AutoEnrollment ya Cheti**, kila moja ikihusishwa na GUID maalum.
- **Haki za Kupanuliwa**, zikiruhusu ruhusa zote za ziada.
- **FullControl/GenericAll**, ikitoa udhibiti kamili juu ya templeti.

### Enterprise CA Enrollment Rights

Haki za CA zinaelezwa katika waelekezi wake wa usalama, zinazopatikana kupitia console ya usimamizi wa Mamlaka ya Cheti. Mipangilio mingine hata inaruhusu watumiaji wenye mamlaka ya chini kupata mbali, ambayo inaweza kuwa wasiwasi wa usalama.

### Additional Issuance Controls

Vikaguzi fulani vinaweza kutumika, kama:

- **Idhini ya Meneja**: Inaweka maombi katika hali ya kusubiri hadi idhini itolewe na meneja wa cheti.
- **Wakala wa Usajili na Sahihi Zilizothibitishwa**: Inaelezea idadi ya sahihi zinazohitajika kwenye CSR na OIDs zinazohitajika za Sera ya Maombi.

### Methods to Request Certificates

Cheti zinaweza kuombwa kupitia:

1. **Protokali ya Usajili wa Cheti ya Mteja wa Windows** (MS-WCCE), ikitumia interfaces za DCOM.
2. **Protokali ya ICertPassage Remote** (MS-ICPR), kupitia mabomba yaliyopewa majina au TCP/IP.
3. Kiolesura cha wavuti cha **usajili wa cheti**, na jukumu la Usajili wa Mamlaka ya Cheti lililosakinishwa.
4. **Huduma ya Usajili wa Cheti** (CES), kwa kushirikiana na huduma ya Sera ya Usajili wa Cheti (CEP).
5. **Huduma ya Usajili wa Vifaa vya Mtandao** (NDES) kwa vifaa vya mtandao, ikitumia Protokali ya Usajili wa Cheti Rahisi (SCEP).

Watumiaji wa Windows wanaweza pia kuomba cheti kupitia GUI (`certmgr.msc` au `certlm.msc`) au zana za mistari ya amri (`certreq.exe` au amri ya `Get-Certificate` ya PowerShell).
```powershell
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```
## Uthibitisho wa Cheti

Active Directory (AD) inasaidia uthibitisho wa cheti, hasa ikitumia **Kerberos** na **Secure Channel (Schannel)** protokali.

### Mchakato wa Uthibitisho wa Kerberos

Katika mchakato wa uthibitisho wa Kerberos, ombi la mtumiaji la Tiketi ya Kutoa Tiketi (TGT) linatiwa saini kwa kutumia **funguo ya faragha** ya cheti cha mtumiaji. Ombi hili hupitia uthibitisho kadhaa na msimamizi wa eneo, ikiwa ni pamoja na **uhalali** wa cheti, **njia**, na **hali ya kufutwa**. Uthibitisho pia unajumuisha kuangalia kwamba cheti kinatoka kwa chanzo kinachotegemewa na kuthibitisha uwepo wa mtoaji katika **duka la cheti la NTAUTH**. Uthibitisho uliofanikiwa unapelekea utoaji wa TGT. Kitu cha **`NTAuthCertificates`** katika AD, kinachopatikana kwenye:
```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```
ni muhimu katika kuanzisha uaminifu kwa uthibitishaji wa cheti.

### Uthibitishaji wa Kituo Salama (Schannel)

Schannel inarahisisha muunganisho salama wa TLS/SSL, ambapo wakati wa mkutano, mteja anawasilisha cheti ambacho, ikiwa kimefanikiwa kuthibitishwa, kinatoa ruhusa ya ufikiaji. Mchoro wa cheti kwa akaunti ya AD unaweza kujumuisha kazi ya Kerberos **S4U2Self** au **Subject Alternative Name (SAN)** ya cheti, miongoni mwa mbinu nyingine.

### Uhesabu wa Huduma za Cheti za AD

Huduma za cheti za AD zinaweza kuhesabiwa kupitia maswali ya LDAP, zikifunua habari kuhusu **Mamlaka ya Cheti ya Biashara (CAs)** na mipangilio yao. Hii inapatikana kwa mtumiaji yeyote aliyeidhinishwa na kikoa bila ruhusa maalum. Zana kama **[Certify](https://github.com/GhostPack/Certify)** na **[Certipy](https://github.com/ly4k/Certipy)** zinatumika kwa uhesabu na tathmini ya udhaifu katika mazingira ya AD CS.

Amri za kutumia zana hizi ni:
```bash
# Enumerate trusted root CA certificates and Enterprise CAs with Certify
Certify.exe cas
# Identify vulnerable certificate templates with Certify
Certify.exe find /vulnerable

# Use Certipy for enumeration and identifying vulnerable templates
certipy find -vulnerable -u john@corp.local -p Passw0rd -dc-ip 172.16.126.128

# Enumerate Enterprise CAs and certificate templates with certutil
certutil.exe -TCAInfo
certutil -v -dstemplate
```
## Marejeo

- [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)
- [https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html](https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html)

{{#include ../../banners/hacktricks-training.md}}
