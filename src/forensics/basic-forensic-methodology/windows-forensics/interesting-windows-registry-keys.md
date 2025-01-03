# Interesting Windows Registry Keys

### Interesting Windows Registry Keys

{{#include ../../../banners/hacktricks-training.md}}

### **Windows Version and Owner Info**

- Iko kwenye **`Software\Microsoft\Windows NT\CurrentVersion`**, utapata toleo la Windows, Service Pack, wakati wa usakinishaji, na jina la mmiliki aliyejiandikisha kwa njia rahisi.

### **Computer Name**

- Jina la kompyuta linapatikana chini ya **`System\ControlSet001\Control\ComputerName\ComputerName`**.

### **Time Zone Setting**

- Muda wa mfumo umehifadhiwa katika **`System\ControlSet001\Control\TimeZoneInformation`**.

### **Access Time Tracking**

- Kwa kawaida, ufuatiliaji wa wakati wa mwisho wa ufikiaji umezimwa (**`NtfsDisableLastAccessUpdate=1`**). Ili kuuwezesha, tumia:
`fsutil behavior set disablelastaccess 0`

### Windows Versions and Service Packs

- **Toleo la Windows** linaonyesha toleo (mfano, Home, Pro) na kutolewa kwake (mfano, Windows 10, Windows 11), wakati **Service Packs** ni masasisho yanayojumuisha marekebisho na, wakati mwingine, vipengele vipya.

### Enabling Last Access Time

- Kuwawezesha ufuatiliaji wa wakati wa mwisho wa ufikiaji kunakuwezesha kuona wakati faili zilifunguliwa kwa mara ya mwisho, ambayo inaweza kuwa muhimu kwa uchambuzi wa forensics au ufuatiliaji wa mfumo.

### Network Information Details

- Usajili una data kubwa kuhusu usanidi wa mtandao, ikiwa ni pamoja na **aina za mitandao (wireless, cable, 3G)** na **makundi ya mtandao (Public, Private/Home, Domain/Work)**, ambayo ni muhimu kwa kuelewa mipangilio ya usalama wa mtandao na ruhusa.

### Client Side Caching (CSC)

- **CSC** inaboresha ufikiaji wa faili za mbali kwa kuhifadhi nakala za faili zilizoshirikiwa. Mipangilio tofauti ya **CSCFlags** inasimamia jinsi na ni faili zipi zinazohifadhiwa, ikihusisha utendaji na uzoefu wa mtumiaji, hasa katika mazingira yenye muunganisho wa muda mfupi.

### AutoStart Programs

- Programu zilizoorodheshwa katika funguo mbalimbali za usajili za `Run` na `RunOnce` zinaanzishwa moja kwa moja wakati wa kuanzisha, zikihusisha muda wa kuanzisha mfumo na kuwa maeneo ya kupigiwa mfano kwa kutambua malware au programu zisizohitajika.

### Shellbags

- **Shellbags** sio tu hifadhi mapendeleo ya maoni ya folda bali pia hutoa ushahidi wa forensics wa ufikiaji wa folda hata kama folda hiyo haipo tena. Ni muhimu kwa uchunguzi, ikifunua shughuli za mtumiaji ambazo hazionekani kupitia njia nyingine.

### USB Information and Forensics

- Maelezo yaliyohifadhiwa katika usajili kuhusu vifaa vya USB yanaweza kusaidia kufuatilia ni vifaa gani vilivyounganishwa kwenye kompyuta, ikihusisha kifaa na uhamisho wa faili nyeti au matukio ya ufikiaji usioidhinishwa.

### Volume Serial Number

- **Nambari ya Mfululizo wa Kijamii** inaweza kuwa muhimu kwa kufuatilia tukio maalum la mfumo wa faili, muhimu katika hali za forensics ambapo asili ya faili inahitaji kuanzishwa kati ya vifaa tofauti.

### **Shutdown Details**

- Wakati wa kuzima na hesabu (hii ya mwisho ni kwa XP pekee) huhifadhiwa katika **`System\ControlSet001\Control\Windows`** na **`System\ControlSet001\Control\Watchdog\Display`**.

### **Network Configuration**

- Kwa maelezo ya kina ya kiunganishi cha mtandao, rejea **`System\ControlSet001\Services\Tcpip\Parameters\Interfaces{GUID_INTERFACE}`**.
- Wakati wa kwanza na wa mwisho wa muunganisho wa mtandao, ikiwa ni pamoja na muunganisho wa VPN, umeandikwa chini ya njia mbalimbali katika **`Software\Microsoft\Windows NT\CurrentVersion\NetworkList`**.

### **Shared Folders**

- Folda na mipangilio zilizoshirikiwa ziko chini ya **`System\ControlSet001\Services\lanmanserver\Shares`**. Mipangilio ya Client Side Caching (CSC) inaamuru upatikanaji wa faili za mbali.

### **Programs that Start Automatically**

- Njia kama **`NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Run`** na entries zinazofanana chini ya `Software\Microsoft\Windows\CurrentVersion` zinaelezea programu zilizowekwa kuanzishwa wakati wa kuanzisha.

### **Searches and Typed Paths**

- Utafutaji wa Explorer na njia zilizotajwa zinafuatiliwa katika usajili chini ya **`NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer`** kwa WordwheelQuery na TypedPaths, mtawalia.

### **Recent Documents and Office Files**

- Hati za hivi karibuni na faili za Ofisi zilizofikiwa zimeandikwa katika `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs` na njia maalum za toleo la Ofisi.

### **Most Recently Used (MRU) Items**

- Orodha za MRU, zikionyesha njia za faili za hivi karibuni na amri, zimehifadhiwa katika funguo mbalimbali za `ComDlg32` na `Explorer` chini ya `NTUSER.DAT`.

### **User Activity Tracking**

- Kipengele cha User Assist kinarekodi takwimu za matumizi ya programu kwa undani, ikiwa ni pamoja na hesabu ya kuendesha na wakati wa mwisho wa kuendesha, katika **`NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count`**.

### **Shellbags Analysis**

- Shellbags, zikifunua maelezo ya ufikiaji wa folda, zimehifadhiwa katika `USRCLASS.DAT` na `NTUSER.DAT` chini ya `Software\Microsoft\Windows\Shell`. Tumia **[Shellbag Explorer](https://ericzimmerman.github.io/#!index.md)** kwa uchambuzi.

### **USB Device History**

- **`HKLM\SYSTEM\ControlSet001\Enum\USBSTOR`** na **`HKLM\SYSTEM\ControlSet001\Enum\USB`** zina maelezo mengi kuhusu vifaa vya USB vilivyounganishwa, ikiwa ni pamoja na mtengenezaji, jina la bidhaa, na nyakati za muunganisho.
- Mtumiaji anayehusishwa na kifaa maalum cha USB anaweza kupatikana kwa kutafuta hives za `NTUSER.DAT` kwa **{GUID}** ya kifaa.
- Kifaa cha mwisho kilichounganishwa na nambari yake ya mfululizo wa volume kinaweza kufuatiliwa kupitia `System\MountedDevices` na `Software\Microsoft\Windows NT\CurrentVersion\EMDMgmt`, mtawalia.

Hii mwongozo inakusanya njia muhimu na mbinu za kufikia maelezo ya kina ya mfumo, mtandao, na shughuli za mtumiaji kwenye mifumo ya Windows, ikilenga uwazi na matumizi.

{{#include ../../../banners/hacktricks-training.md}}
