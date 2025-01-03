# macOS Memory Dumping

{{#include ../../../banners/hacktricks-training.md}}

## Memory Artifacts

### Swap Files

Faili za kubadilishana, kama `/private/var/vm/swapfile0`, hutumikia kama **cache wakati kumbukumbu ya kimwili imejaa**. Wakati hakuna nafasi zaidi katika kumbukumbu ya kimwili, data yake inahamishwa kwenye faili ya kubadilishana na kisha inarudishwa kwenye kumbukumbu ya kimwili inapohitajika. Faili nyingi za kubadilishana zinaweza kuwepo, zikiwa na majina kama swapfile0, swapfile1, na kadhalika.

### Hibernate Image

Faili iliyoko kwenye `/private/var/vm/sleepimage` ni muhimu wakati wa **hali ya kulala**. **Data kutoka kwenye kumbukumbu huhifadhiwa katika faili hii wakati OS X inalala**. Wakati kompyuta inapoamka, mfumo unapata data ya kumbukumbu kutoka faili hii, ikiruhusu mtumiaji kuendelea mahali alipoacha.

Inafaa kutaja kwamba kwenye mifumo ya kisasa ya MacOS, faili hii kwa kawaida imefungwa kwa sababu za usalama, na kufanya urejeleaji kuwa mgumu.

- Ili kuangalia kama usimbaji umewezeshwa kwa sleepimage, amri `sysctl vm.swapusage` inaweza kutumika. Hii itaonyesha kama faili imefungwa.

### Memory Pressure Logs

Faili nyingine muhimu inayohusiana na kumbukumbu katika mifumo ya MacOS ni **kumbukumbu za shinikizo la kumbukumbu**. Kumbukumbu hizi ziko katika `/var/log` na zina maelezo ya kina kuhusu matumizi ya kumbukumbu ya mfumo na matukio ya shinikizo. Zinweza kuwa na manufaa hasa kwa kutambua matatizo yanayohusiana na kumbukumbu au kuelewa jinsi mfumo unavyosimamia kumbukumbu kwa muda.

## Dumping memory with osxpmem

Ili kutupa kumbukumbu katika mashine ya MacOS unaweza kutumia [**osxpmem**](https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip).

**Kumbuka**: Maagizo yafuatayo yatatumika tu kwa Macs zenye usanifu wa Intel. Chombo hiki sasa kimehifadhiwa na toleo la mwisho lilikuwa mwaka 2017. Binary iliyopakuliwa kwa kutumia maagizo hapa chini inalenga chips za Intel kwani Apple Silicon haikuwapo mwaka 2017. Inaweza kuwa inawezekana kukusanya binary kwa usanifu wa arm64 lakini itabidi ujaribu mwenyewe.
```bash
#Dump raw format
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem

#Dump aff4 format
sudo osxpmem.app/osxpmem -o /tmp/dump_mem.aff4
```
Ikiwa unakutana na kosa hili: `osxpmem.app/MacPmem.kext failed to load - (libkern/kext) authentication failure (file ownership/permissions); check the system/kernel logs for errors or try kextutil(8)` Unaweza kulitatua kwa kufanya:
```bash
sudo cp -r osxpmem.app/MacPmem.kext "/tmp/"
sudo kextutil "/tmp/MacPmem.kext"
#Allow the kext in "Security & Privacy --> General"
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
**Makosa mengine** yanaweza kurekebishwa kwa **kuruhusu upakiaji wa kext** katika "Usalama & Faragha --> Kawaida", tu **ruhusu**.

Unaweza pia kutumia hii **oneliner** kupakua programu, kupakia kext na kutupa kumbukumbu:
```bash
sudo su
cd /tmp; wget https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip; unzip osxpmem-2.1.post4.zip; chown -R root:wheel osxpmem.app/MacPmem.kext; kextload osxpmem.app/MacPmem.kext; osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
{{#include ../../../banners/hacktricks-training.md}}
