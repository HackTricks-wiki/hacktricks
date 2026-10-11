# Viashiria vya Kupandisha Mamlaka kupitia Session na Huduma ya Diski za SUSE

{{#include ../../banners/hacktricks-training.md}}

## Uidhinishaji wa session ya SSH kupitia PAM

CVE-2025-6018 iliathiri usanidi wa PAM wa SUSE 15 ambapo stack ya uthibitishaji wa SSH ilipakia `pam_env` kabla stack ya session haijapakia `pam_systemd`. `pam_env` iliposoma `.pam_environment` ya mtumiaji, mtumiaji huyo angeweza kuweka thamani za `XDG_SEAT` na `XDG_VTNR` zilizofanya Polkit ichukulie session ya SSH kuwa inatumika kimwili. Kisha kitendo cha `allow_active=yes` kingeweza kupatikana kwa mtumiaji wa mbali. Hili hubadilisha uidhinishaji wa session; peke yake halihakikishi ufikiaji wa root. SUSE ilirekebisha tabia chaguomsingi ya mazingira ya mtumiaji katika `pam` na uwekaji wa moduli unaozalishwa na `pam-config`.<sup>[[1]](#references)[[2]](#references)</sup>

Kagua msururu wa `include` unaotumika katika `/etc/pam.d/sshd`, mpangilio wa `pam_env.so` na `pam_systemd.so`, na chaguo lolote la wazi la `user_readenv=1`. Kifurushi cha `pam` kilichorekebishwa hubadilisha tabia chaguomsingi, lakini chaguo la wazi bado linaweza kuomba usomaji wa mazingira ya mtumiaji. Kifurushi kipya cha `pam-config` hakithibitishi kuwa stack ya PAM iliyobadilishwa ndani au iliyopitwa na wakati ilizalishwa upya. Kagua toleo la kifurushi cha mtengenezaji pamoja na usanidi halisi.<sup>[[1]](#references)[[2]](#references)</sup>

## Njia ya huduma ya diski kwa mtumiaji aliye active

CVE-2025-6019 ilikuwa njia ya kupandisha mamlaka katika `libblockdev` iliyotumiwa kupitia `udisks2`: wakati wa kubadilisha ukubwa wa XFS, mfumo wa faili uliotolewa na mshambulizi ungeweza kupachikwa kwa muda bila kizuizi cha `nosuid` kilichotarajiwa. Njia hii inahitaji huduma ya UDisks D-Bus inayoweza kutumika, usaidizi wa kubadilisha ukubwa wa XFS, kitendo husika cha Polkit kinachopatikana kwa mwitaji, na kifurushi cha maktaba kilichoathiriwa. CVE-2025-6018 ni njia moja ya kupata session ya mtumiaji aliye active, lakini mtumiaji ambaye tayari yuko active anaweza kufikia njia ya huduma ya diski kivyake.<sup>[[3]](#references)</sup>

Kwa ukaguzi usiobadilisha mfumo, kagua metadata ya huduma ya UDisks, sera ya `org.freedesktop.udisks2.modify-device`, `xfs_growfs`, na kifurushi cha `libbd_fs2` kilichosakinishwa. SUSE inaorodhesha toleo la `libbd_fs2` `2.26-150400.3.5.1` kuwa limerekebishwa kwa openSUSE Leap 15.6; toleo mahususi lililorekebishwa hutegemea bidhaa. Kuwepo kwa sera na kifurushi pekee ni vidokezo, si uthibitisho kwamba mwitaji anaweza kupachika au kubadilisha ukubwa wa kifaa. Epuka kubadilisha mounts au kuita mbinu za D-Bus wakati wa upelelezi.<sup>[[3]](#references)</sup>

## References

- [1] [Ushauri wa SUSE kuhusu CVE-2025-6018](https://www.suse.com/security/cve/CVE-2025-6018.html)
- [2] [Sasisho la usalama la SUSE pam-config](https://www.suse.com/support/update/announcement/2025/suse-su-202502082-1)
- [3] [Ushauri wa SUSE kuhusu CVE-2025-6019](https://www.suse.com/security/cve/CVE-2025-6019.html)
{{#include ../../banners/hacktricks-training.md}}
