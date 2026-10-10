# Viashiria vya Kuinua Haki kupitia Session na Huduma ya Diski ya SUSE

{{#include ../../banners/hacktricks-training.md}}

## Uidhinishaji wa session ya SSH kupitia PAM

CVE-2025-6018 iliathiri usanidi wa PAM wa SUSE 15 ambapo stack ya uthibitishaji wa SSH ilipakia `pam_env` kabla stack ya session haijapakia `pam_systemd`. `pam_env` iliposoma `.pam_environment` ya mtumiaji, mtumiaji huyo angeweza kutoa thamani za `XDG_SEAT` na `XDG_VTNR` zilizofanya session ya SSH ionekane kwa Polkit kana kwamba inatumika moja kwa moja kwenye kifaa halisi. Kisha hatua ya `allow_active=yes` ingeweza kupatikana kwa mtumiaji wa mbali. Hili hubadilisha uidhinishaji wa session; peke yake halihakikishi ufikiaji wa root. SUSE ilirekebisha tabia chaguomsingi ya mazingira ya mtumiaji katika `pam` na uwekaji wa moduli unaozalishwa na `pam-config`.<sup>[[1]](#references)[[2]](#references)</sup>

Kagua mnyororo halisi wa `include` katika `/etc/pam.d/sshd`, mpangilio wa `pam_env.so` na `pam_systemd.so`, pamoja na chaguo lolote la wazi la `user_readenv=1`. Kifurushi cha `pam` kilichowekewa viraka hubadilisha chaguo-msingi, lakini chaguo lililowekwa wazi bado linaweza kuruhusu usomaji wa mazingira ya mtumiaji. Kifurushi kipya cha `pam-config` hakithibitishi kuwa stack ya PAM iliyobadilishwa ndani ya mfumo au iliyopitwa na wakati ilitengenezwa upya. Kagua toleo la kifurushi la muuzaji pamoja na usanidi halisi.<sup>[[1]](#references)[[2]](#references)</sup>

## Njia ya huduma ya diski kwa mtumiaji aliye hai

CVE-2025-6019 ilikuwa njia ya kuinua haki katika `libblockdev` iliyotumiwa kupitia `udisks2`: wakati wa kubadilisha ukubwa wa XFS, mfumo wa faili uliotolewa na mshambulizi ungeweza kupachikwa kwa muda bila kizuizi cha `nosuid` kilichotarajiwa. Njia hii inahitaji huduma ya UDisks D-Bus inayoweza kutumika, usaidizi wa kubadilisha ukubwa wa XFS, kitendo husika cha Polkit kinachopatikana kwa mtumiaji, na kifurushi cha maktaba kilichoathiriwa. CVE-2025-6018 ni njia mojawapo ya kupata session ya mtumiaji aliye hai, lakini mtumiaji aliye hai tayari anaweza kufikia njia ya huduma ya diski bila hiyo.<sup>[[3]](#references)</sup>

Kwa ukaguzi usiobadilisha hali ya mfumo, kagua metadata ya huduma ya UDisks, sera ya `org.freedesktop.udisks2.modify-device`, `xfs_growfs`, na kifurushi cha `libbd_fs2` kilichosakinishwa. SUSE inaorodhesha toleo la `libbd_fs2` `2.26-150400.3.5.1` kuwa limerekebishwa kwa openSUSE Leap 15.6; toleo halisi lililorekebishwa hutegemea bidhaa. Kuwepo kwa sera na kifurushi ni vidokezo tu, si uthibitisho kuwa mtumiaji anaweza kupachika au kubadilisha ukubwa wa kifaa. Epuka kubadilisha sehemu zilizopachikwa au kuita mbinu za D-Bus wakati wa kuorodhesha mifumo.<sup>[[3]](#references)</sup>

## References

- [1] [Tangazo la SUSE kuhusu CVE-2025-6018](https://www.suse.com/security/cve/CVE-2025-6018.html)
- [2] [Sasisho la usalama la SUSE pam-config](https://www.suse.com/support/update/announcement/2025/suse-su-202502082-1)
- [3] [Tangazo la SUSE kuhusu CVE-2025-6019](https://www.suse.com/security/cve/CVE-2025-6019.html)
{{#include ../../banners/hacktricks-training.md}}
