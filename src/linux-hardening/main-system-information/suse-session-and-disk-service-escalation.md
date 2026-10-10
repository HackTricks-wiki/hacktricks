# SUSE-sessie- en skyfdiens-eskalasie-aanwysers

{{#include ../../banners/hacktricks-training.md}}

## SSH-sessie-magtiging deur PAM

CVE-2025-6018 het SUSE 15 PAM-konfigurasies geraak waarin ’n SSH-verifikasiestapel `pam_env` gelaai het voordat die sessiestapel `pam_systemd` gelaai het. Wanneer `pam_env` ’n gebruiker se `.pam_environment` gelees het, kon daardie gebruiker `XDG_SEAT`- en `XDG_VTNR`-waardes verskaf wat ’n SSH-sessie vir Polkit soos ’n fisies aktiewe sessie laat lyk het. ’n `allow_active=yes`-aksie kon dan vir ’n afstandgebruiker beskikbaar word. Dit verander sessiemagtiging; dit waarborg nie op sigself root-toegang nie. SUSE het die verstekgedrag vir gebruikersomgewings in `pam` en die moduleplasing wat deur `pam-config` gegenereer word, reggestel.<sup>[[1]](#references)[[2]](#references)</sup>

Inspekteer die effektiewe `/etc/pam.d/sshd`-insluitketting, die volgorde van `pam_env.so` en `pam_systemd.so`, en enige eksplisiete `user_readenv=1`-opsie. ’n Gelapte `pam`-pakket verander die verstekinstelling, maar ’n eksplisiete opsie kan steeds die lees van die gebruikersomgewing versoek. ’n Nuwer `pam-config`-pakket bewys nie dat ’n plaaslik gewysigde of verouderde PAM-stapel hergenereer is nie. Gaan die verskafferpakketvrystelling en die werklike konfigurasie saam na.<sup>[[1]](#references)[[2]](#references)</sup>

## Skyfdiensroete vir aktiewe gebruikers

CVE-2025-6019 was ’n eskalasieroete in `libblockdev` wat deur `udisks2` gebruik is: tydens ’n XFS-vergroting kon ’n aanvallerbeheerde lêerstelsel tydelik gemonteer word sonder die verwagte `nosuid`-beperking. Die roete vereis ’n bruikbare UDisks D-Bus-diens, XFS-vergrotingsondersteuning, ’n toepaslike Polkit-aksie wat vir die oproeper beskikbaar is, en ’n geraakte biblioteekpakket. CVE-2025-6018 is een manier om ’n aktiewe-gebruiker-sessie te verkry, maar ’n gebruiker wat reeds aktief is, kan die skyfdiensroete onafhanklik bereik.<sup>[[3]](#references)</sup>

Gaan vir ’n passiewe hersiening die UDisks-diensmetadata, die `org.freedesktop.udisks2.modify-device`-beleid, `xfs_growfs` en die geïnstalleerde `libbd_fs2`-pakket na. SUSE lys `libbd_fs2`-weergawe `2.26-150400.3.5.1` as reggestel vir openSUSE Leap 15.6; die presiese reggestelde vrystelling hang van die produk af. Die teenwoordigheid van ’n beleid en pakket is bloot leidrade, nie bewys dat ’n oproeper ’n toestel kan monteer of vergroot nie. Vermy dit om monterings te verander of D-Bus-metodes tydens enumerasie aan te roep.<sup>[[3]](#references)</sup>

## References

- [1] [SUSE CVE-2025-6018-advies](https://www.suse.com/security/cve/CVE-2025-6018.html)
- [2] [SUSE pam-config-sekuriteitsopdatering](https://www.suse.com/support/update/announcement/2025/suse-su-202502082-1)
- [3] [SUSE CVE-2025-6019-advies](https://www.suse.com/security/cve/CVE-2025-6019.html)
{{#include ../../banners/hacktricks-training.md}}
