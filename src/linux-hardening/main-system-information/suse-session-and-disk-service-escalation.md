# SUSE-sessie- en skyfdiens-eskalasie-aanwysers

{{#include ../../banners/hacktricks-training.md}}

## SSH-sessiemagtiging deur PAM

CVE-2025-6018 het SUSE 15 PAM-konfigurasies geraak waarin ’n SSH-verifikasiestapel `pam_env` gelaai het voordat die sessiestapel `pam_systemd` gelaai het. Wanneer `pam_env` ’n gebruiker se `.pam_environment` gelees het, kon daardie gebruiker `XDG_SEAT`- en `XDG_VTNR`-waardes verskaf wat ’n SSH-sessie vir Polkit soos ’n fisies aktiewe sessie laat lyk het. ’n `allow_active=yes`-aksie kon toe vir ’n afgeleë gebruiker beskikbaar word. Dit verander sessiemagtiging; dit waarborg nie op sigself worteltoegang nie. SUSE het die verstekgedrag vir gebruikersomgewings in `pam` en die moduleplasing wat deur `pam-config` gegenereer word, reggestel.<sup>[[1]](#references)[[2]](#references)</sup>

Ondersoek die effektiewe `/etc/pam.d/sshd`-insluitketting, die volgorde van `pam_env.so` en `pam_systemd.so`, en enige eksplisiete `user_readenv=1`-opsie. ’n Gelapte `pam`-pakket verander die verstekgedrag, maar ’n eksplisiete opsie kan steeds die lees van die gebruikersomgewing versoek. ’n Nuwer `pam-config`-pakket bewys nie dat ’n plaaslik gewysigde of verouderde PAM-stapel hergenereer is nie. Gaan die verskaffer se pakketweergawe en die werklike konfigurasie saam na.<sup>[[1]](#references)[[2]](#references)</sup>

## Skyfdienspad vir aktiewe gebruikers

CVE-2025-6019 was ’n eskalasiepad in `libblockdev` wat deur `udisks2` gebruik is: tydens ’n XFS-grootteverandering kon ’n aanvallerbeheerde lêerstelsel tydelik gemonteer word sonder die verwagte `nosuid`-beperking. Die pad vereis ’n bruikbare UDisks D-Bus-diens, ondersteuning vir XFS-grootteverandering, ’n relevante Polkit-aksie wat vir die aanroeper beskikbaar is, en ’n geraakte biblioteekpakket. CVE-2025-6018 is een manier om ’n aktiewegebruikersessie te verkry, maar ’n gebruiker wat reeds aktief is, kan die skyfdienspad onafhanklik bereik.<sup>[[3]](#references)</sup>

Gaan tydens ’n passiewe hersiening die UDisks-diensmetadata, die `org.freedesktop.udisks2.modify-device`-beleid, `xfs_growfs` en die geïnstalleerde `libbd_fs2`-pakket na. SUSE lys `libbd_fs2`-weergawe `2.26-150400.3.5.1` as reggestel vir openSUSE Leap 15.6; die presiese reggestelde weergawe hang van die produk af. Die teenwoordigheid van ’n beleid en pakket is op sigself net leidrade, nie bewys dat ’n aanroeper ’n toestel kan monteer of die grootte daarvan kan verander nie. Moenie monterings verander of D-Bus-metodes aanroep tydens enumerasie nie.<sup>[[3]](#references)</sup>

## References

- [1] [SUSE CVE-2025-6018-advies](https://www.suse.com/security/cve/CVE-2025-6018.html)
- [2] [SUSE pam-config-sekuriteitsopdatering](https://www.suse.com/support/update/announcement/2025/suse-su-202502082-1)
- [3] [SUSE CVE-2025-6019-advies](https://www.suse.com/security/cve/CVE-2025-6019.html)
{{#include ../../banners/hacktricks-training.md}}
