# Indikatori eskalacije preko SUSE sesije i disk-servisa

{{#include ../../banners/hacktricks-training.md}}

## Autorizacija SSH sesije preko PAM-a

CVE-2025-6018 je uticao na SUSE 15 PAM konfiguracije u kojima je SSH stek za autentifikaciju učitavao `pam_env` pre nego što je stek sesije učitao `pam_systemd`. Kada bi `pam_env` pročitao korisnikov `.pam_environment`, korisnik je mogao da navede vrednosti `XDG_SEAT` i `XDG_VTNR` zbog kojih bi Polkit SSH sesiju smatrao fizički aktivnom. Tada bi akcija `allow_active=yes` mogla da postane dostupna udaljenom korisniku. Ovo menja autorizaciju sesije; samo po sebi ne garantuje root pristup. SUSE je ispravio podrazumevano ponašanje za korisničko okruženje u paketu `pam` i poziciju modula koju generiše `pam-config`.<sup>[[1]](#references)[[2]](#references)</sup>

Pregledajte efektivni lanac uključivanja u `/etc/pam.d/sshd`, redosled `pam_env.so` i `pam_systemd.so`, kao i svaku eksplicitnu opciju `user_readenv=1`. Ažurirani paket `pam` menja podrazumevano ponašanje, ali eksplicitna opcija i dalje može da zatraži čitanje korisničkog okruženja. Noviji paket `pam-config` ne dokazuje da je lokalno izmenjeni ili zastareli PAM stek ponovo generisan. Proverite izdanje paketa dobavljača i stvarnu konfiguraciju zajedno.<sup>[[1]](#references)[[2]](#references)</sup>

## Putanja disk-servisa za aktivnog korisnika

CVE-2025-6019 je bila putanja za eskalaciju u `libblockdev`, korišćena preko `udisks2`: tokom promene veličine XFS sistema datoteka, sistem datoteka pod kontrolom napadača mogao je privremeno da se montira bez očekivanog ograničenja `nosuid`. Za ovu putanju su potrebni funkcionalan UDisks D-Bus servis, podrška za promenu veličine XFS sistema datoteka, relevantna Polkit akcija dostupna pozivaocu i ranjiva verzija paketa biblioteke. CVE-2025-6018 je jedan od načina za dobijanje sesije aktivnog korisnika, ali aktivan korisnik može nezavisno da dođe do putanje disk-servisa.<sup>[[3]](#references)</sup>

Za pasivni pregled proverite metapodatke UDisks servisa, pravilo `org.freedesktop.udisks2.modify-device`, `xfs_growfs` i instalirani paket `libbd_fs2`. SUSE navodi da je verzija `libbd_fs2` `2.26-150400.3.5.1` ispravljena za openSUSE Leap 15.6; tačno izdanje sa ispravkom zavisi od proizvoda. Samo prisustvo pravila i paketa predstavlja naznaku, a ne dokaz da pozivalac može da montira uređaj ili promeni njegovu veličinu. Tokom enumeracije nemojte menjati montiranja niti pozivati D-Bus metode.<sup>[[3]](#references)</sup>

## References

- [1] [SUSE savet za CVE-2025-6018](https://www.suse.com/security/cve/CVE-2025-6018.html)
- [2] [SUSE bezbednosno ažuriranje za pam-config](https://www.suse.com/support/update/announcement/2025/suse-su-202502082-1)
- [3] [SUSE savet za CVE-2025-6019](https://www.suse.com/security/cve/CVE-2025-6019.html)
{{#include ../../banners/hacktricks-training.md}}
