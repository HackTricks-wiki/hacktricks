# Indikatori eskalacije preko SUSE sesije i disk-servisa

{{#include ../../banners/hacktricks-training.md}}

## Autorizacija SSH sesije preko PAM-a

CVE-2025-6018 je uticao na SUSE 15 PAM konfiguracije u kojima je SSH stek za autentifikaciju učitavao `pam_env` pre nego što je stek sesije učitao `pam_systemd`. Kada je `pam_env` čitao korisnikov `.pam_environment`, korisnik je mogao da zada vrednosti `XDG_SEAT` i `XDG_VTNR` zbog kojih bi Polkit SSH sesiju smatrao fizički aktivnom. Tada bi akcija `allow_active=yes` mogla da postane dostupna udaljenom korisniku. Time se menja autorizacija sesije; samo po sebi, to ne garantuje pristup root nalogu. SUSE je ispravio podrazumevano ponašanje u vezi sa korisničkim okruženjem u paketu `pam` i pozicioniranje modula koje generiše `pam-config`.<sup>[[1]](#references)[[2]](#references)</sup>

Proverite efektivni lanac uključivanja u `/etc/pam.d/sshd`, redosled `pam_env.so` i `pam_systemd.so`, kao i svaku eksplicitnu opciju `user_readenv=1`. Zakrpljeni paket `pam` menja podrazumevano podešavanje, ali eksplicitna opcija i dalje može da zahteva čitanje korisničkog okruženja. Noviji paket `pam-config` ne dokazuje da je lokalno izmenjeni ili zastareli PAM stek ponovo generisan. Proverite zajedno izdanje paketa dobavljača i stvarnu konfiguraciju.<sup>[[1]](#references)[[2]](#references)</sup>

## Putanja disk-servisa dostupna aktivnom korisniku

CVE-2025-6019 predstavljao je putanju za eskalaciju u `libblockdev`, korišćenu preko `udisks2`: tokom promene veličine XFS particije, fajl sistem koji je obezbedio napadač mogao je privremeno da se montira bez očekivanog ograničenja `nosuid`. Ova putanja zahteva dostupan UDisks D-Bus servis, podršku za promenu veličine XFS particija, relevantnu Polkit akciju dostupnu pozivaocu i pogođenu verziju bibliotečkog paketa. CVE-2025-6018 je jedan od načina da se dobije sesija aktivnog korisnika, ali korisnik koji je već aktivan može nezavisno da pristupi putanji disk-servisa.<sup>[[3]](#references)</sup>

Za pasivni pregled proverite metapodatke UDisks servisa, Polkit pravilo `org.freedesktop.udisks2.modify-device`, `xfs_growfs` i instalirani paket `libbd_fs2`. SUSE navodi da je verzija `libbd_fs2` `2.26-150400.3.5.1` ispravljena za openSUSE Leap 15.6; tačno ispravljeno izdanje zavisi od proizvoda. Samo prisustvo pravila i paketa predstavlja naznaku, a ne dokaz da pozivalac može da montira uređaj ili promeni njegovu veličinu. Tokom enumeracije nemojte menjati montiranja niti pozivati D-Bus metode.<sup>[[3]](#references)</sup>

## References

- [1] [SUSE bezbednosno obaveštenje za CVE-2025-6018](https://www.suse.com/security/cve/CVE-2025-6018.html)
- [2] [SUSE bezbednosno ažuriranje za pam-config](https://www.suse.com/support/update/announcement/2025/suse-su-202502082-1)
- [3] [SUSE bezbednosno obaveštenje za CVE-2025-6019](https://www.suse.com/security/cve/CVE-2025-6019.html)
{{#include ../../banners/hacktricks-training.md}}
