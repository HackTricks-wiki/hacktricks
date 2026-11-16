# Ojačavanje Linuxa

{{#include ../banners/hacktricks-training.md}}

Koristite ovaj odeljak za ispitivanje Linux hostova, razumevanje granica privilegija i pregled kontrola koje ograničavaju lokalni pristup. Za opštu procenu počnite od [osnova Linuxa](linux-basics/README.md) i [kontrolne liste za eskalaciju privilegija](main-system-information/linux-privilege-escalation-checklist.md), a zatim pratite relevantnu temu u nastavku.

- [Osnove Linuxa](linux-basics/README.md): metodologija eskalacije privilegija, korisne komande, promenljive okruženja i zaobilaženje ograničenja.
- [Glavne informacije o sistemu](main-system-information/README.md): kernel, moduli, sudo, ponašanje sistema datoteka, jail-ovi i kontrolna lista za eskalaciju.
- [Informacije o korisnicima](user-information/README.md): Linux identiteti, grupe, prosleđivanje SSH agenta i integracija sa Active Directory-jem.
- [Zanimljive datoteke i dozvole](interesting-files-permissions/README.md): putanje sa dozvolom za upis, capabilities, SUID ponašanje, NFS, proširivanje džoker znakova i SELinux.
- [Mrežne informacije](network-information/README.md): lokalni servisi, socket-i i primeri eksploatacije povezani sa mrežom.
- [Informacije o softveru](software-information/README.md): moduli za autentifikaciju i površine napada specifične za aplikacije.
- [Procesi, crontab, systemd i D-Bus](processes-crontab-systemd-dbus/README.md): zakazano izvršavanje i međuprocesna komunikacija.
- [Kontejneri i namespace-ovi](containers-namespaces/README.md): runtime okruženja, granice izolacije i ojačavanje kontejnera.
- [Zloupotreba AppArmor datoteke za kontrolu politike](containers-namespaces/container-security/protections/apparmor.md#policy-control-files-as-a-privileged-write-primitive): procenite da li privilegovani pomoćni program može da piše u AppArmor kontrolnu datoteku koju je otvorio lokalni korisnik.
- [Post-exploitation](post-exploitation/README.md): otkrivanje akreditiva, persistence i tehnike za dalje aktivnosti na nivou hosta.

Na pogođenim kernelima, neprivilegovani korisnik može uspešno da otvori AppArmor securityfs kontrolnu datoteku politike, iako je direktan upis odbijen. Ako privilegovani pomoćni program nasledi tu datoteku kao stdout, njegov upis može da promeni učitanu politiku; ovo je zaseban lokalni put napada, a ne samo pronalaženje slabe politike kontejnera. Pre testiranja proverite ispravke za kernel i pomoćne programe koje je objavio dobavljač.<sup>[[1]](#references)[[2]](#references)</sup>



## References

- [1] [Tehničko upozorenje kompanije Qualys o CrackArmor-u](https://cdn2.qualys.com/advisory/2026/03/10/crack-armor.txt)
- [2] [Baza znanja o ranjivosti CrackArmor-a kompanije Ubuntu](https://ubuntu.com/security/vulnerabilities/crackarmor)
{{#include ../banners/hacktricks-training.md}}
