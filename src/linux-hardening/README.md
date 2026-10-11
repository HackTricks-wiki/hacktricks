# Ojačavanje Linuxa

{{#include ../banners/hacktricks-training.md}}

Koristite ovaj odeljak za ispitivanje Linux hostova, razumevanje granica privilegija i pregled kontrola koje ograničavaju lokalni pristup. Za opštu procenu počnite od [osnova Linuxa](linux-basics/README.md) i [kontrolne liste za eskalaciju privilegija](main-system-information/linux-privilege-escalation-checklist.md), a zatim pređite na odgovarajuću temu u nastavku.

- [Osnove Linuxa](linux-basics/README.md): metodologija eskalacije privilegija, korisne komande, promenljive okruženja i zaobilaženje ograničenja.
- [Glavne informacije o sistemu](main-system-information/README.md): kernel, moduli, sudo, ponašanje sistema datoteka, jail-ovi i kontrolna lista za eskalaciju.
- [Informacije o korisnicima](user-information/README.md): Linux identiteti, grupe, prosleđivanje SSH agenta i integracija sa Active Directory-jem.
- [Zanimljive datoteke i dozvole](interesting-files-permissions/README.md): putanje sa dozvolom za upis, capabilities, SUID ponašanje, NFS, proširivanje wildcard znakova i SELinux.
- [Informacije o mreži](network-information/README.md): lokalne usluge, soketi i primeri eksploatacije povezani sa mrežom.
- [Informacije o softveru](software-information/README.md): moduli za autentifikaciju i površine napada specifične za aplikacije.
- [Procesi, crontab, systemd i D-Bus](processes-crontab-systemd-dbus/README.md): planirano izvršavanje i međuprocesna komunikacija.
- [Kontejneri i namespaces](containers-namespaces/README.md): runtime okruženja, granice izolacije i ojačavanje bezbednosti kontejnera.
- [Post-eksploatacija](post-exploitation/README.md): otkrivanje akreditiva, postojanost pristupa i tehnike za dalje ispitivanje hosta.
{{#include ../banners/hacktricks-training.md}}
