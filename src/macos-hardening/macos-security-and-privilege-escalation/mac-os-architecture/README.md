# macOS Kernel & System Extensions

{{#include ../../../banners/hacktricks-training.md}}

## XNU Kernel

**Osnova macOS je XNU**, što znači "X nije Unix". Ovaj kernel se fundamentalno sastoji od **Mach mikrokerne**la (o kojem će biti reči kasnije), **i** elemenata iz Berkeley Software Distribution (**BSD**). XNU takođe pruža platformu za **kernel drajvere putem sistema nazvanog I/O Kit**. XNU kernel je deo Darwin open source projekta, što znači da je **njegov izvorni kod slobodno dostupan**.

Iz perspektive istraživača bezbednosti ili Unix programera, **macOS** može delovati prilično **slično** **FreeBSD** sistemu sa elegantnim GUI-jem i mnoštvom prilagođenih aplikacija. Većina aplikacija razvijenih za BSD će se kompajlirati i raditi na macOS bez potrebe za modifikacijama, jer su svi komandno-linijski alati poznati korisnicima Unixa prisutni u macOS-u. Međutim, pošto XNU kernel uključuje Mach, postoje neke značajne razlike između tradicionalnog Unix-sličnog sistema i macOS-a, a te razlike mogu izazvati potencijalne probleme ili pružiti jedinstvene prednosti.

Open source verzija XNU: [https://opensource.apple.com/source/xnu/](https://opensource.apple.com/source/xnu/)

### Mach

Mach je **mikrokernel** dizajniran da bude **UNIX-kompatibilan**. Jedan od njegovih ključnih dizajnerskih principa bio je da **minimizuje** količinu **koda** koji se izvršava u **kernel** prostoru i umesto toga dozvoli mnogim tipičnim kernel funkcijama, kao što su sistem datoteka, umrežavanje i I/O, da **rade kao korisnički zadaci**.

U XNU, Mach je **odgovoran za mnoge kritične niskonivo operacije** koje kernel obično obrađuje, kao što su planiranje procesora, multitasking i upravljanje virtuelnom memorijom.

### BSD

XNU **kernel** takođe **uključuje** značajnu količinu koda izvedenog iz **FreeBSD** projekta. Ovaj kod **radi kao deo kernela zajedno sa Mach**, u istom adresnom prostoru. Međutim, FreeBSD kod unutar XNU može se značajno razlikovati od originalnog FreeBSD koda jer su modifikacije bile potrebne da bi se osigurala njegova kompatibilnost sa Mach. FreeBSD doprinosi mnogim kernel operacijama uključujući:

- Upravljanje procesima
- Obrada signala
- Osnovni bezbednosni mehanizmi, uključujući upravljanje korisnicima i grupama
- Infrastruktura sistemskih poziva
- TCP/IP stek i soketi
- Firewall i filtriranje paketa

Razumevanje interakcije između BSD i Mach može biti složeno, zbog njihovih različitih konceptualnih okvira. Na primer, BSD koristi procese kao svoju osnovnu izvršnu jedinicu, dok Mach funkcioniše na osnovu niti. Ova razlika se pomiruje u XNU tako što se **svakom BSD procesu pridružuje Mach zadatak** koji sadrži tačno jednu Mach nit. Kada se koristi BSD-ov fork() sistemski poziv, BSD kod unutar kernela koristi Mach funkcije za kreiranje strukture zadatka i niti.

Štaviše, **Mach i BSD svaki održavaju različite bezbednosne modele**: **Machov** bezbednosni model se zasniva na **pravima portova**, dok BSD-ov bezbednosni model funkcioniše na osnovu **vlasništva procesa**. Razlike između ova dva modela su povremeno rezultirale lokalnim ranjivostima za eskalaciju privilegija. Pored tipičnih sistemskih poziva, postoje i **Mach zamke koje omogućavaju programima u korisničkom prostoru da komuniciraju sa kernelom**. Ovi različiti elementi zajedno čine složenu, hibridnu arhitekturu macOS kernela.

### I/O Kit - Drajveri

I/O Kit je open-source, objektno orijentisan **okvir za drajvere uređaja** u XNU kernelu, koji upravlja **dinamički učitanim drajverima uređaja**. Omogućava dodavanje modularnog koda u kernel u hodu, podržavajući raznovrsni hardver.

{{#ref}}
macos-iokit.md
{{#endref}}

### IPC - Inter Process Communication

{{#ref}}
../macos-proces-abuse/macos-ipc-inter-process-communication/
{{#endref}}

## macOS Kernel Extensions

macOS je **super restriktivan za učitavanje Kernel Extensions** (.kext) zbog visokih privilegija sa kojima će kod raditi. U stvari, po defaultu je praktično nemoguće (osim ako se ne pronađe zaobilaženje).

Na sledećoj stranici možete takođe videti kako da povratite `.kext` koji macOS učitava unutar svog **kernelcache**:

{{#ref}}
macos-kernel-extensions.md
{{#endref}}

### macOS System Extensions

Umesto korišćenja Kernel Extensions, macOS je stvorio System Extensions, koje nude API-je na korisničkom nivou za interakciju sa kernelom. Na ovaj način, programeri mogu da izbegnu korišćenje kernel ekstenzija.

{{#ref}}
macos-system-extensions.md
{{#endref}}

## References

- [**The Mac Hacker's Handbook**](https://www.amazon.com/-/es/Charlie-Miller-ebook-dp-B004U7MUMU/dp/B004U7MUMU/ref=mt_other?_encoding=UTF8&me=&qid=)
- [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)

{{#include ../../../banners/hacktricks-training.md}}
