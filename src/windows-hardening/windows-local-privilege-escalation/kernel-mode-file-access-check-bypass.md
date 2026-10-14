# Zaobilaženje provera pristupa datotekama u kernel režimu

{{#include ../../banners/hacktricks-training.md}}

## Ranjivi obrazac drajvera

Drajver ne čuva bezbednosnu granicu pozivaoca samo time što se predstavlja kao taj pozivalac. Otvaranje objekata iz kernel režima obično zaobilazi provere pristupa. `OBJ_KERNEL_HANDLE` samo čini dobijeni handle dostupnim iz kernel režima. Kada drajver otvara objekat ili manipuliše njime u ime korisničkog režima, mora da koristi i `OBJ_FORCE_ACCESS_CHECK` kako bi Object Manager proverio traženi pristup u odnosu na efektivni token.<sup>[[3]](#references)[[4]](#references)</sup>

Proverite IOCTL-ove za rad sa datotekama i create callback funkcije da biste utvrdili da li se dešava sledeći sled:<sup>[[3]](#references)[[4]](#references)</sup>

1. Korisnički režim zadaje putanju, source handle, željeni pristup ili tip operacije.
2. Drajver se predstavlja kao pozivalac, ali poziva `IoCreateFileEx`, `ZwCreateFile` ili sličnu rutinu bez `OBJ_FORCE_ACCESS_CHECK`.
3. Handle datoteke ili direktorijuma dostupnog samo iz kernela čuva se u stanju po handle-u.
4. Kasnija operacija odlučuje da li će se predstavljati kao pozivalac na osnovu stanja pod uticajem napadača, kao što je maska pristupa zatražena prilikom prvog otvaranja.
5. Privilegovana grana obavlja preimenovanje ili kreiranje linka pomoću klase informacija `BypassAccessCheck`.

Ovo je **file primitive sa zbunjenim posrednikom**, a ne nužno oštećenje memorije. Posebno opasna inverzija stanja je „zatraženo je pisanje znači predstavljanje kao pozivalac; nije zatraženo pisanje znači ostati privilegovan“. U takvom dizajnu, namerno traženje samo pristupa za čitanje može da otključa moćniji put.<sup>[[3]](#references)</sup>

## vSMB primer: privilegovani root i privilegovano preimenovanje

`storvsp.sys` implementira Virtual Server Message Block (vSMB). Kada je omogućena funkcija **Virtual Machine Platform**, korisnički režim može da pristupi uređaju `\Device\STORVSP` preko `\\.\STORVSP`. Putanja vSMB sistema datoteka ima oblik `\\.\STORVSP\VSMB\??\C:\path`. CVE-2025-59517 i CVE-2025-64673 pokazali su kako dve nedosledne odluke o kontroli pristupa mogu da pretvore ovaj interfejs u lokalnu eskalaciju privilegija.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

Mapiranje funkcija iz izvornog koda na CVE-ove zasnovano je na reverznom inženjeringu zakrpljenog binarnog fajla, a ne na Microsoftovom izvornom kodu. Istraživači upozoravaju da bi ova dva identifikatora mogla da odgovaraju suprotnim funkcijama.<sup>[[3]](#references)</sup>

### 1. Kreirajte deljenje samo za čitanje sa korenom u zaštićenom direktorijumu

Ranjivi put kreiranja beležio je zatražena prava u trajnim zastavicama kao što su `HasReadAccess`, `HasWriteAccess` i `HasAppendAccess`. Zatim je otvarao putanju do pozadinske datoteke pomoću `OBJ_KERNEL_HANDLE`, ali bez `OBJ_FORCE_ACCESS_CHECK`. Zbog toga pokušaj predstavljanja kao pozivalac nije doveo do toga da se pri otvaranju datoteke poštuju NTFS dozvole pozivaoca.<sup>[[3]](#references)[[4]](#references)</sup>

Zatražite samo `FILE_READ_DATA`. Time `HasWriteAccess` ostaje isključeno, a ipak se dobija deljenje čiji je interni koren zaštićeni direktorijum:<sup>[[3]](#references)</sup>

```c
HANDLE root = CreateFileW(
    L"\\\\.\\STORVSP\\VSMB\\??\\C:\\Windows\\System32\\",
    FILE_READ_DATA,
    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
    NULL, OPEN_EXISTING,
    FILE_FLAG_BACKUP_SEMANTICS | FILE_ATTRIBUTE_DIRECTORY,
    NULL
);
```

Važan artefakt nije handle direktorijuma System32 u user-mode-u. To je handle vSMB uređaja povezan sa stanjem driver-a koje sadrži privilegovani root handle kernela.<sup>[[3]](#references)</sup>

### 2. Pretvorite nepodudaranje stanja u zaštićenu zamenu fajla

IOCTL `0x240330` prihvatao je handle izvornog fajla, klasu informacija i bafer informacija promenljive dužine:<sup>[[3]](#references)</sup>

```c
#define IOCTL_VSMB_SET_INFORMATION_FILE_REQUEST 0x240330

typedef struct _VSMB_SET_INFO {
    DWORD Version;
    DWORD Reserved;
    UINT64 SourceHandle;
    DWORD InformationClass;
    DWORD BufferLength;
    BYTE Buffer[1];
} VSMB_SET_INFO;
```

Ranjivi handler prihvatao je `FileRenameInformation`, `FileLinkInformation` i `FileRenameInformationEx`. Za uobičajenu putanju preimenovanja razdvajao je putanju nadređenog direktorijuma od završne komponente, a zatim otvarao nadređeni direktorijum relativno u odnosu na sačuvani root handle. To otvaranje ponovo je koristilo `OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE`, bez `OBJ_FORCE_ACCESS_CHECK`. Nenulta vrednost `RootDirectory` koju je napadač prosledio unutar strukture za preimenovanje bila je odbijana, pa je upravljački program obezbeđivao sopstveni privilegovani handle direktorijuma.<sup>[[3]](#references)</sup>

Eksploatabilna grana birala se tako što se u fazi 1 **nije** tražio pristup za pisanje:<sup>[[3]](#references)</sup>

- `HasWriteAccess == 1`: impersonate sačuvani bezbednosni kontekst root-a.
- `HasWriteAccess == 0`: preskoči impersonation i konvertuj `FileRenameInformation` ili `FileRenameInformationEx` u odgovarajuću `BypassAccessCheck` varijantu.

Handler je duplirao handle izvornog objekta koji je prosledio napadač u `PsInitialSystemProcess`, referencirao ga kao file object, postavio privilegovani handle ciljnog direktorijuma u strukturu za preimenovanje i pozvao `ZwSetInformationFile`. Kada je `ReplaceIfExists = TRUE`, datoteka pod kontrolom pozivaoca je stoga mogla da zameni postojeću datoteku ispod zaštićenog root direktorijuma.<sup>[[3]](#references)</sup>

Pri analizi sličnog handler-a, pratite **poreklo handle-ova i bezbednosni kontekst** kroz sve grane. Validacija ulaza, provere integer overflow-a, `IO_STOP_ON_SYMLINK` i ograničavanje dozvoljenih information class-ova ne nadoknađuju kombinaciju privilegovanog root handle-a i operacije koja zaobilazi proveru pristupa.<sup>[[3]](#references)</sup>

## Od zaštićenog upisa do izvršavanja kao SYSTEM

Primitivna operacija zamene zaštićene datoteke postaje izvršavanje koda kada privilegovani proces naknadno učita zamenjeni modul. U demonstriranom lancu, odredište je bilo `C:\Windows\System32\wuapi.dll`. Aktiviranje lokalne COM klase servera `{72566E27-1ABB-4EB3-B4F0-EB431CB1CB32}` za interfejs `{b4c1d279-966e-44e9-a9c5-ccaf4a77023d}` i pozivanje `IWaaSRemediation::LaunchDetectionOnly()` dovelo je do toga da SYSTEM proces učita tu DLL datoteku.<sup>[[3]](#references)</sup>

Ovaj COM poziv je **okidač za aktivaciju**, a ne [COM registry hijacking](com-hijacking.md). Primitivna operacija nad datotekom obezbeđuje podmetnuti modul, a privilegovani loader njegovo izvršavanje. Za druge lance koji koriste zaštićeni upis, utvrdite tačnu sliku procesa, putanju DLL datoteke, potpisnu politiku, bitnost, eksportovane funkcije i pouzdan okidač pre nego što izaberete cilj. Za opšti postupak analize loader-a pogledajte [chaining an arbitrary file write into DLL hijacking](dll-hijacking/#chaining-an-arbitrary-file-write-into-a-missing-dll-hijack).<sup>[[3]](#references)</sup>

### Premeštanje Session 0 token-a na interaktivnu radnu površinu

Payload koji učita servis obično se izvršava u Session 0. Da bi kreirao interaktivni proces, može da pribavi aktivnu sesiju konzole pomoću `WTSGetActiveConsoleSessionId`, omogući potrebne privilegije token-a, duplira trenutni SYSTEM token kao primarni token i postavi njegov `TokenSessionId` na aktivnu sesiju. Zatim `CreateProcessAsUserW` koristi taj token sa `STARTUPINFO.lpDesktop = L"winsta0\\default"`.<sup>[[3]](#references)[[5]](#references)</sup>

```c
DWORD sid = WTSGetActiveConsoleSessionId();
DuplicateTokenEx(currentToken, MAXIMUM_ALLOWED, NULL,
                 SecurityImpersonation, TokenPrimary, &primary);
SetTokenInformation(primary, TokenSessionId, &sid, sizeof(sid));
si.lpDesktop = L"winsta0\\default";
CreateProcessAsUserW(primary, L"C:\\Windows\\System32\\cmd.exe",
                     NULL, NULL, NULL, FALSE, CREATE_NEW_CONSOLE,
                     NULL, NULL, &si, &pi);
```

`SeTcbPrivilege` je potreban za postavljanje ID-ja sesije tokena u ovom scenariju. Interaktivna window station i desktop takođe moraju da odobre pristup tokenu. Pogledajte [dupliciranje tokena iz Session 0](sedebug-+-seimpersonate-copy-token.md) za širi tok rada kopiranja tokena.<sup>[[3]](#references)[[5]](#references)</sup>

## Smernice za zakrpe i pregled

Microsoft-ova ažuriranja iz decembra 2025. ispravila su demonstrirani lanac. Obrnutim inženjeringom je utvrđeno da zakrpljena putanja za kreiranje vSMB-a odbacuje nepouzdane pozivaoce koji zahtevaju koren deljenog resursa bez `FILE_WRITE_DATA`. Za relevantne operacije uvedena je i prinudna provera pristupa. Time se sprečava inverzija stanja pre nego što neprivilegovani pozivalac može da dobije privilegovani koren.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

Za kod drajvera primenite ova pravila:<sup>[[3]](#references)[[4]](#references)</sup>

- Dodajte `OBJ_FORCE_ACCESS_CHECK` kad god se objekat otvara u ime zahteva iz korisničkog režima. Nemojte tretirati `OBJ_KERNEL_HANDLE` kao kontrolu autorizacije.<sup>[[4]](#references)</sup>
- Uhvatite i proverite režim podnosioca zahteva i efektivni kontekst subjekta. Ne dozvolite da tražena prava odaberu izvršnu granu sa višim privilegijama.
- Proveravajte korisničke handle-ove koristeći ispravan tip objekta, masku pristupa i `UserMode`. Dupliranje handle-a u sistemski proces ne proverava ovlašćenje za traženu operaciju.
- Zadržite razrešavanje cilja relativnim u odnosu na pouzdani handle, ali proverite da li je sam pouzdani handle otvoren uz sprovedenu proveru pristupa podnosioca zahteva.
- Izbegavajte klase `File*BypassAccessCheck` za operacije pokrenute od korisnika. Ako im je interni kod zaista potreban, ograničite tu putanju одлуком о ауторизацији која је независна од заставица приступа које контролише корисник.
- Закрпите погођене системе. Рањива површина је релевантна када Virtual Machine Platform учитава `storvsp.sys`.<sup>[[3]](#references)</sup>

## References

- [1] [Microsoft Security Response Center - CVE-2025-59517](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-59517)
- [2] [Microsoft Security Response Center - CVE-2025-64673](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-64673)
- [3] [Exodus Intelligence - Од виртуелног дељеног ресурса до физичке љуске: искоришћавање недоследне контроле приступа у Windows-у за LPE](https://blog.exodusintel.com/2026/07/27/from-virtual-share-to-physical-shell-leveraging-windows-inconsistent-access-control-for-lpe/)
- [4] [Microsoft Learn - Handle-ови објеката](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/object-handles)
- [5] [Microsoft Learn - Функција CreateProcessAsUserW](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessasuserw)
{{#include ../../banners/hacktricks-training.md}}
