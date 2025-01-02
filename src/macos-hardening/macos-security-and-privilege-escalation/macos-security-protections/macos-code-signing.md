# macOS Code Signing

{{#include ../../../banners/hacktricks-training.md}}

## Podstawowe informacje

Binarne pliki Mach-o zawierają polecenie ładujące zwane **`LC_CODE_SIGNATURE`**, które wskazuje **offset** i **rozmiar** podpisów wewnątrz binarnego pliku. W rzeczywistości, używając narzędzia GUI MachOView, można znaleźć na końcu binarnego pliku sekcję o nazwie **Code Signature** z tymi informacjami:

<figure><img src="../../../images/image (1) (1) (1) (1).png" alt="" width="431"><figcaption></figcaption></figure>

Magiczny nagłówek podpisu kodu to **`0xFADE0CC0`**. Następnie znajdują się informacje takie jak długość i liczba blobów superBlob, które je zawierają.\
Można znaleźć te informacje w [kodzie źródłowym tutaj](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/osfmk/kern/cs_blobs.h#L276):
```c
/*
* Structure of an embedded-signature SuperBlob
*/

typedef struct __BlobIndex {
uint32_t type;                                  /* type of entry */
uint32_t offset;                                /* offset of entry */
} CS_BlobIndex
__attribute__ ((aligned(1)));

typedef struct __SC_SuperBlob {
uint32_t magic;                                 /* magic number */
uint32_t length;                                /* total length of SuperBlob */
uint32_t count;                                 /* number of index entries following */
CS_BlobIndex index[];                   /* (count) entries */
/* followed by Blobs in no particular order as indicated by offsets in index */
} CS_SuperBlob
__attribute__ ((aligned(1)));

#define KERNEL_HAVE_CS_GENERICBLOB 1
typedef struct __SC_GenericBlob {
uint32_t magic;                                 /* magic number */
uint32_t length;                                /* total length of blob */
char data[];
} CS_GenericBlob
__attribute__ ((aligned(1)));
```
Zwykłe bloby zawierają Code Directory, Requirements i Entitlements oraz Cryptographic Message Syntax (CMS).\
Ponadto, zauważ, że dane zakodowane w blobach są zakodowane w **Big Endian.**

Ponadto, podpisy mogą być odłączane od binarnych plików i przechowywane w `/var/db/DetachedSignatures` (używane przez iOS).

## Code Directory Blob

Możliwe jest znalezienie deklaracji [Code Directory Blob w kodzie](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/osfmk/kern/cs_blobs.h#L104):
```c
typedef struct __CodeDirectory {
uint32_t magic;                                 /* magic number (CSMAGIC_CODEDIRECTORY) */
uint32_t length;                                /* total length of CodeDirectory blob */
uint32_t version;                               /* compatibility version */
uint32_t flags;                                 /* setup and mode flags */
uint32_t hashOffset;                    /* offset of hash slot element at index zero */
uint32_t identOffset;                   /* offset of identifier string */
uint32_t nSpecialSlots;                 /* number of special hash slots */
uint32_t nCodeSlots;                    /* number of ordinary (code) hash slots */
uint32_t codeLimit;                             /* limit to main image signature range */
uint8_t hashSize;                               /* size of each hash in bytes */
uint8_t hashType;                               /* type of hash (cdHashType* constants) */
uint8_t platform;                               /* platform identifier; zero if not platform binary */
uint8_t pageSize;                               /* log2(page size in bytes); 0 => infinite */
uint32_t spare2;                                /* unused (must be zero) */

char end_earliest[0];

/* Version 0x20100 */
uint32_t scatterOffset;                 /* offset of optional scatter vector */
char end_withScatter[0];

/* Version 0x20200 */
uint32_t teamOffset;                    /* offset of optional team identifier */
char end_withTeam[0];

/* Version 0x20300 */
uint32_t spare3;                                /* unused (must be zero) */
uint64_t codeLimit64;                   /* limit to main image signature range, 64 bits */
char end_withCodeLimit64[0];

/* Version 0x20400 */
uint64_t execSegBase;                   /* offset of executable segment */
uint64_t execSegLimit;                  /* limit of executable segment */
uint64_t execSegFlags;                  /* executable segment flags */
char end_withExecSeg[0];

/* Version 0x20500 */
uint32_t runtime;
uint32_t preEncryptOffset;
char end_withPreEncryptOffset[0];

/* Version 0x20600 */
uint8_t linkageHashType;
uint8_t linkageApplicationType;
uint16_t linkageApplicationSubType;
uint32_t linkageOffset;
uint32_t linkageSize;
char end_withLinkage[0];

/* followed by dynamic content as located by offset fields above */
} CS_CodeDirectory
__attribute__ ((aligned(1)));
```
Zauważ, że istnieją różne wersje tej struktury, w których starsze mogą zawierać mniej informacji.

## Strony podpisu kodu

Haszowanie pełnego binarnego pliku byłoby nieefektywne, a nawet bezużyteczne, jeśli jest on ładowany w pamięci tylko częściowo. Dlatego podpis kodu jest w rzeczywistości haszem haszy, gdzie każda strona binarna jest haszowana indywidualnie.\
W rzeczywistości, w poprzednim kodzie **Code Directory** możesz zobaczyć, że **rozmiar strony jest określony** w jednym z jego pól. Co więcej, jeśli rozmiar binarnego pliku nie jest wielokrotnością rozmiaru strony, pole **CodeLimit** określa, gdzie kończy się podpis.
```bash
# Get all hashes of /bin/ps
codesign -d -vvvvvv /bin/ps
[...]
CandidateCDHash sha256=c46e56e9490d93fe35a76199bdb367b3463c91dc
CandidateCDHashFull sha256=c46e56e9490d93fe35a76199bdb367b3463c91dcdb3c46403ab8ba1c2d13fd86
Hash choices=sha256
CMSDigest=c46e56e9490d93fe35a76199bdb367b3463c91dcdb3c46403ab8ba1c2d13fd86
CMSDigestType=2
Executable Segment base=0
Executable Segment limit=32768
Executable Segment flags=0x1
Page size=4096
-7=a542b4dcbc134fbd950c230ed9ddb99a343262a2df8e0c847caee2b6d3b41cc8
-6=0000000000000000000000000000000000000000000000000000000000000000
-5=2bb2de519f43b8e116c7eeea8adc6811a276fb134c55c9c2e9dcbd3047f80c7d
-4=0000000000000000000000000000000000000000000000000000000000000000
-3=0000000000000000000000000000000000000000000000000000000000000000
-2=4ca453dc8908dc7f6e637d6159c8761124ae56d080a4a550ad050c27ead273b3
-1=0000000000000000000000000000000000000000000000000000000000000000
0=a5e6478f89812c0c09f123524cad560a9bf758d16014b586089ddc93f004e39c
1=ad7facb2586fc6e966c004d7d1d16b024f5805ff7cb47c7a85dabd8b48892ca7
2=93d476eeace15a5ad14c0fb56169fd080a04b99582b4c7a01e1afcbc58688f
[...]

# Calculate the hasehs of each page manually
BINARY=/bin/ps
SIZE=`stat -f "%Z" $BINARY`
PAGESIZE=4096 # From the previous output
PAGES=`expr $SIZE / $PAGESIZE`
for i in `seq 0 $PAGES`; do
dd if=$BINARY of=/tmp/`basename $BINARY`.page.$i bs=$PAGESIZE skip=$i count=1
done
openssl sha256 /tmp/*.page.*
```
## Entitlements Blob

Zauważ, że aplikacje mogą również zawierać **blob uprawnień**, w którym zdefiniowane są wszystkie uprawnienia. Co więcej, niektóre binaria iOS mogą mieć swoje uprawnienia specyficzne w specjalnym slocie -7 (zamiast w specjalnym slocie -5 dla uprawnień).

## Special Slots

Aplikacje MacOS nie mają wszystkiego, co potrzebne do wykonania wewnątrz binarnego, ale korzystają również z **zewnętrznych zasobów** (zwykle wewnątrz **bundla** aplikacji). Dlatego w binarnym znajdują się pewne sloty, które będą zawierać hashe niektórych interesujących zewnętrznych zasobów, aby sprawdzić, czy nie zostały zmodyfikowane.

W rzeczywistości można zobaczyć w strukturach Code Directory parametr zwany **`nSpecialSlots`**, który wskazuje liczbę specjalnych slotów. Nie ma slotu specjalnego 0, a najczęstsze z nich (od -1 do -6) to:

- Hash `info.plist` (lub ten wewnątrz `__TEXT.__info__plist`).
- Hash Wymagań
- Hash Katalogu Zasobów (hash pliku `_CodeSignature/CodeResources` wewnątrz bundla).
- Specyficzny dla aplikacji (niewykorzystany)
- Hash uprawnień
- Tylko podpisy kodu DMG
- Uprawnienia DER

## Code Signing Flags

Każdy proces ma powiązany bitmaskę znaną jako `status`, która jest inicjowana przez jądro, a niektóre z nich mogą być nadpisane przez **podpis kodu**. Te flagi, które mogą być zawarte w podpisie kodu, są [zdefiniowane w kodzie](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/osfmk/kern/cs_blobs.h#L36):
```c
/* code signing attributes of a process */
#define CS_VALID                    0x00000001  /* dynamically valid */
#define CS_ADHOC                    0x00000002  /* ad hoc signed */
#define CS_GET_TASK_ALLOW           0x00000004  /* has get-task-allow entitlement */
#define CS_INSTALLER                0x00000008  /* has installer entitlement */

#define CS_FORCED_LV                0x00000010  /* Library Validation required by Hardened System Policy */
#define CS_INVALID_ALLOWED          0x00000020  /* (macOS Only) Page invalidation allowed by task port policy */

#define CS_HARD                     0x00000100  /* don't load invalid pages */
#define CS_KILL                     0x00000200  /* kill process if it becomes invalid */
#define CS_CHECK_EXPIRATION         0x00000400  /* force expiration checking */
#define CS_RESTRICT                 0x00000800  /* tell dyld to treat restricted */

#define CS_ENFORCEMENT              0x00001000  /* require enforcement */
#define CS_REQUIRE_LV               0x00002000  /* require library validation */
#define CS_ENTITLEMENTS_VALIDATED   0x00004000  /* code signature permits restricted entitlements */
#define CS_NVRAM_UNRESTRICTED       0x00008000  /* has com.apple.rootless.restricted-nvram-variables.heritable entitlement */

#define CS_RUNTIME                  0x00010000  /* Apply hardened runtime policies */
#define CS_LINKER_SIGNED            0x00020000  /* Automatically signed by the linker */

#define CS_ALLOWED_MACHO            (CS_ADHOC | CS_HARD | CS_KILL | CS_CHECK_EXPIRATION | \
CS_RESTRICT | CS_ENFORCEMENT | CS_REQUIRE_LV | CS_RUNTIME | CS_LINKER_SIGNED)

#define CS_EXEC_SET_HARD            0x00100000  /* set CS_HARD on any exec'ed process */
#define CS_EXEC_SET_KILL            0x00200000  /* set CS_KILL on any exec'ed process */
#define CS_EXEC_SET_ENFORCEMENT     0x00400000  /* set CS_ENFORCEMENT on any exec'ed process */
#define CS_EXEC_INHERIT_SIP         0x00800000  /* set CS_INSTALLER on any exec'ed process */

#define CS_KILLED                   0x01000000  /* was killed by kernel for invalidity */
#define CS_NO_UNTRUSTED_HELPERS     0x02000000  /* kernel did not load a non-platform-binary dyld or Rosetta runtime */
#define CS_DYLD_PLATFORM            CS_NO_UNTRUSTED_HELPERS /* old name */
#define CS_PLATFORM_BINARY          0x04000000  /* this is a platform binary */
#define CS_PLATFORM_PATH            0x08000000  /* platform binary by the fact of path (osx only) */

#define CS_DEBUGGED                 0x10000000  /* process is currently or has previously been debugged and allowed to run with invalid pages */
#define CS_SIGNED                   0x20000000  /* process has a signature (may have gone invalid) */
#define CS_DEV_CODE                 0x40000000  /* code is dev signed, cannot be loaded into prod signed code (will go away with rdar://problem/28322552) */
#define CS_DATAVAULT_CONTROLLER     0x80000000  /* has Data Vault controller entitlement */

#define CS_ENTITLEMENT_FLAGS        (CS_GET_TASK_ALLOW | CS_INSTALLER | CS_DATAVAULT_CONTROLLER | CS_NVRAM_UNRESTRICTED)
```
Zauważ, że funkcja [**exec_mach_imgact**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_exec.c#L1420) może również dynamicznie dodawać flagi `CS_EXEC_*` podczas uruchamiania.

## Wymagania dotyczące podpisu kodu

Każda aplikacja przechowuje **wymagania**, które musi **spełniać**, aby mogła być uruchomiona. Jeśli **aplikacja zawiera wymagania, które nie są spełnione przez aplikację**, nie zostanie uruchomiona (prawdopodobnie została zmieniona).

Wymagania binarne używają **specjalnej gramatyki**, która jest strumieniem **wyrażeń** i są kodowane jako blob za pomocą `0xfade0c00` jako magii, której **hash jest przechowywany w specjalnym slocie kodu**.

Wymagania binarne można zobaczyć, uruchamiając:
```bash
codesign -d -r- /bin/ls
Executable=/bin/ls
designated => identifier "com.apple.ls" and anchor apple

codesign -d -r- /Applications/Signal.app/
Executable=/Applications/Signal.app/Contents/MacOS/Signal
designated => identifier "org.whispersystems.signal-desktop" and anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] /* exists */ and certificate leaf[field.1.2.840.113635.100.6.1.13] /* exists */ and certificate leaf[subject.OU] = U68MSDN6DR
```
> [!NOTE]
> Zauważ, jak te podpisy mogą sprawdzać takie rzeczy jak informacje o certyfikacie, TeamID, identyfikatory, uprawnienia i wiele innych danych.

Ponadto możliwe jest generowanie niektórych skompilowanych wymagań za pomocą narzędzia `csreq`:
```bash
# Generate compiled requirements
csreq -b /tmp/output.csreq -r='identifier "org.whispersystems.signal-desktop" and anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] /* exists */ and certificate leaf[field.1.2.840.113635.100.6.1.13] /* exists */ and certificate leaf[subject.OU] = U68MSDN6DR'

# Get the compiled bytes
od -A x -t x1 /tmp/output.csreq
0000000    fa  de  0c  00  00  00  00  b0  00  00  00  01  00  00  00  06
0000010    00  00  00  06  00  00  00  06  00  00  00  06  00  00  00  02
0000020    00  00  00  21  6f  72  67  2e  77  68  69  73  70  65  72  73
[...]
```
Możliwe jest uzyskanie dostępu do tych informacji oraz tworzenie lub modyfikowanie wymagań za pomocą niektórych API z `Security.framework`, takich jak:

#### **Sprawdzanie ważności**

- **`Sec[Static]CodeCheckValidity`**: Sprawdza ważność SecCodeRef według wymagań.
- **`SecRequirementEvaluate`**: Waliduje wymaganie w kontekście certyfikatu.
- **`SecTaskValidateForRequirement`**: Waliduje działający SecTask w odniesieniu do wymagań `CFString`.

#### **Tworzenie i zarządzanie wymaganiami kodu**

- **`SecRequirementCreateWithData`:** Tworzy `SecRequirementRef` z danych binarnych reprezentujących wymaganie.
- **`SecRequirementCreateWithString`:** Tworzy `SecRequirementRef` z wyrażenia tekstowego wymagania.
- **`SecRequirementCopy[Data/String]`**: Pobiera binarną reprezentację danych `SecRequirementRef`.
- **`SecRequirementCreateGroup`**: Tworzy wymaganie dla członkostwa w grupie aplikacji.

#### **Uzyskiwanie informacji o podpisywaniu kodu**

- **`SecStaticCodeCreateWithPath`**: Inicjalizuje obiekt `SecStaticCodeRef` z ścieżki systemu plików do inspekcji podpisów kodu.
- **`SecCodeCopySigningInformation`**: Uzyskuje informacje o podpisie z `SecCodeRef` lub `SecStaticCodeRef`.

#### **Modyfikowanie wymagań kodu**

- **`SecCodeSignerCreate`**: Tworzy obiekt `SecCodeSignerRef` do wykonywania operacji podpisywania kodu.
- **`SecCodeSignerSetRequirement`**: Ustala nowe wymaganie dla podpisującego kod, które ma być zastosowane podczas podpisywania.
- **`SecCodeSignerAddSignature`**: Dodaje podpis do kodu, który jest podpisywany przez określonego podpisującego.

#### **Walidacja kodu z wymaganiami**

- **`SecStaticCodeCheckValidity`**: Waliduje statyczny obiekt kodu w odniesieniu do określonych wymagań.

#### **Dodatkowe przydatne API**

- **`SecCodeCopy[Internal/Designated]Requirement`: Uzyskaj SecRequirementRef z SecCodeRef**
- **`SecCodeCopyGuestWithAttributes`**: Tworzy `SecCodeRef` reprezentujący obiekt kodu na podstawie określonych atrybutów, przydatne do sandboxingu.
- **`SecCodeCopyPath`**: Pobiera ścieżkę systemu plików powiązaną z `SecCodeRef`.
- **`SecCodeCopySigningIdentifier`**: Uzyskuje identyfikator podpisu (np. Team ID) z `SecCodeRef`.
- **`SecCodeGetTypeID`**: Zwraca identyfikator typu dla obiektów `SecCodeRef`.
- **`SecRequirementGetTypeID`**: Uzyskuje CFTypeID `SecRequirementRef`.

#### **Flagi i stałe podpisywania kodu**

- **`kSecCSDefaultFlags`**: Domyślne flagi używane w wielu funkcjach Security.framework do operacji podpisywania kodu.
- **`kSecCSSigningInformation`**: Flaga używana do określenia, że informacje o podpisie powinny być pobrane.

## Egzekwowanie podpisu kodu

**Jądro** to ono, które **sprawdza podpis kodu** przed zezwoleniem na wykonanie kodu aplikacji. Ponadto, jednym ze sposobów na możliwość zapisu i wykonania nowego kodu w pamięci jest nadużycie JIT, jeśli `mprotect` jest wywoływane z flagą `MAP_JIT`. Należy zauważyć, że aplikacja potrzebuje specjalnego uprawnienia, aby móc to zrobić.

## `cs_blobs` & `cs_blob`

[**cs_blob**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/ubc_internal.h#L106) struktura zawiera informacje o uprawnieniach działającego procesu. `csb_platform_binary` informuje również, czy aplikacja jest binarną platformą (co jest sprawdzane w różnych momentach przez system operacyjny w celu zastosowania mechanizmów zabezpieczających, takich jak ochrona praw SEND do portów zadań tych procesów).
```c
struct cs_blob {
struct cs_blob  *csb_next;
vnode_t         csb_vnode;
void            *csb_ro_addr;
__xnu_struct_group(cs_cpu_info, csb_cpu_info, {
cpu_type_t      csb_cpu_type;
cpu_subtype_t   csb_cpu_subtype;
});
__xnu_struct_group(cs_signer_info, csb_signer_info, {
unsigned int    csb_flags;
unsigned int    csb_signer_type;
});
off_t           csb_base_offset;        /* Offset of Mach-O binary in fat binary */
off_t           csb_start_offset;       /* Blob coverage area start, from csb_base_offset */
off_t           csb_end_offset;         /* Blob coverage area end, from csb_base_offset */
vm_size_t       csb_mem_size;
vm_offset_t     csb_mem_offset;
void            *csb_mem_kaddr;
unsigned char   csb_cdhash[CS_CDHASH_LEN];
const struct cs_hash  *csb_hashtype;
#if CONFIG_SUPPLEMENTAL_SIGNATURES
unsigned char   csb_linkage[CS_CDHASH_LEN];
const struct cs_hash  *csb_linkage_hashtype;
#endif
int             csb_hash_pageshift;
int             csb_hash_firstlevel_pageshift;   /* First hash this many bytes, then hash the hashes together */
const CS_CodeDirectory *csb_cd;
const char      *csb_teamid;
#if CONFIG_SUPPLEMENTAL_SIGNATURES
char            *csb_supplement_teamid;
#endif
const CS_GenericBlob *csb_entitlements_blob;    /* raw blob, subrange of csb_mem_kaddr */
const CS_GenericBlob *csb_der_entitlements_blob;    /* raw blob, subrange of csb_mem_kaddr */

/*
* OSEntitlements pointer setup by AMFI. This is PAC signed in addition to the
* cs_blob being within RO-memory to prevent modifications on the temporary stack
* variable used to setup the blob.
*/
void *XNU_PTRAUTH_SIGNED_PTR("cs_blob.csb_entitlements") csb_entitlements;

unsigned int    csb_reconstituted;      /* signature has potentially been modified after validation */
__xnu_struct_group(cs_blob_platform_flags, csb_platform_flags, {
/* The following two will be replaced by the csb_signer_type. */
unsigned int    csb_platform_binary:1;
unsigned int    csb_platform_path:1;
});

/* Validation category used for TLE */
unsigned int    csb_validation_category;

#if CODE_SIGNING_MONITOR
void *XNU_PTRAUTH_SIGNED_PTR("cs_blob.csb_csm_obj") csb_csm_obj;
bool csb_csm_managed;
#endif
};
```
## Odniesienia

- [**\*OS Internals Volume III**](https://newosxbook.com/home.html)

{{#include ../../../banners/hacktricks-training.md}}
