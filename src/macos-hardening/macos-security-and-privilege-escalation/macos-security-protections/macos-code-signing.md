# macOS Code Signing

{{#include ../../../banners/hacktricks-training.md}}

## Grundlegende Informationen

Mach-o-Binärdateien enthalten einen Ladebefehl namens **`LC_CODE_SIGNATURE`**, der den **Offset** und die **Größe** der Signaturen innerhalb der Binärdatei angibt. Tatsächlich ist es möglich, mit dem GUI-Tool MachOView am Ende der Binärdatei einen Abschnitt namens **Code Signature** mit diesen Informationen zu finden:

<figure><img src="../../../images/image (1) (1) (1) (1).png" alt="" width="431"><figcaption></figcaption></figure>

Der magische Header der Code-Signatur ist **`0xFADE0CC0`**. Dann haben Sie Informationen wie die Länge und die Anzahl der Blobs des SuperBlobs, die sie enthalten.\
Diese Informationen sind im [Quellcode hier](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/osfmk/kern/cs_blobs.h#L276) zu finden:
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
Häufig enthaltene Blobs sind Codeverzeichnis, Anforderungen und Berechtigungen sowie eine kryptografische Nachrichten-Syntax (CMS).\
Außerdem beachten Sie, dass die in den Blobs codierten Daten in **Big Endian** codiert sind.

Darüber hinaus können Signaturen von den Binärdateien getrennt und in `/var/db/DetachedSignatures` gespeichert werden (verwendet von iOS).

## Codeverzeichnis-Blob

Es ist möglich, die Deklaration des [Codeverzeichnis-Blobs im Code zu finden](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/osfmk/kern/cs_blobs.h#L104):
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
Beachten Sie, dass es verschiedene Versionen dieser Struktur gibt, bei denen ältere möglicherweise weniger Informationen enthalten.

## Signing Code Pages

Das Hashing des vollständigen Binaries wäre ineffizient und sogar nutzlos, wenn es nur teilweise im Speicher geladen ist. Daher ist die Codesignatur tatsächlich ein Hash von Hashes, bei dem jede Binärseite einzeln gehasht wird.\
Tatsächlich können Sie im vorherigen **Code Directory**-Code sehen, dass die **Seitenhöhe angegeben ist** in einem seiner Felder. Darüber hinaus gibt das Feld **CodeLimit** an, wo das Ende der Signatur liegt, wenn die Größe des Binaries kein Vielfaches der Seitenhöhe ist.
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

Beachten Sie, dass Anwendungen auch einen **Entitlement Blob** enthalten können, in dem alle Berechtigungen definiert sind. Darüber hinaus können einige iOS-Binärdateien ihre Berechtigungen spezifisch im speziellen Slot -7 (anstatt im speziellen Slot -5 für Berechtigungen) haben.

## Special Slots

MacOS-Anwendungen haben nicht alles, was sie zur Ausführung benötigen, innerhalb der Binärdatei, sondern verwenden auch **externe Ressourcen** (normalerweise innerhalb des Anwendungs-**Bundles**). Daher gibt es einige Slots innerhalb der Binärdatei, die die Hashes einiger interessanter externer Ressourcen enthalten, um zu überprüfen, ob sie nicht modifiziert wurden.

Tatsächlich ist es möglich, in den Code Directory-Strukturen einen Parameter namens **`nSpecialSlots`** zu sehen, der die Anzahl der speziellen Slots angibt. Es gibt keinen speziellen Slot 0, und die häufigsten (von -1 bis -6) sind:

- Hash von `info.plist` (oder dem innerhalb von `__TEXT.__info__plist`).
- Hash der Anforderungen
- Hash des Ressourcenverzeichnisses (Hash der Datei `_CodeSignature/CodeResources` innerhalb des Bundles).
- Anwendungsspezifisch (nicht verwendet)
- Hash der Berechtigungen
- DMG-Code-Signaturen nur
- DER-Berechtigungen

## Code Signing Flags

Jeder Prozess hat eine zugehörige Bitmaske, die als `status` bekannt ist und vom Kernel gestartet wird. Einige davon können durch die **Code-Signatur** überschrieben werden. Diese Flags, die in der Code-Signierung enthalten sein können, sind [im Code definiert](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/osfmk/kern/cs_blobs.h#L36):
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
Beachten Sie, dass die Funktion [**exec_mach_imgact**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_exec.c#L1420) auch die `CS_EXEC_*`-Flags dynamisch hinzufügen kann, wenn die Ausführung gestartet wird.

## Anforderungen an die Code-Signatur

Jede Anwendung speichert einige **Anforderungen**, die sie **erfüllen** muss, um ausgeführt werden zu können. Wenn die **Anforderungen der Anwendung nicht von der Anwendung erfüllt werden**, wird sie nicht ausgeführt (da sie wahrscheinlich verändert wurde).

Die Anforderungen einer Binärdatei verwenden eine **spezielle Grammatik**, die ein Stream von **Ausdrücken** ist und als Blobs mit `0xfade0c00` als Magie kodiert ist, deren **Hash in einem speziellen Codeslot gespeichert ist**.

Die Anforderungen einer Binärdatei können durch Ausführen von:
```bash
codesign -d -r- /bin/ls
Executable=/bin/ls
designated => identifier "com.apple.ls" and anchor apple

codesign -d -r- /Applications/Signal.app/
Executable=/Applications/Signal.app/Contents/MacOS/Signal
designated => identifier "org.whispersystems.signal-desktop" and anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] /* exists */ and certificate leaf[field.1.2.840.113635.100.6.1.13] /* exists */ and certificate leaf[subject.OU] = U68MSDN6DR
```
> [!NOTE]
> Beachten Sie, wie diese Signaturen Dinge wie Zertifizierungsinformationen, TeamID, IDs, Berechtigungen und viele andere Daten überprüfen können.

Darüber hinaus ist es möglich, einige kompilierte Anforderungen mit dem `csreq`-Tool zu generieren:
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
Es ist möglich, auf diese Informationen zuzugreifen und Anforderungen mit einigen APIs aus dem `Security.framework` zu erstellen oder zu ändern, wie:

#### **Überprüfung der Gültigkeit**

- **`Sec[Static]CodeCheckValidity`**: Überprüft die Gültigkeit von SecCodeRef pro Anforderung.
- **`SecRequirementEvaluate`**: Validiert die Anforderung im Kontext des Zertifikats.
- **`SecTaskValidateForRequirement`**: Validiert eine laufende SecTask gegen die `CFString`-Anforderung.

#### **Erstellen und Verwalten von Code-Anforderungen**

- **`SecRequirementCreateWithData`:** Erstellt ein `SecRequirementRef` aus binären Daten, die die Anforderung darstellen.
- **`SecRequirementCreateWithString`:** Erstellt ein `SecRequirementRef` aus einem String-Ausdruck der Anforderung.
- **`SecRequirementCopy[Data/String]`**: Ruft die binäre Datenrepräsentation eines `SecRequirementRef` ab.
- **`SecRequirementCreateGroup`**: Erstellt eine Anforderung für die Mitgliedschaft in einer App-Gruppe.

#### **Zugriff auf Code-Signaturinformationen**

- **`SecStaticCodeCreateWithPath`**: Initialisiert ein `SecStaticCodeRef`-Objekt von einem Dateisystempfad zur Überprüfung von Codesignaturen.
- **`SecCodeCopySigningInformation`**: Erhält Signaturinformationen von einem `SecCodeRef` oder `SecStaticCodeRef`.

#### **Ändern von Code-Anforderungen**

- **`SecCodeSignerCreate`**: Erstellt ein `SecCodeSignerRef`-Objekt für die Durchführung von Codesignierungsoperationen.
- **`SecCodeSignerSetRequirement`**: Setzt eine neue Anforderung für den Codesigner, die während der Signierung angewendet werden soll.
- **`SecCodeSignerAddSignature`**: Fügt eine Signatur zu dem zu signierenden Code mit dem angegebenen Signierer hinzu.

#### **Validierung von Code mit Anforderungen**

- **`SecStaticCodeCheckValidity`**: Validiert ein statisches Codeobjekt gegen die angegebenen Anforderungen.

#### **Zusätzliche nützliche APIs**

- **`SecCodeCopy[Internal/Designated]Requirement`: Erhalte SecRequirementRef von SecCodeRef**
- **`SecCodeCopyGuestWithAttributes`**: Erstellt ein `SecCodeRef`, das ein Codeobjekt basierend auf spezifischen Attributen darstellt, nützlich für Sandboxing.
- **`SecCodeCopyPath`**: Ruft den Dateisystempfad ab, der mit einem `SecCodeRef` verknüpft ist.
- **`SecCodeCopySigningIdentifier`**: Erhält die Signaturkennung (z. B. Team-ID) von einem `SecCodeRef`.
- **`SecCodeGetTypeID`**: Gibt die Typkennung für `SecCodeRef`-Objekte zurück.
- **`SecRequirementGetTypeID`**: Erhält eine CFTypeID eines `SecRequirementRef`.

#### **Code-Signierungsflags und Konstanten**

- **`kSecCSDefaultFlags`**: Standardflags, die in vielen Funktionen des Security.framework für Codesignierungsoperationen verwendet werden.
- **`kSecCSSigningInformation`**: Flag, das angibt, dass Signaturinformationen abgerufen werden sollen.

## Durchsetzung der Codesignatur

Der **Kernel** ist derjenige, der **die Codesignatur überprüft**, bevor er den Code der App ausführen lässt. Darüber hinaus ist eine Möglichkeit, neuen Code im Speicher zu schreiben und auszuführen, den JIT zu missbrauchen, wenn `mprotect` mit dem `MAP_JIT`-Flag aufgerufen wird. Beachten Sie, dass die Anwendung eine spezielle Berechtigung benötigt, um dies tun zu können.

## `cs_blobs` & `cs_blob`

[**cs_blob**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/ubc_internal.h#L106) Struktur enthält die Informationen über die Berechtigung des laufenden Prozesses. `csb_platform_binary` informiert auch, ob die Anwendung ein Plattform-Binary ist (was zu verschiedenen Zeitpunkten vom OS überprüft wird, um Sicherheitsmechanismen anzuwenden, wie z. B. den Schutz der SEND-Rechte zu den Task-Ports dieser Prozesse).
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
## Referenzen

- [**\*OS Internals Volume III**](https://newosxbook.com/home.html)

{{#include ../../../banners/hacktricks-training.md}}
