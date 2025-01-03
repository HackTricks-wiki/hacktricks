# macOS Code Signing

{{#include ../../../banners/hacktricks-training.md}}

## Información Básica

Los binarios Mach-o contienen un comando de carga llamado **`LC_CODE_SIGNATURE`** que indica el **offset** y **size** de las firmas dentro del binario. De hecho, utilizando la herramienta GUI MachOView, es posible encontrar al final del binario una sección llamada **Code Signature** con esta información:

<figure><img src="../../../images/image (1) (1) (1) (1).png" alt="" width="431"><figcaption></figcaption></figure>

El encabezado mágico de la Code Signature es **`0xFADE0CC0`**. Luego tienes información como la longitud y el número de blobs del superBlob que los contiene.\
Es posible encontrar esta información en el [código fuente aquí](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/osfmk/kern/cs_blobs.h#L276):
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
Los blobs comunes que se contienen son el Directorio de Código, Requisitos y Derechos, y un Sintaxis de Mensaje Criptográfico (CMS).\
Además, note cómo los datos codificados en los blobs están codificados en **Big Endian.**

Además, las firmas pueden ser separadas de los binarios y almacenadas en `/var/db/DetachedSignatures` (utilizado por iOS).

## Blob del Directorio de Código

Es posible encontrar la declaración del [Blob del Directorio de Código en el código](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/osfmk/kern/cs_blobs.h#L104):
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
Nota que hay diferentes versiones de esta estructura donde las antiguas pueden contener menos información.

## Páginas de Firma de Código

Hacer un hash del binario completo sería ineficiente e incluso inútil si solo se carga en memoria parcialmente. Por lo tanto, la firma del código es en realidad un hash de hashes donde cada página binaria se hash individualmente.\
De hecho, en el código del **Directorio de Código** anterior puedes ver que **el tamaño de la página está especificado** en uno de sus campos. Además, si el tamaño del binario no es un múltiplo del tamaño de una página, el campo **CodeLimit** especifica dónde está el final de la firma.
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

Tenga en cuenta que las aplicaciones también pueden contener un **entitlement blob** donde se definen todos los derechos. Además, algunos binarios de iOS pueden tener sus derechos específicos en el slot especial -7 (en lugar de en el slot especial de derechos -5).

## Special Slots

Las aplicaciones de MacOS no tienen todo lo que necesitan para ejecutarse dentro del binario, sino que también utilizan **recursos externos** (generalmente dentro del **bundle** de las aplicaciones). Por lo tanto, hay algunos slots dentro del binario que contendrán los hashes de algunos recursos externos interesantes para verificar que no han sido modificados.

De hecho, es posible ver en las estructuras del Directorio de Código un parámetro llamado **`nSpecialSlots`** que indica el número de los slots especiales. No hay un slot especial 0 y los más comunes (del -1 al -6) son:

- Hash de `info.plist` (o el que está dentro de `__TEXT.__info__plist`).
- Hash de los Requisitos
- Hash del Directorio de Recursos (hash del archivo `_CodeSignature/CodeResources` dentro del bundle).
- Específico de la aplicación (no utilizado)
- Hash de los derechos
- Firmas de código DMG solamente
- Derechos DER

## Code Signing Flags

Cada proceso tiene asociado un bitmask conocido como `status` que es iniciado por el kernel y algunos de ellos pueden ser anulados por la **firma de código**. Estas banderas que pueden incluirse en la firma de código están [definidas en el código](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/osfmk/kern/cs_blobs.h#L36):
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
Note que la función [**exec_mach_imgact**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/kern/kern_exec.c#L1420) también puede agregar dinámicamente las banderas `CS_EXEC_*` al iniciar la ejecución.

## Requisitos de Firma de Código

Cada aplicación almacena algunos **requisitos** que debe **satisfacer** para poder ser ejecutada. Si los **requisitos de la aplicación no son satisfechos por la aplicación**, no se ejecutará (ya que probablemente ha sido alterada).

Los requisitos de un binario utilizan una **gramática especial** que es un flujo de **expresiones** y están codificados como blobs usando `0xfade0c00` como el mágico cuyo **hash se almacena en un slot de código especial**.

Los requisitos de un binario se pueden ver ejecutando:
```bash
codesign -d -r- /bin/ls
Executable=/bin/ls
designated => identifier "com.apple.ls" and anchor apple

codesign -d -r- /Applications/Signal.app/
Executable=/Applications/Signal.app/Contents/MacOS/Signal
designated => identifier "org.whispersystems.signal-desktop" and anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] /* exists */ and certificate leaf[field.1.2.840.113635.100.6.1.13] /* exists */ and certificate leaf[subject.OU] = U68MSDN6DR
```
> [!NOTE]
> Nota cómo estas firmas pueden verificar cosas como información de certificación, TeamID, IDs, derechos y muchos otros datos.

Además, es posible generar algunos requisitos compilados utilizando la herramienta `csreq`:
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
Es posible acceder a esta información y crear o modificar requisitos con algunas APIs del `Security.framework` como:

#### **Verificación de Validez**

- **`Sec[Static]CodeCheckValidity`**: Verifica la validez de SecCodeRef por Requisito.
- **`SecRequirementEvaluate`**: Valida el requisito en el contexto del certificado.
- **`SecTaskValidateForRequirement`**: Valida un SecTask en ejecución contra el requisito `CFString`.

#### **Creación y Gestión de Requisitos de Código**

- **`SecRequirementCreateWithData`:** Crea un `SecRequirementRef` a partir de datos binarios que representan el requisito.
- **`SecRequirementCreateWithString`:** Crea un `SecRequirementRef` a partir de una expresión de cadena del requisito.
- **`SecRequirementCopy[Data/String]`**: Recupera la representación de datos binarios de un `SecRequirementRef`.
- **`SecRequirementCreateGroup`**: Crea un requisito para la membresía de grupo de aplicaciones.

#### **Acceso a Información de Firma de Código**

- **`SecStaticCodeCreateWithPath`**: Inicializa un objeto `SecStaticCodeRef` a partir de una ruta del sistema de archivos para inspeccionar firmas de código.
- **`SecCodeCopySigningInformation`**: Obtiene información de firma de un `SecCodeRef` o `SecStaticCodeRef`.

#### **Modificación de Requisitos de Código**

- **`SecCodeSignerCreate`**: Crea un objeto `SecCodeSignerRef` para realizar operaciones de firma de código.
- **`SecCodeSignerSetRequirement`**: Establece un nuevo requisito para que el firmante de código lo aplique durante la firma.
- **`SecCodeSignerAddSignature`**: Agrega una firma al código que se está firmando con el firmante especificado.

#### **Validación de Código con Requisitos**

- **`SecStaticCodeCheckValidity`**: Valida un objeto de código estático contra requisitos especificados.

#### **APIs Útiles Adicionales**

- **`SecCodeCopy[Internal/Designated]Requirement`: Obtener SecRequirementRef de SecCodeRef**
- **`SecCodeCopyGuestWithAttributes`**: Crea un `SecCodeRef` que representa un objeto de código basado en atributos específicos, útil para el sandboxing.
- **`SecCodeCopyPath`**: Recupera la ruta del sistema de archivos asociada con un `SecCodeRef`.
- **`SecCodeCopySigningIdentifier`**: Obtiene el identificador de firma (por ejemplo, Team ID) de un `SecCodeRef`.
- **`SecCodeGetTypeID`**: Devuelve el identificador de tipo para objetos `SecCodeRef`.
- **`SecRequirementGetTypeID`**: Obtiene un CFTypeID de un `SecRequirementRef`.

#### **Banderas y Constantes de Firma de Código**

- **`kSecCSDefaultFlags`**: Banderas predeterminadas utilizadas en muchas funciones de Security.framework para operaciones de firma de código.
- **`kSecCSSigningInformation`**: Bandera utilizada para especificar que se debe recuperar información de firma.

## Aplicación de la Firma de Código

El **kernel** es el que **verifica la firma de código** antes de permitir que el código de la aplicación se ejecute. Además, una forma de poder escribir y ejecutar nuevo código en memoria es abusar de JIT si `mprotect` se llama con la bandera `MAP_JIT`. Tenga en cuenta que la aplicación necesita un derecho especial para poder hacer esto.

## `cs_blobs` & `cs_blob`

[**cs_blob**](https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/sys/ubc_internal.h#L106) la estructura contiene la información sobre el derecho de la proceso en ejecución sobre él. `csb_platform_binary` también informa si la aplicación es un binario de plataforma (que es verificado en diferentes momentos por el OS para aplicar mecanismos de seguridad como proteger los derechos de SEND a los puertos de tarea de estos procesos).
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
## Referencias

- [**\*OS Internals Volume III**](https://newosxbook.com/home.html)

{{#include ../../../banners/hacktricks-training.md}}
