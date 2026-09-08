# Modelado de amenazas y separación de identidades

{{#include ../banners/hacktricks-training.md}}

El fallo de anonimato más común no es una criptografía rota. Es la **vinculación**: un identificador, patrón temporal, dispositivo, cuenta, pago, archivo o hábito humano conecta dos contextos que debían permanecer separados.

## Crear un modelo de amenazas de privacidad

El plan de seguridad de seis preguntas de EFF es una base sólida: qué debe protegerse, de quién, el impacto y la probabilidad de un fallo, el esfuerzo disponible y los aliados que pueden ayudar.<sup>[[1]](#references)</sup> Hazlo operativo con una tabla pequeña:

| Recurso/acción | Observador | Datos observables | Vía de correlación | Control | Riesgo residual |
|---|---|---|---|---|---|
| Investigar a un cliente | ISP | Metadatos de destino/tiempo | Registro del abonado doméstico | Tor Browser | Uso de Tor visible; correlación de extremo a extremo |
| Cuenta seudónima | Plataforma | IP, navegador, datos de recuperación | Teléfono/email/foto reutilizados | Contexto y alias dedicados | Correlación por escritura/grafo social |
| Compra online | Comerciante | Cuenta, entrega, tarjeta tokenizada | Historial de dirección y cuenta | Compra como invitado, campos mínimos, tarjeta virtual | El emisor y el operador conservan registros |
| Tráfico de Red Team | Objetivo/cliente | IP de origen y comportamiento | Registros del proveedor/contratación | Egress autorizado dedicado | Deliberadamente atribuible durante una escalada |

Revisa la tabla cada vez que cambien la ubicación, el proveedor, el dispositivo, la contraparte o las consecuencias.

## Dibujar el grafo de vinculabilidad

Trata cada identidad como un nodo independiente. Añade una arista por cada atributo compartido:

- email o dirección de recuperación;
- número de teléfono o carga de la libreta de contactos;
- nombre de usuario, avatar, foto, biografía o estilo de escritura/código;
- contraseña, cuenta de passkey-sync o pregunta de recuperación;
- dispositivo, ID de publicidad, perfil del navegador, cookies, fuentes o extensiones;
- dirección IP, zona horaria, idioma, horario o estado online simultáneo;
- tarjeta bancaria, cuenta de exchange, cluster de wallet, dirección de envío o programa de fidelización;
- campos de autor del documento, ubicación EXIF, marcas de impresora o propietario del recurso compartido en la nube;
- compañero, pertenencia a grupos y grafo social.

Una arista no es automáticamente fatal, pero indica qué observador puede establecer la conexión. EFF advierte específicamente que los números de teléfono, las direcciones de email y las fotografías reutilizadas pueden vincular perfiles.<sup>[[2]](#references)</sup>

## Crear un compartimento paso a paso

1. **Nombra el contexto y los vínculos prohibidos.** Ejemplo: `client-red-2026`, prohibido para el email personal, los perfiles del navegador doméstico, los métodos de pago personales y los clientes no relacionados.
2. **Elige el límite de aislamiento.** En orden de fuerza creciente: perfil de navegador separado → cuenta de SO separada → VM/qube separado → dispositivo dedicado. Una pestaña separada o una ventana privada no es un límite de seguridad.
3. **Crea identificadores nuevos dentro de ese límite.** Usa un email/alias específico del contexto, nombre de usuario, contraseña, vault o colección del gestor de contraseñas y claves de autenticación. No añadas un canal de recuperación personal si la desvinculación del proveedor es importante.
4. **Elige una política de red.** Decide si el contexto siempre usa una VPN del cliente, un VPS de la contratación, una VPN de confianza o Tor. Aplica un enrutamiento fail-closed cuando sea posible.
5. **Elige una política de pagos.** El método de pago debe coincidir con el modelo del observador; una tarjeta virtual puede ocultar el PAN al comerciante, pero seguir identificando al cliente ante el emisor.
6. **Establece reglas de transferencia de datos.** Prefiere transferencias deliberadas y estrictamente limitadas. Trata el portapapeles, las carpetas compartidas, los dispositivos USB, la sincronización en la nube, las impresoras y las capturas de pantalla como posibles puentes.
7. **Registra las fechas de creación y desmontaje.** Define qué evidencias deben conservarse por motivos contractuales/fiscales/de compliance y qué datos transitorios deben caducar.
8. **Busca vínculos antes de usarlo.** Inspecciona la configuración de la cuenta, los campos de recuperación, el perfil público, la IP/DNS, el estado del navegador, los metadatos de los archivos y los paneles del proveedor.

{% hint style="warning" %}
No inventes información de identidad cuando un servicio o la ley exija una identificación exacta. Un compartimento de privacidad trata sobre minimización y separación de datos, no sobre fraude de identidad ni sobre evadir la due diligence del cliente.
{% endhint %}

## Línea base del endpoint y de las cuentas

- Usa hardware compatible e instala rápidamente las actualizaciones del SO, navegador, wallet y firmware.
- Activa el cifrado del dispositivo y usa un código de acceso sólido. El cifrado en reposo ayuda cuando un dispositivo apagado se pierde o es incautado, pero no mientras el malware o una sesión desbloqueada puedan leer los datos.<sup>[[3]](#references)</sup>
- Usa contraseñas únicas generadas aleatoriamente en un gestor de contraseñas.
- Prefiere autenticación resistente al phishing, como WebAuthn/passkeys o claves de seguridad de hardware, cuando el modelo de amenazas permita su modelo de recuperación/sincronización. NIST señala que los OTP introducidos manualmente no son resistentes al phishing porque un impostor puede retransmitirlos.<sup>[[4]](#references)</sup>
- Mantén los códigos de recuperación offline y separados del endpoint. Revisa si una cuenta de passkey sincronizada une identidades que deberían permanecer separadas.
- Desactiva los permisos innecesarios de ubicación, contactos, micrófono, cámara, Bluetooth, ID de publicidad y ejecución en segundo plano.
- No mezcles la sincronización personal en la nube, la sincronización del navegador, las cuentas del gestor de contraseñas ni las tiendas de aplicaciones en un contexto de alta separación.

## Privacidad del navegador

Browser fingerprinting utiliza la configuración observable, el dispositivo, el entorno y el comportamiento para identificar o correlacionar a un usuario. Borrar las cookies o cambiar las direcciones IP no lo derrota de forma fiable, y el W3C considera inverosímil su eliminación técnica completa mediante medios ampliamente desplegados.<sup>[[5]](#references)</sup>

Para la privacidad ordinaria:

1. Usa un navegador mantenido, con modo HTTPS-only y una protección sólida contra el tracking.
2. Bloquea el tracking de terceros y particiona el estado cuando sea compatible.
3. Usa perfiles de navegador separados para contextos realmente independientes.
4. Desactiva los permisos innecesarios y borra los datos de los sitios siguiendo un calendario definido.
5. Evita iniciar sesión en cuentas con mucha información de identidad mientras realizas investigaciones sensibles no relacionadas.

Para el anonimato web, usa **Tor Browser en su configuración estándar**. No uses un navegador normal a través de Tor: Tor Project advierte que los navegadores comunes pueden leak mediante DNS/WebRTC, estado persistente, fuentes, plugins y diferencias de fingerprint.<sup>[[6]](#references)</sup> Evita extensiones adicionales, tamaños de ventana inusuales, fuentes personalizadas y preferencias que hagan destacar al navegador.<sup>[[7]](#references)</sup>

## Comunicaciones y metadatos

Los metadatos incluyen el remitente, el destinatario, la hora, la ubicación y otro contexto, incluso cuando el contenido del mensaje está cifrado.<sup>[[8]](#references)</sup>

- Prefiere herramientas con cifrado de extremo a extremo, metadatos del lado del servidor minimizados y protocolos/clientes abiertos cuando sea práctico.
- Verifica los contactos sensibles mediante un canal independiente o en persona. Los números de seguridad de Signal están diseñados para esta comprobación.<sup>[[9]](#references)</sup>
- Los nombres de usuario de Signal pueden iniciar contactos sin compartir un número de teléfono, pero sigue siendo necesario un número de teléfono para registrarse; configura deliberadamente la visibilidad/localización por número de teléfono.<sup>[[9]](#references)</sup>
- Los mensajes que desaparecen reducen las copias conservadas; los destinatarios aún pueden fotografiar, copiar, reenviar o archivar el contenido.
- El email normalmente expone metadatos de enrutamiento. Incluso los proveedores centrados en la privacidad no pueden hacer que un mensaje tenga cifrado de extremo a extremo cuando la otra parte usa email ordinario, a menos que ambas partes utilicen un método E2EE compatible. Proton, por ejemplo, documenta que el correo ordinario dirigido a otros proveedores usa TLS y sigue siendo legible para el proveedor receptor.<sup>[[10]](#references)</sup>
- Separa las libretas de direcciones y no cargues contactos personales en una cuenta seudónima.

## Archivos, fotos y autoría

Tails advierte que las fotografías pueden contener datos de la cámara y de ubicación, y que los documentos de oficina pueden contener campos de autor y de hora de creación.<sup>[[11]](#references)</sup>

Antes de compartir:
```bash
# Inspect recursively; do not assume the extension tells the whole story
exiftool -a -u -g1 path/to/file

# Create a cleaned copy. Verify the copy before publishing.
exiftool -all= -o cleaned-file path/to/file
```
Luego vuelve a abrir la copia limpiada en un visor aislado y comprueba:

- las propiedades del documento, los comentarios, los cambios registrados, las hojas/diapositivas ocultas, las miniaturas y los archivos adjuntos;
- EXIF/XMP/IPTC, GPS, marcas de tiempo, nombres de dispositivos/software e identificadores únicos;
- reflejos visibles, puntos de referencia, contenido de pantallas, voces, rostros y sonidos de fondo;
- el nombre de archivo, las rutas dentro de archivos, el propietario del uso compartido en la nube, el certificado de firma y el historial de revisiones.

La sanitización puede dañar las pruebas o la autenticidad. Conserva un original cifrado cuando la cadena de custodia o la verificación posterior sean importantes. La estilometría y el estilo de programación también pueden vincular la autoría; eliminar los metadatos no cambia el estilo humano.

## Patrones de fallo comunes

- Iniciar sesión en una cuenta personal mediante una conexión “anónima”.
- Reutilizar un teléfono de recuperación, avatar, nombre de usuario, clave pública, wallet o dirección de donación.
- Operar dos identidades al mismo tiempo desde contextos correlacionados.
- Copiar texto/archivos mediante un portapapeles personal en la nube o una carpeta compartida.
- Instalar extensiones distintivas de Tor Browser o cambiar muchos valores predeterminados.
- Confiar en una afirmación de “no logs” sin entender qué se registra, durante cuánto tiempo y por qué subcontratistas.
- Suponer que un teléfono secundario es anónimo mientras viaja junto a un teléfono personal. EFF señala que la ubicación celular y los desplazamientos conjuntos pueden correlacionar los dispositivos.<sup>[[3]](#references)</sup>
- Tratar el cifrado como eliminación; los endpoints y los destinatarios pueden conservar el texto plano.

## Lista de verificación

- [ ] El contexto no contiene ninguna dirección personal de recuperación, teléfono, cuenta de sincronización ni contenido multimedia reutilizado, salvo que se haya aceptado intencionadamente.
- [ ] La ruta de red prevista está activa y falla de forma segura.
- [ ] La zona horaria, la configuración regional, las extensiones y los permisos del navegador/dispositivo coinciden con el plan.
- [ ] No hay cuentas personales abiertas en el compartimento.
- [ ] Los archivos se han inspeccionado y sanitizado; los originales se gestionan por separado.
- [ ] Los contactos se han autenticado mediante un segundo canal.
- [ ] Se comprenden los metadatos visibles para el proveedor y el periodo de retención.
- [ ] Los procedimientos de desmontaje, conservación de pruebas y recuperación de cuentas están documentados.

## References

- [1] [EFF Surveillance Self-Defense — Tu plan de seguridad](https://ssd.eff.org/module/your-security-plan)
- [2] [EFF Surveillance Self-Defense — Cómo protegerte en las redes sociales](https://ssd.eff.org/module/protecting-yourself-social-networks)
- [3] [EFF Surveillance Self-Defense — Asistir a una protesta](https://ssd.eff.org/module/attending-protest)
- [4] [NIST SP 800-63B-4 — Gestión de autenticación y autenticadores](https://pages.nist.gov/800-63-4/sp800-63b.html)
- [5] [W3C — Mitigación del fingerprinting de navegadores en las especificaciones web](https://www.w3.org/TR/fingerprinting-guidance/)
- [6] [Tor Project — Usar Tor con otros navegadores](https://support.torproject.org/tor-browser/security/using-tor-with-other-browsers/)
- [7] [Tor Project — Plugins y complementos en Tor Browser](https://support.torproject.org/tor-browser/features/plugins/)
- [8] [EFF Surveillance Self-Defense — Por qué importan los metadatos de comunicación](https://ssd.eff.org/module/why-metadata-matters)
- [9] [Signal — Privacidad del número de teléfono y nombres de usuario: análisis más profundo](https://support.signal.org/hc/en-us/articles/6829998083994-Phone-Number-Privacy-and-Usernames-Deeper-Dive)
- [10] [Proton — ¿Qué está cifrado dentro de Proton Mail?](https://proton.me/support/what-is-encrypted-within-protonmail)
- [11] [Tails — Advertencias: Tails es seguro, pero no es magia](https://tails.net/doc/about/warnings/index.en.html)
{{#include ../banners/hacktricks-training.md}}
