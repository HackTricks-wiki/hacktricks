# Database leaks

{{#include ../../banners/hacktricks-training.md}}

## Motores de búsqueda de brechas de datos

Para obtener acceso a la API y conocer las particularidades de cada servicio al buscar datos de brechas o reputación, consulta el [catálogo de API de reconocimiento e inteligencia de amenazas](reconnaissance-and-threat-intelligence-apis.md).

- [GreyNoise Visualizer](https://viz.greynoise.io/) - Busca IP y CIDR, y consulta la actividad de los scanners por etiquetas, CVE y metadatos.<sup>[[1]](#references)</sup>
- [DeHashed](https://www.dehashed.com/) - Busca datos expuestos por nombres de usuario, direcciones de correo electrónico, direcciones IP y otros selectores; también ofrece monitorización y una API.<sup>[[2]](#references)</sup>
- [Have I Been Pwned?](https://haveibeenpwned.com/) - Comprueba si una dirección de correo electrónico aparece en brechas de datos conocidas o registros de paste; también ofrece notificaciones y una API.<sup>[[3]](#references)</sup>
- [ScamSearch](https://scamsearch.io/) - Busca registros de estafadores denunciados por foto de perfil, correo electrónico, nombre de usuario, número de teléfono, dirección de criptomonedas o sitio web.<sup>[[4]](#references)</sup>
- [Intelligence X](https://intelx.io/) - Busca selectores como direcciones de correo electrónico, dominios, URL, IP y CIDR en fuentes indexadas.<sup>[[5]](#references)</sup>
- [SpyCloud](https://spycloud.com/check-your-exposure/) - Comprueba si un correo electrónico o dominio empresarial está asociado a credenciales expuestas, identidades infectadas por infostealer y cookies de sesión robadas.<sup>[[6]](#references)</sup>
- [WeLeakInfo](https://weleakinfo.io/) - Busca bases de datos filtradas usando dominios, nombres, correos electrónicos, ID, teléfonos, IP, URL o hashes.<sup>[[7]](#references)</sup>
- [BreachDirectory](https://breachdirectory.org/) - Comprueba si tu correo electrónico o nombre de usuario se ha visto comprometido.
- [LeakCheck](https://leakcheck.io/) - Busca datos expuestos de correos electrónicos, nombres de usuario, teléfonos, hashes o dominios, y monitoriza nuevas entradas.<sup>[[8]](#references)</sup>
- [Findemail.io](https://findemail.io/) - Encuentra direcciones de correo electrónico de una empresa.
- [Library of Leaks](https://search.libraryofleaks.org/) - Busca documentos públicos, empresas y personas, incluidos conjuntos de datos de leaks.<sup>[[9]](#references)</sup>
- [LeakRadar](https://leakradar.io/) - Busca credenciales filtradas por correo electrónico, dominio o cadena sin procesar, y monitoriza nuevas exposiciones.<sup>[[10]](#references)</sup>
- [InfoStealers](https://infostealers.info/en/info) - Busca registros de infostealer procedentes de dispositivos infectados y monitoriza nuevos datos.<sup>[[11]](#references)</sup>
- [Leak-Lookup](https://leak-lookup.com/) - Busca en brechas de datos y monitoriza la exposición de credenciales.<sup>[[12]](#references)</sup>
- [Scylla.so](https://scylla.so/) - Motor de búsqueda de brechas en bases de datos impulsado por la comunidad.
- [Leaked.domains](https://leaked.domains/) - Busca credenciales filtradas y registros relacionados por dominio, correo electrónico, nombre de usuario, contraseña, IP y otros selectores.<sup>[[13]](#references)</sup>
- [WhiteIntel](https://whiteintel.io/) - Monitoriza la actividad de la dark web, los leaks de credenciales, los datos de infostealer y las menciones de marca.<sup>[[14]](#references)</sup>
- [PSBDMP](https://psbdmp.ws/) - Plataforma de búsqueda y monitorización de dumps de Pastebin.

## Herramientas para enumerar data leaks

- [Leaker](https://github.com/vflame6/leaker) - CLI pasiva para descubrir leaks que busca en varias fuentes en línea por correo electrónico, nombre de usuario, dominio, palabra clave o teléfono.<sup>[[15]](#references)</sup>

## References

- [1] [Uso de GreyNoise Visualizer](https://docs.greynoise.io/docs/using-the-greynoise-visualizer)
- [2] [DeHashed](https://www.dehashed.com/)
- [3] [Have I Been Pwned](https://haveibeenpwned.com/)
- [4] [Base de datos global de estafadores - ScamSearch](https://scamsearch.io/)
- [5] [Intelligence X](https://intelx.io/)
- [6] [Comprueba tu exposición - SpyCloud](https://spycloud.com/check-your-exposure/)
- [7] [WeLeakInfo](https://weleakinfo.io/)
- [8] [Motor de búsqueda de brechas de datos - LeakCheck](https://leakcheck.io/)
- [9] [Library of Leaks](https://search.libraryofleaks.org/)
- [10] [LeakRadar](https://leakradar.io/)
- [11] [OSINT InfoStealers.Info](https://infostealers.info/en/info)
- [12] [Leak-Lookup - Motor de búsqueda de brechas de datos](https://leak-lookup.com/)
- [13] [Leaked.Domains - Búsqueda universal](https://leaked.domains/)
- [14] [WhiteIntel - Plataforma de inteligencia y monitorización de la dark web](https://whiteintel.io/)
- [15] [vflame6/leaker](https://github.com/vflame6/leaker)
{{#include ../../banners/hacktricks-training.md}}
