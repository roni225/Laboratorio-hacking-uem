#set document(title: "Auditoría OSINT: Endesa", author: "Rodrigo Revuelta Alonso")
#set heading(numbering: "1.")
#show link: set text(fill: blue.darken(20%))
#show cite: set text(fill: blue.darken(20%))

#align(center, text(20pt, weight: "bold")[Práctica 1: Reconocimiento Pasivo])
#align(center, text(14pt)[Objetivo: Endesa.com])
#v(1cm)

== Resumen

En este informe se ha realizado una auditoría de seguridad "pasiva" sobre la empresa Endesa. Esto significa que hemos buscado información disponible públicamente en Internet (como un detective) sin tocar ni atacar sus servidores reales. Se han identificado sus dominios de internet, los sistemas de protección que usan (como Imperva) y se ha comprobado si existen documentos privados expuestos en Google. Los resultados indican que Endesa mantiene una buena higiene digital, aunque se han localizado numerosos portales de acceso que podrían ser puntos de interés para un atacante.

#heading(numbering: none, bookmarked: false)[Índice]
#outline(indent: auto, depth: 3)
#pagebreak()

== Introducción

El reconocimiento es la primera fase de cualquier auditoría de ciberseguridad. En este laboratorio, aplicamos técnicas OSINT (Open Source Intelligence) para perfilar la infraestructura digital de Endesa. El objetivo es demostrar cómo un atacante o un auditor puede obtener datos críticos (servidores, subdominios y proveedores tecnológicos) utilizando únicamente herramientas gratuitas y bases de datos públicas, cumpliendo estrictamente con el marco ético de no interactuar con los sistemas de la víctima.

== Investigación de Registros DNS

El Sistema de Nombres de Dominio (DNS) es fundamental para la resolución de nombres en Internet. Desde la perspectiva de OSINT, el análisis de estos registros permite identificar la infraestructura crítica de la organización sin interactuar directamente con ella @robledano2026hacking.

=== Descripción de Registros Técnicos

A continuación, se detallan los registros analizados y su relevancia en el reconocimiento:

#figure(
  table(
    columns: (auto, 1fr),
    inset: 10pt,
    align: horizon,
    fill: (x, y) => if y == 0 { gray.lighten(80%) },
    [*Registro*], [*Descripción y Utilidad en Auditoría*],
    [A], [Mapea un nombre de dominio a una dirección IPv4. Permite identificar el hosting principal.],
    [AAAA], [Versión IPv6 del registro A. Revela infraestructura de red moderna.],
    [MX (Mail Exchange)], [Indica los servidores de correo. Permite deducir si usan servicios como Office 365 o Google Workspace.],
    [TXT], [Contiene texto arbitrario. Se usa para registros SPF/DKIM que revelan otros servicios autorizados.],
    [CNAME], [Alias de un dominio. Útil para descubrir el uso de CDNs como Cloudflare o Akamai.],
    [NS], [Servidores de nombres autoritativos. Identifica quién gestiona el DNS de la empresa.],
    [SOA], [Información administrativa de la zona. Indica la frecuencia de actualización de los datos.],
    [PTR], [Resolución inversa (IP a nombre). Confirma la identidad del propietario de una IP.],
  ),
  caption: [Resumen de registros DNS y su impacto en el reconocimiento.],
)

=== Discusión: Reconocimiento Pasivo vs. Activo

El reconocimiento se clasifica según la interacción con el objetivo:

- *Reconocimiento Pasivo:* Se ha realizado consultando bases de datos de terceros y servidores DNS públicos (como 8.8.8.8). Al no realizar consultas directamente a los servidores autoritativos de la empresa, no existe registro de nuestra actividad en sus logs.
- *Reconocimiento Activo:* Acciones como la **Transferencia de Zona (AXFR)** o el *fuzzing* de subdominios contra los servidores de la empresa se consideran activas. Estas técnicas han sido descartadas en este trabajo para cumplir con el código ético y las restricciones de la práctica.

Mientras que herramientas como dig o nslookup podrían cruzar la línea hacia el reconocimiento activo si se dirigen contra los NS de la empresa, el uso de plataformas como @dnsdumpster garantiza la pasividad al actuar como un intermediario que ya posee los datos indexados.

Para la obtención de estos datos se han utilizado exclusivamente fuentes de agregación de terceros como DNSDumpster @dnsdumpster, visto en @talwar2023overview y el análisis de registros públicos de transparencia de certificados mediante crt.sh @crtsh. Estas herramientas garantizan una metodología 100% pasiva, ya que la información se extrae de bases de datos indexadas previamente, sin establecer comunicación con la infraestructura de Endesa.

=== Auditoría OSINT sobre Endesa

Empecé por mirar en la web de DNSDumpster donde conseguí sacar el mapa de la empresa Endesa pero el MX records donde están los correos de los empleados pero me salía vacío. Probé a usar otras páginas web como viewDNS.info o Pentest-tools y me seguía sin salir nada asi que solo tengo el mapa de la empresa.

#figure(
  image("imagenes/mapaEndesa.png", width: 80%),
  caption: [Mapa empresa Endesa @dnsdumpster.],
)

Posteriormente busqué una página web donde consiga ver los subdominios y certificados de Endesa eso lo conseguí hacer con @crtsh Donde puse %.endesa.com y me salió una extensa tabla donde se consiguen ver activos reales como comunicaciones.endesa.com o oficina.endesa.com y varios de desarrollo como dev o qual.

También se ve en la tabla que aparece mucho imperva.com con esto conseguimos saber que Endesa usa imperva como WAF que es similar a Akamai y en cuanto a las certificadoras usan GlobalSign y Lets Encrypt.

#figure(
  image("imagenes/crt.sh.png", width: 80%),
  caption: [Enumeración de subdominios y certificados de Endesa @crtsh.],
)

Para hacer los dorks probé tres de los cuales ninguno me dió resultados. El primero fue para los logins site:endesa.com inurl:login | inurl:portal. EL segundo es para encontrar documentos técnicos o normativos site:endesa.com filetype:pdf "prohibida su reproducción". Por último prové un dork para monitorizar futuras fugas de archivos de configuración. El hecho de que no salga nada hoy significa que su seguridad es buena, pero el dork es una herramienta preventiva.

#figure(
  image("imagenes/dork1.png", width: 80%),
  caption: [Para logins.],
)

#figure(
  image("imagenes/dork2.png", width: 80%),
  caption: [Para documentos técnicos.],
)

#figure(
  image("imagenes/dork3.png", width: 80%),
  caption: [Monitorizar futuras fugas.],
)

== Resultados de la Auditoría

A continuación, se sintetizan los activos y tecnologías identificados durante el proceso de reconocimiento:

#figure(
  table(
    columns: (auto, 1fr),
    inset: 10pt,
    fill: (x, y) => if y == 0 { blue.lighten(90%) },
    [*Categoría*], [*Hallazgo OSINT*],
    [Proveedor de Seguridad], [Imperva Inc. (Identificado mediante certificados SSL)],
    [Gestión de Certificados], [GlobalSign y Let's Encrypt],
    [Infraestructura Web], [Uso de subdominios para entornos de desarrollo (dev, qual)],
    [Proveedores DNS], [Akamai Technologies],
    [Estado de Dorking], [Bajo nivel de exposición de documentos sensibles (Seguridad Preventiva)],
  ),
  caption: [Resumen ejecutivo de hallazgos tecnológicos.],
)

== Conclusiones

La investigación realizada permite concluir que Endesa posee una infraestructura robusta y madura. El uso de un WAF como Imperva sugiere una inversión significativa en protección perimetral. Aunque no se han localizado fugas de documentos críticos mediante Google Dorks, la exposición de subdominios de desarrollo representa un riesgo potencial si estos entornos no están tan protegidos como el portal principal. Como aprendizaje técnico, este laboratorio destaca la importancia de la transparencia de certificados (crt.sh) como una de las fuentes más ricas para el mapeo de activos.

#pagebreak()

== Bibliografía

// Esto vincula tu archivo .bib y hace que las citas sean interactivas
#bibliography("bibliografia.bib", style: "ieee")