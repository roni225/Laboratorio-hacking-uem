#set document(
  title: "Práctica 3: MITM y Suplantación",
  author: "Estudiante",
)

#set text(lang: "es", font: "New Computer Modern", size: 11pt)
#set page(
  numbering: "1",
  number-align: center,
  margin: (top: 2.5cm, bottom: 2.5cm, left: 2.5cm, right: 2.5cm)
)
#set heading(numbering: "1.")
#set par(justify: true, leading: 0.75em)

#show link: underline

// ─── PORTADA ────────────────────────────────────────────────────────────────
#page(numbering: none)[
  #align(center)[
    #v(2cm)
    #text(size: 16pt, weight: "bold")[Universidad Europea de Madrid]
    #v(0.4cm)
    #text(size: 13pt)[Grado en Ingeniería de la Ciberseguridad]
    #v(0.3cm)
    #text(size: 12pt)[Técnicas de Hacking]
    #v(2.5cm)
    #line(length: 100%, stroke: 2pt)
    #v(0.5cm)
    #text(size: 22pt, weight: "bold")[Práctica 3]
    #v(0.3cm)
    #text(size: 17pt, weight: "bold")[MITM y Suplantación]
    #v(0.4cm)
    #text(size: 13pt)[
      Detección de Envenenamiento ARP y DNS Snooping \
      mediante Sistemas de Detección de Intrusos Basados en Firmas
    ]
    #v(0.5cm)
    #line(length: 100%, stroke: 2pt)
    #v(3cm)
    #grid(
      columns: (1fr, 1fr),
      gutter: 1cm,
      align(left)[
        *Asignatura:* Técnicas de Hacking \
        *Curso:* 2025--2026 \
        *Entrega:* 26 de mayo de 2026
      ],
      align(left)[
        *Profesor:* Alfredo Robledano Abasolo \
        *Contacto:* alfredo.robledano\@universidadeuropea.es
      ]
    )
  ]
]

// ─── RESUMEN ────────────────────────────────────────────────────────────────
#page(numbering: none)[
  #heading(outlined: false, numbering: none)[Resumen]

  Esta práctica implementa un sistema de monitorización capaz de detectar dos tipos de ataques de red habituales en entornos locales: el envenenamiento de tablas ARP y el reconocimiento mediante consultas DNS masivas a subdominios inexistentes (técnica asociada al ataque de Kaminsky).

  En términos no técnicos, el envenenamiento ARP es como si alguien en una oficina cambiara todas las etiquetas de los buzones para que el correo llegue a la persona equivocada. El DNS Snooping es similar a alguien que llama repetidamente a una centralita telefónica preguntando por extensiones inventadas para mapear la estructura interna de la organización.

  Para detectar ambos ataques se han desarrollado dos funciones en Python utilizando la librería Scapy @scapy, desplegadas sobre escenarios de red virtualizados con Docker Compose @docker. Los resultados demuestran que ambos detectores funcionan correctamente, lanzando alertas en tiempo real cuando se superan los umbrales definidos.

  *Palabras clave:* ARP Spoofing, DNS Cache Poisoning, MITM, Kaminsky, IDS, Scapy, Docker.
]

// ─── ÍNDICE ─────────────────────────────────────────────────────────────────
#page(numbering: none)[
  #outline(
    title: [Índice de Contenidos],
    indent: auto,
    depth: 3,
  )
  #v(1cm)
  #outline(
    title: [Índice de Figuras],
    target: figure.where(kind: image),
  )
  #v(1cm)
  #outline(
    title: [Índice de Tablas],
    target: figure.where(kind: table),
  )
]

// ─── CUERPO ─────────────────────────────────────────────────────────────────
#set page(numbering: "1")
#counter(page).update(1)

= Introducción

En un entorno hiperconectado, la integridad de las comunicaciones de red depende de protocolos diseñados décadas atrás, en una época en la que la seguridad no era una prioridad. Dos de los protocolos más fundamentales de las redes locales, ARP y DNS, presentan vulnerabilidades estructurales que permiten a un atacante situado en la misma red manipular el flujo de tráfico sin ser detectado.

El *envenenamiento ARP* (_ARP Spoofing_) explota la naturaleza _stateless_ del protocolo ARP @rfc826: cualquier dispositivo acepta respuestas ARP aunque no haya realizado una petición previa, lo que permite a un atacante asociar su dirección MAC con la IP de otro dispositivo legítimo, posicionándose como intermediario en todas las comunicaciones (_Man-In-The-Middle_, MITM).

El *envenenamiento DNS* (_DNS Cache Poisoning_) aprovecha la misma naturaleza _stateless_ del protocolo UDP sobre el que DNS opera @rfc1034. El ataque de Kaminsky @kaminsky2008, descubierto en 2008, demostró que era posible envenenar la caché de un resolver DNS realizando consultas masivas a subdominios inexistentes e inyectando respuestas falsas en la sección de autoridad.

El objetivo de esta práctica es diseñar e implementar un sistema IDS (_Intrusion Detection System_) basado en firmas capaz de detectar ambos tipos de ataque en tiempo real, utilizando Python con Scapy @scapy sobre escenarios de red virtualizados con Docker @docker.

= Marco Teórico

== El protocolo ARP

El protocolo ARP (_Address Resolution Protocol_) fue definido en 1982 en el RFC 826 @rfc826 y tiene como función resolver direcciones de capa de red (IP) a direcciones de capa de enlace (MAC) dentro de una misma red local. Su funcionamiento es sencillo: cuando un dispositivo A quiere comunicarse con un dispositivo B cuya IP conoce pero cuya MAC desconoce, emite un paquete de broadcast preguntando "¿quién tiene la IP X?". El dispositivo B responde con su MAC, y A almacena esta asociación en su caché ARP local para futuras comunicaciones.

El diseño original de ARP presenta dos características que lo hacen inherentemente vulnerable:

- *Stateless*: el protocolo no mantiene estado. Cualquier dispositivo puede enviar una respuesta ARP en cualquier momento, independientemente de si se realizó una petición previa.
- *Sin autenticación*: no existe ningún mecanismo que permita verificar que la respuesta ARP proviene del dispositivo legítimo.

Estas dos características, combinadas, permiten el ataque conocido como *ARP Spoofing* o *ARP Poisoning*, en el que un atacante envía respuestas ARP falsas para asociar su propia MAC con la IP de otro dispositivo.

=== Estructura del paquete ARP

Un paquete ARP contiene los siguientes campos relevantes para la detección:

#figure(
  table(
    columns: (auto, auto, 1fr),
    align: (center, center, left),
    stroke: 0.5pt,
    fill: (col, row) => if row == 0 { luma(220) } else { white },
    [*Campo*], [*Tamaño*], [*Descripción*],
    [`op`],    [2 bytes],  [Operación: 1 = request, 2 = reply],
    [`hwsrc`], [6 bytes],  [MAC del emisor],
    [`psrc`],  [4 bytes],  [IP del emisor],
    [`hwdst`], [6 bytes],  [MAC del destinatario],
    [`pdst`],  [4 bytes],  [IP del destinatario],
  ),
  caption: [Campos del protocolo ARP relevantes para la detección de spoofing]
) <tabla-campos-arp>

El campo `op=2` identifica un ARP reply. Un _Gratuitous ARP_ se produce cuando `psrc == pdst`, es decir, cuando un dispositivo anuncia su propia IP sin que nadie lo haya solicitado.

=== ARP Spoofing y MITM

El ataque ARP Spoofing permite al atacante posicionarse como intermediario (_Man-In-The-Middle_) entre la víctima y el gateway. El flujo del ataque es el siguiente:

+ El atacante envía un ARP reply falso a la víctima, indicando que la IP del router corresponde a su propia MAC.
+ El atacante envía otro ARP reply falso al router, indicando que la IP de la víctima corresponde a su propia MAC.
+ Todo el tráfico entre víctima y router pasa ahora por el atacante, quien puede interceptarlo, modificarlo o simplemente reenviarlo.

Este ataque es la base de numerosas técnicas más avanzadas como el _SSL Stripping_, la inyección de contenido HTTP o el robo de credenciales.

== El protocolo DNS

El Sistema de Nombres de Dominio (_Domain Name System_, DNS) fue definido en 1987 en los RFC 1034 y 1035 @rfc1034. Su función es traducir nombres de dominio legibles por humanos (como `www.google.com`) a direcciones IP numéricas que los dispositivos utilizan para comunicarse.

=== Jerarquía DNS

DNS está organizado de forma jerárquica. Cuando un cliente realiza una consulta, el proceso de resolución implica varios actores:

#figure(
  table(
    columns: (auto, 1fr),
    align: (center, left),
    stroke: 0.5pt,
    fill: (col, row) => if row == 0 { luma(220) } else { white },
    [*Componente*], [*Función*],
    [DNS Client],              [Aplicación que realiza la consulta (navegador, SO)],
    [Resolver recursivo],      [Servidor que realiza la resolución completa en nombre del cliente],
    [Root nameserver],         [Conoce los servidores TLD. Existen 13 clusters (a--m.root-servers.net)],
    [TLD nameserver],          [Gestiona el TLD (.com, .es, .org...). Conoce los servidores autoritativos],
    [Authoritative nameserver],[Tiene la respuesta definitiva para el dominio consultado],
  ),
  caption: [Componentes del sistema DNS y sus funciones]
) <tabla-componentes-dns>

=== Vulnerabilidades del protocolo DNS

DNS opera sobre UDP en el puerto 53, heredando su naturaleza _stateless_. Un paquete DNS es aceptado como respuesta legítima si cumple tres condiciones:

+ Llega al puerto de origen correcto (aleatorio desde 2008).
+ Contiene el Transaction ID correcto (16 bits, aleatorio).
+ Tiene el flag QR=1 (respuesta).

Antes de 2008, el puerto de origen no era aleatorio, lo que reducía el espacio de búsqueda a solo 65.536 valores posibles (el Transaction ID). El ataque de Kaminsky @kaminsky2008 explotó esta debilidad de forma brillante.

=== El ataque de Kaminsky

Dan Kaminsky presentó en Black Hat 2008 un ataque que permitía envenenar la caché de cualquier resolver DNS sin necesidad de estar en la misma red. La técnica se basa en:

+ Realizar consultas masivas a subdominios inexistentes del dominio objetivo (p.ej., `abc123.victima.com`, `xyz789.victima.com`...).
+ Para cada consulta, enviar simultáneamente miles de respuestas falsas con diferentes Transaction IDs intentando adivinar el correcto.
+ En la sección de autoridad (_Authority Section_) de la respuesta falsa, incluir una entrada que envenena la caché del resolver para el dominio raíz.

La clave del ataque es que cada consulta a un subdominio inexistente obliga al resolver a realizar una nueva petición externa, reiniciando la "carrera" y permitiendo múltiples intentos sin esperar al TTL. Tras el descubrimiento, todos los resolvers modernos implementaron la aleatorización del puerto de origen, elevando el espacio de búsqueda a $2^{32}$ combinaciones.

== Herramientas utilizadas

=== Scapy

Scapy @scapy es una librería de Python que permite la creación, envío, captura y análisis de paquetes de red a bajo nivel. Es ampliamente utilizada en investigación de seguridad y permite construir paquetes arbitrarios en cualquier capa del modelo OSI. En esta práctica se utiliza tanto para el envío de paquetes ARP y DNS maliciosos como para la captura y análisis de tráfico en los detectores.

=== bettercap

bettercap @bettercap es una herramienta de seguridad ofensiva modular que implementa, entre otras funcionalidades, ataques ARP Spoofing con soporte para modo _full-duplex_ (envenenamiento simultáneo de víctima y gateway). En esta práctica se utilizó para la fase de descubrimiento de hosts y como herramienta de ataque en el escenario ARP.

=== BIND9

BIND9 @bind9 (_Berkeley Internet Name Domain_) es el servidor DNS más utilizado en Internet. En esta práctica se empleó tanto como resolver recursivo como servidor autoritativo para la zona `victima.local`, proporcionando un entorno DNS realista sobre el que validar el detector.

=== Docker y Docker Compose

Docker @docker permite virtualizar entornos de red completos mediante contenedores ligeros. Docker Compose facilita la definición declarativa de escenarios multi-contenedor con topologías de red personalizadas. El uso de contenedores frente a máquinas virtuales reduce significativamente el tiempo de despliegue y el consumo de recursos, siendo ideal para entornos de laboratorio.

= Metodología

== Justificación del enfoque

La detección de ataques de red puede abordarse desde dos perspectivas complementarias:

#figure(
  table(
    columns: (auto, 1fr, 1fr),
    align: (center, left, left),
    stroke: 0.5pt,
    fill: (col, row) => if row == 0 { luma(220) } else { white },
    [*Enfoque*], [*Ventajas*], [*Inconvenientes*],
    [Basado en firmas],    [Alta precisión, bajo coste computacional, fácil de auditar], [No detecta variantes desconocidas del ataque],
    [Basado en anomalías], [Detecta ataques nuevos, adaptable],                          [Mayor tasa de falsos positivos, más complejo],
  ),
  caption: [Comparativa de enfoques de detección IDS]
) <tabla-enfoques-ids>

En esta práctica se ha optado por el enfoque basado en firmas, más apropiado para ataques bien conocidos y documentados como el ARP Spoofing y el DNS Snooping.

== Metodología de desarrollo

El desarrollo de la práctica siguió la siguiente metodología:

+ *Despliegue del escenario*: definición de la topología en Docker Compose y verificación de la conectividad entre nodos.
+ *Establecimiento del estado legítimo*: captura del estado normal de la red (tabla ARP limpia, resolución DNS correcta) como línea base.
+ *Simulación del ataque*: ejecución del ataque con herramientas reales (bettercap, Scapy) para generar tráfico malicioso real.
+ *Implementación del detector*: desarrollo de las funciones de detección en Python con Scapy.
+ *Validación*: verificación de que el detector genera alertas correctas ante el tráfico malicioso.

== Entorno de laboratorio

#figure(
  table(
    columns: (auto, 1fr),
    align: (center, left),
    stroke: 0.5pt,
    fill: (col, row) => if row == 0 { luma(220) } else { white },
    [*Componente*], [*Versión / Detalle*],
    [Sistema operativo], [Kali Linux (VirtualBox)],
    [Docker],            [27.5.1],
    [Docker Compose],    [2.32.4],
    [Python],            [3.13],
    [Scapy],             [2.7.0],
    [bettercap],         [2.41.5],
    [BIND9],             [9.18.39],
    [uv],                [Gestor de dependencias Python],
  ),
  caption: [Entorno de laboratorio utilizado]
) <tabla-entorno>

== Gestión de dependencias

Las dependencias Python de cada parte se gestionaron con `uv`, inicializando proyectos independientes con `uv init --bare` en cada subdirectorio:

```
P3/
├── pyproject.toml
└── src/
    ├── part1_arp/
    │   ├── pyproject.toml  ← scapy
    │   └── uv.lock
    └── part2_dns/
        ├── pyproject.toml  ← scapy
        └── uv.lock
```

= Desarrollo

== Parte 1: Detección de Envenenamiento ARP

=== Escenario de red

Se ha definido un escenario de red mediante Docker Compose @docker que incluye cuatro nodos distribuidos en dos redes virtuales:

#figure(
  table(
    columns: (auto, auto, auto, auto),
    align: center,
    stroke: 0.5pt,
    fill: (col, row) => if row == 0 { luma(220) } else { white },
    [*Contenedor*], [*Imagen*],               [*IP*],                       [*Rol*],
    [victim],       [ubuntu:22.04],            [192.168.100.10],             [Nodo víctima],
    [router],       [ubuntu:22.04],            [192.168.100.20 / .200.20],   [Gateway entre redes],
    [webserver],    [nginx:alpine],            [192.168.200.30],             [Servidor web externo],
    [attacker],     [kalilinux/kali-rolling],  [192.168.100.99],             [Nodo atacante],
  ),
  caption: [Topología del escenario ARP]
) <tabla-topologia-arp>

#figure(
  image("imagenes/Docker_compose_up.png", width: 100%),
  caption: [Contenedores del escenario ARP levantados correctamente]
) <fig-docker-arp>

=== Estado legítimo de la tabla ARP

Antes de ejecutar el ataque, se registró el estado legítimo de la tabla ARP de la víctima:

#figure(
  image("imagenes/Tabla_ARP_victima.png", width: 90%),
  caption: [Tabla ARP legítima de la víctima antes del envenenamiento]
) <fig-arp-legitima>

Como se observa en @fig-arp-legitima, la dirección IP `192.168.100.20` está correctamente asociada a la MAC `02:42:c0:a8:64:14`, correspondiente al router legítimo.

=== Ataque: ARP Spoofing con bettercap y Scapy

El ataque se realizó en dos fases. Primero se utilizó bettercap @bettercap para el descubrimiento de hosts y la fase inicial del spoofing. Posteriormente, dado el aislamiento propio del bridge de Docker, se empleó Scapy @scapy directamente desde el host para inyectar paquetes ARP falsos en el namespace de red de la víctima mediante `nsenter`:

#figure(
  image("imagenes/tabla_ARP_victima_envenenada.png", width: 90%),
  caption: [Tabla ARP de la víctima tras el envenenamiento: la MAC del router ha sido sustituida por la del atacante]
) <fig-arp-envenenada>

En @fig-arp-envenenada se aprecia que la entrada para `192.168.100.20` muestra ahora la MAC `02:42:c0:a8:64:63` (atacante), con flag `CM` indicando una entrada estática modificada.

=== Función `alert_arpspoof`

Se implementó la función `alert_arpspoof` en Python con Scapy que monitoriza los paquetes ARP en tiempo real y detecta las siguientes anomalías:

#figure(
  table(
    columns: (auto, 1fr),
    align: (center, left),
    stroke: 0.5pt,
    fill: (col, row) => if row == 0 { luma(220) } else { white },
    [*Anomalía detectada*], [*Descripción*],
    [Cambio de MAC],   [Una IP conocida aparece asociada a una MAC distinta a la registrada],
    [Gratuitous ARP],  [ARP reply enviado sin solicitud previa o hacia broadcast],
  ),
  caption: [Firmas de detección implementadas en `alert_arpspoof`]
) <tabla-firmas-arp>

=== Resultados: detección en tiempo real

#figure(
  image("imagenes/Deteccion_correcta_envenenamiento.png", width: 100%),
  caption: [Alerta disparada por `alert_arpspoof` al detectar el cambio de MAC para `192.168.100.20`]
) <fig-alerta-arp>

Como se muestra en @fig-alerta-arp, el detector identifica correctamente el ataque, mostrando la IP afectada, la MAC legítima y la MAC falsa del atacante.

== Parte 2: Suplantación y Anomalías DNS

=== Escenario de red

Se desplegó un segundo escenario Docker con tres nodos:

#figure(
  table(
    columns: (auto, auto, auto, auto),
    align: center,
    stroke: 0.5pt,
    fill: (col, row) => if row == 0 { luma(220) } else { white },
    [*Contenedor*], [*Imagen*],       [*IP*],           [*Rol*],
    [resolver],     [ubuntu/bind9],   [192.168.150.10], [DNS Resolver recursivo],
    [authns],       [ubuntu/bind9],   [192.168.150.20], [Servidor autoritativo],
    [client],       [ubuntu:22.04],   [192.168.150.30], [Cliente DNS],
  ),
  caption: [Topología del escenario DNS]
) <tabla-topologia-dns>

#figure(
  image("imagenes/Dockers_DNS.png", width: 100%),
  caption: [Contenedores del escenario DNS levantados correctamente]
) <fig-docker-dns>

=== Configuración DNS

Se configuró BIND9 @bind9 como resolver recursivo y servidor autoritativo para la zona `victima.local`. La correcta resolución del dominio se verificó mediante `dig`:

#figure(
  image("imagenes/DNS_resolver_funciona.png", width: 100%),
  caption: [Resolución correcta de `www.victima.local` a través del resolver]
) <fig-dns-funciona>

=== Ataque: simulación del ataque de Kaminsky

El script `generate_dns_traffic.py` genera consultas UDP con Scapy hacia el resolver usando subdominios aleatorios inexistentes:

#figure(
  table(
    columns: (auto, 1fr),
    align: (center, left),
    stroke: 0.5pt,
    fill: (col, row) => if row == 0 { luma(220) } else { white },
    [*Parámetro*],        [*Valor*],
    [Dominio base],       [`victima.local`],
    [Subdominios],        [Aleatorios de 8 caracteres alfanuméricos],
    [Transaction ID],     [Aleatorio (16 bits)],
    [Puerto origen],      [Aleatorio (1024--65535)],
    [Número de consultas],[20],
    [Intervalo],          [0.2 segundos],
  ),
  caption: [Parámetros del generador de tráfico DNS malicioso]
) <tabla-params-dns>

=== Función `alert_dnssnooping`

#figure(
  table(
    columns: (auto, 1fr),
    align: (center, left),
    stroke: 0.5pt,
    fill: (col, row) => if row == 0 { luma(220) } else { white },
    [*Parámetro*],         [*Valor*],
    [Ventana temporal],    [5 segundos],
    [Umbral de consultas], [5 consultas por IP],
    [Filtro],              [UDP puerto 53, solo queries (QR=0)],
    [Agrupación],          [Por IP origen],
  ),
  caption: [Parámetros de detección de `alert_dnssnooping`]
) <tabla-params-ids>

=== Resultados: detección en tiempo real

#figure(
  image("imagenes/Detector_DNS_funciona.png", width: 100%),
  caption: [Alertas disparadas por `alert_dnssnooping` al superar el umbral de consultas DNS sospechosas]
) <fig-alerta-dns>

= Análisis del Tráfico Capturado

== Análisis del tráfico ARP

=== Comparativa entre tráfico ARP legítimo y envenenado

#figure(
  table(
    columns: (auto, auto, auto, auto),
    align: center,
    stroke: 0.5pt,
    fill: (col, row) => if row == 0 { luma(220) } else { white },
    [*Campo*],   [*Valor legítimo*],       [*Valor envenenado*],      [*Diferencia*],
    [`op`],      [2 (reply)],              [2 (reply)],               [—],
    [`psrc`],    [`192.168.100.20`],       [`192.168.100.20`],        [Igual],
    [`hwsrc`],   [`02:42:c0:a8:64:14`],   [`02:42:c0:a8:64:63`],    [*MAC diferente* ← firma],
    [`pdst`],    [`192.168.100.10`],       [`192.168.100.10`],        [Igual],
  ),
  caption: [Comparativa entre paquete ARP legítimo y envenenado]
) <tabla-comparativa-arp>

La firma de detección se basa en esta discrepancia: la IP de origen (`psrc`) es la del router legítimo, pero la MAC de origen (`hwsrc`) pertenece al atacante.

=== Secuencia temporal del ataque ARP

#figure(
  table(
    columns: (auto, auto, 1fr),
    align: (center, center, left),
    stroke: 0.5pt,
    fill: (col, row) => if row == 0 { luma(220) } else { white },
    [*Tiempo*], [*Origen*],  [*Evento*],
    [T+0s],    [Víctima],   [Ping al router → ARP request legítimo],
    [T+1s],    [Router],    [ARP reply legítimo: MAC `02:42:c0:a8:64:14`],
    [T+2s],    [Detector],  [Registra: `192.168.100.20` → `02:42:c0:a8:64:14`],
    [T+60s],   [Atacante],  [ARP reply falso: MAC `02:42:c0:a8:64:63`],
    [T+60s],   [Detector],  [*ALERTA*: cambio de MAC detectado],
  ),
  caption: [Secuencia temporal del ataque ARP y detección]
) <tabla-secuencia-arp>

== Análisis del tráfico DNS

=== Estructura de un paquete DNS de consulta

#figure(
  table(
    columns: (auto, auto, 1fr),
    align: (center, center, left),
    stroke: 0.5pt,
    fill: (col, row) => if row == 0 { luma(220) } else { white },
    [*Capa*], [*Campo*],   [*Valor típico*],
    [IP],     [`src`],     [IP del cliente],
    [IP],     [`dst`],     [IP del resolver (192.168.150.10)],
    [UDP],    [`sport`],   [Puerto aleatorio > 1024],
    [UDP],    [`dport`],   [53],
    [DNS],    [`id`],      [Transaction ID aleatorio (0--65535)],
    [DNS],    [`qr`],      [0 (query)],
    [DNS],    [`rd`],      [1 (recursión deseada)],
    [DNS],    [`qname`],   [Nombre consultado],
    [DNS],    [`qtype`],   [A (dirección IPv4)],
  ),
  caption: [Estructura de un paquete DNS query capturado con Scapy]
) <tabla-estructura-dns>

=== Patrón de tráfico del ataque de Kaminsky

#figure(
  table(
    columns: (auto, 1fr, 1fr),
    align: (center, left, left),
    stroke: 0.5pt,
    fill: (col, row) => if row == 0 { luma(220) } else { white },
    [*Característica*],  [*Tráfico legítimo*],            [*Tráfico malicioso (Kaminsky)*],
    [Frecuencia],        [Baja, esporádica],              [Alta, ráfagas sostenidas],
    [Subdominios],       [Conocidos y repetidos],         [Aleatorios, nunca repetidos],
    [Respuestas],        [NOERROR],                       [NXDOMAIN],
    [Transaction ID],    [Secuencial o bajo],             [Completamente aleatorio],
    [Puerto origen],     [Variable],                      [Aleatorio en cada paquete],
  ),
  caption: [Comparativa entre tráfico DNS legítimo y ataque de Kaminsky]
) <tabla-comparativa-dns>

=== Secuencia temporal del ataque DNS

#figure(
  table(
    columns: (auto, auto, 1fr),
    align: (center, center, left),
    stroke: 0.5pt,
    fill: (col, row) => if row == 0 { luma(220) } else { white },
    [*Tiempo*],        [*Evento*],        [*Detalle*],
    [T+0.0s],          [Consulta 1/20],   [`cz24ktcu.victima.local` (TID=40105)],
    [T+0.2s],          [Consulta 2/20],   [`q2isv8uw.victima.local` (TID=62661)],
    [T+0.4s],          [Consulta 3/20],   [`61zy6vwl.victima.local` (TID=34354)],
    [T+0.6s],          [Consulta 4/20],   [`mhim18yu.victima.local` (TID=18855)],
    [T+0.8s],          [Consulta 5/20],   [`5zf1pmlc.victima.local` (TID=46796)],
    [T+0.8s],          [*ALERTA*],        [Umbral superado: 5 consultas en 5s],
    [T+1.0s--4.0s],    [Consultas 6--20], [Continúan las consultas a subdominios aleatorios],
    [T+2.6s],          [*ALERTA*],        [Segunda alerta: 13 consultas en ventana],
  ),
  caption: [Secuencia temporal del ataque DNS y detección]
) <tabla-secuencia-dns>

== Limitaciones del entorno Docker

#figure(
  table(
    columns: (auto, 1fr, 1fr),
    align: (center, left, left),
    stroke: 0.5pt,
    fill: (col, row) => if row == 0 { luma(220) } else { white },
    [*Limitación*],               [*Causa*],                                         [*Solución adoptada*],
    [ARP filtering en bridges],   [Docker filtra paquetes ARP entre contenedores],   [Uso de `nsenter` en namespace de red de la víctima],
    [Scapy no ve tráfico Docker], [El bridge Docker aísla el tráfico del host],      [Ejecución de scripts dentro del namespace],
    [pip en contenedores Kali],   [Entorno Python externamente gestionado],           [Flag `--break-system-packages`],
  ),
  caption: [Limitaciones del entorno Docker y soluciones adoptadas]
) <tabla-limitaciones>

= Resultados

== Resumen de detecciones

#figure(
  table(
    columns: (auto, auto, auto, auto),
    align: center,
    stroke: 0.5pt,
    fill: (col, row) => if row == 0 { luma(220) } else { white },
    [*Parte*],    [*Ataque simulado*],                       [*Alertas generadas*],          [*Resultado*],
    [1 — ARP],    [ARP Spoofing (bettercap + Scapy)],       [1 alerta de cambio de MAC],    [✓ Detectado],
    [2 — DNS],    [DNS Snooping / Kaminsky (20 consultas)],  [2 alertas por umbral],         [✓ Detectado],
  ),
  caption: [Resumen de resultados de detección]
) <tabla-resultados>

== Comparativa de detectores

#figure(
  table(
    columns: (auto, auto, auto, auto, auto),
    align: center,
    stroke: 0.5pt,
    fill: (col, row) => if row == 0 { luma(220) } else { white },
    [*Detector*],           [*Protocolo*], [*Capa OSI*], [*Método*],           [*Falsos positivos*],
    [`alert_arpspoof`],     [ARP],         [Capa 2],     [Firma: cambio MAC],  [Bajos],
    [`alert_dnssnooping`],  [DNS],         [Capa 7],     [Umbral de volumen],  [Medios],
  ),
  caption: [Comparativa de los detectores implementados]
) <tabla-comparativa-detectores>

= Conclusiones

Esta práctica ha permitido comprender en profundidad dos de los vectores de ataque más clásicos y persistentes en redes locales: el envenenamiento ARP y el DNS Snooping/Kaminsky.

Se ha demostrado que es posible detectar ambos ataques en tiempo real mediante análisis de tráfico basado en firmas, implementado con herramientas de código abierto como Scapy @scapy. Los detectores desarrollados presentan características complementarias:

- `alert_arpspoof` detecta cambios inesperados en la asociación IP→MAC con baja tasa de falsos positivos, al basarse en una firma determinista y bien definida.
- `alert_dnssnooping` detecta ráfagas de consultas DNS mediante umbral de volumen, técnica propia de los IDS de red modernos, con mayor sensibilidad pero también mayor riesgo de falsos positivos en entornos con alto volumen de consultas legítimas.

Como limitaciones identificadas, el entorno Docker introduce restricciones en la propagación de paquetes ARP entre contenedores, requiriendo el uso de `nsenter` para acceder al namespace de red correcto. En una red física real, ambos detectores operarían sin estas restricciones.

Como trabajo futuro se propone la integración de DNSSEC @rfc1034 para mitigar el envenenamiento DNS mediante firma digital de registros, y el uso de entradas ARP estáticas o _Dynamic ARP Inspection_ (DAI) en switches gestionados para prevenir el ARP Spoofing a nivel de infraestructura.

#bibliography("references.bib", style: "ieee")
