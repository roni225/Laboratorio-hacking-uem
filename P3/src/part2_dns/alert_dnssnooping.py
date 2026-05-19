#!/usr/bin/env python3
"""
alert_dnssnooping.py — Detección de DNS Snooping y ataques tipo Kaminsky
mediante análisis de volumen de consultas a subdominios inexistentes (NXDOMAIN).

Técnicas de Hacking — Universidad Europea
Práctica 3: MITM y Suplantación
"""

from scapy.all import sniff, DNS, DNSQR, IP, UDP
from datetime import datetime
from collections import defaultdict
import time

# Configuración del umbral
VENTANA_SEGUNDOS = 5
UMBRAL_NXDOMAIN  = 5

# Registro de consultas por IP origen: {ip: [timestamps]}
consultas = defaultdict(list)
alertas_enviadas = set()


def alert_dnssnooping(pkt):
    """
    Detecta ráfagas de consultas DNS a subdominios inexistentes.
    Firma: más de UMBRAL_NXDOMAIN consultas distintas en VENTANA_SEGUNDOS segundos
    desde la misma IP origen.
    """

    # Solo paquetes DNS sobre UDP con capa IP
    if not (pkt.haslayer(DNS) and pkt.haslayer(IP) and pkt.haslayer(UDP)):
        return

    dns = pkt[DNS]

    # Solo consultas (qr=0), no respuestas
    if dns.qr != 0:
        return

    # Solo si hay pregunta
    if dns.qdcount == 0 or not pkt.haslayer(DNSQR):
        return

    ip_src  = pkt[IP].src
    qname   = pkt[DNSQR].qname.decode(errors="ignore").rstrip(".")
    ts      = datetime.now().strftime("%H:%M:%S")
    ahora   = time.time()

    # Registra la consulta
    consultas[ip_src].append(ahora)

    # Limpia consultas fuera de la ventana
    consultas[ip_src] = [t for t in consultas[ip_src] if ahora - t <= VENTANA_SEGUNDOS]

    total = len(consultas[ip_src])

    print(f"[{ts}] [INFO]  Consulta DNS: {ip_src} → {qname} "
          f"({total}/{UMBRAL_NXDOMAIN} en {VENTANA_SEGUNDOS}s)")

    # Dispara alerta si se supera el umbral
    clave = f"{ip_src}-{int(ahora // VENTANA_SEGUNDOS)}"
    if total >= UMBRAL_NXDOMAIN and clave not in alertas_enviadas:
        print(f"[{ts}] [ALERTA] DNS Snooping / Kaminsky detectado!")
        print(f"         Origen:   {ip_src}")
        print(f"         Consultas en ventana: {total}")
        print(f"         Última consulta: {qname}")
        print(f"         Posible ataque de subdominios falsos o reconocimiento DNS.")
        alertas_enviadas.add(clave)


def main():
    import sys
    iface = sys.argv[1] if len(sys.argv) > 1 else None
    print("=" * 60)
    print(" IDS DNS — Detector de DNS Snooping / Kaminsky")
    print(f" Umbral: {UMBRAL_NXDOMAIN} consultas en {VENTANA_SEGUNDOS}s")
    print(f" Interfaz: {iface if iface else 'todas'}")
    print("=" * 60)
    sniff(filter="udp port 53", prn=alert_dnssnooping, store=False, iface=iface)


if __name__ == "__main__":
    main()