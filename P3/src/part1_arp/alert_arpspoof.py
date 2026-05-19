#!/usr/bin/env python3
"""
alert_arpspoof.py — Detección de envenenamiento ARP mediante análisis de
anomalías en respuestas ARP (ARP Spoofing / MITM detection).

Técnicas de Hacking — Universidad Europea
Práctica 3: MITM y Suplantación
"""

from scapy.all import sniff, ARP
from datetime import datetime

# Tabla ARP legítima conocida: {ip: mac}
# Se puebla dinámicamente con el primer ARP reply visto por cada IP
arp_table = {}

# Registro de alertas para evitar spam
alertas_enviadas = set()


def alert_arpspoof(pkt):
    """
    Monitoriza paquetes ARP y detecta anomalías que indican envenenamiento.

    Detecta:
    - Cambio de MAC asociada a una IP ya conocida (ARP Spoofing clásico)
    - Gratuitous ARP (ARP reply no solicitado hacia broadcast)
    """

    # Solo nos interesan ARP replies (op=2)
    if not pkt.haslayer(ARP):
        return
    if pkt[ARP].op != 2:
        return

    ip_src  = pkt[ARP].psrc
    mac_src = pkt[ARP].hwsrc
    ip_dst  = pkt[ARP].pdst
    mac_dst = pkt[ARP].hwdst
    ts      = datetime.now().strftime("%H:%M:%S")

    # --- Anomalía 1: Gratuitous ARP ---
    # Un dispositivo anuncia su propia IP sin que nadie lo haya pedido
    if ip_src == ip_dst or mac_dst == "ff:ff:ff:ff:ff:ff":
        clave = f"gratuitous-{ip_src}-{mac_src}"
        if clave not in alertas_enviadas:
            print(f"[{ts}] [ALERTA] Gratuitous ARP detectado: "
                  f"{ip_src} anuncia su MAC como {mac_src}")
            alertas_enviadas.add(clave)

    # --- Anomalía 2: Cambio de MAC para una IP conocida ---
    if ip_src in arp_table:
        mac_conocida = arp_table[ip_src]
        if mac_conocida != mac_src:
            clave = f"spoof-{ip_src}-{mac_src}"
            if clave not in alertas_enviadas:
                print(f"[{ts}] [ALERTA] ARP Spoofing detectado!")
                print(f"         IP:       {ip_src}")
                print(f"         MAC real: {mac_conocida}")
                print(f"         MAC falsa: {mac_src}")
                print(f"         Posible atacante suplantando al dispositivo "
                      f"legítimo.")
                alertas_enviadas.add(clave)
            # Actualiza la tabla para seguir monitorizando
            arp_table[ip_src] = mac_src
    else:
        # Primera vez que vemos esta IP: la registramos como legítima
        arp_table[ip_src] = mac_src
        ts2 = datetime.now().strftime("%H:%M:%S")
        print(f"[{ts2}] [INFO]  Entrada ARP registrada: {ip_src} → {mac_src}")


def main():
    print("=" * 60)
    print(" IDS ARP — Detector de Envenenamiento de Caché ARP")
    print(" Escuchando en la interfaz de red...")
    print("=" * 60)
    # filter="arp" captura solo paquetes ARP
    sniff(filter="arp", prn=alert_arpspoof, store=False)


if __name__ == "__main__":
    main()