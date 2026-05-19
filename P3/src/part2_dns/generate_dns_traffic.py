#!/usr/bin/env python3
"""
generate_dns_traffic.py — Generador de tráfico DNS malicioso para simular
el ataque de Kaminsky mediante consultas a subdominios inexistentes.

Técnicas de Hacking — Universidad Europea
Práctica 3: MITM y Suplantación
"""

from scapy.all import *
import random
import string
import time

RESOLVER_IP  = "192.168.150.10"
DOMINIO_BASE = "victima.local"
NUMERO_CONSULTAS = 20
INTERVALO = 0.2  # segundos entre consultas


def subdominio_aleatorio(base, longitud=8):
    """Genera un subdominio aleatorio inexistente."""
    chars = string.ascii_lowercase + string.digits
    prefijo = ''.join(random.choices(chars, k=longitud))
    return f"{prefijo}.{base}"


def generar_consulta_dns(subdominio, resolver_ip):
    """Construye y envía un paquete DNS query con Scapy."""
    tid = random.randint(1, 65535)
    pkt = (
        IP(dst=resolver_ip) /
        UDP(sport=random.randint(1024, 65535), dport=53) /
        DNS(id=tid, rd=1, qd=DNSQR(qname=subdominio, qtype="A"))
    )
    send(pkt, verbose=False)
    return subdominio, tid


def main():
    print("=" * 60)
    print(" Generador de tráfico DNS malicioso (Kaminsky simulation)")
    print(f" Objetivo: {RESOLVER_IP}")
    print(f" Dominio base: {DOMINIO_BASE}")
    print(f" Consultas: {NUMERO_CONSULTAS}")
    print("=" * 60)

    for i in range(NUMERO_CONSULTAS):
        subdominio = subdominio_aleatorio(DOMINIO_BASE)
        nombre, tid = generar_consulta_dns(subdominio, RESOLVER_IP)
        ts = time.strftime("%H:%M:%S")
        print(f"[{ts}] [{i+1:02d}/{NUMERO_CONSULTAS}] "
              f"Consulta enviada: {nombre} (TID={tid})")
        time.sleep(INTERVALO)

    print("\n[*] Ataque simulado completado.")


if __name__ == "__main__":
    main()