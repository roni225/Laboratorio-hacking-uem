from scapy.all import IP, TCP, UDP, ICMP, sr1, sr
import logging

# Desactivar avisos de Scapy
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

def craft_discovery_pkts(protocolos, rango_ip, conteos=None, puerto=80):
    """
    Crea paquetes para host discovery según la rúbrica.
    """
    paquetes = []
    # Normalizar protocolos a lista
    if isinstance(protocolos, str):
        protocolos = [protocolos]
    
    # Normalizar IPs a lista (soporta formato Scapy)
    objetivos = [rango_ip] if isinstance(rango_ip, str) else rango_ip

    for ip in objetivos:
        for proto in protocolos:
            proto_up = proto.upper()
            # Determinar número de paquetes (opcional en rúbrica)
            num = conteos.get(proto, 1) if conteos else 1
            
            for _ in range(num):
                if proto_up == "TCP":
                    # TCP ACK como pide el enunciado
                    paquetes.append(IP(dst=ip)/TCP(dport=puerto, flags="A"))
                elif proto_up == "UDP":
                    paquetes.append(IP(dst=ip)/UDP(dport=puerto))
                elif proto_up == "ICMP":
                    # ICMP Timestamp (Type 13) como pide el enunciado
                    paquetes.append(IP(dst=ip)/ICMP(type=13))
    
    return paquetes # Movido fuera del bucle para que funcione

def descubrimiento_hosts(ips, protos=["ICMP", "TCP"]):
    print(f"[*] Iniciando descubrimiento en: {ips}")
    pkts = craft_discovery_pkts(protos, ips, puerto=443)
    
    # Enviamos y recibimos
    respondidos, _ = sr(pkts, timeout=2, verbose=False)
    
    hosts_activos = {recibido.src for enviado, recibido in respondidos}
    
    print(f"\n[+] Resultados del escaneo:")
    for host in sorted(hosts_activos):
        print(f" -> Host activo detectado: {host}")

if __name__ == "__main__":
    # Prueba con un host activo (Google) y uno inactivo para la evidencia
    objetivos = ["8.8.8.8", "192.168.1.250"] 
    descubrimiento_hosts(objetivos)