from scapy.all import IP, TCP, UDP, ICMP, sr, conf
import logging

# Suprimir warnings de scapy
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
conf.verb = 0


def craft_discovery_pkts(protocols, ip_range, pkt_count=None, port=80):
    """
    Construye paquetes de descubrimiento de hosts.

    Args:
        protocols (str | list): Protocolo/s a usar: 'udp', 'tcp_ack', 'icmp_timestamp'
        ip_range (str): IP o rango en formato scapy (ej: '172.28.0.1/24' o '172.28.0.10')
        pkt_count (dict, optional): {protocolo: num_paquetes}. Por defecto 1 por protocolo.
        port (int, optional): Puerto para TCP y UDP. Por defecto 80.

    Returns:
        list: Lista de paquetes construidos
    """

    # Normalizar protocols a lista
    if isinstance(protocols, str):
        protocols = [protocols]

    # Limitar a 3 protocolos
    protocols = protocols[:3]

    # Valor por defecto de pkt_count
    if pkt_count is None:
        pkt_count = {proto: 1 for proto in protocols}

    packets = []

    for proto in protocols:
        n = pkt_count.get(proto, 1)
        proto_lower = proto.lower()

        for _ in range(n):
            if proto_lower == 'udp':
                pkt = IP(dst=ip_range) / UDP(dport=port)

            elif proto_lower == 'tcp_ack':
                pkt = IP(dst=ip_range) / TCP(dport=port, flags='A')

            elif proto_lower == 'icmp_timestamp':
                # Tipo 13 = ICMP Timestamp Request
                pkt = IP(dst=ip_range) / ICMP(type=13, code=0)

            else:
                print(f"[!] Protocolo no reconocido: {proto}")
                continue

            packets.append(pkt)

    return packets


def discover_hosts(protocols, ip_range, pkt_count=None, port=80, timeout=2):
    """
    Usa craft_discovery_pkts + sr() para descubrir hosts activos.

    Args:
        protocols (str | list): Protocolo/s a usar
        ip_range (str): IP o rango
        pkt_count (dict, optional): Num paquetes por protocolo
        port (int, optional): Puerto TCP/UDP
        timeout (int, optional): Timeout de espera de respuesta

    Returns:
        set: IPs activas detectadas
    """

    pkts = craft_discovery_pkts(protocols, ip_range, pkt_count, port)

    if not pkts:
        print("[!] No se generaron paquetes.")
        return set()

    print(f"[*] Enviando {len(pkts)} paquete(s) a {ip_range}...")
    answered, unanswered = sr(pkts, timeout=timeout, verbose=0)

    active_ips = set()
    for sent, received in answered:
        ip = received[IP].src
        active_ips.add(ip)
        print(f"[+] Host activo: {ip}")

    if unanswered:
        print(f"[-] Sin respuesta: {len(unanswered)} paquete(s)")

    return active_ips