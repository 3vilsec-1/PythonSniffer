#debemos anadir manejo de paquetes ipv6
#debemos agregar manejo de diferentes protocolos icmp, udp , etc



import socket
import struct


def sniff():
    
    conection = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP) #esto va a crear el socket que va a capturar los paquetes entrantes y salientes configurando el socket para ipv4 / indicando que los paquetes seran en crudo / utilizaremos protocolo ip para manipulacion de encabezados
    conection.bind((socket.gethostbyname(socket.gethostname()), 0))#esto va enlazar el socket raw a nuestra ip donde ejecutemos el script y se asignara un puerto aleatorio disponible para que se ejecute
    
    conection.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)#obligamos a todas las aplicaciones que al pasar por nuestro socket creado incluyan las ip en la cabecera para poder capturarlos
    
    # Habilitar el modo promiscuo
    conection.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

    try:
        while True:
            raw_data, addr = conection.recvfrom(65535)
            analyze_packet(raw_data)
    except KeyboardInterrupt:
        conection.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
        conection.close()



#esta funcion va a tomar la data capturada para procesarla e imprimirla por consola de manera legible
#por el momento lo dejare asi, aunque quisiera convertir los condicionales en funciones separadas para mas organizacion en el codigo
def analyze_packet(raw_data):
    ip_version=(raw_data[0] >> 4) & 0xF #este condicional va a detectar si el paquete es ipv4 o ipv6
    if ip_version == 4:
        ip_header = raw_data[0:20] #esto va a extraer los primeros 20 bytes que corresponden a la cabecera ip
        iph = struct.unpack('!BBHHHBBH4s4s', ip_header) #desempaqueta el ip_header usando la estructura !BBHHHBBH4s4s que es el standard para los paquetes ipv4
        
        version_ihl = iph[0]
        version = version_ihl >> 4
        ihl = version_ihl & 0xF
        ip_header_length = ihl * 4

        ttl = iph[5]
        protocol = iph[6]
        src_address = socket.inet_ntoa(iph[8])
        dst_address = socket.inet_ntoa(iph[9])

        print(f"IP Packet - Version: {version}, Header Length: {ip_header_length} bytes, TTL: {ttl}")
        print(f"Protocol: {protocol}, Source Address: {src_address}, Destination Address: {dst_address}")

        if protocol == 6:  # TCP
            tcp_header = raw_data[ip_header_length:ip_header_length+20]
            tcph = struct.unpack('!HHLLBBHHH', tcp_header)
            
            src_port = tcph[0]
            dst_port = tcph[1]
            sequence = tcph[2]
            acknowledgment = tcph[3]
            doff_reserved = tcph[4]
            tcp_header_length = doff_reserved >> 4
            
            print(f"TCP Packet - Source Port: {src_port}, Destination Port: {dst_port}")
            print(f"Sequence Number: {sequence}, Acknowledgment: {acknowledgment}")
            print(f"Header Length: {tcp_header_length * 4} bytes")

            http_data = raw_data[ip_header_length + tcp_header_length * 4:]
            try:
                http_header = http_data.decode('utf-8')
                if http_header.startswith('GET') or http_header.startswith('POST'):
                    print("HTTP Data:")
                    print(http_header)

            except UnicodeDecodeError:
                pass
    elif ip_version == 6:
        ipv6_header = raw_data[0:40]  # Encabezado IPv6 de 40 bytes
        ipv6h = struct.unpack('!4s4sBB16s16s', ipv6_header)
        src_address = socket.inet_ntop(socket.AF_INET6, ipv6h[4])
        dst_address = socket.inet_ntop(socket.AF_INET6, ipv6h[5])
        payload_length = struct.unpack('!H', ipv6h[2])[0]
        next_header = ipv6h[3]

        print(f"IPv6 Packet - Payload Length: {payload_length} bytes, Next Header: {next_header}")
        print(f"Source Address: {src_address}, Destination Address: {dst_address}")

        if next_header == 6:  # TCP
            tcp_header_start = 40  # IPv6 header length is 40 bytes
            tcp_header = raw_data[tcp_header_start:tcp_header_start+20]
            tcph = struct.unpack('!HHLLBBHHH', tcp_header)
            
            src_port = tcph[0]
            dst_port = tcph[1]
            sequence = tcph[2]
            acknowledgment = tcph[3]
            doff_reserved = tcph[4]
            tcp_header_length = doff_reserved >> 4
            
            print(f"TCP Packet - Source Port: {src_port}, Destination Port: {dst_port}")
            print(f"Sequence Number: {sequence}, Acknowledgment: {acknowledgment}")
            print(f"Header Length: {tcp_header_length * 4} bytes")

            http_data = raw_data[tcp_header_start + tcp_header_length * 4:]
            try:
                http_header = http_data.decode('utf-8')
                if http_header.startswith('GET') or http_header.startswith('POST'):
                    print("HTTP Data:")
                    print(http_header)
            except UnicodeDecodeError:
                pass

    else:
        print("version desconocida")



if __name__ == '__main__':
    sniff()