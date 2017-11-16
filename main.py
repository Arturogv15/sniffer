import socket, sys
from socket import AF_INET6
from struct import *
import pandas

#Convertir una cadena de 6 caracteres de la direccion Ethernet en una cadena hexadecimal separada por puntos
def eth_addr (a) :
  eth = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (ord(a[0]) , ord(a[1]) , ord(a[2]), ord(a[3]), ord(a[4]) , ord(a[5]))
  return eth

#socket.IPPROTO_TCP
#socket.IPPROTO_UDP
#socket.IPPROTO_ICMP
#socket.ntohs(0x0003) -> Recibe todos los paquetes IP (TC,UDP,ICMP) y paquetes de ARP si existen
# Regresa tambien la cabecera de Ethernet en el mismo paquete

try:
    s = socket.socket( socket.AF_PACKET , socket.SOCK_RAW , socket.ntohs(0x0003))
except socket.error , mensaje:
    print 'El socket no se pudo crear. Codigo de error: ' + str(mensaje[0]) + ' Mensaje ' + mensaje[1]
    sys.exit()

#Se recibe un paquete
while True:

    packet = s.recvfrom(65565)
    packet = packet[0]

    #Tamanioo de la cabecera de Ethernet
    eth_length = 14

    #Se obtiene la cabecera completa del paquete
    eth_header = packet[:eth_length]

    #!6s6sH indica el formato del desempaquetado, y eth_header es lo que se va a desempaquetar
    #El primer caracter indica el tamanioo, alineacion y el byte order de los datos empaquetados
    #   ! -> indica el byte order si es little-endian o big-endian
    #Los siguientes caracteres indican el formato completo de los datos
    # 6s ->  indica que se leera una cadena de caracteres de longitud igual a 6
    # H  -> indica un entero de tamanioo estandar 2 (unsigned short)
    eth = unpack('!6s6sH' , eth_header)

    #regresa el numero indicador del protocolo de Ethernet
    #nthos convierte el entero unsigned short a un host byte order
    eth_protocol = socket.ntohs(eth[2])

    #Manda llamar a la funcion eth_adrr para parsear los datos del paquete y obtener asi la direccion fuente y la destino
    print 'MAC destino : ' + eth_addr(packet[0:6])
    print 'MAC fuente : ' + eth_addr(packet[6:12])
    if(eth_protocol==8):
        protocolo = "IPv4"
    elif(eth_protocol==56710):
        protocolo = "IPv6"   #ICMP, ICMPv6, UDP, OTROS
    elif(eth_protocol==1544):
        protocolo = "ARP"

    print "Protocolo: " + protocolo
    #print 'Protocolo : ' + str(eth_protocol)

     #IP = 8
    if eth_protocol == 8:
        #Parsear la cabecera IP
        #Despues de leer las direcciones destino, fuente y el protocolo ahora se obtiene la cabecera IP
        #Se lee desde donde se habia quedado la lectura anterior.
        ip_header = packet[eth_length:20+eth_length]

        #Se hace el desempaquetado de la cabecera
        # B -> indica un entero (unsigned char) de longitud 1
        #Total(tamanioo) = 1+1+2+2+2+1+1+2+4char+4char
        iph = unpack('!BBHHHBBH4s4s' , ip_header)

        #Se obtiene la version y el tamanio de la cabecera
        version_ihl = iph[0]
        version = version_ihl >> 4
        ihl = version_ihl & 0xF

        iph_length = ihl * 4
        #Tiempo de vida del paquete
        ttl = iph[5]
        #Protocolo del paquete
        protocol = iph[6]
        #Checksum del header
        checksum = iph[7]
        #Direccion fuente
        s_addr = socket.inet_ntoa(iph[8]);
        #Direccion destino
        d_addr = socket.inet_ntoa(iph[9]);

        print 'Version: ' + str(version)
        print 'Tamanio de cabecera IP: ' + str(ihl)
        print 'TTL : ' + str(ttl)
        print 'Protocolo : ' + str(protocol)
        print 'Checksum: ' + str(checksum)
        print 'Direccion fuente: ' + str(s_addr)
        print 'Direccion destino: ' + str(d_addr)

        #Protocolo TCP
        if protocol == 6 :
            print "-------------------------------------------------------"
            print "Protocolo TCP"
            #Tamanio leido del paquete hasta el momento
            t = iph_length + eth_length
            tcp_header = packet[t:t+20]

            #Desempaquetar la cabecera TCP
            # L -> Indica un entero (unsigned long) de 4 bytes.
            tcph = unpack('!HHLLBBHHH' , tcp_header)

            #Numero de puerto fuente
            source_port = tcph[0]
            #Numero de puerto destino
            dest_port = tcph[1]
            #Numero de Secuencia
            sequence = tcph[2]
            #Numero de acuse de recibido
            acknowledgement = tcph[3]
            #Desplazamiento de datos y reservado
            doff_reserved = tcph[4]
            #Longitu de cabecera
            tcph_length = doff_reserved >> 4

            print 'Puerto fuente: ' + str(source_port)
            print 'Puerto destino: ' + str(dest_port)
            print 'Numero de secuencia : ' + str(sequence)
            print 'Acknowledgement (numero de acuse de recibido): ' + str(acknowledgement)
            print 'Tamanio de cabecera TCP: ' + str(tcph_length)

            h_size = eth_length + iph_length + tcph_length * 4
            data_size = len(packet) - h_size
            print 'Tamanio de los datos: ' + str(data_size)
            #Obtener los datos del paquete
            data = packet[h_size:]
            print 'Datos : ' + data

        elif protocol == 1 :
            print "Protocolo ICMP"
            print "------------------------------------"
            u = iph_length + eth_length
            #Tamanio de la cabecera de ICMP
            icmph_length = 4
            icmp_header = packet[u:u+4]

            #Desempaquetado de ICMP
            icmph = unpack('!BBH' , icmp_header)

             #Tipo de protocolo
            icmp_type = icmph[0]
            #Codigo
            code = icmph[1]
            #Checksum
            checksum = icmph[2]

            print 'Tipo: ' + str(icmp_type)
            print 'Codigo: ' + str(code)
            print 'Checksum: ' + str(checksum)

            h_size = eth_length + iph_length + icmph_length
            data_size = len(packet) - h_size

            #Obtener datos a partir del tamanio indicado
            data = packet[h_size:]

            print 'Datos: ' + data


        elif protocol == 17 :
            print "Protocolo UDP"
            #print "------------------------------------"
            u = iph_length + eth_length
            udph_length = 8
            udp_header = packet[u:u+8]

            udph = unpack('!HHHH' , udp_header)

            source_port = udph[0]
            dest_port = udph[1]
            length = udph[2]
            checksum = udph[3]

            print 'Puerto fuente: ' + str(source_port)
            print 'Puerto destino: ' + str(dest_port)
            print 'Tamanio: ' + str(length)
            print 'Checksum: ' + str(checksum)

            h_size = eth_length + iph_length + udph_length
            data_size = len(packet) - h_size

            #obtener los datos del paquete
            data = packet[h_size:]

            print 'Datos: ' + data

        else :
            print 'Son otros protocolos diferentes TCP/UDP/ICMP'

        print
        print "-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-"
        print " "

    elif eth_protocol == 56710:


        #Se lee desde donde se habia quedado la lectura anterior.
        ip_header = packet[eth_length:40+eth_length]

        #Se hace el desempaquetado de la cabecera

        iph = unpack('!4sHBB16s16s' , ip_header)
        print "-----------------------"
        protocolo = iph[2]
        iph_length = 40
        direccion_fuente = socket.inet_ntop(AF_INET6, iph[4]);
        direccion_destino = socket.inet_ntop(AF_INET6, iph[5]);
        print "Protocolo: " + str(protocolo)
        print "Tamanio: " + str(iph_length)
        print "Direccion fuente: " + str(direccion_fuente)
        print "Direccion destino: " + str(direccion_destino)




        if protocolo == 6 :
            print "-------------------------------------------------------"
            print "Protocolo TCP"
            #Tamanio leido del paquete hasta el momento
            t = iph_length + eth_length
            tcp_header = packet[t:t+20]

            #Desempaquetar la cabecera TCP

        #    if len(tcp_header) >= 20:
            tcph = unpack('!HHLLBBHHH' , tcp_header)

            #Numero de puerto fuente
            source_port = tcph[0]
            #Numero de puerto destino
            dest_port = tcph[1]
            #Numero de Secuencia
            sequence = tcph[2]
            #Numero de acuse de recibido
            acknowledgement = tcph[3]
            #Desplazamiento de datos y reservado
            doff_reserved = tcph[4]
            #Longitu de cabecera
            tcph_length = doff_reserved >> 4

            print 'Puerto fuente: ' + str(source_port)
            print 'Puerto destino: ' + str(dest_port)
            print 'Numero de secuencia : ' + str(sequence)
            print 'Acknowledgement (numero de acuse de recibido): ' + str(acknowledgement)
            print 'Tamanio de cabecera TCP: ' + str(tcph_length)

            h_size = eth_length + iph_length + tcph_length * 4
            data_size = len(packet) - h_size
            print 'Tamanio de los datos: ' + str(data_size)
            #Obtener los datos del paquete
            data = packet[h_size:]
            print 'Datos : ' + data
        #    else:
        #        print "Tamanio de cabecera TCP menor a 20"

        elif protocolo == 58 :
            print "Protocolo ICMP"
            print "------------------------------------"
            u = iph_length + eth_length
            #Tamanio de la cabecera de ICMP
            icmph_length = 4
            icmp_header = packet[u:u+4]
            #print "Tamanio de icmp " + str(len(icmp_header))
        #    if len(icmp_header) >= 4:
                #Desempaquetado de ICMP
            icmph = unpack('!BBH' , icmp_header)
            print "ICMP - " + str(icmph)

             #Tipo de protocolo
            icmp_type = icmph[0]
            #Codigo
            code = icmph[1]
            #Checksum
            checksum = icmph[2]

            print 'Tipo: ' + str(icmp_type)
            print 'Codigo: ' + str(code)
            print 'Checksum: ' + str(checksum)

            h_size = eth_length + iph_length + icmph_length
            data_size = len(packet) - h_size

            #Obtener datos a partir del tamanio indicado
            data = packet[h_size:]

            print 'Datos: ' + data
            #else:
            #    print "Tamanio del cabecera ICMP igual a 0"



        elif protocolo == 17 :
            print "Protocolo UDP"
            #print "------------------------------------"
            u = iph_length + eth_length
            udph_length = 8

            udp_header = packet[u:u+8]
            #print "Tamanio de udp " + str(len(udp_header))
            #if len(udp_header) >= 8:
            udph = unpack('!HHHH' , udp_header)

            source_port = udph[0]
            dest_port = udph[1]
            length = udph[2]
            checksum = udph[3]

            print 'Puerto fuente: ' + str(source_port)
            print 'Puerto destino: ' + str(dest_port)
            print 'Tamanio: ' + str(length)
            print 'Checksum: ' + str(checksum)

            h_size = eth_length + iph_length + udph_length
            data_size = len(packet) - h_size

            #obtener los datos del paquete
            data = packet[h_size:]

            print 'Datos: ' + data
            #else:
            #    print "Tamanio del cabecera UDP igual a 0"

        else :
            print 'Son otros protocolos diferentes TCP/UDP/ICMP'
            print "Protocolo " + str(protocolo)

        print
        print "-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-"
        print " "

    elif eth_protocol == 1544:
        print "Protocolo ARP"
            #Se lee desde donde se habia quedado la lectura anterior.
        arp_header = packet[eth_length:28+eth_length]

        #Se hace el desempaquetado de la cabecera

        arph = unpack('HHBBH6s4s6s4s' , arp_header)
        print "-----------------------"
        print "Tipo de Hardware: " + str(arph[0])
        print "Protocolo: " + str(arph[1])
        print "Longitud de direccion de Hardware: " + str(arph[2])
        print "Longitud de direccion de Protocolo: " + str(arph[3])
        print "Codigo de operacion: " + str(arph[4])
        puerto_fuente = socket.inet_ntoa(arph[6]);
        puerto_destino = socket.inet_ntoa(arph[8]);

        print "Puerto fuente: " + puerto_fuente
        print "Puerto destino: " + puerto_destino
