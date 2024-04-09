from typing import List, Dict
import dpkt
import uuid
import os
import socket

# Constants EtherType
# https://en.wikipedia.org/wiki/EtherType#Values
# - Se isso crescer demais quem sabe seja bom por em um arquivo separado
ETH_TYPE_IPv4 = 0x0800
ETH_TYPE_IPv6 = 0x86DD
ETH_TYPE_ARP = 0x0806
ETH_TYPE_RARP = 0x8035


class Packet:
    uniqueId: uuid.UUID

    '''
    Quem sabe seja útil quando for lidar com TCP e UDP
    '''
    payload: uuid.UUID

    def convert(pkg) -> 'Packet':
        '''
        Converte o esquema de pacote do dpkt para IPPacket
        '''
        if isinstance(pkg, dpkt.ip.IP):
            return IPPacket.convert(pkg)
        elif isinstance(pkg, dpkt.ip6.IP6):
            return IP6Packet.convert(pkg)
        elif isinstance(pkg, dpkt.arp.ARP):
            return ARPPacket.convert(pkg)

        else:
            print("Tipo de pacote desconhecido! Tipo:" + str(type(pkg)))


class ARPPacket(Packet):
    """ARPPacket.

    Args:
        hardware_type (int): 16 bits. The type of the network on which ARP is running. Ethernet is given type 1.
        protocol_type (int): 16 bits. Defining the protocol. The value of this field for the IPv4 protocol is 0800H.
        hardware_lenght (int): 8 bits. Length of the hardware address in bytes.
        protocol_lenght (int): 8 bits. Length of the logical address in bytes.
        operation: (str): 16 bits. REQUEST OR REPLY

    """
    hardware_type: int
    protocol_type: int
    hardware_length: int
    protocol_length: int
    operation: str

    source_hardware_address: str
    source_protocol_address: str
    destiation_hardware_address: str
    destination_protocol_address: str

    #Não quebrar a API
    sourceIp: str
    destinationIp: str
    def convert(pkg: dpkt.arp.ARP) -> 'ARPPacket':

        def format_protocol_address(value: bytes, proto_type) -> str:
            if proto_type == ETH_TYPE_IPv4:
                return f'{value[0]}.{value[1]}.{value[2]}.{value[3]}'
            elif proto_type == ETH_TYPE_IPv6:
                return socket.inet_ntop(socket.AF_INET6, value)
            else:
                return 'Unknown Protocol Type'

        def format_hardware_address(value: bytes, proto_type) -> str:
            if proto_type == 1:
                return ':'.join('{:02x}'.format(byte) for byte in value)
            else:
                return 'Unknown Protocol Type'


        arpPkg = ARPPacket()
        arpPkg.hardware_type = pkg.hrd
        arpPkg.protocol_type = pkg.pro
        arpPkg.hardware_length = pkg.hln
        arpPkg.protocol_length = pkg.pln
        arpPkg.operation = pkg.op
        arpPkg.source_protocol_address = format_protocol_address(pkg.spa, pkg.pro)
        arpPkg.source_hardware_address = format_hardware_address(pkg.sha, pkg.hrd)
        arpPkg.destination_protocol_address = format_protocol_address(pkg.tpa, pkg.pro)
        arpPkg.destination_hardware_address = format_hardware_address(pkg.tha, pkg.hrd)

        arpPkg.sourceIp = arpPkg.source_protocol_address
        arpPkg.destinationIp = arpPkg.destination_protocol_address

        return arpPkg


class IPPacket(Packet):
    '''
    Classe para encapsular dpkt.ip.IP e printar
    certinho na fastAPI
    '''
    version: int
    headerLength: int
    length: int
    sourceIp: str
    destinationIp: str
    ttl: int
    protocol: str

    fragmentationId: int
    flagDontFragment: bool
    flagMoreFragments: bool
    offset: int

    headerChecksum: int
    service: int

    def convert(ip: dpkt.ip.IP) -> 'IPPacket':
        packet = IPPacket()
        packet.version = 4
        packet.version = ip.v
        packet.headerLength = ip.hl
        packet.length = ip.len
        packet.sourceIp = f'{ip.src[0]}.{ip.src[1]}.{ip.src[2]}.{ip.src[3]}'
        packet.destinationIp = f'{ip.dst[0]}.{ip.dst[1]}.{ip.dst[2]}.{ip.dst[3]}'
        packet.ttl = ip.ttl
        packet.fragmentationId = ip.id
        packet.flagMoreFragments = bool(ip.mf)
        packet.flagDontFragment = bool(ip.df)
        packet.offset = ip.offset * 8

        packet.headerChecksum = ip.sum
        packet.service = ip.tos

        if ip.p == 6:
            packet.protocol = 'TCP'
        elif ip.p == 17:
            packet.protocol = 'UDP'
        elif ip.p == 1:
            packet.protocol = 'ICMP'
        else:
            packet.protocol = 'UNKN (' + str(ip.p) + ')'
        return packet


class IP6Packet(Packet):
    version: int
    sourceIp: int
    sourceIp: int
    payloadLength: int
    nextHeader: int
    hopLimit: int
    flow: int
    fc: int  # flow control? nao sei oq é

    def convert(ip: dpkt.ip6.IP6) -> 'IP6Packet':
        packet = IP6Packet()
        packet.version = 6

        packet.sourceIp = socket.inet_ntop(socket.AF_INET6, ip.src)
        packet.destinationIp = socket.inet_ntop(socket.AF_INET6, ip.dst)
        packet.payloadLength = ip.plen
        packet.nextHeader = ip.nxt
        packet.hopLimit = ip.hlim
        packet.flow = ip.flow
        packet.fc = ip.fc
        return packet


class PacketSource:
    '''
    Classe que junta logica de captura e leitura de pacotes.
    Usado para prevenir que cada pacote tenha uuids diferentes
    a cada request.
    '''

    packetData: Dict[uuid.UUID, dpkt.Packet]
    '''Dicionario com o conteudo de cada pacote'''
    allPackets: List[Packet]
    '''Lista com todos os pacotes disponiveis(IP e ARP)'''

    def readPackets(self, filePath: str) -> list:
        '''
        Le um arquivo pcap e retorna uma lista de pacotes IP
        '''
        f = open(filePath, 'rb')
        pcap = None
        if filePath.endswith('.pcap'):
            pcap = dpkt.pcap.Reader(f)
        elif filePath.endswith('.pcapng'):
            pcap = dpkt.pcapng.Reader(f)
        else:
            print("Arquivo nao suportado: " + filePath)
            return []

        # pcap = dpkt.pcap.Reader(f)
        packets = []
        if pcap is None:
            print("Nao consegui ler o arquivo " + filePath + "!")
            return []
        for ts, buf in pcap:
            eth = dpkt.ethernet.Ethernet(buf)
            if eth.type == ETH_TYPE_IPv4 or eth.type == ETH_TYPE_IPv6:
                ip = eth.data
                packets.append(ip)
            elif eth.type == ETH_TYPE_ARP:
                arp = eth.data
                packets.append(arp)
            else:
                print("Ethernet type não tratado.")

        f.close()
        return packets

    def readAll(self) -> List[Packet]:
        '''
        Le todos os pcap da pasta captures e retorna uma lista de pacotes IP
        '''

        arquivos = os.listdir('./pcaps')
        output = []
        for arquivo in arquivos:
            print("Lendo arquivo: ", arquivo)
            packets = self.readPackets(f'./pcaps/{arquivo}')
            for packet in packets:
                pkt: Packet = Packet.convert(packet)
                if pkt is None:
                    # print("um pacote nao foi convertido")
                    continue
                pkt.uniqueId = uuid.uuid4()
                self.packetData[pkt.uniqueId] = packet.data
                output.append(pkt)

        print("li um total de", len(output), "pacotes")
        return output

    def __init__(self):
        self.packetData = {}
        self.allPackets = self.readAll()
