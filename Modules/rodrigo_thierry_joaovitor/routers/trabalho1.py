from typing import List

from fastapi import APIRouter
from ...rodrigo_thierry_joaovitor.Parser import PacketSource, IPPacket, ARPPacket, packetSource as src

# import scapy.all as scapy

router = APIRouter(prefix="/grupo_rodrigo_thierry_joao/ip", tags=[""])


class IP_:
  """ Por causa dos atributos external_pdu e internal_pdu
  ocorria erro de limite de recursão ao passar o objeto IPPacket
  para json"""
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

  def __init__(self, IP: IPPacket) -> None:
    self.version = IP.version
    self.headerLength = IP.headerLength
    self.length = IP.length
    self.sourceIp = IP.sourceIp
    self.destinationIp = IP.destinationIp
    self.ttl = IP.ttl
    self.protocol = IP.protocol
    self.fragmentationId = IP.fragmentationId
    self.flagDontFragment = IP.flagDontFragment
    self.flagMoreFragments = IP.flagMoreFragments
    self.offset = IP.offset
    self.headerChecksum = IP.headerChecksum
    self.service = IP.service


@router.get("/enviados/list")
def get_enviados_list():
  output = {packet.sourceIp for packet in src.allPackets if isinstance(packet, IPPacket)}
  return output


@router.get("/enviados/{ip}")
def get_enviados(ip: str):
  output: List[IP_] = [IP_(packet) for packet in src.allPackets if
                       isinstance(packet, IPPacket) and packet.sourceIp == ip]
  return output


@router.get('/recebidos/list')
def get_recebidos_list():
  output = [packet.destinationIp for packet in src.allPacketsDict[IPPacket]]
  output.sort()
  return output


@router.get("/recebidos/{ip}")
def get_recebidos(ip: str):
  output = [packet for packet in src.allPackets if isinstance(packet, IPPacket) and packet.destinationIp == ip]
  return output


@router.get("/relatorio/simples/{ip}")
def get_soma(ip: str):
  output = {}
  output['origem'] = ip
  output['trafego'] = {}
  output['protocolo'] = {}
  for packet in src.allPackets:
    if not isinstance(packet, IPPacket) or (packet.sourceIp != ip and packet.destinationIp != ip):
      continue

    size = 0
    if packet.version == 4:
      size = packet.length
    elif packet.version == 6:
      size = packet.payloadLength
    if packet.sourceIp == ip:
      if packet.destinationIp not in output['trafego']:
        output['trafego'][packet.destinationIp] = 0
      output['trafego'][packet.destinationIp] += size
    else:
      if packet.sourceIp not in output['trafego']:
        output['trafego'][packet.sourceIp] = 0
      output['trafego'][packet.sourceIp] += size

    if packet.version == 4:
      output['protocolo'][packet.protocol] = output['protocolo'].get(packet.protocol, 0) + 1
  return output


@router.get("/todos/")
def get_todos():
  return src.allPackets


@router.get("/pacote/{id}")
def get_pacote(id: str):
  uniqueId = uuid.UUID(id)
  for packet in src.allPackets:
    if packet.uniqueId == uniqueId:
      return packet, src.packetData[uniqueId]

# @router.get("/analise2")
# def analise():
#     arquivo = './pcaps/pacotes.pcap'
#     pacotes = scapy.rdpcap(arquivo)

#     #ips
#     ips = []

#     # pega a quantidade de pacotes por protocolo
#     protocolos = {}
#     portas = {}
#     for pacote in pacotes:
#         # printa a porta do pacote
#         if pacote.haslayer(scapy.TCP):
#             portas[pacote[scapy.TCP].dport] = portas.get(pacote[scapy.TCP].dport, 0) + 1
#         if pacote.haslayer(scapy.UDP):
#             portas[pacote[scapy.UDP].dport] = portas.get(pacote[scapy.UDP].dport, 0) + 1
#         if pacote.haslayer(scapy.IP):
#             ips.append(pacote[scapy.IP].src)
#             if pacote[scapy.IP].proto in protocolos:
#                 protocolos[pacote[scapy.IP].proto] += 1
#             else:
#                 protocolos[pacote[scapy.IP].proto] = 1

#         # pega a quantidade de pacotes por ip
#         ips_count = {}
#         for ip in ips:
#             if ip in ips_count:
#                 ips_count[ip] += 1
#             else:
#                 ips_count[ip] = 1

#         # pega o tempo total da captura
#         tempo_total = pacotes[-1].time - pacotes[0].time
#         # passa para segundos
#         tempo_total = round(tempo_total, 2)

#     return {
#         "Protocolos": protocolos,
#         "IPs": ips_count,
#         "Portas": portas,
#         "Tempo total": tempo_total
#     }
