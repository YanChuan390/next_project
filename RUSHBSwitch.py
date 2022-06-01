
import struct
import sys
import threading
import ipaddress
import math
import socket

from binascii import hexlify, unhexlify



PACKET_SIZE = 1500
DAT_SIZE = 1488

EMPTYIP = '0.0.0.0'
X = None
Y = None
UDP_S = None
HOST = "127.0.0.1"
ADJACENT_SWITCHS = dict()
WAY = dict()
DATA_LIST = dict()
TCP_SE = None
DISC_MODE = 0x01
OFFER_MODE = 0x02
REQ_MODE = 0x03
ACK_MODE = 0x04
DATA_MODE = 0x05
IS_AVAIL_MODE = 0x06
AVAIL_MODE = 0x07
LOCATION_MODE = 0x08
BRC_MODE = 0x09
CHUNK_MODE = 0x0a
LAST_CHUNK_MODE = 0x0b
VALID_MODES = [DISC_MODE, OFFER_MODE, REQ_MODE, ACK_MODE, DATA_MODE, AVAIL_MODE,
               IS_AVAIL_MODE, LOCATION_MODE, BRC_MODE, CHUNK_MODE, LAST_CHUNK_MODE]

NUM_OF_TCP_CONNECTIONS = 0
NUM_OF_UDP_CONNECTIONS = 0
MAX_UDP_CON = 0
MAX_TCP_CON = 0
UDP_IP = None
TCP_IP = None
UDP_INFO = None
TCP_INFO = None

lock = threading.Lock()

class GSRUSHBPacket():
    def __init__(self,pkt,type):
        self.pkt_size = len(pkt)
        self.sourceIP = None
        self.destinationIP = None
        self.RESERVED = None
        self.mode = None
        self.assignedIP = None
        self.data = None
        self.X = None
        self.Y = None
        if pkt:
            self.setData(pkt,type)
    def setData(self,pkt,type):
        try:
            if type == "GREETING":
                self.sourceIP = pkt[:4]
                self.destinationIP = pkt[4:8]
                self.assignedIP = pkt[12:]
                self.mode = pkt[11]
            elif type == "LOCATION":
                self.sourceIP = pkt[:4]
                self.destinationIP = pkt[4:8]
                self.X = pkt[12:14]
                self.Y = pkt[14:16]
                self.mode = pkt[11]
            elif type == "BROADCAST":
                self.sourceIP = pkt[:4]
                self.destinationIP = pkt[4:8]
                self.mode = pkt[11]
                self.target_ip = pkt[12:16]
                self.distance = pkt[16:20]
            if self.mode not in VALID_MODES:
                return None
        except IndexError:
            return None
        print(self.mode)

def int_to_bytes(integer,size):
    return integer.to_bytes(size, byteorder='big')
def ip_to_int(addr):
    return struct.unpack("!I", socket.inet_aton(addr))[0]
def int_to_ip(addr):
    return socket.inet_ntoa(struct.pack("!I", addr))
def bytes_to_int(data):
    return int.from_bytes(data, byteorder='big')
def split_slash_ip(str):
    return str.split("/",1)[0]

def split_slash_subnet(str):
    return str.split("/",1)[1]
def build_send_packet(source_ip,des_ip,mode,assigned_ip = None,X = None,Y = None,targetIP = None,distance = None,reserved = None,data = None):
    offset = 0x000000
    packet = bytearray()
    packet += int_to_bytes(ip_to_int(source_ip),4)
    packet += int_to_bytes(ip_to_int(des_ip),4)
    packet += int_to_bytes(offset,3)
    packet += int_to_bytes(mode,1)
    if mode in (1, 2, 3, 4):
        packet += int_to_bytes(ip_to_int(assigned_ip),4)
    if mode in (5,10,11):
        data_packet = bytearray()
        data_packet += int_to_bytes(ip_to_int(source_ip),4)
        data_packet += int_to_bytes(ip_to_int(des_ip), 4)
        if reserved != None:
            data_packet += int_to_bytes(ip_to_int(reserved), 3)
        data_packet += int_to_bytes(mode, 1)
        for d in data:
            packet += d
        return data_packet
    if mode  ==  8:
        packet += int_to_bytes(X,2)
        packet += int_to_bytes(Y,2)
    if mode  == 9:
        packet += int_to_bytes(ip_to_int(targetIP),4)
        # print(type(distance))
        packet += int_to_bytes(distance,4)
    return packet

def convert_reserved_value(val):
    bytes_val = val.to_bytes(3, 'big')
    hex_val = hexlify(bytes_val).decode('utf-8')
    return unhexlify(hex_val)

def assign_new_ip(type):
    global NUM_OF_TCP_CONNECTIONS
    global NUM_OF_UDP_CONNECTIONS

    if type == "TCP":
        next_ip = ipaddress.ip_address(
            TCP_IP) + 1 + NUM_OF_TCP_CONNECTIONS
        NUM_OF_TCP_CONNECTIONS += 1
    elif type == "UDP":
        next_ip = ipaddress.ip_address(
            UDP_IP) + 1 + NUM_OF_UDP_CONNECTIONS
        NUM_OF_UDP_CONNECTIONS += 1
    return str(ipaddress.ip_address(next_ip))


def ip_to_bin(ip):
    return ' '.join(format(int(x), '08b') for x in ip.split('.'))


def longest_prefix_matching(destionIP, ip_list):
    dest_ip_bin = ip_to_bin(destionIP)
    longest_matchings = []
    for ip in ip_list:
        longest_matching = 0
        ip_bin = ip_to_bin(ip)
        for index, bin_of_ip in enumerate(dest_ip_bin):
            if ip_bin[index] == bin_of_ip:
                longest_matching += 1
            else:
                break
        longest_matchings.append(longest_matching)
    if longest_matchings:
        return ip_list[longest_matchings.index(max(longest_matchings))]
    else:
        return None

def Pass():
    pass
class Switch:
    def __init__(self, packet, Client_Server, socket, protocol="TCP", udp_addr=None):
        self.packet = packet
        self.type = Client_Server
        self.socket = socket
        self.protocol = protocol
        self.addr = udp_addr
        self.adj_switchs = ADJACENT_SWITCHS
        self.X = X
        self.Y = Y
        self.path = WAY
        if packet:
            self.handle_packet()
    def handle_packet(self):
        global NUM_OF_TCP_CONNECTIONS
        try:
            currentPkt = GSRUSHBPacket(self.packet, "GREETING")
        except:
            return
        if currentPkt.mode == 1:
            if self.protocol == "UDP" and NUM_OF_UDP_CONNECTIONS < MAX_UDP_CON:
                offer_pkt = build_send_packet(UDP_IP, int_to_ip(bytes_to_int(currentPkt.sourceIP)), 2, assign_new_ip("UDP"))
                self.socket.sendto(offer_pkt, self.addr)
            elif self.protocol == "TCP" and NUM_OF_TCP_CONNECTIONS < MAX_TCP_CON:
                offer_pkt = build_send_packet(TCP_IP, int_to_ip(bytes_to_int(currentPkt.sourceIP)), 2, assign_new_ip("TCP"))
                self.socket.sendall(offer_pkt)
        elif currentPkt.mode == 2:
            req_pkt = build_send_packet(EMPTYIP, int_to_ip(bytes_to_int(currentPkt.sourceIP)), 3, int_to_ip(bytes_to_int(currentPkt.assignedIP)))
            if self.protocol == "TCP":
                self.socket.sendall(req_pkt)
            else:
                self.socket.sendto(req_pkt, self.addr)
        elif currentPkt.mode == 3:
            if self.protocol == "TCP":
                new_src_ip = TCP_IP
                n_info = {
                    'ip_assigned': TCP_IP,
                    'socket': self.socket,
                    'timer': threading.Timer(5.0, Pass)
                }
            elif self.protocol == "UDP":
                new_src_ip = UDP_IP
                n_info = {
                    'ip_assigned': UDP_IP,
                    'socket': self.socket,
                    "udp_addr": self.addr,
                    'timer': threading.Timer(5.0, Pass)
                }
            ADJACENT_SWITCHS[socket.inet_ntoa(currentPkt.assignedIP)] = n_info
            ack_pkt = build_send_packet(new_src_ip,int_to_ip(bytes_to_int(currentPkt.assignedIP)),4,int_to_ip(bytes_to_int(currentPkt.assignedIP)))

            if self.protocol == "TCP":
                self.socket.sendall(ack_pkt)
            else:
                self.socket.sendto(ack_pkt, self.addr)
        elif currentPkt.mode == 4 or (currentPkt.mode == 8 and self.type == "server"):
            if self.type == "client":
                n_info = {
                    'ip_assigned': socket.inet_ntoa(currentPkt.assignedIP),
                    'socket': self.socket,
                    'timer': threading.Timer(5.0, Pass)
                }
                ADJACENT_SWITCHS[socket.inet_ntoa(currentPkt.sourceIP)] = n_info
                new_src_ip = currentPkt.assignedIP
            else:
                new_src_ip = socket.inet_aton(
                    TCP_IP if self.protocol == "TCP" else UDP_IP)
            location_pkt = build_send_packet(int_to_ip(bytes_to_int(new_src_ip)), int_to_ip(bytes_to_int(currentPkt.sourceIP)), 8, X=X, Y=Y)
            if self.protocol == "TCP":
                self.socket.sendall(location_pkt)
            else:
                self.socket.sendto(location_pkt, self.addr)

        elif currentPkt.mode in (5,10,11):
            packet_len = len(self.packet)
            packet_chunks = []
            if packet_len > PACKET_SIZE:
                data_len = packet_len - 12
                num_full_packets = math.floor(data_len / DAT_SIZE)
                for i in range(num_full_packets):
                    new_reserved = int_to_ip(bytes_to_int(convert_reserved_value(i * DAT_SIZE)))
                    data_chunk = currentPkt.assignedIP[i * DAT_SIZE:(DAT_SIZE * (i + 1))]
                    packet_chunk = build_send_packet(int_to_ip(bytes_to_int(currentPkt.sourceIP)),int_to_ip(bytes_to_int(currentPkt.destinationIP)),10,reserved=new_reserved,data=data_chunk)
                    packet_chunks.append(packet_chunk)

                consumed_data_len = num_full_packets * DAT_SIZE
                remain_data_len = data_len - consumed_data_len
                if remain_data_len > 0:
                    new_reserved = int_to_ip(bytes_to_int(convert_reserved_value(num_full_packets*DAT_SIZE)))
                    remain_data = currentPkt.assignedIP[consumed_data_len:data_len]
                    last_packet_chunk = build_send_packet(int_to_ip(bytes_to_int(currentPkt.sourceIP)),int_to_ip(bytes_to_int(currentPkt.destinationIP)),11,reserved=new_reserved,data=remain_data)
                    packet_chunks.append(last_packet_chunk)
            else:
                packet_chunks = [self.packet]
            o_dest_ip = socket.inet_ntoa(currentPkt.destinationIP)
            if o_dest_ip not in WAY.keys():
                current_assignedIP = None
                for switch in ADJACENT_SWITCHS:
                    if ADJACENT_SWITCHS[switch]['socket'] == self.socket:
                        current_assignedIP = switch
                cd = list(ADJACENT_SWITCHS.keys())
                cd.remove(current_assignedIP)
                nt_ip_switch = longest_prefix_matching(o_dest_ip, cd)
            else:
                nt_ip_switch = WAY[o_dest_ip]["pass_switch"]
                if not nt_ip_switch:
                    nt_ip_switch = o_dest_ip

            sock_to_send = ADJACENT_SWITCHS[nt_ip_switch]['socket']
            if UDP_IP and TCP_IP:
                nt_ip_switch = o_dest_ip
                if nt_ip_switch not in ADJACENT_SWITCHS:
                    return
            if nt_ip_switch not in DATA_LIST:
                DATA_LIST[nt_ip_switch] = {
                    "packet": packet_chunks,
                    "socket": sock_to_send
                }
            elif nt_ip_switch in DATA_LIST and not DATA_LIST[nt_ip_switch]["packet"]:
                DATA_LIST[nt_ip_switch]["packet"] = packet_chunks
            else:
                DATA_LIST[nt_ip_switch]["packet"].extend(packet_chunks)
            if currentPkt.mode == 10:
                return
            dest_timer = ADJACENT_SWITCHS[nt_ip_switch]['timer']
            if not dest_timer.is_alive():
                is_avail_packet = build_send_packet(ADJACENT_SWITCHS[nt_ip_switch]['ip_assigned'],nt_ip_switch,6)
                if TCP_IP and UDP_IP:
                    udp_addr = ADJACENT_SWITCHS[nt_ip_switch]["udp_addr"]
                    sock_to_send.sendto(is_avail_packet, udp_addr)
                else:
                    sock_to_send.sendall(is_avail_packet)
                try:
                    dest_timer.start()
                except RuntimeError:
                    dest_timer = threading.Timer(5.0, Pass)
                    dest_timer.start()
                return
        elif currentPkt.mode == 6:
            avail_pkt = build_send_packet(socket.inet_ntoa(currentPkt.destinationIP),socket.inet_ntoa(currentPkt.sourceIP),7)
            if self.protocol == "UDP":
                self.socket.sendto(avail_pkt, self.addr)
            else:
                self.socket.sendall(avail_pkt)
        elif currentPkt.mode == 7:
            sock_to_send = DATA_LIST[socket.inet_ntoa(currentPkt.sourceIP)]["socket"]
            packet_list = DATA_LIST[socket.inet_ntoa(currentPkt.sourceIP)]["packet"]
            for packet in packet_list:
                if self.protocol == "UDP":
                    sock_to_send.sendto(packet, self.addr)
                else:
                    sock_to_send.sendall(packet)

        if currentPkt.mode == 8:
            try:
                currentPkt = GSRUSHBPacket(self.packet, "LOCATION")
            except:
                return
            x = int.from_bytes(currentPkt.X, 'big')
            y = int.from_bytes(currentPkt.Y, 'big')
            distance = math.floor(
                math.sqrt((X - x) ** 2 + (Y - y) ** 2))
            if distance > 1000:
                return
            ADJACENT_SWITCHS[socket.inet_ntoa(currentPkt.sourceIP)]["distance"] = distance
            if socket.inet_ntoa(currentPkt.sourceIP) not in WAY or (socket.inet_ntoa(currentPkt.sourceIP) in WAY and
                                                                    WAY[socket.inet_ntoa(currentPkt.sourceIP)]["pass_distance"] > distance):
                WAY[socket.inet_ntoa(currentPkt.sourceIP)] = {
                    "pass_switch": None,
                    "pass_distance": distance
                }
            if UDP_IP and self.type == "server":
                new_src_ip = currentPkt.destinationIP
                new_dest_ip = currentPkt.sourceIP
                distance_pkt = build_send_packet(socket.inet_ntoa(new_src_ip), socket.inet_ntoa(new_dest_ip), 9, targetIP=UDP_IP, distance = distance)
                self.socket.sendall(distance_pkt)
                return

            for switch in ADJACENT_SWITCHS.keys():
                if switch == socket.inet_ntoa(currentPkt.sourceIP):
                    continue
                new_src_ip = ADJACENT_SWITCHS[switch]['ip_assigned']
                new_dst_ip = switch
                distance_b = (distance + ADJACENT_SWITCHS[switch]["distance"])
                sourceIP = int_to_ip(bytes_to_int(currentPkt.sourceIP))
                new_pkt = build_send_packet(new_src_ip,new_dst_ip,9,targetIP=sourceIP,distance=distance_b)
                skt = ADJACENT_SWITCHS[switch]['socket']
                if self.protocol == "TCP":
                    skt.sendall(new_pkt)
                else:
                    skt.sendto(new_pkt, self.addr)

        elif currentPkt.mode == 9:
            try:
                currentPkt = GSRUSHBPacket(self.packet, "BROADCAST")
            except:
                return

            int_distance = int.from_bytes(currentPkt.distance, "big")

            if (socket.inet_ntoa(currentPkt.target_ip) in WAY and WAY[socket.inet_ntoa(currentPkt.target_ip)]["pass_switch"] == socket.inet_ntoa(currentPkt.sourceIP) and WAY[socket.inet_ntoa(currentPkt.target_ip)][
                "pass_distance"] < int_distance):
                return
            if socket.inet_ntoa(currentPkt.target_ip) != TCP_IP and (not socket.inet_ntoa(currentPkt.target_ip) in WAY) or (
                    socket.inet_ntoa(currentPkt.target_ip) in WAY and WAY[socket.inet_ntoa(currentPkt.target_ip)]["pass_distance"] > int_distance):
                if not UDP_IP or (UDP_IP and socket.inet_ntoa(currentPkt.target_ip) != UDP_IP):
                    WAY[socket.inet_ntoa(currentPkt.target_ip)] = {
                        "pass_switch": socket.inet_ntoa(currentPkt.sourceIP),
                        "pass_distance": int_distance
                    }
            for switch in ADJACENT_SWITCHS.keys():
                if switch != socket.inet_ntoa(currentPkt.sourceIP) and switch != socket.inet_ntoa(currentPkt.destinationIP) and switch != socket.inet_ntoa(currentPkt.target_ip):
                    send_src_ip = ADJACENT_SWITCHS[switch]['ip_assigned']
                    send_dst_ip = switch
                    send_d_int = int_distance + ADJACENT_SWITCHS[switch]["distance"]
                    target_ip = int_to_ip(bytes_to_int(currentPkt.target_ip))
                    send_pkt = build_send_packet(send_src_ip,send_dst_ip,9,targetIP=target_ip,distance=send_d_int)
                    skt = ADJACENT_SWITCHS[switch]['socket']
                    if self.protocol == "TCP":
                        skt.sendall(send_pkt)
                    else:
                        skt.sendto(send_pkt, self.addr)

def send_connect(port):
    discovery_pkt = build_send_packet(EMPTYIP, EMPTYIP, 1, EMPTYIP)
    socket_tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    socket_tcp.connect((HOST, port))
    socket_tcp.sendall(discovery_pkt)
    while True:
        data = socket_tcp.recv(1500)
        lock.acquire()
        switch = Switch(data,"client",socket_tcp)
        lock.release()


def udp_server():
    while True:
        packet, address = UDP_S.recvfrom(55296)
        udp_thread = threading.Thread(
            target=udp_start, args=(packet, address,))
        udp_thread.start()


def udp_start(packet, address):
    lock.acquire()
    udp_switch = Switch(packet, "server", UDP_S,
               protocol="UDP", udp_addr=address)
    lock.release()


def tcp_server():
    while True:
        conn, adr = TCP_SE.accept()
        threading.Thread(target=tcp_start, args=(conn,)).start()



def tcp_start(conn):
    with conn:
        while True:
            packet = conn.recv(1500)
            switch = Switch(packet, "server", conn)


def handle_command(command):
    if command.split(" ", 1)[0] == "connect" and len_argv < 6:
        dst_port = int(command.split(" ", 1)[1])
        discovery_pkt = build_send_packet(EMPTYIP, EMPTYIP, 1, EMPTYIP)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((HOST, dst_port))
        s.sendall(discovery_pkt)
        while True:
            data = s.recv(1500)
            lock.acquire()
            switch = Switch(data, "client", s)
            lock.release()

def command_line():
    while True:
        try:
            command = input("> ")
            threading.Thread(target=handle_command, args=(command,)).start()
        except EOFError:
            break

def judge_switch_type(argv):
    global UDP_IP
    global UDP_SUB
    global MAX_UDP_CON
    global MAX_TCP_CON
    global UDP_S
    global TCP_IP
    global TCP_SE
    global X
    global Y

    switch_type = argv[1]
    if len(argv) == 6:
        X = int(argv[4])
        Y = int(argv[5])
    else:
        X = int(argv[3])
        Y = int(argv[4])

    # Initializing a port
    if switch_type == "local":
        UDP_IP = split_slash_ip(argv[2])
        UDP_SUB = split_slash_subnet(argv[2])
        MAX_UDP_CON = 2 ** (32 - int(UDP_SUB)) - 2

        # create udp server
        udp_socket = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
        udp_socket.bind((HOST,0))
        UDP_S = udp_socket
        udp_port = udp_socket.getsockname()[1]
        print(udp_port,flush=True)
        udp_thread = threading.Thread(target=udp_server)
        udp_thread.start()
    if switch_type == "local" and len_argv == 6 or switch_type == "global":
        if switch_type == "local":
            TCP_IP = split_slash_ip(argv[3])
            TCP_SUB = split_slash_subnet(argv[3])
            MAX_TCP_CON = 2 ** (32 - int(TCP_SUB)) - 2
        if switch_type == "global":
            TCP_IP = split_slash_ip(argv[2])
            TCP_SUB = split_slash_subnet(argv[2])
            MAX_TCP_CON = 2 ** (32 - int(TCP_SUB)) - 2
        tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tcp_socket.bind((HOST, 0))
        tcp_socket.listen(5)
        TCP_SE = tcp_socket
        print(tcp_socket.getsockname()[1], flush=True)
        threading.Thread(target=tcp_server).start()
    command_line()

len_argv = len(sys.argv)

def main(argv):

    judge_switch_type(argv)

if __name__ == "__main__":
    main(sys.argv)