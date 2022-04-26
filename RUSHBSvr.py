import socket
from datetime import datetime
from multiprocessing import  Process
import struct

RECV_SIZE = 1500
PACKET_SIZE = 1472
PAYLOAD_SIZE = 1464
REVERSED = 000000
FIN_ACK = 0b1000100
FIN = 0b0000100
FIN_CHK = 0b0000110
FIN_ACK_CHK = 0b1000110
DAT = 0b0001000
DAT_ACK = 0b1001000
DAT_NAK = 0b0101000
GET = 0b0010000
GET_CHK = 0b0010010
DAT_CHK = 0b0001010

def carry_around_add(a, b):
    c = a + b
    return (c & 0xffff) + (c >> 16)


def compute_checksum(message):
    b_str = message
    if len(b_str) % 2 == 1:
        b_str += b'\0'
    checksum = 0
    for i in range(0, len(b_str), 2):
        w = b_str[i] + (b_str[i + 1] << 8)
        checksum = carry_around_add(checksum, w)
    return ~checksum & 0xffff

class RUSHBpacket():
    def __init__(self, pkt: bytes = b'', **fields):
        self._data = pkt
        self._fields = {}

        self.seq_num = fields.get('seq_num', 0)
        self.ack_num = fields.get('ack_num', 0)
        self.checksum = fields.get('checksum', 0)
        self.all_flag = fields.get('all_flag',0)
        self.ack_flag = fields.get('ack_flag', 0)
        self.nak_flag = fields.get('nak_flag', 0)
        self.get_flag = fields.get('get_flag', 0)
        self.dat_flag = fields.get('dat_flag', 0)
        self.fin_flag = fields.get('fin_flag', 0)
        self.chk_flag = fields.get('chk_flag', 0)
        self.enc_flag = fields.get('enc_flag', 0)
        self.reserved = fields.get('reserved', 0)
        self.version = fields.get('version', 2)
        self.data = fields.get('data', 0)
        if pkt:
            self.setData()
    def setData(self):
        if len(self._data) > PACKET_SIZE:
            raise ('aaa')
        nowData = self._data
        self.seq_num = int.from_bytes(nowData[:2], byteorder='big')
        self.ack_num = int.from_bytes(nowData[2:4],byteorder='big')
        self.checksum = int.from_bytes(nowData[4:6], byteorder='big')
        bin_flags = bin(int.from_bytes(nowData[6:8],byteorder='big'))[2:]
        bin_flags = '0' * (16 - len(bin_flags)) + bin_flags
        self.all_flag = int(bin_flags[:7])
        self.ack_flag = int(bin_flags[0])
        self.nak_flag = int(bin_flags[1])
        self.get_flag = int(bin_flags[2])
        self.dat_flag = int(bin_flags[3])
        self.fin_flag = int(bin_flags[4])
        self.chk_flag = int(bin_flags[5])
        self.enc_flag = int(bin_flags[6])
        self.reserved = int(bin_flags[7:13])
        self.data = nowData[8:]

class fileTransferText():
    def __init__(self,filename:str):
        self._filename = filename
        with open(filename,'rb') as f:
            self._content = f.read()

        self._size = len(self._content)
        self._hasWritten = 0
    def next_size(self):
        if self._hasWritten < self._size:
            return min(PAYLOAD_SIZE,self._size - self._hasWritten)
        else:
            return 0
    def next_content(self):
        content = self._content[self._hasWritten:self._hasWritten+ self.next_size()]
        if len(content) < PAYLOAD_SIZE:
            content += (PAYLOAD_SIZE - len(content)) * b'\x00'
        return content

    def next_ok(self):
        self._hasWritten += self.next_size()
    def done(self):
        return self._hasWritten == self._size

class RUSHBSession(object):
    def __init__(self, remote,socket):
        self._seq_num = 0
        self._client_num = 0
        self._remote = remote
        self._file = None
        self._socket = socket
        self._packet_cache = None
        self._get_except_flag = []
        self._fin_except_flag = []
        self.time = None
    def resend_packet(self):
        self._socket.sendto(self._packet_cache,self._remote)
        self.time = datetime.now()
        # self._socket.settimeout(4)
    def getfile(self,now_packet:RUSHBpacket,chk):
        self._get_except_flag.append('ACK')
        self._get_except_flag.append('NAK')
        if chk == 0:
            filename = now_packet.data.rstrip(b'\x00').decode('ascii')
            try:
                self._file = fileTransferText(filename)
            except Exception:
                self._get_except_flag.remove('ACK')
                self._get_except_flag.remove('NAK')
                return
            payload = self._file.next_content()
            flags = DAT
            self.send_packet(self._remote,flags,0,0,payload)
            self._client_num += 1
        else:
            filename = now_packet.data.rstrip(b'\x00')
            if now_packet.checksum != compute_checksum(filename):
                self._get_except_flag.remove('ACK')
                self._get_except_flag.remove('NAK')
                return
            else:
                filename = now_packet.data.rstrip(b'\x00').decode('ascii')
                try:
                    self._file = fileTransferText(filename)
                except Exception:
                    self._get_except_flag.remove('ACK')
                    self._get_except_flag.remove('NAK')
                    return
                flags = DAT_CHK
                payload = self._file.next_content()
                raw_payload = payload.rstrip(b'\x00')
                data_chk = compute_checksum(raw_payload)
                self.send_packet(self._remote, flags, 0, data_chk, payload)
                self._client_num += 1

    def nakfile(self,req_packet:RUSHBpacket,chk):
        resp_packet = self._packet_cache
        self._socket.sendto(resp_packet,self._remote)
        self.time = datetime.now()
    def finish(self,req_packet:RUSHBpacket,chk):
        # self._seq_num += 1
        if chk == 0:
            self._fin_except_flag.append('FIN_ACK')
            self.send_packet(self._remote,FIN,0,chk)
            self._client_num += 1
        else:
            self.send_packet(self._remote, FIN_CHK, 0, chk)
            self._client_num += 1
    def ackFinish(self,req_packet:RUSHBpacket,chk):
        if chk == 0:
            seq = req_packet.seq_num
            self.send_packet(self._remote,FIN_ACK,seq,chk)
        else:
            seq = req_packet.seq_num
            self.send_packet(self._remote, FIN_ACK_CHK, seq, chk)

    def ackfile(self,req_packet:RUSHBpacket,chk):
        if chk == 0:
            self._file.next_ok()
            if self._file.done():
                self.finish(req_packet,chk)
                return
            payload = self._file.next_content()
            flags = DAT
            self.send_packet(self._remote,flags,0,0,payload)
            self._client_num += 1
        else:
            if req_packet.checksum != compute_checksum(req_packet.data):
                return
            else:
                self._file.next_ok()
                if self._file.done():
                    self.finish(req_packet, chk)
                    return
                payload = self._file.next_content()
                flags = DAT_CHK
                chk_pck = compute_checksum(payload)
                self.send_packet(self._remote, flags, 0, chk_pck, payload)
                self._client_num += 1
    def send_packet(self,address,flags,ack,chk,paload=None):
        self._seq_num += 1
        self.packet = self.package(self._seq_num ,ack,chk,flags,paload)
        self._packet_cache = self.packet
        self.time = datetime.now()
        self._socket.sendto(self.packet,address)


    def handle_packet(self,data:bytes):
        req_packet = RUSHBpacket(data)
        if len(self._fin_except_flag) > 0:
            if req_packet.fin_flag == 0:
                return self.time,0
        if len(self._get_except_flag) > 0:
            if req_packet.ack_flag == 0 and req_packet.nak_flag == 0:
                return self.time,0
        if req_packet.seq_num != self._client_num + 1 :

            return self.time,0
        if req_packet.ack_num != self._seq_num:
            return self.time,0
        if req_packet.ack_flag and req_packet.fin_flag and req_packet.chk_flag:
            chk = req_packet.checksum
            self.ackFinish(req_packet,chk)
            self._client_num += 1
            return self.time,1
        if req_packet.ack_flag and req_packet.chk_flag:
            chk = req_packet.checksum
            self.ackfile(req_packet,chk)
            return self.time,0
        if req_packet.nak_flag and req_packet.chk_flag:
            chk = req_packet.checksum
            self.nakfile(req_packet,chk)
            self._client_num += 1
            return self.time,0
        if req_packet.get_flag and req_packet.chk_flag:
            chk = req_packet.chk_flag
            self.getfile(req_packet,chk)
            return self.time,0
        # checksum
        # req_packet.setData()
        if req_packet.ack_flag and req_packet.fin_flag:
            self.ackFinish(req_packet,0)
            self._client_num += 1
            return self.time,1

        # if req_packet.ack_flag or req_packet.nak_flag:
        if req_packet.ack_flag:
            self.ackfile(req_packet,0)
            return self.time,0
        # if req_packet.fin_flag and req_packet.ack_flag:
        if req_packet.nak_flag:
            self.nakfile(req_packet,0)
            self._client_num += 1
            return self.time,0
        if req_packet.get_flag:
            self.getfile(req_packet,0)
            return self.time,0
        else:
            return self.time,0

    def package(self,seq_num,ack_num,checksum,flag, file = None) -> bytes:
        ver = 0b010
        rev = 0b000000
        flag_rev_ver = ver + (rev << 3) + (flag << (3 + 6))

        header_bytes = struct.pack('!HHHH', seq_num, ack_num, checksum, flag_rev_ver)
        if file is None:
            file = PAYLOAD_SIZE * b'\x00'
        packget = header_bytes + file
        return packget


def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.bind(('127.0.0.1', 0))
    print(server.getsockname()[1])
    sessions = {}
    sessions_checksum = {}
    sessions_time = {}
    while True:
        try:
            data, remote = server.recvfrom(RECV_SIZE)
        except socket.timeout:
            # if session is None:
            #     print("session is none")
            #     socket.settimeout(4)
            #     continue
            # else:
            for key in sessions_time:
                nowTime = datetime.now()
                if (nowTime - sessions_time[key]).seconds > 4:
                    sessions[key].resend_packet()
            continue
        server.settimeout(1)
        if remote in sessions:
            session = sessions[remote]
            r = RUSHBpacket(data)
            if r.chk_flag == 1:
                if sessions_checksum[remote] == False:
                    continue
            if r.chk_flag == 0:
                if sessions_checksum[remote] == True:
                    continue

        else:
            r = RUSHBpacket(data)
            session = RUSHBSession(remote,server)
            sessions[remote] = session
            if r.get_flag != 1:
                continue
            if r.chk_flag == 0:
                sessions_checksum[remote] = False
            else:
                sessions_checksum[remote] = True

        time , fin= session.handle_packet(data)
        if time is None:
            continue
        else:
            sessions_time[remote] = time
        if fin == 1:
            sessions_time.pop(remote)

if __name__ == "__main__":
    main()
