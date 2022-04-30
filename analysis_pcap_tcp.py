import struct
import dpkt


def getData(temp, f, position, field_size):
    if len(temp) > position:
        return str(struct.unpack(f, temp[position:position + field_size])[0])
    else:
        pass


# check if connection established
def check_Connection(pack):
    if pack.syn == "1" and pack.ack == "1":
        return True
    return False


# check tcp connection
def TCP_Connection(pack, source_ip, destination_ip):
    if pack.source_ip == source_ip and pack.destination_ip == destination_ip:
        return True
    return False


# check source and destination ports
def Port_Check(p1, p2):
    if p1.source_port == p2.source_port and p2.destination_port == p1.destination_port:
        return True
    if p1.source_port == p2.destination_port and p2.source_port == p1.destination_port:
        return True
    return False


class Connection:
    packets = []
    source_port = destination_port = ""

    def __init__(self, source, destination):
        self.source_port = source
        self.destination_port = destination


class TCP_Packet:
    timestamp = 0
    source_ip = source_port = ""
    destination_ip = destination_port = ""
    sequence_number = ack_number = ""
    syn = ack = ""
    window_size = size = ""
    valid = True

    def parse(self, time_stamp, temp):
        try:
            # parse addresses and ports (of source and destination)
            x, y = 26, 30
            while x < 29:
                self.source_ip = self.source_ip + getData(temp, ">B", x, 1) + "."
                self.destination_ip = self.destination_ip + getData(temp, ">B", y, 1) + "."
                x = x + 1
                y = y + 1
            self.source_ip = self.source_ip + getData(temp, ">B", x, 1)
            self.destination_ip = self.destination_ip + getData(temp, ">B", y, 1)
            self.source_port = getData(temp, ">H", 34, 2)
            self.destination_port = getData(temp, ">H", 36, 2)

            # parse sequence and acknowledgement numbers
            self.sequence_number = getData(temp, ">I", 38, 4)
            self.syn = "{0:16b}".format(int(getData(temp, ">H", 46, 2)))[14]
            self.ack_number = getData(temp, ">I", 42, 4)
            self.ack = "{0:16b}".format(int(getData(temp, ">H", 46, 2)))[11]

            # parse window size, size and timestamp
            self.window_size = getData(temp, ">H", 48, 2)
            self.size = len(temp)
            self.timestamp = time_stamp
        except:
            self.valid = False


# Throughput of each connection
def Throughput(connection):
    first_packet = True
    payload = 0
    # initialize start and end to 0
    start_time = end_time = 0
    result = 0
    i = 0
    # Timestamp of when the first packet is sent is stored
    # Next, calculate total payload by adding every packet's size
    for packet in connection.packets:
        if packet.source_ip == "130.245.145.12":
            if first_packet:
                start_time = packet.timestamp
                first_packet = False
            else:
                if i < 3:
                    if i != 0:
                        print('Source Port: ', packet.source_port)
                        print('Source IP Address: ', packet.source_ip)
                        print('Destination Port: ', packet.destination_port)
                        print('Destination IP Address: ', packet.destination_ip)
                        print('Sequence Number: ', packet.sequence_number)
                        print('ACK Number: ', packet.ack_number)
                        print('Receive Window size: ', packet.window_size)
                        print(' ')
                    i += 1
                payload += int(packet.size)
                end_time = packet.timestamp

    result = payload / (end_time - start_time)
    return result


# Lost packets
def Loss(connection):
    loss = total_sent = 0
    triple = 0
    sequence_key = {}
    ack_key = {}

    # Sequence number is key, value = #times a sequence number is seen = starting at 1
    for packet in connection.packets:
        if TCP_Connection(packet, "130.245.145.12", "128.208.2.198"):
            total_sent += 1
            sequence_key[packet.sequence_number] = sequence_key.get(packet.sequence_number, 0) + 1
        # for part B
        if TCP_Connection(packet, "128.208.2.198", "130.245.145.12"):
            ack_key[packet.ack_number] = ack_key.get(packet.ack_number, 0) + 1

    # When sequence number appears > 1 => there is loss
    for key, value in sequence_key.items():
        if (key in ack_key) and (ack_key[key] > 2):
            triple += sequence_key[key] - 1
        elif key in sequence_key:
            loss += sequence_key[key] - 1

    print('Retransmissions due to Triple Duplicate ACK: %s' % str(triple))
    print('Retransmissions due to Timeout: %s' % str(loss))
    return loss * 1.0 / total_sent


def RTT(connection):
    all_ack = {}
    sequence_key = {}
    num = time_taken = 0
    for packet in connection.packets:
        if TCP_Connection(packet, "130.245.145.12", "128.208.2.198") and packet.sequence_number not in sequence_key:
            sequence_key[packet.sequence_number] = packet.timestamp

        if packet.source_ip == "128.208.2.198" and packet.destination_ip == "130.245.145.12":
            all_ack[packet.ack_number] = packet.timestamp

    for key, value in sequence_key.items():
        if str((int(key) + 1)) in all_ack:
            num += 1
            time_taken += all_ack[str((int(key) + 1))] - value

    return time_taken / num


# Part B
def congestion(connection):
    i = counter = c = 0
    first_packet = True
    first_timestamp = 0
    for packet in connection.packets:
        c += 1
        if i > 4:
            break
        if TCP_Connection(packet, "130.245.145.12", "128.208.2.198"):
            counter = counter + 1
            if first_packet:
                first_timestamp = packet.timestamp
                first_packet = False
            elif (packet.timestamp - first_timestamp) > 0.073:
                if i != 0:
                    print("Congestion Window Sizes = %s " % (counter * 1460))
                counter = 0
                first_packet = True
                i += 1


if __name__ == '__main__':
    tcp_connection_count = 0
    connections = []
    packets = []
    for timestamp, buffer in dpkt.pcap.Reader(open('assignment2.pcap', 'rb')):
        p = TCP_Packet()
        p.parse(timestamp, buffer)
        if p.valid:
            packets.append(p)
            if check_Connection(p):
                tcp_connection_count = tcp_connection_count + 1
                connection = Connection(p.source_port, p.destination_port)
                connection.packets = []
                connections.append(connection)

    for p in packets:
        for connection in range(0, len(connections), 1):
            if Port_Check(p, connections[connection]):
                connections[connection].packets.append(p)

    count = 1
    print("\nTcp connection count = %s \n" % tcp_connection_count)
    for connection in connections:
        print("Connection %s" % count)
        print("--------------------------------------------------------------")
        print("First two transactions after establishing connection")
        print("Throughput = %s Mbps" % (Throughput(connection) / 125000))
        print("Loss Rate = %s" % Loss(connection))
        print("Average RTT = %s ms \n" % (RTT(connection) * 1000))
        congestion(connection)
        count = count + 1
