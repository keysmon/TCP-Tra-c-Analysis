#Hang Ruan  V00923058
import struct
import sys

#Given by Dr.Wu Kui
class IP_Header:
    src_ip = None #<type 'str'>
    dst_ip = None #<type 'str'>
    ip_header_len = None #<type 'int'>
    total_len = None    #<type 'int'>
    
    def __init__(self):
        self.src_ip = None
        self.dst_ip = None
        self.ip_header_len = 0
        self.total_len = 0
    
    def ip_set(self,src_ip,dst_ip):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
    
    def header_len_set(self,length):
        self.ip_header_len = length
    
    def total_len_set(self, length):
        self.total_len = length
        
    def get_IP(self,buffer1,buffer2):
        src_addr = struct.unpack('BBBB',buffer1)
        dst_addr = struct.unpack('BBBB',buffer2)
        s_ip = str(src_addr[0])+'.'+str(src_addr[1])+'.'+str(src_addr[2])+'.'+str(src_addr[3])
        d_ip = str(dst_addr[0])+'.'+str(dst_addr[1])+'.'+str(dst_addr[2])+'.'+str(dst_addr[3])
        self.ip_set(s_ip, d_ip)
        
    def get_header_len(self,value):
        result = struct.unpack('B', value)[0]
        length = (result & 15)*4
        self.header_len_set(length)

    def get_total_len(self,buffer):
        num1 = ((buffer[0]&240)>>4)*16*16*16
        num2 = (buffer[0]&15)*16*16
        num3 = ((buffer[1]&240)>>4)*16
        num4 = (buffer[1]&15)
        length = num1+num2+num3+num4
        self.total_len_set(length)
        
#Given by Dr.Wu Kui
class TCP_Header:
    src_port = 0
    dst_port = 0
    seq_num = 0
    ack_num = 0
    data_offset = 0
    flags = {}
    window_size =0
    checksum = 0
    ugp = 0
    
    def __init__(self):
        self.src_port = 0
        self.dst_port = 0
        self.seq_num = 0
        self.ack_num = 0
        self.data_offset = 0
        self.flags = {}
        self.window_size =0
        self.checksum = 0
        self.ugp = 0
    
    def src_port_set(self, src):
        self.src_port = src
        
    def dst_port_set(self,dst):
        self.dst_port = dst
        
    def seq_num_set(self,seq):
        self.seq_num = seq
        
    def ack_num_set(self,ack):
        self.ack_num = ack
        
    def data_offset_set(self,data_offset):
        self.data_offset = data_offset
        
    def flags_set(self,ack, rst, syn, fin):
        self.flags["ACK"] = ack
        self.flags["RST"] = rst
        self.flags["SYN"] = syn
        self.flags["FIN"] = fin
    
    def win_size_set(self,size):
        self.window_size = size
        
    def get_src_port(self,buffer):
        num1 = ((buffer[0]&240)>>4)*16*16*16
        num2 = (buffer[0]&15)*16*16
        num3 = ((buffer[1]&240)>>4)*16
        num4 = (buffer[1]&15)
        port = num1+num2+num3+num4
        self.src_port_set(port)
        #print(self.src_port)
        return None
    
    def get_dst_port(self,buffer):
        num1 = ((buffer[0]&240)>>4)*16*16*16
        num2 = (buffer[0]&15)*16*16
        num3 = ((buffer[1]&240)>>4)*16
        num4 = (buffer[1]&15)
        port = num1+num2+num3+num4
        self.dst_port_set(port)
        #print(self.dst_port)
        return None
    
    def get_seq_num(self,buffer):
        seq = struct.unpack(">I",buffer)[0]
        self.seq_num_set(seq)
        #print(seq)
        return None
    
    def get_ack_num(self,buffer):
        ack = struct.unpack('>I',buffer)[0]
        self.ack_num_set(ack)
        return None
    
    def get_flags(self,buffer):
        value = struct.unpack("B",buffer)[0]
        fin = value & 1
        syn = (value & 2)>>1
        rst = (value & 4)>>2
        ack = (value & 16)>>4
        self.flags_set(ack, rst, syn, fin)
        return None
    def get_window_size(self,buffer1,buffer2):
        buffer = buffer2+buffer1
        size = struct.unpack('H',buffer)[0]
        self.win_size_set(size)
        return None
        
    def get_data_offset(self,buffer):
        value = struct.unpack("B",buffer)[0]
        length = ((value & 240)>>4)*4
        self.data_offset_set(length)
        #print(self.data_offset)
        return None
    
    def relative_seq_num(self,orig_num):
        if(self.seq_num>=orig_num):
            relative_seq = self.seq_num - orig_num
            self.seq_num_set(relative_seq)
        #print(self.seq_num)
        
    def relative_ack_num(self,orig_num):
        if(self.ack_num>=orig_num):
            relative_ack = self.ack_num-orig_num+1
            self.ack_num_set(relative_ack)
   
#Given by Dr.Wu Kui
class packet():
    
    #pcap_hd_info = None
    
    IP_header = None
    TCP_header = None
    timestamp = 0
    packet_No = 0
    RTT_value = 0
    RTT_flag = False
    buffer = None
    data_length = 0
    
    def __init__(self):
        self.IP_header = IP_Header()
        self.TCP_header = TCP_Header()
        #self.pcap_hd_info = pcap_ph_info()
        self.timestamp = 0
        self.packet_No =0
        self.RTT_value = 0.0
        self.RTT_flag = False
        self.buffer = None
        self.data_length = 0
        
    def timestamp_set(self,buffer1,buffer2,orig_time):
        self.timestamp = round(buffer1+buffer2*0.000001-orig_time,6)
        #print(self.timestamp,self.packet_No)
    def packet_No_set(self,number):
        self.packet_No = number
        #print(self.packet_No)
        
    def get_RTT_value(self,p):
        rtt = p.timestamp-self.timestamp
        self.RTT_value = round(rtt,8)
#unpack timestamp,incl_len and package_length from package frame

#connection to save each connection
class connection():
    syn = 0
    fin = 0
    forward = []
    forward_data = 0
    backward = []
    backward_data = 0
    src_addr = 0
    src_port = 0
    dest_addr = 0
    dest_port = 0
    start_time = 0
    end_time = 0
    reset = 0
    src_to_dest = 0
    dest_to_src = 0
    complete = 0
    
    def __init__(self):
        self.syn = 0
        self.fin = 0
        self.forward = []
        self.backward = []
        self.src_addr = 0
        self.src_port = 0
        self.dest_addr = 0
        self.dest_port = 0
        self.start_time = 0
        self.end_time = 0
        self.reset = 0
        self.src_to_dest = 0
        self.dest_to_src = 0
        self.complete = 0

#get timestamp and total_length of package
def package_frame(data):
    ts_sec,ts_usec,incl_len,orig_len = struct.unpack('I I I I',data[:16])
    return ts_sec,ts_usec,incl_len,orig_len,data[16:]


#get dest_address,src_address and protocol
def ethernet_frame(data):
    dest,src,proto = struct.unpack('! 6s 6s H',data[:14])
    return get_mac_address(dest),get_mac_address(src),proto,data[14:]
    
#format address into the format AA:BB:CC:DD:EE:FF
def get_mac_address(bytes_address):
    bytes_str = map('{:02x}'.format, bytes_address)
    mac_addr = ':'.join(bytes_str).upper()
    return mac_addr
    
#unpack ip_header info
def ipv4_packet(data):
    version_headerLength = data[0]
    version = version_headerLength >> 4
    header_length = (version_headerLength&15) * 4
    total_length = struct.unpack('! H',data[2:4])[0]
    ttl,proto,src,dest = struct.unpack('!8x B B 2x 4s 4s',data[:20])
    return total_length,version,header_length,ttl,proto,ipv4(src),ipv4(dest),data[header_length:]
    
#format ip_address
def ipv4(addr):
    return '.'.join(map(str,addr))
    
#unpack tcp_package
def tcp_package(data):
    (src_port,dest_port,seq,ack,offset_reserved_flag) = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flag >> 12)*4
    flag_urg = (offset_reserved_flag& 32 )>>5
    flag_ack = (offset_reserved_flag& 16 )>>4
    flag_psh = (offset_reserved_flag& 8 )>>3
    flag_ret = (offset_reserved_flag& 4 )>>2
    flag_syn = (offset_reserved_flag& 2 )>>1
    flag_fin = (offset_reserved_flag& 1)
    win_size = struct.unpack('!H',data[14:16])[0]
    
    return win_size,offset,src_port,dest_port,seq,ack, flag_urg,flag_ack,flag_psh,flag_ret,flag_syn,flag_fin,data[offset:]
#fill in RTT values in packets
def RTT_filler(connection_list):
    RTT_list = []
    no = []
    for connection in connection_list:
        #check for complete connection
        if not(connection.complete):
            continue
        for packet in connection.forward:
            syn = packet.TCP_header.flags["SYN"]
            fin = packet.TCP_header.flags["FIN"]
            seq = packet.TCP_header.seq_num
            data = packet.data_length
            
            
            
            if not(data  == 0):
                #check RTT for client sending data to server
                for return_pac in connection.backward:
                    ack = return_pac.TCP_header.ack_num
                    #check for a matching pair where return comes after client
                    if(ack == seq+data and return_pac.timestamp > packet.timestamp):
                    #if(ack == seq+data and return_pac.packet_No > packet.packet_No):
                        packet.RTT_flag = True
                        packet.RTT_value = return_pac.timestamp - packet.timestamp
                        RTT_list.append(packet.RTT_value)
                        
                       
                       
                        break;
            #check RTT for client sending syn to server
            if(syn):
                for return_pac in connection.backward:
                    ack = return_pac.TCP_header.ack_num
                    if(ack == seq+1 and return_pac.timestamp > packet.timestamp):
                        packet.RTT_flag = True
                        packet.RTT_value = return_pac.timestamp - packet.timestamp
                        RTT_list.append(packet.RTT_value)
                        break;
            #check RTT for client sending fin to server
            if(fin):
                for return_pac in connection.backward:
                    ack = return_pac.TCP_header.ack_num
                    if(ack == seq+1 and return_pac.timestamp > packet.timestamp):
                        packet.RTT_flag = True
                        packet.RTT_value = return_pac.timestamp - packet.timestamp
                        RTT_list.append(packet.RTT_value)
                        break;
                    
    
    
    return RTT_list

def outputA(connection_list):
    print("A) Total number of connections: ",len(connection_list),end = "\n\n\n")
    
    
def outputB(connection_list):
    print("B) Connections' detail:")
    for index in range(0,len(connection_list)):
        temp = connection_list[index]
        print("Connection ",index+1,":",sep="")
        print("Source Address:", temp.src_addr)
        print("Destination Address:", temp.dest_addr)
        print("Source Port:", temp.src_port)
        print("Destination Port:", temp.dest_port)
        print("Status:S",temp.syn,"F",temp.fin,sep="",end = "")
        #put /R on status if reseted
        if(temp.reset):
            print("/R",end = "")
        print("")
        #print out following only for completed connection
        if(temp.syn>0 and temp.fin>0):
            print("Start time:",temp.start_time,"s")
            print("End time:",temp.end_time,"s")
            print("Duration:",round(temp.end_time-temp.start_time,6),"s")
            print("Number of packets sent from Source to Destination:",len(temp.forward))
            print("Number of packets sent from Destination to Source:",len(temp.backward))
            print("Total number of packets:",len(temp.forward)+len(temp.backward))
            print("Number of databytes sent from Source to Destination:",temp.forward_data)
            print("Number of databytes sent from Destination to Source:",temp.backward_data)
            print("Total number of data bytes:",temp.forward_data+temp.backward_data)
        print("End", end = "\n\n")
    print("")
    return


def outputC(connection_list):
    complete = 0    #num_of complete connection
    reset = 0       #num of reset connection
    for temp in connection_list:
        if (temp.complete):
            complete += 1
        if (temp.reset):
            reset += 1
    print("C) General")
    print("Total number of complete TCP connections:",complete)
    print("Number of reset TCP connections:",reset)
    print("Number of TCP connections that were still open when the trace capture ended:",len(connection_list)-complete)
    print("\n")
    
    
def outputD(connection_list):
    print("D) Complete TCP connections:")
    
    #Time duration
    time_duration = []
    for temp in connection_list:
        #check for complete connection
        if(temp.syn>0 and temp.fin>0):
            #find time duration
            diff = temp.end_time-temp.start_time
            time_duration.append(diff)
    print("Minmum time duration:", round(min(time_duration),6),"s")
    print("Mean time duration:", round(sum(time_duration)/len(time_duration),6),"s")
    print("Maximum time duration:", round(max(time_duration),6),"s")
    
    
    #RTT value
    RTT_value = RTT_filler(connection_list)
    print("Minimum RTT value:",round(min(RTT_value),6),"s")
    print("Mean RTT value",round(sum(RTT_value)/len(RTT_value),6),"s")
    print("Maximum RTT value:",round(max(RTT_value),6),"s")
    
    
    
    #Number of packets
    num_of_pac = []
    for temp in connection_list:
        #check for complete connection
        if(temp.syn>0 and temp.fin>0):
            num = len(temp.forward) + len(temp.backward)
            num_of_pac.append(num)
    print("Minimum number of packets including both send/received:",round(min(num_of_pac),6))
    print("Mean number of packets including both send/received:",round(sum(num_of_pac)/len(num_of_pac),6))
    print("Maximum number of packets including both send/received:",round(max(num_of_pac),6))


    #Window_size
    windows = []
    for temp in connection_list:
        if(temp.syn>0 and temp.fin>0):
            for x in temp.forward:
                windows.append(x.TCP_header.window_size)
            for y in temp.backward:
                windows.append(y.TCP_header.window_size)
    print("Minmum receive window size including both send/received:",round(min(windows),6),"bytes")
    print("Mean receive window size including both send/received:",round(sum(windows)/len(windows),6),"bytes")
    print("Maximum receive window size including both send/received:",round(max(windows),6),"bytes")


def main(argv):
    package_list = []
    connection_list = []
    
    file_name = argv[1]
    f = open(file_name,"rb")
    fileContent = f.read()
    #skip global
    fileContent = fileContent[24:]
    i = 1   #frame counter
   
    #loop till EOF and add all package to the packet_list
    while len(fileContent) != 0:
        #No. of frame
        #print("No.",i)
        
        #print("Package frame:")
        ts_sec,ts_usec,incl_len,orig_len,fileContent = package_frame(fileContent)
        #print(ts_sec, " ",ts_usec, " ",incl_len, " ",orig_len)
        
        #set orig_time
        if(i==1):
            orig_time = round(ts_sec+ts_usec*0.000001,6)
        
        #print("Ethernet frame:")
        dest,src,proto,fileContent = ethernet_frame(fileContent)
        #print(dest+ "(dest_MAC) ",src+"(src_Mac) ",proto,"(proto) ")
        
        #print("IP header:")
        total_length, version,header_length,ttl,proto,src,dest,fileContent = ipv4_packet(fileContent)
        #print(version,"(vers) ",header_length,"(header_len) ",ttl,"(ttl) ",proto,"(proto) ",src,"(src_addr) ",dest,"(dest_addr) ")
        
        #print("TCP header:")
        (win_size,offset,src_port,dest_port,sequence,acknowledgement, flag_urg,flag_ack,flag_psh,flag_ret,flag_syn,flag_fin,fileContent) = tcp_package(fileContent)
        #print(src_port,"(src_port) ",dest_port,"(dest_port) ",sequence,"(Seq) ",acknowledgement,"(Ack) ")
        
        data_length = total_length - header_length - offset
        #print("Data:",data_length,"bytes")
        fileContent = fileContent[data_length:]
        #print("Time:",round(ts_sec+ts_usec*0.000001-orig_time,6),"s",end="\n\n")
        
        
        #skip padding
        fileContent = fileContent[orig_len-14-total_length:]
        
        
       
        #create Package_Header classs
        package = packet()
        IP_package = IP_Header()
        TCP_package = TCP_Header()
        package.TCP_header = TCP_package
        package.packet_No_set(i-1)
        package.timestamp_set(ts_sec,ts_usec,orig_time)
        package.data_length = data_length
        package_list.append(package)
       
        #create IP_Header class
        package.IP_header.src_ip = src
        package.IP_header.dst_ip = dest
        package.IP_header.header_len_set(header_length)
        package.IP_header.total_len_set(total_length)

        #create TCP_Header class
        package.TCP_header.src_port_set(src_port)
        package.TCP_header.dst_port_set(dest_port)
        package.TCP_header.ack_num_set(acknowledgement)
        package.TCP_header.seq_num_set(sequence)
        package.TCP_header.data_offset_set(offset)
        package.TCP_header.window_size = win_size
        package.TCP_header.flags_set(flag_ack,flag_ret,flag_syn,flag_fin)
        
       
        i = i+1
        
    
    # Packet_list -> Connection_list
    for p in package_list:
        
        exist = 0
        flag_syn = p.TCP_header.flags["SYN"]
        flag_rst = p.TCP_header.flags["RST"]
        flag_fin = p.TCP_header.flags["FIN"]
        src_addr = p.IP_header.src_ip
        src_port = p.TCP_header.src_port
        dest_addr = p.IP_header.dst_ip
        dest_port = p.TCP_header.dst_port
        timestamp = p.timestamp
        data = p.data_length
        
        for temp in connection_list:
            #if length = 0, then this is a new connection
            if(len(connection_list) == 0):
                exist = 1
                break
            #if connection already exist with same 4-tuple
            if(temp.src_addr == src_addr and  temp.src_port == src_port and temp.dest_addr == dest_addr and temp.dest_port == dest_port):
                temp.forward.append(p)
                temp.forward_data += data
                exist = 1
                #check for no of syn/fin flag
                if(flag_syn == 1):
                    temp.syn += 1
                if(flag_fin == 1):
                    temp.fin += 1
                #check if connection is reset or complete
                if(flag_rst == 1):
                    temp.reset = 1
                if(flag_fin == 1):
                    temp.complete = 1   #if complete,get the end time
                    temp.end_time = timestamp
                break
            #if connection exists with the opposite address,port
            elif(temp.src_addr == dest_addr and  temp.src_port == dest_port and temp.dest_addr == src_addr and temp.dest_port == src_port):
                temp.backward.append(p)
                temp.backward_data += data
                exist = 1
                #check for no of syn/fin flag
                if(flag_syn == 1):
                    temp.syn += 1
                if(flag_fin == 1):
                    temp.fin += 1
                #check if connection is reset or complete
                if(flag_rst == 1):
                    temp.reset = 1
                if(flag_fin == 1):
                    temp.complete = 1   #if complete,get the end time
                    temp.end_time = timestamp
                break
        if(exist == 1):
            continue
            
        
        #create a new connection
        new_connection = connection()
        new_connection.src_addr = src_addr
        new_connection.src_port = src_port
        new_connection.dest_addr = dest_addr
        new_connection.dest_port = dest_port
        new_connection.start_time = timestamp
        new_connection.forward_data += data
        if(flag_syn):
            new_connection.syn = 1
        new_connection.forward.append(p)
        connection_list.append(new_connection)
    # part A output
    outputA(connection_list)
    # part B output
    outputB(connection_list)
    # part C output
    outputC(connection_list)
    # part D output
    outputD(connection_list)
    
    #close file
    f.close()
    




if __name__ =="__main__":
    if len(sys.argv) != 2:
        print("Invalid argrument! Exiting")
    else:
        main(sys.argv)
