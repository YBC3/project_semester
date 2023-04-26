import pyshark
import csv
from multiprocessing import Pool
cnt = 0
def process_packet(pkt):
    
    packet_data = ['-1'] * 9  # fill in DNS, HTTP, and comments with -1
    packet_type = ''
    try:
        if 'tls' in pkt:
            packet_type = 'TLS'
            #print('TLS')
            h_type = int(pkt.tls.handshake_type)
            #print(h_type)
            if  h_type == 1:
                #packet_data[0] = pkt.frame_info.comment
                packet_data[1] = pkt.length  # Example: use packet length as comment
                packet_data[2] = pkt.tls.handshake_extensions_server_name_len
            elif h_type == 2:
                #packet_data[0] = pkt.frame_info.comment
                packet_data[1] = pkt.length  # Example: use packet length as comment
                packet_data[3] = pkt.tls.handshake_ciphersuite
            else:
                #packet_data[0] = 'Other TLS packet'
                packet_data[1] = pkt.length

        elif 'dns' in pkt:
            #print("dns")
            packet_type = 'DNS'
            #packet_data[0] = pkt.frame_info.comment
            packet_data[1] = pkt.length  # Example: use packet length as comment
            packet_data[4] = pkt.dns.qry_name
            packet_data[5] = pkt.dns.qry_name_len

        elif 'http' in pkt:
            #print('http')
            packet_type = 'HTTP'
            #packet_data[0] = pkt.frame_info.comment
            try:
                packet_data[1] = pkt.length  # Example: use packet length as comment
                packet_data[6] = pkt.http.content_type
                packet_data[7] = pkt.http.response_code
            except Exception as e:
                #print('exp 1')
                pass
        if 'malware' in str(pkt.frame_info):
            packet_data[8] = 1
        else:
            packet_data[8] = 0
        return [packet_type] + packet_data
    
    except Exception as e:
        #print('exception')
        return None

def file_to_csv(packet):
    with open('output_data.csv', 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['Packet Type', 'Packet Comments', 'TLS option 1', 'TLS option 2', 'TLS option 3','DNS TTL', 'DNS Domain Length', 'HTTP Content Type', 'HTTP Return Code', 'label'])
        with Pool() as p:
            results = p.imap(process_packet, pyshark.FileCapture(packet))
            #print(results)
            idx = 0
            for r in results:
                #print(r)
                if r is not None:
                    writer.writerow(r)
                idx += 1
                if idx % 1000 == 0:
                    print(idx)

file_to_csv('traffic_test.pcapng')