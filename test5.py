import pyshark
import csv
import multiprocessing as mp

def process_packet(pkt):
    packet_data = ['-1'] * 8  # fill in DNS, HTTP, and comments with -1
    packet_type = ''
    try:
        # Check the packet type
        if 'tls' in pkt:
            packet_type = 'TLS'
            if int(pkt.tls.handshake_type) == 1:
                #packet_data[0] = pkt.frame_info.comment
                packet_data[1] = pkt.length  # Example: use packet length as comment
                packet_data[2] = pkt.tls.handshake_extensions_server_name_len
            elif int(pkt.tls.handshake_type) == 2:
                #packet_data[0] = pkt.frame_info.comment
                packet_data[1] = pkt.length  # Example: use packet length as comment
                packet_data[3] = pkt.tls.handshake_ciphersuite
            else:
                #packet_data[0] = 'Other TLS packet'
                packet_data[1] = pkt.length  # Example: use packet length as comment

        if 'dns' in pkt:
            packet_type = 'DNS'
            #packet_data[0] = pkt.frame_info.comment
            packet_data[1] = pkt.length  # Example: use packet length as comment
            packet_data[4] = pkt.dns.qry_name
            packet_data[5] = pkt.dns.qry_name_len

        if 'http' in pkt:
            packet_type = 'HTTP'
            #packet_data[0] = pkt.frame_info.comment
            try:
                packet_data[1] = pkt.length  # Example: use packet length as comment
                packet_data[6] = pkt.http.content_type
                packet_data[7] = pkt.http.response_code
            except Exception as e:
                pass

        return [packet_type] + packet_data

    except Exception as e:
        pass

def file_to_csv(packet):
    
    # Open the CSV file for writing
    with open('output.csv', 'w', newline='') as f:
        idx = 0
        writer = csv.writer(f)

        # Write the header row to the CSV file
        writer.writerow(['Packet Type', 'Packet Comments', 'TLS option 1', 'TLS option 2', 'TLS option 3','DNS TTL', 'DNS Domain Length', 'HTTP Content Type', 'HTTP Return Code'])
        
        # Create a pool of worker processes
        pool = mp.Pool()

        # Process packets in parallel using the pool of worker processes
        cap = pyshark.FileCapture(packet)
        for row in pool.imap_unordered(process_packet, cap):
            if row is not None:
                writer.writerow(row)
        
        pool.close()
        pool.join()
        
        idx += 1
        if idx % 1000 == 0:
            print(idx)

file_to_csv('traffic_test.pcapng')
