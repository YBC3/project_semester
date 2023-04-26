import pyshark
import csv
import ray
ray.init()
@ray.remote
def file_to_csv(packet):
    li = []
    # Open the CSV file for writing
    with open('output.csv', 'w', newline='') as f:
        writer = csv.writer(f)

        # Write the header row to the CSV file
        writer.writerow(['Packet Type', 'Packet Comments', 'Client Hello Server Name Length', 'Server Hello Server Name Length', 'DNS TTL', 'DNS Domain Length', 'HTTP Content Type', 'HTTP Return Code'])

        # Iterate through the packets in the capture file
        for pkt in pyshark.FileCapture(packet):

            # Initialize the packet data
            packet_data = ['-1'] * 6  # fill in DNS, HTTP, and comments with -1
            packet_type = ''

            try:
                # Check the packet type
                if 'tls' in pkt:
                    packet_type = 'TLS'
                    if pkt.tls.handshake_type == '1':
                        packet_data[0] = 'Client Hello'
                        packet_data[1] = pkt.length  # Example: use packet length as comment
                        packet_data[2] = pkt.tls.handshake_extensions_length
                    elif pkt.tls.handshake_type == '2':
                        packet_data[0] = 'Server Hello'
                        packet_data[1] = pkt.length  # Example: use packet length as comment
                        packet_data[3] = pkt.tls.handshake_extensions_length
                    else:
                        packet_data[0] = 'Other TLS packet'
                        packet_data[1] = pkt.length  # Example: use packet length as comment

                elif 'dns' in pkt:
                    packet_type = 'DNS'
                    packet_data[1] = pkt.length  # Example: use packet length as comment
                    packet_data[4] = pkt.dns.count
                    packet_data[5] = len(pkt.dns.qry_name)

                elif 'http' in pkt:
                    packet_type = 'HTTP'
                    packet_data[1] = pkt.length  # Example: use packet length as comment
                    packet_data[6] = pkt.http.content_type
                    packet_data[7] = pkt.http.response_for_uri.status_code

                # Write the packet data to the CSV file
                writer.writerow([packet_type] + packet_data)
                li.append([packet_type] + packet_data)

            except Exception as e:
                # Handle any exceptions (e.g. invalid packets) and continue to the next packet
                continue
    return li

l = file_to_csv.remote('traffic_test.pcapng')
l_info = ray.get(l)
print(l_info)
ray.shutdown()