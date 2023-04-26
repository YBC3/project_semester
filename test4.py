import csv
import subprocess

def process_packet(packet_data):
    try:
        if packet_data[0] == 'TLS':
            if packet_data[1] == '1':
                return [packet_data[2], packet_data[3], packet_data[4], '', '', '', '', '']
            elif packet_data[1] == '2':
                return [packet_data[2], packet_data[3], '', packet_data[4], '', '', '', '']
            else:
                return [packet_data[2], packet_data[3], '', '', '', '', '', '']
        elif packet_data[0] == 'DNS':
            return [packet_data[0], packet_data[2], '', '', '', packet_data[1], packet_data[3], '', '']
        elif packet_data[0] == 'HTTP':
            return [packet_data[0], packet_data[2], '', '', '', '', '', packet_data[1], packet_data[3]]
        else:
            return None
    except Exception as e:
        return None

def file_to_csv(packet):
    with open('output.csv', 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['Packet Type', 'Packet Comments', 'TLS option 1', 'TLS option 2', 'TLS option 3','DNS TTL', 'DNS Domain Length', 'HTTP Content Type', 'HTTP Return Code'])

        cmd = ['tshark', '-r', packet, '-T', 'fields', '-E', 'separator=,', '-e', 'frame.comment', '-e', 'frame.len', '-e', 'tls.handshake.type', '-e', 'tls.handshake.extensions_server_name_length', '-e', 'tls.handshake.ciphersuite', '-e', 'dns.count', '-e', 'dns.qry.name.len', '-e', 'http.content_type', '-e', 'http.response_for.uri.status_code']

        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()
        print(stdout)
        '''
        idx = 0
        for line in stdout.decode('utf-8').splitlines():
            packet_data = line.split(',')
            result = process_packet(packet_data)
            if result is not None:
                writer.writerow(result)
            idx += 1
            if idx % 100 == 0:
                print(idx)
                '''

file_to_csv('traffic_test.pcapng')