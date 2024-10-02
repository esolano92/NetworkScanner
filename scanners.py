from scapy.all import ARP, Ether, srp
import socket
import sys
import queue
import threading

"""
This module contains functions to scan a network for IP and Mac Addresses, open ports.
"""
def load_oui_database(file_path):
    oui_database = {}
    with open(file_path, 'r', encoding='utf-8') as f:
        line_count = 0
        for line in f:
            parts = line.strip().split('\t')
            oui_prefix = parts[0].strip().replace("-", ":").upper()
            manufacturer = parts[1].strip()
            oui_database[oui_prefix] = manufacturer
    return oui_database

def get_device_name(mac_address, oui_database):
    mac_address = mac_address.upper()
    oui_prefix = mac_address[:8]
    manufacturer = oui_database.get(oui_prefix, 'Unknown')
    return manufacturer

def scan_network(ip_range, oui_database):
    arp = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp
    result = srp(packet, timeout=3, verbose=False)[0]
    
    devices = []
    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc.upper(), 'name': get_device_name(received.hwsrc, oui_database)})
    return devices

def port_scan(target, start_port,end_port):
    #Create a queue to hold ports to be scanned
    ports_queue = queue.Queue()

    #Create an empty list use to store the port numbers that open and display later
    open_ports = []

    #store the ports in range in the Queue
    for i in range(start_port, end_port + 1):
        # end_port is not inclusive so +1 is needed
        ports_queue.put(i)

    #Helper function to scan ports within the range specified
    def scan():
        #Scan all ports in Queue
        while not ports_queue.empty(): #While the queue has ports to scan

            #Gets the next port to be scanned from Queue
            port_to_scan = ports_queue.get()
            print(f"Port being scanned: {port_to_scan}")

            try:
                
                #Create a TCP socket object with a timeout
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as connection_socket:
                    socket.setdefaulttimeout(5)

                    #connect_ex will return 0 if connection is successful
                    result = connection_socket.connect_ex((target, port_to_scan))

                    if result == 0:
                        print(f"#DEBUG TEST: Port {port_to_scan} is open!")
                        #if the port is open add to open_port list
                        open_ports.append(port_to_scan)
            
            
            #-----Exception Handling-----

            except KeyboardInterrupt:
                #If user interupts the program
                print("Exiting Program")
                sys.exit()
            
            except socket.gaierror:
                #If the host name cannot be resolved
                print("Hostname could not be resoloved!")
                sys.exit()

            except socket.error:
                #General error occurs
                sys.exit()

    #------Multithreading for optimization-------
    
    #Create an empty threads list
    threads = []
    

    #Create number of threads to use 
    for _ in range(100):
        #Create a thread object 
        thread = threading.Thread(target=scan, daemon=True)
        thread.start()
        threads.append(thread)

    #Wait for all threads to complete
    for thread in threads:
        thread.join()
    
    return open_ports