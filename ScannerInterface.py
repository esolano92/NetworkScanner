import tkinter as tk
from tkinter import ttk
from NetworkScanner.scanners import *


#default text
default_text="e.g., 192.168.1.0/24"
#----Custom Widegt Functions----

def on_entry_click(event):
    # handles entry click event
    if target_entryfield.get() == default_text:
        target_entryfield.delete(0, tk.END)
        target_entryfield.config(fg="black")
def on_focusout(event):
    # handles non entry click event 
    if target_entryfield.get() == "":
        target_entryfield.insert(0, default_text)
        target_entryfield.config(bg="grey")

def network_scan():
   ip_range =  target_entryfield.get()
   oui_database = load_oui_database("oui.txt")
   devices = scan_network(ip_range, oui_database)
   

   #Clear Content 
   network_scan_display.delete(1.0, tk.END)

   #Display on text widget
   network_scan_display.insert(tk.END, "Devices on the network:\n")
   network_scan_display.insert(tk.END, "No.\tIP Address\t\tMAC Address\t\tDevice Name\n")
   network_scan_display.insert(tk.END, "---------------------------------------------------\n")
   for i, device in enumerate(devices, 1):
    ip = device["ip"]
    mac = device["mac"]
    device_name = get_device_name(mac, oui_database)
    network_scan_display.insert(tk.END, f"{i}\t{ip}\t\t{mac}\t\t{device_name}\n")

def scan_ports():
    # Clear port scan display text widget
    port_scan_display.delete(1.0, tk.END)

    # selected port ranges to scan 
    selected_range = port_ranges.get()
    # # Get start and end ports
    start_port, end_port = map(int, selected_range.split("-"))

    # Get the IP's address from the network scan display entry widget
    ip_to_scan = ip_to_port_scan_entry.get()

    # Display a message indicating that port scanning has started
    port_scan_display.insert(tk.END, f"Scanning ports {start_port} - {end_port} for IP: {ip_to_scan}\n")
    port_scan_display.update()

    #store open port numbers
    open_ports = port_scan(ip_to_scan, start_port, end_port)

    
    
    #display ports
    if open_ports:
        port_scan_display.insert(tk.END, f"Open Ports for IP: {ip_to_scan}\n")
        port_scan_display.insert(tk.END, "\n".join(map(str, open_ports)) + "\n\n")
    else:
        port_scan_display.insert(tk.END, f"No open ports found for IP: {ip_to_scan}")

# Create a default text entry

#----Create the GUI----
main_window = tk.Tk()
main_window.title("Network Scanner")
main_window.geometry("845x730") #set the dimensions of the window
main_window.config(bg="light blue")



#----GUI Component----
#Label
target_label = tk.Label(main_window, text="Enter IP Range:",bg="light blue") 
target_label.grid(column=0, row=0, padx=5, pady=5)

#Entry Field
target_entryfield = tk.Entry(main_window, fg="grey")
target_entryfield.insert(0, default_text)
target_entryfield.grid(column=1, row=0, padx=5, pady=5)
target_entryfield.bind("<FocusIn>", on_entry_click)
target_entryfield.bind("<FocusOut>", on_focusout)

#Network Scan Button
scan_network_button = tk.Button(main_window, text="Network Scan", command=network_scan,bg="red")
scan_network_button.grid(column=2, row=0, padx=5, pady=5)

#Port Scan Button
port_scan_button = tk.Button(main_window, text="Port Scan", command=scan_ports, bg="red")
port_scan_button.grid(column=8,row=0,padx=5, pady=5)

#----Frame for Text Widget----
network_scan_frame = tk.Frame(main_window)
port_scan_frame = tk.Frame(main_window)

#----Content Display Component----
network_scan_display = tk.Text(network_scan_frame, height=20, width=50)
network_scan_display.pack(expand=True, fill="both")
port_scan_display = tk.Text(port_scan_frame, width=50, height=20)
port_scan_display.pack(expand=True, fill="both")
network_scan_frame.grid(row=1, column=0, columnspan=9, padx=5, pady=5, sticky="nsew")
port_scan_frame.grid(row=2, column=0, columnspan=9, padx=5, pady=5, sticky="nsew")


#Combox Box for Port Ranges
range_label = tk.Label(main_window, text="Port Ranges:",bg="light blue")
port_ranges = ttk.Combobox(main_window, values=["1-1023", "1024-11123", "11124-21123", "21124-31123","31124-41123","41124-51124","51123-65534"], width=10)
range_label.grid(column=5, row=0, padx=5, pady=5)
port_ranges.current(0)
port_ranges.grid(column=7, row=0,padx=5,pady=5)

#IP to scan port 
ip_to_port_scan_label = tk.Label(main_window, text="IP/Host Name to Port Scan", bg="light blue")
ip_to_port_scan_label.grid(column=3, row=0)

ip_to_port_scan_entry = tk.Entry(main_window)
ip_to_port_scan_entry.grid(column=4, row=0)

#starts the window and keeps it open 
main_window.mainloop()