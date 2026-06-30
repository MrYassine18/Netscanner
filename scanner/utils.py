import ipaddress
import os
import socket 
#This file for creating useful function before starting the real scanning 
#I will start with input validation 


def parse_target(input):
    try:
        net = ipaddress.ip_network(input, strict=False)
        if net.num_addresses ==1 :
            return [str(net.network_address)]
        return [str(ip) for ip in net.hosts()]
    except ValueError:
        try :
            Hostname = socket.gethostbyname(input) 
            return [Hostname]
        except socket.gaierror:
            raise ValueError(f"'{input}' is not a valid IP, CIDR range, or hostname.")

       


def port_validation(port):
    try : 

        port_list = set()

        for i in port.split(","):
            i = i.strip()
            if  "-" in i :
                start,end = i.split("-")
                start,end = int(start),int(end)
                if start > end:
                    raise ValueError("the end must be bigger than the start")
                port_list.update(range(start,end+1))
            else :
                port_list.add(int(i))
    except ValueError as e :
        raise ValueError(f"Invalid port specification '{port}': {e}")
    for i in port_list:
        if i<1 or i>65535:
            raise ValueError(f"Port {i} out of range (1-65535)")
        
    return sorted(port_list)
        
def is_root():
    return os.geteuid() == 0