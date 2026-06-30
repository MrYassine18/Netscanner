import ipaddress
import os
import socket 
#This file for creating useful function before starting the real scanning 
#I will start with input validation 

def ip_validation(ip):
    try :
        ipaddress.ip_address(ip)
        return ip
    except ValueError:
        #for hostnames 
        try :
            Ip = socket.gethostbyname(ip)
            return Ip
        except socket.gaierror:
            raise ValueError("the ip adresse is not valid.")
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