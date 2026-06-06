import socket
from utils import port_validation, Ip_validation
from dataclasses import dataclass
import errno
from concurrent.futures import ThreadPoolExecutor, as_completed
@dataclass
class scanResult :
      host: str
      port: int
      state : str
      banner : str = ""
def scan_one_port(ip:str,port:int,timeout:float = 1.0):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try :
            result = s.connect_ex((ip,port))
            if result ==0 :
                banner = ""
                try:
                      s.settimeout(0.5)
                      banner = s.recv(1024).decode(errors="replace").strip()
                except Exception:
                      pass
                return scanResult(host=ip,port=port,state="open",banner=banner)
                
            elif result == errno.ECONNREFUSED:
                return scanResult(host=ip,port=port,state="closed")
            else:
                return scanResult(host=ip,port=port,state="filtered")

                
                    
    except socket.TimeoutError: 
            return scanResult(host=ip,port=port,state="filtered")
    finally: 
        s.close()

def scanning(ip:str,ports:str, timeout:float = 1.0, threads:int = 100):
    ip = Ip_validation(ip)
    port_list = port_validation(ports)
    results = []
    with ThreadPoolExecutor(max_workers=threads) as executer : 
         futures = {
              executer.submit(scan_one_port,ip, port ,timeout): port for port in port_list
         }

    for future in as_completed(futures):
            result = future.result()
            results.append(result)
            if result.state == "open":
                print(f"  [OPEN]     {result.host}:{result.port}  {result.banner[:50]}")
            elif result.state == "closed":
                print(f"  [CLOSED]   {result.host}:{result.port}")
            else:
                print(f"  [FILTERED] {result.host}:{result.port}")

    # Sort by port number for clean output
    return sorted(results, key=lambda r: r.port)
     
