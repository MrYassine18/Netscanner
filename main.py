from scanner.portscan import scanning
from scanner.utils import ip_validation,port_validation
import click 
@click.command()
@click.argument("ip")
@click.option("-p","--ports", default = "1-1024", show_default = True, help = "Port range: 22 | 22,80 | 1-1024")
@click.option("-t", "--timeout", default=1.0,        show_default=True, help="Seconds to wait per port")
@click.option("--threads", default= 100, show_default = True, help="number of cucurrent threads")
@click.option("--open-only", is_flag=True, help="show only the open ports")

def main(ip : str ,ports:str,  timeout:float, threads:int, open_only:bool):
    """TCP port scanner — scan a host for open ports.

    \b
    Examples:
        python main.py 192.168.1.1
        python main.py 192.168.1.1 -p 22,80,443 --open-only
        python main.py scanme.nmap.org -p 1-1024 -t 2
    """
    try :
        ip = ip_validation(ip)
        ports = port_validation(ports)
    except ValueError as e :
        click.echo(f"[ERROR] {e}", err=True)
        raise SystemExit(1)
    results = scanning(ip, ports,timeout, threads)
    for element in results:
        if element.state == "open" :
            click.echo(f"  [OPEN]     {element.host}:{element.port}  {element.banner[:50]}")
        
        elif not open_only:
            if element.state == "closed":
                click.echo(f"  [CLOSED]   {element.host}:{element.port}")
            else:
                click.echo(f"  [FILTERED] {element.host}:{element.port}")
    # Summary line
    open_count = sum(1 for r in results if r.state == "open")
    click.echo(f"\n{open_count} open port(s) found out of {len(ports)} scanned.")
if __name__ == "__main__" :
    main()
        