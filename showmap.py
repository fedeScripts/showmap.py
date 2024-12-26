#!/usr/bin/python3

import re
import argparse
import csv
from rich.console import Console
from rich.text import Text
from rich.table import Table

# Configuración de Rich
console = Console()

# Variables globales
script_name = "showmap.py"
script_version = "v1.1"
url_repo = "https://github.com/fedeScripts/showmap.py" 

# Mensajes de error
MESSAGES = {
    "file_not_found": "{indicator} Error: No se pudo encontrar el archivo: {file}",
    "no_results": "{indicator} No se encontraron resultados que coincidan con los términos de búsqueda.",
    "no_action": "{indicator} No se proporcionó ninguna acción válida. Usa -h para más ayuda.",
    "processing": "{indicator} Procesando el archivo {file}",
    "export_csv": "{indicator} Exportando datos a {file}...",
    "success_csv": "{indicator} Datos exportados a {file} exitosamente.",
    "ip_port": "{indicator} Creando lista [IP] (port/tcp): \n"
}

# Indicadores de mensaje
MESSAGE_INDICATORS = {
    "colored_error": "[yellow][!][/yellow]",
    "colored_info": "[cyan][+][/cyan]",
    "no_colored_error": "[!]",
    "no_colored_info": "[+]",
}


# Banner
def print_banner(no_colour=False):
    banner_width = 50
    banner_description = "Procesa el normal output (-oN) de Nmap"
    colours = {
        True: {"title": "bold black on white", "url": "white italic", "separator": "white"},
        False: {"title": "bold white on medium_orchid", "url": "blue italic", "separator": "yellow"}
    }
    banner_colours = colours[no_colour]
    banner = Text()
    title = f" {script_name} - {script_version} "
    spaces = " " * ((banner_width - len(title)) // 2)
    banner.append("\n\n" + spaces)
    banner.append(title, style=banner_colours["title"])
    banner.append("\n\n")
    banner.append(banner_description.center(banner_width) + "\n", style="bold")
    url_text = Text(url_repo, style=f"link {url_repo}") 
    banner.append(f"{url_text}".center(banner_width) + "\n", style=banner_colours["url"])
    banner.append("\n  " + "﹉" * 23 + "\n", style=banner_colours["separator"])
    console.print(banner)


# Parsear el archivo de entrada
def parse_nmap_output(file_path):
    results = []
    with open(file_path, 'r') as file:
        host = None
        for line in file:
            # Detectar la IP
            host_match = re.match(r"Nmap scan report for (\S+)", line)
            if host_match:
                host = host_match.group(1)
            # Detectar el puerto
            port_match = re.match(r"(\d+)/tcp\s+(\S+)\s+(\S+)(.*)", line)
            if port_match and host:
                port = port_match.group(1)
                state = port_match.group(2)
                service = port_match.group(3)
                version = port_match.group(4).strip()
                results.append([host, port, state, service, version])
    return results


# Buscar por strings
def search_data(data, search_string):
    search_terms = [term.strip().lower() for term in search_string.split(",")]
    return [
        row for row in data
        if any(term in row[3].lower() or term in row[4].lower() or term in row[1] for term in search_terms)
    ]


# Crear la tabla
def print_table(data, output_file, no_colour=False):  
    colours = {
        True: {"table": "white", "host": "white", "port": "white", "state": "white", "service": "white", "version": "white"},
        False: {"table": "blue", "host": "yellow", "port": "green", "state": "blue", "service": "magenta", "version": "white"}
    }
    columns_colours = colours[no_colour]
    indicator_key = "no_colored_info" if no_colour else "colored_info"
    indicator = MESSAGE_INDICATORS[indicator_key]
    table = Table(title=f"{indicator} Resumen de {output_file}:\n", style=columns_colours["table"], title_style="bold", title_justify='left', show_edge=False, show_lines=False) 
    columns = [("Host", columns_colours["host"], 20), 
               ("Port", columns_colours["port"], 8), 
               ("State", columns_colours["state"], 6), 
               ("Service", columns_colours["service"], 15), 
               ("Version", columns_colours["version"], 15)]
    for column, style, width in columns:
        table.add_column(column, style=style, justify="left", min_width=width)
    for row in data:
        table.add_row(*row)
    console.print(table)


# Escribir la salida en formato CSV
def write_to_csv(data, output_file, no_colour=False):
    headers = ["Host", "Port", "State", "Service", "Version"]
    with open(output_file, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(headers)
        writer.writerows(data)
    show_message("success_csv", message_type="info", no_colour=no_colour, file=output_file)


# Imprimir puertos en formato IP (tcp/port)
def print_ip_ports(data, no_colour=False):
    results = []
    show_message("ip_port", message_type="info", no_colour=no_colour)    
    for row in data:
        host = row[0]
        port = row[1]
        results.append(f"{host} ({port}/tcp)")
    if no_colour:
        print("\n".join(results))
    else:
        console.print("\n".join(results), style="cyan")


# Parsear los argumentos
def parse_arguments():
    parser = argparse.ArgumentParser(description="Procesa el normal output (-oN) de Nmap y genera una tabla.")
    parser.add_argument("-i", "--input", required=True, help="Archivo de entrada con el output de nmap.")
    parser.add_argument("-csv", "--csv_output", help="Nombre del archivo CSV de salida.")
    parser.add_argument("-s", "--search", help="Realiza una búsqueda parcial o total (case-insensitive).")
    parser.add_argument("-ip", "--ip_ports", action="store_true", help="Imprime IPs y puertos abiertos en formato [IP] (port/tcp).")
    parser.add_argument("-n", "--no_colour", action="store_true", help="Desactiva el uso de colores en la salida.")
    return parser.parse_args()


# Mostrar mensajes
def show_message(key, message_type="error", no_colour=False, **kwargs):
    indicator_key = f"no_colored_{message_type}" if no_colour else f"colored_{message_type}"
    indicator = MESSAGE_INDICATORS[indicator_key]
    message = MESSAGES[key].format(indicator=indicator, **kwargs)
    if no_colour:
        print(message)
    else:
        console.print(f"{message}" if message_type == "error" else f"{message}")


# Función principal
def main():
    args = parse_arguments()
    print_banner(no_colour=args.no_colour)

    # Chequear la existencia del archivo
    try:
        data = parse_nmap_output(args.input)
    except FileNotFoundError:
        show_message("file_not_found", message_type="error", no_colour=args.no_colour, file=args.input)
        return

    if args.search and not args.ip_ports and not args.csv_output:
        data = search_data(data, args.search)

        if data:
            print_table(data, output_file=args.input, no_colour=args.no_colour)
        else:
            show_message("no_results", message_type="error", no_colour=args.no_colour, file=args.input)
    elif args.csv_output:
        if args.search:
            data = search_data(data, args.search)
            if data:
                write_to_csv(data, args.csv_output, no_colour=args.no_colour)
            else:
                show_message("no_results", message_type="error", no_colour=args.no_colour, file=args.input)
        else:
            write_to_csv(data, args.csv_output, no_colour=args.no_colour)
    elif args.ip_ports:
        if args.search:
            data = search_data(data, args.search)
            if data:
                print_ip_ports(data, no_colour=args.no_colour)
            else:
                show_message("no_results", message_type="error", no_colour=args.no_colour, file=args.input)
        else:
            print_ip_ports(data, no_colour=args.no_colour)
    elif args.input:
        print_table(data, output_file=args.input, no_colour=args.no_colour)
    else:
        show_message("no_actions", message_type="error", no_colour=args.no_colour, file=args.input)


if __name__ == "__main__":
    main()
