#!/bin/python3
# Autor: Federico Galarza
# LinkedIn: linkedin.com/in/federico-galarza

import re
import argparse
import csv
from tabulate import tabulate

# Variables globales 
script_name = "showmap.py"
script_version = "0.1"

# Banner
def print_banner():
    banner = f"""
    
                {script_name} - v{script_version}
            ◣━━━━━━━━━━━━━━━━━━━━━━━◢
    """
    print(banner)


# Recorrer linea a linea el archivo de entrada
def parse_nmap_output(file_path):
    results = []
    with open(file_path, 'r') as file:
        host = None
        for line in file:
            # Detecto la IP
            host_match = re.match(r"Nmap scan report for (\S+)", line)
            if host_match:
                host = host_match.group(1)
            # Detecto el puerto
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
def print_table(data):
    headers = ["Host", "Port", "State", "Service", "Version"]
    table = tabulate(data, headers, tablefmt="plain")

    # Obtener el encabezado y calcular las longitudes
    header_line = table.split('\n')[0]
    header_parts = header_line.split(' ')
    underlines = ''.join(['=' * len(part) + ' ' for part in header_parts]).rstrip()

    # Imprimir la tabla con subrayado en el encabezado
    print(header_line)
    print(underlines)
    print('\n'.join(table.split('\n')[1:]))


# Escribir la salida en formato CSV
def write_to_csv(data, output_file):
    headers = ["Host", "Port", "State", "Service", "Version"]
    with open(output_file, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(headers)
        writer.writerows(data)
    print(f"Datos exportados a {output_file} exitosamente.")

# Parsear los argumentos
def parse_arguments():
    parser = argparse.ArgumentParser(description="Procesa el output de nmap y genera una tabla.")
    parser.add_argument("-i", "--input", required=True, help="Archivo de entrada con el output de nmap.")
    parser.add_argument("-csv", "--csv_output", help="Archivo CSV de salida.")
    parser.add_argument("-p", "--print_table", action="store_true", help="Imprime la tabla en consola.")
    parser.add_argument("-s", "--search", help="Realiza una búsqueda parcial o total (case-insensitive).")
    return parser.parse_args()


def main():

    print_banner()  
    args = parse_arguments()
    
    # Chequear la existencia del archivo
    try:
        data = parse_nmap_output(args.input)
    except FileNotFoundError:
        print(f"Error: No se pudo encontrar el archivo {args.input}")
        return    
    
    if args.search:
        data = search_data(data, args.search)
        if data:
            print_table(data)
        else:
            print("No se encontraron resultados que coincidan con los términos de búsqueda.")
    elif args.print_table:
        print_table(data)
    elif args.csv_output:
        write_to_csv(data, args.csv_output)
    elif not args.print_table and args.input:
        print_table(data)

if __name__ == "__main__":
    main()
