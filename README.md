# showmap.py
Procesa el normal output (-oN) de nmap y muestra la información en formato de tabla, también permite aplicar filtros de búsqueda y exportar la información en formato CSV.

## Uso
```python
python showmap.py -i [archivo_nmap] 
```

##### Opciones:
```
 	-i      Archivo de entrada con el output de Nmap.
 	-s      Aplica filtros de busqueda.
 	-csv    Exporta la salida en formato CSV.
```

## Instalación


```
  git pull https://github.com/fedeScripts/showmap.py.git
  cd showmap.py 
  python showmap.py
```

## To Do
Implementar las siguientes funcionalidades
```
	-u	  Imprimir los puertos http en formato url -> http://10.0.0.1:80.
	-vuln	  Imprimir un resumen de las vulnerabilidades reportadas por Nmap.
```

## Autor
- Federico Galarza  - [@fedeScripts](https://github.com/fedeScripts) 

[![linkedin](https://img.shields.io/badge/linkedin-0A66C2?style=for-the-badge&logo=linkedin&logoColor=white)](https://www.linkedin.com/in/federico-galarza)
