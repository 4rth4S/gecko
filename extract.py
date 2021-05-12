#!/usr/bin/env python3
#_*_ coding: utf8 _*_

# Recibe un texto extrae IOC.. ver https://github.com/renzejongman/iocparser
# Envia a un archivo e invoca metodos que hacen la llamadas a APIs de las soluciones.
# Notas: Optimizar código.


from iocparser import IOCParser
import json
import os.path
#import trend   
from keys import misp_url, misp_key, misp_verifycert
from pymisp import PyMISP
from pymisp import MISPEvent, MISPAttribute


def init(url, key):
    return PyMISP(url, key, misp_verifycert, 'json')

misp = init(misp_url, misp_key)

def create_event(misp):
    event = MISPEvent()
    event.info = 'Evento creado por el BOT d telegram'
    event = misp.add_event(event, pythonify=True)
    return event


def _attribute(category, type, value):
    attribute = MISPAttribute()
    attribute.category = category
    attribute.type = type
    attribute.value = value
    return attribute


def cargar_IOC_MISP(misp, event , results , categoria, tipo):
    for res in results:
        misp.add_attribute(event, _attribute(categoria, tipo, res.value))
    misp.publish(event)
    return None

def extraer(texto, categoria, tipo):    
    extObj = IOCParser(texto)
    results = eliminar_duplicados(extObj.parse())
    results = eliminar_dominios_ips_privadas(results)
    event = create_event(misp)
    cargar_IOC_MISP(misp, event, results, categoria, tipo)
    mostrarResultados(results)
    return results
    
def buscar(texto):    
    extObj = IOCParser(texto)
    results = eliminar_duplicados(extObj.parse())
    results = limpiar(results)
    results = eliminar_dominios_ips_privadas(results)
    if (len(results)==0):
        return ''
    else:
        return generar_salida(results)

def contar(texto):    
    extObj = IOCParser(texto)
    results = eliminar_duplicados(extObj.parse())
    results = limpiar(results)
    results = eliminar_dominios_ips_privadas(results)
    return len(results)
     
def mostrarResultados(results):
    for res in results:
        print(res.kind + ":" + res.value)

def eliminar_duplicados(results):
    results_noduplicate = []
    for r in results:
        if (isInList(r.value,results_noduplicate)==False):
            results_noduplicate.append(r)
    return results_noduplicate

def isInList(value,results):
    for r in results:
        if(r.value == value):
           return True
    return False

def limpiar(results):
    results_util=[]
    for res in results:
        if(res.kind=='IP' or res.kind=='sha256' or res.kind=='uri' or res.kind=='md5'):
            results_util.append(res)
    return results_util

def generar_salida(results):
    sha = []
    ips = []
    URL = []
    md5 = []

    for res in results:
        if(res.kind=='IP'):
            ips.append(res)
        if(res.kind=='sha256'):
            sha.append(res)
        if(res.kind=='uri'):
            URL.append(res)
        if(res.kind=='md5'):
            md5.append(res)
    return listToString(ips) + listToString(sha) + listToString(URL) + listToString(md5)

def listToString(s):  
    
    # initialize an empty string 
    str1 = ""  
    
    # traverse in the string   
    for ele in s:  
        str1 += ele.kind + " : " + ele.value +"\n" 
    
    # return string   
    return str1  

def eliminar_dominios_ips_privadas(results):
    results_seguro = []
    for r in results:
        if (isPrivado(r)==False):
                results_seguro.append(r)
    return results_seguro


def isPrivado(r):
    ip_privados = ['192.168.','10.','0.0.0.0','127.0.0.1','172.16.','172.17.','172.18.','172.19.','172.20.','172.21.','172.22.','172.23.', 
        '172.24.','172.25.''172.26.','172.27.','172.28.','172.29.','172.30.','172.31.']
    dominios_privados = ['mycompany.com','myfriendcompany.com']

    if (r.kind=='IP'):
        for ip in ip_privados:
            if(r.value.startswith(ip)):
                return True
    
    if (r.kind=='uri'):
        for domain in dominios_privados:
            if(domain in r.value):
                return True
    return False
