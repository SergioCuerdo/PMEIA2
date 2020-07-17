#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""


@author: sergio
"""
import time
import inspect
import argparse
import dns.zone
import dns.resolver
import socket
import sys
import requests
import threading
import curses
from random import randint
from datetime import date, datetime
import whois
import queue
from past.builtins import xrange
import logging
from colorama import init, Fore, Back, Style
import os

clear = lambda: os.system('clear')

url = 'https://raw.githubusercontent.com/stamparm/blackbook/master/blackbook.txt'

init()

def a_record(dominio, ficheroResultado,resolver):
	try:
		answer = resolver.query(dominio, 'A')
		for i in xrange(0, len(answer)):
			print("A [IPv4]: ", answer[i])
			ficheroResultado.write("A [IPv4]: {}\n".format(answer[i]))
	except dns.resolver.Timeout:
		logging.error(Fore.RED+'TIMEOUT superado en [A]')
		

def aaaa_record(dominio, ficheroResultado,resolver):
	try:
		answer6 = resolver.query(dominio, 'AAAA')
		for i in xrange(0, len(answer6)):
			print("AAAA [IPv6]: ", answer6[i])
			ficheroResultado.write("AAAA [IPv6]: {}\n".format(answer6[i]))
	except dns.resolver.NoAnswer as e:
		print("Exception in resolving the IPv6 Resource Record:", e)
	except dns.resolver.NoNameservers as e:
		print("Esception no nameservers AAAA SERVFAIL ", e)
	except dns.resolver.Timeout:
		logging.error(Fore.RED+'TIMEOUT superado en [AAAA]')
	

def mx_record(dominio, ficheroResultado,resolver):
	try:
		mx = resolver.query(dominio, 'MX')
		for i in xrange(0, len(mx)):
			print("MX [mail exchanger]: ", mx[i])
			ficheroResultado.write("MX [mail exchanger]: {}\n".format(mx[i]))
	except dns.resolver.NoAnswer as e:
		print("Exception in resolving the MX Resource Record:", e)
	except dns.resolver.Timeout:
		logging.error(Fore.RED+'TIMEOUT superado en [MX]')
    
        


def cname_record(dominio, ficheroResultado,resolver):
	try:
		cname_answer = resolver.query(dominio, 'CNAME')
		print("CNAME: ", cname_answer.qname)
		ficheroResultado.write("CNAME: {}\n".format(cname_answer.qname))
		for rdata in cname_answer:
			print("CNAME target address: ", rdata.target)
			ficheroResultado.write("CNAME target address: {}\n".format(rdata.target))
	except dns.resolver.NoAnswer as e:
		print('Exception retrieving CNAME', e)
	except dns.resolver.Timeout:
		logging.error(Fore.RED+'TIMEOUT superado en [CNAME] ')
	

def ns_record(dominio, ficheroResultado,resolver):
	try:
		ns_answer = resolver.query(dominio, 'NS')
		nameservers = [str(ns) for ns in ns_answer]
		servidoresns = nameservers
		print("NS: ", nameservers)
		ficheroResultado.write("NS: {}\n".format(nameservers))
	except dns.resolver.NoAnswer as e:
		print("Exception in resolving the NS Resource Record:", e)
	except dns.resolver.Timeout:
		logging.error(Fore.RED+'TIMEOUT superado en [NS] ')


def sig_record(dominio, ficheroResultado,resolver):
	try: 
		sig_answer = resolver.query(dominio, 'SIG')
		print("SIG: ", sig_answer)
		ficheroResultado.write("SIG: {}\n".format(sig_answer))
	except dns.resolver.NoAnswer as e:
		print('Exception retrieving SIG', e)
	except dns.resolver.Timeout:
		logging.error(Fore.RED+'TIMEOUT superado en [SIG]')
        

def key_record(dominio, ficheroResultado,resolver):
	try: 
		key_answer = resolver.query(dominio, 'KEY')
		print("KEY: ", key_answer)
		ficheroResultado.write("KEY: {}\n".format(key))
	except dns.resolver.NoAnswer as e:
		print('Exception retrieving KEY', e)
	except dns.resolver.Timeout:
		logging.error(Fore.RED+'TIMEOUT superado en [KEY] ')


def soa_record(dominio, ficheroResultado,resolver):
	try:
		soa_answer = resolver.query(dominio, 'SOA')
		print("SOA Answer: ", soa_answer[0].mname)
		ficheroResultado.write("SOA Answer: {}\n".format(soa_answer[0].mname))
		master_answer = resolver.query(soa_answer[0].mname, 'A')
		print("Master Answer: ", master_answer[0].address)
		ficheroResultado.write("Master Answer: {}\n\n".format(master_answer[0].address))
	except dns.resolver.Timeout:
		logging.error(Fore.RED+'TIMEOUT superado en [SOA]')


def dns_threads(dominio, ficheroResultado, resolver):
	procesos = []
	
	ficheroResultado.write(Fore.GREEN+"\t\t\t Domain: {}\n\n".format(dominio)+Fore.RESET)
	
	a = threading.Thread(target=a_record, args=(dominio, ficheroResultado,resolver,))
	procesos.append(a)
	a.start()
	aaaa = threading.Thread(target=aaaa_record, args=(dominio, ficheroResultado,resolver,))
	procesos.append(aaaa)
	aaaa.start()
	mx = threading.Thread(target=mx_record, args=(dominio, ficheroResultado,resolver,))
	procesos.append(mx)
	mx.start()
	cname = threading.Thread(target=cname_record, args=(dominio, ficheroResultado,resolver,))
	procesos.append(cname)
	cname.start()
	ns = threading.Thread(target=ns_record, args=(dominio, ficheroResultado,resolver,))
	procesos.append(ns)
	ns.start()
	sig = threading.Thread(target=sig_record, args=(dominio, ficheroResultado,resolver,))
	procesos.append(sig)
	sig.start()
	key = threading.Thread(target=key_record, args=(dominio, ficheroResultado,resolver,))
	procesos.append(key)
	key.start()
	soa = threading.Thread(target=soa_record, args=(dominio, ficheroResultado,resolver,))
	procesos.append(soa)
	soa.start()
	
	return procesos


def dns_analysis(dominio,ficheroResultado):
    
    resolver = dns.resolver.Resolver()
    resolver.timeout = 3
    resolver.lifetime = 3
    
    ficheroResultado.write(Fore.GREEN+"\t\t\t Domain: {}\n\n".format(dominio)+Fore.RESET)
    
    # IPv4 DNS Records
    try:
        answer = resolver.query(dominio, 'A')
        for i in xrange(0, len(answer)):
            print("A [IPv4]: ", answer[i])
            ficheroResultado.write("A [IPv4]: {}\n".format(answer[i]))
    except dns.resolver.Timeout:
        logging.error(Fore.RED+'TIMEOUT superado en [A]')
    
        # IPv6 DNS Records
    try:
        answer6 = resolver.query(dominio, 'AAAA')
        for i in xrange(0, len(answer6)):
            print("AAAA [IPv6]: ", answer6[i])
            ficheroResultado.write("AAAA [IPv6]: {}\n".format(answer6[i]))
    except dns.resolver.NoAnswer as e:
        print("Exception in resolving the IPv6 Resource Record:", e)
    except dns.resolver.NoNameservers as e:
        print("Esception no nameservers AAAA SERVFAIL ", e)
    except dns.resolver.Timeout:
        logging.error(Fore.RED+'TIMEOUT superado en [AAAA]')
    
        # MX (Mail Exchanger) Records
    try:
        mx = resolver.query(dominio, 'MX')
        for i in xrange(0, len(mx)):
            print("MX [mail exchanger]: ", mx[i])
            ficheroResultado.write("MX [mail exchanger]: {}\n".format(mx[i]))
    except dns.resolver.NoAnswer as e:
        print("Exception in resolving the MX Resource Record:", e)
    except dns.resolver.Timeout:
        logging.error(Fore.RED+'TIMEOUT superado en [MX]')
    
    try: 
        cname_answer = resolver.query(dominio, 'CNAME')
        print("CNAME: ", cname_answer.qname)
        ficheroResultado.write("CNAME: {}\n".format(cname_answer.qname))
        for rdata in cname_answer:
            print("CNAME target address: ", rdata.target)
            ficheroResultado.write("CNAME target address: {}\n".format(rdata.target))
    except dns.resolver.NoAnswer as e:
        print('Exception retrieving CNAME', e)
    except dns.resolver.Timeout:
        logging.error(Fore.RED+'TIMEOUT superado en [CNAME] ')
    
    try:
        ns_answer = resolver.query(dominio, 'NS')
        nameservers = [str(ns) for ns in ns_answer]
        servidoresns = nameservers
        print("NS: ", nameservers)
        ficheroResultado.write("NS: {}\n".format(nameservers))
    except dns.resolver.NoAnswer as e:
        print("Exception in resolving the NS Resource Record:", e)
    except dns.resolver.Timeout:
        logging.error(Fore.RED+'TIMEOUT superado en [NS] ')
    
    try: 
        sig_answer = resolver.query(dominio, 'SIG')
        print("SIG: ", sig_answer)
        ficheroResultado.write("SIG: {}\n".format(sig_answer))
    except dns.resolver.NoAnswer as e:
        print('Exception retrieving SIG', e)
    except dns.resolver.Timeout:
        logging.error(Fore.RED+'TIMEOUT superado en [SIG]')
    
    try: 
        key_answer = resolver.query(dominio, 'KEY')
        print("KEY: ", key_answer)
        ficheroResultado.write("KEY: {}\n".format(key))
    except dns.resolver.NoAnswer as e:
        print('Exception retrieving KEY', e)
    except dns.resolver.Timeout:
        logging.error(Fore.RED+'TIMEOUT superado en [KEY] ')
    
    
    try:
    
        soa_answer = resolver.query(dominio, 'SOA')
        print("SOA Answer: ", soa_answer[0].mname)
        ficheroResultado.write("SOA Answer: {}\n".format(soa_answer[0].mname))
        master_answer = resolver.query(soa_answer[0].mname, 'A')
        print("Master Answer: ", master_answer[0].address)
        ficheroResultado.write("Master Answer: {}\n\n".format(master_answer[0].address))


    except dns.resolver.Timeout:
        logging.error(Fore.RED+'TIMEOUT superado en [SOA]')
    
    input(Fore.BLUE+Back.WHITE+Style.BRIGHT+'Press enter to domains menu'+Back.RESET)
    menu_dominios(dominio,ficheroResultado)
    

def my_whois(dominio,ficheroResultado):
	whois_from_dom(dominio)
	input(Back.WHITE+Style.BRIGHT+'Press enter to domains menu'+Back.RESET)
	menu_dominios(dominio)
       

def whois_from_dom(dominio,ficheroResultado):
	
	try:
	
		res = whois.whois(dominio)
		return res
	except:
		print('No se pudo realizar el WHOIS...')
		pass
	
	
def menu_iocs(ficheroResultado):
	clear()
	init(autoreset=True)
	print('1 - Dominios')
	print('2 - Direcciones IP')
	print('3 - Hashes')
	print('4 - Volver')
	choice = input('Selecciona el tipo de IOC: ')
	if choice == '1':
		#print('Seleccionando dominios...')
		#time.sleep(1)
		dominio = input(Fore.GREEN+'Introduce dominio --example.com--'+Fore.RESET)
		menu_dominios(dominio,ficheroResultado)
		
	elif choice == '2':
		print('Seleccionando direcciones IP')
	elif choice == '3':
		print('Seleccionando hashes')
	elif choice == '4':
		menuPrincipal(ficheroResultado)
	else:
		print(Fore.RED+Back.WHITE+Style.BRIGHT+'Introduce una opción válida por favor'+Back.RESET)
		time.sleep(1)
		menu_iocs(ficheroResultado)
	
	

def get_domain_list():

	doms = []
	archivoDominios = open("dominios2.txt", "r")
	
	dominios = archivoDominios.read()
	
	for dom in dominios.splitlines():
		doms.append(dom)
	
	return doms


def menu_lista(dominios):
	
	print('Listado de dominios')
	
	indices = []
	doms = []
	
	for i, dom in enumerate(dominios):
		indices.append(str(i))
		doms.append(dom)
		print('{} - {} '.format(i, dom))
	
	diccio = dict(zip(indices, doms))
	choice = input('Selecciona dominio a través de su número')
	dominioSeleccionado = diccio.get(choice, "")
	if dominioSeleccionado == "":
		print(Fore.RED+Back.WHITE+Style.BRIGHT+'Por favor selecciona un dominio del listado'+Back.RESET)
		time.sleep(1)
		return menu_lista(doms)
	
	else:
		print('Has seleccionado el dominio - {} -'.format(dominioSeleccionado))
		return dominioSeleccionado
	
	#return dominioSeleccionado
	#print(diccio)


def menu_dominios(dominio,ficheroResultado):
	# clear()
	init(autoreset=True)
	print('Dominio seleccionado: {}'.format(dominio))
	
	print('0 - Obtener listado de dominios')
	print('1 - Analisis DNS')
	print('2 - WHOIS')	
	print('3 - Volver')	
	choice = input('Selecciona accion: ')
	if choice == '0':
		domains = get_domain_list()
		d = menu_lista(domains)
		input(Fore.BLUE+Back.WHITE+Style.BRIGHT+'Press enter to domains menu'+Back.RESET)
		menu_dominios(d,ficheroResultado)
	elif choice == '1':
		#dns_analysis(dominio, ficheroResultado)
		resolver = dns.resolver.Resolver()
		resolver.timeout = 3
		resolver.lifetime = 3
		procs = dns_threads(dominio, ficheroResultado, resolver)
		
		for p in procs:
			p.join()
		
		input(Fore.BLUE+Back.WHITE+Style.BRIGHT+'Press enter to domains menu'+Back.RESET)
		menu_dominios(dominio,ficheroResultado)
    
		
	elif choice == '2':
		print('Performing a WHOIS scan...')
		ficheroResultado.write(Fore.YELLOW+"\t\t\t WHOIS to {}\n\n".format(dominio)+Fore.RESET)
		whoisAnswer = whois_from_dom(dominio,ficheroResultado)
		print(Fore.YELLOW+'Name: {}'.format(whoisAnswer.name))
		print(Fore.YELLOW+'nameservers: {}'.format(whoisAnswer.name_servers))
		print(Fore.YELLOW+'Last updated: {}'.format(whoisAnswer.last_updated))
		
		#print(type(whoisAnswer.expiration_date))
		
		ficheroResultado.write("Name: {}\n".format(whoisAnswer.name))
		ficheroResultado.write("Nameservers: {}\n".format(whoisAnswer.name_servers))
		ficheroResultado.write("Last updated: {}\n".format(whoisAnswer.last_updated))
		
		if isinstance(whoisAnswer.creation_date, datetime) == False:
		
			if len(whoisAnswer.creation_date) > 1:
				for i,crea in enumerate(whoisAnswer.creation_date):
					print(Fore.YELLOW+'Creation date [{}]: {}'.format(i,crea))
					ficheroResultado.write('Creation date [{}]: {}\n'.format(i,crea))
			else:
				print(Fore.YELLOW+'Creation date: {}'.format(whoisAnswer.creation_date))
				ficheroResultado.write("Creation date: {}\n".format(whoisAnswer.creation_date))
				
		if isinstance(whoisAnswer.expiration_date, datetime) == False:
			
			if len(whoisAnswer.expiration_date) > 1:
				for j,expi in enumerate(whoisAnswer.expiration_date):
					print(Fore.YELLOW+'Expiration date [{}]: {}'.format(j,expi))
					ficheroResultado.write('Expiration date [{}]: {}\n'.format(j,expi))
				ficheroResultado.write('\n')
			else:
				print(Fore.YELLOW+'Expiration date: {}'.format(whoisAnswer.expiration_date))
				ficheroResultado.write("Expiration date: {}\n\n".format(whoisAnswer.expiration_date))
		else:
			
			print(Fore.YELLOW+'Creation date: {}'.format(whoisAnswer.creation_date))
			print(Fore.YELLOW+'Expiration date: {}'.format(whoisAnswer.expiration_date))
			ficheroResultado.write("Creation date: {}\n".format(whoisAnswer.creation_date))
			ficheroResultado.write("Expiration date: {}\n\n".format(whoisAnswer.expiration_date))
			#print(type(whoisAnswer.expiration_date))			
		
		input(Fore.BLUE+Back.WHITE+Style.BRIGHT+'Press enter to domains menu'+Back.RESET)
		menu_dominios(dominio,ficheroResultado)

	elif choice == '3':
		menu_iocs(ficheroResultado)
	else:
		print(Fore.RED+Back.WHITE+Style.BRIGHT+'Introduce una opción válida por favor'+Back.RESET)
		time.sleep(1)
		menu_dominios(dominio,ficheroResultado)

def menuPrincipal(ficheroResultado):
	clear()
	init(autoreset=True)
	print('1 - Inicio')
	print('2 - Seleccionar tipo de IOC')
	print('3 - Acerca de PMEIA')
	print('4 - Salir')
	choice = input('Introduce la opcion: ')
	if choice == '1':
		inicio()
	elif choice == '2':
		menu_iocs(ficheroResultado)
	elif choice == '3':
		about_pmeia()
	elif choice == '4':
		print('Hasta pronto...')
		time.sleep(1)
		exit()
	else:
		print(Fore.RED+Back.WHITE+Style.BRIGHT+'Introduce una opción válida por favor'+Back.RESET)
		time.sleep(1)
		menuPrincipal(ficheroResultado)

def inicio():
	clear()
	print('Es el inicio')
	input("Press Enteer for menu")
	menuPrincipal(ficheroResultado)

	
def about_pmeia():
	clear()
	print('Trabajo de Fin de Grado realizado por Sergio Cuerdo Miguel')
	input("Press Enteer for menu")
	menuPrincipal(ficheroResultado)


def open_project_menu(nuevo):
	indices = []
	indicesP = []
	proys = []
	clear()
	init(autoreset=True)
	print('1 - Nuevo Proyecto')
	print('2 - Abrir Proyecto Existente')
	choice = input('¿Qué desea hacer?  ')
	if choice == '1':
		nuevo = True
		n = input('Escriba el nombre del proyecto: ')
		now = datetime.now()
		nombre =  n + "_" + str(now.year) + "_" + str(now.month) + "_" + str(now.day) + ".txt"
		return nombre
	elif choice == '2':
		nuevo = False
		rutaActual = os.getcwd()
		#print(rutaActual) 
		proyectos = os.listdir(rutaActual)
		print(Fore.BLUE+'\t\t Listado de Proyectos Anteriores'+Fore.RESET)
		for i, proy in enumerate(proyectos):
			indices.append(str(i))
			proys.append(proy)
			if (proy.find('.txt') != -1) and (proy.find('_') != -1):
				indicesP.append(str(i))
				print(Fore.YELLOW+'{} - {}'.format(i, proy)+Fore.RESET)
		diccio = dict(zip(indicesP, proys))
		elige = input('Selecciona el proyecto a abrir: ')
		proyectoSeleccionado = diccio.get(elige, "")
		if proyectoSeleccionado == "":
			print(Fore.RED+Back.WHITE+Style.BRIGHT+'Por favor selecciona un proyecto del listado'+Back.RESET)
			time.sleep(1)
			return open_project_menu(nuevo)
		else:
			print('Has seleccionado el proyecto {}'.format(proyectoSeleccionado))
			return proyectoSeleccionado
			
		

if __name__ == '__main__':
	
	nuevo = False
	#n = input('Escriba el nombre del proyecto: ')
	#now = datetime.now()
	#nombre =  n + "_" + str(now.year) + "_" + str(now.month) + "_" + str(now.day) + ".txt"
	
	nombre = open_project_menu(nuevo)
	
	try:
		if nuevo == True:
			ficheroResultado = open(nombre, "w+")
		else:
			ficheroResultado = open(nombre, "a+")
		
		
	except:
		print(Fore.RED+'Error al abrir o crear fichero... ')
	
	menuPrincipal(ficheroResultado)
	ficheroResultado.close()




	
