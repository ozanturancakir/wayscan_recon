#!/usr/bin/env python3
"""
Wayscan - Wayback-based passive recon (V1.4 - Expanded XSS Logic)
"""
import argparse
import os
import requests
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
import pyfiglet
from termcolor import colored

# --- Config (Aynı) ---
CDX_API = "https://web.archive.org/cdx/search/cdx" 
USER_AGENT = "Wayscan/1.4 (Wider Recon Logic)" 
REQUEST_TIMEOUT = 60.0 

# Parametre kümeleri
OPEN_REDIRECT_PARAMS = {
    "go","return","r_url","returnurl","returnuri","locationurl","goto","return_url","return_uri",
    "ref","referrer","backurl","returnto","successurl","redirect","redirect_url","redirecturi",
    "url","next","target","site","page","returnUrl","returnUri","r_Url","locationUrl","return_Url""return_Uri","redirect_Url""redirectUri","redirectUrl","redirect_uri"
}

# GENİŞLETİLMİŞ XSS PARAMETRE LİSTESİ
# Popüler arama/mesaj parametrelerine ek olarak, kullanıcı girdisi taşıyabilecek 
# ID'ler, değerler ve mesaj alanları eklendi.
XSS_PARAMS = {
    "search","q","query","s","term","keyword","keywords","text","msg","message","title","body",
    "id", "itemid", "catid", "post_id", "page_id", "user_id", "uid", "pid", # ID'ler
    "name", "value", "data", "input", "output", "format", "mode", "type",  # Genel Girdiler
    "html", "content", "view", "section", "comment", "lang", "locale"       # İçerik/Format
}

# Uzantı haritası (Aynı)
EXT_MAP = {
    ".json": "json",
    ".js": "js",
    ".php": "php"
}

def banner():
    text = pyfiglet.figlet_format("Wayscan", font="slant")
    print(colored(text, 'cyan')) 
    print("           Passive Recon & URL Analyzer")
    print(colored("                       Ozan Turan Çakır", 'yellow') + "\n")

def mkdir_p(path):
    os.makedirs(path, exist_ok=True)

def fetch_wayback_urls(target, include_subdomains=False, limit=None):
    """Wayback Machine CDX API'den URL'leri çeker."""
    
    url_pattern = f"{target}/*" if not include_subdomains else f"*.{target}/*"
    
    params = {
        "url": url_pattern,
        "output": "json",
        "fl": "original",
        # "filter": "statuscode:200",  # Geniş sonuçlar için 200 filtresi kaldırıldı
        "collapse": "urlkey" 
    }
    if limit:
        params["limit"] = str(limit)
        
    headers = {"User-Agent": USER_AGENT}
    
    print(f"[*] API Query: {CDX_API}?url={url_pattern}...")

    try:
        r = requests.get(CDX_API, params=params, headers=headers, timeout=REQUEST_TIMEOUT)
        r.raise_for_status() 
    except requests.exceptions.Timeout as e:
        print(f"[!] CDX request FAILED: Connection timed out after {REQUEST_TIMEOUT}s.")
        print("[!] Target may be too large. Try running with the --limit <number> flag.")
        return []
    except requests.exceptions.RequestException as e:
        print(f"[!] CDX request FAILED: {e}")
        return []

    try:
        data = r.json()
        if not data:
             print("[!] CDX returned an empty list.")
             return []
        
        if data and isinstance(data[0], list):
             if data[0][0] == "original":
                 urls = [row[0] for row in data[1:]]
             else:
                 urls = [row[0] for row in data]
        else:
             urls = [str(item) for item in data if item != "original"] 

    except ValueError:
        urls = [line.strip() for line in r.text.splitlines() if line.strip()]
        
    seen = set()
    uniq = []
    for u in urls:
        if u and u not in seen:
            seen.add(u)
            uniq.append(u)
            
    return uniq

def parse_query_params(url):
    """URL'deki sorgu parametrelerini (küçük harf) sözlük olarak döndürür."""
    parsed = urllib.parse.urlparse(url)
    q = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    return {k.lower(): v for k, v in q.items()}

def check_alive(url, method="head"):
    headers = {"User-Agent": USER_AGENT}
    try:
        if method.lower() == "head":
            r = requests.head(url, allow_redirects=True, timeout=REQUEST_TIMEOUT, headers=headers)
        else:
            r = requests.get(url, allow_redirects=True, timeout=REQUEST_TIMEOUT, headers=headers)
        return r.status_code
    except Exception:
        return None

def write_list(path, items):
    with open(path, "w", encoding="utf-8") as f:
        for it in items:
            f.write(it.rstrip() + "\n")

def dedup_preserve(items):
    seen = set(); out = []
    for x in items:
        if x not in seen:
            seen.add(x); out.append(x)
    return out

def main():
    banner()
    
    parser = argparse.ArgumentParser(description="WAYSAN - Passive Recon")
    parser.add_argument("target", help="Hedef domain (örn: example.com)")
    parser.add_argument("--include-subdomains", help="Subdomainleri dahil et", action="store_true")
    parser.add_argument("--alive200", help="Status:200 olanları listele (Aktif kontrol yapar!)", action="store_true")
    parser.add_argument("--threads", help="Default 20",type=int, default=20)
    parser.add_argument("--outdir", help="Default kayıt dizini wayscan_output",default="wayscan_output")
    parser.add_argument("--limit", type=int, default=None, help="Wayback'ten çekilecek maksimum URL sayısı (Büyük hedefler için önerilir!)") 
    args = parser.parse_args()

    target = args.target.strip()
    outdir = args.outdir
    mkdir_p(outdir)

    print(f"[+] Target: {target}")
    print("[*] Fetching Wayback URLs (collapse=urlkey)...")
    
    urls = fetch_wayback_urls(target, include_subdomains=args.include_subdomains, limit=args.limit)
    
    if not urls:
        print("[!] No URLs collected. Exiting.")
        return

    print(f"[+] Collected {len(urls)} unique URLs")

    json_list = []
    js_list = []
    php_list = []
    openredirect_list = []
    xss_list = []

    for u in urls:
        parsed_url = urllib.parse.urlparse(u)
        lower_path = parsed_url.path.lower()
        
        for ext, name in EXT_MAP.items():
            if lower_path.endswith(ext):
                if name == "json": json_list.append(u)
                elif name == "js": js_list.append(u)
                elif name == "php": php_list.append(u)
                break
                
        params = parse_query_params(u)
        
        if params:
            keys = set(params.keys())
            
            # 1. Open Redirect Kontrolü (Geniş Mantık: Herhangi bir parametre varsa)
            if keys & OPEN_REDIRECT_PARAMS: 
            	openredirect_list.append(u) 
            
            # 2. XSS Kontrolü (Genişletilmiş Anahtar Kelime Mantığı)
            if keys & XSS_PARAMS: # <-- GENİŞLETİLMİŞ XSS_PARAMS listesiyle kontrol eder
                xss_list.append(u)


    json_list = dedup_preserve(json_list)
    js_list = dedup_preserve(js_list)
    php_list = dedup_preserve(php_list)
    openredirect_list = dedup_preserve(openredirect_list) 
    xss_list = dedup_preserve(xss_list)

    base = target
    paths = {
        "json": os.path.join(outdir, f"{base}_json.txt"),
        "js": os.path.join(outdir, f"{base}_js.txt"),
        "php": os.path.join(outdir, f"{base}_php.txt"),
        "openredirect": os.path.join(outdir, f"{base}_openredirect.txt"),
        "xss": os.path.join(outdir, f"{base}_xss.txt"),
        "alive200": os.path.join(outdir, f"{base}_alive200.txt")
    }

    write_list(paths["json"], json_list)
    write_list(paths["js"], js_list)
    write_list(paths["php"], php_list)
    write_list(paths["openredirect"], openredirect_list)
    write_list(paths["xss"], xss_list)

    all_urls_path = os.path.join(outdir, f"{base}_all_urls.txt")
    write_list(all_urls_path, urls) 

    print(f"[+] .json         : {len(json_list):<5} JSON URLs  -> {paths['json']}")
    print(f"[+] .js           : {len(js_list):<5} JS URLs    -> {paths['js']}")
    print(f"[+] .php          : {len(php_list):<5} PHP URLs   -> {paths['php']}")
# O.Red için daha uzun bir alana ihtiyacımız var
    print(f"[+] OpenRedirect  : {len(openredirect_list):<5} O.Red URLs -> {paths['openredirect']}")
    print(f"[+] XSS           : {len(xss_list):<5} XSS URLs   -> {paths['xss']}")
    print(f"[+] Total         : {len(urls):<5} ALL URLs   -> {all_urls_path}")

    if args.alive200:
        print(f"\n[*] Running alive200 checks with {args.threads} threads (Active checks - may take a while)...")
        alive200 = []
        with ThreadPoolExecutor(max_workers=max(4, args.threads)) as ex:
            futures = {ex.submit(check_alive, u): u for u in urls}
            for i, fut in enumerate(as_completed(futures)):
                u = futures[fut]
                status = fut.result()
                if status == 200:
                    alive200.append(u)
                if (i + 1) % 100 == 0 or (i + 1) == len(urls):
                    print(f"\r[*] Progress: {i + 1}/{len(urls)} checked, {len(alive200)} alive", end="", flush=True)

        alive200 = dedup_preserve(alive200)
        write_list(paths["alive200"], alive200)
        print(f"\n[+] Wrote: {len(alive200):<5} ALIVE (Status 200) URLs -> {paths['alive200']}")

    print("\n[+] Done. All category files produced in the output directory.")

if __name__ == "__main__":
    main()
