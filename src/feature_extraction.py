import tldextract
import re
import whois
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urlencode
import socket
from datetime import datetime
import time

def extract_features(url, api_key=None):
    features = {}
    
    # URL parsing
    parsed_url = urlparse(url)
    domain_info = tldextract.extract(url)
    
    # Feature 1: length_url
    features['length_url'] = float(len(url))
    
    # Feature 2: length_hostname
    features['length_hostname'] = float(len(domain_info.domain + '.' + domain_info.suffix))
    
    # Feature 3: ip address
    try:
        ip = socket.gethostbyname(domain_info.domain + '.' + domain_info.suffix)
        features['ip'] = 1.0  # Map to 1 if IP is resolved
    except socket.gaierror:
        features['ip'] = 0.0  # Map to 0 if IP is not resolved
    
    # Feature 4-13: Count of various characters
    features['nb_dots'] = float(url.count('.'))
    features['nb_hyphens'] = float(url.count('-'))
    features['nb_at'] = float(url.count('@'))
    features['nb_qm'] = float(url.count('?'))
    features['nb_and'] = float(url.count('&'))
    features['nb_eq'] = float(url.count('='))
    features['nb_slash'] = float(url.count('/'))
    features['nb_semicolumn'] = float(url.count(';'))
    features['nb_www'] = float(url.count('www'))
    features['nb_com'] = float(url.count('.com'))
    
    # Feature 14: https_token
    features['https_token'] = 1.0 if url.startswith('https') else 0.0
    
    # Feature 15: ratio_digits_url
    features['ratio_digits_url'] = sum(c.isdigit() for c in url) / len(url) if len(url) > 0 else 0.0
    
    # Feature 16: ratio_digits_host
    features['ratio_digits_host'] = sum(c.isdigit() for c in domain_info.domain) / len(domain_info.domain) if len(domain_info.domain) > 0 else 0.0
    
    # Feature 17: tld_in_subdomain
    features['tld_in_subdomain'] = 1.0 if domain_info.suffix in domain_info.subdomain else 0.0
    
    # Feature 18: abnormal_subdomain
    features['abnormal_subdomain'] = 1.0 if re.search(r'[0-9]{5,}', domain_info.subdomain) else 0.0
    
    # Feature 19: nb_subdomains
    features['nb_subdomains'] = float(len(domain_info.subdomain.split('.'))) if domain_info.subdomain else 0.0
    
    # Feature 20: prefix_suffix
    features['prefix_suffix'] = 1.0 if re.match(r'^[a-zA-Z0-9]+[.-_][a-zAZ0-9]+$', domain_info.domain) else 0.0
    
    # Feature 21: shortening_service
    shortening_services = ['bit.ly', 'tinyurl.com', 'goo.gl']
    features['shortening_service'] = 1.0 if any(service in url for service in shortening_services) else 0.0
    
    # Feature 22-27: Word length and average calculations
    words = [word for word in re.findall(r'\w+', url)]
    features['length_words_raw'] = float(sum(len(word) for word in words))
    features['shortest_word_host'] = float(len(min(words, key=len))) if words else 0.0
    features['longest_words_raw'] = float(len(max(words, key=len))) if words else 0.0
    
    host_words = [word for word in re.findall(r'\w+', domain_info.domain)]
    features['longest_word_host'] = float(len(max(host_words, key=len))) if host_words else 0.0
    
    path_words = [word for word in re.findall(r'\w+', parsed_url.path)]
    features['longest_word_path'] = float(len(max(path_words, key=len))) if path_words else 0.0
    
    features['avg_words_raw'] = sum(len(word) for word in words) / len(words) if words else 0.0
    features['avg_word_host'] = sum(len(word) for word in host_words) / len(host_words) if host_words else 0.0
    features['avg_word_path'] = sum(len(word) for word in path_words) / len(path_words) if path_words else 0.0
    
    # Feature 28: phish_hints (Placeholder for phishing hints - simple heuristic)
    def phish_hints(url_path):
        count = 0
        HINTS = ["login", "secure", "account", "update", "signin", "bank", "confirm", "password", "verify"]
        for hint in HINTS:
            count += url_path.lower().count(hint)
        return count
    
    features['phish_hints'] = phish_hints(url)
    
    # Feature 29: suspecious_tld
    suspicious_tlds = ['xyz', 'top', 'club', 'win']
    features['suspecious_tld'] = 1.0 if domain_info.suffix in suspicious_tlds else 0.0
    
    # Feature 30: statistical_report (Placeholder for statistical analysis - dummy data)
    features['statistical_report'] = 0.0  # Placeholder for statistical analysis
    
    # Web scraping features
    response = None  # Initialize response variable
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Feature 31: nb_hyperlinks
        features['nb_hyperlinks'] = float(len(soup.find_all('a')))
        
        # Feature 32: ratio_intHyperlinks
        internal_links = [link for link in soup.find_all('a', href=True) if domain_info.domain in link['href']]
        features['ratio_intHyperlinks'] = len(internal_links) / len(soup.find_all('a')) if len(soup.find_all('a')) > 0 else 0.0
        
        # Feature 33: ratio_extRedirection (External redirection links)
        external_links = [link for link in soup.find_all('a', href=True) if domain_info.domain not in link['href']]
        features['ratio_extRedirection'] = len(external_links) / len(soup.find_all('a')) if len(soup.find_all('a')) > 0 else 0.0
        
        # Feature 34: external_favicon
        features['external_favicon'] = 1.0 if soup.find('link', rel='icon') and domain_info.domain not in soup.find('link', rel='icon')['href'] else 0.0
        
        # Feature 35: links_in_tags
        features['links_in_tags'] = 1.0 if soup.find_all('a') else 0.0
        
        # Feature 36: ratio_intMedia (Internal media)
        media_links = [media for media in soup.find_all(['img', 'script', 'link'], src=True) if domain_info.domain in media['src']]
        features['ratio_intMedia'] = len(media_links) / len(soup.find_all(['img', 'script', 'link'])) if len(soup.find_all(['img', 'script', 'link'])) > 0 else 0.0
        
        # Feature 37: ratio_extMedia (External media)
        external_media_links = [media for media in soup.find_all(['img', 'script', 'link'], src=True) if domain_info.domain not in media['src']]
        features['ratio_extMedia'] = len(external_media_links) / len(soup.find_all(['img', 'script', 'link'])) if len(soup.find_all(['img', 'script', 'link'])) > 0 else 0.0
        
        # Feature 38: safe_anchor
        safe_anchors = [anchor for anchor in soup.find_all('a', href=True) if 'javascript:' not in anchor['href']]
        features['safe_anchor'] = 1.0 if safe_anchors else 0.0
        
        # Feature 39: empty_title
        features['empty_title'] = 1.0 if not soup.title else 0.0
        
        # Feature 40: domain_in_title
        features['domain_in_title'] = 1.0 if domain_info.domain in (soup.title.string if soup.title else '') else 0.0
        
        # Feature 41: domain_with_copyright
        features['domain_with_copyright'] = 1.0 if '©' in (soup.find('meta', {'name': 'copyright'})['content'] if soup.find('meta', {'name': 'copyright'}) else '') else 0.0
        
    except requests.exceptions.RequestException:
        # Handle case when the URL cannot be accessed
        features['nb_hyperlinks'] = 0.0
        features['ratio_intHyperlinks'] = 0.0
        features['ratio_extRedirection'] = 0.0
        features['external_favicon'] = 0.0
        features['links_in_tags'] = 0.0
        features['ratio_intMedia'] = 0.0
        features['ratio_extMedia'] = 0.0
        features['safe_anchor'] = 0.0
        features['empty_title'] = 1.0
        features['domain_in_title'] = 0.0
        features['domain_with_copyright'] = 0.0
    
    # Feature 42: domain_registration_length
    try:
        domain_info_whois = whois.whois(url)
        features['domain_registration_length'] = (datetime.now() - domain_info_whois.creation_date).days if domain_info_whois.creation_date else 0.0
    except Exception:
        features['domain_registration_length'] = 0.0
    
    # Feature 43: domain_age
    try:
        features['domain_age'] = (datetime.now() - domain_info_whois.creation_date).days if domain_info_whois.creation_date else 0.0
    except Exception:
        features['domain_age'] = 0.0

    # Feature 44: dns_record
    try:
        dns_info = socket.getaddrinfo(domain_info.domain, None)
        features['dns_record'] = 1.0 if dns_info else 0.0
    except socket.gaierror:
        features['dns_record'] = 0.0
    
    # Feature 45: google_index 
    def google_index(url):
        time.sleep(0.6)  # To avoid rapid requests
        user_agent = 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/48.0.2564.116 Safari/537.36'
        headers = {'User-Agent': user_agent}
        query = {'q': 'site:' + url}
        google = "https://www.google.com/search?" + urlencode(query)
        data = requests.get(google, headers=headers)
        data.encoding = 'ISO-8859-1'
        soup = BeautifulSoup(str(data.content), "html.parser")
        try:
            if 'Our systems have detected unusual traffic from your computer network.' in str(soup):
                return -1
            check = soup.find(id="rso").find("div").find("div").find("a")
            if check and check['href']:
                return 0
            else:
                return 1
        except AttributeError:
            return 1
    
    features['google_index'] = google_index(url)
    
    # Feature 46: page_rank 
    def page_rank(key, domain):
        url = f'https://openpagerank.com/api/v1.0/getPageRank?domains%5B0%5D={domain}'
        try:
            request = requests.get(url, headers={'API-OPR': key})
            result = request.json()
            return result['response'][0].get('page_rank_integer', 0)  # return 0 if not found
        except:
            return -1  # return -1 on error
    
    features['page_rank'] = page_rank(api_key, domain_info.domain) if api_key else -1
    
    
    return features
    

