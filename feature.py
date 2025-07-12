import ipaddress
import re
import urllib.request
from bs4 import BeautifulSoup
import socket
import requests
from googlesearch import search
import whois
from datetime import date, datetime
import time
from dateutil.parser import parse as date_parse
from urllib.parse import urlparse

class FeatureExtraction:
    features = []

    def __init__(self, url):
        self.features = []
        self.url = url
        self.domain = ""
        self.whois_response = ""
        self.urlparse = ""
        self.response = ""
        self.soup = ""

        try:
            self.response = requests.get(url)
            self.soup = BeautifulSoup(self.response.text, 'html.parser')
        except:
            pass

        try:
            self.urlparse = urlparse(url)
            self.domain = self.urlparse.netloc
        except:
            pass

        try:
            self.whois_response = whois.whois(self.domain)
        except:
            pass

        self.features.append(self.usingIp())
        self.features.append(self.longUrl())
        self.features.append(self.shortUrl())
        self.features.append(self.symbol())
        self.features.append(self.redirecting())
        self.features.append(self.prefixSuffix())
        self.features.append(self.SubDomains())
        self.features.append(self.Hppts())
        self.features.append(self.DomainRegLen())
        self.features.append(self.Favicon())
        self.features.append(self.NonStdPort())
        self.features.append(self.HTTPSDomainURL())
        self.features.append(self.RequestURL())
        self.features.append(self.AnchorURL())
        self.features.append(self.LinksInScriptTags())
        self.features.append(self.ServerFormHandler())
        self.features.append(self.InfoEmail())
        self.features.append(self.AbnormalURL())
        self.features.append(self.WebsiteForwarding())
        self.features.append(self.StatusBarCust())
        self.features.append(self.DisableRightClick())
        self.features.append(self.UsingPopupWindow())
        self.features.append(self.IframeRedirection())
        self.features.append(self.AgeofDomain())
        self.features.append(self.DNSRecording())
        self.features.append(self.WebsiteTraffic())
        self.features.append(self.PageRank())
        self.features.append(self.GoogleIndex())
        self.features.append(self.LinksPointingToPage())
        self.features.append(self.StatsReport())

    def usingIp(self):
        try:
            ipaddress.ip_address(self.url)
            return -1
        except:
            return 1

    def longUrl(self):
        try:
            if len(self.url) < 54:
                return 1
            elif len(self.url) >= 54 and len(self.url) <= 75:
                return 0
            else:
                return -1
        except:
            return -1

    def shortUrl(self):
        try:
            match = re.search(r'(bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs)', self.url)
            return -1 if match else 1
        except:
            return -1

    def symbol(self):
        return -1 if "@" in self.url else 1

    def redirecting(self):
        return -1 if self.url.rfind('//') > 6 else 1

    def prefixSuffix(self):
        try:
            return -1 if '-' in self.domain else 1
        except:
            return -1

    def SubDomains(self):
        try:
            dot_count = self.url.count('.')
            if dot_count == 1:
                return 1
            elif dot_count == 2:
                return 0
            else:
                return -1
        except:
            return -1

    def Hppts(self):
        try:
            return 1 if 'https' in self.urlparse.scheme else -1
        except:
            return 1

    def DomainRegLen(self):
        try:
            expiration_date = self.whois_response.expiration_date
            creation_date = self.whois_response.creation_date
            if isinstance(expiration_date, list):
                expiration_date = expiration_date[0]
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            age = (expiration_date.year - creation_date.year) * 12 + (expiration_date.month - creation_date.month)
            return 1 if age >= 12 else -1
        except:
            return -1

    def Favicon(self):
        try:
            for link in self.soup.find_all('link', href=True):
                if self.url in link['href'] or self.domain in link['href']:
                    return 1
            return -1
        except:
            return -1

    def NonStdPort(self):
        return -1 if ':' in self.domain else 1

    def HTTPSDomainURL(self):
        return -1 if 'https' in self.domain else 1

    def RequestURL(self):
        try:
            i, success = 0, 0
            for tag in ['img', 'audio', 'embed', 'iframe']:
                for resource in self.soup.find_all(tag, src=True):
                    if self.url in resource['src'] or self.domain in resource['src']:
                        success += 1
                    i += 1
            percentage = (success / i) * 100 if i > 0 else 0
            if percentage < 22.0:
                return 1
            elif 22.0 <= percentage < 61.0:
                return 0
            else:
                return -1
        except:
            return -1

    def AnchorURL(self):
        try:
            i, unsafe = 0, 0
            for a in self.soup.find_all('a', href=True):
                if '#' in a['href'] or 'javascript' in a['href'].lower() or 'mailto' in a['href'].lower():
                    unsafe += 1
                elif self.url not in a['href'] and self.domain not in a['href']:
                    unsafe += 1
                i += 1
            percentage = (unsafe / i) * 100 if i > 0 else 0
            if percentage < 31.0:
                return 1
            elif 31.0 <= percentage < 67.0:
                return 0
            else:
                return -1
        except:
            return -1

    def LinksInScriptTags(self):
        try:
            i, success = 0, 0
            for tag in ['link', 'script']:
                for resource in self.soup.find_all(tag, src=True if tag == 'script' else 'href'):
                    if self.url in resource.get('src', '') or self.domain in resource.get('src', ''):
                        success += 1
                    i += 1
            percentage = (success / i) * 100 if i > 0 else 0
            if percentage < 17.0:
                return 1
            elif 17.0 <= percentage < 81.0:
                return 0
            else:
                return -1
        except:
            return -1

    def ServerFormHandler(self):
        try:
            forms = self.soup.find_all('form', action=True)
            if not forms:
                return 1
            for form in forms:
                action = form['action']
                if action in ["", "about:blank"]:
                    return -1
                elif self.url not in action and self.domain not in action:
                    return 0
            return 1
        except:
            return -1

    def InfoEmail(self):
        try:
            return -1 if re.findall(r"[mail\(\)|mailto:?]", self.soup.text) else 1
        except:
            return -1

    def AbnormalURL(self):
        try:
            return 1 if self.domain in self.url else -1
        except:
            return -1

    def WebsiteForwarding(self):
        try:
            length = len(self.response.history)
            if length <= 1:
                return 1
            elif length <= 4:
                return 0
            else:
                return -1
        except:
            return -1

    def StatusBarCust(self):
        try:
            return 1 if re.findall("<script>.+onmouseover.+</script>", self.response.text) else -1
        except:
            return -1

    def DisableRightClick(self):
        try:
            return 1 if re.findall(r"event.button ?== ?2", self.response.text) else -1
        except:
            return -1

    def UsingPopupWindow(self):
        try:
            return 1 if re.findall(r"alert\\(", self.response.text) else -1
        except:
            return -1

    def IframeRedirection(self):
        try:
            return 1 if re.findall(r"<iframe>|<frameBorder>", self.response.text) else -1
        except:
            return -1

    def AgeofDomain(self):
        try:
            creation_date = self.whois_response.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            today = date.today()
            age = (today.year - creation_date.year) * 12 + (today.month - creation_date.month)
            return 1 if age >= 6 else -1
        except:
            return -1

    def DNSRecording(self):
        return self.AgeofDomain()

    def WebsiteTraffic(self):
        try:
            rank = BeautifulSoup(urllib.request.urlopen("http://data.alexa.com/data?cli=10&dat=s&url=" + self.url).read(), "xml").find("REACH")["RANK"]
            return 1 if int(rank) < 100000 else 0
        except:
            return -1

    def PageRank(self):
        try:
            response = requests.post("https://www.checkpagerank.net/index.php", {"name": self.domain})
            rank = int(re.findall("Global Rank: ([0-9]+)", response.text)[0])
            return 1 if 0 < rank < 100000 else -1
        except:
            return -1

    def GoogleIndex(self):
        try:
            return 1 if list(search(self.url, num_results=1)) else -1
        except:
            return 1

    def LinksPointingToPage(self):
        try:
            links = len(re.findall(r"<a href=", self.response.text))
            if links == 0:
                return 1
            elif links <= 2:
                return 0
            else:
                return -1
        except:
            return -1

    def StatsReport(self):
        try:
            url_match = re.search(r'at\\.ua|usa\\.cc|baltazarpresentes\\.com\\.br|pe\\.hu|esy\\.es|hol\\.es|sweddy\\.com|myjino\\.ru|96\\.lt|ow\\.ly', self.url)
            ip_address = socket.gethostbyname(self.domain)
            ip_match = re.search(r'146\\.112\\.61\\.108|213\\.174\\.157\\.151|121\\.50\\.168\\.88|192\\.185\\.217\\.116', ip_address)
            return -1 if url_match or ip_match else 1
        except:
            return 1

    def getFeaturesList(self):
        return self.features
