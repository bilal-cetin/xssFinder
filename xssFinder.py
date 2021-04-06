import requests
from urllib.request import urlparse, urljoin
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from pprint import pprint



headers = requests.utils.default_headers()
headers.update({ 'User-Agent': 'Mozilla/5.0 (Windows NT 6.3; Win64; x64; rv:72.0) Gecko/20100101 Firefox/72.0'})

#Global variables initialize the set of links(unique links)

internal_urls = set()
external_urls = set()

# Not all 'a' tags are valid some of them might be javascript
# Checking url is a valid URL

def is_valid (url):

    parsed = urlparse(url)

    return bool(parsed.netloc) and bool(parsed.scheme)

#Returns all URLs that is found on `url` in which it belongs to the same website

def get_all_website_links(url):
    

    urls = set ()

    #domain name of the URL without the protocol
    domain_name = urlparse(url).netloc

    req = requests.get(url)

    soup = BeautifulSoup(req.content, "html.parser")

    for a_tag in soup.find_all("a"):

        href = a_tag.attrs.get("href")

        if href == "" or href is None:

            # href empty tag

            continue
        # join the URL if it's relative (not absolute link)
        
        href = urljoin(url, href)

        # remove unnecessary things in url (parameters,fragments, etc.)

        parsed_href = urlparse(href)

        href = parsed_href.scheme + "://" + parsed_href.netloc + parsed_href.path

        if not is_valid(href):
            # not a valid URL 
            continue
        if href in internal_urls:
            # already in the set
            continue

        

        urls.add(href)

        internal_urls.add(href)

    return urls

        

def get_all_forms(url):

    soup = BeautifulSoup(requests.get(url).content, "html.parser")

    form = soup.find_all("form")
    return form

def get_form_details(form):
    #This function extracts all possible useful information about an HTML `form`  (actions, methods, inputs)

    details = {}

    action = form.attrs.get("action").lower()

    method = form.attrs.get("method","get").lower()

    inputs = []
    for input_tag in form.find_all("input"):
        input_type = input_tag.attrs.get("type","text")
        input_name = input_tag.attrs.get("name")

        inputs.append({"type":input_type, "name":input_name})

    # put everything to the resulting dictionary
    details["action"] = action
    details["method"] = method
    details["inputs"] = inputs

    return details

#After we got the form details , we need another function to submit any given form

def submit_form(form_details, url, value):

    target_url = urljoin(url, form_details["action"])

    inputs = form_details["inputs"]

    data = {}

    for input in inputs:
        # raplace all text and search values with 'value'

        if input["type"] == "text" or input["type"] == "search":
            input["value"] = value

        input_name = input.get("name")
        input_value = input.get("value")

        if input_name and input_value:
            # if input name and value are not none then add them to the data of form submission
            data[input_name] = input_value
    
    if form_details["method"] == "post":

        return requests.post(target_url, data=data)

    else:
        # GET request
        return requests.get(target_url, params=data)

        
def scan_xss(url):

    #get all the forms from the URL
    forms = get_all_forms(url)
    

    print(f"[+] Detected {len(forms)} forms on {url}.")
    characters = [' pre" ' , " pre' " , "pre<" , "pre>"] 

    # returning value
    is_vulnerable = False

    # iterate over all forms
    for form in forms:

        form_details = get_form_details(form)
        
        
        for char in characters:
        
            content = submit_form(form_details, url, char).content.decode()
            unencoded_chars = []
            if char in content:
                unencoded_chars = char

        print("XSS detected on {url}.")

        print("Form details:")

        pprint(form_details)

        pprint("Unencoded Characters: "+unencoded_chars.replace("pre", ""))

        is_vulnerable = True

                # won t break because we want to print available vulnerable forms

    return is_vulnerable







if __name__ == "__main__":

  
    urls = get_all_website_links("https://xss-game.appspot.com/level1/frame")
    for url in urls:
        print(scan_xss(url))
    