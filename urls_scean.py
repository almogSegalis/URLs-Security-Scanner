#!/usr/bin/env python
import requests
import json
from datetime import datetime
import pandas as pd
import argparse
import validators
import os.path

def check_header(response_headers):
            counter = 0
            msg = []
            if 'Content-security-policy' in response_headers:
                counter+=1
                msg = ["(V) Content-security-policy"]

            if 'X-Frame-Options' in response_headers:
                if 'X-Frame-Options' == 'strict-origin-when-cross-origin':
                    counter+=1
                    msg += ['(V) X-Frame-Options']
                    
            if 'Referrer-Policy' in response_headers:
                if 'Referrer-Policy' == 'strict-origin-when-cross-origin':
                    counter+=1
                    msg += ['(V) Referrer-Policy']

            if 'X-Content-Type-Options' in response_headers:
                counter+=1
                msg += ['(V) X-Content-Type-Options']

            if 'Permissions-Policy' in response_headers:
                counter+=1
                msg += ['(V) Permissions-Policy']
            
            return counter, msg

def check_if_url(input):
    url = input.split(' ',1)[0]
    if validators.url(url):
        return True
    else:
        return False
        
def get_url_by_asking():
    while True:
        user_input = input("Please enter a url or a file path: ")
        if check_if_url(user_input):
            urls_to_scan = user_input.split(' ')
            break
        
        elif os.path.isfile(user_input):
            with open(user_input, mode='r') as file:
                urls_to_scan = []
                for line in file:
                    urls_to_scan += [line.strip('\n')]
            break
        else:
            print('Please enter a valid url or a file path')
            continue
    return urls_to_scan


# Create a parser
parser = argparse.ArgumentParser()

parser.add_argument('--url', type=str)

args = parser.parse_args()

if args.url:
    if check_if_url(str(args.url)):
        urls = args.url
        urls_to_scan = urls.split(' ')
    else:
        urls_to_scan = ""
        get_url_by_asking()
else:
    urls_to_scan = get_url_by_asking()


def create_files(urls_to_scan):
    info_dict = {}
    urls=[]
    scores = []
    msgs =[]

    for url in urls_to_scan:
        if validators.url(str(url)):
            urls+= [url]

        # A GET request to the API
            response = requests.get(str(url))

            response_headers = response.headers

            counter, msg = check_header(response_headers)
            scores += [counter]
            msgs += [msg]
        
            info_dict['url'] = urls
            info_dict['security score'] = scores
            info_dict['reason'] = msgs
            info_dict['time'] = datetime.now().strftime("%d/%m/%Y %H:%M:%S")

            df = pd.DataFrame(info_dict)
            df.to_csv('output_file.csv')

            with open('output.json', mode='w') as file:
                json.dump(info_dict, file)

create_files(urls_to_scan)
