#!/usr/bin/env python
import requests
import json
from datetime import datetime
import pandas as pd
import argparse
import validators
import os.path

# Calculate the security score and add messages according to the headers
def check_header(response_headers):
    score = 0
    msg = []
    if 'Content-security-policy' in response_headers:
        score+=1
        msg += ["(V) Content-security-policy"]

    if 'X-Frame-Options' in response_headers:
        if response_headers['X-Frame-Options'] == 'strict-origin-when-cross-origin':
            score+=1
            msg += ['(V) X-Frame-Options']
            
    if 'Referrer-Policy' in response_headers:
        if response_headers['Referrer-Policy'] == 'strict-origin-when-cross-origin':
            score+=1
            msg += ['(V) Referrer-Policy']

    if 'X-Content-Type-Options' in response_headers:
        score+=1
        msg += ['(V) X-Content-Type-Options']

    if 'Permissions-Policy' in response_headers:
        score+=1
        msg += ['(V) Permissions-Policy']

    return score, msg

# Check if the first word in the input is a url
def check_if_url(input):
    url = input.split(' ',1)[0]
    if validators.url(url):
        return True
    else:
        return False

# Get the url from the user input
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

# Scan the urls and create the csv and json files
def scan_urls(urls_to_scan):
    info_dict = {}
    scanned_urls = []
    scores = []
    msgs = []

    for url in urls_to_scan:
        if validators.url(url):
            # A GET request to the API
            try:
                response = requests.get(url)
                response_headers = response.headers
            except Exception as e:
                print(e)
                continue

            score, msg = check_header(response_headers)
            scanned_urls+= [url]
            scores += [score]
            msgs += [msg]

    # Create the csv and json files
    info_dict['url'] = scanned_urls
    info_dict['security score'] = scores
    info_dict['reason'] = msgs
    info_dict['time'] = datetime.now().strftime("%d/%m/%Y %H:%M:%S")

    df = pd.DataFrame(info_dict)
    df.to_csv('output_file.csv')

    with open('output.json', mode='w') as file:
        json.dump(info_dict, file)

# Create a parser
parser = argparse.ArgumentParser()

parser.add_argument('--urls', type=str)

args = parser.parse_args()

if args.urls:
    if check_if_url(args.urls):
        urls = args.urls
        urls_to_scan = urls.split(' ')
    else:
        urls_to_scan = ""
        get_url_by_asking()
else:
    urls_to_scan = get_url_by_asking()

scan_urls(urls_to_scan)
