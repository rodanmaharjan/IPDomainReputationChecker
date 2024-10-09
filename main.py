from itertools import cycle
import requests
import time
import re
import vt

# Read IP addresses and API keys from files
with open('input.txt', 'r') as ip_file, open('api_keys.txt', 'r') as key_file:
    ip_addresses = ip_file.read().splitlines()
    api_keys = key_file.read().splitlines()
    api_key_cycle = cycle(api_keys)
    
    malicious_addresses = []
    
    for each in ip_addresses:
        new_api_key = next(api_key_cycle)  # Get the next API key
        ip_regex = re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d+)?')
        url_regex = re.compile(r'\b(?:https?://)?(?:www\.)?(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}|(?:https?://)?(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?\b')
        
        if ip_regex.match(each):
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{each}"
            headers = {"accept": "application/json", "x-apikey": new_api_key}
            print(f"\nMaking request for IP: {each} \nUsing API key: {new_api_key}")
            response = requests.get(url, headers=headers)
            
            if response.status_code == 200:
                malicious_value = response.json()["data"]["attributes"]["last_analysis_stats"]["malicious"]
                if malicious_value > 0:
                    print(f'Response for IP {each}: Malicious. \n Number of malicious reports: {malicious_value}\n')
                    malicious_addresses.append(each)
                else:
                    print(f'Response for IP {each}: Not malicious')
                time.sleep(20)  # Rate limit
            else:
                print(f"Request failed for IP {each} with status code: {response.status_code}")
                print(response.text)  # Print the response content for debugging
            
        elif url_regex.match(each):
            client = vt.Client(new_api_key)  # Initialize the VirusTotal client
            try:
                print(f"\nMaking request for URL: {each}\nUsing API key: {new_api_key}")
                url_id = vt.url_id(each)  # Get the URL ID
                url_info = client.get_object("/urls/{}".format(url_id))  # Retrieve the URL analysis information
                
                if not url_info:
                    print(f"No results found for: {each} on VirusTotal")
                    continue
                
                value = url_info.last_analysis_stats.get("malicious", 0)
                if value > 0:
                    print(f"Response of URL {each} : Malicious")
                    print("Number of malicious reports:", value)
                    malicious_addresses.append(each)
                else:
                    print(f"Response of URL {each}: Not malicious.")
                time.sleep(20)  # Rate limit
                
            except Exception as e:
                print(f"An error occurred for {each}: {str(e)}")
                continue
            
            finally:
                client.close()  # Close the VirusTotal client

    # Write malicious addresses to a file
    with open('malicious.txt', 'a') as malicious_file:
        malicious_file.write('\n'.join(malicious_addresses) + '\n')

print(f"Malicious IP addresses and URLs written to malicious.txt")
