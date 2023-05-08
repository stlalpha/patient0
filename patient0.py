import requests
import json
import sys
import os
import re

#This function is used to get the CVE details from the NVD API
def get_cve_details(cve_id):
    api_url = f"https://services.nvd.nist.gov/rest/json/cve/1.0/{cve_id}"
    response = requests.get(api_url)
    response_dict = json.loads(response.content)
    return response_dict['result']

#This function is used to get the vulnerable versions of the affected operating systems from the CVE details
def get_vulnerable_versions(cve_id):
    cve_details = get_cve_details(cve_id)
    vulnerable_versions = {}
    if 'affects' in cve_details:
        for vendor_data in cve_details['affects']['vendor']['vendor_data']:
            vendor_name = vendor_data['vendor_name']
            for product_data in vendor_data['product']['product_data']:
                product_name = product_data['product_name']
                if 'version' in product_data:
                    for version_data in product_data['version']['version_data']:
                        version_value = version_data['version_value']
                        if version_data['version_affected'] == '<=':
                            version_range = f'0-{version_value}'
                        elif version_data['version_affected'] == '<':
                            version_range = f'0-{version_data["version_start_excluding"]}'
                        elif version_data['version_affected'] == '>=':
                            version_range = f'{version_value}-99'
                        elif version_data['version_affected'] == '>':
                            version_range = f'{version_data["version_end_excluding"]}-99'
                        else:
                            version_range = version_value
                        if vendor_name in vulnerable_versions:
                            if product_name in vulnerable_versions[vendor_name]:
                                vulnerable_versions[vendor_name][product_name].append(version_range)
                            else:
                                vulnerable_versions[vendor_name][product_name] = [version_range]
                        else:
                            vulnerable_versions[vendor_name] = {product_name: [version_range]}
    return vulnerable_versions

#This function is used to select the OS version to build
def select_os_version(os_versions):
    os_list = list(os_versions.keys())
    for i, os_name in enumerate(os_list):
        print(f"{i+1}. {os_name}")
    os_index = int(input("Select the index of the operating system you want to build: "))
    selected_os = os_list[os_index-1]
    os_versions_list = os_versions[selected_os]
    for i, os_version in enumerate(os_versions_list):
        print(f"{i+1}. {os_version}")
    version_index = int(input("Select the index of the version you want to build: "))
    selected_version = os_versions_list[version_index-1]
    return selected_os, selected_version

#This function is used to build the Vagrantfile
def build_vagrantfile(os_name, os_version, package_name):
    vagrantfile_content = f'''Vagrant.configure("2") {{
  config.vm.box = "generic/{os_name}{os_version}"
  config.vm.provision "shell", inline: <<-SHELL
    apt-get update
    apt-get install -y {package_name}
  SHELL
}}
'''
    with open('Vagrantfile', 'w') as f:
        f.write(vagrantfile_content)


if __name__ == '__main__':
    # Prompt user to enter CVE
    cve_id = input("Enter CVE ID: ")

    # Get vulnerable versions of affected operating systems from CVE details
    os_versions = get_vulnerable_versions(cve_id)

    # Select OS version to build
    selected_os, selected_version = select_os_version(os_versions)

    # Get package name from CVE details
    cve_details = get_cve_details(cve_id)
    package_name = cve_details['configurations']['nodes'][0]['cpe_match'][0]['cpe23Uri'].split(':')[4]
    

