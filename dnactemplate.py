import requests
import base64
from requests.auth import HTTPBasicAuth
import urllib3
import configparser


def find_string(string,substr):
    """
    This function will find the substr within the string.  After we find substr in string, we will  parse
    the data until the end of line and then return that value.   If we do not return that value, then we will return
    false.

    :param string: The string that we will search in
    :param substr:  The string the we will search for
    :return: False if the substr wasn't found or if it was found, return the data after the substr up to the newline
    """

    position = string.find(substr)
    if position == -1:
        # If the hostname wasn't found, then let's make a generic filename from the UUID
        return False
    else:
        done = False
        space = False
        name = ""
        while not done:
            if string[position] == ' ':
                space = True
            elif string[position] == '\n':
                done = True
            else:
                if space == True:
                    name += string[position]

            position = position + 1

    return name

def initalize_connection(ipaddress, username, password):
    """
    This function will initialize a connection to the DNA Center platform.

    :param ipaddress: This is the IP Address and Port number of DNA Center (i.e., "192.168.0.1:8443")
    :param username:  This is the username for DNA Center
    :param password:  This is a password for DNA Center
    :return: A security token that will be used to make other calls to DNA Center
    """

    # Disable warnings like unsigned certificates, etc.
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    url = "https://" + ipaddress + "/dna/system/api/v1/auth/token"

    data_string = username + ":" + password
    encode_string = data_string.encode("utf-8")
    base64username = base64.b64encode(encode_string)

    payload = "j_username=" + username + "&j_password=" + password
    headers = {
        'content-type': "application/json",
        'authorization': base64username.decode("utf-8")
    }

    # sess=requests.session()

    # Handle exceptions if we cannot connect to the vManage
    try:
        resp = requests.post(url, auth=HTTPBasicAuth(username=username, password=password), headers=headers,
                             verify=False)
    except requests.exceptions.ConnectionError:
        print("Unable to Connect to " + ipaddress)
        return False

    response_json = resp.json()
    token = response_json["Token"]

    return token


def query_dnac(ipaddress, token):
    """
    This function will query the DNA Center for the configuration files.

    :param ipaddress: This is the IP Address and Port number of DNA Center (i.e., "192.168.0.1:8443")
    :param token:  This is the security token that was already received from the calls.
    :return: None
    """
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    # BEGIN - Questionable Code
    # NOTE: This is is place holder code to attempt to retrive the device db to correlate the host name with a configuration
    #       However, the data returned doesn't seem correct to me.

    url = "https://" + ipaddress + "/api/v1/network-device"

    headers = {
        'content-type': "application/json",
        'x-auth-token': token
    }

    device_db = {}
    resp = requests.get(url, headers=headers, verify=False)
    response_json = resp.json()

    for device in response_json['response']:
        device_db[device['id']] = device['hostname']

    # END - Questionable Code

    url = "https://" + ipaddress + "/api/v1/network-device/config"

    headers = {
        'content-type': "application/json",
        'x-auth-token': token
    }

    resp = requests.get(url, headers=headers, verify=False)
    response_json = resp.json()

    for i in response_json['response']:

        # We will attempt to find either the hostname or the SN: within the running config
        value = find_string(i['runningConfig'],"hostname")

        if value == False:
            value = find_string(i['runningConfig'],"SN:")

        filename=value+'.txt'

        f = open(filename, "w")
        f.write(i['runningConfig'])
        f.close()


print("DNAC Engine Starting...\n")

# Open up the configuration file and get all application defaults
try:
    config = configparser.ConfigParser()
    config.read('package_config.ini')

    serveraddress = config.get("application", "serveraddress")
    username = config.get("application", "username")
    password = config.get("application", "password")
except configparser.Error:
    print("Cannot Parse package_config.ini")
    exit(-1)

print("DNAC Configuration:")
print("DNAC Server Address: " + serveraddress)
print("DNAC Username: " + username)

token = initalize_connection(serveraddress, username, password)
inventory = query_dnac(serveraddress, token)
