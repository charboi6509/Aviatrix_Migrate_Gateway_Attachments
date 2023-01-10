import sys
import requests
import json
import configparser
import urllib3
import logging


def request(url, payload, method):
    """Requests wrapper
    Args:
        url (str): URL to request. Example: https://www.google.com/search?q=do+a+barrel+roll
        payload (dict): Dict of key/values payload to be sent in request.
        method (str): "GET" or "POST"
    Raises:
        SystemExit: Any exception will trigger a system exit.
    Returns:
        dict: JSON response text.
    """
    try:
        response = requests.request(method, url, data=payload, verify=False) #POST
        response_json = json.loads(response.text)
    except requests.exceptions.RequestException as e:
        raise SystemExit(e)

    return response_json

def login(controller_ip, controller_username, controller_password):
    """This creates a login session to the controller and obtains a CID token to use in subsequent requests.
    Args:
        controller_ip (str): IP Address of Aviatrix Controller
        controller_username (str): Aviatrix Controller Username
        controller_password (str): Aviatrix Controller Password
    Returns:
        dict: JSON response text
    """

    url = "https://%s/v1/api" % controller_ip

    payload={'action': 'login',
    'username': controller_username,
    'password': controller_password}
      
    response = request(url, payload, "POST")

    return response

def get_multi_cloud_security_domain_attachment_details(controller_ip, cid, spoke_gateway_name):
    """This function gets the security domain details from a specified attachment.

    Args:
    controller_ip (str): IP Address of Aviatrix Controller
    cid (str): Login CID
    spoke_gateway_name (str): Name of Spoke Gateway, which is the name of the attachment.
    """

    url = "https://%s/v1/api" % controller_ip

    payload={
    'CID': cid,
    'action' : "get_multi_cloud_security_domain_attachment_details",
    'attachment_name': spoke_gateway_name
    }
      
    response = request(url, payload, "POST")
    logging.info(response)
    return response

def associate_attachment_to_multi_cloud_security_domain(controller_ip, cid, spoke_gateway_name, network_domain_name):
    """This associates an attachment to a multi-cloud security domain.

    Args:
    controller_ip (str): IP Address of Aviatrix Controller
    cid (str): Login CID
    spoke_gateway_name (str): Name of Spoke Gateway, which is the name of the attachment.
    network_domain_name (str): Name of Network Domain
    """

    url = "https://%s/v1/api" % controller_ip

    payload={
    'CID': cid,
    'action' : "associate_attachment_to_multi_cloud_security_domain",
    'attachment_name': spoke_gateway_name,
    'domain_name': network_domain_name
    }
      
    response = request(url, payload, "POST")
    logging.info(response)
    return response

def detach_spoke_from_transit(controller_ip, cid, spoke_gateway_name, transit_gateway_name):
    """This function detaches a spoke from a transit

    Args:
        controller_ip (str): IP Address of Aviatrix Controller
        cid (str): Login CID
        spoke_gateway_name (str): Name of Spoke Gateway
        transit_gateway_name (str): Name of Transit Gateway

    """

    url = "https://%s/v1/api" % controller_ip

    payload={
    'CID': cid,
    'action' : "detach_spoke_from_transit_gw",
    'spoke_gw': spoke_gateway_name,
    'transit_gw' : transit_gateway_name
    }
      
    response = request(url, payload, "POST")
    logging.info(response)
    return response

def attach_spoke_to_transit(controller_ip, cid, spoke_gateway_name, transit_gateway_name, route_table_list):
    """This function attaches a spoke from a transit

    Args:
        controller_ip (str): IP Address of Aviatrix Controller
        cid (str): Login CID
        spoke_gateway_name (str): Name of Spoke Gateway
        transit_gateway_name (str): Name of Transit Gateway
        route_table_list: Not required.

    """

    url = "https://%s/v1/api" % controller_ip

    payload={
    'CID': cid,
    'action' : "attach_spoke_to_transit_gw",
    'spoke_gw': spoke_gateway_name,
    'transit_gw' : transit_gateway_name,
    'route_table_list' : route_table_list
    }
      
    response = request(url, payload, "POST")
    logging.info(response)
    return response

def add_spoke_to_transit_firenet_inspection(controller_ip, cid, spoke_gateway_name, transit_gateway_name):
    """This function adds an attachment to an inspection policy

    Args:
        controller_ip (str): IP Address of Aviatrix Controller
        cid (str): Login CID
        spoke_gateway_name (str): Name of Spoke Gateway
        firenet_gateway_name (str): Name of Transit Gateway

    """

    url = "https://%s/v1/api" % controller_ip

    payload={
    'CID': cid,
    'action' : "add_spoke_to_transit_firenet_inspection",
    'spoke_gateway_name': spoke_gateway_name,
    'firenet_gateway_name' : transit_gateway_name
    }
      
    response = request(url, payload, "POST")
    logging.info(response)
    return response

def main():
    #Disable the SSL warnings
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    #Load the configuration file
    config = configparser.ConfigParser()
    config.read("api_attach_gateways.ini")
    loglevel = config.get("aviatrix", "loglevel")
    controller_ip = config.get("aviatrix", "controller_ip")
    controller_username = config.get("aviatrix", "controller_username")
    controller_password = config.get("aviatrix", "controller_password")
    
    
    #We're only supporting two log levels in the config at this time: debug and info.
    if loglevel.lower() == "debug":
        logging.basicConfig(format='%(asctime)s %(clientip)-15s %(user)-8s %(message)s', level=logging.DEBUG)
    else:
        logging.basicConfig(format='%(asctime)s %(levelname)s %(message)s', level=logging.INFO)


    login_request = login(controller_ip, controller_username, controller_password)
    cid = login_request["CID"]
    old_transit_gateway = "transit1"
    new_transit_gateway = "transit2"
    new_spoke_route_table = ""

    spoke_gateway_list = ("spoke1", "spoke2", "spoke3", "spoke4", "spoke5")

    #Get the existing network/security domain names from the listed spokes.
    response_list=[]
    for individual_gateway in spoke_gateway_list:
        print("Now GETting network domain for %s attachment" %(individual_gateway))
        response=get_multi_cloud_security_domain_attachment_details(controller_ip, cid, individual_gateway)
        response_list.append(response["results"]["domain"])
    print(response_list)
   
    #Detach the existing spokes from a transit gateway.
    for individual_gateway in spoke_gateway_list:
        print("Now detaching %s from %s" %(individual_gateway, old_transit_gateway))
        detach_spoke_from_transit(controller_ip, cid, individual_gateway, old_transit_gateway)

    #Attach the existing spokes to a transit gateway.
    for individual_gateway in spoke_gateway_list:
        print("Now attaching %s to %s" %(individual_gateway, new_transit_gateway))
        attach_spoke_to_transit(controller_ip, cid, individual_gateway, new_transit_gateway, new_spoke_route_table)
    
    #Associate network domain to new attachment.
    for indivial_gateway, network_domain_name in zip(spoke_gateway_list, response_list):
        payload=associate_attachment_to_multi_cloud_security_domain(controller_ip, cid, indivial_gateway, network_domain_name)
        print(payload)
   
   
    #Enable inspection for a defined spoke gateway and firenet gateway.
    # for individual_gateway in spoke_gateway_list:
    #     print("Now adding %s to %s inspection policy" %(individual_gateway, new_transit_gateway))
    #     add_spoke_to_transit_firenet_inspection(controller_ip, cid, individual_gateway, new_transit_gateway)


if __name__ == "__main__":
    main()
