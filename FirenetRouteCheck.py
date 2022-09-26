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

def get_interfaces(controller_ip, cid, gw_name):
    """This function returns the interfaces on the provided gateway.

    Args:
        controller_ip (str): IP Address of Aviatrix Controller
        cid (str): Login CID
        gw_name (str): Gateway name to review
    """

    url = "https://%s/v1/api?action=list_gateway_interfaces&CID=%s&gateway_name=%s&for_ping=" % (controller_ip, cid, gw_name)

    payload={}
  
    response = request(url, payload, "GET")
    
    #logging.info(response)
    return(response)


def get_gateway_firenet_routes(controller_ip, cid, gw_name):
    """This function gets the routes on a Gateway for the firewall route table

    Args:
        controller_ip (str): IP Address of Aviatrix Controller
        cid (str): Login CID
        gw_name (str): Gateway name to review
    """
    url = "https://%s/v1/api?action=get_transit_or_spoke_gateway_details&CID=%s&gateway_name=%s&option=gw_route&table_name=firewall" % (controller_ip, cid, gw_name)

    payload={}

    data = request(url, payload, "GET")

    findings = {}

    findings["results"] = {}
    for item in data["results"]["gateway_route_table"]:
    
        logging.info ("Gateway %s has %d route(s) in the firewall_rtb" % (item["gw_name"], len(item["route_table"])))

        findings["results"][item["gw_name"]] = {}

        gw_interfaces = get_interfaces(controller_ip, cid, item["gw_name"])
        if "eth1" in gw_interfaces["results"]:
            logging.warning("Gateway %s eth1 is up." % item["gw_name"])
            findings["results"][item["gw_name"]]["firewall_eth1_status"] = "up"
        else:
            logging.warning("Gateway %s eth1 is down." % item["gw_name"])
            findings["results"][item["gw_name"]]["firewall_eth1_status"] = "down"


        if len(item["route_table"]) == 0:
            logging.warning("Gateway %s Firenet Route table is empty." % item["gw_name"])
            findings["results"][item["gw_name"]]["firewall_rtb_empty"] = "YES"

        else:
            logging.warning("Gateway %s Firenet Route table is NOT empty." % item["gw_name"])
            findings["results"][item["gw_name"]]["firewall_rtb_empty"] = "NO"

    return findings

def main():
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    config = configparser.ConfigParser()
    config.read("FirenetRouteCheck.ini")
    loglevel = config.get("aviatrix", "loglevel")
    controller_ip = config.get("aviatrix", "controller_ip")
    controller_username = config.get("aviatrix", "controller_username")
    controller_password = config.get("aviatrix", "controller_password")
    monitored_gateways = config.get("aviatrix", "firenet_gateways")    
    
    #We're only supporting two log levels, debug and info.
    if loglevel.lower() == "debug":
        logging.basicConfig(format='%(asctime)s %(clientip)-15s %(user)-8s %(message)s', level=logging.DEBUG)
    else:
        logging.basicConfig(format='%(asctime)s %(levelname)s %(message)s', level=logging.INFO)


    login_request = login(controller_ip, controller_username, controller_password)
    cid = login_request["CID"]
    results = get_gateway_firenet_routes(controller_ip, cid, monitored_gateways)
    

    for r in results["results"]:
        if results["results"][r]["firewall_rtb_empty"] == "YES":
            print("Gateway %s has an issue." % r)


if __name__ == "__main__":
    main()