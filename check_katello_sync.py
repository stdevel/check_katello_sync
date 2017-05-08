#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
A Nagios/Icinga plugin for checking product synchronization
within Foreman/Katello or Red Hat Satellite 6
"""



import argparse
import logging
import os
import stat
import json
import datetime
import getpass
from ForemanAPIClient import ForemanAPIClient
from datetime import datetime

__version__ = "0.5.2"
"""
str: Program version
"""
LOGGER = logging.getLogger('check_katello_sync')
"""
logging: Logger instance
"""
FOREMAN_CLIENT = None
"""
ForemanAPIClient: Foreman API client handle
"""
STATE = 0
"""
int: Nagios/Icinga plugin return code
"""
PROD_CRIT = []
"""
list: critical products
"""
PROD_WARN = []
"""
list: warning products
"""
PROD_OK = []
"""
list: okay products
"""
PROD_TOTAL = 0
"""
int: total products
"""



def set_code(return_code):
    """
    This function sets or updates the result code.

    :param return_code: Return code
    :type return_code: int
    """
    global STATE
    if return_code > STATE:
        #update return code
        STATE = return_code



def get_return_str():
    """
    This function returns the result status based on the state code.
    """
    #get return string
    if STATE == 3:
        return "UNKNOWN"
    elif STATE == 2:
        return "CRITICAL"
    elif STATE == 1:
        return "WARNING"
    else:
        return "OK"



def check_product(product):
    """
    Checks a product for currency.

    :param product: Product dictionary
    :type product: dict
    """
    global PROD_OK, PROD_WARN, PROD_CRIT

    #Check if product unsynced
    if product["last_sync"] == None:
        LOGGER.debug("Product '{0}' ({1}) is UNSYNCED!".format(
            product["label"], product["description"]
        ))
        PROD_CRIT.append(product["label"])
        set_code(2)
    else:
        LOGGER.debug("Product '{0}' ({1}) was synced at {2}".format(
            product["label"], product["description"], product["last_sync"][0:19]
        ))
        last_sync = datetime.strptime(
            product["last_sync"][0:19], "%Y-%m-%d %H:%M:%S"
        )
        delta = datetime.now() - last_sync
        LOGGER.debug("Delta for '{0}' is {1} days".format(
            product["label"], delta.days
        ))
        if delta.days > options.outdated_crit:
            PROD_CRIT.append(product["label"])
            set_code(2)
            LOGGER.debug("Critical product: '{0}'".format(product["label"]))
        if delta.days > options.outdated_warn:
            PROD_WARN.append(product["label"])
            set_code(1)
            LOGGER.debug("Warning product: '{0}'".format(product["label"]))
        else:
            PROD_OK.append(product["label"])
            LOGGER.debug("Ok product: '{0}'".format(product["label"]))



def check_products():
    """
    Checks products for currency.
    """
    global PROD_TOTAL

    #get API result
    result_obj = json.loads(
        FOREMAN_CLIENT.api_get(
            "/products?organization_id={}".format(options.org)
        )
    )

    #check for non-existing products
    for product in options.include:
        if product not in [x["label"] for x in result_obj["results"]]:
            PROD_CRIT.append(product)
            set_code(2)

    #check _all_ the products
    for product in result_obj["results"]:
        PROD_TOTAL = PROD_TOTAL + 1
        if len(options.include) > 0:
            if product["label"] in options.include:
                check_product(product)
        elif len(options.exclude) > 0:
            if product["label"] not in options.exclude:
                check_product(product)
        else:
            check_product(product)

    #set output

    #critical products
    str_crit = ", ".join(PROD_CRIT)
    if len(PROD_CRIT) >= 1:
        str_crit = "Products non-existent or outdated more than {0} days: {1}".format(
            options.outdated_crit, str_crit)
        if len(PROD_WARN) >= 1 or len(PROD_OK) >= 1:
            str_crit = "{0}. ".format(str_crit)
    else:
        str_crit = ""

    #warning products
    str_warn = ", ".join(PROD_WARN)
    if len(PROD_WARN) >= 1:
        str_warn = "Products outdated up to {0} days: {1}".format(
            options.outdated_warn, str_warn)
        if len(PROD_OK) >= 1:
            str_warn = "{0}. ".format(str_warn)
    else:
        str_warn = ""

    #ok products
    str_ok = ", ".join(PROD_OK)
    if len(PROD_OK) >= 1:
        str_ok = "Products synchronized: {0}".format(str_ok)
    else:
        str_ok = ""

    #perfdata
    perfdata = "|"
    if options.show_perfdata:
        perfdata = "{0} 'prod_total'={1};;;; " \
            "'prod_warn'={2};{3};{3};; " \
            "'prod_crit'={4};{5};{5};; ".format(
                perfdata, PROD_TOTAL,
                len(PROD_WARN), options.outdated_warn,
                len(PROD_CRIT), options.outdated_crit,
            )

    #final string
    output = "{0}{1}{2} {3} ".format(
        str_crit, str_warn, str_ok, perfdata
    )
    #print result and die in a fire
    print "{0}: {1}".format(get_return_str(), output)
    exit(STATE)



def get_credentials(prefix, input_file=None):
    """
    Retrieves credentials for a particular external system (e.g. Satellite).
    :param prefix: prefix for the external system (used in variables/prompts)
    :type prefix: str
    :param input_file: name of the auth file (default: none)
    :type input_file: str
    """
    if input_file:
        LOGGER.debug("Using authfile")
        try:
            #check filemode and read file
            filemode = oct(stat.S_IMODE(os.lstat(input_file).st_mode))
            if filemode == "0600":
                LOGGER.debug("File permission matches 0600")
                with open(input_file, "r") as auth_file:
                    s_username = auth_file.readline().replace("\n", "")
                    s_password = auth_file.readline().replace("\n", "")
                return (s_username, s_password)
            else:
                LOGGER.warning("File permissions (" + filemode + ")" \
                    " not matching 0600!")
        except OSError:
            LOGGER.warning("File non-existent or permissions not 0600!")
            LOGGER.debug("Prompting for {} login credentials as we have a" \
                " faulty file".format(prefix))
            s_username = raw_input(prefix + " Username: ")
            s_password = getpass.getpass(prefix + " Password: ")
            return (s_username, s_password)
    elif prefix.upper()+"_LOGIN" in os.environ and \
        prefix.upper()+"_PASSWORD" in os.environ:
        #shell variables
        LOGGER.debug("Checking {} shell variables".format(prefix))
        return (os.environ[prefix.upper()+"_LOGIN"], \
            os.environ[prefix.upper()+"_PASSWORD"])
    else:
        #prompt user
        LOGGER.debug("Prompting for {} login credentials".format(prefix))
        s_username = raw_input(prefix + " Username: ")
        s_password = getpass.getpass(prefix + " Password: ")
        return (s_username, s_password)



def parse_options(args=None):
    """Parses options and arguments."""

    desc = '''check_katello_sync.py is used to check product synchronization
    within Foreman/Katello or Red Hat Satellite 6.x.
    Login credentials are assigned using the following shell variables:
    SATELLITE_LOGIN  username
    SATELLITE_PASSWORD  password
    It is also possible to create an authfile (permissions 0600) for usage
    with this script. The first line needs to contain the username, the
    second line should consist of the appropriate password. If you're not
    defining variables or an authfile you will be prompted to enter your
    login information.
    '''
    epilog = '''Check-out the website for more details:
    http://github.com/stdevel/check_katello_sync'''
    parser = argparse.ArgumentParser(description=desc, version=__version__, \
    epilog=epilog)

    #define option groups
    gen_opts = parser.add_argument_group("generic arguments")
    fman_opts = parser.add_argument_group("Foreman arguments")
    prod_opts = parser.add_argument_group("product arguments")
    filter_opts = parser.add_argument_group("product filter arguments")
    filter_opts_excl = filter_opts.add_mutually_exclusive_group()

    #GENERIC ARGUMENTS
    #-d / --debug
    gen_opts.add_argument("-d", "--debug", dest="debug", default=False, \
    action="store_true", help="enable debugging outputs")
    #-P / --show-perfdata
    gen_opts.add_argument("-P", "--show-perfdata", dest="show_perfdata", \
    default=False, action="store_true", \
    help="enables performance data (default: no)")

    #FOREMAN ARGUMENTS
    #-a / --authfile
    fman_opts.add_argument("-a", "--authfile", dest="authfile", metavar="FILE",\
    default="", help="defines an auth file to use instead of shell variables")
    #-s / --server
    fman_opts.add_argument("-s", "--server", dest="server", metavar="SERVER", \
    default="localhost", help="defines the server to use (default: localhost)")
    #--insecure
    fman_opts.add_argument("--insecure", dest="ssl_verify", default=True, \
    action="store_false", help="Disables SSL verification (default: no)")
    #-o / --organization
    fman_opts.add_argument("-o", "--organization", dest="org", \
    action="store", default="", metavar="NAME|ID", help="specifies the " \
    "organization to check", required=True)

    #PRODUCT ARGUMENTS
    prod_opts.add_argument("-w", "--outdated-warning", dest="outdated_warn", \
    default=2, metavar="DAYS", type=int, help="defines outdated products" \
    " warning threshold in days (default: 2)")
    #-U / --outdated-critical
    prod_opts.add_argument("-c", "--outdated-critical", dest="outdated_crit", \
    default=5, metavar="DAYS", type=int, help="defines outdated products" \
    " critical threshold in days (default: 5)")

    #PRODUCT FILTER ARGUMENTS
    #-o / --organization
    filter_opts_excl.add_argument("-i", "--include", action="append", \
    default=[], type=str, dest="include", metavar="NAME", help="specifies " \
    " particular products to check (default: no)")
    #-e / --exclude
    filter_opts_excl.add_argument("-e", "--exclude", action="append", \
    default=[], type=str, dest="exclude", metavar="NAME", help="specfies " \
    " particular products to ignore (default: no)")


    #parse options and arguments
    options = parser.parse_args()
    return (options, args)



def main(options):
    """Main function, starts the logic based on parameters."""
    global FOREMAN_CLIENT

    #splitting is fun
    if len(options.include) == 1:
        options.include = options.include[0].split(',')
    if len(options.exclude) == 1:
        options.exclude = options.exclude[0].split(',')

    LOGGER.debug("Options: {0}".format(options))
    LOGGER.debug("Arguments: {0}".format(args))

    #define client
    (fman_user, fman_pass) = get_credentials("Satellite", options.authfile)
    FOREMAN_CLIENT = ForemanAPIClient(
        options.server, fman_user, fman_pass, options.ssl_verify, "/katello"
    )

    #get organization ID if string supplied
    if options.org.isdigit() == False:
        options.org = FOREMAN_CLIENT.get_id_by_name(
            options.org, "organization")

    #do the magic
    check_products()



if __name__ == "__main__":
    (options, args) = parse_options()

    #set logging level
    logging.basicConfig()
    if options.debug:
        LOGGER.setLevel(logging.DEBUG)
    else:
        LOGGER.setLevel(logging.ERROR)

    #yes this is main function
    main(options)
