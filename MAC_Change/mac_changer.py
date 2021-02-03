import subprocess
import optparse
import re


def get_arguments():
    parse = optparse.OptionParser()
    parse.add_option('-i', '--interface', dest="interface", help="Interface to change its MAC address")
    parse.add_option('-m', '--mac', dest="new_mac_address", help="Current MAC address will change to new MAC address")
    (options, arguments) = parse.parse_args()
    if not options.interface:
        parse.error("[-] User needs to provide an interface, use --help for more info")
    if not options.new_mac_address:
        parse.error("[-] User needs to provide a new mac address , use --help for more info")
    return options


def change_mac(interface, new_mac_address):
    print("[+] Changing MAC address for {} to {}".format(interface, new_mac_address))
    # this is a unsecured way of subprocess call, user can put his own script inside the call
    # subprocess.call("ifconfig {} down".format(interface), shell=True)
    # subprocess.call("ifconfig {} hw ether {}".format(interface, new_mac_address), shell=True)
    # subprocess.call("ifconfig {} up".format(interface), shell=True)
    subprocess.call(["ifconfig", interface, "down"])
    subprocess.call(["ifconfig", interface, "hw", "ether", new_mac_address])
    subprocess.call(["ifconfig", interface, "up"])


def get_current_mac(interface):
    ifconfig_result = str(subprocess.check_output(["ifconfig", interface]))
    mac_address_result = re.search(r"\w\w:\w\w:\w\w:\w\w:\w\w:\w\w", ifconfig_result)
    if mac_address_result:
        return mac_address_result.group(0)
    else:
        print("[-] Could not find the MAC Address")
        exit()


def check_given_interface(interface):
    ifconfig_result = str(subprocess.check_output(["ifconfig"]))
    interface_flag = re.search(rf'{interface}: ', ifconfig_result)
    if not interface_flag:
        print("[-] Interface is not valid")
        exit()
    else:
        print(f"interface_flag : {interface_flag.group(0)}")
        print("[+] got a valid interface {}".format(interface))


options = get_arguments()
check_given_interface(options.interface)
current_mac = get_current_mac(options.interface)
print("[+] current MAC address for {} is {}".format(options.interface, current_mac))
change_mac(options.interface, options.new_mac_address)
current_mac = get_current_mac(options.interface)
if current_mac == options.new_mac_address:
    print("[+] MAC address is successfully changed to {}".format(options.new_mac_address))
else:
    print("[-] MAC address change failed")