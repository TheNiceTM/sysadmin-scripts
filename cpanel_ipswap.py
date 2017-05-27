#!/usr/bin/env python

#cPanel IP Swap Script#
#rewritten in python with programmatic generation of network configuration and sanity checking by Josh Navarro
#original idea and bash implementation by Dave Hurley

import subprocess
import os
import base64
import sys
import re
import socket
import shutil
from cStringIO import StringIO

try:
    import paramiko
except ImportError:
    subprocess.call('yum install -y pip', shell=True)
    subprocess.call('python -m pip install --upgrade --force pip', shell=True)
    subprocess.call('pip install setuptools==33.1.1', shell=True)
    subprocess.call('pip install paramiko', shell=True)
    try:
        import paramiko
    except:
        print("[error] we we're unable to automatically install the paramiko python library with pip.\n"
              "please attempt manual install of paramiko.")

from optparse import OptionParser
import uuid

ips_path = '/etc/ips'
hosts_path = '/etc/hosts'
ifcfg_path = '/etc/sysconfig/network-scripts/ifcfg-'
network_path = '/etc/sysconfig/network'

class Network:
    def __init__(self, device, ipaddr, netmask, gateway, extra_ips, hwaddr, hostname):
        self.device = device
        self.ipaddr = ipaddr
        self.netmask = netmask
        self.gateway = gateway
        self.hostname = hostname
        self.extra_ips = extra_ips
        self.hwaddr = hwaddr

    def generatecConfig(self):
        file_data = \
"""ONBOOT=yes
BOOTPROTO=static
TYPE=Ethernet
HWADDR=%s
DEVICE=%s
IPADDR=%s
NETMASK=%s
GATEWAY=%s""" \
        % (self.hwaddr, self.device, self.ipaddr, self.netmask,self.gateway)
        return file_data

    def generateHosts(self):
        file_data = \
"""127.0.0.1 localhost localhost.localdomain localhost4 localhost4.localdomain4
::1 localhost localhost.localdomain localhost6 localhost6.localdomain6
%s %s %s""" \
        % (self.ipaddr, self.hostname, self.hostname.split('.')[0] )
        return file_data

    def generateNetwork(self):
        file_data = \
"""HOSTNAME=%s
DOMAINNAME=%s
GATEWAY=%s""" \
        % (self.hostname, self.hostname, self.gateway)
        return file_data


def sshkeys(sourceport, sourceip): # create and apply sshkeys
	genkey="ssh-keygen -t rsa"
	sendkey="ssh-copy-id -p %s %s" % (sourceport, sourceip)
	subprocess.call(genkey, shell=True)
	subprocess.call(sendkey, shell=True)

def dumpclean(obj):
    if type(obj) == dict:
        for k, v in obj.items():
            if hasattr(v, '__iter__'):
                print k
                dumpclean(v)
            else:
                print '%s: {%s}' % (k, v)
    elif type(obj) == list:
        for v in obj:
            if hasattr(v, '__iter__'):
                dumpclean(v)
            else:
                print v
    else:
        print obj

def query_yes_no(question, default="yes"):
    """Ask a yes/no question via raw_input() and return their answer.

    "question" is a string that is presented to the user.
    "default" is the presumed answer if the user just hits <Enter>.
        It must be "yes" (the default), "no" or None (meaning
        an answer is required of the user).

    The "answer" return value is True for "yes" or False for "no".
    """
    valid = {"yes": True, "y": True, "ye": True,
             "no": False, "n": False}
    if default is None:
        prompt = " [y/n] "
    elif default == "yes":
        prompt = " [Y/n] "
    elif default == "no":
        prompt = " [y/N] "
    else:
        raise ValueError("invalid default answer: '%s'" % default)

    while True:
        sys.stdout.write(question + prompt)
        choice = raw_input().lower()
        if default is not None and choice == '':
            return valid[default]
        elif choice in valid:
            return valid[choice]
        else:
            sys.stdout.write("Please respond with 'yes' or 'no' "
                             "(or 'y' or 'n').\n")

#Hastily made, can be done better with a string argument instead
def getInterfaceName(file):
    ifname = 0
    if file is None:
        with open('/etc/wwwacct.conf', 'r') as obj:
            for line in obj:
                if 'ETHDEV' in line:
                    regex = re.search('(?<=\s).*', line)
                    ifname = regex.group(0)
    else:
        with file as obj:
            for line in obj:
                if 'ETHDEV' in line:
                    regex = re.search('(?<=\s).*', line)
                    ifname = regex.group(0)
    return ifname

def sshCommand(ssh_client, command):
    stdin, stdout, stderr = ssh_client.exec_command(command)
    return str.strip(stdout.read())

def overwriteFile(filename, data=None, sftp_client=None):
    if(sftp_client == None):
        file = open(filename, 'r+')
        file.seek(0)
        file.write(data)
        file.close()
    else:
        file = sftp_client.open(filename, 'wb')
        file.seek(0)
        file.write(data)
        file.close()


def main():
    usage = "usage: python %prog [options]"
    parser = OptionParser(usage)
    parser.add_option("-s", "--source", dest="sourceip", type=str,
                      help="set the source ip address.")
    parser.add_option("-p", "--port", dest="sourceport", default="22",
                      help="set port, defaults to 22 if not set")
    (options, args) = parser.parse_args()

    if(options.sourceip is None):
        print('[error] no source IP given please use %prog -h for help')
        exit()

    if(os.getuid() != 0):
        print('[error] please run this script as the root user.')

    #Check or generate SSH keys.
    ssh_key_path = ("%s/.ssh/id_rsa" % os.environ['HOME'])
    if(os.path.isfile(ssh_key_path)==False):
        if(query_yes_no('Could not find id_rsa key would you like to generate one and copy to the source?', 'yes')==True):
            sshkeys(options.sourceport, options.sourceip)
        else:
            exit()

    subprocess.call("ssh-copy-id -p %s %s" % (options.sourceport, options.sourceip), shell=True)
    if(query_yes_no('Warning: This script has been designed to allow as little failure as possible but issues can occur.\nDo you wish to continue?', 'yes')==False):
        exit()

    # Setup SSH Client
    paramiko.util.log_to_file(os.environ['HOME']+'/'+'ip_swap.log')
    ssh_client      = paramiko.SSHClient()
    ssh_priv_key    = paramiko.RSAKey.from_private_key_file(ssh_key_path)
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh_client.load_system_host_keys()
    ssh_client.connect(options.sourceip, int(options.sourceport), pkey=ssh_priv_key)
    sftp_client     = ssh_client.open_sftp()

    #Populate local config
    local_ips       = file.read(open(ips_path, 'r'))
    local_ifname    = getInterfaceName(None)
    local_ifcfg     = open(ifcfg_path+local_ifname, 'r')

    #Populate remote config
    remote_wwwacct  = sftp_client.open('/etc/wwwacct.conf')
    remote_ips      = paramiko.BufferedFile.read(sftp_client.open(ips_path))
    remote_ifname   = getInterfaceName(remote_wwwacct)
    remote_ifcfg    = sftp_client.open(ifcfg_path+remote_ifname)


    #create and populate network objects
    local_conf = dict(line.strip().split('=') for line in local_ifcfg)
    remote_conf = dict(line.strip().split('=') for line in remote_ifcfg)

    local_network = Network(local_ifname,
        remote_conf['IPADDR'],
        remote_conf['NETMASK'],
        remote_conf['GATEWAY'],
        extra_ips=remote_ips,
        hostname=socket.getfqdn(),
        hwaddr=str.strip(subprocess.check_output(['cat', '/sys/class/net/%s/address' % (local_ifname)])))

    remote_network = Network(remote_ifname,
        local_conf['IPADDR'],
        local_conf['NETMASK'],
        local_conf['GATEWAY'],
        extra_ips=local_ips,
        hostname=sshCommand(ssh_client, 'hostname -f'),
        hwaddr=sshCommand(ssh_client, 'cat /sys/class/net/%s/address' % (local_ifname)))

    print(
"""
Swapped configs:
Local: %s

Remote %s

""" % (local_network.generatecConfig(), remote_network.generatecConfig()))

    commands = [
        'mkdir -p /backup/ipswap/etc',
        'mkdir -p /backup/ipswap/etc/sysconfig/network-scripts',
    ]

    for cmd in commands:
        subprocess.call(cmd, shell=True)
        ssh_client.exec_command(cmd)

    local_files = [
        ips_path,
        hosts_path,
        network_path,
        ifcfg_path+local_network.device
    ]

    remote_files= [
        ips_path,
        hosts_path,
        network_path,
        ifcfg_path+remote_network.device
    ]
    #Create backup directories
    for item in local_files:
        subprocess.call('cp %s /backup/ipswap/%s' % (item, item), shell=True)
        ssh_client.exec_command('cp %s /backup/ipswap/%s' % (item, item))

    for item in remote_files:
        ssh_client.exec_command('cp %s /backup/ipswap%s' % (item, item))

    print('Backups of the configurations are available in /backup/ipswap on both servers.')
    print('Overwriting configs on dst...')

    overwriteFile(ips_path, local_network.extra_ips)
    overwriteFile(hosts_path, local_network.generateHosts())
    overwriteFile(ifcfg_path+local_network.device, local_network.generatecConfig())
    overwriteFile(network_path, local_network.generateNetwork())

    print('Overwriting configs on dst...')

    overwriteFile(ips_path, remote_network.extra_ips, sftp_client)
    overwriteFile(hosts_path, remote_network.generateHosts(), sftp_client)
    overwriteFile(ifcfg_path+remote_network.device, remote_network.generatecConfig(), sftp_client)
    overwriteFile(network_path, remote_network.generateNetwork(), sftp_client)

    print('IP swap configuration done, swap network allocations and restart networking')

    remote_wwwacct.close()
    remote_ifcfg.close()
    local_ifcfg.close()

    #Close SSH connection
    ssh_client.close()
    print
if __name__ == "__main__":
    main()