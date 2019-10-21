
from pox.core import core
from pox.openflow import *
import pox.openflow.libopenflow_01 as of
from pox.lib.packet.arp import arp
from pox.lib.packet.ipv4 import ipv4
from pox.lib.addresses import EthAddr, IPAddr
log = core.getLogger()
import time
import random
import json # addition to read configuration from file

from pox.lib.util import dpid_to_str
from pox.lib.packet.ethernet import ethernet, ETHER_BROADCAST

LB_MAPPING_TIMOUT = 10

class SimpleLoadBalancer(object):

    
    # initialize SimpleLoadBalancer class instance
    def __init__(self, lb_mac = None, service_ip = None, 
                 server_ips = [], user_ip_to_group = {}, server_ip_to_group = {}):
        
        # add the necessary openflow listeners
        core.openflow.addListeners(self)

        # set class parameters
        self.lb_mac = lb_mac
        self.service_ip = service_ip
        self.server_ips = server_ips
        self.user_ip_to_group = user_ip_to_group
        self.server_ip_to_group = server_ip_to_group

        self.arpTable = {} # ip to mac-port


    # respond to switch connection up event
    def _handle_ConnectionUp(self, event):
        self.connection = event.connection
        log.debug("Switch %s has come up.", dpid_to_str(event.dpid))
        for ip in self.server_ips:
            self.send_proxied_arp_request(self.connection, ip)


    # update the load balancing choice for a certain client
    def update_lb_mapping(self, client_ip):
        color = self.user_ip_to_group[client_ip]
        while True:
            server_ip = self.server_ips[random.randint(0, 4)-1]
            server_color = self.server_ip_to_group[server_ip]
            if (server_color == color):
                return server_ip
    

    # send ARP reply "proxied" by the controller (on behalf of another machine in network)
    def send_proxied_arp_reply(self, packet, connection, outport, requested_mac):
        log.debug("\n->[ARP REPLY]\n\tSRC: %s %s (SERVICE)\n\tDST: %s %s\n", requested_mac, packet.payload.protodst, packet.src, packet.payload.protosrc)
        arp_reply = arp()
        arp_reply.opcode = arp.REPLY
        arp_reply.hwsrc = requested_mac
        arp_reply.protosrc = packet.payload.protodst
        arp_reply.hwdst = packet.src
        arp_reply.protodst = packet.payload.protosrc

        ether = ethernet()
        ether.type = ethernet.ARP_TYPE
        ether.src = requested_mac
        ether.dst = packet.src
        ether.payload = arp_reply

        msg = of.ofp_packet_out()
        msg.data = ether.pack()
        msg.actions.append(of.ofp_action_output(port = outport))
        connection.send(msg)


    # send ARP request "proxied" by the controller (so that the controller learns about another machine in network)
    def send_proxied_arp_request(self, connection, ip):
        log.debug("\n->[ARP REQUEST]\n\tSRC: SERVICE\n\tDST: %s\n", ip)
        arp_req = arp()
        arp_req.opcode = arp.REQUEST
        arp_req.hwsrc = self.lb_mac
        arp_req.protosrc = self.service_ip
        arp_req.hwdst = ETHER_BROADCAST
        arp_req.protodst = ip

        ether = ethernet()
        ether.type = ethernet.ARP_TYPE
        ether.src = self.lb_mac
        ether.dst = ETHER_BROADCAST
        ether.payload = arp_req

        msg = of.ofp_packet_out()
        msg.data = ether.pack()
        msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
        connection.send(msg)
 

    # install flow rule from a certain client to a certain server
    def install_flow_rule_client_to_server(self, connection, outport, client_ip, server_ip, buffer_id=of.NO_BUFFER):
        log.debug("\n[FLOW RULE ADD]\tCLIENT->SERVR\n\tCLIENT: %s\n\tSERVER: %s\n\tOUTPORT: %s\n", client_ip, server_ip, outport)

        match = of.ofp_match()
        match.dl_src = self.arpTable[client_ip]['mac']
        match.nw_src = client_ip
        match.dl_dst = self.lb_mac
        match.nw_dst = self.service_ip

        actions = []
        actions.append(of.ofp_action_dl_addr.set_dst(self.arpTable[server_ip]['mac']))
        actions.append(of.ofp_action_nw_addr.set_dst(server_ip))
        actions.append(of.ofp_action_output(port = outport))

        msg = of.ofp_flow_mod(
            command=of.OFPFC_ADD,
            idle_timeout=LB_MAPPING_TIMOUT,
            buffer_id=buffer_id,
            match=match,
            actions=actions
            )
        connection.send(msg)


    # install flow rule from a certain server to a certain client
    def install_flow_rule_server_to_client(self, connection, outport, server_ip, client_ip, buffer_id=of.NO_BUFFER):
        log.debug("\n[FLOW RULE ADD]\tSERVR->CLIENT\n\tSERVER: %s\n\tCLIENT: %s\n\tOUTPORT: %s\n", server_ip, client_ip, outport)

        match = of.ofp_match()
        match.dl_src = self.arpTable[server_ip]['mac']
        match.nw_src = server_ip
        match.dl_dst = self.arpTable[client_ip]['mac']
        match.nw_dst = client_ip

        actions = []
        actions.append(of.ofp_action_dl_addr.set_src(self.lb_mac))
        actions.append(of.ofp_action_nw_addr.set_src(self.service_ip))
        actions.append(of.ofp_action_output(port = outport))

        msg = of.ofp_flow_mod(
            command=of.OFPFC_ADD,
            idle_timeout=LB_MAPPING_TIMOUT,
            buffer_id=buffer_id,
            match=match,
            actions=actions
            )
        connection.send(msg)


    # main packet-in handling routine
    def _handle_PacketIn(self, event):
        packet = event.parsed
        connection = event.connection
        inport = event.port

        src_mac = packet.src
        dst_mac = packet.dst

        if packet.type == packet.ARP_TYPE:
            src_ip = packet.payload.protosrc
            dst_ip = packet.payload.protodst
            self.ARPactions(src_ip, src_mac, inport)

            if packet.payload.opcode == arp.REQUEST:
                log.debug("\n<-[ARP REQUEST]\n\tSRC: %s %s\n\tDST: %s %s\n", src_mac, src_ip, dst_mac, dst_ip)
                requested_mac = self.lb_mac
                if (src_ip in self.server_ips):
                    requested_mac = self.arpTable[dst_ip]['mac']
                self.send_proxied_arp_reply(packet, connection, inport, requested_mac)

            elif packet.payload.opcode == arp.REPLY:
                log.debug("\n<-[ARP REPLY]\n\tSRC: %s %s\n\tDST: %s %s\n", src_mac, src_ip, dst_mac, dst_ip)
                

            else:
                log.debug("ARP")

        elif packet.type == packet.IP_TYPE:
            src_ip = packet.payload.srcip
            dst_ip = packet.payload.dstip
            self.ARPactions(src_ip, src_mac, inport)

            log.debug("\n<-[IP]\n\tSRC: %s %s\n\tDST: %s %s\n", src_mac, src_ip, dst_mac, dst_ip)
            source_ip = packet.payload.srcip
            if (src_ip in self.server_ips):
                outport = self.arpTable[dst_ip]['port']
                self.install_flow_rule_server_to_client(connection, outport, src_ip, dst_ip, event.ofp.buffer_id)
            else:
                destination_server_ip = self.update_lb_mapping(src_ip)
                outport = self.arpTable[destination_server_ip]['port']
                self.install_flow_rule_client_to_server(connection, outport, src_ip, destination_server_ip, event.ofp.buffer_id)
                pass
        else:
            log.info("Unknown Packet type: %s" % packet.type)
            return
        return
    

    def ARPactions(self, src_ip, src_mac, inport):
        if (src_ip not in self.arpTable or self.arpTable[src_ip]['mac'] != src_mac or self.arpTable[src_ip]['port'] != inport):
            log.debug("\n+++ %s %s %s\n", src_ip, src_mac, inport)
            self.arpTable[src_ip] = {}
            self.arpTable[src_ip]['mac'] = src_mac
            self.arpTable[src_ip]['port'] = inport


# extra function to read json files
def load_json_dict(json_file):
    json_dict = {}    
    with open(json_file, 'r') as f:
        json_dict = json.load(f)
    return json_dict


# main launch routine
def launch(configuration_json_file):
    log.info("Loading Simple Load Balancer module")
    
    # load the configuration from file
    configuration_dict = load_json_dict(configuration_json_file)   

    # the service IP that is publicly visible from the users' side   
    service_ip = IPAddr(configuration_dict['service_ip'])

    # the load balancer MAC with which the switch responds to ARP requests from users/servers
    lb_mac = EthAddr(configuration_dict['lb_mac'])

    # the IPs of the servers
    server_ips = [IPAddr(x) for x in configuration_dict['server_ips']]    

    # map users (IPs) to service groups (e.g., 10.0.0.1 to 'red')    
    user_ip_to_group = {}
    for user_ip,group in configuration_dict['user_groups'].items():
        user_ip_to_group[IPAddr(user_ip)] = group

    # map servers (IPs) to service groups (e.g., 10.0.0.7 to 'blue')
    server_ip_to_group = {}
    for server_ip,group in configuration_dict['server_groups'].items():
        server_ip_to_group[IPAddr(server_ip)] = group

    # do the launch with the given parameters
    core.registerNew(SimpleLoadBalancer, lb_mac, service_ip, server_ips, user_ip_to_group, server_ip_to_group)
    log.info("Simple Load Balancer module loaded")
