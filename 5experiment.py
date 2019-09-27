#!/usr/bin/env python
# -*- coding: utf-8 -*- 
# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License. CHECKING VERSION CHECKING


import os, sys
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ether_types, ipv4, in_proto, tcp, arp,udp,icmp
from ryu.lib import snortlib
from ryu.controller.dpset import DPSet
import time


import array


class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {'snortlib': snortlib.SnortLib, 'dpset':DPSet}

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.snort = kwargs['snortlib']
        #pigrelay
        self.snort_port = 5
        #Listen on network socket
        socket_config = {'unixsock': False}
        self.snort.set_config(socket_config)
        self.snort.start_socket_server()
        self.dpset = kwargs['dpset']
        self.dpid = None
        self.datapath = None
        self.ports = []
        self.mac_to_port = {}
        self.initAllowed()
        self.macToInterFace = {"54:b2:03:10:b9:a8": 2, "54:b2:03:0e:9e:65": 1}
    
    #
    def initAllowed(self):
        self.allowed = {"IP":[],"TCP":[]}
        self.allowed["IP"].append("192.168.1.100")
        self.allowed["IP"].append("192.168.1.99")
        self.allowed["IP"].append("192.168.1.98")
        self.allowed["TCP"].extend(["5001", "5002", "31337"])
        
    #Run when Snort alerts Ryu    
    @set_ev_cls(snortlib.EventAlert, MAIN_DISPATCHER)
    def _dump_alert(self, ev):
        msg = ev.msg
        pkt = packet.Packet(array.array('B', msg.pkt))
        ofproto = self.datapath.ofproto
        parser = self.datapath.ofproto_parser
        eth = pkt.get_protocol(ethernet.ethernet)
        ip4 = pkt.get_protocol(ipv4.ipv4)
        actions = []
        match = parser.OFPMatch(eth_src=eth.src)
        self.add_flow(self.datapath, 99, match, actions)
        match = parser.OFPMatch(eth_dst=eth.src)
        self.add_flow(self.datapath, 99, match, actions)
                        
    #Run when connecting switch with Ryu, as a response to SwitchFeaturesRequest
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        msg = ev.msg
        datapath = ev.msg.datapath
        self.datapath = datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        #Default flow for miss match, sends incoming packet to Ryu
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
        #Handle arp as legacy
        actions = [parser.OFPActionOutput(ofproto.OFPP_NORMAL)]
        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_ARP)
        self.add_flow(datapath,98,match,actions)
        
    #Helper function to add a flow entry    
    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
                                             
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                priority=priority, match=match,
                                instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                        match=match, instructions=inst)
        
        datapath.send_msg(mod)

    #Run when Ryu receives a PACKET_IN
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        
        if eth.ethertype == ether_types.ETH_TYPE_IP:
            ip = pkt.get_protocol(ipv4.ipv4)
            srcip = ip.src
            dstip = ip.dst
            dst1 = eth.dst
            src1 = eth.src
            proto = ip.proto
            
            if srcip not in self.allowed["IP"]:
                match = parser.OFPMatch(eth_src=src1)
                actions = []
                self.add_flow(self.datapath, 99, match, actions)
                match = parser.OFPMatch(eth_dst=src1)
                self.add_flow(self.datapath, 99, match, actions)
                return

            if proto == in_proto.IPPROTO_TCP:
                t = pkt.get_protocol(tcp.tcp)
                tcpSrc = t.src_port
                tcpDst = t.dst_port
              
                if str(t.dst_port) not in self.allowed["TCP"]:
                    match =  parser.OFPMatch(eth_src=src1)
                    actions = []
                    self.add_flow(self.datapath, 99, match,actions)
                    matchDst = parser.OFPMatch(eth_dst=src1)
                    self.add_flow(datapath, 99, matchDst, actions)                    
                    return
                else:        
                    match = parser.OFPMatch(eth_type=0x0800, ip_proto=6,ipv4_dst=dstip,tcp_dst=tcpDst)
                    actions = [parser.OFPActionOutput(ofproto.OFPP_NORMAL)]
                    self.add_flow(self.datapath, 99, match, actions)
                    return
                
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        
        
        #-------------------------------------------Original Code---------------------------------------------------
        dst = eth.dst
        src = eth.src
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        # learn a mac address
        self.mac_to_port[dpid][src] = in_port
        print("We missed its this type: ", eth.ethertype)
        

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD
        
        actions = [parser.OFPActionOutput(out_port)]
        
        #install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            
            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                #msg.buffer_id applies the flow to the msg stored in the switch directly
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)




