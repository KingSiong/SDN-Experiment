# ryu-manager shortest_forward.py --observe-links
from dis import Instruction
import math
from tokenize import cookie_re
from click import command
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER, HANDSHAKE_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet, arp, ipv4
from ryu.controller import ofp_event
from ryu.topology import event
from ryu.topology.switches import LLDPPacket
from ryu.base.app_manager import lookup_service_brick
import sys
from network_awareness import NetworkAwareness
import networkx as nx
ETHERNET = ethernet.ethernet.__name__
ETHERNET_MULTICAST = "ff:ff:ff:ff:ff:ff"
IDLE_TIMEOUT = 30
HARD_TIMEOUT = 50
ARP = arp.arp.__name__
class ShortestForward(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {
        'network_awareness': NetworkAwareness
    }

    def __init__(self, *args, **kwargs):
        super(ShortestForward, self).__init__(*args, **kwargs)
        self.network_awareness = kwargs['network_awareness']
        self.weight = 'delay'
        self.mac_to_port = {}
        self.sw = {}
        self.path = None

    def add_flow(self, datapath, priority, match, actions, idle_timeout=0, hard_timeout=0):
        dp = datapath
        ofp = dp.ofproto
        parser = dp.ofproto_parser

        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(
            datapath=dp, priority=priority,
            idle_timeout=idle_timeout,
            hard_timeout=hard_timeout,
            match=match, instructions=inst)
        dp.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        ofp = dp.ofproto
        parser = dp.ofproto_parser

        dpid = dp.id
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth_pkt = pkt.get_protocol(ethernet.ethernet)
        arp_pkt = pkt.get_protocol(arp.arp)
        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)

        pkt_type = eth_pkt.ethertype

        # layer 2 self-learning
        dst_mac = eth_pkt.dst
        src_mac = eth_pkt.src


        if isinstance(arp_pkt, arp.arp):
            self.handle_arp(msg, in_port, dst_mac,src_mac, pkt, pkt_type)

        if isinstance(ipv4_pkt, ipv4.ipv4):
            self.handle_ipv4(msg, ipv4_pkt.src, ipv4_pkt.dst, pkt_type)

    def handle_arp(self, msg, in_port, dst, src, pkt, pkt_type):
        #just handle loop here
        #just like your code in exp1 mission2
        dp = msg.datapath
        ofp = dp.ofproto
        parser = dp.ofproto_parser
        dpid = dp.id
        self.mac_to_port.setdefault(dpid, {})
        
        self.sw.setdefault((dpid, src, dst), None)
        if self.sw.get((dpid, src, dst)) == None:
            self.sw[(dpid, src, dst)] = in_port
        elif self.sw[(dpid, src, dst)] != in_port:
            return
        
        self.mac_to_port[dpid][src] = in_port
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofp.OFPP_FLOOD

        actions = [dp.ofproto_parser.OFPActionOutput(out_port)]

        if out_port != ofp.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_type=pkt_type)
            self.add_flow(dp, 1, match, actions, IDLE_TIMEOUT, HARD_TIMEOUT)

        data = None
        if msg.buffer_id == ofp.OFP_NO_BUFFER:
            data = msg.data

        out = dp.ofproto_parser.OFPPacketOut(
            datapath = dp, buffer_id = msg.buffer_id, in_port = in_port,
            actions = actions, data = data)
        dp.send_msg(out)

    def handle_ipv4(self, msg, src_ip, dst_ip, pkt_type):
        parser = msg.datapath.ofproto_parser

        dpid_path = self.network_awareness.shortest_path(src_ip, dst_ip, weight=self.weight)
        if not dpid_path:
            return

        self.path = dpid_path

        # get port path:  h1 -> in_port, s1, out_port -> h2
        port_path = []
        for i in range(1, len(dpid_path) - 1):
            in_port = self.network_awareness.link_info[(dpid_path[i], dpid_path[i - 1])]
            out_port = self.network_awareness.link_info[(dpid_path[i], dpid_path[i + 1])]
            port_path.append((in_port, dpid_path[i], out_port))
        self.show_path(src_ip, dst_ip, port_path)
        # calc path delay


        # send flow mod
        for node in port_path:
            in_port, dpid, out_port = node
            self.send_flow_mod(parser, dpid, pkt_type, src_ip, dst_ip, in_port, out_port)
            self.send_flow_mod(parser, dpid, pkt_type, dst_ip, src_ip, out_port, in_port)

        # send packet_out
        _, dpid, out_port = port_path[-1]
        dp = self.network_awareness.switch_info[dpid]
        actions = [parser.OFPActionOutput(out_port)]
        out = parser.OFPPacketOut(
            datapath=dp, buffer_id=msg.buffer_id, in_port=in_port, actions=actions, data=msg.data)
        dp.send_msg(out)

    def send_flow_mod(self, parser, dpid, pkt_type, src_ip, dst_ip, in_port, out_port):
        dp = self.network_awareness.switch_info[dpid]
        match = parser.OFPMatch(
            in_port=in_port, eth_type=pkt_type, ipv4_src=src_ip, ipv4_dst=dst_ip)
        actions = [parser.OFPActionOutput(out_port)]
        self.add_flow(dp, 1, match, actions, IDLE_TIMEOUT, HARD_TIMEOUT)

    def show_path(self, src, dst, port_path):
        self.logger.info('path: {} -> {}'.format(src, dst))
        path = src + ' -> '
        for node in port_path:
            path += '{}:s{}:{}'.format(*node) + ' -> '
        path += dst
        self.logger.info(path)
    
    def delete_flow(self, dp, idle_timeout=0, hard_timeout=0):
        ofp = dp.ofproto
        parser = dp.ofproto_parser

        for dst in self.mac_to_port[dp.id].keys():
            match = parser.OFPMatch(eth_dst=dst)
            mod = parser.OFPFlowMod(
                datapath=dp, cookie=0, cookie_mask=0, table_id=0, command=ofp.OFPFC_DELETE,
                idle_timeout=idle_timeout, hard_timeout=hard_timeout, priority=1, buffer_id=ofp.OFP_NO_BUFFER, 
                out_port=ofp.OFPP_ANY, out_group=ofp.OFPG_ANY, flags=ofp.OFPFF_SEND_FLOW_REM, 
                match=match, 
                instructions=None)
            dp.send_msg(mod)

    def del_flow(self, datapath, priority, match, out_port, idle_timeout=0, hard_timeout=0):
        dp = datapath
        ofp = dp.ofproto
        parser = dp.ofproto_parser

        mod = parser.OFPFlowMod(datapath=dp, cookie=0, cookie_mask=0, table_id=0,
                command=ofp.OFPFC_DELETE,
                idle_timeout=idle_timeout, hard_timeout=hard_timeout,
                priority=priority,
                buffer_id=ofp.OFP_NO_BUFFER,
                out_port=out_port, out_group=ofp.OFPG_ANY, flags=ofp.OFPFF_SEND_FLOW_REM,
                match=match,
                instructions=None)
        dp.send_msg(mod)

    def sup_del_flow(self, dp, match, priority=1):
        ofp = dp.ofproto
        parser = dp.ofproto_parser
        mod = parser.OFPFlowMod(datapath=dp, cookie=0, cookie_mask=0, table_id=0,
                command=ofp.OFPFC_DELETE,
                idle_timeout=0, hard_timeout=0,
                priority=priority,
                buffer_id=ofp.OFP_NO_BUFFER,
                out_port=ofp.OFPP_ANY, out_group=ofp.OFPG_ANY, flags=ofp.OFPFF_SEND_FLOW_REM,
                match=match,
                instructions=None)
        dp.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def port_status_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        ofp = dp.ofproto
        parser = dp.ofproto_parser

        if msg.reason == ofp.OFPPR_MODIFY:
            reason = 'MODIFY'
            if msg.desc.state == ofp.OFPPS_LINK_DOWN or msg.desc.state == ofp.OFPPS_LIVE:
                self.sw.clear()
                if dp.id in self.path:
                    # arp flow_tables
                    for i in range(1, len(self.path) - 1):
                        now_dpid = self.path[i]
                        now_dp = self.network_awareness.switch_info[now_dpid]
                        if now_dpid in self.mac_to_port:
                            self.delete_flow(now_dp)
                            del self.mac_to_port[now_dpid]
                    # ipv4 flow_tables
                    for i in range(1, len(self.path) - 1):
                        in_port = self.network_awareness.link_info[(self.path[i], self.path[i - 1])]
                        out_port = self.network_awareness.link_info[(self.path[i], self.path[i + 1])]
                        dpid = self.path[i]
                        dp = self.network_awareness.switch_info[dpid]
                        match = parser.OFPMatch(in_port=in_port, eth_type=0x0800, ipv4_src=self.path[0], ipv4_dst=self.path[-1])
                        self.del_flow(dp, 1, match, out_port, IDLE_TIMEOUT, HARD_TIMEOUT)
                        match = parser.OFPMatch(in_port=out_port, eth_type=0x0800, ipv4_src=self.path[-1], ipv4_dst=self.path[0])
                        self.del_flow(dp, 1, match, in_port, IDLE_TIMEOUT, HARD_TIMEOUT)
                self.logger.info('OFPPortStatus received: reason=%s, desc=%s',
                        reason, msg.desc)

    # @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    # def port_status_handler(self, ev):
    #     msg = ev.msg
    #     dp = msg.datapath
    #     ofp = dp.ofproto
    #     parser = dp.ofproto_parser

    #     if msg.reason == ofp.OFPPR_MODIFY:
    #         reason = 'MODIFY'
    #         if msg.desc.state == ofp.OFPPS_LINK_DOWN or msg.desc.state == ofp.OFPPS_LIVE:
    #             self.sw.clear()
    #             self.mac_to_port.clear()
    #             for dp in self.network_awareness.switch_info.values():
    #                 match = parser.OFPMatch(eth_type=0x0800)
    #                 self.sup_del_flow(dp, match)
    #                 match = parser.OFPMatch(eth_type=0x0806)
    #                 self.sup_del_flow(dp, match)

    #             self.logger.info('OFPPortStatus received: reason=%s, desc=%s',
    #                     reason, msg.desc)