from cmath import exp
from curses.ascii import CR
from inspect import CORO_RUNNING
from tkinter import W
import networkx as nx
from networkx.algorithms import tree
from operator import attrgetter
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import arp
from ryu.lib.packet import tcp
from ryu.lib import hub
from ryu.topology import event, switches
from ryu.topology.api import get_switch, get_link
from ryu.lib.packet import ether_types
from collections import defaultdict
from ryu.topology.api import get_host, get_link, get_switch
from queue import Queue
ETHERNET = ethernet.ethernet.__name__
ETHERNET_MULTICAST = "ff:ff:ff:ff:ff:ff"
ARP = arp.arp.__name__
IDLE_TIMEOUT = 10
HARD_TIMEOUT = 30
BANDWIDTH_INF = 0x7fffff
BANDWIDTH_MAX = 1000
CRUCIAL = False


class Workload(app_manager.RyuApp):

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    
    def __init__(self, *args, **kwargs):
        super(Workload, self).__init__(*args, **kwargs)
        self.topology_api_app = self
        self.datapaths={} #dpid: datapath
        self.port_stats={}# (dpid,port_no):a list of port_stats
        self.link_info = {}  # (s1, s2): s1.port
        self.port_link={} # s1,port:s1,s2
        self.port_info = {}  # dpid: (ports linked hosts)
        self.topo_map = nx.Graph()
        self.workload_thread = hub.spawn(self._count_workload)
        # self.show_workload_thread = hub.spawn(self._show_workload)
        self.mac_to_port={}
        self.sw = {} # use it to avoid arp loop
        self.weight='bandwidth'
        #you need to store workload of every port here
        self.workload={} # dpid: {port_no : work_load}
        self.mst = nx.Graph()
    
    def show_workload(self):
        print('*' * 80)
        for dpid in self.workload.keys():
            print("dpid {}: ".format(dpid), end="")
            for port, load in self.workload[dpid].items():
                print("<port {}: {:.12f}> ".format(port, load[2]), end="")
            print("")

    def _count_workload(self):
        while True:
            for dp in self.datapaths.values():
                self._send_request(dp)
            self.get_topology(None)
            self.show_workload()
            hub.sleep(4)

    def _send_request(self,datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        datapath.send_msg(req)
        
    @set_ev_cls(ofp_event.EventOFPStateChange,[MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if not datapath.id in self.datapaths:
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                del self.datapaths[datapath.id]
        
    def add_flow(self, dp, p, match, actions, idle_timeout=0, hard_timeout=0):
        ofproto = dp.ofproto
        parser = dp.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        mod = parser.OFPFlowMod(datapath=dp, priority=p,
                                idle_timeout=idle_timeout,
                                hard_timeout=hard_timeout,
                                match=match, instructions=inst)
        dp.send_msg(mod)
        
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER) 
    def switch_features_handler(self, ev): 
        msg = ev.msg 
        dp = msg.datapath 
        ofp = dp.ofproto 
        parser = dp.ofproto_parser
        match = parser.OFPMatch() 
        actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER,ofp.OFPCML_NO_BUFFER)] 
        self.add_flow(dp, 0, match, actions)
    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        body = ev.msg.body
        dpid = ev.msg.datapath.id
        self.workload.setdefault(dpid, {})
        #you need to code here to finish mission1
        #of course, you can define new function as you wish

        for stat in sorted(body, key=attrgetter('port_no')):
            port_no = stat.port_no
            if port_no != ofproto_v1_3.OFPP_LOCAL:
                self.workload[dpid].setdefault(port_no, [0, 0, 0])
                key = (dpid, port_no)
                value = (stat.tx_bytes, stat.rx_bytes,
                        stat.duration_sec, stat.duration_nsec)
                
                self.workload[dpid][port_no][2] = \
                    ((stat.tx_bytes + stat.rx_bytes) * 8 * 1e-6 - self.workload[dpid][port_no][0]) \
                         / (stat.duration_sec + stat.duration_nsec * 1e-9 - self.workload[dpid][port_no][1])
                self.workload[dpid][port_no][0] = (stat.tx_bytes + stat.rx_bytes) * 8 * 1e-6
                self.workload[dpid][port_no][1] = stat.duration_sec + stat.duration_nsec * 1e-9
                # print("workload: {}, {}: {}".format(dpid, port_no, self.workload[dpid][port_no]))
                # print(key, end=':')
                # print(value)

############################detect topology############################
    def get_topology(self, ev):
        """
            Gett topology info to calculate shortest paths.
        """
        _hosts, _switches, _links = None, None, None
        hosts = get_host(self)
        switches = get_switch(self)
        links = get_link(self)

        # update topo_map when topology change
        # if [str(x) for x in hosts] == _hosts and [str(x) for x in switches] == _switches and [str(x) for x in
        #                                                                                       links] == _links:
        #     return 
        # _hosts, _switches, _links = [str(x) for x in hosts], [str(x) for x in switches], [str(x) for x in links]
        self.topo_map.clear()
        for switch in switches:
            self.port_info.setdefault(switch.dp.id, set())
            # record all ports
            for port in switch.ports:
                self.port_info[switch.dp.id].add(port.port_no)

        for host in hosts:
            # take one ipv4 address as host id
            if host.ipv4:
                self.link_info[(host.port.dpid, host.ipv4[0])] = host.port.port_no
                self.link_info[(host.ipv4[0], host.port.dpid)] = 0
                self.topo_map.add_edge(host.ipv4[0], host.port.dpid, hop=1, delay=0, bandwidth=BANDWIDTH_INF, is_host=True)
        for link in links:
            # delete ports linked switches
            self.port_info[link.src.dpid].discard(link.src.port_no)
            self.port_info[link.dst.dpid].discard(link.dst.port_no)

            # s1 -> s2: s1.port, s2 -> s1: s2.port
            self.port_link[(link.src.dpid, link.src.port_no)] = (link.src.dpid, link.dst.dpid)
            self.port_link[(link.dst.dpid, link.dst.port_no)] = (link.dst.dpid, link.src.dpid)

            self.link_info[(link.src.dpid, link.dst.dpid)] = link.src.port_no
            self.link_info[(link.dst.dpid, link.src.dpid)] = link.dst.port_no
            _min = min(self.workload[link.src.dpid][link.src.port_no][2], \
                self.workload[link.src.dpid][link.src.port_no][2])
            self.topo_map.add_edge(link.src.dpid, link.dst.dpid, hop=1, bandwidth=BANDWIDTH_MAX - _min, is_host=False)

        print(self.topo_map.edges)
        self.get_mst()

    def get_mst(self):
        mst_edge = tree.maximum_spanning_edges(self.topo_map, algorithm="kruskal", weight='bandwidth', data=True)
        self.mst.clear()
        for edge in mst_edge:
            self.mst.add_edge(edge[0], edge[1], bandwidth=edge[2]['bandwidth'])
            # print("bandwidth: {}".format(edge[2]['bandwidth']))
        # print(self.mst.nodes)
        # print(self.mst.edges)

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

############################deal with loop############################
    def handle_arp(self, msg, in_port, dst,src, pkt, pkt_type):
    #just your code in exp1 mission2
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

############################get shortest(hop) path############################
    def handle_ipv4(self, msg, src_ip, dst_ip, pkt_type):
        parser = msg.datapath.ofproto_parser

        dpid_path = []
        if CRUCIAL == True:
            dpid_path = self.crucial_point_path(src_ip, dst_ip, '10.0.0.21')
        if not dpid_path:
            dpid_path = self.shortest_path(src_ip, dst_ip, weight=self.weight)

        if not dpid_path:
            return

        self.path=dpid_path
        # get port path:  h1 -> in_port, s1, out_port -> h2
        port_path = []
        for i in range(1, len(dpid_path) - 1):
            in_port = self.link_info[(dpid_path[i], dpid_path[i - 1])]
            out_port = self.link_info[(dpid_path[i], dpid_path[i + 1])]
            port_path.append((in_port, dpid_path[i], out_port))
        self.show_path(src_ip, dst_ip, port_path)


        # send flow mod
        for node in port_path:
            in_port, dpid, out_port = node
            try:
                self.send_flow_mod(parser, dpid, pkt_type, src_ip, dst_ip, in_port, out_port)
                self.send_flow_mod(parser, dpid, pkt_type, dst_ip, src_ip, out_port, in_port)
            except:
                continue

        # send packet_out
        _, dpid, out_port = port_path[-1]
        dp = self.datapaths[dpid]
        actions = [parser.OFPActionOutput(out_port)]
        out = parser.OFPPacketOut(
            datapath=dp, buffer_id=msg.buffer_id, in_port=in_port, actions=actions, data=msg.data)
        dp.send_msg(out)
    def shortest_path(self, src, dst, weight='hop'):
        topo = self.topo_map
        if weight == 'bandwidth':
            topo = self.mst
        try:
            path = list(nx.dijkstra_path(topo, src, dst, weight=weight))
            return path
        except:
            self.logger.info('host not find/no path')
    def send_flow_mod(self, parser, dpid, pkt_type, src_ip, dst_ip, in_port, out_port):
        dp = self.datapaths[dpid]
        match = parser.OFPMatch(
            in_port=in_port, eth_type=pkt_type, ipv4_src=src_ip, ipv4_dst=dst_ip)
        actions = [parser.OFPActionOutput(out_port)]
        self.add_flow(dp, 5, match, actions, IDLE_TIMEOUT, HARD_TIMEOUT)

    def show_path(self, src, dst, port_path):
        self.logger.info('path: {} -> {}'.format(src, dst))
        path = src + ' -> '
        for node in port_path:
            if node[0] == 0 and node[2] == 0:
                path += '{}:{}:{}'.format(*node) + ' -> '
            else:
                path += '{}:s{}:{}'.format(*node) + ' -> '
        path += dst
        self.logger.info(path)

    def crucial_point_path(self, src, dst, way_point):
        q = Queue(maxsize=0)
        E = {}
        vis = {}
        edges = list(self.topo_map.edges)
        for edge in edges:
            vis.setdefault(edge[0], False)
            vis.setdefault(edge[1], False)
            E.setdefault(edge[0], [])
            E.setdefault(edge[1], [])
            E[edge[0]].append(edge[1])
            E[edge[1]].append(edge[0])
        path = []
        try:
            dst_dpid = E[dst][0]
            way_point_dpid = E[way_point][0]
            q.put((src, [src]))
            vis[src] = True
            while q.empty() == False:
                u = q.get()
                if u[0] == way_point:
                    path = u[1]
                    break
                for v in E[u[0]]:
                    if vis[v] == True:
                        continue
                    vis[v] = True
                    if v == dst_dpid:
                        continue
                    q.put((v, u[1] + [v]))
            if not path:
                return []
            for u in vis.keys():
                vis[u] = False
            while q.empty() == False:
                q.get()
            q.put((way_point, path))
            vis[way_point] = True
            while q.empty() == False:
                u = q.get()
                if u[0] == dst:
                    return u[1]
                for v in E[u[0]]:
                    if vis[v] == True:
                        continue
                    vis[v] = True
                    q.put((v, u[1] + [v]))
        except:
            return []
        return []
