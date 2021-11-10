from ryu.base import app_manager
from ryu.controller import mac_to_port
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.mac import haddr_to_bin
from ryu.lib.packet import packet
from ryu.lib.packet import arp
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import ipv6

from ryu.lib.packet import tcp
from ryu.lib.packet import udp

from ryu.lib.packet import ether_types
from ryu.lib import dpid, mac, ip
from ryu.topology.api import get_switch, get_link
from ryu.app.wsgi import ControllerBase
from ryu.topology import event

from ryu.lib import dpid as dpid_lib
from collections import defaultdict
from operator import itemgetter, attrgetter

from ryu.controller import dpset

from ryu.lib import hub






import os
import random
import time
import logging


# Cisco Reference bandwidth = 1 Gbps
REFERENCE_BW = 10000000


DEFAULT_BW = 10000000


MAX_PATHS = 10

VERBOSE = 1

DEBUGING = 0

# logging.basicConfig(level = logging.INFO)

class ProjectController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]


    def __init__(self, *args, **kwargs):
        super(ProjectController, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.topology_api_app = self
        self.datapath_list = {}
        self.arp_table = {}
        self.switches = []
        self.hosts = {}
        self.multipath_group_ids = {}
        self.all_group_id = {}
        self.group_id_count =0
        self.group_ids = []
        self.adjacency = defaultdict(dict)
        self.bandwidths = defaultdict(lambda: defaultdict(lambda: DEFAULT_BW))
        self.sw_port = {}
        self.count = 0
        
        if DEBUGING == 1:
            self.logger.setLevel(logging.DEBUG)
        else:
            self.logger.setLevel(logging.INFO)
            

        
        # monitor
        self.sleep = 1
        # self.datapaths = {}
        self.monitor_thread = hub.spawn(self._monitor)
        self.tx_pkt_cur = {}    # currently monitoring TX packets
        self.tx_byte_cur = {}   # currently monitoring TX bytes
        self.tx_pkt_int = {}    # TX packets in the last monitoring interval
        self.tx_byte_int = {}    # TX bytes in the last monitoring interval
    
        
    def get_paths(self, src, dst):
        '''
        Get all paths from src to dst using DFS algorithm    
        '''
        print("################################################")
        if src == dst:
            # host target is on the same switch
            return [[src]]
        paths = []
        stack = [(src, [src])]
        
        if VERBOSE == 1:
            print("--stack",stack)
            print("---adjacency",self.adjacency)
            
        while stack:
            # stack pop the last item => LIFO
            (node, path) = stack.pop()
            
            if VERBOSE == 1:
                print((node, path))
                # set is sorted
                print("---adjacency[",node,']:',self.adjacency[node].keys())
                
            for next in set(self.adjacency[node].keys()) - set(path):
                if next is dst:
                    paths.append(path + [next])
                    
                    if VERBOSE == 1:
                        print("-paths",paths)
                else:
                    stack.append((next, path + [next]))
                    
                    if VERBOSE == 1:
                        print("--stack",stack)
        print("################################################")
        print("Available paths from ", src, " to ", dst, " : ", paths)
        
        return paths


    def get_link_cost(self, s1, s2):
        '''
        Get the link cost between two switches 
        '''
        e1 = self.adjacency[s1][s2]
        e2 = self.adjacency[s2][s1]
        # print('------')
        # print(e1,e2)
        # print(not self.tx_byte_int[s1][e1] or not self.tx_byte_int[s2][e2])
        if not self.tx_byte_int or not self.tx_byte_int.setdefault(s1,{}):
        # print(self.tx_byte_int)
            print("No bandwitdh")
            bl = min(self.bandwidths[s1][e1], self.bandwidths[s2][e2])
            print(bl)
            
        else:
            print("bandwitdh")
            bl = min(self.tx_byte_int[s1][e1], self.tx_byte_int[s2][e2])
            
            print(bl)
            
        # ew = REFERENCE_BW/bl
        ew = bl
        print("linkcost",ew)
        return ew


    def get_path_cost(self, path):
        '''
        Get the path cost
        '''
        cost = 0
        for i in range(len(path) - 1):
            cost += self.get_link_cost(path[i], path[i+1])
        return cost


    def get_optimal_paths(self, src, dst):
        '''
        Get the n-most optimal paths according to MAX_PATHS
        '''
        paths = self.get_paths(src, dst)
        paths_count = len(paths) if len(
            paths) < MAX_PATHS else MAX_PATHS
        return sorted(paths, key=lambda x: self.get_path_cost(x))[0:(paths_count)]


    def add_ports_to_paths(self, paths, first_port, last_port):
        '''
        Add the ports that connects the switches for all paths
        '''
        paths_p = []
        for path in paths:
            p = {}
            in_port = first_port
            # print("-----")
            # print(path[:-1],"\n", path[1:])
            for s1, s2 in zip(path[:-1], path[1:]):
                out_port = self.adjacency[s1][s2]
                # print('s',s1,s2,out_port)
                p[s1] = (in_port, out_port)
                in_port = self.adjacency[s2][s1]
            p[path[-1]] = (in_port, last_port)
            paths_p.append(p)
        # print(paths_p)
        return paths_p


    def generate_openflow_gid(self,src,dst):
        '''
        Returns a random OpenFlow group id
        '''
        n = self.group_id_count + 1
        
        while n in self.group_ids:
            n = n + 1
            
        if n < 10:
            s = "{}".format(n)
        if n>=10:
            s = "{}".format(n)
        self.group_ids.append(n)
        # self.all_group_id.append(int(s))
        return int(s)


    def install_paths(self, src, first_port, dst, last_port, ip_src, ip_dst):
        computation_start = time.time()
        paths = self.get_optimal_paths(src, dst)
        pw = []
        for path in paths:
            pw.append(self.get_path_cost(path))
            print(path, "cost = ", pw[len(pw) - 1])
        sum_of_pw = sum(pw) * 1.0
        paths_with_ports = self.add_ports_to_paths(paths, first_port, last_port)
        switches_in_paths = set().union(*paths)
        # print(switches_in_paths)
        if VERBOSE == 1:
            print(paths_with_ports)
            # print(pw)
            print("#adjacency",self.adjacency)

        for node in switches_in_paths:

            dp = self.datapath_list[node]
            ofp = dp.ofproto
            ofp_parser = dp.ofproto_parser


            # pw is total cost of a path (path weight)
            # ports contain inport:(outport,pw)
            ports = defaultdict(list)
            actions = []
            i = 0


            for path in paths_with_ports:
                if node in path:
                    in_port = path[node][0]
                    out_port = path[node][1]
                    if (out_port, pw[i]) not in ports[in_port]:
                        ports[in_port].append((out_port, pw[i]))
                i += 1
            if VERBOSE == 1:
                print("-------------------------------")
                print("\tnode {}: ports{}".format(node,ports) ) 

            for in_port in ports:
                # Ipv4
                match_ip = ofp_parser.OFPMatch(
                    eth_type=0x0800, 
                    ipv4_src=ip_src, 
                    ipv4_dst=ip_dst
                )
                # ARP
                match_arp = ofp_parser.OFPMatch(
                    eth_type=0x0806, 
                    arp_spa=ip_src, 
                    arp_tpa=ip_dst
                )
                


                out_ports = ports[in_port]
                # print("pos4type",type(out_ports[0]))
                # print("pos4type",type(out_ports[0][0]),type(out_ports[0][1]))
            
             
                dup_port = {}
                for i in range(0,len(out_ports)-1):
                    for j in range(i+1,len(out_ports)):
                        if out_ports[i][0] == out_ports[j][0]:
                            if out_ports[i][0] not in dup_port:
                                dup_port.setdefault(out_ports[i][0],out_ports[i][1]+out_ports[j][1])
                            else:
                                dup_port[out_ports[i][0]]+=out_ports[j][1]
                                
                print("dup: ", dup_port)
                
                del_port = out_ports.copy()
             
                for i in dup_port.keys():
                    a=0
                    for j in range(len(del_port)):
                        if i == del_port[j][0]:
                            out_ports.pop(a)
                            a = a - 1
                        a = a+1
                    del_port = out_ports.copy()
                            
                    out_ports.append((i, dup_port[i]))
                # print("pos",out_ports_1)
                # print("postype",type(out_ports_1[0]))
                # print("postype",type(out_ports_1[0][0]),type(out_ports_1[0][1]))
                          
                                
                            
                    
                    
                if VERBOSE == 1:
                    print("\t\t-Outport",out_ports )


                if len(out_ports) > 1:
                    group_id = None
                    group_new = False
                    
                    

                    if (node, src, dst) not in self.multipath_group_ids:
                        self.all_group_id.setdefault(src,{})
                        group_new = True
                        self.multipath_group_ids[
                            node, src, dst] = self.generate_openflow_gid(src,dst)
                        self.all_group_id[src].setdefault(self.multipath_group_ids[
                            node, src, dst], {})
                        
                    group_id = self.multipath_group_ids[node, src, dst]


                    buckets = []
                    if VERBOSE == 1:
                        print("node at ",node," out ports : ",out_ports)
                        print("groupid",group_id)
                        
                        
                    for port, weight in out_ports:
                        bucket_weight = int(round((1 - weight/sum_of_pw) * 10))
                        # self.all_group_id[group_id].setdefault(src,{})
                        self.all_group_id[src][group_id][port]=bucket_weight
                        # bucket_weight = 50
                        # print(self.all_group_id)
                        
                        if VERBOSE == 1:
                            print("bucketw of node{},outport{}:{}".format(node,port,bucket_weight))
                        bucket_action = [ofp_parser.OFPActionOutput(port)]
                        buckets.append(
                            ofp_parser.OFPBucket(
                                weight=bucket_weight,
                                watch_port=port,
                                watch_group=ofp.OFPG_ANY,
                                actions=bucket_action
                            )
                        )


                    if group_new:
                        req = ofp_parser.OFPGroupMod(
                            dp, ofp.OFPGC_ADD, ofp.OFPGT_SELECT, group_id,
                            buckets
                        )
                        dp.send_msg(req)
                    else:
                        req = ofp_parser.OFPGroupMod(
                            dp, ofp.OFPGC_MODIFY, ofp.OFPGT_SELECT,
                            group_id, buckets)
                        dp.send_msg(req)


                    actions = [ofp_parser.OFPActionGroup(group_id)]


                    self.add_flow(dp, 32768, match_ip, actions)
                    self.add_flow(dp, 1, match_arp, actions)


                elif len(out_ports) == 1:
                    actions = [ofp_parser.OFPActionOutput(out_ports[0][0])]


                    self.add_flow(dp, 32768, match_ip, actions)
                    self.add_flow(dp, 1, match_arp, actions)
        print("Path installation finished in ", time.time() - computation_start )
        print(paths_with_ports[0][src][1])
        return paths_with_ports[0][src][1]

    def old_install_paths(self, src, first_port, dst, last_port, ip_src, ip_dst):
        computation_start = time.time()
        paths = self.get_optimal_paths(src, dst)
        pw = []
        for path in paths:
            pw.append(self.get_path_cost(path))
            print(path, "cost = ", pw[len(pw) - 1])
        sum_of_pw = sum(pw) * 1.0
        paths_with_ports = self.add_ports_to_paths(paths, first_port, last_port)
        switches_in_paths = set().union(*paths)
        # print(switches_in_paths)
        if VERBOSE == 1:
            print(paths_with_ports)
            # print(pw)
            print("#adjacency",self.adjacency)

        for node in switches_in_paths:

            dp = self.datapath_list[node]
            ofp = dp.ofproto
            ofp_parser = dp.ofproto_parser


            # pw is total cost of a path (path weight)
            # ports contain inport:(outport,pw)
            ports = defaultdict(list)
            actions = []
            i = 0


            for path in paths_with_ports:
                if node in path:
                    in_port = path[node][0]
                    out_port = path[node][1]
                    if (out_port, pw[i]) not in ports[in_port]:
                        ports[in_port].append((out_port, pw[i]))
                i += 1
            if VERBOSE == 1:
                print("-------------------------------")
                print("\tnode {}: ports{}".format(node,ports) ) 

            for in_port in ports:
                # Ipv4
                match_ip = ofp_parser.OFPMatch(
                    eth_type=0x0800, 
                    ipv4_src=ip_src, 
                    ipv4_dst=ip_dst
                )
                # ARP
                match_arp = ofp_parser.OFPMatch(
                    eth_type=0x0806, 
                    arp_spa=ip_src, 
                    arp_tpa=ip_dst
                )


                out_ports = ports[in_port]
               
                            
                    
                    
                if VERBOSE == 1:
                    print("\t\t-Outport",out_ports )


                if len(out_ports) > 1:
                    group_id = None
                    group_new = False
                    
                    

                    if (node, src, dst) not in self.multipath_group_ids:
                        self.all_group_id.setdefault(src,{})
                        group_new = True
                        self.multipath_group_ids[
                            node, src, dst] = self.generate_openflow_gid(src,dst)
                        self.all_group_id[src].setdefault(self.multipath_group_ids[
                            node, src, dst], {})
                        
                    group_id = self.multipath_group_ids[node, src, dst]


                    buckets = []
                    if VERBOSE == 1:
                        print("node at ",node," out ports : ",out_ports)
                        print("groupid",group_id)
                        
                        
                    for port, weight in out_ports:
                        bucket_weight = int(round((1 - weight/sum_of_pw) * 10))
                        # self.all_group_id[group_id].setdefault(src,{})
                        self.all_group_id[src][group_id][port]=bucket_weight
                        # bucket_weight = 50
                        # print(self.all_group_id)
                        
                        if VERBOSE == 1:
                            print("bucketw of node{},outport{}:{}".format(node,port,bucket_weight))
                        bucket_action = [ofp_parser.OFPActionOutput(port)]
                        buckets.append(
                            ofp_parser.OFPBucket(
                                weight=bucket_weight,
                                watch_port=port,
                                watch_group=ofp.OFPG_ANY,
                                actions=bucket_action
                            )
                        )


                    if group_new:
                        req = ofp_parser.OFPGroupMod(
                            dp, ofp.OFPGC_ADD, ofp.OFPGT_SELECT, group_id,
                            buckets
                        )
                        dp.send_msg(req)
                    else:
                        req = ofp_parser.OFPGroupMod(
                            dp, ofp.OFPGC_MODIFY, ofp.OFPGT_SELECT,
                            group_id, buckets)
                        dp.send_msg(req)


                    actions = [ofp_parser.OFPActionGroup(group_id)]


                    self.add_flow(dp, 32768, match_ip, actions)
                    self.add_flow(dp, 1, match_arp, actions)


                elif len(out_ports) == 1:
                    actions = [ofp_parser.OFPActionOutput(out_ports[0][0])]


                    self.add_flow(dp, 32768, match_ip, actions)
                    self.add_flow(dp, 1, match_arp, actions)
        print("Path installation finished in ", time.time() - computation_start )
        print(paths_with_ports[0][src][1])
        return paths_with_ports[0][src][1]
    


    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        # print "Adding flow ", match, actions
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
        
    

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def _switch_features_handler(self, ev):
        print("switch_features_handler is called")
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser


        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)



    @set_ev_cls(ofp_event.EventOFPPortDescStatsReply, MAIN_DISPATCHER)
    def port_desc_stats_reply_handler(self, ev):
        switch = ev.msg.datapath
        for p in ev.msg.body:
            self.bandwidths[switch.id][p.port_no] = p.curr_speed


    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # self.logger.info("PACKETIN %d" % (self.count))
        self.count += 1
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']


        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        arp_pkt = pkt.get_protocol(arp.arp)


        # avoid broadcast from LLDP
        if eth.ethertype == 35020:
            return


        if pkt.get_protocol(ipv6.ipv6):  # Drop the IPV6 Packets.
            match = parser.OFPMatch(eth_type=eth.ethertype)
            actions = []
            self.add_flow(datapath, 1, match, actions)
            return None


        dst = eth.dst
        src = eth.src
        dpid = datapath.id


        if src not in self.hosts:
            self.hosts[src] = (dpid, in_port)
            if VERBOSE == 1:
                print("-----------------------------------")
                print("\t\tHost_learned: ",self.hosts)
                print("-----------------------------------")

        out_port = ofproto.OFPP_FLOOD


        if arp_pkt:
            # print dpid, pkt
            if VERBOSE == 1:
                print("datapath id: "+str(dpid))
                print("port: "+str(in_port))
                print(("pkt_eth.dst: " + str(eth.dst)))
                print(("pkt_eth.src: " + str(eth.src)))
                print(("pkt_arp: " + str(arp_pkt)))
                print(("pkt_arp:src_ip: " + str(arp_pkt.src_ip)))
                print(("pkt_arp:dst_ip: " + str(arp_pkt.dst_ip)))
                print(("pkt_arp:src_mac: " + str(arp_pkt.src_mac)))
                print(("pkt_arp:dst_mac: " + str(arp_pkt.dst_mac)))
                # dst_mac will be 00:00:00:00:00:00 when host is unknown (ARPRequest)
            
            src_ip = arp_pkt.src_ip
            dst_ip = arp_pkt.dst_ip
            
            
            
            
            if arp_pkt.opcode == arp.ARP_REPLY:
                # ARP table IP - MAC
                self.arp_table[src_ip] = src
                h1 = self.hosts[src]
                h2 = self.hosts[dst]
                # if h1[1] not in self.sw_port[h1[0]]:
                #     self.sw_port[h1[0]].append(h1[1])
                #     # print('---------------------------port',self.sw_port)
                # if h2[1] not in self.sw_port[h2[0]]:
                #     self.sw_port[h2[0]].append(h2[1])
                #     # print('---------------------------port',self.sw_port)
                if h1[0] == 5:
                        print("dpid5")
                
                #Install path: dpid src, src in_port, dpid dst, dpid in_port, src_ip, dst_ip
                if VERBOSE == 1:
                    print("Installing: Src:{}, Src in_port{}. Dst:{}, Dst in_port:{}, Src_ip:{}, Dst_ip:{}".format(h1[0], h1[1], h2[0], h2[1], src_ip, dst_ip))
                out_port = self.install_paths(h1[0], h1[1], h2[0], h2[1], src_ip, dst_ip)
                self.install_paths(h2[0], h2[1], h1[0], h1[1], dst_ip, src_ip) # reverse
            elif arp_pkt.opcode == arp.ARP_REQUEST:
                if dst_ip in self.arp_table:
                    print("dst_ip found in arptable")
                    self.arp_table[src_ip] = src
                    dst_mac = self.arp_table[dst_ip]
                    h1 = self.hosts[src]
                    h2 = self.hosts[dst_mac]
                    if h1[0] == 5:
                        print("dpid5")
                    out_port = self.install_paths(h1[0], h1[1], h2[0], h2[1], src_ip, dst_ip)
                    self.install_paths(h2[0], h2[1], h1[0], h1[1], dst_ip, src_ip) # reverse
            # if VERBOSE == 1:
            #     print("--arptable",self.arp_table)
        # print pkt
        else:
            print("notARP",pkt)

        actions = [parser.OFPActionOutput(out_port)]


        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data


        out = parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port,
            actions=actions, data=data)
        datapath.send_msg(out)
        
        

        # ip_pkt = pkt.get_protocol(ipv4.ipv4)
        # if isinstance(ip_pkt, ipv4.ipv4):
        #     # load balancing based on traffic monitoring
        #     h1 = self.hosts[src]
        #     h2 = self.hosts[dst]

        #     if VERBOSE == 1:
        #         print("Installing: Src:{}, Src in_port{}. Dst:{}, Dst in_port:{}, Src_ip:{}, Dst_ip:{}".format(h1[0], h1[1], h2[0], h2[1], src_ip, dst_ip))
        #         out_port = self.install_paths(h1[0], h1[1], h2[0], h2[1], src_ip, dst_ip)
        #         self.install_paths(h2[0], h2[1], h1[0], h1[1], dst_ip, src_ip) # reverse
        
        # actions = [parser.OFPActionOutput(out_port)]


        # data = None
        # if msg.buffer_id == ofproto.OFP_NO_BUFFER:
        #     data = msg.data


        # out = parser.OFPPacketOut(
        #     datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port,
        #     actions=actions, data=data)
        # datapath.send_msg(out)
        

    @set_ev_cls(event.EventSwitchEnter)
    def switch_enter_handler(self, ev):
        switch = ev.switch.dp
        ofp_parser = switch.ofproto_parser
        if VERBOSE == 1:
            print("Switch In: ",switch.id)

        if switch.id not in self.switches:
            self.switches.append(switch.id)
            self.datapath_list[switch.id] = switch


            # Request port/link descriptions, useful for obtaining bandwidth
            req = ofp_parser.OFPPortDescStatsRequest(switch)
            switch.send_msg(req)


    @set_ev_cls(event.EventSwitchLeave, MAIN_DISPATCHER)
    def switch_leave_handler(self, ev):
        print(ev)
        switch = ev.switch.dp.id
        if switch in self.switches:
            self.switches.remove(switch)
            del self.datapath_list[switch]
            del self.adjacency[switch]


    @set_ev_cls(event.EventLinkAdd, MAIN_DISPATCHER)
    def link_add_handler(self, ev):
        s1 = ev.link.src
        s2 = ev.link.dst
        
        self.adjacency[s1.dpid][s2.dpid] = s1.port_no
        self.adjacency[s2.dpid][s1.dpid] = s2.port_no
        
        self.sw_port.setdefault(s1.dpid, [])
        self.sw_port.setdefault(s2.dpid, [])
        
        if s1.port_no not in self.sw_port[s1.dpid]:
            self.sw_port[s1.dpid].append(s1.port_no)
        if s2.port_no not in self.sw_port[s2.dpid]:
            self.sw_port[s2.dpid].append(s2.port_no)
        # print('----------------------------port',self.sw_port)
            

        
    def _monitor(self):
        while True:
            for dp in self.datapath_list.values():
                self._request_stats(dp)
                # print("START OF {} SECONDS!!!".format(self.sleep))
            hub.sleep(self.sleep)

    def _request_stats(self, datapath):
        self.logger.debug('send stats request: %016x', datapath.id)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # req = parser.OFPFlowStatsRequest(datapath)
        # datapath.send_msg(req)
        
        #Send PortStatsRequest

        req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        datapath.send_msg(req)

    def delete_flow(self, datapath, table_id):
        
       
        """Removing all flow entries."""
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        empty_match = parser.OFPMatch()
        instructions = []
        
        # Del/Mod flow table, group table
        flow_mod = self.remove_table_flows(datapath, table_id,
                                        empty_match, instructions)
        print("deleting all flow entries in table ", table_id)
        
        datapath.send_msg(flow_mod)
        
    
    def remove_table_flows(self, datapath, table_id, match, instructions):
        """Create OFP flow mod message to remove flows from table."""
        ofproto = datapath.ofproto
        flow_mod = datapath.ofproto_parser.OFPFlowMod(datapath, 0, 0, table_id,
                                                      ofproto.OFPFC_DELETE, 0, 0,
                                                      1,
                                                      ofproto.OFPCML_NO_BUFFER,
                                                      ofproto.OFPP_ANY,
                                                      ofproto.OFPG_ANY, 0,
                                                      match, instructions)
        return flow_mod
    
    
        
    def send_group_mod(self, datapath):
        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser
        
        if not self.all_group_id or not self.all_group_id.setdefault(datapath.id,{}):
            return
        else:
            for group_id in self.all_group_id[datapath.id].keys():
                #buckets
                buckets = []
                for port in self.all_group_id[datapath.id][group_id].keys():
                    bucket_weight = self.all_group_id[datapath.id][group_id][port] 
                    
                    
                    
                    
                    bucket_action = [ofp_parser.OFPActionOutput(port)]
                    # bucket_action = []
                    buckets.append(
                                    ofp_parser.OFPBucket(
                                        weight=bucket_weight,
                                        watch_port=port,
                                        watch_group=ofp.OFPG_ANY,
                                        actions=bucket_action
                                    )
                                )
                    
                    self.logger.info("dataid:%d gid:%d port:%d bucketw:%d buckets %s" 
                                        %(datapath.id,group_id,port,bucket_weight,buckets))
        
                req = ofp_parser.OFPGroupMod(datapath, ofp.OFPGC_MODIFY, ofp.OFPGT_SELECT, group_id)  
                datapath.send_msg(req)

    
    # def groupdel(datapath=None, group_id=ofp.OFPG_ALL):
    # # """Delete a group (default all groups)."""
    
    #     return parser.OFPGroupMod(
    #         datapath,
    #         ofp.OFPGC_DELETE,
    #         0,
    #         group_id)
        
    def delete_group_mod(self, datapath):

            
        
        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser

        # for dst in self.all_group_id[datapath.id].keys():
        # self.logger.info("dpid:%s "
        #                             %(datapath.id))
        
        # self.logger.info("allgr:%s "
        #                             %(self.all_group_id))

        if not self.all_group_id or not self.all_group_id.setdefault(datapath.id,{}):
            return
        else:
            for group_id in self.all_group_id[datapath.id].keys():
                #buckets
        
                # self.logger.info("dataid:%d gID:%d" %(datapath.id,group_id))

                
                # group_id = ofp.OFPG_ALL to delete all group
                req = ofp_parser.OFPGroupMod(datapath, ofp.OFPGC_DELETE, 0, group_id)  
                datapath.send_msg(req)
            del self.all_group_id[datapath.id]
                


        
    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        # print("PortStat")
        
        dpid = ev.msg.datapath.id

        body = ev.msg.body
        

        # self.logger.info('datapath         port     '
        #                  'rx-pkts  rx-bytes rx-error '
        #                  'tx-pkts  tx-bytes tx-error')
        # self.logger.info('---------------- -------- '
        #                  '-------- -------- -------- '
        #                  '-------- -------- --------')
        # if dpid == 3 or dpid == 4 or dpid == 5:
        #     self.logger.info('datapath         port     tx-pkts  tx-bytes')
        #     self.logger.info('---------------- -------- -------- --------')
        for stat in sorted(body, key=attrgetter('port_no')):
            
            if(stat.port_no != 4294967294):
                # self.logger.info('%016x %8x %8d %8d %8d %8d %8d %8d',
                #                  ev.msg.datapath.id, stat.port_no,
                #                  stat.rx_packets, stat.rx_bytes, stat.rx_errors,
                #                  stat.tx_packets, stat.tx_bytes, stat.tx_errors)

                port_no = stat.port_no
                self.tx_pkt_cur.setdefault(dpid, {})
                self.tx_byte_cur.setdefault(dpid, {})
                self.tx_pkt_int.setdefault(dpid, {})
                self.tx_byte_int.setdefault(dpid, {})

                if port_no in self.tx_pkt_cur[dpid]:
                    self.tx_pkt_int[dpid][port_no] = stat.tx_packets - self.tx_pkt_cur[dpid][port_no]
                    if self.tx_pkt_int[dpid][port_no] < 0:
                        self.logger.warning('Negative value of interval TX packets')
                self.tx_pkt_cur[dpid][port_no] = stat.tx_packets

                if port_no in self.tx_byte_cur[dpid]:
                    self.tx_byte_int[dpid][port_no] = stat.tx_bytes - self.tx_byte_cur[dpid][port_no]
                    if self.tx_byte_int[dpid][port_no] < 0:
                        self.logger.warning('Negative value of interval TX bytes')
                self.tx_byte_cur[dpid][port_no] = stat.tx_bytes

            else:
                pass
                    
        # print(self.tx_byte_int)
        
    
    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def port_status_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        ofp = dp.ofproto

        if msg.reason == ofp.OFPPR_ADD:
            reason = 'ADD'
        elif msg.reason == ofp.OFPPR_DELETE:
            reason = 'DELETE'
        elif msg.reason == ofp.OFPPR_MODIFY:
            reason = 'MODIFY'
        else:
            reason = 'unknown'
            
        # port = msg.desc.port_no

        port_attr = msg.desc
        
        self.logger.info('OFPPortStatus received: reason=%s desc=%s' ,
                          reason, msg.desc)
        
        
        
    # Port information:
        # self.logger.info("\t ***switch dpid=%s"
        #                  "\n \t port_no=%d hw_addr=%s name=%s config=0x%08x "
        #                  "\n \t state=0x%08x curr=0x%08x advertised=0x%08x "
        #                  "\n \t supported=0x%08x peer=0x%08x curr_speed=%d max_speed=%d" %
        #                  (dp.id, port_attr.port_no, port_attr.hw_addr,
        #                   port_attr.name, port_attr.config,
        #                   port_attr.state, port_attr.curr, port_attr.advertised,
        #                   port_attr.supported, port_attr.peer, port_attr.curr_speed,
        #                   port_attr.max_speed))
        
        
        
        out_port = port_attr.port_no
        host_dist = False
        remove_host = []
        if port_attr.state == 1:
            for host in self.hosts:
                if out_port == self.hosts[host][1] and self.hosts[host][0] == dp.id:
                    host_dist = True
                    self.logger.info("Host %s disconnected: dpid:%d port:%d " % (host,self.hosts[host][0],self.hosts[host][1]))
                    # del self.hosts[host]
                    remove_host.append(host)
                    ip = self.get_ip(host)
                    del self.arp_table[ip]
                    # self.logger.info("arp %s  " % (self.hosts)
            if host_dist == False:
            
                #del port flow and group
                self.count += 1
                self.logger.info("Port sw-sw down")
                for i in self.datapath_list.keys():
                    # self.delete_flow(self.datapath_list[i],0)
                    self.logger.info("Reset Topo And ready to install path")
                    self.delete_group_mod(self.datapath_list[i])
                # self.all_group_id = {}

                
                self.multipath_group_ids = {}
                self.group_id_count =0
                self.group_ids = []
                # self.arp_table = {}
                self.sw_port = {}
                # self.hosts = {}
                return
                #del flow and group ...    
            else:
                #del host flow and group
                for host in remove_host:
                    del self.hosts[host]
                for i in self.datapath_list.keys():
                    # self.delete_flow(self.datapath_list[i],0)
                    self.logger.info("Reset Topo And ready to install path")
                    self.delete_group_mod(self.datapath_list[i])
                    self.multipath_group_ids = {}
                    self.group_id_count =0
                    self.group_ids = []
                    # self.arp_table = {}
                    self.sw_port = {}
           
        elif port_attr.state == 0:
            pass  
        
        
    #   #EventOFPPortStatsReply  
    # @set_ev_cls(ofp_event.EventOFPPortStateChange, MAIN_DISPATCHER)
    # def port_modify_handler(self, ev):
    #     # dp = ev.dp
    #     # port_attr = ev.port
    #     dp = ev.datapath
        

    #     body = ev.reason
    #     port = ev.port_no
        
    #     self.logger.info("dpid: %d reason: %s port: %d"%(dp.id,body,port))
        
   
 
   
                
                
            
        
    #get ip from arp table with host
    def get_ip(self,host):
        for ip in self.arp_table:
            if self.arp_table[ip] == host:
                return ip
                
        
    
    # Active only when LLDP packet received
    @set_ev_cls(event.EventLinkDelete, MAIN_DISPATCHER)
    def link_delete_handler(self, ev):
        s1 = ev.link.src
        s2 = ev.link.dst
        # Exception handling if switch already deleted
        try:
            del self.adjacency[s1.dpid][s2.dpid]
            del self.adjacency[s2.dpid][s1.dpid]
        except KeyError:
            pass