from ryu.base import app_manager
from ryu.controller import mac_to_port
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER, HANDSHAKE_DISPATCHER
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
from ryu.lib.packet import icmp


from ryu.lib.packet import ether_types
from ryu.lib import dpid, mac, ip
from ryu.topology.api import get_switch, get_link
from ryu.app.wsgi import ControllerBase
from ryu.topology import event

from ryu.lib import dpid as dpid_lib
from collections import defaultdict
from operator import itemgetter, attrgetter, mul

from ryu.controller import dpset

from ryu.lib import hub
from ryu import utils



from ryu.ofproto import ofproto_parser  


import os
import random
import time
import logging


# Cisco Reference bandwidth = 1 Gbps
REFERENCE_BW = 10000000


DEFAULT_BW = 10000000


MAX_PATHS = 10

VERBOSE = 0
DEBUGING = 0
SHOW_PATH = 0





# logging.basicConfig(level = logging.INFO)

class ProjectController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]


    def __init__(self, *args, **kwargs):
        super(ProjectController, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.LEARNING = 1
        self.FLAG = 1
        
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
        self.path_install_cnt =0
        
        self.max_bw = {}
        self.curr_max_bw = {}
        self.all_path = {}
        
        self.ip_port = {}
        self.porttcp = {}
        self.arp_port = {}
        self.arp_limit = {}
        
        self.test =0
        
        
        
        if DEBUGING == 1:
            self.logger.setLevel(logging.DEBUG)
        else:
            self.logger.setLevel(logging.INFO)
            

        
        # monitor
        self.sleep = 2
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
        if SHOW_PATH == 1:
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
        if SHOW_PATH == 1:
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
            # print("No bandwitdh")
            bl = min(self.bandwidths[s1][e1], self.bandwidths[s2][e2])
            # print(bl)
            
        else:
            # print("bandwitdh")
            bl = min(self.tx_byte_int[s1][e1], self.tx_byte_int[s2][e2])
            
            # print(bl)
            
        # ew = REFERENCE_BW/bl
        ew = bl
        # print("linkcost",ew)
        return ew


    def get_path_cost(self, path):
        '''
        Get the path cost
        '''
        cost = 0
        for i in range(len(path) - 1):
            cost += self.get_link_cost(path[i], path[i+1])
        return cost

    def sorted_path(self,paths,pw):
        # sorted paths based on pw
        zip_list = zip(pw,paths)
        sorted_zip_list = sorted(zip_list)
        sorted_list = [e for _, e in sorted_zip_list]
       
        # self.logger.info("sorted:%s",
                    
        #                 sorted_list)
        return sorted_list
           
                        
                        
                        
                    
                
    def get_optimal_paths(self, src, dst):
        '''
        Get the n-most optimal paths according to MAX_PATHS
        '''
        paths = self.get_paths(src, dst)
        paths_count = len(paths) if len(
            paths) < MAX_PATHS else MAX_PATHS
        pw = []
        for path in paths:
            pw.append(self.get_path_cost(path))
        # print(sorted(paths, key=lambda x: self.get_path_cost(path)[0:(paths_count)]
        # return sorted(paths, key=lambda x: self.sorted_path(x,paths,pw))[0:(paths_count)],pw[0:(paths_count)]
        return self.sorted_path(paths,pw)[0:(paths_count)],sorted(pw[0:(paths_count)])

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
        return int(s)
    
    # def generate_openflow_gid(self,src,dst):
    #     '''
    #     Returns a random OpenFlow group id
    #     '''
    #     n = random.randint(0, 2**32)
    #     while n in self.group_ids:
    #         n = random.randint(0, 2**32)
    #     self.group_ids.append(n)
    #     return n

    def install_ip_paths(self, src, first_port, dst, last_port, ip_src, ip_dst,ip_protocol,src_port,dst_port):
    
        
        # self.ip_port.setdefault(src_port,())
        # self.ip_port.setdefault(dst_port,())
        # self.porttcp.setdefault(src_port,())
        # self.porttcp.setdefault(dst_port,())
        
        # print('tablearp',self.arp_table.items())
        # print("TEST",src,first_port)
        if src_port not in self.ip_port or (ip_src,ip_protocol) not in self.ip_port[src_port]:
            self.ip_port[src_port] = (ip_src,ip_protocol)
        
        if dst_port not in self.ip_port or (ip_dst,ip_protocol) not in self.ip_port[dst_port]:
            self.ip_port[dst_port]= (ip_dst,ip_protocol)
        
        if src_port not in self.porttcp:
            self.porttcp[src_port] = (src, first_port)
        
        if dst_port not in self.porttcp:
            self.porttcp[dst_port] = (dst, last_port)
        
        # print("porttcp",self.porttcp)
        # print("hosts",self.hosts)
        
        
        
        
        # if SHOW_PATH == 1:
        #     self.path_install_cnt +=1
            # self.logger.info("installing path cnt: %d" % (self.path_install_cnt))
        self.LEARNING = 1
        computation_start = time.time()
        paths,pw = self.get_optimal_paths(src, dst)
        # self.logger.info("paths:%s\n"
        #                  "pw:%s\n"
        #                  ,paths,pw)
        
        
        # pw = []
        # for path in paths:
        #     pw.append(self.get_path_cost(path))
        #     if VERBOSE == 1:
        #         print(path, "cost = ", pw[len(pw) - 1])
        paths_with_ports = self.add_ports_to_paths(paths, first_port, last_port)

        sum_of_pw = sum(pw) * 1.0
        
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
                # UDP
                if ip_protocol == 17:
                    match_ip = ofp_parser.OFPMatch(
                        eth_type=0x0800, 
                        ipv4_src=ip_src, 
                        ipv4_dst=ip_dst,
                        ip_proto=17,
                        udp_src=src_port,
                        udp_dst=dst_port
                    )
                    # print("UDP",match_ip)
                    
                # TCP
                if ip_protocol == 6:
                    match_ip = ofp_parser.OFPMatch(
                        eth_type=0x0800, 
                        ipv4_src=ip_src, 
                        ipv4_dst=ip_dst,
                        ip_proto=6,
                        tcp_src=src_port,
                        tcp_dst=dst_port
                    )
                    # print("TCP",match_ip)
                    
               
                

                out_ports = ports[in_port]

                # print("_OUTPORT",ports)

                dup_port = {}
                for i in range(0,len(out_ports)-1):
                    if len(dup_port) > 0:
                        if out_ports[i][0] in dup_port.keys():
                            continue
                    for j in range(i+1,len(out_ports)):
                        if out_ports[i][0] == out_ports[j][0]:
                            if out_ports[i][0] not in dup_port:
                                dup_port.setdefault(out_ports[i][0],out_ports[i][1]+ out_ports[j][1])
                               
                                    
                            else:
                                dup_port[out_ports[i][0]] += out_ports[j][1]
                    
                                    
                                    
                # print("dup: ", dup_port)
                
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
                # print("pos",out_ports)
                # print("postype",type(out_ports[0]))
                # print("postype",type(out_ports[0][0]),type(out_ports[0][1]))
                del del_port   
                            
                    
                    
                if len(out_ports) > 1:
                    group_id = None
                    group_new = False
                    
                    

                    if (node, src, dst, src_port, dst_port) not in self.multipath_group_ids:
                        self.all_group_id.setdefault(src,{})
                        group_new = True
                        self.multipath_group_ids[
                            node, src, dst, src_port, dst_port] = self.generate_openflow_gid(src,dst)
                        self.all_group_id[src].setdefault(self.multipath_group_ids[
                            node, src, dst, src_port, dst_port], {})
                        
                    group_id = self.multipath_group_ids[node, src, dst, src_port, dst_port]


                    buckets = []
                    if VERBOSE == 1:
                        print("node at ",node," out ports : ",out_ports)
                        print("groupid",group_id)
                        
                        
                    for port, weight in out_ports:
                        
                        
                        bucket_weight = int(round((1 - weight/sum_of_pw) * 10))
                        # if bucket_weight < 0:
                            # print("-----------NEGATIVE-----------")
                            # print("sumofpw:",sum_of_pw)
                
                            # print("_OUTPORT",out_ports)
                            # print("pw",pw)
                            # print("------------------------------------------------------\n")
                            # print("dup: ", dup_port)
                            
                            # print("pos",out_ports)
                            # print("postype",type(out_ports[0]))
                            # print("postype",type(out_ports[0][0]),type(out_ports[0][1]))
                        # self.all_group_id[group_id].setdefault(src,{})
                        self.all_group_id[src][group_id][port]=bucket_weight
                        # bucket_weight = 50
        
                        
                        if VERBOSE == 1:
                            print("bucketw of node{},outport{}:{}".format(node,port,bucket_weight))
                        bucket_action = [ofp_parser.OFPActionOutput(port)]
                        buckets.append(
                            ofp_parser.OFPBucket(
                                weight=bucket_weight,
                                # watch_port=port,
                                watch_port=ofp.OFPP_ANY,                           
                                watch_group=ofp.OFPG_ANY,
                                actions=bucket_action
                            )
                        )


                    if group_new:
                        req = ofp_parser.OFPGroupMod(
                            dp, ofp.OFPGC_ADD, ofp.OFPGT_SELECT, group_id,
                            buckets
                        )
                        # print("node at ",node," out ports : ",port)
                        # print("Group_new dp: ",req)
                        # print("src ",src," dst: ",dst)
                        
                        # print("/////////////////////////////////////")
                        # dp.send_msg(req)

                        try:
                            dp.send_msg(req)
                        except:
                            self.logger.info("logger GROUPNEW dp %s\n"
                                            'dpid src %s\n'
                                            'dpid dst %s\n'
                                            'group_id %s\n'
                                            'node: %s\n'
                                            'Outport %s\n'
                                            'weight %s\n'
                                            'sumofweight %s\n'
                                            'pathweight %s\n'
                                            
                                         % (req,src,dst,group_id,node,port,weight,sum_of_pw,pw))
                            dp.send_msg(req)
                        
                            
                    else:
                        req = ofp_parser.OFPGroupMod(
                            dp, ofp.OFPGC_MODIFY, ofp.OFPGT_SELECT,
                            group_id, buckets)
                        # print("node at ",node," out ports : ",port)
                        # print("GROUPID dp: ",req)
                        # print("src ",src," dst: ",dst)
                        
                        # dp.send_msg(req)
                        try:
                            dp.send_msg(req)
                        except:
                            self.logger.info("logger GROUPID dp %s\n"
                                            'dpid src %s\n'
                                            'dpid dst %s\n'
                                            'group_id %s\n'
                                            'node: %s\n'
                                            'Outport %s\n'
                                            'weight %s\n'
                                            'sumofweight %s\n'
                                            'pathweight %s\n'

                                         
                                         % (req,src,dst,group_id,node,port,weight,sum_of_pw,pw))
                            dp.send_msg(req)
                        
                        # try:
                        #     dp.send_msg(req)
                        # except:
                        #     self.logger.info('logger GROUPID dp %s' % (req))
                            
                        # print("Group_mod", time.time() - computation_start)



                    actions = [ofp_parser.OFPActionGroup(group_id)]
                    self.add_flow(dp, 32768, match_ip, actions)

                elif len(out_ports) == 1:
                    actions = [ofp_parser.OFPActionOutput(out_ports[0][0])]


                    self.add_flow(dp, 32768, match_ip, actions)
        print("Path installation finished in ", time.time() - computation_start )
        # print(paths_with_ports[0][src][1])
        return paths_with_ports[0][src][1]

    
    def install_paths(self, src, first_port, dst, last_port, ip_src, ip_dst):
        if SHOW_PATH == 1:
            self.path_install_cnt +=1
            # self.logger.info("installing path cnt: %d" % (self.path_install_cnt))
        self.LEARNING = 1
        computation_start = time.time()
        paths,pw = self.get_optimal_paths(src, dst)
        # self.logger.info("paths:%s\n"
        #                  "pw:%s\n"
        #                  ,paths,pw)

        
        # pw = []
        # for path in paths:
        #     pw.append(self.get_path_cost(path))
        #     if VERBOSE == 1:
        #         print(path, "cost = ", pw[len(pw) - 1])
        paths_with_ports = self.add_ports_to_paths(paths, first_port, last_port)
        
        sum_of_pw = sum(pw) * 1.0
        # print("sumofpw:",sum_of_pw)
        
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
                    ipv4_dst=ip_dst,
                    ip_proto=1
                    
                )
                # ARP
                match_arp = ofp_parser.OFPMatch(
                    eth_type=0x0806, 
                    arp_spa=ip_src, 
                    arp_tpa=ip_dst
                )


                out_ports = ports[in_port]
 
                dup_port = {}
                for i in range(0,len(out_ports)-1):
                    if len(dup_port) > 0:
                        if out_ports[i][0] in dup_port.keys():
                            continue
                    for j in range(i+1,len(out_ports)):
                        if out_ports[i][0] == out_ports[j][0]:
                            if out_ports[i][0] not in dup_port:
                                dup_port.setdefault(out_ports[i][0],out_ports[i][1]+ out_ports[j][1])
                               
                                    
                            else:
                                dup_port[out_ports[i][0]] += out_ports[j][1]
      
                                    
                # print("dup: ", dup_port)
                
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
                # print("pos",out_ports)
                # print("postype",type(out_ports[0]))
                # print("postype",type(out_ports[0][0]),type(out_ports[0][1]))
                del del_port          
                                

                    
                if VERBOSE == 1:
                    print("\t\t-Outport",out_ports )


                if len(out_ports) > 1:
                    group_id = None
                    group_new = False
                    
                    
                    # self.multipath_group_ids.setdefault()
                    if (node, src, dst , 0, 0) not in self.multipath_group_ids:
                        self.all_group_id.setdefault(src,{})
                        group_new = True
                        self.multipath_group_ids[
                            node, src, dst, 0, 0] = self.generate_openflow_gid(src,dst)
                        self.all_group_id[src].setdefault(self.multipath_group_ids[
                            node, src, dst, 0, 0], {})
                        
                    group_id = self.multipath_group_ids[node, src, dst, 0, 0]


                    buckets = []
                    if VERBOSE == 1:
                        print("node at ",node," out ports : ",out_ports)
                        print("groupid",group_id)
                        
                        
                    for port, weight in out_ports:
                        
                        
                        bucket_weight = int(round((1 - weight/sum_of_pw) * 10))
                        # if bucket_weight < 0:
                            # print("-----------NEGATIVE-----------")
                            # print("sumofpw:",sum_of_pw)
                
                            # print("_OUTPORT",out_ports)
                            # print("pw",pw)
                            # print("------------------------------------------------------\n")
                            # print("dup: ", dup_port)
                            
                            # print("pos",out_ports)
                            # print("postype",type(out_ports[0]))
                            # print("postype",type(out_ports[0][0]),type(out_ports[0][1]))
                        # self.all_group_id[group_id].setdefault(src,{})
                        self.all_group_id[src][group_id][port]=bucket_weight
                        # bucket_weight = 50
        
                        
                        if VERBOSE == 1:
                            print("bucketw of node{},outport{}:{}".format(node,port,bucket_weight))
                        bucket_action = [ofp_parser.OFPActionOutput(port)]
                        buckets.append(
                            ofp_parser.OFPBucket(
                                weight=bucket_weight,
                                # watch_port=port,
                                watch_port=ofp.OFPP_ANY,                           
                                watch_group=ofp.OFPG_ANY,
                                actions=bucket_action
                            )
                        )


                    if group_new:
                        req = ofp_parser.OFPGroupMod(
                            dp, ofp.OFPGC_ADD, ofp.OFPGT_SELECT, group_id,
                            buckets
                        )
                        # print("node at ",node," out ports : ",port)
                        # print("Group_new dp: ",req)
                        # print("src ",src," dst: ",dst)
                        
                        # print("/////////////////////////////////////")
                        # dp.send_msg(req)

                        try:
                            dp.send_msg(req)
                        except:
                            self.logger.info("logger GROUPNEW dp %s\n"
                                            'dpid src %s\n'
                                            'dpid dst %s\n'
                                            'group_id %s\n'
                                            'node: %s\n'
                                            'Outport %s\n'
                                            'weight %s\n'
                                            'sumofweight %s\n'
                                            'pathweight %s\n'
                                            
                                         % (req,src,dst,group_id,node,port,weight,sum_of_pw,pw))
                            dp.send_msg(req)
                        
                            
                    else:
                        req = ofp_parser.OFPGroupMod(
                            dp, ofp.OFPGC_MODIFY, ofp.OFPGT_SELECT,
                            group_id, buckets)
                        # print("node at ",node," out ports : ",port)
                        # print("GROUPID dp: ",req)
                        # print("src ",src," dst: ",dst)
                        
                        # dp.send_msg(req)
                        try:
                            dp.send_msg(req)
                        except:
                            self.logger.info("logger GROUPID dp %s\n"
                                            'dpid src %s\n'
                                            'dpid dst %s\n'
                                            'group_id %s\n'
                                            'node: %s\n'
                                            'Outport %s\n'
                                            'weight %s\n'
                                            'sumofweight %s\n'
                                            'pathweight %s\n'

                                         
                                         % (req,src,dst,group_id,node,port,weight,sum_of_pw,pw))
                            dp.send_msg(req)
                        
                        # try:
                        #     dp.send_msg(req)
                        # except:
                        #     self.logger.info('logger GROUPID dp %s' % (req))
                            
                        # print("Group_mod", time.time() - computation_start)



                    actions = [ofp_parser.OFPActionGroup(group_id)]


                    self.add_flow(dp, 32768, match_ip, actions)
                    self.add_flow(dp, 1, match_arp, actions)


                elif len(out_ports) == 1:
                    actions = [ofp_parser.OFPActionOutput(out_ports[0][0])]


                    self.add_flow(dp, 32768, match_ip, actions)
                    self.add_flow(dp, 1, match_arp, actions)
        print("Path installation finished in ", time.time() - computation_start )
        # print(paths_with_ports[0][src][1])
        return paths_with_ports[0][src][1]

    def install_replace_paths(self, src, first_port, dst, last_port, ip_src, ip_dst):
        if SHOW_PATH == 1:
            self.path_install_cnt +=1
            # self.logger.info("installing path cnt: %d" % (self.path_install_cnt))
        self.LEARNING = 1
        computation_start = time.time()
        paths,pw = self.get_optimal_paths(src, dst)
        # print('path',paths)
        # self.all_path.setdefault(src,{})
        # self.all_path[src][dst] = paths
        # print('path',self.all_path[src][dst])
        
        # print('all_path',self.all_path)
        
 
        
        # pw = []
        # for path in paths:
        #     pw.append(self.get_path_cost(path))
        #     if VERBOSE == 1:
        #         print(path, "cost = ", pw[len(pw) - 1])
        # sum_of_pw = sum(pw) * 1.0
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
                out_ports = ports[in_port]
            
                # print("_MODOUTPORT",ports)
                    
                    
                if VERBOSE == 1:
                    print("\t\t-Outport",out_ports )


                if len(out_ports) > 1:             
                    group_id = None
                    group_new = False
                    
                    

                    if (node, src, dst, 0 , 0) not in self.multipath_group_ids:
                        self.all_group_id.setdefault(src,{})
                        group_new = True
                        self.multipath_group_ids[
                            node, src, dst, 0, 0] = self.generate_openflow_gid(src,dst)
                        self.all_group_id[src].setdefault(self.multipath_group_ids[
                            node, src, dst, 0, 0], {})    
                    group_id = self.multipath_group_ids[node, src, dst, 0, 0]


                    buckets = []
                    if VERBOSE == 1:
                        print("node at ",node," out ports : ",out_ports)
                        print("groupid",group_id)
                        
                        
                    for port, weight in out_ports:
                        sum_of_pw = sum(pw) * 1.0
                        
                        bucket_weight = int(round((1 - weight/sum_of_pw) * 10))
                        # self.all_group_id[group_id].setdefault(src,{})
                        self.all_group_id[src][group_id][port]=bucket_weight
                        # bucket_weight = 50
    
                        
                        if VERBOSE == 1:
                            print("bucketw of node{},outport{}:{}".format(node,port,bucket_weight))
                        bucket_action = [ofp_parser.OFPActionOutput(port)]
                        buckets.append(
                            ofp_parser.OFPBucket(
                                weight=bucket_weight,
                                # watch_port=port,
                                watch_port=ofp.OFPP_ANY,
                                watch_group=ofp.OFPG_ANY,
                                actions=bucket_action
                            )
                        )


            
                    req = ofp_parser.OFPGroupMod(
                        dp, ofp.OFPGC_MODIFY, ofp.OFPGT_SELECT,
                        group_id, buckets)
                    # dp.send_msg(req)
                    
                    # print("node at ",node," out ports : ",port)
                    # print("src ",src," dst: ",dst)
                    
                    # print("GROUPMOD dp: ",req)
                    try:
                        dp.send_msg(req)
                    except:
                        self.logger.info("logger GROUPMOD dp %s\n"
                                         'dpid src %s\n'
                                         'dpid dst %s\n'
                                         'group_id %s\n'
                                         'node: %s\n'
                                         'Outport %s\n'
                                         'weight %s\n'
                                         'sumofweight %s\n'
                                         'pathweight %s\n'
                                         
                                         
                                         
                                         % (req,src,dst,group_id,node,port,weight,sum_of_pw,pw))
                        dp.send_msg(req)
                        
                    # print("Group_mod", time.time() - computation_start)
                        # return
        return 

    def install_replace_paths_ip(self, src, first_port, dst, last_port, ip_src, ip_dst, ip_protocol, src_port, dst_port):
        
        # if SHOW_PATH == 1:
        #     self.path_install_cnt +=1
        #     self.logger.info("installing path cnt: %d" % (self.path_install_cnt))
        self.LEARNING = 1
        computation_start = time.time()
        paths,pw = self.get_optimal_paths(src, dst)
        
        # self.logger.info('path %s'% paths)
        # self.logger.info('pw %s'% pw)
        # self.logger.info('all_path %s'% self.all_path)
        # self.logger.info('cal_pw %s'% cal_pw)
        
        
        
        
                  
        
        # renew:    
        
        
        # pw = []
       
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
                # print("\tnode {}: ports{}".format(node,ports) ) 


            for in_port in ports:
                out_ports = ports[in_port]
            
                # print("_MODOUTPORT",ports)
                    
                    
                if VERBOSE == 1:
                    print("\t\t-Outport",out_ports )


                if len(out_ports) > 1:             
                    group_id = None
                    group_new = False
                    
                    

                    if (node, src, dst, src_port, dst_port) not in self.multipath_group_ids:
                        self.all_group_id.setdefault(src,{})
                        group_new = True
                        self.multipath_group_ids[
                            node, src, dst,src_port,dst_port] = self.generate_openflow_gid(src,dst)
                        self.all_group_id[src].setdefault(self.multipath_group_ids[
                            node, src, dst,src_port, dst_port], {})    
                    group_id = self.multipath_group_ids[node, src, dst, src_port, dst_port]


                    buckets = []
                    if VERBOSE == 1:
                        print("node at ",node," out ports : ",out_ports)
                        print("groupid",group_id)
                        
                        
                    for port, weight in out_ports:
                        sum_of_pw = sum(pw) * 1.0
                        
                        bucket_weight = int(round((1 - weight/sum_of_pw) * 10))
                        # self.all_group_id[group_id].setdefault(src,{})
                        self.all_group_id[src][group_id][port]=bucket_weight
                        # bucket_weight = 50
    
                        
                        if VERBOSE == 1:
                            print("bucketw of node{},outport{}:{}".format(node,port,bucket_weight))
                        bucket_action = [ofp_parser.OFPActionOutput(port)]
                        buckets.append(
                            ofp_parser.OFPBucket(
                                weight=bucket_weight,
                                # watch_port=port,
                                watch_port=ofp.OFPP_ANY,
                                watch_group=ofp.OFPG_ANY,
                                actions=bucket_action
                            )
                        )


            
                    req = ofp_parser.OFPGroupMod(
                        dp, ofp.OFPGC_MODIFY, ofp.OFPGT_SELECT,
                        group_id, buckets)
                    # dp.send_msg(req)
                    
                    # print("node at ",node," out ports : ",port)
                    # print("src ",src," dst: ",dst)
                    
                    # print("GROUPMOD dp: ",req)
                    try:
                        dp.send_msg(req)
                    except:
                        self.logger.info("logger GROUPMOD dp %s\n"
                                         'dpid src %s\n'
                                         'dpid dst %s\n'
                                         'group_id %s\n'
                                         'node: %s\n'
                                         'Outport %s\n'
                                         'weight %s\n'
                                         'sumofweight %s\n'
                                         'pathweight %s\n'
                                         
                                         
                                         
                                         % (req,src,dst,group_id,node,port,weight,sum_of_pw,pw))
                        dp.send_msg(req)
                        
                    # print("Group_mod", time.time() - computation_start)
                        # return
        return 


        
        
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
    
    
    @set_ev_cls(ofp_event.EventOFPErrorMsg,
    [HANDSHAKE_DISPATCHER, CONFIG_DISPATCHER, MAIN_DISPATCHER])
    # def error_msg_handler(self, ev):
    #     msg = ev.msg
    #     # self.logger.info('OFPErrorMsg received: type=0x%02x code=0x%02x '
        # 'message=%s \n ,msg=%s',
        # msg.type, msg.code, hex_array(msg.data),msg)
    
    def error_msg_handler(self, ev):
        msg = ev.msg
        ofp = msg.datapath.ofproto
        self.logger.debug(
            "EventOFPErrorMsg received.\n"
            "version=%s, msg_type=%s, msg_len=%s, xid=%s\n"
            " `-- msg_type: %s\n"
            "OFPErrorMsg(type=%s, code=%s, data=b'%s')\n"
            " |-- type: %s\n"
            " |-- code: %s\n"
            " |-- dpid: %s\n"
            ,
            
            hex(msg.version), hex(msg.msg_type), hex(msg.msg_len),
            hex(msg.xid), ofp.ofp_msg_type_to_str(msg.msg_type),
            hex(msg.type), hex(msg.code), utils.binary_str(msg.data),
            ofp.ofp_error_type_to_str(msg.type),
            ofp.ofp_error_code_to_str(msg.type, msg.code),
            msg.datapath.id)
        if msg.type == ofp.OFPET_HELLO_FAILED:
            self.logger.debug(
                " `-- data: %s", msg.data.decode('ascii'))
        elif len(msg.data) >= ofp.OFP_HEADER_SIZE:
            (version, msg_type, msg_len, xid) = ofproto_parser.header(msg.data)
            self.logger.debug(
                " `-- data: version=%s, msg_type=%s, msg_len=%s, xid=%s\n"
                "     `-- msg_type: %s",
                hex(version), hex(msg_type), hex(msg_len), hex(xid),
                ofp.ofp_msg_type_to_str(msg_type))
        else:
            self.logger.warning(
                "The data field sent from the switch is too short: "
                "len(msg.data) < OFP_HEADER_SIZE\n"
                "The OpenFlow Spec says that the data field should contain "
                "at least 64 bytes of the failed request.\n"
                "Please check the settings or implementation of your switch.")

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
            self.LEARNING = 1
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
                    # print('---------------------------port',self.sw_port)
             
                
                #Install path: dpid src, src in_port, dpid dst, dpid in_port, src_ip, dst_ip
                if VERBOSE == 1:
                    print("Installing: Src:{}, Src in_port{}. Dst:{}, Dst in_port:{}, Src_ip:{}, Dst_ip:{}".format(h1[0], h1[1], h2[0], h2[1], src_ip, dst_ip))
                out_port = self.install_paths(h1[0], h1[1], h2[0], h2[1], src_ip, dst_ip)
                self.install_paths(h2[0], h2[1], h1[0], h1[1], dst_ip, src_ip) # reverse
            elif arp_pkt.opcode == arp.ARP_REQUEST:
                if dst_ip in self.arp_table:
                    # print("dst_ip found in arptable")
                    self.arp_table[src_ip] = src
                    dst_mac = self.arp_table[dst_ip]
                    h1 = self.hosts[src]
                    h2 = self.hosts[dst_mac]
                    out_port = self.install_paths(h1[0], h1[1], h2[0], h2[1], src_ip, dst_ip)
                    self.install_paths(h2[0], h2[1], h1[0], h1[1], dst_ip, src_ip) # reverse
                
                else:
                    self.arp_limit.setdefault(dpid,[])
                    if (arp_pkt.src_ip, arp_pkt.dst_ip, arp_pkt.src_mac, arp_pkt.dst_mac) not in self.arp_limit[dpid]:
                        self.arp_limit[dpid].append((arp_pkt.src_ip, arp_pkt.dst_ip, arp_pkt.src_mac, arp_pkt.dst_mac))
                        # print('FLOOD', self.arp_limit)
                        
                    else:
                        # print('LIMIT')
                        
                        # pass
                        self.LEARNING = 0
                        return            
            
            
            if VERBOSE == 1:
                print("--arptable",self.arp_table)
                print("--host",self.hosts)
                
        # print pkt
        # else:
        #     # print("notARP",pkt)
        #     pass
        
            actions = [parser.OFPActionOutput(out_port)]


            data = None
            if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                data = msg.data


            out = parser.OFPPacketOut(
                datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port,
                actions=actions, data=data)
            datapath.send_msg(out)
            self.LEARNING = 0
            
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
    
        if isinstance(ip_pkt, ipv4.ipv4):
            # print("IPIP")
            # load balancing based on traffic monitoring
            ip_dst = ip_pkt.dst
            ip_src = ip_pkt.src
            
            ip_proto = ip_pkt.proto
            # print("ip_pkt",ip_pkt)
            
            if ip_dst not in self.arp_table.keys():
                if ip_src not in self.arp_table.keys():
                    self.arp_table[ip_src] = src
                return
            else:
                dst_mac = self.arp_table[ip_dst]
                h1 = self.hosts[src]
                h2 = self.hosts[dst_mac]
                
                
                if ip_proto == 6:
                    # TCP
                    # self.logger.info("Switch %s: TCP packet", dpid)
                    tcp_pkt = pkt.get_protocol(tcp.tcp)
                    # print("tcp_pkt",tcp_pkt)
                    dst_port = tcp_pkt.dst_port
                    src_port = tcp_pkt.src_port
                 
                    
                    # self.logger.info("TCP packet %s" % (tcp_pkt))
                    # print("TCP ether type:",eth.ethertype)
                    

                    # match = parser.OFPMatch(eth_type=eth.ethertype,
                    #                         ipv4_dst=ip_dst,
                    #                         ip_proto=ip_proto,
                    #                         tcp_dst=dst_port)

                    # if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                    #     self.add_flow(datapath, 1000, 5, match, actions, msg.buffer_id)
                    #     return
                    # else:
                    #     self.add_flow(datapath, 1000, 5, match, actions)
                    #Install path: dpid src, src in_port, dpid dst, dpid in_port, src_ip, dst_ip
                    
                    out_port = self.install_ip_paths(h1[0], h1[1], h2[0], h2[1], ip_src, ip_dst,ip_proto,src_port,dst_port)
                    self.install_ip_paths(h2[0], h2[1], h1[0], h1[1], ip_dst, ip_src,ip_proto,dst_port,src_port) # reverse
                    
                elif ip_proto == 17:
                    # UDP
                    # self.logger.debug("Switch %s: UDP packet", dpid)
                    udp_pkt = pkt.get_protocol(udp.udp)
                    # print("udp_pkt",udp_pkt)
               
                    
                    dst_port = udp_pkt.dst_port
                    src_port = udp_pkt.src_port
                    # dst_port = udp_pkt.dst_port
                    # self.logger.info("UDP packet %s" % (udp_pkt))
                    

                    out_port = self.install_ip_paths(h1[0], h1[1], h2[0], h2[1], ip_src, ip_dst,ip_proto,src_port,dst_port)
                    self.install_ip_paths(h2[0], h2[1], h1[0], h1[1], ip_dst, ip_src,ip_proto,dst_port,src_port) # reverse

                    
                actions = [parser.OFPActionOutput(out_port)]
                
                data = None
                if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                    data = msg.data
        
                out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                            in_port=in_port, actions=actions, data=data)
                datapath.send_msg(out)
                # self.logger.info("Switch %s: UDP packets assign to port %d", dpid, out_port)
                self.LEARNING = 0
                return

        
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

    def delete_all_flow(self, datapath, table_id):
        
       
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
        # self.logger.info("PortStat")
        print("--arptable",self.arp_table)
        print("--host",self.hosts)
        
        dpid = ev.msg.datapath.id
        body = ev.msg.body
        
        if dpid == 1:
            self.logger.info('datapath         port     '
                                'rx-pkts  rx-bytes rx-error '
                                'tx-pkts  tx-bytes tx-error')
            self.logger.info('---------------- -------- '
                            '-------- -------- -------- '
                            '-------- -------- --------')
        if dpid == 1:
            self.logger.info('datapath         port     tx-pkts  tx-bytes')
            self.logger.info('---------------- -------- -------- --------')
        for stat in sorted(body, key=attrgetter('port_no')):
            
            if(stat.port_no != 4294967294):
                if dpid == 1:
                    
                    self.logger.info('%016x %8x %8d %8d %8d %8d %8d %8d',
                                    ev.msg.datapath.id, stat.port_no,
                                    stat.rx_packets, stat.rx_bytes, stat.rx_errors,
                                    stat.tx_packets, stat.tx_bytes, stat.tx_errors)

                port_no = stat.port_no
                self.tx_pkt_cur.setdefault(dpid, {})
                self.tx_byte_cur.setdefault(dpid, {})
                self.tx_pkt_int.setdefault(dpid, {})
                self.tx_byte_int.setdefault(dpid, {})
                self.curr_max_bw.setdefault(dpid, {})
                self.max_bw.setdefault(dpid, {})
                
                
                
                

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
                
                if dpid == 1:
                    if port_no in self.tx_pkt_int[dpid] and port_no in self.tx_byte_int[dpid]:
                        self.logger.info('%016x %8x %8d', dpid, port_no,
                                        # self.tx_pkt_int[dpid][port_no],
                                        self.tx_byte_int[dpid][port_no])
                
            else:
                pass
     
        # self.max_bw[dpid] = sorted(self.tx_byte_int[dpid].items(), key=lambda x: x[1], reverse=True)  
        self.max_bw[dpid] = {k: v for k, v in sorted(self.tx_byte_int[dpid].items(), key=lambda item: item[1], reverse=True)}
        if not self.curr_max_bw[dpid]:
            self.curr_max_bw[dpid]= tuple(self.max_bw[dpid].keys())
        
        
        
        if self.LEARNING == 0:
            # self.logger.info("Calculating bw")
            if self.curr_max_bw[dpid] != tuple(self.max_bw[dpid].keys()):
                self.logger.info("Reset weight")         
                
                
                self.curr_max_bw[dpid] = tuple(self.max_bw[dpid].keys())

            # GROUP MOD OPTION
                # Calculate bucket weight
                multipath_list= self.multipath_group_ids.copy()
                for multipath in multipath_list.keys():
                    # print("multi",multipath)
                    if not multipath:
                        continue
                    else:
                        if dpid == multipath[1]:
                            if multipath[3] == 0 and multipath[4] == 0:
                                dst = multipath[2]
                                self.replace_path(dpid,dst)
                            else:
                                dst = multipath[2]
                                self.replace_path_ip(dpid,dst)
                   

        
    def replace_path(self,src,dst):
        src_ips = self.get_ip_from_dpid(src)
        dst_ips = self.get_ip_from_dpid(dst)
        # self.logger.info("src_ips:  %s"% (src_ips))
        # self.logger.info("dst_ips:  %s"% (dst_ips))
        
        ip_h1 = []
        ip_h2 = []
        for ip_host in src_ips:
            ip_h1.append(ip_host.popitem())
            
        for ip_host in dst_ips:
            ip_h2.append(ip_host.popitem())
        
        for ip_1,h_1 in ip_h1:
            # self.logger.info("HOST ip: %s host: %s"% (ip_1,h_1))   
            
            for ip_2,h_2 in ip_h2:
                # self.logger.info("HOST ip2: %s host2: %s"% (ip_2,h_2))   
                
                self.install_replace_paths(src,self.hosts[h_1][1],dst,self.hosts[h_2][1],ip_1,ip_2)
                self.install_replace_paths(dst,self.hosts[h_2][1],src,self.hosts[h_1][1],ip_2,ip_1)
            
        # self.logger.info("IP %s"% (self.hosts))
    
    def replace_path_ip(self,src,dst):
        src_ips = self.get_ip_from_porttcp(src)
        dst_ips = self.get_ip_from_porttcp(dst)
        ip_p1 = []
        ip_p2 = []
        for ip_port in src_ips:
            ip_p1.append(ip_port.popitem())
            
        for ip_port in dst_ips:
            ip_p2.append(ip_port.popitem())
        
        for p_1,ip_and_proto_1 in ip_p1:
            # self.logger.info("HOST ip: %s host: %s"% (ip_1,h_1))
            ip_1, ip_proto_1 = ip_and_proto_1
                 
            for p_2,ip_and_proto_2 in ip_p2:
                # self.logger.info("HOST ip2: %s host2: %s"% (ip_2,h_2))   
                ip_2,ip_proto_2 = ip_and_proto_2
    
                
                self.install_replace_paths_ip(src,self.porttcp[p_1][1],dst,self.porttcp[p_2][1],ip_1,ip_2,ip_proto_1,p_1,p_2)
                self.install_replace_paths_ip(dst,self.porttcp[p_2][1],src,self.porttcp[p_1][1],ip_2,ip_1,ip_proto_2,p_2,p_1)
                self.logger.info("CHANGEPATH")
        
        
        
        
      
        
        
    def get_host_from_dpid(self,dpid):
        return [k for k, v in self.hosts.items() if v[0] == dpid]
    
    def get_ip_from_dpid(self,dpid):
        hosts = self.get_host_from_dpid(dpid)
        ip = []
        for host in hosts:
            
            a = [{k:v} for k, v in self.arp_table.items() if v == host]
            # 1 host has only 1 IP
            ip.append(a[0])
        return ip
    
    
    
    def get_porttcp_from_dpid(self,dpid):
        return [k for k, v in self.porttcp.items() if v[0] == dpid]                    
                        
    def get_ip_from_porttcp(self,dpip):
        ports = self.get_porttcp_from_dpid(dpip)
        ip = []
        for port in ports:
            
            a = [{k:v} for k, v in self.ip_port.items() if k == port]
            # 1 host has 1 IP
            ip.append(a[0])
        return ip      
            
                           
            # DELETE OPTION:
                # multipath : (node in path, srcid, dstid)
                # del group id
                
                # multi_group = self.multipath_group_ids.copy()
                # for multipath in self.multipath_group_ids.keys():
                #     # print("multi",multipath)
                #     if not multipath:
                #         continue
                #     else:
                #         if dpid == multipath[1]:
                #             node = multipath[0]
                #             dst = multipath[2]
                #             if self.group_id_count > self.multipath_group_ids[node,dpid,dst]:
                #                 self.group_id_count = self.multipath_group_ids[node,dpid,dst] - 1
                #             self.group_ids.remove(self.multipath_group_ids[node,dpid,dst])
                #             del multi_group[node,dpid,dst]
                #             # self.logger.info("TRUEEEEEEEEEEEEEEEEEEEEEEEEEEEee")
                #         if dpid == multipath[2]:
                #             node = multipath[0]
                #             src = multipath[1]
                #             if self.group_id_count > self.multipath_group_ids[node,src,dpid]:
                #                 self.group_id_count = self.multipath_group_ids[node,src,dpid] - 1
                #             self.group_ids.remove(self.multipath_group_ids[node,src,dpid])
                #             del multi_group[node,src,dpid]
                            
                # self.multipath_group_ids = multi_group
                # self.delete_group_mod(self.datapath_list[dpid])
                
                
            # DELETE ALL OPTION
                # for i in self.datapath_list.keys():
                #     # self.delete_flow(self.datapath_list[i],0)
                #     # self.logger.info("Reset Topo And ready to install path")
                #     self.delete_group_mod(self.datapath_list[i])
   

                
                # self.multipath_group_ids = {}
                # self.group_id_count =0
                # self.group_ids = []
                # # self.arp_table = {}
                # self.sw_port = {}
                
        
    
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
                self.logger.info("Port sw-sw down")
                for i in self.datapath_list.keys():
                    # self.delete_flow(self.datapath_list[i],0)
                    self.logger.info("Reset Topo And ready to install path")
                    self.delete_group_mod(self.datapath_list[i])
       

                
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