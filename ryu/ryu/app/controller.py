
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
# limitations under the License.



from ryu.base import app_manager
from ryu.controller import mac_to_port
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.mac import haddr_to_bin
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib import mac

from ryu.topology.api import get_switch, get_link
from ryu.app.wsgi import ControllerBase
from ryu.topology import event, switches
from collections import defaultdict
import os

#switches
switches = []
#mymac[srcmac]->(switch, port)
mymac={}
#adjacency map [sw1][sw2]->port from sw1 to sw2
adjacency=defaultdict(lambda:defaultdict(lambda:None))

"""
  finding minimum weight node in network and returning it
"""
def minimum_distance(distance, Q):
    print("minimum_distance(distance, Q) is called!= ", distance, Q)
    min = float('Inf')
    node = 0
    for v in Q:
        if distance[v] < min:
            min = distance[v]
            node = v

    return node


"""
  finding shortest path from src to dst by running dijkstra algorithm
  after finding shortest path, return shortest path by id and ports
"""
def get_path (src,dst,first_port,final_port):
    print("get_path is called!")
    #Dijkstra's algorithm

    print ("get_path is called, src=",src," dst=",dst, " first_port=", first_port, " final_port=", final_port)
    distance = {}
    previous = {}

    for dpid in switches:
        distance[dpid] = float('Inf')
        previous[dpid] = None

    distance[src]=0
    Q=set(switches)
    print ("Q=", Q)


    #running dijkstra algorithm
    while len(Q)>0:
        u = minimum_distance(distance, Q)
        print("u= ", u)
        Q.remove(u)

        for p in switches:
          if adjacency[u][p]!=None:
            print("port: adjacency from u to p = ", adjacency[u][p])
            w = 1 #>>????? get this from adjacency matrix
            if distance[u] + w < distance[p]:
              distance[p] = distance[u] + w
              previous[p] = u


    # appending shortest path from src to dest to r
    r=[]
    p=dst
    r.append(p)
    q=previous[p]

    while q is not None:
        if q == src:
            r.append(q)
            break

        p=q
        r.append(p)
        q=previous[p]

    r.reverse()
    if src==dst:
        path=[src]
    else:
        path=r



    # Now add the ports
    r = []
    in_port = first_port
    for s1,s2 in zip(path[:-1],path[1:]):
        out_port = adjacency[s1][s2]
        r.append((s1,in_port,out_port))
        in_port = adjacency[s2][s1]
    r.append((dst,in_port,final_port))
    return r



class ProjectController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(ProjectController, self).__init__(*args, **kwargs)
        self.mac_to_port = {}

        self.topology_api_app = self
        self.datapath_dict={}


    @set_ev_cls(ofp_event.EventOFPSwitchFeatures , CONFIG_DISPATCHER)
    def switch_features_handler(self , ev):
        print ("switch_features_handler is called")
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]

        self.add_flow(datapath, 0, match, actions)


    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        print("add_flow is called!")
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




    def install_path(self, p, ev, src_mac, dst_mac):

        print ("install_path is called")
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser


        for sw, in_port, out_port in p:
            datapath = self.datapath_dict[int(sw)]
            print (src_mac,"->", dst_mac, "via ", sw, " in_port=", in_port, " out_port=", out_port)
            match = parser.OFPMatch(in_port=in_port, eth_src=src_mac, eth_dst=dst_mac)
            actions = [parser.OFPActionOutput(out_port)]
            self.add_flow(datapath, 1, match, actions)


    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        print("_packet_in_handler(self, ev) was called!")
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return

        dst = eth.dst
        src = eth.src

        dpid = format(datapath.id, "d").zfill(16)
        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        if src not in mymac.keys():
            mymac[src]=(dpid,  in_port)

        self.mac_to_port[dpid][src] = in_port

        if not dst in self.mac_to_port[dpid]:
            out_port = ofproto.OFPP_FLOOD

        else:
            # print("223 ----> ", eth.ethertype, src , dst)
            p = get_path(int(mymac[src][0]), int(mymac[dst][0]), mymac[src][1], mymac[dst][1])
            print (p)
            # print("226 ----->  ", p[0][2], self.mac_to_port[dpid][dst], type(p[0][2]), type(self.mac_to_port[dpid][dst]))
            self.install_path(p, ev, src, dst)
            # print("229 ---->  ", int(mymac[src][0]), int(mymac[dst][0]), mymac[src][1], mymac[dst][1], msg.match['in_port'], dpid, self.mac_to_port[dpid][dst])

            out_port = self.mac_to_port[dpid][dst]

        actions = [parser.OFPActionOutput(out_port)]
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)


    """
    The event EventSwitchEnter will trigger the activation of get_topology_data().
     Next we call get_switch() to get the list of objects Switch, and get_link() to get the list of objects Link.
      This objects are defined in the topology.switches file. Then, we build a list with all the switches ([switches]) and next a list with all the links [(srcNode, dstNode, srcPort,dstPort)].
      Notice that we also get the port from the source node that arrives at the destination node, and reverse as that information will be necessary later during the forwarding step.
    """
    @set_ev_cls(event.EventSwitchEnter)
    def get_topology_data(self, ev):
        global switches

        switch_list = get_switch(self.topology_api_app, None)
        switches=[switch.dp.id for switch in switch_list]
        self.datapath_dict= dict([(switch.dp.id, switch.dp) for switch in switch_list])

        print("switches=", switches)

        links_list = get_link(self.topology_api_app, None)
        mylinks= [(link.src.dpid, link.dst.dpid, link.src.port_no, link.dst.port_no) for link in links_list]

        for s1, s2, port1, port2 in mylinks:
            adjacency[s1][s2]= port1
            adjacency[s2][s1]= port2


        print("adjacency list")
        for key in adjacency:
            print (key, ":", adjacency[key])

        if not adjacency:
            print("coudl'nt get links from  mininet")
            print("this is not our fault :)\nplease try running again !")
            os.abort()
