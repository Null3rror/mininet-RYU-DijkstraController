
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

# finding minimum weight node in network and returning it
# weight of node is the total weight of path that crossed form src to this nodes so far
# if node weight are inf it means that this node wasn't reached from src in this level
def minimum_distance(distance, Q):
    # print("minimum_distance(distance, Q) is called!= ", distance, Q)
    min = float('Inf')
    node = 0
    for v in Q:
        if distance[v] < min:
            min = distance[v]
            node = v

    return node


# finding shortest path from src to dst by running dijkstra algorithm
# after finding shortest path, return shortest path by id and ports
def get_path (src,dst,first_port,final_port):
    print("get_path is called!")
    #Dijkstra's algorithm

    print ("get_path is called, src=",src," dst=",dst, " first_port=", first_port, " final_port=", final_port)
    distance = {}
    previous = {}

    # initializing switches's distance and previous list
    for dpid in switches:
        distance[dpid] = float('Inf')
        previous[dpid] = None

    distance[src]=0
    Q=set(switches)
    print ("Q=", Q)


    # running dijkstra algorithm
    # first finding minimum weighted switch
    # removing from queue and finding its neighbour weights
    # repeat algho till queue become null
    while len(Q)>0:
        u = minimum_distance(distance, Q)
        print("u= ", u)
        Q.remove(u)

        # finding neighbour of selected node's weight
        for p in switches:
          if adjacency[u][p]!=None:
            print("port: adjacency from u to p = ", adjacency[u][p])
            w = 1 #>>????? get this from adjacency matrix, we suppose that weight of nodes are 1
            if distance[u] + w < distance[p]:
              distance[p] = distance[u] + w
              previous[p] = u


    # appending shortest path from dest to src to r
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

    #since we get path from dest to src we need to reverse the list
    r.reverse()
    if src==dst:
        path=[src]
    else:
        path=r




    # Now add the ports to path
    # by adjacency matrix and shortest path that was found with dijkstra algorithm
    # for each switch we know its next switch so we try to find its port in adjacency matrix
    # and append it to r
    r = []
    in_port = first_port
    for s1,s2 in zip(path[:-1],path[1:]):
        out_port = adjacency[s1][s2]
        r.append((s1,in_port,out_port))
        in_port = adjacency[s2][s1]
    r.append((dst,in_port,final_port))

    return r



class ProjectController(app_manager.RyuApp):
    # specifies which versions of the OpenFlow protocol that our application is compatible with
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(ProjectController, self).__init__(*args, **kwargs)
        # it is a dict<int, dict<int, int>>. which the first key contains id of switch, and the second key is mac address of a host, and finally the value contains a port number of that switch
        # for example mac_to_port[2][00:00:00:00:00:01] = 2, means that in s2(which is a switch), host with mac address of 00:00:00:00:00:01, is connected to s2 form s2's second port(eth2)
        self.mac_to_port = {}
        # used to get info from our topology. we get list of switches and list of links
        self.topology_api_app = self
        # it is a dict<int, datapath>. which the first key contains id of switch, and the value is the datapath(switch) object
        self.datapath_dict = {}

    # """
    # While a switch connects to the Ryu controller, the switch connection goes through different negotiation phases.
    # During the CONFIG_DISPATCHER negotiation phase,
    # Ryu asks the switch for its features. so CONFIG_DISPATCHER means that we are Waiting to receive SwitchFeatures message.
    # The decorator @set_ev_cls(...) registers the attached function as an event handler for the specified event type,
    # within the specified dispatcher. In this case, the instance method switch_features_handler(self, ev) will be called
    # any time Ryu processes an event of type EventOFPSwitchFeaturessrc,  during the CONFIG_DISPATCHERsrc,  negotiation phase.
    # """
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures , CONFIG_DISPATCHER)
    # upon receiving the Switch Features(Features Reply) message, we'll add Table-miss flow entry to our flow table
    def switch_features_handler(self , ev):
        print ("switch_features_handler is called")
        # the OpenFlow switch that issued this message
        datapath = ev.msg.datapath
        # Indicates the ofproto module that supports the OpenFlow version in use.
        ofproto = datapath.ofproto
        # indicates the ofproto_parser module
        parser = datapath.ofproto_parser
        # Now that controller is notified of the attached switch, it will install a table-miss flow.
        # This allows any traffic not handled by the current flow entries in the switch to be sent to the controller.
        # parser.OFPMatch() means that it'll match any packet.
        match = parser.OFPMatch()
        # In the instruction of this entry, by specifying the output action to output to the controller port,
        # in case the received packet does not match any of the normal flow entries, Packet-In is issued.
        # OFPCML_NO_BUFFER is specified to max_len in order to send all packets to the controller.
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        # we'll use a helper function that adds flow entry to the flow table
        # we have set the priority to 0(actually it's the lowest priority) and this entry matches all packets
        self.add_flow(datapath, 0, match, actions)

    # this is a helper function which adds a flow entry to the flow table of the specified switch(datapath)
    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        print("add_flow is called!")
        # Indicates the ofproto module that supports the OpenFlow version in use.
        ofproto = datapath.ofproto
        # indicates the ofproto_parser module
        parser = datapath.ofproto_parser
        # As this is working with OpenFlow above v1.2, a flow-mod must include a set of instructions rather than just actions.
        # This is due to the additional abilities added such as writing metadata or, more commonly,
        # instructing the switch to continue processing the packet on a different table.
        # OpenFlow v1.3 adds an additional instruction for applying a meter.
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        # we'll create the flow mod message
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        # Once the message is created,
        # Ryu will take care of the rest to ensure the message is properly encoded and sent to the switch.
        datapath.send_msg(mod)



    # after finding shortest path by dijkstra,
    # with this function, trying to save the output of dijkstra path that has been declared,
    # in the flow_table for each switch we define that if src_mac and dst_mac are these then
    # use this flow (path).
    def install_path(self, p, ev, src_mac, dst_mac):

        print ("install_path is called")
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        for sw, in_port, out_port in p:
            #getting datapath of each switch to find out its port
            datapath = self.datapath_dict[int(sw)]
            print (src_mac,"->", dst_mac, "via ", sw, " in_port=", in_port, " out_port=", out_port)
            # Unlike the Table-miss flow entry, set conditions for match this time. the receive port (in_port) and destination MAC address (eth_dst) have been specified.
            # For example, packets addressed to host B received by port 1 is the target.
            match = parser.OFPMatch(in_port=in_port, eth_src=src_mac, eth_dst=dst_mac)
            actions = [parser.OFPActionOutput(out_port)]
            self.add_flow(datapath, 1, match, actions)

    # Create the handler of the Packet-In event handler in order to accept received packets with an unknown destination.
    # by unknown destination we mean the output port, not the destination host.
    # MAIN_DISPATCHER means Normal status, which is after CONFIG_DISPATCHER
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        print("_packet_in_handler(self, ev) was called!")
        # the OpenFlow switch that issued this message
        msg = ev.msg
        # Indicates the ofproto module that supports the OpenFlow version in use.
        datapath = msg.datapath
        # Indicates the ofproto module that supports the OpenFlow version in use.
        ofproto = datapath.ofproto
        # indicates the ofproto_parser module
        parser = datapath.ofproto_parser
        # get the received port number from packet_in message.
        in_port = msg.match['in_port']
        # Binary data indicating received packets themselves(the data as an ethernet frame).
        # This class instantiation automatically parses the first header in the data as an ethernet frame.
        pkt = packet.Packet(msg.data)
        # The decoded ethernet frame
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        # eth.ethertype is an int which is 16-bit and specifies ethertype of the packet (can be ICMP, LLDP, ARP...)
        # ignores packets using the Link Layer Discovery Protocol (LLDP)
        # This prevents the forwarding of LLDP traffic as only the controller is allowed to flood packets and processing is stopped before that action can be given.
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return

        # String representation of the destination MAC, like 'ff:ff:ff:ff:ff:ff'
        dst = eth.dst
        # String representation of the source MAC, like '00:00:00:00:00:01'
        src = eth.src
        # for example turn 5 to 0000000000000005
        dpid = format(datapath.id, "d").zfill(16)
        # if mac_to_port was not already set up for this switch before, we'll initialize it.
        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # we'll add the port number of the switch our host used to connect to this switch, only if it wasn't added before
        # since a host is only connected to only one switch(via one port), the value won't change
        if src not in mymac.keys():
            mymac[src] = (dpid,  in_port)
        # we'll add the port number of the switch our host used to connect to this switch, only if it wasn't added before
        # since a host is only connected to only one switch(via one port), the value won't change
        self.mac_to_port[dpid][src] = in_port
        # if the destination mac address isn't already learned, FLOOD.
        if not dst in self.mac_to_port[dpid]:
            # print("----> ", eth.ethertype, src , dst)
            # print("---->  ", int(mymac[src][0]), mymac[src][1], dpid)
            out_port = ofproto.OFPP_FLOOD
        else:
            print("----> ", eth.ethertype, src , dst)
            # use dijkstra to find the shortest path from src to dst.
            p = get_path(int(mymac[src][0]), int(mymac[dst][0]), mymac[src][1], mymac[dst][1])
            print (p)
            # print("226 ----->  ", p[0][2], self.mac_to_port[dpid][dst], type(p[0][2]), type(self.mac_to_port[dpid][dst]))
            # add flow entries to each switch in our shortest path p.
            self.install_path(p, ev, src, dst)
            # print("229 ---->  ", int(mymac[src][0]), int(mymac[dst][0]), mymac[src][1], mymac[dst][1], msg.match['in_port'], dpid, self.mac_to_port[dpid][dst])
            # since we know that dst mac address is already learned,
            # we can easily decide which port to output the packet.
            out_port = self.mac_to_port[dpid][dst]

        actions = [parser.OFPActionOutput(out_port)]

        # Specifies the binary data of packets. This is used when OFP_NO_BUFFER is specified for buffer_id. When the OpenFlow switch’s buffer is used, this is omitted.
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        # Regardless whether the destination MAC address is found from the MAC address table,
        # at the end the Packet-Out message is issued and received packets are transferred.
        # in_port, Specifies the port that received packets. if it is not the received packet, OFPP_CONTROLLER is specified.
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)


    # """
    #   The event EventSwitchEnter will trigger the activation of get_topology_data().
    #   Next we call get_switch() to get the list of objects Switch, and get_link() to get the list of objects Link.
    #   This objects are defined in the topology.switches file. Then, we build a list with all the switches ([switches]) and next a list with all the links [(srcNode, dstNode, srcPort,dstPort)].
    #   Notice that we also get the port from the source node that arrives at the destination node, and reverse as that information will be necessary later during the forwarding step.
    # """
    @set_ev_cls(event.EventSwitchEnter)
    def get_topology_data(self, ev):
        global switches

        # getting list of objects Switch
        switch_list = get_switch(self.topology_api_app, None)

        #getting switches Id ( switches Id are like 1,2,3,... buy in pictures they are like s1,s2,s3,...)
        switches=[switch.dp.id for switch in switch_list]
        #setting datapath_dict with dictionary of {switches Id: switches datapath}
        self.datapath_dict= dict([(switch.dp.id, switch.dp) for switch in switch_list])

        print("switches=", switches)

        #getting list of objects link
        links_list = get_link(self.topology_api_app, None)

        #creating list of connections in network as (srcId, destId, src_port, dest_port)
        mylinks= [(link.src.dpid, link.dst.dpid, link.src.port_no, link.dst.port_no) for link in links_list]

        #setting adjacency graph as matrix in which each element in matrix is equal to port that index in first is routed to second
        #for example if switch s2 in network has link to switch s3 by port number 5 then the adjacency matrix fill as adjacency[s2][s3] = 5
        #we use this adjacency in dijkstra algorithm to find shortest path in network
        for s1, s2, port1, port2 in mylinks:
            adjacency[s1][s2]= port1
            adjacency[s2][s1]= port2


        print("adjacency list")
        for key in adjacency:
            print (key, ":", adjacency[key])

        #sometimes in running mininet with remote controller controller.py, connection between mininet and ryu isn't become stable
        #so in this moments get_link function can't get links in network and mylinks and adjacency matrix become null
        #becuase of that program doesn't work well and mininet host can't get packets and packets lost become 100%
        #so this part of code warn and abort the program
        if not adjacency:
            print("coudl'nt get links from  mininet")
            print("this is not our fault :)\nplease try running again !")
            os.abort()
