from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3, ether
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import vlan
from ryu import utils

class ETN13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    TABLE_VLAN_REM = 0 # TABLE_VLAN_REM is for removing the VLAN header if it exists.
    TABLE_PBB_REM = 1 # TABLE_PBB_REM is for removing the PBB header if it exists.
    TABLE_SRC = 2 # TABLE_SRC is for reading the src MAC and writing in metadata the L2seg of the packet.
    TABLE_DST = 3 # TABLE_DST is for reading metadata and the dst MAC and forwarding the packet to the appropriate port.
    TABLE_PBB_MOD = 4 # TABLE_PBB_MOD is for modifing the PBB header before forwarding to ext_port.

    CREATE_FLOWS_REACTIVELY = False

    def __init__(self, *args, **kwargs):
        super(ETN13, self).__init__(*args, **kwargs)
        
        #self.etnid=kwargs["etnid"]
        # An option is to set self.etnid equal to self.datapath.id in switch_features_handler method
        #self.etnid=open('/sys/class/net/eth0/address').readline()  
        #print self.etnid
        # Nested dictionary. Outer key: l2sid , Middle key: mac, Inner keys: port, etnid
        # (This should replace the l2seg_mac_to_port and l2seg_mac_to_etn dictionaries)
        self.vifaces={}

        self.local_vifaces={}

        self.etnid = None

        # Hardcoded dictionary for all potential local vifaces
        # In practice, some Openstack functionality might replace this
        self.local_viface_to_port={20:{"00:00:00:00:00:04":2,"00:00:00:00:00:05":3}}  

        self.port_to_l2seg = {} 
        self.l2seg_mac_to_port = {}
	self.etn_to_tunnel={} # To replace etn_to_path dictionary. Tunnels might map to multiple paths (load balancing, failover)

        self.local_tunnels={}       

        self.etn_to_path = {}
        self.l2seg_mac_to_etn = {}
        self.l2seg_mac_to_path = {}


        self.datapath = None
        self.ofproto = None
        self.parser = None
        self.ext_port = 1 # ext_port is the port connecting this ETN with the other ETN's. Any packet forwarded to this port, has to be tagged with VLAN and PBB.
        self.ext_port_name = "eth1"
        self.ext_port_mac = ''

        if self.CREATE_FLOWS_REACTIVELY:
            self.logger.info("This ETN controller enables flows to be configured reactively.")
        else:
            self.logger.info("This ETN controller DOES NOT enable flows to be configured reactively.")

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        self.datapath = ev.msg.datapath
        self.ofproto = self.datapath.ofproto
        self.parser = self.datapath.ofproto_parser

        self.logger.info('Datapath id: %016x', self.datapath.id)
        ## Remove all flows from all tables.
        mod = self.parser.OFPFlowMod(self.datapath, 0, 0, self.ofproto.OFPTT_ALL, self.ofproto.OFPFC_DELETE, 0, 0, 1, self.ofproto.OFPCML_NO_BUFFER, self.ofproto.OFPP_ANY, self.ofproto.OFPG_ANY, 0, self.parser.OFPMatch(), [])
        self.datapath.send_msg(mod)

        ## Configure TABLE_VLAN_REM with two flows. One for removing the VLAN header, if it exists, and sending the packet to TABLE_SRC. 
        match = self.parser.OFPMatch(vlan_vid=(0x1000, 0x1000))
        actions = [self.parser.OFPActionPopVlan()]
        inst = [self.parser.OFPInstructionActions(self.ofproto.OFPIT_APPLY_ACTIONS, actions), self.parser.OFPInstructionGotoTable(self.TABLE_PBB_REM)]
        self.add_flow(priority=1, table_id=self.TABLE_VLAN_REM, match=match, inst=inst, buffer_id=self.ofproto.OFP_NO_BUFFER)
        ## If packet is not VLAN packet, it will be forwarded as it is by a table-miss flow to TABLE_SRC.
        match = self.parser.OFPMatch()
        inst = [self.parser.OFPInstructionGotoTable(self.TABLE_SRC)]
        self.add_flow(priority=0, table_id=self.TABLE_VLAN_REM, match=match, inst=inst, buffer_id=self.ofproto.OFP_NO_BUFFER)

        ## Configure TABLE_PBB_REM with two flows. One for removing the PBB header, if it exists, and sending the packet to TABLE_SRC. 
        match = self.parser.OFPMatch(eth_type=ether.ETH_TYPE_8021AH)
        actions = [self.parser.OFPActionPopPbb()]
        inst = [self.parser.OFPInstructionActions(self.ofproto.OFPIT_APPLY_ACTIONS, actions), self.parser.OFPInstructionGotoTable(self.TABLE_SRC)]
        self.add_flow(priority=1, table_id=self.TABLE_PBB_REM, match=match, inst=inst, buffer_id=self.ofproto.OFP_NO_BUFFER)
        ## If packet is not PBB packet, it will be forwarded as it is by a table-miss flow to TABLE_SRC.
        match = self.parser.OFPMatch()
        inst = [self.parser.OFPInstructionGotoTable(self.TABLE_SRC)]
        self.add_flow(priority=0, table_id=self.TABLE_PBB_REM, match=match, inst=inst, buffer_id=self.ofproto.OFP_NO_BUFFER)

        ## Configure TABLE_SRC and TABLE_DST with a table-miss flow that sends the packets to controller.
        match = self.parser.OFPMatch()
        actions = [self.parser.OFPActionOutput(self.ofproto.OFPP_CONTROLLER,
                                               self.ofproto.OFPCML_NO_BUFFER)] # We specify NO BUFFER to max_len of the output action due to OVS bug.
        inst = [self.parser.OFPInstructionActions(self.ofproto.OFPIT_APPLY_ACTIONS, actions)]
        if self.CREATE_FLOWS_REACTIVELY:
            self.add_flow(priority=0, table_id=self.TABLE_SRC, match=match, inst=inst, buffer_id=self.ofproto.OFP_NO_BUFFER)
        self.add_flow(priority=0, table_id=self.TABLE_DST, match=match, inst=inst, buffer_id=self.ofproto.OFP_NO_BUFFER)

        ## Configure dictionaries
        #self.port_to_l2seg = {2: 0x10, 3: 0x10, 4: 0x10} 
        #self.l2seg_mac_to_port = {(0x10, "00:00:00:00:00:01"): 2, (0x10, "00:00:00:00:00:02"): 3, (0x10, "00:00:00:00:00:03"): 4, (0x10, "00:00:00:00:00:04"): 1}
        #self.etn_to_path = {"00:00:00:00:01:02": [1, 2, 3]}
        #self.l2seg_mac_to_etn = {(0x10, "00:00:00:00:00:04"): "00:00:00:00:01:02"}
        #self.l2seg_mac_to_path = {(0x10, "00:00:00:00:00:04"): 2}

        ## Request port descriptions to learn the MAC of the ext_port.
        req = self.parser.OFPPortDescStatsRequest(self.datapath, 0)
        self.datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPPortDescStatsReply, MAIN_DISPATCHER)
    def port_desc_stats_reply_handler(self, ev):
        self.logger.debug("This ETN controller searches for an external port named: %s.", self.ext_port_name)
        for p in ev.msg.body:
            if self.ext_port_name in p.name:
                self.ext_port = p.port_no
                self.ext_port_mac = p.hw_addr
                self.logger.info('Name, port and MAC address of external port: %s, %s, %s', p.name, self.ext_port, self.ext_port_mac)
        ## After retrieving the ext_port, we can configure proactively some flows.
        #self.configure_flows()

#############################################################################################################

    def create_actions(self, l2seg, out_ports):
        actions = [self.parser.OFPActionOutput(out_port) for out_port in out_ports]
        if self.ext_port in out_ports: 
            ext_port_push_vlan = [self.parser.OFPActionPushVlan(ether.ETH_TYPE_8021Q), 
                                  self.parser.OFPActionSetField(vlan_vid=l2seg|ofproto_v1_3.OFPVID_PRESENT)]
            ext_port_push_pbb = [self.parser.OFPActionPushPbb(ether.ETH_TYPE_8021AH)]
            actions = actions[:-1] + ext_port_push_vlan + ext_port_push_pbb # ext_port should always be the last one, since before packet be forwarded to this port, it will be tagged with L2seg id.
        return actions

    def create_actions_pbb(self, l2seg, out_ports, etn="ff:ff:ff:ff:ff:ff", path=0):
        actions_pbb = []
        if self.ext_port in out_ports: 
            ext_port_push_pbb = [self.parser.OFPActionSetField(eth_src=self.ext_port_mac), 
                                 self.parser.OFPActionSetField(eth_dst=etn), 
                                 self.parser.OFPActionPushVlan(ether.ETH_TYPE_8021Q), 
                                 self.parser.OFPActionSetField(vlan_vid=path|ofproto_v1_3.OFPVID_PRESENT)] #self.parser.OFPActionSetField(pbb_isid=path)]
            actions_pbb = ext_port_push_pbb + [self.parser.OFPActionOutput(self.ext_port)]
        return actions_pbb

#############################################################################################################

    def add_flow(self, priority, table_id, match, inst, buffer_id):
        mod = self.parser.OFPFlowMod(datapath=self.datapath, priority=priority,
                                match=match, table_id=table_id, instructions=inst, buffer_id=buffer_id)
        self.datapath.send_msg(mod)

    def rem_flow(self, table_id, match):
        mod = self.parser.OFPFlowMod(self.datapath, 0, 0, table_id, self.ofproto.OFPFC_DELETE, 
                                0, 0, 1, self.ofproto.OFPCML_NO_BUFFER, self.ofproto.OFPP_ANY, 
                                self.ofproto.OFPG_ANY, 0, match, [])
        self.datapath.send_msg(mod)

#############################################################################################################

    def port_to_l2sid_removal(self, port):
        match = self.parser.OFPMatch(in_port=port)
        self.rem_flow(table_id=self.TABLE_SRC, match=match) 
        del self.port_to_l2seg[port]

    def port_to_l2sid_addflow (self, port, l2seg, buffer_id):
        match = self.parser.OFPMatch(in_port=port)
        inst = [self.parser.OFPInstructionWriteMetadata(l2seg, 0xffffffffffffffff), self.parser.OFPInstructionGotoTable(self.TABLE_DST)]
        self.add_flow(priority=1, table_id=self.TABLE_SRC, match=match, inst=inst, buffer_id=buffer_id)

    def port_to_l2sid_update (self, port, l2seg):
        self.port_to_l2sid_addflow(port, l2seg, self.ofproto.OFP_NO_BUFFER)
        self.port_to_l2seg[port] = l2seg
        self.logger.debug("port_to_l2sid:%s", self.port_to_l2seg)

    def l2sid_and_mac_to_port_removal (self, l2seg, mac):
        match = self.parser.OFPMatch(metadata=l2seg, eth_dst=mac)
        self.rem_flow(table_id=self.TABLE_DST, match=match) 
        del self.l2seg_mac_to_port[(l2seg, mac)]

    def l2sid_and_mac_to_port_addflow (self, l2seg, mac, port, buffer_id):
        match = self.parser.OFPMatch(metadata=l2seg, eth_dst=mac)
        actions = self.create_actions(l2seg, [port])
        inst = [self.parser.OFPInstructionActions(self.ofproto.OFPIT_APPLY_ACTIONS, actions)]
        self.add_flow(priority=1, table_id=self.TABLE_DST, match=match, inst=inst, buffer_id=buffer_id)

    def l2sid_and_mac_to_port_update (self, l2seg, mac, port):
        self.l2sid_and_mac_to_port_addflow (l2seg, mac, port, self.ofproto.OFP_NO_BUFFER)
        self.l2seg_mac_to_port[(l2seg, mac)] = port
        self.logger.debug("l2seg_mac_to_port:%s", self.l2seg_mac_to_port)

    def l2sid_and_mac_to_etn_removal (self, l2seg, mac):
        ## The corresponding flow should be removed from TABLE_SRC for the incoming traffic from this MAC, UNLESS this flow is also used by another connection.
        for (l2seg_iter, mac_iter) in self.l2seg_mac_to_etn.keys():
            if l2seg_iter==l2seg and mac_iter!=mac:
                match = self.parser.OFPMatch(vlan_vid=l2seg)
                self.rem_flow(table_id=self.TABLE_SRC, match=match)
                break
        ## The corresponding flow is removed from TABLE_DST for the outgoing traffic to this MAC.
        match = self.parser.OFPMatch(metadata=l2seg, eth_dst=mac)
        self.rem_flow(table_id=self.TABLE_DST, match=match)
        ## The corresponding flow is removed from TABLE_PBB_MOD for the outgoing traffic.
        match = self.parser.OFPMatch(eth_type=ether.ETH_TYPE_8021AH, metadata=l2seg, eth_dst=mac)
        self.rem_flow(table_id=self.TABLE_PBB_MOD, match=match)
        ## Remove from the dictionaries.
        del self.l2seg_mac_to_port[(l2seg, mac)]
        del self.l2seg_mac_to_etn[(l2seg, mac)]
        del self.l2seg_mac_to_path[(l2seg, mac)]

    def l2sid_from_etn_addflow (self, l2seg, buffer_id):
        ## A new flow is configured in TABLE_SRC for the incoming traffic from this MAC.
        match = self.parser.OFPMatch(vlan_vid=l2seg)
        actions = [self.parser.OFPActionPopVlan()]
        inst = [self.parser.OFPInstructionActions(self.ofproto.OFPIT_APPLY_ACTIONS, actions), 
                self.parser.OFPInstructionWriteMetadata(l2seg, 0xffffffffffffffff), 
                self.parser.OFPInstructionGotoTable(self.TABLE_DST)]
        self.add_flow(priority=1, table_id=self.TABLE_SRC, match=match, inst=inst, buffer_id=buffer_id)

    def l2sid_and_mac_to_etn_addflow (self, l2seg, mac, etn, path, buffer_id):
        ## A new flow is configured in TABLE_PBB_MOD for the outgoing traffic.
        match = self.parser.OFPMatch(eth_type=ether.ETH_TYPE_8021AH, metadata=l2seg, eth_dst=mac)
        if path==0:
            path = self.etn_to_path[etn][0] ## To be improved!!
        actions = self.create_actions_pbb(l2seg, [self.ext_port], etn, path)
        inst = [self.parser.OFPInstructionActions(self.ofproto.OFPIT_APPLY_ACTIONS, actions)]
        self.add_flow(priority=1, table_id=self.TABLE_PBB_MOD, match=match, inst=inst, buffer_id=self.ofproto.OFP_NO_BUFFER)
        self.datapath.send_barrier()
        ## A new flow is configured in TABLE_DST for the outgoing traffic to this MAC.
        match = self.parser.OFPMatch(metadata=l2seg, eth_dst=mac)
        actions = self.create_actions(l2seg, [self.ext_port])
        inst = [self.parser.OFPInstructionActions(self.ofproto.OFPIT_APPLY_ACTIONS, actions),
                self.parser.OFPInstructionGotoTable(self.TABLE_PBB_MOD)] # TABLE_PBB_MOD is responsible to match the PBB packet, modify and forward this to ext_port.
        self.add_flow(priority=1, table_id=self.TABLE_DST, match=match, inst=inst, buffer_id=buffer_id)

    def l2sid_and_mac_to_etn_update (self, l2seg, mac, etn, path=0):
        if path==0 and etn not in self.etn_to_path:
            self.logger.info("Flow is not configured since path is not given and there are no paths stored for the given ETN")
            return
        self.l2sid_from_etn_addflow (l2seg, self.ofproto.OFP_NO_BUFFER)
        self.l2sid_and_mac_to_etn_addflow (l2seg, mac, etn, path, self.ofproto.OFP_NO_BUFFER)
        self.l2seg_mac_to_port[(l2seg, mac)] = self.ext_port
        self.l2seg_mac_to_etn[(l2seg, mac)] = etn
        self.l2seg_mac_to_path[(l2seg, mac)] = path
        self.logger.debug("l2seg_mac_to_port:%s", self.l2seg_mac_to_port)
        self.logger.debug("l2seg_mac_to_etn:%s", self.l2seg_mac_to_etn)
        self.logger.debug("l2seg_mac_to_path:%s", self.l2seg_mac_to_path)

    def l2sid_and_mac_to_etn_aggregate_update (self, etn):
        for key, etn_value in self.l2seg_mac_to_etn.items():
            if etn_value==etn and self.l2seg_mac_to_path[key]==0:
                self.l2sid_and_mac_to_etn_update (key[0], key[1], etn)
        
    def etn_to_path_removal (self, etn, paths=[]):
        if paths==[]:
            del self.etn_to_path[etn]
        else:
            for item in paths:
                self.etn_to_path[etn].remove(item)

    def etn_to_path_update (self, etn, paths, replace=True):
        if replace or etn not in self.etn_to_path:
            self.etn_to_path[etn] = paths
            #self.l2sid_and_mac_to_etn_aggregate_update(etn)
        else:
            self.etn_to_path[etn] = self.etn_to_path[etn] + paths
        self.logger.debug("etn_to_path:%s", self.etn_to_path)

    def configure_flows(self):
        ## configure flows for TABLE_SRC.
        for port, l2seg in self.port_to_l2seg.iteritems():
            self.port_to_l2sid_addflow(port, l2seg, self.ofproto.OFP_NO_BUFFER)
        ## configure flows for TABLE_DST.
        for (l2seg, mac), port in self.l2seg_mac_to_port.iteritems():
            if port!=self.ext_port:
                self.l2sid_and_mac_to_port_addflow(l2seg, mac, port, self.ofproto.OFP_NO_BUFFER)
        ## configure flows based on l2seg_mac_to_etn.
        for (l2seg, mac), etn in self.l2seg_mac_to_etn.iteritems():
            path = self.l2seg_mac_to_path[(l2seg, mac)] if (l2seg, mac) in self.l2seg_mac_to_path else 0
            self.l2sid_and_mac_to_etn_update(l2seg, mac, etn, path)

#############################################################################################################

    def send_packet(self, l2seg, in_port, out_ports, buffer_id, data):
        actions = []
        if in_port==self.ext_port:
           actions = [self.parser.OFPActionPopVlan()]
        actions = actions + self.create_actions(l2seg, out_ports)
        actions = actions + self.create_actions_pbb(l2seg, out_ports) 
        out = self.parser.OFPPacketOut(datapath=self.datapath, buffer_id=buffer_id,
                                       in_port=in_port, actions=actions, data=data)
        self.datapath.send_msg(out)

    def packet_in_table_src(self, ev):
        msg = ev.msg
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        eth_vlan = pkt.get_protocols(vlan.vlan)[0] if eth.ethertype==ether.ETH_TYPE_8021Q else None
        src = eth.src 
        ext_port_l2seg = eth_vlan.vid if eth_vlan else None
        in_port = msg.match['in_port']

        data = msg.data if msg.buffer_id==self.ofproto.OFP_NO_BUFFER else None

        self.logger.debug("Packet_in src:%s in_port:%s table_id:%s", src, in_port, msg.table_id)

        ## Check if in_port is not mapped to any L2seg.
        if in_port not in self.port_to_l2seg and in_port!=self.ext_port:
            self.logger.info("Packet from port %s is dropped since this port does not belong to any L2 segment", in_port)
            self.send_packet(None, in_port, [], msg.buffer_id, data) # In case that this packet is buffered, with this send_packet we clear the buffer.
            return

        ## L2seg of the packet is defined by in_port, unless in_port is ext_port, so in this case it is defined by vlan.vid
        l2seg = self.port_to_l2seg[in_port] if in_port!=self.ext_port else ext_port_l2seg

        self.logger.debug("Packet belongs to L2 segment:%s", l2seg)

        ## A new flow is configured in TABLE_SRC.
        if in_port!=self.ext_port:
            self.port_to_l2sid_addflow(in_port, l2seg, msg.buffer_id)
        else:
            self.l2sid_from_etn_addflow(l2seg, msg.buffer_id)

        ## Check and add src MAC to the list of known dst MACs that are mapped to ports.
        if (l2seg, src) not in self.l2seg_mac_to_port:
            self.l2seg_mac_to_port[(l2seg, src)] = in_port

    def packet_in_table_dst(self, ev):
        msg = ev.msg
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        in_port = msg.match['in_port']
        dst = eth.dst
        l2seg = msg.match['metadata']

        data = msg.data if msg.buffer_id==self.ofproto.OFP_NO_BUFFER else None

        self.logger.debug("Packet_in dst:%s in_port:%s table_id:%s ethertype:%s metadata:%s", dst, in_port, msg.table_id, eth.ethertype, msg.match['metadata'])

        self.logger.debug("Packet belongs to L2 segment:%s", l2seg)

        ## Check if dst MAC is included in the known MACs, that are mapped to specific ports.
        if self.CREATE_FLOWS_REACTIVELY and (l2seg, dst) in self.l2seg_mac_to_port:
            out_port = self.l2seg_mac_to_port[(l2seg, dst)]
            if out_port!=self.ext_port:
                self.l2sid_and_mac_to_port_addflow(l2seg, dst, out_port, self.ofproto.OFP_NO_BUFFER) # XXX: if OFP_NO_BUFFER is replaced with buffer_id, the behavior is strange. A packet is copied and sent to ext_port without VLAN and PBB headers.
            ## Send to ext_port if the other ETN and the path are known.
            elif (l2seg, dst) in self.l2seg_mac_to_etn:
                etn = self.l2seg_mac_to_etn[(l2seg, dst)]
                path = 0
                if (l2seg, dst) in self.l2seg_mac_to_path:
                    path = self.l2seg_mac_to_path[(l2seg, dst)]  
                elif etn not in self.etn_to_path:
                    self.logger.info("Packet is dropped since there is no path given to the other ETN")
                    self.send_packet(None, in_port, [], msg.buffer_id, data) # In case that this packet is buffered, with this send_packet we clear the buffer.
                    return
                self.l2sid_and_mac_to_etn_addflow(l2seg, dst, etn, path, msg.buffer_id)
            else:
                self.logger.info("Packet is dropped since the other ETN is not given")
                self.send_packet(None, in_port, [], msg.buffer_id, data) # In case that this packet is buffered, with this send_packet we clear the buffer.
                return
        ## If dst MAC is not included in the known MACs, the packet is sent broadcast only to the ports that have the same L2seg with the in_port.
        elif self.CREATE_FLOWS_REACTIVELY or dst=="ff:ff:ff:ff:ff:ff":
            out_ports = [ out_port for out_port, out_port_l2seg in self.port_to_l2seg.items() if (out_port_l2seg==l2seg and out_port!=in_port) ]
            # Check if this packet should be also forwarded to the ext_port.
            ext_port_l2segs = [ l2seg for (l2seg, mac) in self.l2seg_mac_to_etn.keys() ]
            if l2seg in ext_port_l2segs and self.ext_port!=in_port:
                out_ports.append(self.ext_port) # ext_port should always be the last one, since before packet be forwarded to this port, it will be encapsulated and tagged.
            self.send_packet(l2seg, in_port, out_ports, msg.buffer_id, data)
    
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        if self.CREATE_FLOWS_REACTIVELY:
            if msg.table_id==self.TABLE_SRC:
                self.packet_in_table_src(ev)
            elif msg.table_id==self.TABLE_DST:
                self.packet_in_table_dst(ev)
        else: # Sends only broadcast packets. No configuration of flows.
            self.packet_in_table_dst(ev)

###################################################################################################

    def update_viface(self,l2sid,mac,etnid):
        l2sid=int(l2sid)
        if etnid != self.ext_port_mac:
            if (l2sid,mac) in self.l2seg_mac_to_port: # Then it already exists, either as local or as remote
                port=self.l2seg_mac_to_port[(l2sid,mac)]
                port=int(port)
                if port!=self.ext_port:  # Then this was local, we have to remove relevant entries
                    self.port_to_l2sid_removal(port)
                    self.l2sid_and_mac_to_port_removal(l2seg=l2sid,mac=mac)
            # In all cases, the new viface belongs to another etn, so we update the relevant table
            self.l2sid_and_mac_to_etn_update(l2seg=l2sid,mac=mac,etn=etnid) 
        else:
            port=self.local_viface_to_port[l2sid][mac] # hardcoded workaround
            # We're checking if it migrated here from another ETN
            if (l2sid,mac) in self.l2seg_mac_to_etn:
                self.l2sid_and_mac_to_etn_removal(l2seg=l2sid,mac=mac)
            self.port_to_l2sid_update(port=port,l2seg=l2sid)
            self.l2sid_and_mac_to_port_update(l2seg=l2sid,mac=mac,port=port)
    
    def remove_viface(self,l2sid,mac):
        if (l2sid,mac) not in self.l2seg_mac_to_etn: # Then this is local viface
            port=self.l2seg_mac_to_port[(l2sid,mac)]
            port=int(port)
            self.port_to_l2sid_removal(port)
            self.l2sid_and_mac_to_port_removal(l2seg=l2sid,mac=mac)
        else: # Remote viface
            self.l2sid_and_mac_to_etn_removal(l2seg=l2sid,mac=mac)
        #self.l2sid_and_mac_to_port_removal(l2seg=l2sid,mac=mac) # This should run for both local and remote

    def add_tunnel(self,tunid,dst):
        self.local_tunnels[tunid]=dst
        self.etn_to_path_update(etn=dst,paths=[tunid],replace=True)

    def remove_tunnel(self,tunid):
        tunid=int(tunid)
        dst=self.local_tunnels[tunid]
        self.etn_to_path_removal(etn=dst,paths=[tunid])
        del self.local_tunnels[tunid] 
