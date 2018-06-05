from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3, ether
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import vlan
from ryu import utils

class IATN13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    TABLE_VLAN_CHANGE = 0 # TABLE_VLAN_CHANGE is for changing the VLAN header.

    def __init__(self, *args, **kwargs):
        super(IATN13, self).__init__(*args, **kwargs)

        #self.local_tunnels={}
        
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        self.datapath = ev.msg.datapath
        self.ofproto = self.datapath.ofproto
        self.parser = self.datapath.ofproto_parser

        self.logger.info('Datapath id: %016x', self.datapath.id)
        ## Remove all flows from all tables.
        mod = self.parser.OFPFlowMod(self.datapath, 0, 0, self.ofproto.OFPTT_ALL, self.ofproto.OFPFC_DELETE, 0, 0, 1, self.ofproto.OFPCML_NO_BUFFER, self.ofproto.OFPP_ANY, self.ofproto.OFPG_ANY, 0, self.parser.OFPMatch(), [])
        self.datapath.send_msg(mod)
        
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

###################################################################################################

    def add_tunnel(self,incoming_vlan,outgoing_vlan,in_port,out_port):
        match = self.parser.OFPMatch()
        match.set_vlan_vid(incoming_vlan)
        match.in_port(in_port)
        actions = [self.parser.OFPActionSetField(vlan_vid=outgoing_vlan),
                   self.parser.OFPActionOutput(out_port)]
        inst = [self.parser.OFPInstructionActions(self.ofproto.OFPIT_APPLY_ACTIONS, actions)]
        self.add_flow(priority=1, table_id=self.TABLE_VLAN_CHANGE, match=match, actions=actions, buffer_id=self.ofproto.OFP_NO_BUFFER)


