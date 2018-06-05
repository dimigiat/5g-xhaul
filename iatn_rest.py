# This is a controller for the datapath of an IATN
# which exposes a REST API to an upper layer controller

import iatn
import json
from webob import Response
from ryu.app.wsgi import ControllerBase, WSGIApplication, route

etn_instance_name = 'iatn_la_api_app'

url1 = '/tunnels'
url2 = '/tunnels/{incoming_vlan}'


class IATN_Rest_OF13(iatn.IATN13):

    _CONTEXTS = { 'wsgi': WSGIApplication }

    def __init__(self,*args,**kwargs):
        super(IATN_Rest_OF13, self).__init__(*args, **kwargs)
        # wsgi is a reference to a WSGIApplication instance
        wsgi = kwargs['wsgi']
        # We use it to register the Url_Http_Xhaul class
        wsgi.register(Url_Http_Iatn, {iatn_instance_name: self})       


    # def paths_msg_parser(iself,item):
    #     paths=item["paths"]
    #     dst_etn=item["dst_etn"]
    #     instr=item["instruction"]
    #     if instr=="remove":
    #         self.etn_to_path_removal(dst_etn,paths)
    #     elif instr=="add":
    #         self.etn_to_path_update(dst_etn,paths,replace=False)
    #     else:
    #         self.etn_to_path_update(dst_etn,paths)
                   

class Url_Http_Iatn(ControllerBase):
    def __init__(self, req, link, data, **config):
        super(Url_Http_Iatn, self).__init__(req, link, data, **config)
        self.iatn_spp = data[iatn_instance_name]

    @route('add_tunnel', url2, methods=['PUT'])
    def add_tunnel(self,req,**kwargs):
        iatn_rest = self.iatn_spp
        req_body=eval(req.body)
        in_port=req_body["in_port"]
		incoming_vlan=kwargs["incoming_vlan"]
        incoming_vlan=int(incoming_vlan)
        outgoing_vlan=req_body["outgoing_vlan"]
        out_port=req_body["out_port"]
        try:
            iatn_rest.add_tunnel(incoming_vlan=incoming_vlan,outgoing_vlan=outgoing_vlan,in_port=in_port,out_port=out_port)
            return Response(status=200)
        except Exception as e:
            return Response(status=500)

    @route('remove_tunnel',url2,methods=['DELETE'])
    def remove_tunnel(self,req,**kwargs):
        iatn_rest=self.iatn_spp
        tunid=kwargs["incoming_vlan"]
        tunid=int(tunid)
        try:
            iatn_rest.remove_tunnel(tunid)
            return Response(status=204)
        except Exception as e:
            return Response(status=500)

 
