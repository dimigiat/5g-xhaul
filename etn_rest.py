# This is a controller for the datapath of an ETN
# which exposes a REST API to an upper layer controller

import etn
import json
from webob import Response
from ryu.app.wsgi import ControllerBase, WSGIApplication, route

etn_instance_name = 'etn_la_api_app'

url1 = '/vifaces/l2sids'
url2 = '/vifaces/l2sids/{l2sid}/mac_addresses'
url3 = '/vifaces/l2sids/{l2sid}/mac_addresses/{mac}'
url4 = '/tunnels'
url5 = '/tunnels/{tunid}'


class ETN_Rest_OF13(etn.ETN13):

    _CONTEXTS = { 'wsgi': WSGIApplication }

    def __init__(self,*args,**kwargs):
        super(ETN_Rest_OF13, self).__init__(*args, **kwargs)
        # wsgi is a reference to a WSGIApplication instance
        wsgi = kwargs['wsgi']
        # We use it to register the Url_Http_Xhaul class
        wsgi.register(Url_Http_Etn, {etn_instance_name: self})       


    # Called when an HTTP PUT request arrives at the URL
    def vifaces_msg_parser(self,msg):
        new_l2sid_and_mac_to_port=msg["l2sid_and_mac_to_port"]
        new_l2sid_and_mac_to_etn=msg["l2sid_and_mac_to_etn"]
        for item in new_l2sid_and_mac_to_port:
            port=item["port"]
            l2sid=item["l2sid"]
            mac=item["mac"]
            if port==0: #then this is a removal
                port=self.l2seg_mac_to_port[(l2sid,mac)]
                self.port_to_l2sid_removal(port)
                self.l2sid_and_mac_to_port_removal(l2sid,mac)
            else:
                self.port_to_l2sid_update(port,l2sid)
                self.l2sid_and_mac_to_port_update(l2sid,mac,port)
        for item in new_l2sid_and_mac_to_etn:
            l2sid=item["l2sid"]
            mac=item["mac"]
            etn=item["etn"]
            if etn==0:
                self.l2sid_and_mac_to_etn_removal(l2sid,mac)
            else:
                self.l2sid_and_mac_to_etn_update(l2sid,mac,etn)

    def paths_msg_parser(iself,item):
        paths=item["paths"]
        dst_etn=item["dst_etn"]
        instr=item["instruction"]
        if instr=="remove":
            self.etn_to_path_removal(dst_etn,paths)
        elif instr=="add":
            self.etn_to_path_update(dst_etn,paths,replace=False)
        else:
            self.etn_to_path_update(dst_etn,paths)
                   

class Url_Http_Etn(ControllerBase):
    def __init__(self, req, link, data, **config):
        super(Url_Http_Etn, self).__init__(req, link, data, **config)
        self.etn_spp = data[etn_instance_name]

    @route('update_viface',url3,methods=['PUT'])
    def update_viface(self, req, **kwargs):
        etn_rest = self.etn_spp
	l2sid=kwargs["l2sid"]
        l2sid=int(l2sid)
	viface_mac=kwargs["mac"]
        req_body = eval(req.body)
	etnid=req_body["etnid"]
        try:         
            etn_rest.update_viface(l2sid,viface_mac,etnid)
	    return_msg="Entry of Viface with l2sid %s and mac %s, located in ETN %s, successfully installed.\n" % (l2sid,viface_mac,etnid) # Stub 
            return Response(status=200, body=json.dumps(return_msg))
        except Exception as e:
            return Response(status=500)

    @route('remove_viface',url3,methods=['DELETE'])
    def remove_viface(self,req,**kwargs):
        etn_rest = self.etn_spp
        l2sid=kwargs["l2sid"]
        l2sid=int(l2sid)
        viface_mac=kwargs["mac"]
        try:
            etn_rest.remove_viface(l2sid,viface_mac)
            return Response(status=204)
        except Exception as e:
            return Response(status=500)

    @route('add_tunnel', url5, methods=['PUT'])
    def add_tunnel(self,req,**kwargs):
        etn_rest = self.etn_spp
        req_body=eval(req.body)
        etnid=req_body["etnid"]
	tunid=kwargs["tunid"]
        tunid=int(tunid)
        try:
            etn_rest.add_tunnel(tunid=tunid,dst=etnid)
            #etn_rest.etn_to_path_update(etn=etnid,paths=[tunid],replace=True)
            return Response(status=200)
        except Exception as e:
            return Response(status=500)

    @route('remove_tunnel',url5,methods=['DELETE'])
    def remove_tunnel(self,req,**kwargs):
        etn_rest=self.etn_spp
        tunid=kwargs["tunid"]
        try:
            etn_rest.remove_tunnel(tunid)
            return Response(status=204)
        except Exception as e:
            return Response(status=500)

    @route('get_l2sids', url1, methods=['GET'])
    def get_l2sids(self,req,**kwargs):
        etn_rest = self.etn_spp
        l2sid_list=[l2sid for l2sid in etn_rest.vifaces]
        try:        
            return Response(content_type='application/json', body=json.dumps(l2sid_list))
        except Exception as e:
            return Response(status=500)
        

    @route('get_vifaces_by_l2sid', url5, methods=['GET']) 
    def get_vifaces_by_l2sid(self,req,**kwargs):
        etn_rest = self.etn_spp
        l2sid=kwargs["l2sid"]
        if l2sid not in etn_rest.vifaces:
            return Response(status=404, body="No virtual interfaces with L2SID %s exist in this ETN" % l2sid )
        try:
            reply=etn_rest.vifaces["l2sid"]
	except Exception as e:
	    return Response(status=500)


 
