# REST interface for Area Controller

import logging
from ryu.app.wsgi import ControllerBase, WSGIApplication, route
import area
import json
from webob import Response

area_instance_name='area_api_app'

url1='/vifaces'
url2='/vifaces/l2sids/{l2sid}/mac_addresses'
url3='/vifaces/l2sids/{l2sid}/mac_addresses/{mac}'
url4='/tunnels'
url5='/tunnels/{tunid}'
url6='/etns'
url7='/etns/{etnid}'
url8='/tunnels2/{tunid}'
url9='/copTopology'

class Rest_Area(area.Area):

    _CONTEXTS = { 'wsgi': WSGIApplication }
    
    def __init__(self,*args,**kwargs):
        super(Rest_Area,self).__init__(*args,**kwargs)
        wsgi=kwargs['wsgi']
        wsgi.register(Url_Http_Area, {area_instance_name:self} )
        


class Url_Http_Area(ControllerBase):

    def __init__(self,req,link,data,**config):
        super(Url_Http_Area,self).__init__(req,link,data,**config)
        self.area_spp=data[area_instance_name]


    @route('get_vifaces_by_etnid',url1,methods=['GET'])
    def get_vifaces_by_etnid(self,req,**kwargs):
        area_rest=self.area_spp
        etnid=req.params["etnid"]
        etnid=str(etnid)
        try:
            etn_vifaces=area_rest.get_vifaces_by_etnid(etnid)
            body=json.dumps(etn_vifaces)
            return Response(content_type='application/json',body=body)
        except Exception as e:
            return Response(status=500)

    @route('update_viface',url3,methods=['PUT'])
    def update_viface(self,req,**kwargs):
        area_rest=self.area_spp
        l2sid=kwargs["l2sid"]
        mac=kwargs["mac"]
        etnid=eval(req.body)["etnid"]
        try:
            area_rest.update_viface(l2sid,mac,etnid)
            return Response(status=200)
        except Exception as e:
            return Response(status=500)

    @route('remove_viface',url3,methods=['DELETE'])
    def remove_viface(self,req,**kwargs):
        area_rest=self.area_spp
        l2sid=kwargs["l2sid"]
        mac=kwargs["mac"]
        try:
            area_rest.remove_viface(l2sid,mac)
            return Response(status=204)
        except Exception as e:
            return Response(status=500)
    
    @route('get_etns',url6,methods=['GET'])
    def get_etns(self,req,**kwargs):
        area_rest=self.area_spp
        try:
            etnlist=area_rest.get_etns()
            body=json.dumps(etnlist)
            return Response(content_type='application/json',body=body)
        except Exception as e:
            return Response(status=500)

    @route('add_etn',url7,methods=['PUT'])
    def add_etn(self,req,**kwargs):
        area_rest=self.area_spp
        etnid=kwargs["etnid"]
        etnid=str(etnid)
        etnip=eval(req.body)["ip"]
        etnport=eval(req.body)["port"]
        try:
            area_rest.add_etn(etnid,etnip,etnport)
            return Response(status=200)
        except Exception as e:
            return Response(status=500)

    @route('remove_etn',url7,methods=['DELETE'])
    def remove_etn(self,req,**kwargs):
        area_rest=self.area_spp
        etnid=kwargs["etnid"]
        etnid=str(etnid)
        try:
            area_rest.remove_etn(etnid)
            return Response(status=204)
        except Exception as e:
            return Response(status=500)



    @route('add_tunnel',url5,methods=['PUT'])
    def add_tunnel(self,req,**kwargs):
        area_rest=self.area_spp
        req_body=eval(req.body)
        src_etn=req_body["src_etn"]
        dst_etn=req_body["dst_etn"]
        tunid=kwargs["tunid"]
        tunid=str(tunid)
        try:
            area_rest.add_tunnel(src_etn,dst_etn,tunid)
            return Response(status=200)
        except Exception as e:
            return Response(status=500)
        
    @route('create_tunnel',url4,methods=['POST'])
    def create_tunnel(self,req,**kwargs):
        area_rest=self.area_spp
        req_body=eval(req.body)
        src_etn=req_body["src_etn"]
        dst_etn=req_body["dst_etn"]
        latency=req_body["latency"]
        reserved_bw=req_body["reserved_bw"]
        try:
            area_rest.create_tunnel(src_etn,dst_etn,latency,reserved_bw)  #Need to implement create_tunnel as COP client
            return Response(status=200)
        except Exception as e:
            return Response(status=500)

    @route('remove_tunnel',url5,methods=['DELETE'])
    def remove_tunnel(self,req,**kwargs):
        area_rest=self.area_spp
        tunid=kwargs["tunid"]
        try:
            area_rest.remove_tunnel(tunid)
            return Response(status=204)
        except Exception as e:
            return Response(status=500)

    @route('create_tunnel',url8,methods=['PUT'])
    def create_tunnel(self,req,**kwargs):
        area_rest=self.area_spp
        req_body=eval(req.body)
        src_etn=req_body["src_etn"]
        dst_etn=req_body["dst_etn"]
        tunid=kwargs["tunid"]
        #tunid=str(tunid)
        try:
            res=area_rest.create_tunnel(src_etn,dst_etn,tunid)
            return Response(status=200)
        except Exception as e:
            return Response(status=500)

    @route('getCopTopology',url9,methods=['GET'])
    def getCopTopology(self,req,**kwargs):
        area_rest=self.area_spp
        try:
            res=area_rest.getCopTopology()
            body=res.json()
            body=json.dumps(body)
            return Response(content_type='application/json', body=body)
        except Exception as e:
            return Response(status=500)
