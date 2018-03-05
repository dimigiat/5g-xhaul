# This app implements the ETNC component of the Area Controller in a 5G-Xhaul control area
# It communicates southbound with the individual ETN controllers and northbound with the L1 controller
# It can also communicate with the TNC component of the Area Controller
# All of these interactions take place through RESTful APIs
#
# The main operation of this app is to parse instructions coming from the L1 controller,
# figure out which ETNs are affected, and send ETN-specific instructions to these ETNs
# It also requests new tunnels from the TNC and informs the respective source ETNs of the tunnel IDs
#
# Expected types of instructions received:
# - Addition/Removal of ETNs
# - Creation/Migration/Removal of virtual interfaces
# - Creation/Removal of Tunnels for inter-ETN transports 
#
# Expected types of instructions dispatched to an ETN:
# - Viface (l2sid:mac) entries the ETN should know about
# - Tunnel IDs for the source ETNs of tunnels
#
# Expected types of instructions dispatched to TNC:
# - Creation/Removal of tunnels


from ryu.base import app_manager
from webob import Response, Request
import requests
import json
import collections

class Area(app_manager.RyuApp):
    def __init__(self,*args,**kwargs):
        super(Area,self).__init__(*args,**kwargs)
         
        # Dictionary mapping ETN IDs to instances of class ETN
        self.etns={}
        #self.etns[1]=Etn(etnid=1,ip="0.0.0.0",port="8081")
        # The nested dictionary below lists all vifaces in the area 
        # {"L2SID1":{
        #     "mac1":{"etnid":XX},   
        #     "mac2":{"etnid":YY}
        #         ...

        self.etnid_to_name={"00:03:1d:0d:bc:89":"ETN1","00:03:1d:0d:bc:a1":"ETN2","00:03:1d:0d:bc:a9":"ETN3"}
        
        self.vifaces={}
        self.tunnels={}
        self.tnc_ip="84.88.34.33"
        self.tnc_port="8181"
        self.tnc_headers={"authorization":"Basic dXNlcjp1c2Vy","cache-control":"no-cache","content-type":"application/json"}

    def get_etns(self):
        return self.etns.keys()

    def add_etn(self,etnid,ip,port):
        self.etns[etnid]=Etn(etnid=etnid,ip=ip,port=port)
        print self.etns

    def remove_etn(self,etnid):
        del self.etns[etnid]

    def get_vifaces_by_etnid(self,etnid):
        print self.etns
        return self.etns[etnid].get_local_vifaces()

    def update_viface(self, l2sid, mac, etnid):
        # First we check if viface exists in other etn (migration)
        # In this case we remove it from local entry of old etn
        if l2sid in self.vifaces:
            if mac in self.vifaces[l2sid]:
                if self.vifaces[l2sid][mac]["etnid"]!=etnid:
                    old_etnid=self.vifaces[l2sid][mac]["etnid"]
                    print "Viface migrating away from %s" % old_etnid
                    # The command below does not have direct effect on the flow tables
                    self.etns[old_etnid].remove_local_viface(l2sid,mac)
                    print "Removed local viface from old etn"
                    # If old_etn no longer has l2sid, we have to remove relevant entries (including old own entry)
                    # If it still does, it will be informed for the update of the viface in the last loop of this method
                    if not self.etns[old_etnid].l2sid_exists(l2sid):
                        print "Found out that the old etn does not have l2sid any more"
                        for mac_iter in self.vifaces[l2sid]:
                            print "Removing L2SID %s and mac %s from old etn" % (l2sid,mac_iter)
                            self.etns[old_etnid].remove_viface(l2sid,mac_iter)
                    del self.vifaces[l2sid][mac]
                    # No need to check for removing l2sid subdictionary here, as we know
                    # we're about to have a new entry for it
        # We're checking about vifaces the host etn should know about if it is new in this L2SID
        # Note that the obsolete entry, in case of migration, has been just removed
        if not self.etns[etnid].l2sid_exists(l2sid) and l2sid in self.vifaces:
            print "First time that ETN %s is to install viface of L2SID %s" % (etnid,l2sid)
            print "Currently the area vifaces record for L2SID %s is as follows" % l2sid
            print self.vifaces[l2sid]
            for existing_mac in self.vifaces[l2sid]:
                print "MAC to be installed %s" % existing_mac
                res=self.etns[etnid].update_viface(l2sid,existing_mac,self.vifaces[l2sid][existing_mac]["etnid"])
                if res.status_code!=200:
                    print "L2SID %s, MAC %s at %s not installed in %s"%(l2sid,mac,self.vifaces[l2sid][mac]["etnid"],etnid)
        self.etns[etnid].add_local_viface(l2sid,mac)
        for item in self.etns:
            if self.etns[item].l2sid_exists(l2sid):
                res=self.etns[item].update_viface(l2sid,mac,etnid)
                if res.status_code!=200:
                    print "L2SID %s, MAC %s interface hosted at %s not installed at %s"%(l2sid,mac,etnid,item)
                    # We need to decide what happens if subset of requests fails
        if l2sid not in self.vifaces:
            self.vifaces[l2sid]={}
        self.vifaces[l2sid][mac]={"etnid":etnid}


    def remove_viface(self,l2sid,mac):
        for item in self.etns:
            if self.etns[item].l2sid_exists(l2sid): # Then they should locally have this entry
                res=self.etns[item].remove_viface(l2sid,mac)
                if res.status_code!=204:
                    print "Something went wrong with viface (%s , %s) removal at ETN %s" % (l2sid,mac,item)
        del self.vifaces[l2sid][mac] 


    def create_tunnel(self,source,target,tunid):
        print "Im in ACs create tunnel and about to call TNCs API"
        addr="http://"+str(self.tnc_ip)+":"+str(self.tnc_port)+"/restconf/operations/fivegxhaul:createTunnel"
        src=self.etnid_to_name[source]
        dst=self.etnid_to_name[target]
        tunid=int(tunid)
        msg={"input":{"tunnelId":tunid,"sourceNode":src,"destinationNode":dst}}
        json_msg=json.dumps(msg)
        print "Addr is %s and msg is %s" % (addr,json_msg)
        res=requests.post(url=addr,data=json_msg,headers=self.tnc_headers)
        print res
        if res.status_code==200:
            print "Successful tunnel creation by TNC"
            self.add_tunnel(source,target,tunid)
        return res


    def add_tunnel(self,src_etn,dst_etn,tunid):
        tunid=int(tunid)
        self.tunnels[tunid]={"src_etn":src_etn,"dst_etn":dst_etn}
        etn=self.etns[src_etn]
        res=etn.add_tunnel(dst_etn,tunid)
        if res.status_code!=200:
            print "Something went wrong with tunnel installation at the ETNs"

    def remove_tunnel(self,tunid):
        print "Im in ACs remove tunnel"
        print self.tunnels
        tunid=int(tunid)
        src_etn=self.tunnels[tunid]["src_etn"]
        print "Src_etn is %s" % src_etn
        etn=self.etns[src_etn]
        print "Ready to remove tunnel from its src etn"
        res=etn.remove_tunnel(tunid)
        if res.status_code!=204:
            print "Something went wrong with tunnel removal from ETN %s" %src_etn
        del self.tunnels[tunid]


class Etn:
    def __init__(self,etnid,ip="0.0.0.0",port="8080"):

        self.etnid=etnid
        self.ip=ip
        self.port=port
        
        self.local_vifaces={}

    def get_local_vifaces(self):
        return self.local_vifaces

    def add_local_viface(self,l2sid,mac):
        if l2sid not in self.local_vifaces:
            self.local_vifaces[l2sid]=[]
        self.local_vifaces[l2sid].append(mac)

    def remove_local_viface(self,l2sid,mac):
        self.local_vifaces[l2sid].remove(mac)
        if self.local_vifaces[l2sid]==[]:
            del self.local_vifaces[l2sid]

    def update_viface(self,l2sid,mac,etnid):
        addr="http://"+str(self.ip)+":"+str(self.port)+"/vifaces/l2sids/"+str(l2sid)+"/mac_addresses/"+str(mac)
        msg={"etnid":etnid}
        print "Address and Message to be sent to ETN LA are %s and %s" % (addr,msg)
        json_msg=json.dumps(msg)
        res=requests.put(addr,json_msg)
        return res
 
    def remove_viface(self,l2sid,mac):
        print "Im in area controller's etn.remove_viface"
        if l2sid in self.local_vifaces: 
            if mac in self.local_vifaces[l2sid]:
                self.remove_local_viface(l2sid,mac)
        addr="http://"+str(self.ip)+":"+str(self.port)+"/vifaces/l2sids/"+str(l2sid)+"/mac_addresses/"+str(mac)
        print "URL for viface removal is %s" % addr
        res=requests.delete(addr)
        return res

    def l2sid_exists(self,l2sid):
        return l2sid in self.local_vifaces
                         
    def add_tunnel(self,dst_etn,tunid):
        print "Im in etn.add_tunnel of ETN %s" % self.etnid
        addr="http://"+str(self.ip)+":"+str(self.port)+"/tunnels/"+str(tunid)
        msg={"etnid":dst_etn}
        print msg
        json_msg=json.dumps(msg)
        res=requests.put(addr,json_msg)
        return res

    def remove_tunnel(self,tunid):
        print "Im in etn.remove_tunnel of ETN %s" % self.etnid 
        addr="http://"+str(self.ip)+":"+str(self.port)+"/tunnels/"+str(tunid)
        res=requests.delete(addr)
        return res   
        
