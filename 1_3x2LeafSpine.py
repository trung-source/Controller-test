#!/usr/bin/python

# 2-by-2 leaf-spine topology
# from abc import abstractclassmethod
# import abc
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.cli import CLI
from mininet.node import RemoteController, Host
from mininet.link import TCLink
from mininet.log import setLogLevel

locations = {'c0':(550,80)}
class MyTopo(Topo):

    spineswitch = []
    leafswitch = []
    host = []

    def __init__(self):

        # initialize topology
        Topo.__init__(self)

        for i in range(1, 3):
            # add spine switches
            s = self.addSwitch("s"+str(i))
            self.spineswitch.append(s)
            locations.update({s:(100+i*300,200)})
        for i in range(1, 4):
            # add leaf switches
            l = self.addSwitch("s"+str(i+2))
            self.leafswitch.append(l)
            locations.update({l:(50+i*250,350)})

        # add hosts
        self.host.append(self.addHost("h1", mac="00:00:00:00:00:01", ip="10.0.0.1/24"))
        self.host.append(self.addHost("h2", mac="00:00:00:00:00:02", ip="10.0.0.2/24"))
        self.host.append(self.addHost("h3", mac="00:00:00:00:00:03", ip="10.0.0.3/24"))
        self.host.append(self.addHost("h4", mac="00:00:00:00:00:04", ip="10.0.0.4/24"))
        self.host.append(self.addHost("h5", mac="00:00:00:00:00:05", ip="10.0.0.5/24"))
        self.host.append(self.addHost("h6", mac="00:00:00:00:00:06", ip="10.0.0.6/24"))
        for i in range(len(self.host)):
            h = self.host[i]    
            locations.update({h:(75+i*150,475)})
        # add links
        for i in range(2):
            self.addLink(self.spineswitch[i], self.leafswitch[0], 1, i+1)
            self.addLink(self.spineswitch[i], self.leafswitch[1], 2, i+1)
            self.addLink(self.spineswitch[i], self.leafswitch[2], 3, i+1)

        for i in range(3):
            self.addLink(self.leafswitch[i], self.host[i*2], 3)
            self.addLink(self.leafswitch[i], self.host[i*2+1], 4)
        self.addLink(self.leafswitch[0], self.leafswitch[1] )
        # self.addLink(self.leafswitch[2], self.leafswitch[1] )
        
            
            
            
        # self.addLink(self.leafswitch[0], self.host[0], 3)
        # self.addLink(self.leafswitch[0], self.host[1], 4)
        
        
        # self.addLink(self.leafswitch[2], self.host[2], 3)
        # self.addLink(self.leafswitch[2], self.host[3], 4)

topos = {'mytopo': (lambda: MyTopo())}


if __name__ == "__main__":
    setLogLevel('info')

    topo = MyTopo()
    net = Mininet(topo=topo, link=TCLink, controller=None)
    net.addController('c0', controller=RemoteController, ip='127.0.0.1')

    net.start()
    CLI(net)
    net.stop()

