from mininet.topo import Topo
class MyTopo(Topo):
        def __init__(self):
                Topo.__init__(self)

                h1 = self.addHost('h1',mac='00:00:00:00:00:01')
                h2 = self.addHost('h2',mac='00:00:00:00:00:02')
                h3 = self.addHost('h3',mac='00:00:00:00:00:03')
               
                h4 = self.addHost('h4',mac='00:00:00:00:00:04')
                h5 = self.addHost('h5',mac='00:00:00:00:00:05')
                

                

                s1 = self.addSwitch('s1')
                s2 = self.addSwitch('s2')
                s3 = self.addSwitch('s3')
                s4 = self.addSwitch('s4')
                s5 = self.addSwitch('s5')

                self.addLink(s1, s2)
                self.addLink(s1, s4)
                self.addLink(s2, s3)
                self.addLink(s3, s4)


                self.addLink(h1,s1)
                self.addLink(h2,s2)
                self.addLink(s3,h3)
                
                self.addLink(h4,s4)
                self.addLink(s5,h5)
                
                
                
                self.addLink(s2, s5)
                self.addLink(s3, s5)

topos = {'mytopo': (lambda: MyTopo())}

locations = {'c0':(50,100), 's1':(200,300), 's2':(600,300), 's4':(400,50), 's3':(800,100), 's5':(900,200), 
             'h1':(200,450),'h2':(600,450), 'h3':(900,30), 'h4':(300,50), 'h5':(900,350),}

#### 3 sw - 3host
#from mininet.topo import Topo
#class MyTopo(Topo):
#        def __init__(self):
#                Topo.__init__(self)

                # h1 = self.addHost('h1',mac='00:00:00:00:00:01')
                # h2 = self.addHost('h2',mac='00:00:00:00:00:02')
                # h3 = self.addHost('h3',mac='00:00:00:00:00:03')

                # s1 = self.addSwitch('s1')
                # s2 = self.addSwitch('s2')
                # s3 = self.addSwitch('s3')

                # self.addLink(s1, s2)
                # #self.addLink(s2, s3)
                # self.addLink(s1, s3)
                # self.addLink(s2, h2)
                # self.addLink(s3, h3)
                # self.addLink(h1, s1)

# topos = {'mytopo': (lambda: MyTopo())}
#ovs-vsctl set bridge br0 stp_enable=true
