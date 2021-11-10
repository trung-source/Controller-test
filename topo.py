from mininet.topo import SingleSwitchReversedTopo, Topo



third_host = True
class MyTopo(Topo):
        switch = []
        host = []
        def __init__(self):
                Topo.__init__(self)

                h1 = self.addHost('h1',mac='00:00:00:00:00:01')
                h2 = self.addHost('h2',mac='00:00:00:00:00:02')
                h3 = self.addHost('h3',mac='00:00:00:00:00:03')
               
                h4 = self.addHost('h4',mac='00:00:00:00:00:04')
                h5 = self.addHost('h5',mac='00:00:00:00:00:05')
                
                # self.host.append(h1)
                # self.host.append(h2)
                # self.host.append(h3)
                # self.host.append(h4)
                # self.host.append(h5)
                
                # h__5 = self.addHost('h__5',mac='00:00:00:00:00:0b')
                
                # h_1 = self.addHost('h_1',mac='00:00:00:00:00:06')
                
                # h_2 = self.addHost('h_2',mac='00:00:00:00:00:07')
                
                # h_3 = self.addHost('h_3',mac='00:00:00:00:00:08')

                # h_4 = self.addHost('h_4',mac='00:00:00:00:00:09')

                # h_5 = self.addHost('h_5',mac='00:00:00:00:00:0a')


                for i in range(1, 6):
                        # add second host
                        self.host.append(self.addHost("h_"+str(i), mac="00:00:00:00:00:0"+str(hex(i+5))))
                                
                if third_host == True:
                        for i in range(1, 6):
                                # add third host
                                self.host.append(self.addHost("h__"+str(i)))        
                        
            
            

                s1 = self.addSwitch('s1')
                s2 = self.addSwitch('s2')
                s3 = self.addSwitch('s3')
                s4 = self.addSwitch('s4')
                s5 = self.addSwitch('s5')
                
                self.switch.append(s1)
                self.switch.append(s2)
                self.switch.append(s3)
                self.switch.append(s4)
                self.switch.append(s5)
                
                

                self.addLink(s1, s2)
                self.addLink(s1, s4)
                self.addLink(s2, s3)
                self.addLink(s3, s4)


                self.addLink(h1,s1)
                self.addLink(h2,s2)
                self.addLink(s3,h3)
                
                self.addLink(h4,s4)
                # self.addLink(s5,h6)
                self.addLink(s5,h5)
                
                for i in range(len(self.switch)):
                        self.addLink(self.switch[i], self.host[i])
                        
                        if third_host == True:
                                self.addLink(self.switch[-i-1], self.host[-i-1])
                        
                        
                
                       
                # self.addLink(s1,h_1)
                
                # self.addLink(s2,h_2)
                # self.addLink(s3,h_3)
                # self.addLink(s4,h_4)
                # self.addLink(s5,h_5)
                # self.addLink(s5,h__5)
        
                
                self.addLink(s2, s5)
                self.addLink(s3, s5)

topos = {'mytopo': (lambda: MyTopo())}

locations = {'c0':(50,100), 's1':(200,300), 's2':(600,300), 's4':(400,120), 's3':(800,120), 's5':(900,200), 
             'h1':(200,450),'h2':(600,450), 'h3':(900,30), 'h4':(400,50), 'h5':(900,350),
             'h_1':(300,450),'h_2':(500,450), 'h_3':(800,30), 'h_4':(300,50), 'h_5':(700,350),
             'h__1':(100,450),'h__2':(400,450), 'h__3':(700,30), 'h__4':(500,50), 'h__5':(800,350),
             
             }

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
