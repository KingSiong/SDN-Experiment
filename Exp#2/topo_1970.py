#!/usr/bin/python

"""
Custom topology for Mininet, generated by GraphML-Topo-to-Mininet-Network-Generator.
"""
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.node import Node
from mininet.node import CPULimitedHost
from mininet.link import TCLink
from mininet.cli import CLI
from mininet.log import setLogLevel
from mininet.util import dumpNodeConnections

class GeneratedTopo( Topo ):
    "Internet Topology Zoo Specimen."

    def __init__( self, **opts ):
        "Create a topology."

        # Initialize Topology
        Topo.__init__( self, **opts )

        # add nodes, switches first...
        s1 = self.addSwitch( 's1' )
        s2 = self.addSwitch( 's2' )
        s3 = self.addSwitch( 's3' )
        s4 = self.addSwitch( 's4' )
        s5 = self.addSwitch( 's5' )
        s6 = self.addSwitch( 's6' )
        s7 = self.addSwitch( 's7' )
        s8 = self.addSwitch( 's8' )
        s9 = self.addSwitch( 's9' )

        # ... and now hosts
        h1 = self.addHost( 'HARVARD' )
        h2 = self.addHost( 'SRI' )
        h3 = self.addHost( 'UCSB' )
        h4 = self.addHost( 'UCLA' )
        h5 = self.addHost( 'RAND' )
        h6 = self.addHost( 'SDC' )
        h7 = self.addHost( 'UTAH' )
        h8 = self.addHost( 'MIT' )
        h9 = self.addHost( 'BBN' )

        # add edges between switch and corresponding host
        self.addLink( s1 , h1 )
        self.addLink( s2 , h2 )
        self.addLink( s3 , h3 )
        self.addLink( s4 , h4 )
        self.addLink( s5 , h5 )
        self.addLink( s6 , h6 )
        self.addLink( s7 , h7 )
        self.addLink( s8 , h8 )
        self.addLink( s9 , h9 )


        # add edges between switches
        self.addLink( s1 , s9, bw=10, delay='10ms')
        self.addLink( s2 , s3, bw=10, delay='11ms')
        self.addLink( s2 , s4, bw=10, delay='13ms')
        self.addLink( s3 , s4, bw=10, delay='14ms')
        self.addLink( s4 , s5, bw=10, delay='15ms')
        self.addLink( s5 , s9, bw=10, delay='29ms')
        self.addLink( s5 , s6, bw=10, delay='17ms')
        self.addLink( s6 , s7, bw=10, delay='10ms')
        self.addLink( s7 , s8, bw=10, delay='62ms')
        self.addLink( s8 , s9, bw=10, delay='17ms')


topos = { 'generated': ( lambda: GeneratedTopo() ) }

# HERE THE CODE DEFINITION OF THE TOPOLOGY ENDS

# the following code produces an executable script working with a remote controller
# and providing ssh access to the the mininet hosts from within the ubuntu vm
controller_ip = ''

def setupNetwork(controller_ip):
    "Create network and run simple performance test"
    # check if remote controller's ip was set
    # else set it to localhost
    topo = GeneratedTopo()
    if controller_ip == '':
        #controller_ip = '10.0.2.2';
        controller_ip = '127.0.0.1';
    net = Mininet(topo=topo, controller=lambda a: RemoteController( a, ip=controller_ip, port=6633 ), host=CPULimitedHost, link=TCLink)
    return net

def connectToRootNS( network, switch, ip, prefixLen, routes ):
    "Connect hosts to root namespace via switch. Starts network."
    "network: Mininet() network object"
    "switch: switch to connect to root namespace"
    "ip: IP address for root namespace node"
    "prefixLen: IP address prefix length (e.g. 8, 16, 24)"
    "routes: host networks to route to"
    # Create a node in root namespace and link to switch 0
    root = Node( 'root', inNamespace=False )
    intf = TCLink( root, switch ).intf1
    root.setIP( ip, prefixLen, intf )
    # Start network that now includes link to root namespace
    network.start()
    # Add routes from root ns to hosts
    for route in routes:
        root.cmd( 'route add -net ' + route + ' dev ' + str( intf ) )

def sshd( network, cmd='/usr/sbin/sshd', opts='-D' ):
    "Start a network, connect it to root ns, and run sshd on all hosts."
    switch = network.switches[ 0 ]  # switch to use
    ip = '10.123.123.1'  # our IP address on host network
    routes = [ '10.0.0.0/8' ]  # host networks to route to
    connectToRootNS( network, switch, ip, 8, routes )
    for host in network.hosts:
        host.cmd( cmd + ' ' + opts + '&' )

    dumpNodeConnections(network.hosts)


    CLI( network )
    for host in network.hosts:
        host.cmd( 'kill %' + cmd )
    network.stop()

# by zys
def start_network(network):
    network.start()

    dumpNodeConnections(network.hosts)

    CLI( network )
    network.stop()

if __name__ == '__main__':
    setLogLevel('info')
    #setLogLevel('debug')
    # sshd( setupNetwork(controller_ip) )
    start_network(setupNetwork(controller_ip))
