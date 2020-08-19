"""Custom topology example

Two directly connected switches plus a host for each switch:

   host --- switch --- switch --- host

Adding the 'topos' dict with a key/value pair to generate our newly defined
topology enables one to pass in '--topo=mytopo' from the command line.
"""

from mininet.topo import Topo

class MyTopo( Topo ):
    "Simple topology example."

    def __init__( self ):
        "Create custom topo."

        # Initialize topology
        Topo.__init__( self )

        # Add hosts and switches
        upperHost1 = self.addHost( 'h1' )
        upperHost2 = self.addHost( 'h2' )
        upperHost3 = self.addHost( 'h3' )

        lowerHost1 = self.addHost( 'h4' )
        lowerHost2 = self.addHost( 'h5' )
        lowerHost3 = self.addHost( 'h6' )
        lowerHost4 = self.addHost( 'h7' )


        lowerHost5 = self.addHost( 'h8' )
        lowerHost6 = self.addHost( 'h9' )
        lowerHost7 = self.addHost( 'h10' )
        lowerHost8 = self.addHost( 'h11' )

        lowerHost9 = self.addHost( 'h12' )
        lowerHost10 = self.addHost( 'h13' )
        lowerHost11 = self.addHost( 'h14' )
        lowerHost12 = self.addHost( 'h15' )

        sw1 = self.addSwitch('s1')
        sw2 = self.addSwitch('s2')
        sw3 = self.addSwitch('s3')
        sw4 = self.addSwitch('s4')
        sw5 = self.addSwitch('s5')
        sw6 = self.addSwitch('s6')
        sw7 = self.addSwitch('s7')
        sw8 = self.addSwitch('s8')
        sw9 = self.addSwitch('s9')
        sw10 = self.addSwitch('s10')
        sw11 = self.addSwitch('s11')
        sw12 = self.addSwitch('s12')
        sw13 = self.addSwitch('s13')
        sw14 = self.addSwitch('s14')
        sw15 = self.addSwitch('s15')
        sw16 = self.addSwitch('s16')



        # Add links
        self.addLink( upperHost1, sw13 )
        self.addLink( upperHost2, sw14 )
        self.addLink( upperHost3, sw16 )

        self.addLink( sw13, sw3 )
        self.addLink( sw14, sw3 )
        self.addLink( sw14, sw7 )

        self.addLink( sw15, sw8 )
        self.addLink( sw15, sw12 )
        self.addLink( sw16, sw8 )

        self.addLink( lowerHost1, sw1)
        self.addLink( lowerHost2, sw1)
        self.addLink( lowerHost3, sw2)
        self.addLink( lowerHost4, sw2)
        self.addLink( sw1, sw4)
        self.addLink( sw1, sw3)
        self.addLink( sw2, sw4)

        self.addLink( lowerHost5, sw5)
        self.addLink( lowerHost6, sw5)
        self.addLink( lowerHost7, sw6)
        self.addLink( lowerHost8, sw6)
        self.addLink( sw5, sw7)
        self.addLink( sw5, sw8)
        self.addLink( sw6, sw8)

        self.addLink( lowerHost9, sw9)
        self.addLink( lowerHost10, sw9)
        self.addLink( lowerHost11, sw10)
        self.addLink( lowerHost12, sw10)
        self.addLink( sw9, sw11)
        self.addLink( sw9, sw12)
        self.addLink( sw10, sw12)



topos = { 'mytopo': ( lambda: MyTopo() ) }
