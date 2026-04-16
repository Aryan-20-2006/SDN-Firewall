SDN Firewall using Ryu Controller

Objective:
To implement a controller-based firewall that blocks or allows traffic.

Tools Used:
- Ryu Controller
- Mininet
- OpenFlow Protocol

Working:
- Controller intercepts packets from switch
- Blocks traffic from specific IP (10.0.0.1)
- Allows other traffic

Steps to Run:
1. Activate virtual environment
2. Run: ryu-manager firewall.py
3. In another terminal:
   sudo mn --custom topo.py --topo mytopo --controller remote --switch ovsk,protocols=OpenFlow13
4. Test using ping between hosts

Result:
Traffic from blocked IP is denied, others are allowed.