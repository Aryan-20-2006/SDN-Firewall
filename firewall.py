from pox.core import core
import pox.openflow.libopenflow_01 as of

log = core.getLogger()

# Block specific IPs
BLOCKED_IPS = ["10.0.0.1"]


def _handle_PacketIn(event):
    packet = event.parsed

    ip_packet = packet.find('ipv4')
    if not ip_packet:
        return

    src_ip = str(ip_packet.srcip)
    log.info("Packet received from %s", src_ip)

    msg = of.ofp_flow_mod()
    msg.match = of.ofp_match.from_packet(packet)

    # FIREWALL: block rule
    if src_ip in BLOCKED_IPS:
        log.info("Action: DROP for %s", src_ip)
        event.connection.send(msg)
        return

    # ROUTING LOGIC (simple port-based forwarding)
    # h1 ↔ port 1, h2 ↔ port 2 (Mininet default)
    if src_ip == "10.0.0.1":
        out_port = 2
    elif src_ip == "10.0.0.2":
        out_port = 1
    else:
        out_port = of.OFPP_FLOOD  # fallback

    log.info("Action: FORWARD %s → port %s", src_ip, out_port)

    msg.actions.append(of.ofp_action_output(port=out_port))
    event.connection.send(msg)


def _handle_ConnectionUp(event):
    log.info("Firewall + Routing running...")
    log.info("BLOCKED_IPS = %s", BLOCKED_IPS)
    
    # Send packets to controller
    msg = of.ofp_flow_mod()
    msg.actions.append(of.ofp_action_output(port=of.OFPP_CONTROLLER))
    event.connection.send(msg)


def launch():
    core.openflow.addListenerByName("PacketIn", _handle_PacketIn)
    core.openflow.addListenerByName("ConnectionUp", _handle_ConnectionUp)