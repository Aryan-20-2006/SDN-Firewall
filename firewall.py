from pox.core import core
import pox.openflow.libopenflow_01 as of

log = core.getLogger()

# Block specific IPs
BLOCKED_IPS = ["10.0.0.1", "10.0.0.2"]


def _handle_PacketIn(event):
    packet = event.parsed

    ip_packet = packet.find('ipv4')
    if not ip_packet:
        return

    src_ip = str(ip_packet.srcip)
    log.info("Packet received from %s", src_ip)

    # Create flow rule (match)
    msg = of.ofp_flow_mod()
    msg.match = of.ofp_match.from_packet(packet)

    # BLOCK rule
    if src_ip in BLOCKED_IPS:
        log.info("Action: DROP for %s", src_ip)
        # No actions = drop
        event.connection.send(msg)
        return

    # ALLOW rule
    log.info("Action: FORWARD for %s", src_ip)
    msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
    event.connection.send(msg)


def _handle_ConnectionUp(event):
    log.info("Firewall running...")

    # Send all packets to controller (important!)
    msg = of.ofp_flow_mod()
    msg.actions.append(of.ofp_action_output(port=of.OFPP_CONTROLLER))
    event.connection.send(msg)


def launch():
    # Register handlers correctly
    core.openflow.addListenerByName("PacketIn", _handle_PacketIn)
    core.openflow.addListenerByName("ConnectionUp", _handle_ConnectionUp)