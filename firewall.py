from pox.core import core
import pox.openflow.libopenflow_01 as of

log = core.getLogger()

# Block multiple IPs
BLOCKED_IPS = ["10.0.0.1", "10.0.0.2"]


def _handle_PacketIn(event):
    packet = event.parsed

    ip_packet = packet.find('ipv4')

    if not ip_packet:
        return

    src_ip = str(ip_packet.srcip)

    # Log packet arrival
    log.info("Packet received from %s", src_ip)

    # Create flow rule
    msg = of.ofp_flow_mod()
    msg.match = of.ofp_match.from_packet(packet)

    # 🚫 BLOCK rule
    if src_ip in BLOCKED_IPS:
        log.info("Action: DROP for %s", src_ip)
        # No action = drop
        event.connection.send(msg)
        return

    # ✅ ALLOW rule
    log.info("Action: FORWARD for %s", src_ip)
    msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
    event.connection.send(msg)


def launch():
    def start_switch(event):
        log.info("Firewall running...")
        connection = event.connection

        # 🔥 IMPORTANT: send packets to controller
        msg = of.ofp_flow_mod()
        msg.actions.append(of.ofp_action_output(port=of.OFPP_CONTROLLER))
        connection.send(msg)

        # Listen for PacketIn events
        connection.addListeners(_handle_PacketIn)

    core.openflow.addListenerByName("ConnectionUp", start_switch)