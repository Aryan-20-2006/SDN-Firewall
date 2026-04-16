from pox.core import core
import pox.openflow.libopenflow_01 as of

log = core.getLogger()

# Block multiple IPs
BLOCKED_IPS = ["10.0.0.1", "10.0.0.2"]

def _handle_PacketIn(event):
    packet = event.parsed

    ip_packet = packet.find('ipv4')

    if ip_packet:
        src_ip = str(ip_packet.srcip)

        # Log incoming packet
        log.info("Packet received from %s", src_ip)

        # Match condition (source IP)
        if src_ip in BLOCKED_IPS:
            # Action: DROP
            log.info("Action: DROP for %s", src_ip)
            return
        else:
            # Action: FORWARD
            log.info("Action: FORWARD for %s", src_ip)

    # Forward packet (flood)
    msg = of.ofp_packet_out()
    msg.data = event.ofp
    msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
    event.connection.send(msg)


def launch():
    def start_switch(event):
        log.info("Firewall running...")
        event.connection.addListeners(_handle_PacketIn)

    core.openflow.addListenerByName("ConnectionUp", start_switch)