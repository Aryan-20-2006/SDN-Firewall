**SDN Firewall using POX Controller**

---

### Objective

To implement a Software Defined Networking (SDN) based firewall that can monitor and control network traffic by allowing or blocking packets based on defined rules.

---

### Tools & Technologies Used

* POX Controller
* Mininet
* OpenFlow Protocol
* Python

---

### Project Description

This project implements a controller-based firewall using the POX SDN controller. The controller inspects incoming packets and applies filtering rules based on the source IP address.

The firewall is configured to block traffic from specific IP addresses while allowing all other traffic.

---

### Working Principle

* Mininet creates a virtual network with hosts and a switch
* The switch sends packets to the POX controller
* The controller analyzes each packet
* If the source IP matches a blocked rule → the packet is dropped
* Otherwise → the packet is forwarded

---

### Implementation Details

* Blocked IPs: `10.0.0.1`, `10.0.0.2`
* Controller: POX
* Protocol: OpenFlow

---

### Steps to Run

1. Navigate to POX directory:

```
cd /mnt/c/Users/Aryan/Desktop/SDN-Project/pox
```

2. Run the controller:

```
./pox.py log.level --DEBUG ext.firewall
```

3. Open a new terminal and run Mininet:

```
sudo mn --topo single,2 --controller=remote,ip=127.0.0.1,port=6633
```

4. Test the firewall:

```
h1 ping h2
```

---

### Output

* Traffic from blocked IPs is denied
* Ping results in “Destination Host Unreachable”
* Controller logs show blocked packets

---

### Result

The firewall successfully filters network traffic based on predefined rules using a centralized SDN controller.

---

### Conclusion

This project demonstrates how SDN enables programmable and centralized network security using a controller-based approach.

---

### Future Enhancements

* Port-based filtering
* Support for multiple dynamic rules
* Logging and monitoring improvements

---
