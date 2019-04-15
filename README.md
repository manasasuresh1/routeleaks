# routeleaks

Route leaks occur when improper network prefixes are advertised and propagated throughout the network leading to packet loss. Having an automated approach to detect and correct route leaks is beneficial. In this research, an Enterprise environment was emulated with Autonomous Systems (AS) running Border Gateway Protocol (BGP) and a server storing telemetry route data. A network design that detects route leak efficiently and blocks the leaked traffic with the Engineer’s approval was implemented by using prefix lists on edge devices. The proposed detection mechanism considers factors like BGP origin AS, timestamp, and network prefix. The Routing Information Base (RIB) data is stored and analyzed in a database from which the developed algorithm fetches the data for route leak detection, and the alerting system notifies the hijacked AS when a route leak is detected. The results of the algorithm developed enables real-time route leak detection, alerts the respective enterprise, and blocks the network within the local enterprise upon user’s approval. A montoring system using Grafana enables real-time traffic monitoring to check for any origin AS changes for a particular prefix over time.

Sequence of steps - 
1) Assumption - We are an enterprise network looking to protect our internal network from being affected by route leaks
2) Enable BGP peering on all of our devices
3) Enable BMP (BGP Monitoring Protocol) on the edge device to gather BGP data from all the internal devices in the enterprise network
4) An OpenBMP collector container hosted on the server gathers BMP data from the edge device. BMP data is sent as a single TCP stream to the OpenBMP collector container running on a specific port and IP address.
5) The collector then forwards it to a Kafka message bus running as a separate docker container in the server which can then be used to serve multiple applications
6) Postgresql database fetches the BGP data from the Kafka message bus and stores it in separate tables which can be queried
7) For monitoring purposes, Grafana fetches data from the PostgreSQL database and plots tables and graphs in real time to visualize Origin AS vs Prefix information. This gives a quick overview of which prefix belongs to which AS and whether there have been any changes which might indicate a route leak. 
8) The route leak detection algorithm considers multiple parameters such as timestamp, Origin AS and prefix information to check for any probable route leaks. 
9) In case there is a possibility of a route leak, an alerting email system alerts the NOC team internally. 
10) Manual checking with the involved AS can validate whether a route leak has taken place. 
11) In case it is a valid alert, the NOC team will have the option to run the self-healing algorithm. This is implemented by means of a web page that asks for the user's input to take the next course of action. 
12) If the user selects yes, the self-healing algoithm runs and this enables blocking the affected prefix on all edge devices on our internal enterpise network by means of using a firewall filter and prefix-list.



