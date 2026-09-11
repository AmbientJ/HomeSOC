\# HomeSOC



HomeSOC is a Windows-based network monitoring and security project I built to get hands-on experience with network discovery, asset monitoring, service scanning, security alerts, and persistent device tracking.



The project started as a simple way to see what devices were connected to my home network. As I continued working on it, I expanded it into a small home Security Operations Center (SOC) that can continuously monitor a local network, identify devices, track changes, detect exposed services, and display everything through a live dashboard.



One of my main goals was to build something that worked with a real network instead of relying entirely on a simulated lab. I also wanted the program to be portable enough to recognize and monitor different local networks rather than being hardcoded for one environment.



\## What HomeSOC Does



HomeSOC continuously scans the local network and builds a persistent inventory of the devices it observes.



It can:



\* Automatically determine the local subnet and default gateway

\* Discover devices using ICMP and ARP information

\* Track devices by MAC address even when their IP address changes

\* Identify hostnames and hardware vendors when available

\* Perform basic device classification using network evidence

\* Scan selected TCP services

\* Establish service baselines for known devices

\* Detect unexpected service changes

\* Track devices going online and offline

\* Generate and manage security alerts

\* Mark devices as Trusted, Suspicious, or Unreviewed

\* Store network and device history in SQLite

\* Recognize previously monitored networks

\* Detect the current Wi-Fi SSID on Windows

\* Allow networks to be given custom names

\* Run scans automatically in the background

\* Display live scan progress and monitoring status

\* Provide a browser-based security dashboard



\## Dashboard



HomeSOC includes a Flask dashboard that provides a quick view of the current network and monitoring state.



The dashboard displays information such as:



\* Current network

\* Wi-Fi SSID

\* Online and offline device counts

\* Device inventory

\* Device type and identification confidence

\* Hostname and vendor information

\* Trust status

\* Active security alerts

\* Recent activity

\* Last completed scan

\* Current scan progress

\* Time until the next scan



\## How It Works



A HomeSOC scan follows roughly this process:



```text

Detect Local Network

       |

       v

Discover Devices

 (ICMP + ARP)

       |

       v

Build Device Inventory

       |

       v

Identify Devices

       |

       v

Scan Selected Services

       |

       v

Compare Against Baselines

       |

       v

Generate Events / Alerts

       |

       v

Store Results in SQLite

       |

       v

Update Dashboard

```



The monitoring service repeats this process in the background while the dashboard remains available.



HomeSOC also stores information about previously monitored networks. A combination of subnet and gateway information is used to distinguish networks, while the Wi-Fi SSID is stored as additional context.



This allows the same installation to maintain separate device histories when used on different networks.



\## Project Structure



```text

HomeSOC/

|

|-- dashboard/

|   |-- static/

|   |-- templates/

|   `-- app.py

|

|-- database/

|   `-- database.py

|

|-- discovery/

|   `-- network.py

|

|-- events/

|   `-- events.py

|

|-- identification/

|   |-- device\_id.py

|   `-- vendor.py

|

|-- inventory/

|   `-- inventory.py

|

|-- security/

|   `-- risk.py

|

|-- services/

|   `-- scanner.py

|

|-- config.py

|-- create\_baseline.py

|-- dashboard\_server.py

|-- homesoc\_app.py

|-- logger.py

|-- main.py

|-- monitor.py

`-- requirements.txt

```



\## Running HomeSOC



HomeSOC V1 is designed primarily for Windows.



\### Requirements



\* Python 3

\* Windows

\* A local network you are authorized to monitor



Install the Python dependencies:



```powershell

pip install -r requirements.txt

```



Then start HomeSOC:



```powershell

python homesoc\_app.py

```



HomeSOC starts the local dashboard and monitoring application. The dashboard runs locally rather than being hosted on the public internet.



\## Windows Build



I also packaged HomeSOC as a standalone Windows application using PyInstaller.



The packaged version allows HomeSOC to run without launching the project manually from a Python terminal and suppresses the command windows normally created by Windows networking utilities during scans.



The Windows build uses the same monitoring and dashboard components as the source version.



\## Technologies Used



\*\*Python\*\* — main application and monitoring logic



\*\*Flask\*\* — local web dashboard



\*\*SQLite\*\* — persistent network, device, service, event, and alert data



\*\*psutil\*\* — local network interface information



\*\*ipaddress\*\* — subnet calculation and validation



\*\*ThreadPoolExecutor\*\* — concurrent network discovery



\*\*Windows networking utilities\*\* — ARP, routing, ICMP, and Wi-Fi information



\*\*PyInstaller\*\* — Windows application packaging



\*\*HTML / CSS / JavaScript\*\* — dashboard interface and live updates



\## Some of the Problems I Worked Through



A large part of this project was figuring out how network behavior differs from what looks correct on paper.



For example, Windows `ping` behavior initially caused HomeSOC to report devices that were not actually responding. I changed discovery logic to validate actual TTL responses instead of relying only on the process exit code.



I also had to account for devices that do not respond to ICMP but still appear in the ARP table, devices that temporarily stop responding, changing IP addresses, locally administered MAC addresses, and services that disappear for only a single scan.



As the project grew, I added persistent device identities, service baselines, retry thresholds, alert lifecycle handling, background monitoring, multi-network tracking, and live dashboard updates.



Packaging the application introduced another set of problems, including application data paths, fresh database creation, hidden imports, dashboard resources, and preventing Windows networking commands from opening console windows.



Working through those issues ended up being one of the most useful parts of building HomeSOC.



\## Device Identification



HomeSOC intentionally takes a conservative approach to device identification.



A device is classified using evidence such as:



\* MAC vendor

\* Hostname

\* Open services

\* Gateway status

\* Local host information

\* Previously observed identity information



When there is not enough evidence to confidently identify a device, HomeSOC leaves it unidentified rather than forcing a potentially incorrect classification.



\## Limitations



HomeSOC is a learning and portfolio project, not a replacement for an enterprise IDS, SIEM, EDR platform, or commercial network monitoring system.



Some current limitations include:



\* Primarily designed for Windows

\* ICMP-based discovery can miss devices that block ping requests

\* ARP information is limited to devices visible from the local network

\* Device classification is heuristic and may not always be accurate

\* Vendor information depends on MAC address availability

\* Service scanning checks a selected group of ports rather than every possible service

\* Network isolation and certain router configurations can limit device visibility



These limitations are intentionally documented rather than hidden because understanding what a monitoring system \*\*cannot\*\* see is just as important as understanding what it can.



\## Security and Responsible Use



HomeSOC is intended for monitoring networks that you own or have explicit authorization to analyze.



Network discovery and service scanning should not be performed against systems or networks without permission.



The repository intentionally does not include my local HomeSOC database, scan logs, network inventory, or other information collected from monitored networks.



\## Future Ideas



V1 is intentionally feature-frozen so I can treat it as a completed project rather than continuously adding features.



Possible future versions could explore:



\* Additional discovery methods

\* Improved device fingerprinting

\* Expanded network-specific event history

\* More detailed service analysis

\* Historical network statistics

\* Dashboard charts and trends

\* Additional alerting options

\* Linux support

\* Remote monitoring nodes



For now, HomeSOC V1 represents the original goal: build a working network security monitoring system from the ground up, run it against a real environment, and learn from the problems that came with making it actually work.



