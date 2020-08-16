# Import data from Netbox

What this script will do:<br>
1) Connect via API to netbox and get information about Devices + Managment Interface (mac+ip)<br>
2) Create YAML file with configuration which can be use for DHCP<br>
3) For juniper device it will create config files which wil lconfigure static IP on device.<br>
