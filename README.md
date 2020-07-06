# Simple DNS forwarder

Simple DNS server with possibility to

- forward requests to upstream server and post-process results
- Resolve name to ipv4/ipv6 from local database (in addition to forwarded results)
- Filter IPv4 or IPv6 addresses from results.
- bind to interface

# systemd

copy provided dnsfilter@.service to /etc/systemd/system/dnsfilter@.service and edit as appripriate.
then

    $ systemctl start dnsfilter@<IP-OR-INTERFACE-NAME>.service
