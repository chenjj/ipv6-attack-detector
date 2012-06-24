from ConfigParser import NoOptionError, NoSectionError

class ParsingError(Exception):
    pass

IDENT = "consesi-agent"

config = {
    'name': "IPv6 low-interaction Honeypot",
}


def parse_config(cfg):
    values = {}
    try:
        # essential config items
        values['ndp'] = cfg.getint('IPv6', 'ndp')
        values['uecho'] = cfg.getint('IPv6', 'icmpv6_echo_unicast')
        values['mecho'] = cfg.getint('IPv6', 'icmpv6_echo_multicast')
        values['iv_ext_hdr'] = cfg.getint('IPv6', 'icmpv6_invalid_exheader')
        values['slaac'] = cfg.getint('IPv6', 'slaac')
        values['dhcpv6'] = cfg.getint('IPv6', 'dhcpv6')
    except (NoSectionError, NoOptionError, ValueError), err:
        raise ParsingError(str(err))

    if cfg.has_option('IPv6', 'tcp_ports'):
        values['tcp_ports'] = map(int, cfg.get('IPv6', 'tcp_ports').split(','))
    if cfg.has_option('IPv6', 'udp_ports'):
        values['udp_ports'] = map(int, cfg.get('IPv6', 'udp_ports').split(','))
    config.update(values)