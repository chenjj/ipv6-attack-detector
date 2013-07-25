#Check the order and count of extension header options
#ret: 0: Valid extension header, do nothing
#ret: 1: The order or count of extension header is invalid, log the event, 
#When more than one extension header is used in the same packet, it is recommended that those headers appear in the following order[RFC 2460, 1998]:
#IPv6 header, Hop-by-Hop Options header, Destination Options header, Routing header, Fragment header, Authentication header, Encapsulating Security Payload header, Destination Options header, Upper-layer header
#Each extension header should occur at most once, except for the Destination Options header which should occur at most twice (once before a Routing header and once before the upper-layer header)[RFC 2460]
def check_extheader_order(pkt):
    #the below values are defined in RFC2460.
    next_headers_vals = [0, 60, 43, 44, 51, 50, 60, 135, 59, 6, 17, 58]
    pkt_index = 0
    header_val_index = 0
    while "IPv6ExtHdr" in pkt[pkt_index].summary() and header_val_index < 8:
        if pkt[pkt_index].nh == next_headers_vals[header_val_index]:
            pkt_index=pkt_index + 1
            header_val_index = header_val_index + 1
        else:
            header_val_index = header_val_index + 1
    if header_val_index >=8 and "IPv6ExtHdr" in pkt[pkt_index].summary():
        msg = self.msg.new_msg(pkt, save_pcap = 0)
        msg['type'] = "Invalid Extension Header"
        msg['name'] = "Invalid Extension Header in packets"
        msg['util'] = "Crafting malformed Packets"
        self.msg.put_event(msg)
        return 1
    return 0
