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

def correct_abused_extheader(pkt, extheaders):
    """try to correct the invalid extension headers, return corrected packet"""
    has_frag_header = 0
    pkt_index = 1
    before_frag_index = 0
    remain_part = None
    pkt = pkt.__class__(str(pkt))
    while isinstance(pkt[pkt_index+1],_IPv6ExtHdr):
        #record the value of extension headers
        extheaders.append(pkt[pkt_index].nh)
        #remove the redundant fragment extension headers and only keep the last one
        if pkt[pkt_index].nh == 44:
            if has_frag_header == 0:
                has_frag_header = 1
                before_frag_index = pkt_index
            remain_part = pkt[pkt_index].payload
        pkt_index += 1
    extheaders.append(pkt[pkt_index].nh)
    #rebuild the packet
    if IPv6ExtHdrFragment in pkt:
        temp_pkt = copy.deepcopy(pkt)
        temp_pkt[before_frag_index].payload = None 
        temp_pkt[before_frag_index].payload= str(remain_part)
        temp_pkt[before_frag_index].plen = len(str(remain_part))
        temp_pkt = temp_pkt.__class__(str(temp_pkt))
    pkt = temp_pkt
    return pkt
