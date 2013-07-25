from scapy.all import *
import StringIO
import os
import sys
import datetime
import binascii
import threading

#max size of ipv6 packet
IP6_MAXPACKET = 65535
IP6_MIN_MTU = 1280

#flag for first fragment and last fragment
FRAG_GOT_FIRST = 0x00000001
FRAG_GOT_LAST = 0x00000002

#different defragment policy, you can add more defragment policy here
FRAG_POLICY_FIRST = 1

#flag for the defragment timeout
FRAG_OK = 0
FRAG_TRACKER_TIMEOUT = 1

#flag for different defragment status
FRAG_INSERT_OK = 0
FRAG_INSERT_FAILED = 1
FRAG_INSERT_REJECTED = 2
FRAG_INSERT_TIMEOUT = 3
FRAG_INSERT_ATTACK = 4
FRAG_INSERT_ANOMALY = 5
FRAG_INSERT_OVERLAP_LIMIT = 7

class Frag6Context(object):
    """runtime context for a specific instance of an defragment engine"""
    frag_policy = FRAG_POLICY_FIRST
    frag_timeout = 60

class Frag6Tracker(object):
    """tracker for a fragmented packet set"""
    src = 0         #source ip
    dst = 0         #destination ip
    frag_id = 0     #fragment id
    frag_flag = 0   #defragment flag
    frags = list()  #a list to store fragments
    frag_timer = None
    frag_time = None
    first_frag = None
    calc_size = 0   #the calc size of a reassambled pkt
    frag_bytes = 0  #currently the size of a reassembled pkt

#a dict to store different fragment trackers
frag_tracker_dict = dict()
#the global engine for defragment
frag_context = Frag6Context()

def PrintFrags(frags):
    """Print the information of fragments"""
    for frag in frags:
        print "Frag offset:",frag[IPv6ExtHdrFragment].offset,"Frag size",len(frag[IPv6ExtHdrFragment].payload)

def Frag6NewTracker(pkt, frag_key):
    """Create a new Tracker to reassemble fragments"""
    frag_tracker_dict[frag_key] = Frag6Tracker()
    temp_tracker = frag_tracker_dict[frag_key]
    temp_tracker.src = pkt[IPv6].src
    temp_tracker.dst = pkt[IPv6].dst
    temp_tracker.frag_id = pkt[IPv6ExtHdrFragment].id
    #record the time when the first fragment arrives
    temp_tracker.frag_time = datetime.datetime.now()
    #set timer to check the timeout fragments
    temp_tracker.frag_timer = threading.Timer(frag_context.frag_timeout, Frag6Timeout, (temp_tracker, frag_key))
    temp_tracker.frag_timer.setDaemon(True)
    temp_tracker.frag_timer.start()
    #add frag_tracker to the global dict
    frag_tracker_dict[frag_key] = temp_tracker

def Frag6Timeout(frag_tracker, frag_key):
    """Record timeout message and delete the tracker"""
    print "Warning : Time out!"
    Frag6DeleteTracker(frag_tracker)    
    del frag_tracker_dict[frag_key]

def Frag6DeleteTracker(frag_tracker):
    """Delete the tracker"""
    del frag_tracker.frags[:]

def Frag6Expire(pkt, frag_tracker,frag_key):
    """Check the timeout fragment"""
    currenttime = datetime.datetime.now()
    if (currenttime - frag_tracker.frag_time).seconds > frag_context.frag_timeout:
        Frag6DeleteTracker(frag_tracker)
        return FRAG_TRACKER_TIMEOUT
    else:
        return FRAG_OK

def Frag6IsComplete(frag_tracker):
    """Check whether all fragments arrives"""
    #if the first and last fragment arrives, and the current pkt size is equal to the calculated size, we think that all fragments has arrived
    if ((frag_tracker.frag_flag & FRAG_GOT_FIRST) and (frag_tracker.frag_flag & FRAG_GOT_LAST)):
        if frag_tracker.frag_bytes == frag_tracker.calc_size:
            return 1
    return 0

def Frag6Rebuild(frag_tracker):
    """Rebuild fragments"""
    # regenerate the fragmentable part
    fragmentable = ""
    for frag in frag_tracker.frags:
        q=frag[IPv6ExtHdrFragment]
        offset = 8*q.offset
        if offset != len(fragmentable):
            warning("Expected an offset of %d. Found %d. Padding with XXXX" % (len(fragmentable), offset))
        fragmentable += "X"*(offset - len(fragmentable))
        fragmentable += str(q.payload)

    # Regenerate the unfragmentable part.
    q = frag_tracker.first_frag
    nh = q[IPv6ExtHdrFragment].nh
    q[IPv6ExtHdrFragment].underlayer.nh = nh
    q[IPv6ExtHdrFragment].underlayer.plen = len(fragmentable)
    q[IPv6ExtHdrFragment].underlayer.payload = None
    q /= Raw(fragmentable)
    q = q.__class__(str(q))
    return q

def Frag6Insert(pkt, frag_tracker,frag_key):
    """Insert a fragment to a tracker"""
    if Frag6Expire(pkt,frag_tracker,frag_key) == FRAG_TRACKER_TIMEOUT:
        del frag_tracker_dict[frag_key]
        return FRAG_INSERT_TIMEOUT
    #if the first fragment arrives, store it and set the flag
    if frag_tracker.frag_flag & FRAG_GOT_FIRST == 0:
        if pkt[IPv6ExtHdrFragment].offset == 0:
            frag_tracker.first_frag = pkt
            frag_tracker.frag_flag |= FRAG_GOT_FIRST
    #if the last fragment arrives, calculate the size of the reassembled pkt
    if frag_tracker.frag_flag & FRAG_GOT_LAST == 0:
        if pkt[IPv6ExtHdrFragment].m == 0:
            frag_tracker.calc_size = pkt[IPv6ExtHdrFragment].offset*8 + len(pkt[IPv6ExtHdrFragment].payload)
            if frag_tracker.calc_size > IP6_MAXPACKET:
                print "Warning : Packet is too big!"
                return FRAG_INSERT_ANOMALY
            frag_tracker.frag_flag |= FRAG_GOT_LAST
    right_frag = None
    left_frag = None
    item = 0
    #find the insert place for current fragment
    for frag in frag_tracker.frags:
        right_frag = frag
        if frag[IPv6ExtHdrFragment].offset >= pkt[IPv6ExtHdrFragment].offset:
            break
        left_frag =right_frag
        item = item + 1
    if item >= len(frag_tracker.frags):
        right_frag = None
    #handle the left overlapping part
    if left_frag != None:
        overlap = left_frag[IPv6ExtHdrFragment].offset * 8 + len(left_frag[IPv6ExtHdrFragment].payload) - pkt[IPv6ExtHdrFragment].offset * 8
        if overlap > 0:
            if frag_context.frag_policy == FRAG_POLICY_FIRST:
                temp_pkt = pkt
                if len(temp_pkt[IPv6ExtHdrFragment].payload) <= overlap:
                    return FRAG_INSERT_ANOMALY
                temp_payload = temp_pkt[IPv6ExtHdrFragment].payload
                pkt[IPv6ExtHdrFragment].payload = str(temp_payload)[overlap:]
                pkt[IPv6ExtHdrFragment].offset = temp_pkt[IPv6ExtHdrFragment].offset + overlap/8
                pkt[IPv6ExtHdrFragment].underlayer.plen = temp_pkt[IPv6ExtHdrFragment].underlayer.plen - overlap
    #handle the right overlapping part
    if right_frag != None:
        overlap = pkt[IPv6ExtHdrFragment].offset * 8 + len(pkt[IPv6ExtHdrFragment].payload) - right_frag[IPv6ExtHdrFragment].offset * 8
        if overlap > 0:
            if frag_context.frag_policy == FRAG_POLICY_FIRST:
                temp_pkt = pkt
                if len(temp_pkt[IPv6ExtHdrFragment].payload) <= overlap:
                    return FRAG_INSERT_ANOMALY
                pkt[IPv6ExtHdrFragment].payload = str(temp_pkt[IPv6ExtHdrFragment].payload)[:0-overlap]
                pkt[IPv6ExtHdrFragment].underlayer.plen = temp_pkt[IPv6ExtHdrFragment].underlayer.plen - overlap
    frag_tracker.frag_bytes += len(pkt[IPv6ExtHdrFragment].payload)
    frag_tracker.frags.insert(item, pkt)
    return FRAG_INSERT_OK

def Frag6Defrag(pkt):
    """Reasseamble the fragments"""
    frag_key = (pkt[IPv6].src, pkt[IPv6].dst, pkt[IPv6ExtHdrFragment].id)
    frag_tracker = frag_tracker_dict.get(frag_key)
    if frag_tracker == None:
        Frag6NewTracker(pkt, frag_key)
        frag_tracker = frag_tracker_dict[frag_key]
    if Frag6Insert(pkt, frag_tracker, frag_key) != FRAG_INSERT_OK:
        return
    if Frag6IsComplete(frag_tracker):
        frag_tracker.frag_timer.cancel()
        p = Frag6Rebuild(frag_tracker)
        Frag6DeleteTracker(frag_tracker)
        del frag_tracker_dict[frag_key]

def run():
    #only test icmpv6 currently
    ip6_filter = "ip6 and not tcp and not udp"
    #only capture specified packets sent to following addrs
    addrs = ["2001:da8:2:101:250:56ff:feac:4eda"]
    ip6_lfilter = lambda (r): IPv6 in r and TCP not in r and UDP not in r and r[IPv6].dst in addrs
    sniff(iface="eth0", filter=ip6_filter, lfilter=ip6_lfilter, prn=process)

def process(pkt):
    #if the packet is fragmented, we will try to reassemble them
    if IPv6ExtHdrFragment in pkt:
        Frag6Defrag(pkt)
    return

def main():
    run()
    while True:
        pass

#if __name__ == '__main__':
#    main()

