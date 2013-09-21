6Guard (IPv6 attack detector) |Build Status|
=============================

.. |Build Status| image:: https://travis-ci.org/chenjj/ipv6-attack-detector.png?branch=master
                       :target: https://travis-ci.org/chenjj/ipv6-attack-detector

Description
------------
6Guard is an IPv6 attack detector aiming at link-local level security threats, including most attacks initiated by `The THC-IPv6 suit <http://thc.org/thc-ipv6/>`_ , the advanced host discovery methods used by `Nmap <http://nmap.org>`_, some attacks initialed by `Evil Foca <http://www.informatica64.com/evilfoca/>`_ and `Metasploit <http://www.metasploit.com/>`_. It can help the network administrators detect the link-local IPv6 attacks in the early stage.

6Guard supported by The Honeynet Project organization is founded by `Weilin Xu <http://www.honeynet.org/gsoc2012/slot9>`_ in Google Summer of Code 2012 and improved by `Jianjun Chen <http://www.honeynet.org/gsoc/slot13>`_ in Google Summer of Code 2013. 

Here is an example of the attacking alert message provided by 6Guard.

::

    [ATTACK]
    Timestamp: 2012-08-19 14:48:27
    Reported by: Honeypot-apple-2A:C4:2D
    Type: DoS
    Name: Fake Echo Request
    Attacker: [Unknown]  00:00:de:ad:be:ef (CETIA)
    Victim  : [Honeypot-apple-2A:C4:2D]  40:3C:FC:2A:C4:2D (Apple, Inc.)
    Utility: THC-IPv6: smurf6
    Packets: b12fe3415c1d61c1da085cb8811974a2.pcap


Installation
-------------
1. Download and install `Scapy <http://www.secdev.org/projects/scapy/>`_ and `Pymongo <https://pypi.python.org/pypi/pymongo/>`_ in your machine. (Or `apt-get install python-scapy python-pymongo`)
2. Download the latest code from `Github/chenjj/ipv6-attack-detector <https://github.com/mzweilin/ipv6-attack-detector>`_ and extract it into a directory.


Usage
----------
1. Enter the directory of 6Guard.
2. Run `$ sudo ./conf_generator.py` to generate the configuration files.
3. Run `$ sudo ./6guadrd.py`.

Hpfeeds
-----------
The 6Guard honeypot has hpfeeds, our central logging feature enabled by default. If you don't want to report your events, turn of hpfeeds in 6guard.cfg. By sending your data via hpfeeds you agree that your data might be shared with 3rd parties. If you are interested in the data collected by 6Guard instances, please contact Jianjun Chen via whucjj[at]gmail[dot]com.


Note
^^^^^^^^^^^^^
    - If it is the first time running 6guard, it will remind you to choice a genuine Router Advertisement message.
    - The attacking alert message will be printed in the screen in real time.
    - The attacking alert message also can be easily configured to be stored in the log file './log/text.log' and  mongodb database.
    - The attacking alert message includes an item 'Packets', telling which pcap file in './pcap/' is the related one that can be reviewd in Wireshark.
