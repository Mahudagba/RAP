try:
    from threading import Thread
    import time
    import typing
    from sys import exit
    import keyboard
    import scapy.all as scapy
    from dprappkg.AccessPoint import AccessPoint
except ImportError as ie:
    print('\033[31m', "Notice: You must have root permission.", '\033[0m', sep='')
    exit(0)


class Deauther(object):
    def __init__(self, interface: str, trusted_ap: AccessPoint):
        self._interface = interface
        self._trusted_ap = trusted_ap
        self._deauth_threads: typing.List[Thread] = list()

    def check_threat(self, ap: AccessPoint):
        """
        Compare ESSIDs and BSSIDs of access point `ap` with access point `_trusted_ap`.
        If the ESSIDS match and the BSSIDS do not match then assume its an evil twin and start sending deauth packets.
        """
        if ap.essid == self._trusted_ap.essid:
            if ap.bssid.lower() != self._trusted_ap.bssid.lower():
                print('\033[31m', "FOUND EVIL TWIN BSSID: {0} | ESSID: {1} ".format(ap.bssid, ap.essid), '\033[0m', sep='')
                print("I Process Send deauth packets... Press ENTER to see the numbers\n\nPress q to quit")
                try:
                    thread = Thread(target=self.deauth, args=(ap,))
                    self._deauth_threads.append(thread)
                    thread.start()
                except KeyboardInterrupt as ke:
                    exit(0)

    def deauth(self, ap: AccessPoint):
        """
        Sends deauth packets to a given access point.
        """
        nbr_pkt_send = 0
        pkt = (
                scapy.RadioTap()
                / scapy.Dot11(addr1="FF:FF:FF:FF:FF:FF", addr2=ap.bssid, addr3=ap.bssid)
                / scapy.Dot11Deauth(reason=7)
        )

        while True:
            scapy.sendp(pkt, inter=0.1, count=100, iface=self._interface, verbose=0)
            nbr_pkt_send = nbr_pkt_send + 100
            if keyboard.is_pressed('enter'):
                print("{0} packets send to BSSID: {1}".format(nbr_pkt_send, ap.bssid))
            elif keyboard.is_pressed("q"):
                exit(0)
            elif keyboard.is_pressed("ctrl"):
                pass
            time.sleep(0.1)