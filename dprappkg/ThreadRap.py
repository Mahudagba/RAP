try:
    from os import system
    from dprappkg.AccessPoint import *
    from dprappkg.Deauth import Deauther
    from dprappkg.Scanner import Scanner
    from threading import Thread
except Exception as e:
    system("clear")
    print(e)


class ThreadRap(Thread):
    """Thread chargé de vérifier les eviltwin."""

    def __init__(self, bssid, essid, iface):
        Thread.__init__(self)
        self._bssid = bssid
        self._essid = essid
        self._iface = iface

    def run(self):
        """Code à exécuter pendant l'exécution du thread."""
        print(" Starting protect AP => BSSID: {0!s} | ESSID: {1!s}".format(self._bssid, self._essid))
        trusted_ap = AccessPoint(bssid=self._bssid, essid=self._essid)
        deauther = Deauther(self._iface, trusted_ap)
        scanr = Scanner(self._iface)
        scanr.subscribe(deauther.check_threat)
        scanr.scan()
