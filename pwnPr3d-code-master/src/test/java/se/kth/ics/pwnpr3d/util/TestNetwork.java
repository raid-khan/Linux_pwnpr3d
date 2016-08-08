package se.kth.ics.pwnpr3d.util;

import se.kth.ics.pwnpr3d.datatypes.PrivilegeType;
import se.kth.ics.pwnpr3d.datatypes.ProtocolType;
import se.kth.ics.pwnpr3d.layer1.Data;
import se.kth.ics.pwnpr3d.layer1.Information;
import se.kth.ics.pwnpr3d.layer1.Message;
import se.kth.ics.pwnpr3d.layer2.computer.Computer;
import se.kth.ics.pwnpr3d.layer2.computer.HardwareComputer;
import se.kth.ics.pwnpr3d.layer2.network.EthernetSwitch;
import se.kth.ics.pwnpr3d.layer2.network.Firewall;
import se.kth.ics.pwnpr3d.layer2.network.Router;
import se.kth.ics.pwnpr3d.layer2.software.OperatingSystem;

import java.util.ArrayList;
import java.util.List;

public class TestNetwork {

    public Router bigIronRouter;
    public List<Router> routers = new ArrayList<>();
    public List<Firewall> firewalls = new ArrayList<>();
    public List<EthernetSwitch> ethernetSwitches = new ArrayList<>();
    public List<Computer> computers = new ArrayList<>();
    public Information information;
    public Message message;

    public TestNetwork(int nRouter, int nSwitchPerRouter, int nOSPerSwitch, int nServerPerOS, int nClientPerOS, boolean hasFirewalls) {

        bigIronRouter = new Router("bigIronRouter");

        for (int iRouter = 0; iRouter < nRouter; iRouter++) {
            Router newRouter = new Router("router_" + Integer.toString(iRouter));
            routers.add(newRouter);
            if (hasFirewalls) {
                Firewall newFirewall = new Firewall("firewall_" + Integer.toString(iRouter));
                firewalls.add(newFirewall);
                newFirewall.connect(newRouter, true);
                newFirewall.connect(bigIronRouter, false);
            } else {
                newRouter.connect(bigIronRouter);
            }

            for (int iSwitch = 0; iSwitch < nSwitchPerRouter; iSwitch++) {

                EthernetSwitch newEthernetSwitch = new EthernetSwitch("ethernetSwitch_" + Integer.toString(iRouter) + "." + Integer.toString(iSwitch));
                ethernetSwitches.add(newEthernetSwitch);

                for (int iOS = 0; iOS < nOSPerSwitch; iOS++) {
                    Computer newComputer = new HardwareComputer("computer_" + Integer.toString(iRouter) + "." + Integer.toString(iSwitch) + "." + Integer.toString(iOS));
                    computers.add(newComputer);
                    OperatingSystem newOperatingSystem = newComputer.newOperatingSystem("operatingSystem_" + Integer.toString(iRouter) + "." + Integer.toString(iSwitch) + "." + Integer.toString(iOS));
                    newEthernetSwitch.connect(newOperatingSystem);
                    newRouter.connect(newOperatingSystem, newEthernetSwitch);
                    for (int iServer = 0; iServer < nServerPerOS; iServer++) {
                        newOperatingSystem.newNetworkedApplication("server_" + Integer.toString(iRouter) + "." + Integer.toString(iSwitch) + "." + Integer.toString(iOS)
                                + "." + Integer.toString(iServer), PrivilegeType.User, ProtocolType.TCP, false, true);
                    }
                    for (int iClient = 0; iClient < nClientPerOS; iClient++) {
                        newOperatingSystem.newNetworkedApplication("client_" + Integer.toString(iRouter) + "." + Integer.toString(iSwitch) + "." + Integer.toString(iOS)
                                + "." + Integer.toString(iClient), PrivilegeType.User, ProtocolType.TCP, false, false);
                    }
                }
            }
        }

        information = new Information("information", 10, 1000, 100);
        Data dataShell = new Data("DataShell",false);
        information.addRepresentingData(dataShell);
        message = computers.get(0).getOperatingSystems().iterator().next().getIPEthernetARPNetworkInterface().newMessage(dataShell);
    }

    public OperatingSystem getOperatingSystem(int iOS) {
        return computers.get(iOS).getOperatingSystems().iterator().next();
    }
}
