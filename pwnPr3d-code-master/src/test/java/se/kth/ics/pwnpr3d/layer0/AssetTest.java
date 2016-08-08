package se.kth.ics.pwnpr3d.layer0;

import org.junit.Test;
import se.kth.ics.pwnpr3d.layer2.computer.HardwareComputer;
import se.kth.ics.pwnpr3d.layer2.software.OperatingSystem;

import java.util.Set;

import static org.junit.Assert.assertTrue;

/**
 * Created by avernotte on 10/8/15.
 */
public class AssetTest {

    @Test
    public void testAllAssets() {
        HardwareComputer computer = new HardwareComputer("computer", null);
        OperatingSystem operatingSystem = computer.newOperatingSystem("operatingSystem");
        Set<Asset> allAssets = Asset.getAllAssets();
        assertTrue(allAssets.contains(operatingSystem));
        assertTrue(allAssets.contains(operatingSystem.getIPEthernetARPNetworkInterface().getArpImplementation()));
        assertTrue(allAssets.contains(operatingSystem.getIPEthernetARPNetworkInterface().getIpAddress()));
    }
}
