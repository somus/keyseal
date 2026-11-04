"""Patches arekinath/jcardsim's VSmartCard so a connection to port 8099
re-inserts the card: the vpcd socket is closed and opened again with the
same simulator, so the card keeps its contents and macOS probes it afresh."""
import sys

path = sys.argv[1]
s = open(path).read()


def sub(old, new):
    global s
    assert s.count(old) == 1, old
    s = s.replace(old, new)


sub(
    """        driverProtocol.connect(host, port);
        startThread(driverProtocol);""",
    """        driverProtocol.connect(host, port);
        startThread(driverProtocol);
        final String reHost = host;
        final int rePort = port;
        final VSmartCardTCPProtocol reProtocol = driverProtocol;
        Thread listener = new Thread() {
            public void run() {
                try (java.net.ServerSocket server = new java.net.ServerSocket(8099)) {
                    while (true) {
                        server.accept().close();
                        System.out.println("== Reinsert");
                        reinsert = true;
                        reProtocol.disconnect();
                        Thread.sleep(2000);
                        reProtocol.connect(reHost, rePort);
                        reinsert = false;
                        System.out.println("== Reinserted");
                    }
                } catch (Exception e) {
                    System.out.println("reinsert listener: " + e);
                }
            }
        };
        listener.setDaemon(true);
        listener.start();""",
)
sub(
    "public class VSmartCard {",
    "public class VSmartCard {\n    static volatile boolean reinsert;",
)
sub(
    """                } catch (Exception e) {
                    System.out.println(e.toString());
                }""",
    """                } catch (Exception e) {
                    if (reinsert) {
                        while (reinsert) {
                            try { Thread.sleep(100); } catch (InterruptedException ignored) {}
                        }
                        continue;
                    }
                    System.out.println(e.toString());
                }""",
)
open(path, "w").write(s)
