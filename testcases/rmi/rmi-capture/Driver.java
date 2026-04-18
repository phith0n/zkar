import java.rmi.*;
import java.rmi.registry.*;
import java.rmi.server.*;
import java.util.Arrays;

/**
 * Exercises each standard java.rmi.registry.Registry stub method in a fresh
 * JVM so every capture corresponds to exactly one TCP connection.
 *
 *   Usage: Driver <op> [port]
 *     op:   lookup | list | bind | rebind | unbind
 *     port: proxy/registry port, default 1100
 *
 * Non-fatal exceptions (NotBoundException, AlreadyBoundException) are printed
 * and swallowed — the wire bytes were already produced.
 */
public class Driver {
    public interface Echo extends Remote {
        String echo(String s) throws RemoteException;
    }

    public static class EchoImpl extends UnicastRemoteObject implements Echo {
        protected EchoImpl() throws RemoteException { super(0); }
        @Override public String echo(String s) { return s; }
    }

    public static void main(String[] args) throws Exception {
        if (args.length < 1) {
            System.err.println("usage: Driver <op> [port]");
            System.exit(1);
        }
        String op = args[0];
        int port = args.length > 1 ? Integer.parseInt(args[1]) : 1100;

        Registry r = LocateRegistry.getRegistry("localhost", port);
        switch (op) {
            case "lookup":
                try { r.lookup("ghost"); }
                catch (NotBoundException e) { System.out.println("lookup NotBound (expected)"); }
                break;
            case "list":
                String[] names = r.list();
                System.out.println("list: " + Arrays.toString(names));
                break;
            case "bind": {
                EchoImpl impl = new EchoImpl();
                try { r.bind("bind-name", impl); System.out.println("bind ok"); }
                catch (AlreadyBoundException e) { System.out.println("AlreadyBound"); }
                UnicastRemoteObject.unexportObject(impl, true);
                break;
            }
            case "rebind": {
                EchoImpl impl = new EchoImpl();
                r.rebind("rebind-name", impl);
                System.out.println("rebind ok");
                UnicastRemoteObject.unexportObject(impl, true);
                break;
            }
            case "unbind":
                try { r.unbind("ghost"); System.out.println("unbind ok"); }
                catch (NotBoundException e) { System.out.println("unbind NotBound (expected)"); }
                break;
            default:
                System.err.println("unknown op: " + op);
                System.exit(1);
        }

        // Force exit so RMI's DGC thread doesn't keep the JVM alive.
        System.exit(0);
    }
}
