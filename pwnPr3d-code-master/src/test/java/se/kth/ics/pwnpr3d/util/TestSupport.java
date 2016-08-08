package se.kth.ics.pwnpr3d.util;

import edu.uci.ics.jung.algorithms.layout.KKLayout;
import edu.uci.ics.jung.algorithms.layout.Layout;
import edu.uci.ics.jung.graph.Graph;
import edu.uci.ics.jung.graph.SparseMultigraph;
import edu.uci.ics.jung.graph.util.EdgeType;
import edu.uci.ics.jung.visualization.BasicVisualizationServer;
import edu.uci.ics.jung.visualization.control.CrossoverScalingControl;
import edu.uci.ics.jung.visualization.control.ScalingControl;
import edu.uci.ics.jung.visualization.decorators.ToStringLabeller;
import edu.uci.ics.jung.visualization.renderers.Renderer.VertexLabel.Position;
import org.apache.commons.collections15.Transformer;
import se.kth.ics.pwnpr3d.layer0.AttackStep;
import se.kth.ics.pwnpr3d.layer0.AttackStepMax;
import se.kth.ics.pwnpr3d.layer1.Data;
import se.kth.ics.pwnpr3d.layer1.Identity;

import javax.swing.*;
import java.awt.*;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.awt.geom.Ellipse2D;
import java.awt.geom.Rectangle2D;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;

public class TestSupport {

    private final static Object lock = new Object();
    public static boolean showGraphsWhenFailed = false;
    static Graph<AttackStep, String> g;

    static public void allAncestorsGraph(Set<AttackStep> sources, int depth) {
        g = new SparseMultigraph<AttackStep, String>();
        Set<AttackStep> attackSteps = new HashSet<>();
        for (AttackStep source : sources) {
            attackSteps.add(source);
            attackSteps.addAll(source.getAllAncestors(depth - 1));
        }
        int i = 0;
        for (AttackStep ancestor : attackSteps) {
            g.addVertex(ancestor);
            for (AttackStep parent : ancestor.getParents()) {
                i++;
                g.addEdge(Integer.toString(i), parent, ancestor, EdgeType.DIRECTED);
            }
        }
        Set<AttackStep> focusAttackSteps = new HashSet<>();
        focusAttackSteps.addAll(sources);
        displayGraph(focusAttackSteps, "Ancestors");
    }

    static public void allProgenyGraph(Set<AttackStep> sources, int depth) {
        g = new SparseMultigraph<>();
        Set<AttackStep> attackSteps = new HashSet<>();
        for (AttackStep source : sources) {
            attackSteps.add(source);
            attackSteps.addAll(source.getAllProgeny(depth - 1));
        }
        int i = 0;
        for (AttackStep progeny : attackSteps) {
            g.addVertex(progeny);
            for (AttackStep child : progeny.getChildren()) {
                i++;
                g.addEdge(Integer.toString(i), progeny, child, EdgeType.DIRECTED);
            }
        }
        Set<AttackStep> focusAttackSteps = new HashSet<>();
        focusAttackSteps.addAll(sources);
        displayGraph(focusAttackSteps, "Progeny");
    }

    static public void identityFlowGraph(Set<AttackStep> sources, int depth) {
        g = new SparseMultigraph<>();
        Set<AttackStep> attackSteps = new HashSet<>();
        for (AttackStep source : sources) {
            assert (source.getAsset() instanceof Identity);
            attackSteps.add(source);
            attackSteps.addAll(source.getAllProgeny(depth - 1).stream().filter(as->as.isCompromised()
                    && as.getAsset() instanceof Identity).collect(Collectors.toList()));
        }
        int i = 0;
        for (AttackStep progeny : attackSteps) {
            g.addVertex(progeny);
            for (AttackStep child : progeny.getChildren().stream().filter(as->as.isCompromised()
                    && as.getAsset() instanceof Identity).collect(Collectors.toList())) {
                i++;
                g.addEdge(Integer.toString(i), progeny, child, EdgeType.DIRECTED);
            }
        }
        Set<AttackStep> focusAttackSteps = new HashSet<>();
        focusAttackSteps.addAll(sources);
        displayGraph(focusAttackSteps, "Identity Flow");
    }

    public static void displayGraph(Set<AttackStep> focusAttackSteps, String title) {
        Layout<AttackStep, String> layout = new KKLayout(g);
        layout.setSize(new Dimension(1280, 868));
        BasicVisualizationServer<AttackStep, String> vv = new BasicVisualizationServer<>(layout);
        vv.setPreferredSize(new Dimension(1280, 868));
        vv.setBackground(Color.WHITE);
        // Setup up a new vertex to paint transformer...
        Transformer<AttackStep, Paint> vertexPaint = as -> {
            if (as.isCompromised()) {
                if (AttackStepMax.class.isAssignableFrom(as.getClass()))
                    return new Color(155, 108, 108);
                else
                    return new Color(176, 192, 168);
            } else {
                if (AttackStepMax.class.isAssignableFrom(as.getClass()))
                    return new Color(255, 208, 208);
                else
                    return new Color(246, 255, 238);

            }
        };
        Transformer<AttackStep, Shape> vertexShape = as -> {
            Polygon largeTriangle = new Polygon();
            largeTriangle.addPoint(-20, -20);
            largeTriangle.addPoint(0, 20);
            largeTriangle.addPoint(20, -20);
            Polygon mediumTriangle = new Polygon();
            mediumTriangle.addPoint(-10, -10);
            mediumTriangle.addPoint(0, 10);
            mediumTriangle.addPoint(10, -10);
            Polygon smallTriangle = new Polygon();
            smallTriangle.addPoint(-3, -3);
            smallTriangle.addPoint(0, 3);
            smallTriangle.addPoint(3, -3);
            if (focusAttackSteps.contains(as))
                if (Identity.class.isAssignableFrom(as.getAsset().getClass()))
                    return new Rectangle2D.Double(-20, -20, 40, 40);
                else if (Data.class.isAssignableFrom(as.getAsset().getClass()))
                    return largeTriangle;
                else
                    return new Ellipse2D.Double(-20, -20, 40, 40);
            else if (as.getName().equals("access") || as.getName().equals("compromise"))
                if (Identity.class.isAssignableFrom(as.getAsset().getClass()))
                    return new Rectangle2D.Double(-10, -10, 20, 20);
                else
                    return new Ellipse2D.Double(-10, -10, 20, 20);
            else if (as.getName().equals("read") || as.getName().equals("write"))
                return mediumTriangle;
            else if (Identity.class.isAssignableFrom(as.getAsset().getClass()))
                return new Rectangle2D.Double(-3, -3, 6, 6);
            else if (Data.class.isAssignableFrom(as.getAsset().getClass()))
                return smallTriangle;
            else
                return new Ellipse2D.Double(-3, -3, 6, 6);
        };
        // Set up a new stroke Transformer for the edges
        final Stroke edgeStroke = new BasicStroke(1.0f, BasicStroke.CAP_ROUND, BasicStroke.JOIN_MITER);

        Transformer<String, Stroke> edgeStrokeTransformer = s -> edgeStroke;
        Transformer<String, Font> edgeFontTransformer = s -> new Font("Verdana", Font.PLAIN, 0);
        Transformer<AttackStep, Font> vertexFontTransformer = s -> new Font("Verdana", Font.PLAIN, 8);
        Transformer<String, Paint> edgePaint = s -> Color.BLACK;
        ScalingControl scaler = new CrossoverScalingControl();
        scaler.scale(vv, 1 / 0.7f, vv.getCenter());
        vv.getRenderContext().setEdgeLabelTransformer(e -> (" "));
        vv.getRenderContext().setVertexFillPaintTransformer(vertexPaint);
        vv.getRenderContext().setEdgeStrokeTransformer(edgeStrokeTransformer);
        vv.getRenderContext().setVertexLabelTransformer(new ToStringLabeller());
        vv.getRenderContext().setEdgeLabelTransformer(new ToStringLabeller());
        vv.getRenderContext().setEdgeFontTransformer(edgeFontTransformer);
        vv.getRenderContext().setVertexFontTransformer(vertexFontTransformer);
        vv.getRenderer().getVertexLabelRenderer().setPosition(Position.CNTR);
        vv.getRenderContext().setEdgeDrawPaintTransformer(edgePaint);
        vv.getRenderContext().setLabelOffset(20);
        vv.getRenderContext().setVertexShapeTransformer(vertexShape);

        JFrame frame = new JFrame(title);
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.getContentPane().add(vv);
        frame.pack();
        frame.setVisible(true);

        Thread t = new Thread() {
            @Override
            public void run() {
                synchronized (lock) {
                    while (frame.isVisible())
                        try {
                            lock.wait();
                        } catch (InterruptedException e) {
                            e.printStackTrace();
                        }
                    System.out.println("Working now");
                }
            }
        };
        t.start();

        frame.addWindowListener(new WindowAdapter() {

            @Override
            public void windowClosing(WindowEvent arg0) {
                synchronized (lock) {
                    frame.setVisible(false);
                    lock.notify();
                }
            }

        });

        try {
            t.join();
        } catch (InterruptedException e1) {
            e1.printStackTrace();
        }
        // Scanner scan = new Scanner(System.in);
        // int userInput = scan.nextInt();
    }

    static public void assertCompromised(AttackStep attackStep) {
        if (!attackStep.isCompromised()) {
            String asType = "AttackStepMin";
            String tempString = " Compromise failed as none of the following parent attack step(s) were compromised:";
            if (AttackStepMax.class.isAssignableFrom(attackStep.getClass())) {
                asType = "AttackStepMax";
                tempString = "  Compromise failed because the following parent attack step(s) were not compromised:";
            }
            System.out.println("Failed to compromise " + asType + " " + attackStep.getFullName());
            System.out.println(tempString);
            for (AttackStep parentStep : attackStep.getRemainingParents()) {
                asType = "AttackStepMin";
                if (AttackStepMax.class.isAssignableFrom(parentStep.getClass())) {
                    asType = "AttackStepMax";
                }
                System.out.print("   " + asType + " " + parentStep.getFullName());
                if (parentStep.isCompromised()) {
                    System.out.println(" (compromised)");
                } else {
                    System.out.println(" (uncompromised)");
                }
                System.out.println("    Whose remaining parents in turn are: ");
                for (AttackStep grandParentStep : parentStep.getRemainingParents()) {
                    System.out.println("      " + grandParentStep.getFullName());
                }
            }

            Set<AttackStep> poa = new HashSet<>();
            poa.add(attackStep);
            if (showGraphsWhenFailed)
                allAncestorsGraph(poa, 5);

            fail("Failed to compromise " + attackStep.getFullName());
        }
    }

    static public void assertNotCompromised(AttackStep attackStep) {
        if (attackStep.isCompromised()) {
            String asType = "AttackStepMin";
            String tempString = "   None of the following parent attack step(s) should have been compromised:";
            if (AttackStepMax.class.isAssignableFrom(attackStep.getClass())) {
                asType = "AttackStepMax";
                tempString = "   At least one of the following parent attack steps should not have been compromised:";
            }
            System.out.println("Inadvertently compromised " + asType + " " + attackStep.getFullName());
            System.out.println(tempString);
            for (AttackStep parentStep : attackStep.getParents()) {
                System.out.println("      " + parentStep.getFullName());
            }
            System.out.println("   However, all but the following were compromised:");
            for (AttackStep parentStep : attackStep.getRemainingParents()) {
                System.out.println("      " + parentStep.getFullName());
            }

            Set<AttackStep> poa = new HashSet<>();
            poa.add(attackStep);
            if (showGraphsWhenFailed)
                allAncestorsGraph(poa, 5);

            fail("Inadvertently compromised " + attackStep.getFullName());
        }
    }

    static public void fail(String message) {
        if (message == null) {
            throw new AssertionError();
        }
        throw new AssertionError(message);
    }

    public static void assertAttackPath(AttackStep source, AttackStep destination, int maxSteps) {
        if (!source.getAllProgeny(maxSteps).contains(destination)) {
            fail(source.getFullName() + " did not lead to " + destination.getFullName() + " within " + maxSteps + " hops.");
        }
    }
}
