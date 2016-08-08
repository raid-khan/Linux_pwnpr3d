package se.kth.ics.pwnpr3d.layer0;

import org.junit.Test;

import static org.junit.Assert.assertTrue;
import static org.mockito.internal.util.collections.Sets.newSet;

/**
 * Created by avernotte on 10/12/15.
 */
public class AttackStepTest {

    @Test
    public void addAndRemoveOneChildTest() {
        AttackStepMin as1 = new AttackStepMin("as1", null);
        AttackStepMin as2 = new AttackStepMin("as2", null);

        as1.addChildren(as2);

        assertTrue(as1.getChildren().contains(as2));
        assertTrue(as2.getParents().contains(as1));

        as1.removeChildren(as2);

        assertTrue(as1.getChildren().size() == 0);
        assertTrue(as2.getParents().size() == 0);
    }

    @Test
    public void addParentAndRemoveChildTest() {
        AttackStepMin as1 = new AttackStepMin("as1", null);
        AttackStepMin as2 = new AttackStepMin("as2", null);

        as2.addParents(as1);

        assertTrue(as1.getChildren().contains(as2));
        assertTrue(as2.getParents().contains(as1));

        as1.removeChildren(as2);

        assertTrue(as1.getChildren().size() == 0);
        assertTrue(as2.getParents().size() == 0);
    }

    @Test
    public void addAndRemoveOneParentTest() {
        AttackStepMin as1 = new AttackStepMin("as1", null);
        AttackStepMin as2 = new AttackStepMin("as2", null);

        as2.addParents(as1);

        assertTrue(as1.getChildren().contains(as2));
        assertTrue(as2.getParents().contains(as1));

        as2.removeParents(as1);

        assertTrue(as1.getChildren().size() == 0);
        assertTrue(as2.getParents().size() == 0);
    }

    @Test
    public void addChildAndRemoveParentTest() {
        AttackStepMin as1 = new AttackStepMin("as1", null);
        AttackStepMin as2 = new AttackStepMin("as2", null);

        as1.addChildren(as2);

        assertTrue(as1.getChildren().contains(as2));
        assertTrue(as2.getParents().contains(as1));

        as2.removeParents(as1);

        assertTrue(as1.getChildren().size() == 0);
        assertTrue(as2.getParents().size() == 0);
    }

    @Test
    public void addAndRemoveChildrenTest() {
        AttackStepMin as1 = new AttackStepMin("as1", null);
        AttackStepMin as2 = new AttackStepMin("as2", null);
        AttackStepMin as3 = new AttackStepMin("as3", null);

        as1.addChildren(as2);
        as1.addChildren(as3);

        assertTrue(as1.getChildren().containsAll(newSet(as2, as3)));
        assertTrue(as2.getParents().contains(as1));
        assertTrue(as3.getParents().contains(as1));

        as1.removeChildren(as2, as3);

        assertTrue(as1.getChildren().size() == 0);
        assertTrue(as2.getParents().size() == 0);
        assertTrue(as3.getParents().size() == 0);
    }

    @Test
    public void addAndRemoveParentsTest() {
        AttackStepMin as1 = new AttackStepMin("as1", null);
        AttackStepMin as2 = new AttackStepMin("as2", null);
        AttackStepMin as3 = new AttackStepMin("as3", null);

        as2.addParents(as1);
        as3.addParents(as2);

        assertTrue(as2.getParents().contains(as1));
        assertTrue(as3.getParents().contains(as2));

        as1.removeChildren(as2);
        as2.removeChildren(as3);

        assertTrue(as1.getChildren().size() == 0);
        assertTrue(as2.getParents().size() == 0);
        assertTrue(as2.getChildren().size() == 0);
        assertTrue(as3.getParents().size() == 0);
    }

    @Test
    public void addParentAndRemoveChildrenTest() {
        AttackStepMin as1 = new AttackStepMin("as1", null);
        AttackStepMin as2 = new AttackStepMin("as2", null);
        AttackStepMin as3 = new AttackStepMin("as3", null);

        as2.addParents(as1);
        as3.addParents(as1);

        assertTrue(as1.getChildren().containsAll(newSet(as2, as3)));
        assertTrue(as2.getParents().contains(as1));
        assertTrue(as3.getParents().contains(as1));

        as1.removeChildren(as2, as3);

        assertTrue(as1.getChildren().size() == 0);
        assertTrue(as2.getParents().size() == 0);
        assertTrue(as3.getParents().size() == 0);
    }

    @Test
    public void addAndRemoveTwoParentsTest() {
        AttackStepMin as1 = new AttackStepMin("as1", null);
        AttackStepMin as2 = new AttackStepMin("as2", null);
        AttackStepMin as3 = new AttackStepMin("as3", null);

        as3.addParents(as1);
        as3.addParents(as2);

        assertTrue(as3.getParents().containsAll(newSet(as1, as2)));
        assertTrue(as1.getChildren().contains(as3));
        assertTrue(as2.getChildren().contains(as3));

        as3.removeParents(as1, as2);

        assertTrue(as1.getChildren().size() == 0);
        assertTrue(as2.getChildren().size() == 0);
        assertTrue(as3.getParents().size() == 0);
    }

}
