package se.kth.ics.pwnpr3d.layer1;

import org.junit.Test;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class DataTest {

    @Test
    public void testContainsNot() {
        Data d1 = new Data("d", null, false);
        Data d2 = new Data("d", null, false);
        assertFalse(d1.contains(d2));
    }

    @Test
    public void testContainsOne() {
        Data d1 = new Data("d", null, false);
        Data d2 = new Data("d", null, false);
        d1.addBody(d2);
        assertTrue(d1.contains(d2));
    }

    @Test
    public void testContainsTwo() {
        Data d1 = new Data("d", null, false);
        Data d2 = new Data("d", null, false);
        Data d3 = new Data("d", null, false);
        d1.addBody(d2);
        d1.addBody(d3);
        assertTrue(d1.contains(d3));
    }

    @Test
    public void testContainsTwoNot() {
        Data d1 = new Data("d", null, false);
        Data d2 = new Data("d", null, false);
        Data d3 = new Data("d", null, false);
        Data d4 = new Data("d", null, false);
        d1.addBody(d2);
        d1.addBody(d3);
        assertFalse(d1.contains(d4));
    }

    @Test
    public void testContainsMultiLevel() {
        Data d1 = new Data("d", null, false);
        Data d2 = new Data("d", null, false);
        Data d3 = new Data("d", null, false);
        d1.addBody(d2);
        d2.addBody(d3);
        assertTrue(d1.contains(d3));
    }

    @Test
    public void testContainsMultiLevelNot() {
        Data d1 = new Data("d", null, false);
        Data d2 = new Data("d", null, false);
        Data d3 = new Data("d", null, false);
        Data d4 = new Data("d", null, false);
        d1.addBody(d2);
        d2.addBody(d3);
        assertFalse(d1.contains(d4));
    }

}
