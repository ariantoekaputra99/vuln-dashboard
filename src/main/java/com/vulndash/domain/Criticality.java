package com.vulndash.domain;

public enum Criticality {
    LOW(0), MEDIUM(0.25), HIGH(0.6), CRITICAL(1.0);

    private final double factor;

    Criticality(double factor) {
        this.factor = factor;
    }

    /** Faktor 0..1 yang dikalikan dengan bobot kritikalitas pada skor prioritas. */
    public double factor() {
        return factor;
    }
}
