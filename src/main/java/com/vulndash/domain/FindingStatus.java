package com.vulndash.domain;

import java.util.EnumSet;
import java.util.Set;

public enum FindingStatus {
    OPEN, IN_PROGRESS, FIXED, VERIFIED, ACCEPTED_RISK, FALSE_POSITIVE;

    public static final Set<FindingStatus> ACTIVE = EnumSet.of(OPEN, IN_PROGRESS);
    public static final Set<FindingStatus> CLOSED = EnumSet.of(FIXED, VERIFIED, ACCEPTED_RISK, FALSE_POSITIVE);

    public boolean isActive() {
        return ACTIVE.contains(this);
    }

    /** Alur status yang diizinkan (workflow remediasi). */
    public Set<FindingStatus> allowedNext() {
        return switch (this) {
            case OPEN -> EnumSet.of(IN_PROGRESS, FIXED, ACCEPTED_RISK, FALSE_POSITIVE);
            case IN_PROGRESS -> EnumSet.of(OPEN, FIXED, ACCEPTED_RISK, FALSE_POSITIVE);
            case FIXED -> EnumSet.of(VERIFIED, OPEN);
            case VERIFIED, ACCEPTED_RISK, FALSE_POSITIVE -> EnumSet.of(OPEN);
        };
    }

    public boolean canTransitionTo(FindingStatus next) {
        return allowedNext().contains(next);
    }
}
