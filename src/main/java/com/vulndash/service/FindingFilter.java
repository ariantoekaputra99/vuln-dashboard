package com.vulndash.service;

import com.vulndash.domain.FindingStatus;
import com.vulndash.domain.Severity;
import com.vulndash.domain.Tool;

import java.util.List;

public record FindingFilter(
        List<FindingStatus> status,
        List<Severity> severity,
        Tool tool,
        Long assetId,
        String q,
        Boolean overdue,
        Boolean knownExploited,
        Double minPriority) {
}
