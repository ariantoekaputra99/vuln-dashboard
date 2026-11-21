package com.vulndash.service;

import com.vulndash.domain.Finding;
import com.vulndash.domain.FindingStatus;
import com.vulndash.domain.Severity;
import com.vulndash.domain.Tool;

import java.time.Duration;
import java.time.Instant;

public record FindingDto(
        Long id,
        Long assetId,
        String assetName,
        Tool tool,
        String title,
        Severity severity,
        Double cvss,
        String cveId,
        String cweId,
        Double epss,
        boolean knownExploited,
        double priorityScore,
        String priority,
        FindingStatus status,
        String assignee,
        String location,
        String component,
        String installedVersion,
        String fixedVersion,
        Instant firstSeen,
        Instant lastSeen,
        Instant dueDate,
        Instant resolvedAt,
        boolean overdue,
        long daysToDue) {

    public static FindingDto from(Finding f, Instant now) {
        long days = Math.floorDiv(Duration.between(now, f.getDueDate()).getSeconds(), 86_400L);
        return new FindingDto(
                f.getId(), f.getAsset().getId(), f.getAsset().getName(), f.getTool(), f.getTitle(), f.getSeverity(),
                f.getCvss(), f.getCveId(), f.getCweId(), f.getEpss(), f.isKnownExploited(),
                f.getPriorityScore(), ScoringService.band(f.getPriorityScore()), f.getStatus(), f.getAssignee(),
                f.getLocation(), f.getComponent(), f.getInstalledVersion(), f.getFixedVersion(),
                f.getFirstSeen(), f.getLastSeen(), f.getDueDate(), f.getResolvedAt(),
                f.isOverdue(now), days);
    }
}
