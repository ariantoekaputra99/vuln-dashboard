package com.vulndash.service;

import com.vulndash.domain.Criticality;
import com.vulndash.domain.FindingStatus;
import com.vulndash.domain.Severity;
import com.vulndash.domain.Tool;

import java.time.Instant;
import java.util.List;
import java.util.Map;

public record DashboardSummary(
        Instant generatedAt,
        Kpis kpis,
        Map<Severity, Long> activeBySeverity,
        Map<String, Long> activeByPriority,
        Map<FindingStatus, Long> byStatus,
        Map<Tool, Long> activeByTool,
        Map<Severity, Double> mttrDaysBySeverity,
        List<TrendPoint> trend,
        List<AssetRisk> topAssets,
        List<FindingDto> topFindings,
        List<FindingDto> slaBreaches) {

    public record Kpis(
            long active,
            long overdue,
            long dueIn7Days,
            long knownExploited,
            long criticalAndHigh,
            long resolved,
            Double slaCompliancePercent) {
    }

    public record TrendPoint(String date, long open) {
    }

    public record AssetRisk(Long id, String name, Criticality criticality, long active, long critical, long high,
                            long overdue, double maxPriority, double riskScore) {
    }
}
