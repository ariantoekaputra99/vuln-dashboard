package com.vulndash.service;

import com.vulndash.domain.*;
import com.vulndash.repo.FindingRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.*;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Agregasi untuk dashboard.
 * Catatan skala: temuan aktif dimuat ke memori (cukup untuk puluhan ribu baris). Untuk skala lebih besar,
 * pindahkan agregasi ke query GROUP BY / materialized view.
 */
@Service
public class DashboardService {

    private static final int TREND_WEEKS = 8;

    private final FindingRepository findings;

    public DashboardService(FindingRepository findings) {
        this.findings = findings;
    }

    @Transactional(readOnly = true)
    public DashboardSummary summary() {
        Instant now = Instant.now();
        List<Finding> active = findings.findAllWithStatus(FindingStatus.ACTIVE);
        List<Finding> resolved = findings.findResolved(EnumSet.of(FindingStatus.FIXED, FindingStatus.VERIFIED));

        Map<Severity, Long> bySeverity = new EnumMap<>(Severity.class);
        for (Severity s : Severity.values()) bySeverity.put(s, 0L);
        Map<String, Long> byPriority = new LinkedHashMap<>();
        for (String b : List.of("P1", "P2", "P3", "P4")) byPriority.put(b, 0L);
        Map<Tool, Long> byTool = new EnumMap<>(Tool.class);
        for (Tool t : Tool.values()) byTool.put(t, 0L);

        long overdue = 0, due7 = 0, kev = 0;
        Instant in7 = now.plus(Duration.ofDays(7));
        for (Finding f : active) {
            bySeverity.merge(f.getSeverity(), 1L, Long::sum);
            byPriority.merge(ScoringService.band(f.getPriorityScore()), 1L, Long::sum);
            byTool.merge(f.getTool(), 1L, Long::sum);
            if (f.getDueDate().isBefore(now)) overdue++;
            else if (f.getDueDate().isBefore(in7)) due7++;
            if (f.isKnownExploited()) kev++;
        }

        Map<FindingStatus, Long> byStatus = new EnumMap<>(FindingStatus.class);
        for (FindingStatus s : FindingStatus.values()) byStatus.put(s, 0L);
        for (Object[] row : findings.countByStatus()) byStatus.put((FindingStatus) row[0], (Long) row[1]);

        // SLA compliance: persentase temuan yang diselesaikan sebelum jatuh tempo.
        Double compliance = null;
        if (!resolved.isEmpty()) {
            long within = resolved.stream().filter(f -> !f.getResolvedAt().isAfter(f.getDueDate())).count();
            compliance = round1(within * 100.0 / resolved.size());
        }

        Map<Severity, Double> mttr = new EnumMap<>(Severity.class);
        for (Severity s : Severity.values()) {
            OptionalDouble avg = resolved.stream().filter(f -> f.getSeverity() == s)
                    .mapToDouble(f -> Duration.between(f.getFirstSeen(), f.getResolvedAt()).toHours() / 24.0)
                    .average();
            if (avg.isPresent()) mttr.put(s, round1(avg.getAsDouble()));
        }

        List<DashboardSummary.TrendPoint> trend = new ArrayList<>();
        LocalDate today = LocalDate.now(ZoneOffset.UTC);
        for (int i = TREND_WEEKS; i >= 0; i--) {
            LocalDate d = today.minusWeeks(i);
            Instant endOfDay = i == 0 ? now : d.plusDays(1).atStartOfDay().toInstant(ZoneOffset.UTC);
            trend.add(new DashboardSummary.TrendPoint(d.toString(), findings.countOpenAt(endOfDay)));
        }

        List<DashboardSummary.AssetRisk> topAssets = active.stream()
                .collect(Collectors.groupingBy(f -> f.getAsset().getId()))
                .values().stream()
                .map(list -> {
                    Asset a = list.get(0).getAsset();
                    return new DashboardSummary.AssetRisk(
                            a.getId(), a.getName(), a.getCriticality(), list.size(),
                            list.stream().filter(f -> f.getSeverity() == Severity.CRITICAL).count(),
                            list.stream().filter(f -> f.getSeverity() == Severity.HIGH).count(),
                            list.stream().filter(f -> f.isOverdue(now)).count(),
                            list.stream().mapToDouble(Finding::getPriorityScore).max().orElse(0),
                            round1(list.stream().mapToDouble(Finding::getPriorityScore).sum()));
                })
                .sorted(Comparator.comparingDouble(DashboardSummary.AssetRisk::riskScore).reversed())
                .limit(8).toList();

        List<FindingDto> top = active.stream()
                .sorted(Comparator.comparingDouble(Finding::getPriorityScore).reversed())
                .limit(10).map(f -> FindingDto.from(f, now)).toList();

        List<FindingDto> breaches = active.stream()
                .filter(f -> f.isOverdue(now))
                .sorted(Comparator.comparing(Finding::getDueDate))
                .limit(10).map(f -> FindingDto.from(f, now)).toList();

        long critHigh = bySeverity.get(Severity.CRITICAL) + bySeverity.get(Severity.HIGH);
        return new DashboardSummary(now,
                new DashboardSummary.Kpis(active.size(), overdue, due7, kev, critHigh, resolved.size(), compliance),
                bySeverity, byPriority, byStatus, byTool, mttr, trend, topAssets, top, breaches);
    }

    private static double round1(double v) {
        return Math.round(v * 10.0) / 10.0;
    }
}
