package com.vulndash.domain;

import jakarta.persistence.*;
import java.time.Instant;

@Entity
@Table(name = "finding")
public class Finding {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true, length = 64)
    private String fingerprint;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "asset_id")
    private Asset asset;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private Tool tool;

    @Column(nullable = false, length = 500)
    private String title;

    @Column(length = 4000)
    private String description;

    @Column(length = 2000)
    private String remediation;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private Severity severity;

    private Double cvss;

    @Column(name = "cve_id")
    private String cveId;

    @Column(name = "cwe_id")
    private String cweId;

    private Double epss;

    @Column(name = "epss_updated_at")
    private Instant epssUpdatedAt;

    @Column(name = "known_exploited", nullable = false)
    private boolean knownExploited;

    @Column(length = 1000)
    private String location;

    private String component;

    @Column(name = "installed_version")
    private String installedVersion;

    @Column(name = "fixed_version")
    private String fixedVersion;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private FindingStatus status = FindingStatus.OPEN;

    @Column(name = "priority_score", nullable = false)
    private double priorityScore;

    private String assignee;

    @Column(name = "first_seen", nullable = false)
    private Instant firstSeen;

    @Column(name = "last_seen", nullable = false)
    private Instant lastSeen;

    @Column(name = "due_date", nullable = false)
    private Instant dueDate;

    @Column(name = "resolved_at")
    private Instant resolvedAt;

    @Column(name = "last_scan_id")
    private Long lastScanId;

    public Long getId() { return id; }
    public String getFingerprint() { return fingerprint; }
    public void setFingerprint(String fingerprint) { this.fingerprint = fingerprint; }
    public Asset getAsset() { return asset; }
    public void setAsset(Asset asset) { this.asset = asset; }
    public Tool getTool() { return tool; }
    public void setTool(Tool tool) { this.tool = tool; }
    public String getTitle() { return title; }
    public void setTitle(String title) { this.title = title; }
    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }
    public String getRemediation() { return remediation; }
    public void setRemediation(String remediation) { this.remediation = remediation; }
    public Severity getSeverity() { return severity; }
    public void setSeverity(Severity severity) { this.severity = severity; }
    public Double getCvss() { return cvss; }
    public void setCvss(Double cvss) { this.cvss = cvss; }
    public String getCveId() { return cveId; }
    public void setCveId(String cveId) { this.cveId = cveId; }
    public String getCweId() { return cweId; }
    public void setCweId(String cweId) { this.cweId = cweId; }
    public Double getEpss() { return epss; }
    public void setEpss(Double epss) { this.epss = epss; }
    public Instant getEpssUpdatedAt() { return epssUpdatedAt; }
    public void setEpssUpdatedAt(Instant epssUpdatedAt) { this.epssUpdatedAt = epssUpdatedAt; }
    public boolean isKnownExploited() { return knownExploited; }
    public void setKnownExploited(boolean knownExploited) { this.knownExploited = knownExploited; }
    public String getLocation() { return location; }
    public void setLocation(String location) { this.location = location; }
    public String getComponent() { return component; }
    public void setComponent(String component) { this.component = component; }
    public String getInstalledVersion() { return installedVersion; }
    public void setInstalledVersion(String installedVersion) { this.installedVersion = installedVersion; }
    public String getFixedVersion() { return fixedVersion; }
    public void setFixedVersion(String fixedVersion) { this.fixedVersion = fixedVersion; }
    public FindingStatus getStatus() { return status; }
    public void setStatus(FindingStatus status) { this.status = status; }
    public double getPriorityScore() { return priorityScore; }
    public void setPriorityScore(double priorityScore) { this.priorityScore = priorityScore; }
    public String getAssignee() { return assignee; }
    public void setAssignee(String assignee) { this.assignee = assignee; }
    public Instant getFirstSeen() { return firstSeen; }
    public void setFirstSeen(Instant firstSeen) { this.firstSeen = firstSeen; }
    public Instant getLastSeen() { return lastSeen; }
    public void setLastSeen(Instant lastSeen) { this.lastSeen = lastSeen; }
    public Instant getDueDate() { return dueDate; }
    public void setDueDate(Instant dueDate) { this.dueDate = dueDate; }
    public Instant getResolvedAt() { return resolvedAt; }
    public void setResolvedAt(Instant resolvedAt) { this.resolvedAt = resolvedAt; }
    public Long getLastScanId() { return lastScanId; }
    public void setLastScanId(Long lastScanId) { this.lastScanId = lastScanId; }

    public boolean isOverdue(Instant now) {
        return status.isActive() && dueDate.isBefore(now);
    }

    /** CVSS efektif: skor asli, atau estimasi dari severity bila tidak ada. */
    public double effectiveCvss() {
        return cvss != null ? cvss : severity.defaultCvss();
    }
}
