package com.vulndash.domain;

import jakarta.persistence.*;
import java.time.Instant;

@Entity
@Table(name = "scan")
public class Scan {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private Tool tool;

    @Column(name = "source_file")
    private String sourceFile;

    @Column(name = "imported_at", nullable = false)
    private Instant importedAt = Instant.now();

    @Column(name = "total_count", nullable = false)
    private int totalCount;

    @Column(name = "new_count", nullable = false)
    private int newCount;

    @Column(name = "reopened_count", nullable = false)
    private int reopenedCount;

    @Column(name = "resolved_count", nullable = false)
    private int resolvedCount;

    protected Scan() {
    }

    public Scan(Tool tool, String sourceFile) {
        this.tool = tool;
        this.sourceFile = sourceFile;
    }

    public Long getId() { return id; }
    public Tool getTool() { return tool; }
    public String getSourceFile() { return sourceFile; }
    public Instant getImportedAt() { return importedAt; }
    public int getTotalCount() { return totalCount; }
    public int getNewCount() { return newCount; }
    public int getReopenedCount() { return reopenedCount; }
    public int getResolvedCount() { return resolvedCount; }

    public void setCounts(int total, int created, int reopened, int resolved) {
        this.totalCount = total;
        this.newCount = created;
        this.reopenedCount = reopened;
        this.resolvedCount = resolved;
    }
}
