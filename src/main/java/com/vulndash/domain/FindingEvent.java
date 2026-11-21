package com.vulndash.domain;

import jakarta.persistence.*;
import java.time.Instant;

@Entity
@Table(name = "finding_event")
public class FindingEvent {

    public enum Type { DETECTED, REOPENED, STATUS_CHANGE, AUTO_RESOLVED, ASSIGNED, COMMENT }

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "finding_id", nullable = false)
    private Long findingId;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private Type type;

    @Enumerated(EnumType.STRING)
    @Column(name = "from_status")
    private FindingStatus fromStatus;

    @Enumerated(EnumType.STRING)
    @Column(name = "to_status")
    private FindingStatus toStatus;

    @Column(length = 2000)
    private String note;

    private String actor;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt = Instant.now();

    protected FindingEvent() {
    }

    public FindingEvent(Long findingId, Type type, FindingStatus from, FindingStatus to, String note, String actor) {
        this.findingId = findingId;
        this.type = type;
        this.fromStatus = from;
        this.toStatus = to;
        this.note = note;
        this.actor = actor;
    }

    public Long getId() { return id; }
    public Long getFindingId() { return findingId; }
    public Type getType() { return type; }
    public FindingStatus getFromStatus() { return fromStatus; }
    public FindingStatus getToStatus() { return toStatus; }
    public String getNote() { return note; }
    public String getActor() { return actor; }
    public Instant getCreatedAt() { return createdAt; }
    public void setCreatedAt(Instant createdAt) { this.createdAt = createdAt; }
}
