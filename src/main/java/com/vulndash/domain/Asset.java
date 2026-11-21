package com.vulndash.domain;

import jakarta.persistence.*;
import java.time.Instant;

@Entity
@Table(name = "asset")
public class Asset {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true)
    private String name;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private AssetType type = AssetType.OTHER;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private Criticality criticality = Criticality.MEDIUM;

    private String owner;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt = Instant.now();

    protected Asset() {
    }

    public Asset(String name, AssetType type, Criticality criticality) {
        this.name = name;
        this.type = type;
        this.criticality = criticality;
    }

    public Long getId() { return id; }
    public String getName() { return name; }
    public AssetType getType() { return type; }
    public void setType(AssetType type) { this.type = type; }
    public Criticality getCriticality() { return criticality; }
    public void setCriticality(Criticality criticality) { this.criticality = criticality; }
    public String getOwner() { return owner; }
    public void setOwner(String owner) { this.owner = owner; }
    public Instant getCreatedAt() { return createdAt; }
}
