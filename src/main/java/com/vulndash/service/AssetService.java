package com.vulndash.service;

import com.vulndash.domain.Asset;
import com.vulndash.domain.AssetType;
import com.vulndash.domain.Criticality;
import com.vulndash.domain.Finding;
import com.vulndash.domain.FindingStatus;
import com.vulndash.repo.AssetRepository;
import com.vulndash.repo.FindingRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;

@Service
public class AssetService {

    public record AssetDto(Long id, String name, AssetType type, Criticality criticality, String owner,
                           long activeFindings, long overdue, double maxPriority) {
    }

    public record Update(Criticality criticality, String owner, AssetType type) {
    }

    private final AssetRepository assets;
    private final FindingRepository findings;
    private final FindingService findingService;

    public AssetService(AssetRepository assets, FindingRepository findings, FindingService findingService) {
        this.assets = assets;
        this.findings = findings;
        this.findingService = findingService;
    }

    @Transactional(readOnly = true)
    public List<AssetDto> list() {
        Instant now = Instant.now();
        Map<Long, List<Finding>> active = findings.findAllWithStatus(FindingStatus.ACTIVE).stream()
                .collect(Collectors.groupingBy(f -> f.getAsset().getId()));
        return assets.findAll().stream()
                .map(a -> toDto(a, active.getOrDefault(a.getId(), List.of()), now))
                .sorted(Comparator.comparingDouble(AssetDto::maxPriority).reversed().thenComparing(AssetDto::name))
                .toList();
    }

    @Transactional
    public AssetDto update(Long id, Update req) {
        Asset a = assets.findById(id).orElseThrow(() -> new NotFoundException("Aset tidak ditemukan: " + id));
        boolean critChanged = req.criticality() != null && req.criticality() != a.getCriticality();
        if (req.criticality() != null) a.setCriticality(req.criticality());
        if (req.type() != null) a.setType(req.type());
        if (req.owner() != null) a.setOwner(req.owner().isBlank() ? null : req.owner().trim());
        assets.save(a);
        if (critChanged) findingService.rescoreAsset(id);
        List<Finding> active = findings.findByAssetId(id).stream().filter(f -> f.getStatus().isActive()).toList();
        return toDto(a, active, Instant.now());
    }

    private AssetDto toDto(Asset a, List<Finding> active, Instant now) {
        return new AssetDto(a.getId(), a.getName(), a.getType(), a.getCriticality(), a.getOwner(),
                active.size(), active.stream().filter(f -> f.isOverdue(now)).count(),
                active.stream().mapToDouble(Finding::getPriorityScore).max().orElse(0));
    }
}
