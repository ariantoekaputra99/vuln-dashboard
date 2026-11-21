package com.vulndash.service;

import com.vulndash.domain.*;
import com.vulndash.repo.AssetRepository;
import com.vulndash.repo.FindingEventRepository;
import com.vulndash.repo.FindingRepository;
import jakarta.persistence.criteria.Predicate;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

@Service
public class FindingService {

    private final FindingRepository findings;
    private final FindingEventRepository events;
    private final AssetRepository assets;
    private final ScoringService scoring;

    public FindingService(FindingRepository findings, FindingEventRepository events, AssetRepository assets,
                          ScoringService scoring) {
        this.findings = findings;
        this.events = events;
        this.assets = assets;
        this.scoring = scoring;
    }

    @Transactional(readOnly = true)
    public Page<FindingDto> search(FindingFilter filter, Pageable pageable) {
        Instant now = Instant.now();
        return findings.findAll(toSpec(filter, now), pageable).map(f -> FindingDto.from(f, now));
    }

    @Transactional(readOnly = true)
    public FindingDetailDto get(Long id) {
        Finding f = findings.findWithAsset(id).orElseThrow(() -> new NotFoundException("Temuan tidak ditemukan: " + id));
        List<FindingDetailDto.EventDto> history = events.findByFindingIdOrderByCreatedAtAscIdAsc(id).stream()
                .map(FindingDetailDto.EventDto::from).toList();
        return new FindingDetailDto(FindingDto.from(f, Instant.now()), f.getDescription(), f.getRemediation(),
                f.getStatus().allowedNext(), history);
    }

    public record Update(FindingStatus status, String assignee, String note) {
    }

    @Transactional
    public FindingDetailDto update(Long id, Update req, String actor) {
        Finding f = findings.findWithAsset(id).orElseThrow(() -> new NotFoundException("Temuan tidak ditemukan: " + id));
        Instant now = Instant.now();
        String who = (actor == null || actor.isBlank()) ? "api" : actor;

        if (req.assignee() != null && !req.assignee().equals(f.getAssignee())) {
            String a = req.assignee().isBlank() ? null : req.assignee().trim();
            f.setAssignee(a);
            events.save(new FindingEvent(id, FindingEvent.Type.ASSIGNED, null, null,
                    a == null ? "Assignee dihapus" : "Ditugaskan ke " + a, who));
        }

        if (req.status() != null && req.status() != f.getStatus()) {
            FindingStatus from = f.getStatus();
            FindingStatus to = req.status();
            if (!from.canTransitionTo(to)) {
                throw new BadRequestException("Transisi status tidak diizinkan: " + from + " -> " + to
                        + " (diizinkan: " + from.allowedNext() + ")");
            }
            boolean needsNote = to == FindingStatus.ACCEPTED_RISK || to == FindingStatus.FALSE_POSITIVE;
            if (needsNote && (req.note() == null || req.note().isBlank())) {
                throw new BadRequestException("Status " + to + " wajib disertai catatan/justifikasi");
            }
            f.setStatus(to);
            if (to.isActive()) {
                f.setResolvedAt(null);
            } else if (from.isActive() || f.getResolvedAt() == null) {
                f.setResolvedAt(now);
            }
            FindingEvent.Type type = (to == FindingStatus.OPEN && !from.isActive())
                    ? FindingEvent.Type.REOPENED : FindingEvent.Type.STATUS_CHANGE;
            events.save(new FindingEvent(id, type, from, to, trim(req.note()), who));
        } else if (req.note() != null && !req.note().isBlank()) {
            events.save(new FindingEvent(id, FindingEvent.Type.COMMENT, null, null, trim(req.note()), who));
        }

        findings.save(f);
        return get(id);
    }

    /** Hitung ulang skor semua temuan sebuah aset (mis. setelah kritikalitas aset diubah). */
    @Transactional
    public int rescoreAsset(Long assetId) {
        Asset asset = assets.findById(assetId).orElseThrow(() -> new NotFoundException("Aset tidak ditemukan: " + assetId));
        List<Finding> list = findings.findByAssetId(assetId);
        for (Finding f : list) {
            f.setAsset(asset);
            f.setPriorityScore(scoring.score(f));
        }
        findings.saveAll(list);
        return list.size();
    }

    private static String trim(String s) {
        if (s == null || s.isBlank()) return null;
        String t = s.trim();
        return t.length() > 2000 ? t.substring(0, 2000) : t;
    }

    static Specification<Finding> toSpec(FindingFilter fl, Instant now) {
        return (root, query, cb) -> {
            if (query != null && query.getResultType() != Long.class && query.getResultType() != long.class) {
                root.fetch("asset");
            }
            List<Predicate> p = new ArrayList<>();
            if (fl.status() != null && !fl.status().isEmpty()) p.add(root.get("status").in(fl.status()));
            if (fl.severity() != null && !fl.severity().isEmpty()) p.add(root.get("severity").in(fl.severity()));
            if (fl.tool() != null) p.add(cb.equal(root.get("tool"), fl.tool()));
            if (fl.assetId() != null) p.add(cb.equal(root.get("asset").get("id"), fl.assetId()));
            if (Boolean.TRUE.equals(fl.overdue())) {
                p.add(root.get("status").in(FindingStatus.ACTIVE));
                p.add(cb.lessThan(root.get("dueDate"), now));
            }
            if (Boolean.TRUE.equals(fl.knownExploited())) p.add(cb.isTrue(root.get("knownExploited")));
            if (fl.minPriority() != null) p.add(cb.greaterThanOrEqualTo(root.get("priorityScore"), fl.minPriority()));
            if (fl.q() != null && !fl.q().isBlank()) {
                String like = "%" + escapeLike(fl.q().trim().toLowerCase(Locale.ROOT)) + "%";
                p.add(cb.or(
                        cb.like(cb.lower(root.get("title")), like, '\\'),
                        cb.like(cb.lower(root.get("cveId")), like, '\\'),
                        cb.like(cb.lower(root.get("location")), like, '\\'),
                        cb.like(cb.lower(root.get("component")), like, '\\'),
                        cb.like(cb.lower(root.get("asset").get("name")), like, '\\')));
            }
            return cb.and(p.toArray(new Predicate[0]));
        };
    }

    private static String escapeLike(String s) {
        return s.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_");
    }
}
