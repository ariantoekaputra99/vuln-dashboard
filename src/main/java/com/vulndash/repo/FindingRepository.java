package com.vulndash.repo;

import com.vulndash.domain.Finding;
import com.vulndash.domain.FindingStatus;
import com.vulndash.domain.Tool;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.Optional;

public interface FindingRepository extends JpaRepository<Finding, Long>, JpaSpecificationExecutor<Finding> {

    Optional<Finding> findByFingerprint(String fingerprint);

    List<Finding> findByAssetIdAndToolAndStatusIn(Long assetId, Tool tool, Collection<FindingStatus> statuses);

    List<Finding> findByAssetId(Long assetId);

    @Query("select f from Finding f join fetch f.asset where f.status in :statuses")
    List<Finding> findAllWithStatus(@Param("statuses") Collection<FindingStatus> statuses);

    @Query("select f from Finding f join fetch f.asset where f.id = :id")
    Optional<Finding> findWithAsset(@Param("id") Long id);

    @Query("select f from Finding f join fetch f.asset where f.resolvedAt is not null and f.status in :statuses")
    List<Finding> findResolved(@Param("statuses") Collection<FindingStatus> statuses);

    /** Temuan yang membutuhkan data EPSS/KEV (punya CVE & status aktif). */
    @Query("select f from Finding f join fetch f.asset where f.cveId is not null and f.status in :statuses")
    List<Finding> findActiveWithCve(@Param("statuses") Collection<FindingStatus> statuses);

    @Query("select count(f) from Finding f where f.firstSeen <= :at and (f.resolvedAt is null or f.resolvedAt > :at)")
    long countOpenAt(@Param("at") Instant at);

    @Query("select f.status, count(f) from Finding f group by f.status")
    List<Object[]> countByStatus();
}
