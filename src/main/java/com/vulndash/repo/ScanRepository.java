package com.vulndash.repo;

import com.vulndash.domain.Scan;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface ScanRepository extends JpaRepository<Scan, Long> {
    List<Scan> findTop20ByOrderByImportedAtDesc();
}
