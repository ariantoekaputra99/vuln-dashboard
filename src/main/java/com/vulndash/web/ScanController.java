package com.vulndash.web;

import com.vulndash.domain.Criticality;
import com.vulndash.domain.Scan;
import com.vulndash.domain.Tool;
import com.vulndash.repo.ScanRepository;
import com.vulndash.service.BadRequestException;
import com.vulndash.service.IngestResult;
import com.vulndash.service.IngestService;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.io.InputStream;
import java.util.List;

@RestController
@RequestMapping("/api/scans")
public class ScanController {

    private final IngestService ingest;
    private final ScanRepository scans;

    public ScanController(IngestService ingest, ScanRepository scans) {
        this.ingest = ingest;
        this.scans = scans;
    }

    /**
     * Upload hasil scan. Contoh:
     * <pre>curl -H "X-API-Key: $KEY" -F tool=TRIVY -F asset=payment-api:1.4 -F file=@trivy.json http://localhost:8080/api/scans</pre>
     */
    @PostMapping(consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    @ResponseStatus(HttpStatus.CREATED)
    public IngestResult upload(@RequestParam Tool tool,
                               @RequestParam("file") MultipartFile file,
                               @RequestParam(required = false) String asset,
                               @RequestParam(required = false) Criticality criticality,
                               @RequestParam(defaultValue = "true") boolean autoResolve) throws IOException {
        if (file.isEmpty()) throw new BadRequestException("File kosong");
        try (InputStream in = file.getInputStream()) {
            return ingest.ingest(tool, file.getOriginalFilename(), in,
                    new IngestService.Options(asset, criticality, autoResolve));
        }
    }

    @GetMapping
    public List<Scan> recent() {
        return scans.findTop20ByOrderByImportedAtDesc();
    }
}
