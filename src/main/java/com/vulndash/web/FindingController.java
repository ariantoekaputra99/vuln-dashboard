package com.vulndash.web;

import com.vulndash.domain.FindingStatus;
import com.vulndash.domain.Severity;
import com.vulndash.domain.Tool;
import com.vulndash.service.*;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/findings")
public class FindingController {

    private static final Map<String, String> SORTABLE = Map.of(
            "priority", "priorityScore",
            "cvss", "cvss",
            "epss", "epss",
            "due", "dueDate",
            "firstSeen", "firstSeen",
            "title", "title");

    private final FindingService service;

    public FindingController(FindingService service) {
        this.service = service;
    }

    @GetMapping
    public Page<FindingDto> list(@RequestParam(required = false) List<FindingStatus> status,
                                 @RequestParam(required = false) List<Severity> severity,
                                 @RequestParam(required = false) Tool tool,
                                 @RequestParam(required = false) Long assetId,
                                 @RequestParam(required = false) String q,
                                 @RequestParam(required = false) Boolean overdue,
                                 @RequestParam(required = false) Boolean kev,
                                 @RequestParam(required = false) Double minPriority,
                                 @RequestParam(defaultValue = "priority") String sort,
                                 @RequestParam(defaultValue = "desc") String dir,
                                 @RequestParam(defaultValue = "0") int page,
                                 @RequestParam(defaultValue = "25") int size) {
        String prop = SORTABLE.get(sort);
        if (prop == null) throw new BadRequestException("Nilai sort tidak valid. Pilihan: " + SORTABLE.keySet());
        Sort.Direction d = "asc".equalsIgnoreCase(dir) ? Sort.Direction.ASC : Sort.Direction.DESC;
        PageRequest pr = PageRequest.of(Math.max(0, page), Math.min(Math.max(1, size), 200),
                Sort.by(d, prop).and(Sort.by(Sort.Direction.ASC, "id")));
        return service.search(new FindingFilter(status, severity, tool, assetId, q, overdue, kev, minPriority), pr);
    }

    @GetMapping("/{id}")
    public FindingDetailDto get(@PathVariable Long id) {
        return service.get(id);
    }

    @PatchMapping("/{id}")
    public FindingDetailDto update(@PathVariable Long id, @RequestBody UpdateRequest body,
                                   @RequestHeader(value = "X-Actor", required = false) String actor) {
        if (body.assignee() != null && body.assignee().length() > 255) throw new BadRequestException("Assignee terlalu panjang");
        if (body.note() != null && body.note().length() > 2000) throw new BadRequestException("Catatan terlalu panjang");
        String who = actor == null ? null : actor.substring(0, Math.min(actor.length(), 100));
        return service.update(id, new FindingService.Update(body.status(), body.assignee(), body.note()), who);
    }

    public record UpdateRequest(FindingStatus status, String assignee, String note) {
    }
}
