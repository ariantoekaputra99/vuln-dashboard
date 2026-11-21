package com.vulndash.service;

import com.vulndash.domain.FindingEvent;
import com.vulndash.domain.FindingStatus;

import java.time.Instant;
import java.util.List;
import java.util.Set;

public record FindingDetailDto(
        FindingDto finding,
        String description,
        String remediation,
        Set<FindingStatus> allowedNext,
        List<EventDto> events) {

    public record EventDto(FindingEvent.Type type, FindingStatus from, FindingStatus to, String note, String actor,
                           Instant at) {
        static EventDto from(FindingEvent e) {
            return new EventDto(e.getType(), e.getFromStatus(), e.getToStatus(), e.getNote(), e.getActor(), e.getCreatedAt());
        }
    }
}
