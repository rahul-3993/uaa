package org.cloudfoundry.identity.uaa.zone;

import static org.cloudfoundry.identity.uaa.zone.ErrorMessageUtil.MANDATORY_VALIDATION_MESSAGE;
import static org.cloudfoundry.identity.uaa.zone.ErrorMessageUtil.getErrorMessagesConstraintViolation;
import static org.cloudfoundry.identity.uaa.zone.ErrorMessageUtil.getErrorMessagesHttpMessageNotReadable;
import static org.cloudfoundry.identity.uaa.zone.ErrorMessageUtil.getErrorMessagesMethodArgumentInvalid;
import static org.springframework.http.HttpStatus.ACCEPTED;
import static org.springframework.http.HttpStatus.CONFLICT;
import static org.springframework.http.HttpStatus.FORBIDDEN;
import static org.springframework.http.HttpStatus.INTERNAL_SERVER_ERROR;
import static org.springframework.http.HttpStatus.METHOD_NOT_ALLOWED;
import static org.springframework.http.HttpStatus.NOT_FOUND;

import javax.naming.OperationNotSupportedException;
import javax.validation.ConstraintViolationException;
import javax.validation.Valid;
import javax.validation.constraints.NotBlank;

import org.cloudfoundry.identity.uaa.zone.model.OrchestratorErrorResponse;
import org.cloudfoundry.identity.uaa.zone.model.OrchestratorZoneRequest;
import org.cloudfoundry.identity.uaa.zone.model.OrchestratorZoneResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@Validated
@RestController("zoneEndpoints")
@RequestMapping("/orchestrator/zones")
public class OrchestratorZoneController {

    public static final String GET_ZONE_PREFIX = "getZone.";
    private static final Logger logger = LoggerFactory.getLogger(OrchestratorZoneController.class);
    public static final String ZONE_CREATED_MESSAGE = "Zone Created Successfully";
    private final OrchestratorZoneService zoneService;

    public OrchestratorZoneController(OrchestratorZoneService zoneService) {
        this.zoneService = zoneService;
    }

    @GetMapping
    @Transactional(readOnly = true)
    public ResponseEntity<OrchestratorZoneResponse> getZone(@NotBlank(message = MANDATORY_VALIDATION_MESSAGE) @RequestParam String name) {
        return ResponseEntity.ok(zoneService.getZoneDetails(name));
    }

    @PostMapping
    @Transactional
    public ResponseEntity<OrchestratorZoneResponse> createOrchestratorZone(
        @RequestBody @Valid OrchestratorZoneRequest orchestratorZoneRequest) {
        zoneService.createZone(orchestratorZoneRequest);
        OrchestratorZoneResponse body =
            new OrchestratorZoneResponse(orchestratorZoneRequest.getName(), null, ZONE_CREATED_MESSAGE,
                    OrchestratorState.CREATE_IN_PROGRESS.toString());
        return ResponseEntity.status(ACCEPTED).body(body);
    }

    @DeleteMapping
    @Transactional
    public ResponseEntity<?> deleteZone(@NotBlank(message = MANDATORY_VALIDATION_MESSAGE) @RequestParam String name) {
        zoneService.deleteZone(name);
        return ResponseEntity.accepted().build();
    }

    @PutMapping
    public ResponseEntity<?> updateZone(@RequestBody OrchestratorZoneRequest zoneRequest) throws OperationNotSupportedException {
        throw new OperationNotSupportedException("Put Operation not Supported");
    }

    @ExceptionHandler(value = {
        MissingServletRequestParameterException.class,
        OrchestratorZoneServiceException.class
    })
    public ResponseEntity<OrchestratorZoneResponse> badRequest(Exception ex) {
        String zoneName = null;
        if (ex instanceof OrchestratorZoneServiceException) {
            zoneName = ((OrchestratorZoneServiceException) ex).getZoneName();
        }
        return ResponseEntity.badRequest().body(new OrchestratorZoneResponse(zoneName, null, ex.getMessage(),
                OrchestratorState.PERMANENT_FAILURE.toString()));
    }

    @ExceptionHandler(value = { ZoneAlreadyExistsException.class })
    public ResponseEntity<OrchestratorZoneResponse> zoneAlreadyExist(ZoneAlreadyExistsException ex) {
        return ResponseEntity.status(CONFLICT).body(
            new OrchestratorZoneResponse(ex.getZoneName(), null, ex.getMessage(),
                    OrchestratorState.PERMANENT_FAILURE.toString()));
    }

    @ExceptionHandler(value = { ZoneDoesNotExistsException.class })
    public ResponseEntity<OrchestratorZoneResponse> notFound(ZoneDoesNotExistsException ex)
    {
        return ResponseEntity.status(NOT_FOUND).body(
                new OrchestratorZoneResponse(ex.getZoneName(), null, ex.getMessage(), OrchestratorState.NOT_FOUND.toString()));
    }

    @ExceptionHandler(value = { AccessDeniedException.class })
    public ResponseEntity<OrchestratorErrorResponse> accessDenied(Exception ex)
    {
        return ResponseEntity.status(FORBIDDEN).body(new OrchestratorErrorResponse(ex.getMessage()));
    }

    @ExceptionHandler(value = { OperationNotSupportedException.class })
    public ResponseEntity<OrchestratorErrorResponse> methodNotAllowed(Exception ex)
    {
        return ResponseEntity.status(METHOD_NOT_ALLOWED).body(new OrchestratorErrorResponse(ex.getMessage()));
    }

    @ExceptionHandler(value = { Exception.class })
    public ResponseEntity<OrchestratorErrorResponse> internalServerError(Exception ex)
    {
        return ResponseEntity.status(INTERNAL_SERVER_ERROR).body(new OrchestratorErrorResponse(ex.getMessage()));
    }

    @ExceptionHandler(value = { HttpMessageNotReadableException.class })
    public ResponseEntity<OrchestratorErrorResponse> messageReadableException(HttpMessageNotReadableException ex)
    {
        return ResponseEntity.badRequest()
                             .body(new OrchestratorErrorResponse(getErrorMessagesHttpMessageNotReadable(ex)));
    }

    @ExceptionHandler(value = { MethodArgumentNotValidException.class })
    public ResponseEntity<OrchestratorErrorResponse> methodArgumentException(MethodArgumentNotValidException ex) {
        return ResponseEntity.badRequest()
                             .body(new OrchestratorErrorResponse(getErrorMessagesMethodArgumentInvalid(ex)));
    }

    @ExceptionHandler(value = { ConstraintViolationException.class})
    public ResponseEntity<OrchestratorErrorResponse> constraintViolationException(ConstraintViolationException ex)
    {
        return ResponseEntity.badRequest()
                             .body(new OrchestratorErrorResponse(getErrorMessagesConstraintViolation(ex)));
    }
}
