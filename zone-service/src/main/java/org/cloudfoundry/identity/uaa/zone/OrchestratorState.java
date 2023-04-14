package org.cloudfoundry.identity.uaa.zone;

public enum OrchestratorState {
    FOUND("FOUND"),
    NOT_FOUND("NOT_FOUND");

    private String value;

    OrchestratorState(String state) {
        this.value = state;
    }

    @Override
    public String toString() {
        return value;
    }
}
