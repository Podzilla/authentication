package com.podzilla.auth.exception;

public class InvalidActionException extends RuntimeException {
    public InvalidActionException(final String message) {
        super("Invalid action: " + message);
    }
}
