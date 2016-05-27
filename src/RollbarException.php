<?php
namespace Rollbar;

class RollbarException {
    private $message;
    private $exception;

    public function __construct($message, \Exception $exception = null) {
        $this->message = $message;
        $this->exception = $exception;
    }

    public function getMessage() {
        return $this->message;
    }

    public function getException() {
        return $this->exception;
    }
}

