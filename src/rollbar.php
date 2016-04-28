<?php
namespace Rollbar;

/**
 * Singleton-style wrapper around RollbarNotifier
 *
 * Unless you need multiple RollbarNotifier instances in the same project, use this.
 */
class Rollbar {
    /** @var RollbarNotifier */
    public static $instance = null;

    public static function init($config = array(), $setExceptionHandler = true, $setErrorHandler = true, $reportFatalErrors = true) {
        // Heroku support
        // Use env vars for configuration, if set
        if (isset($_ENV['ROLLBAR_ACCESS_TOKEN']) && !isset($config['accessToken'])) {
            $config['access_token'] = $_ENV['ROLLBAR_ACCESS_TOKEN'];
        }
        if (isset($_ENV['ROLLBAR_ENDPOINT']) && !isset($config['endpoint'])) {
            $config['endpoint'] = $_ENV['ROLLBAR_ENDPOINT'];
        }
        if (isset($_ENV['HEROKU_APP_DIR']) && !isset($config['root'])) {
            $config['root'] = $_ENV['HEROKU_APP_DIR'];
        }

        self::$instance = new RollbarNotifier($config);

        if ($setExceptionHandler) {
            set_exception_handler('Rollbar::reportException');
        }
        if ($setErrorHandler) {
            set_error_handler('Rollbar::reportPhpError');
        }
        if ($reportFatalErrors) {
            register_shutdown_function('Rollbar::reportFatalError');
        }

        if (self::$instance->batched) {
            register_shutdown_function('Rollbar::flush');
        }
    }

    public static function reportException($exc, $extraData = null, $payloadData = null) {
        if (self::$instance == null) {
            return;
        }
        return self::$instance->reportException($exc, $extraData, $payloadData);
    }

    public static function reportMessage($message, $level = Level::ERROR, $extraData = null, $payloadData = null) {
        if (self::$instance == null) {
            return;
        }
        return self::$instance->reportMessage($message, $level, $extraData, $payloadData);
    }

    public static function reportFatalError() {
        // Catch any fatal errors that are causing the shutdown
        $lastError = error_get_last();
        if (!is_null($lastError)) {
            switch ($lastError['type']) {
                case E_PARSE:
                case E_ERROR:
                    self::$instance->reportPhpError($lastError['type'], $lastError['message'], $lastError['file'], $lastError['line']);
                    break;
            }
        }
    }

    // This function must return false so that the default php error handler runs
    public static function report_php_error($errno, $errstr, $errfile, $errline) {
        if (self::$instance != null) {
            self::$instance->reportPhpError($errno, $errstr, $errfile, $errline);
        }
        return false;
    }

    public static function flush() {
        self::$instance->flush();
    }
}

/*
interface iRollbarLogger {
    public function log($level, $msg);
}

class Ratchetio extends Rollbar {}
*/
