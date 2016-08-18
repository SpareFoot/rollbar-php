<?php
namespace Rollbar;

// Throw Exceptions in PHP < v7.0, throw Throwables in PHP > 7.0
if(!defined('BASE_EXCEPTION')) {
    define('BASE_EXCEPTION', version_compare(phpversion(), '7.0', '<') ? '\Exception' : '\Throwable');
}

// Send errors that have these levels
if (!defined('ROLLBAR_INCLUDED_ERRNO_BITMASK')) {
    define('ROLLBAR_INCLUDED_ERRNO_BITMASK', E_ERROR | E_WARNING | E_PARSE | E_CORE_ERROR | E_USER_ERROR | E_RECOVERABLE_ERROR);
}

class RollbarNotifier {
    const VERSION = '0.18.0';

    // required
    public $accessToken = '';

    // optional / defaults
    public $baseApiUrl = 'https://api.rollbar.com/api/1/';
    public $batchSize = 50;
    public $batched = true;
    public $branch = null;
    public $captureErrorBacktraces = true;
    public $codeVersion = null;
    public $environment = 'production';
    public $errorSampleRates = array();
    // available handlers: blocking, agent
    public $handler = 'blocking';
    public $agentLogLocation = '/var/tmp';
    public $host = null;
    /** @var iRollbarLogger */
    public $logger = null;
    public $includedErrno = ROLLBAR_INCLUDED_ERRNO_BITMASK;
    public $person = null;
    public $personFn = null;
    public $root = '';
    public $checkIgnore = null;
    public $scrubFields = array('passwd', 'pass', 'password', 'secret', 'confirm_password', 'password_confirmation', 'auth_token', 'csrf_token');
    public $shiftFunction = true;
    public $timeout = 3;
    public $reportSuppressed = false;
    public $useErrorReporting = false;
    public $proxy = null;
    public $includeErrorCodeContext = false;
    public $includeExceptionCodeContext = false;

    private $configKeys = [
        'accessToken', 'agentLocation', 'baseApiUrl', 'batchSize', 'batched', 'branch', 'captureErrorBacktraces',
        'checkIgnore', 'codeVersion', 'environment', 'errorSampleRates', 'handler', 'host', 'includeErrNo',
        'includeErrorCodeContext', 'includeExceptionCodeContext', 'logger', 'person', 'personFn', 'proxy', 'root',
        'scrubFields', 'shiftFunction', 'timeout', 'reportSuppressed', 'useErrorReporting'
    ];

    // cached values for request/server/person data
    private $_phpContext = null;
    private $_requestData = null;
    private $_serverData = null;
    private $_personData = null;

    // payload queue, used when $batched is true
    private $_queue = array();

    // file handle for agent log
    private $_agentLog = null;

    private $_iconvAvailable = null;

    private $_mtRandmax;

    private $_curlIpResolveSupported;

    /** @var SourceFileReader */
    private $_sourceFileReader;

    public function __construct($config) {
        foreach ($this->configKeys as $key) {
            if (isset($config[$key])) {
                #$camelCasedKey = lcfirst(ucwords(strtr($key, '_', ' ')));
                $this->$key = $config[$key];
            }
        }
        $this->_sourceFileReader = new SourceFileReader();

        if (!$this->accessToken && $this->handler != 'agent') {
            $this->logError('Missing access token');
        }

        // fill in missing values in errorSampleRates
        $levels = array(E_WARNING, E_NOTICE, E_USER_ERROR, E_USER_WARNING, E_USER_NOTICE, E_STRICT, E_RECOVERABLE_ERROR);

        // PHP 5.3.0
        if (defined('E_DEPRECATED')) {
            $levels = array_merge($levels, array(E_DEPRECATED, E_USER_DEPRECATED));
        }

        // PHP 5.3.0
        $this->_curlIpResolveSupported = defined('CURLOPT_IPRESOLVE');

        $curr = 1;
        for ($i = 0, $num = count($levels); $i < $num; $i++) {
            $level = $levels[$i];
            if (isset($this->errorSampleRates[$level])) {
                $curr = $this->errorSampleRates[$level];
            } else {
                $this->errorSampleRates[$level] = $curr;
            }
        }

        // cache this value
        $this->_mtRandmax = mt_getrandmax();
    }

    public function reportException($exc, $extraData = null, $payloadData = null) {
        try {
            if (!is_a($exc, BASE_EXCEPTION)) {
                throw new Exception(sprintf('Report exception requires an instance of %s.', BASE_EXCEPTION));
            }

            return $this->_reportException($exc, $extraData, $payloadData);
        } catch (Exception $e) {
            try {
                $this->logError('Exception while reporting exception');
            } catch (Exception $e) {
                // swallow
            }
        }
    }

    public function reportMessage($message, $level = Level::ERROR, $extraData = null, $payloadData = null) {
        try {
            return $this->_reportMessage($message, $level, $extraData, $payloadData);
        } catch (Exception $e) {
            try {
                $this->logError('Exception while reporting message');
            } catch (Exception $e) {
                // swallow
            }
        }
    }

    public function reportPhpError($errno, $errstr, $errfile, $errline) {
        try {
            return $this->_reportPhpError($errno, $errstr, $errfile, $errline);
        } catch (Exception $e) {
            try {
                $this->logError('Exception while reporting php error');
            } catch (Exception $e) {
                // swallow
            }
        }
    }

    /**
     * Flushes the queue.
     * Called internally when the queue exceeds $batchSize, and by Rollbar::flush
     * on shutdown.
     */
    public function flush() {
        $queueSize = $this->queueSize();
        if ($queueSize > 0) {
            $this->logInfo('Flushing queue of size ' . $queueSize);
            $this->sendBatch($this->_queue);
            $this->_queue = array();
        }
    }

    /**
     * Returns the current queue size.
     */
    public function queueSize() {
        return count($this->_queue);
    }

    /**
     * @param \Throwable|\Exception $exc
     * @param array $extraData
     * @param array $payloadData
     * @return string UUID
     */
    protected function _reportException($exc, $extraData = null, $payloadData = null) {
        if (!$this->checkConfig()) {
            return;
        }

        if (error_reporting() === 0 && !$this->reportSuppressed) {
            // ignore
            return;
        }

        $data = $this->buildBaseData();

        $traceChain = $this->buildExceptionTraceChain($exc, $extraData);

        if (count($traceChain) > 1) {
            $data['body']['trace_chain'] = $traceChain;
        } else {
            $data['body']['trace'] = $traceChain[0];
        }

        // request, server, person data
        if ('http' === $this->_phpContext) {
            $data['request'] = $this->buildRequestData();
        }
        $data['server'] = $this->buildServerData();
        $data['person'] = $this->buildPersonData();

        // merge $payloadData into $data
        // (overriding anything already present)
        if ($payloadData !== null && is_array($payloadData)) {
            foreach ($payloadData as $key => $val) {
                $data[$key] = $val;
            }
        }

        $data = $this->_sanitizeKeys($data);
        array_walk_recursive($data, array($this, '_sanitizeUtf8'));

        $payload = $this->buildPayload($data);

        // Determine whether to send the request to the API
        if ($this->_shouldIgnore(true, new RollbarException($exc->getMessage(), $exc), $payload)) {
            return;
        }

        $this->sendPayload($payload);

        return $data['uuid'];
    }

    protected function _sanitizeUtf8(&$value) {
        if (!isset($this->_iconvAvailable)) {
            $this->_iconvAvailable = function_exists('iconv');
        }
        if (is_string($value) && $this->_iconvAvailable) {
            $value = @iconv('UTF-8', 'UTF-8//IGNORE', $value);
        }
    }

    protected function _sanitizeKeys(array $data) {
        $response = array();
        foreach ($data as $key => $value) {
            $this->_sanitizeUtf8($key);
            if (is_array($value)) {
                $response[$key] = $this->_sanitizeKeys($value);
            } else {
                $response[$key] = $value;
            }
        }

        return $response;
    }

    protected function _reportPhpError($errno, $errstr, $errfile, $errline) {
        if (!$this->checkConfig()) {
            return;
        }

        if (error_reporting() === 0 && !$this->reportSuppressed) {
            // ignore
            return;
        }

        if ($this->useErrorReporting && (error_reporting() & $errno) === 0) {
            // ignore
            return;
        }

        if ($this->includedErrno != -1 && ($errno & $this->includedErrno) != $errno) {
            // ignore
            return;
        }

        if (isset($this->errorSampleRates[$errno])) {
            // get a float in the range [0, 1)
            // mt_rand() is inclusive, so add 1 to mt_randmax
            $floatRand = mt_rand() / ($this->_mtRandmax + 1);
            if ($floatRand > $this->errorSampleRates[$errno]) {
                // skip
                return;
            }
        }

        $data = $this->buildBaseData();

        // set error level and error constant name
        $level = Level::INFO;
        $constant = '#' . $errno;
        switch ($errno) {
            case 1:
                $level = Level::ERROR;
                $constant = 'E_ERROR';
                break;
            case 2:
                $level = Level::WARNING;
                $constant = 'E_WARNING';
                break;
            case 4:
                $level = Level::CRITICAL;
                $constant = 'E_PARSE';
                break;
            case 8:
                $level = Level::INFO;
                $constant = 'E_NOTICE';
                break;
            case 256:
                $level = Level::ERROR;
                $constant = 'E_USER_ERROR';
                break;
            case 512:
                $level = Level::WARNING;
                $constant = 'E_USER_WARNING';
                break;
            case 1024:
                $level = Level::INFO;
                $constant = 'E_USER_NOTICE';
                break;
            case 2048:
                $level = Level::INFO;
                $constant = 'E_STRICT';
                break;
            case 4096:
                $level = Level::ERROR;
                $constant = 'E_RECOVERABLE_ERROR';
                break;
            case 8192:
                $level = Level::INFO;
                $constant = 'E_DEPRECATED';
                break;
            case 16384:
                $level = Level::INFO;
                $constant = 'E_USER_DEPRECATED';
                break;
        }
        $data['level'] = $level;

        // use the whole $errstr. may want to split this by colon for better de-duping.
        $errorClass = $constant . ': ' . $errstr;

        // build something that looks like an exception
        $data['body'] = array(
            'trace' => array(
                'frames' => $this->buildErrorFrames($errfile, $errline),
                'exception' => array(
                    'class' => $errorClass
                )
            )
        );

        // request, server, person data
        $data['request'] = $this->buildRequestData();
        $data['server'] = $this->buildServerData();
        $data['person'] = $this->buildPersonData();

        array_walk_recursive($data, array($this, '_sanitizeUtf8'));

        $payload = $this->buildPayload($data);

        // Determine whether to send the request to the API
        $exception = new \ErrorException($errorClass, 0, $errno, $errfile, $errline);
        if ($this->_shouldIgnore(true, new RollbarException($exception->getMessage(), $exception), $payload)) {
            return;
        }

        $this->sendPayload($payload);

        return $data['uuid'];
    }

    protected function _reportMessage($message, $level, $extraData, $payloadData) {
        if (!$this->checkConfig()) {
            return;
        }

        $data = $this->buildBaseData();
        $data['level'] = strtolower($level);

        $messageObj = array('body' => $message);
        if ($extraData !== null && is_array($extraData)) {
            // merge keys from $extraData to $messageObj
            foreach ($extraData as $key => $val) {
                if ($key == 'body') {
                    // rename to 'body_' to avoid clobbering
                    $key = 'body_';
                }
                $messageObj[$key] = $val;
            }
        }
        $data['body']['message'] = $messageObj;

        $data['request'] = $this->buildRequestData();
        $data['server'] = $this->buildServerData();
        $data['person'] = $this->buildPersonData();

        // merge $payload_data into $data
        // (overriding anything already present)
        if ($payloadData !== null && is_array($payloadData)) {
            foreach ($payloadData as $key => $val) {
                $data[$key] = $val;
            }
        }

        array_walk_recursive($data, array($this, '_sanitizeUtf8'));

        $payload = $this->buildPayload($data);

        // Determine whether to send the request to the API
        if ($this->_shouldIgnore(true, new RollbarException($message), $payload)) {
            return;
        }

        $this->sendPayload($payload);

        return $data['uuid'];
    }

    /**
     * Run the checkIgnore function and determine whether to send the Exception to the API or not.
     *
     * @param  bool  $isUncaught
     * @param  RollbarException $exception
     * @param  array $payload
     * @return bool
     */
    protected function _shouldIgnore($isUncaught, RollbarException $exception, array $payload) {
        try {
            if (is_callable($this->checkIgnore)
                && call_user_func_array($this->checkIgnore, [$isUncaught, $exception, $payload])
            ) {
                $this->log_info('This item was not sent to Rollbar because it was ignored. '
                    . 'This can happen if a custom checkIgnore() function was used.');

                return true;
            }
        } catch (\Exception $e) {
            // Disable the custom checkIgnore and report errors in the checkIgnore function
            $this->checkIgnore = null;
            $this->logError("Removing custom checkIgnore(). Error while calling custom checkIgnore function:\n"
                . $e->getMessage());
        }

        return false;
    }

    protected function checkConfig() {
        return $this->handler == 'agent' || ($this->accessToken && strlen($this->accessToken) == 32);
    }

    protected function buildRequestData() {
        if ($this->_requestData === null) {
            $request = array(
                'url' => $this->scrubUrl($this->currentUrl()),
                'user_ip' => $this->userIp(),
                'headers' => $this->headers(),
                'method' => isset($_SERVER['REQUEST_METHOD']) ? $_SERVER['REQUEST_METHOD'] : null,
            );

            if ($_GET) {
                $request['GET'] = $this->scrubRequestParams($_GET);
            }
            if ($_POST) {
                $request['POST'] = $this->scrubRequestParams($_POST);
            }
            if (isset($_SESSION) && $_SESSION) {
                $request['session'] = $this->scrubRequestParams($_SESSION);
            }
            $this->_requestData = $request;
        }

        return $this->_requestData;
    }

    protected function scrubUrl($url) {
        $urlQuery = parse_url($url, PHP_URL_QUERY);
        if (!$urlQuery) {
            return $url;
        }
        parse_str($urlQuery, $parsedOutput);
        // using x since * requires URL-encoding
        $scrubbedParams = $this->scrubRequestParams($parsedOutput, 'x');
        $scrubbedUrl = str_replace($urlQuery, http_build_query($scrubbedParams), $url);
        return $scrubbedUrl;
    }

    protected function scrubRequestParams($params, $replacement = '*') {
        $scrubbed = array();
        $potentialRegexFilters = array_filter($this->scrubFields, function($field) {
            return strpos($field, '/') === 0;
        });
        foreach ($params as $k => $v) {
            if ($this->_keyShouldBeScrubbed($k, $potentialRegexFilters)) {
                $scrubbed[$k] = $this->_scrub($v, $replacement);
            } elseif (is_array($v)) {
                // recursively handle array params
                $scrubbed[$k] = $this->scrubRequestParams($v, $replacement);
            } else {
                $scrubbed[$k] = $v;
            }
        }

        return $scrubbed;
    }

    protected function _keyShouldBeScrubbed($key, $potentialRegexFilters) {
        if (in_array(strtolower($key), $this->scrubFields, true)) return true;
        foreach ($potentialRegexFilters as $potentialRegex) {
            if (@preg_match($potentialRegex, $key)) return true;
        }
        return false;
    }

    protected function _scrub($value, $replacement = '*') {
        $count = is_array($value) ? count($value) : strlen($value);
        return str_repeat($replacement, $count);
    }

    protected function headers() {
        $headers = array();
        foreach ($this->scrubRequestParams($_SERVER) as $key => $val) {
            if (substr($key, 0, 5) == 'HTTP_') {
                // convert HTTP_CONTENT_TYPE to Content-Type, HTTP_HOST to Host, etc.
                $name = strtolower(substr($key, 5));
                if (strpos($name, '_') != -1) {
                    $name = preg_replace('/ /', '-', ucwords(preg_replace('/_/', ' ', $name)));
                } else {
                    $name = ucfirst($name);
                }
                $headers[$name] = $val;
            }
        }

        if (count($headers) > 0) {
            return $headers;
        } else {
            // serializes to emtpy json object
            return new \stdClass;
        }
    }

    protected function currentUrl() {
        if (!empty($_SERVER['HTTP_X_FORWARDED_PROTO'])) {
            $proto = strtolower($_SERVER['HTTP_X_FORWARDED_PROTO']);
        } else if (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] == 'on') {
            $proto = 'https';
        } else {
            $proto = 'http';
        }

        if (!empty($_SERVER['HTTP_X_FORWARDED_HOST'])) {
            $host = $_SERVER['HTTP_X_FORWARDED_HOST'];
        } else if (!empty($_SERVER['HTTP_HOST'])) {
            $parts = explode(':', $_SERVER['HTTP_HOST']);
            $host = $parts[0];
        } else if (!empty($_SERVER['SERVER_NAME'])) {
            $host = $_SERVER['SERVER_NAME'];
        } else {
            $host = 'unknown';
        }

        if (!empty($_SERVER['HTTP_X_FORWARDED_PORT'])) {
            $port = $_SERVER['HTTP_X_FORWARDED_PORT'];
        } else if (!empty($_SERVER['SERVER_PORT'])) {
            $port = $_SERVER['SERVER_PORT'];
        } else if ($proto === 'https') {
            $port = 443;
        } else {
            $port = 80;
        }

        $path = isset($_SERVER['REQUEST_URI']) ? $_SERVER['REQUEST_URI'] : '/';

        $url = $proto . '://' . $host;

        if (($proto == 'https' && $port != 443) || ($proto == 'http' && $port != 80)) {
            $url .= ':' . $port;
        }

        $url .= $path;

        return $url;
    }

    protected function userIp() {
        $forwardFor = isset($_SERVER['HTTP_X_FORWARDED_FOR']) ? $_SERVER['HTTP_X_FORWARDED_FOR'] : null;
        if ($forwardFor) {
            // return everything until the first comma
            $parts = explode(',', $forwardFor);
            return $parts[0];
        }

        $realIp = isset($_SERVER['HTTP_X_REAL_IP']) ? $_SERVER['HTTP_X_REAL_IP'] : null;
        if ($realIp) {
            return $realIp;
        }

        return isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : null;
    }

    /**
     * @param \Throwable|\Exception $exc
     * @param mixed $extra_data
     * @return array
     */
    protected function buildExceptionTrace($exc, $extraData = null) {
        $message = $exc->getMessage();

        $trace = array(
            'frames' => $this->buildExceptionFrames($exc),
            'exception' => array(
                'class' => get_class($exc),
                'message' => !empty($message) ? $message : 'unknown'
            )
        );

        if ($extraData !== null) {
            $trace['extra'] = $extraData;
        }

        return $trace;
    }

    /**
     * @param \Throwable|\Exception $exc
     * @param array $extraData
     * @return array
     */
    protected function buildExceptionTraceChain($exc, $extraData = null) {
        $chain = array();
        $chain[] = $this->buildExceptionTrace($exc, $extraData);

        $previous = $exc->getPrevious();

        while (is_a($previous, BASE_EXCEPTION)) {
            $chain[] = $this->buildExceptionTrace($previous);
            $previous = $previous->getPrevious();
        }

        return $chain;
    }

    /**
     * @param \Throwable|\Exception $exc
     * @return array
     */
    protected function buildExceptionFrames($exc) {
        $frames = array();

        foreach ($exc->getTrace() as $frame) {
            $framedata = array(
                'filename' => isset($frame['file']) ? $frame['file'] : '<internal>',
                'lineno' =>  isset($frame['line']) ? $frame['line'] : 0,
                'method' => $frame['function']
                // TODO include args? need to sanitize first.
            );
            if($this->includeExceptionCodeContext && isset($frame['file']) && isset($frame['line'])) {
                $this->addFrameCodeContext($frame['file'], $frame['line'], $framedata);
            }
            $frames[] = $framedata;
        }

        // rollbar expects most recent call to be last, not first
        $frames = array_reverse($frames);

        // add top-level file and line to end of the reversed array
        $file = $exc->getFile();
        $line = $exc->getLine();
        $framedata = array(
            'filename' => $file,
            'lineno' => $line
        );
        if($this->includeExceptionCodeContext) {
            $this->addFrameCodeContext($file, $line, $framedata);
        }
        $frames[] = $framedata;

        $this->shiftMethod($frames);

        return $frames;
    }

    protected function shiftMethod(&$frames) {
        if ($this->shiftFunction) {
            // shift 'method' values down one frame, so they reflect where the call
            // occurs (like Rollbar expects), instead of what is being called.
            for ($i = count($frames) - 1; $i > 0; $i--) {
                $frames[$i]['method'] = $frames[$i - 1]['method'];
            }
            $frames[0]['method'] = '<main>';
        }
    }

    protected function buildErrorFrames($errfile, $errline) {
        if ($this->captureErrorBacktraces) {
            $frames = array();
            $backtrace = debug_backtrace();
            foreach ($backtrace as $frame) {
                // skip frames in this file
                if (isset($frame['file']) && $frame['file'] == __FILE__) {
                    continue;
                }
                // skip the confusing set_error_handler frame
                if ($frame['function'] == 'reportPhpError' && count($frames) == 0) {
                    continue;
                }

                $frameData = array(
                    // Sometimes, file and line are not set. See:
                    // http://stackoverflow.com/questions/4581969/why-is-debug-backtrace-not-including-line-number-sometimes
                    'filename' => isset($frame['file']) ? $frame['file'] : '<internal>',
                    'lineno' =>  isset($frame['line']) ? $frame['line'] : 0,
                    'method' => $frame['function']
                );
                if($this->includeErrorCodeContext && isset($frame['file']) && isset($frame['line'])) {
                    $this->addFrameCodeContext($frame['file'], $frame['line'], $frameData);
                }
                $frames[] = $frameData;
            }

            // rollbar expects most recent call last, not first
            $frames = array_reverse($frames);

            // add top-level file and line to end of the reversed array
            $frameData = array(
                'filename' => $errfile,
                'lineno' => $errline
            );
            if($this->includeErrorCodeContext) {
                $this->addFrameCodeContext($errfile, $errline, $frameData);
            }
            $frames[] = $frameData;

            $this->shiftMethod($frames);

            return $frames;
        } else {
            return array(
                array(
                    'filename' => $errfile,
                    'lineno' => $errline
                )
            );
        }
    }

    protected function buildServerData() {
        if ($this->_serverData === null) {
            $serverData = array();

            if ($this->host === null) {
                // PHP 5.3.0
                if (function_exists('gethostname')) {
                    $this->host = gethostname();
                } else {
                    $this->host = php_uname('n');
                }
            }
            $serverData['host'] = $this->host;
            $serverData['argv'] = isset($_SERVER['argv']) ? $_SERVER['argv'] : null;

            if ($this->branch) {
                $serverData['branch'] = $this->branch;
            }
            if ($this->root) {
                $serverData['root'] = $this->root;
            }
            $this->_serverData = $serverData;
        }
        return $this->_serverData;
    }

    protected function buildPersonData() {
        // return cached value if non-null
        // it *is* possible for it to really be null (i.e. user is not logged in)
        // but we'll keep trying anyway until we get a logged-in user value.
        if ($this->_personData == null) {
            // first priority: try to use $this->person
            if ($this->person && is_array($this->person)) {
                if (isset($this->person['id'])) {
                    $this->_personData = $this->person;
                    return $this->_personData;
                }
            }

            // second priority: try to use $this->person_fn
            if ($this->personFn && is_callable($this->personFn)) {
                $data = @call_user_func($this->personFn);
                if (isset($data['id'])) {
                    $this->_personData = $data;
                    return $this->_personData;
                }
            }
        } else {
            return $this->_personData;
        }

        return null;
    }

    protected function buildBaseData($level = Level::ERROR) {
        if (null === $this->_phpContext) {
            $this->_phpContext = $this->getPhpContext();
        }

        $data = array(
            'timestamp' => time(),
            'environment' => $this->environment,
            'level' => $level,
            'language' => 'php',
            'framework' => 'php',
            'php_context' => $this->_phpContext,
            'notifier' => array(
                'name' => 'rollbar-php',
                'version' => self::VERSION
            ),
            'uuid' => $this->uuid4()
        );

        if ($this->codeVersion) {
            $data['code_version'] = $this->codeVersion;
        }

        return $data;
    }

    protected function buildPayload($data) {
        $payload = array(
            'data' => $data
        );

        if ($this->accessToken) {
            $payload['access_token'] = $this->accessToken;
        }

        return $payload;
    }

    protected function sendPayload($payload) {
        if ($this->batched) {
            if ($this->queueSize() >= $this->batchSize) {
                // flush queue before adding payload to queue
                $this->flush();
            }
            $this->_queue[] = $payload;
        } else {
            $this->_sendPayload($payload);
        }
    }

    /**
     * Sends a single payload to the /item endpoint.
     * $payload - php array
     */
    protected function _sendPayload($payload) {
        if ($this->handler == 'agent') {
            $this->_sendPayloadAgent($payload);
        } else {
            $this->_sendPayloadBlocking($payload);
        }
    }

    protected function _sendPayloadBlocking($payload) {
        $this->logInfo('Sending payload');
        $accessToken = $payload['access_token'];
        $postData = json_encode($payload);
        $this->makeApiCall('item', $accessToken, $postData);
    }

    protected function _sendPayloadAgent($payload) {
        // Only open this the first time
        if (empty($this->_agentLog)) {
            $this->loadAgentFile();
        }
        $this->logInfo('Writing payload to file');
        fwrite($this->_agentLog, json_encode($payload) . "\n");
    }

    /**
     * Sends a batch of payloads to the /batch endpoint.
     * A batch is just an array of standalone payloads.
     * $batch - php array of payloads
     */
    protected function sendBatch($batch) {
        if ($this->handler == 'agent') {
            $this->sendBatchAgent($batch);
        } else {
            $this->sendBatchBlocking($batch);
        }
    }

    protected function sendBatchAgent($batch) {
        $this->logInfo('Writing batch to file');

        // Only open this the first time
        if (empty($this->_agentLog)) {
            $this->loadAgentFile();
        }

        foreach ($batch as $item) {
            fwrite($this->_agentLog, json_encode($item) . "\n");
        }
    }

    protected function sendBatchBlocking($batch) {
        $this->logInfo('Sending batch');
        $accessToken = $batch[0]['access_token'];
        $postData = json_encode($batch);
        $this->makeApiCall('item_batch', $accessToken, $postData);
    }

    protected function getPhpContext() {
        return php_sapi_name() === 'cli' || defined('STDIN') ? 'cli' : 'http';
    }

    protected function makeApiCall($action, $accessToken, $postData) {
        $url = $this->baseApiUrl . $action . '/';

        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $postData);
        curl_setopt($ch, CURLOPT_VERBOSE, false);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, $this->timeout);
        curl_setopt($ch, CURLOPT_HTTPHEADER, array('X-Rollbar-Access-Token: ' . $accessToken));

        if ($this->proxy) {
            $proxy = is_array($this->proxy) ? $this->proxy : array('address' => $this->proxy);

            if (isset($proxy['address'])) {
                curl_setopt($ch, CURLOPT_PROXY, $proxy['address']);
                curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
            }

            if (isset($proxy['username']) && isset($proxy['password'])) {
                curl_setopt($ch, CURLOPT_PROXYUSERPWD, $proxy['username'] . ':' . $proxy['password']);
            }
        }

        if ($this->_curlIpResolveSupported) {
            curl_setopt($ch, CURLOPT_IPRESOLVE, CURL_IPRESOLVE_V4);
        }

        $result = curl_exec($ch);
        $statusCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        if ($statusCode != 200) {
            $this->logWarning('Got unexpected status code from Rollbar API ' . $action . ': ' .$statusCode);
            $this->logWarning('Output: ' .$result);
        } else {
            $this->logInfo('Success');
        }
    }

    /* Logging */

    protected function logInfo($msg) {
        $this->logMessage('INFO', $msg);
    }

    protected function logWarning($msg) {
        $this->logMessage('WARNING', $msg);
    }

    protected function logError($msg) {
        $this->logMessage('ERROR', $msg);
    }

    protected function logMessage($level, $msg) {
        error_log($msg);
        if ($this->logger !== null) {
            $this->logger->log($level, $msg);
        }
    }

    // from http://www.php.net/manual/en/function.uniqid.php#94959
    protected function uuid4() {
        mt_srand();
        return sprintf('%04x%04x-%04x-%04x-%04x-%04x%04x%04x',
            // 32 bits for "time_low"
            mt_rand(0, 0xffff), mt_rand(0, 0xffff),

            // 16 bits for "time_mid"
            mt_rand(0, 0xffff),

            // 16 bits for "time_hi_and_version",
            // four most significant bits holds version number 4
            mt_rand(0, 0x0fff) | 0x4000,

            // 16 bits, 8 bits for "clk_seq_hi_res",
            // 8 bits for "clk_seq_low",
            // two most significant bits holds zero and one for variant DCE1.1
            mt_rand(0, 0x3fff) | 0x8000,

            // 48 bits for "node"
            mt_rand(0, 0xffff), mt_rand(0, 0xffff), mt_rand(0, 0xffff)
        );
    }

    protected function loadAgentFile() {
        $this->_agentLog = fopen($this->agentLogLocation . '/rollbar-relay.' . getmypid() . '.' . microtime(true) . '.rollbar', 'a');
    }

    protected function addFrameCodeContext($file, $line, array &$frameData) {
        $source = $this->getSourceFileReader()->readAsArray($file);
        if (is_array($source)) {
            $source = str_replace(array("\n", "\t", "\r"), '', $source);
            $total = count($source);
            $line = $line - 1;
            $frameData['code'] = $source[$line];
            $offset = 6;
            $min = max($line - $offset, 0);
            if ($min !== $line) {
                $frameData['context']['pre'] = array_slice($source, $min, $line - $min);
            }
            $max = min($line + $offset, $total);
            if ($max !== $line) {
                $frameData['context']['post'] = array_slice($source, $line + 1, $max - $line);
            }
        }
    }

    protected function getSourceFileReader() {
        return $this->_sourceFileReader;
    }
}
