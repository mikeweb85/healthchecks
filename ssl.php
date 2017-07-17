<?php

/**
 * Basic global configurations
 * SSL_CERTIFICATE_MAX_RETRY_INTERVAL (in seconds)
 * SSL_CERTIFICATE_MAX_SIMUL_CERTS
 * SSL_CERTIFICATE_MAX_HISTORY_RETENTION (in days)
 */
define('DS', DIRECTORY_SEPARATOR);
define('SSL_CERTIFICATE_MAX_RETRY_INTERVAL', 900);
define('SSL_CERTIFICATE_MAX_SIMUL_CERTS', 5);
define('SSL_CERTIFICATE_MAX_HISTORY_RETENTION', 7);
define('SSL_CERTIFICATE_REQUEST_TIMEOUT', 15);
define('SSL_CERTIFICATE_WARNING_TIME_STR', '1 week');


/**
 * Do NOT modify below this line
 */

/**
 * Standard HTTP Response Code Exceptions
 */
class HttpException extends Exception {
    protected $code = 400;
    protected $message = 'Unknown error.';
}

class HttpClientException extends HttpException {
    protected $code = 400;
    protected $message = 'Unknown request error.';
}

class BadRequestException extends HttpClientException {
    protected $code = 400;
    protected $message = 'Bad Request.';
}

class NotAuthorizedException extends HttpClientException {
    protected $code = 401;
    protected $message = 'Not authorized.';
}

class ForbiddenException extends HttpClientException {
    protected $code = 403;
    protected $message = 'Forbidden.';
}

class NotFoundException extends HttpClientException {
    protected $code = 404;
    protected $message = 'Not Found.';
}

class MethodNotAllowedException extends HttpClientException {
    protected $code = 405;
    protected $message = 'Method Not Allowed.';
}

class NotAcceptableException extends HttpClientException {
    protected $code = 406;
    protected $message = 'Not Acceptable.';
}

class RequestTimeoutException extends HttpClientException {
    protected $code = 408;
    protected $message = 'Request Timeout.';
}

class ConflictException extends HttpClientException {
    protected $code = 409;
    protected $message = 'Conflict.';
}

class GoneException extends HttpClientException {
    protected $code = 410;
    protected $message = 'Gone.';
}

class PreconditionException extends HttpClientException {
    protected $code = 412;
    protected $message = 'Precondition Failed.';
}

class RequestRangeException extends HttpClientException {
    protected $code = 416;
    protected $message = 'Requested Range Not Satisfiable.';
}

class ExpectationException extends HttpClientException {
    protected $code = 417;
    protected $message = 'Expectation Failed.';
}

class TeaPotException extends HttpClientException {
    protected $code = 418;
    protected $message = 'I\'m a teapot.';
}

class HttpServerException extends HttpException {
    protected $code = 500;
    protected $message = 'Unknown server error.';
}

class NotImplementedException extends HttpServerException {
    protected $code = 501;
    protected $message = 'Not Implemented.';
}

class BadGatewayException extends HttpServerException {
    protected $code = 502;
    protected $message = 'Bad Gateway.';
}

class ServiceUnavailableException extends HttpServerException {
    protected $code = 503;
    protected $message = 'Service Unavailable.';
}

class InsufficientStorageException extends HttpServerException {
    protected $code = 507;
    protected $message = 'Insufficient Storage.';
}

class NetworkAuthenticationRequiredException extends HttpServerException {
    protected $code = 511;
    protected $message = 'Network Authentication Required.';
}

class NetworkConnectTimeoutException extends HttpServerException {
    protected $code = 599;
    protected $message = 'Network Connect Timeout.';
}



/**
 * Custom Application Exceptions
 */
class CouldNotDownloadCertificate extends Exception {
    protected $message = 'Could not download certificate.';
}

class HostDoesNotExist extends CouldNotDownloadCertificate {
    protected $message = 'Host not found.';
}

class NoCertificateInstalled extends CouldNotDownloadCertificate {
    protected $message = 'No certificate installed at host.';
}

class InvalidUrl extends Exception {
    protected $message = 'Invalid URL parameter.';
}

class CouldNotDetermineHost extends InvalidUrl {
    protected $message = 'Could not determine host from URL.';
}

class Sqlite3Exception extends HttpServerException {
    protected $message = 'Sqlite3 database error.';
}

class Sqlite3CouldNotWriteToDatabaseException extends Sqlite3Exception {
    protected $message = 'Could not write to Sqlite3 database.';
}

class Sqlite3NotAvailableException extends Sqlite3Exception {
    protected $message = 'PDO/Sqlite3 database driver not available.';
}

class Sqlite3CouldNotCreateTableException extends Sqlite3CouldNotWriteToDatabaseException {
    protected $message = 'Could not create required database table.';
}

class Sqlite3CouldNotCreateIndexException extends Sqlite3CouldNotWriteToDatabaseException {
    protected $message = 'Could not create required index on database table.';
}

class FormDataNotValidException extends NotAcceptableException {
    protected $message = 'Missing require form parameters.';
}







class SslCertificate {
    
    private $defaultDateFormat = DateTime::ISO8601;
    
    private $endpoint;
    
    private $rawCertificateFields;
    
    private $domains;
    
    private $validFrom;
    
    private $validTo;
    
    private $context_options = ['ssl'=>['capture_peer_cert'=>true, 'verify_peer_name'=>false, 'allow_self_signed'=>true, 'SNI_enabled'=>true, 'SNI_server_name'=>null]];
    
    
    public function __construct($host) {
        if (is_string($host)) {
            $request = ['host'=>$host];
            
        } else {
            $request = $host;
        }
        
        $request = array_merge(['port'=>443, 'hostname'=>null], $request);
        
        if ($request['hostname'] === null) {
            $request['hostname'] = $request['host'];
        }
        
        $this->context_options['ssl']['SNI_server_name'] = $request['hostname'];
        
        $this->endpoint = $request;
        $this->downloadCertificate();
    }
    
    
    private function downloadCertificate() {
        $errno = null;
        $errstr = null;
        
        $context = stream_context_create($this->context_options);
        
        try {
            $client = @stream_socket_client("ssl://{$this->endpoint['host']}:{$this->endpoint['port']}", $errno, $errstr, SSL_CERTIFICATE_REQUEST_TIMEOUT, STREAM_CLIENT_CONNECT, $context);
            
            if ($errno || $errstr) {
                throw new Exception($errstr, $errno);
            }
            
        } catch (Exception $e) {
            if (false !== mb_strpos(mb_strtolower($e->getMessage()), 'getaddrinfo failed')) {
                throw new HostDoesNotExist($this->endpoint['hostname']);
            
            } elseif (false !== mb_strpos(mb_strtolower($e->getMessage()), 'error:14090086')) {
                throw new NoCertificateInstalled($this->endpoint['hostname']);
            }
            
            throw new CouldNotDownloadCertificate($e->getMessage());
        }
        
        if (!$client) {
            throw new CouldNotDownloadCertificate();
        }
        
        $response = stream_context_get_params($client);
        $this->rawCertificateFields = openssl_x509_parse($response['options']['ssl']['peer_certificate']);
    }
    
    
    public function validFrom($format=null) {
        if ($this->validFrom === null) {
            $this->validFrom = new DateTime();
            $this->validFrom->setTimestamp($this->rawCertificateFields['validFrom_time_t']);
        }
        
        if (!$format) {
            $format = $this->defaultDateFormat;
        }
        
        return $this->validFrom->format($format);
    }
    
    
    public function validTo($format=null) {
        if ($this->validTo=== null) {
            $this->validTo = new DateTime();
            $this->validTo->setTimestamp($this->rawCertificateFields['validTo_time_t']);
        }
        
        if (!$format) {
            $format = $this->defaultDateFormat;
        }
        
        return $this->validTo->format($format);
    }
    
    
    public function expires($format=null) {
        return $this->validTo($format);
    }
    
    
    public function getDomains() {
        if ($this->domains === null) {
            $this->domains = [ mb_strtolower($this->rawCertificateFields['subject']['CN']) ];
            
            if (array_key_exists('subjectAltName', $this->rawCertificateFields['extensions'])) {
                $alternateDomains = array_map(function ($domain) {
                    return mb_strtolower(str_replace('DNS:', '', $domain));
                }, explode(', ', $this->rawCertificateFields['extensions']['subjectAltName']));
                
                if (!empty($alternateDomains)) {
                    foreach ($alternateDomains as $domain) {
                        if (!in_array($domain, $this->domains)) {
                            $this->domains[] = $domain;
                        }
                    }
                }
            }
        }
        
        return $this->domains;
    }
    
    
    public function getDomain() {
        $domains = $this->getDomains();
        return $domains[0];
    }
    
    
    public function appliesToDomain($domain) {
        return $this->isCovered($domain);
    }
    
    
    public function isCovered($domain) {
        if (!is_string($domain)) {
            throw new InvalidArgumentException("Domain must be provided in string format.");
        }
        
        $domain = mb_strtolower($domain);
        
        foreach ($this->getDomains() as $coveredDomain) {
            if ( $domain === $coveredDomain) {
                return true;
                
            } elseif (0 === mb_strpos($coveredDomain, '*')) {
                $domainSuffix = mb_substr($coveredDomain, 2);
                
                if ($domainSuffix === mb_substr($domain, -mb_strlen($domainSuffix))) {
                    return true;
                }
            }
        }
        
        return false;
    }
    
    
    public function isExpired(DateTime $dateInQuestion = null) {
        if (!$dateInQuestion) {
            $dateInQuestion = new DateTime();
        }
        
        if ($dateInQuestion->getTimestamp() >= $this->validFrom('U') && $dateInQuestion->getTimestamp() <= $this->validTo('U')) {
            return false;
        }
        
        return true;
    }
    
    
    public function isValid($domain) {
        if (!is_string($domain)) {
            throw new InvalidArgumentException("Domain must be provided in string format.");
        }
        
        if ($this->isCovered($domain) && !$this->isExpired()) {
            return true;
        }
        
        return false;
    }
    
    
    public function getRawCertificateFields() {
        return $this->rawCertificateFields;
    }
    
    
    public function getIssuer() {
        return $this->rawCertificateFields['issuer']['CN'];
    }
    
    
    public function getSerialNumber() {
        return $this->rawCertificateFields['serialNumber'];
    }
    
    
    public function getSignatureAlgorithm() {
        return $this->rawCertificateFields['signatureTypeSN'];
    }
    
    
    public static function doCertificateDomainCovered($domain, array $certificate) {
        $domain = strtolower($domain);
        $domains = array_map('strtolower', $certificate['domains']);
        
        foreach ($domains as $coveredDomain) {
            if ( $domain === $coveredDomain) {
                return true;
                
            } elseif (0 === mb_strpos($coveredDomain, '*')) {
                $domainSuffix = mb_substr($coveredDomain, 2);
                
                if ($domainSuffix === mb_substr($domain, -mb_strlen($domainSuffix))) {
                    return true;
                }
            }
        }
        
        return false;
    }
    
    
    public static function doBasicCertificateIsValid($domain, array $certificate, $warning=null) {
        $warning = ($warning !== null) ? $warning : SSL_CERTIFICATE_WARNING_TIME_STR;
        $expires = intval($certificate['valid_to']);
        $warningTime = strtotime("-{$warning}", $expires);
        $time = time();
        
        if ($time >= $expires) {
            return false;
        }
        
        if (!self::doCertificateDomainCovered($domain, $certificate)) {
            return false;
        }
        
        if ($time >= $warningTime && $time < $expires) {
            return 2;
        }
        
        return true;
    }
}


/**
 * Recursively strip slashes
 */
function stripslashes_deep($values) {
    if (is_array($values)) {
        foreach ($values as $key => $value) {
            $values[$key] = stripslashes_deep($value);
        }
    
    } else {
        $values = stripslashes($values);
    }
    
    return $values;
}



/**
 * Begin SSL verification script
 * @author mweb <mweb@edgehosting.com>
 */
$start = microtime(true);
$path = dirname(__FILE__);
$errors = [];



/**
 * Build request object
 */
$request = (object) [
    'ajax'          => (isset($_SERVER['HTTP_X_REQUESTED_WITH']) && !empty($_SERVER['HTTP_X_REQUESTED_WITH']) && strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) == 'xmlhttprequest'),
    'method'        => strtolower($_SERVER['REQUEST_METHOD']),
    'data'          => [],
    'query'         => $_GET,
    'input'         => null,
    'action'        => 'read',
    'context'       => 'endpoint',
    'scheme'        => ( (isset($_SERVER['HTTP_X_FORWARDED_PROTO']) && strtolower($_SERVER['HTTP_X_FORWARDED_PROTO']) == 'https') || (isset($_SERVER['HTTPS']) && strtolower($_SERVER['HTTPS']) == 'on') || $_SERVER['SERVER_PORT'] == 443) ? 'https' : 'http',
];

if ($_POST) {
    $request->data = $_POST;
    
} elseif (in_array($request->method, ['put', 'delete']) && 0 === strpos($_SERVER('CONTENT_TYPE'), 'application/x-www-form-urlencoded')) {
    $fh = fopen('php://input', 'r');
    $content = stream_get_contents($fh);
    fclose($fh);
    $data = $content;
    
    parse_str($data, $request->data);
}

if (isset($_SERVER['HTTP_X_HTTP_METHOD_OVERRIDE'])) {
    $request->method = strtolower($_SERVER['HTTP_X_HTTP_METHOD_OVERRIDE']);
    $request->data['_method'] = $request->method;
}

if (ini_get('magic_quotes_gpc') === '1') {
    $request->query = stripslashes_deep($request->query);
    $request->data = stripslashes_deep($request->data);
}

switch ($request->method) {
    case 'post':
        $request->action = 'create';
        break;
        
    case 'put':
        $request->action = 'update';
        break;
        
    case 'delete':
        $request->action = 'delete';
        break;
        
    case 'get':
        $request->action = isset($request->query['action']) ? strtolower($request->query['action']): 'read';
        break;
        
    default:
        $errors[] = new NotImplementedException();
}

$contexts = [];

$searchArray = ($request->action == 'read') ? $request->query : $request->data;

foreach ($searchArray as $context=>$contextData) {
    if (in_array(strtolower($context), ['endpoint', 'event','certificate'])) {
        if (!empty($contextData) && is_array($contextData)) {
            $contexts[] = strtolower($context);
        }
    }
}

if (!empty($contexts)) {
    if (count($contexts) > 1) {
        throw new BadRequestException('Context not clearly defined.');
    }
    
    $request->context = $contexts[0];
}

unset($contexts, $searchArray, $context, $contextData);



/**
 * Build response object
 */
$response = (object) [
    'code'              => 200,
    'message'           => 'OK',
    'headers'           => [
        'Content-Type'      => ($request->ajax) ? 'application/json' : 'text/html',
    ],
    'body'              => '',
];



/**
 * Initialize session
 */
session_cache_expire(10);
session_name('php-ssl-sessid');
session_start();

/**
 * Create SQLLite3 database connection
 * Database file will be created if it does not already exist
 * SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = 'YourTableName'
 */
$dbFile = $path . DS . 'ssl.db';
$dbTables = [
    'endpoint'              => 'CREATE TABLE IF NOT EXISTS %s (id integer PRIMARY KEY, host text NOT NULL, port integer DEFAULT 443, hostname text, created integer NOT NULL, modified integer NOT NULL, last_checked integer)',
    'certificate'           => 'CREATE TABLE IF NOT EXISTS %s (id integer PRIMARY KEY, serial_number text NOT NULL, algorithm text, issuer text, valid_from integer NOT NULL, valid_to integer NOT NULL, domains text NOT NULL, created integer NOT NULL, modified integer NOT NULL)',
    'event'                 => 'CREATE TABLE IF NOT EXISTS %s (id integer PRIMARY KEY, endpoint_id integer NOT NULL, certificate_id integer, result text NOT NULL, message text, time real NOT NULL, created integer NOT NULL, FOREIGN KEY (endpoint_id) REFERENCES endpoint (id) ON DELETE CASCADE ON UPDATE CASCADE, FOREIGN KEY (certificate_id) REFERENCES certificate (id) ON DELETE SET NULL ON UPDATE CASCADE)',
];

$dbIndexes = [
    'endpoint'              => [
        'idx_endpoint_hhp'          => 'CREATE UNIQUE INDEX %2$s ON %1$s (host, port, hostname)',
    ],
    'certificate'           => [
        'idx_certificate_isn'       => 'CREATE UNIQUE INDEX %2$s ON %1$s (issuer, serial_number, valid_to)',
        'idx_certificate_vtf'       => 'CREATE INDEX %2$s ON %1$s (valid_from, valid_to)',
        'idx_certificate_sn'        => 'CREATE INDEX %2$s ON %1$s (issuer, serial_number)',
    ],
    'event'               => [
        'idx_event_epid'          => 'CREATE INDEX %2$s ON %1$s (endpoint_id)',
        'idx_event_crtid'         => 'CREATE INDEX %2$s ON %1$s (certificate_id)',
        'idx_event_result'        => 'CREATE INDEX %2$s ON %1$s (result)',
        'idx_event_created'       => 'CREATE INDEX %2$s ON %1$s (created)',
    ],
];

try {
    if (!class_exists('PDO')) {
        throw new HttpServerException('PDO extension not enabled');
    }
    
    if (!in_array('sqlite', PDO::getAvailableDrivers())) {
        throw new Sqlite3NotAvailableException();
    }
    
    $db = new PDO("sqlite:{$dbFile}");
    $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    
    $db->exec('PRAGMA foreign_keys = ON');
    
    $statement = $db->prepare('SELECT name FROM sqlite_master WHERE type=:type');
    
    $statement->execute([':type'=>'table']);
    $tables = $statement->fetchAll(PDO::FETCH_COLUMN, 0);
    
    $statement->execute([':type'=>'index']);
    $indexes = $statement->fetchAll(PDO::FETCH_COLUMN, 0);
    
    foreach ($dbTables as $table=>$tableScript) {
        if (!in_array($table, $tables)) {
            if (false === $db->exec( sprintf($tableScript, $table) )) {
                throw new Sqlite3CouldNotCreateTableException("Could not create table [{$table}]. Reason: \"{$db->lastErrorMsg()}\"");
            }
        }
        
        if (array_key_exists($table, $dbIndexes) && !empty($dbIndexes[$table])) {
            foreach ($dbIndexes[$table] as $index=>$indexScript) {
                if (!in_array($index, $indexes) && false === $db->exec( sprintf($indexScript, $table, $index) )) {
                    throw new Sqlite3CouldNotCreateIndexException("Could not create index [{$index}] on table [{$table}]. Reason: \"{$db->lastErrorMsg()}\"");
                }
            }
        }
    }
    
    unset($statement, $tables, $indexes);
    
} catch (Exception $e) {
    $errors[] = $e;
}


/**
 * Normalize ASSOC_ARRAY data from PDO
 */
function PdoNormalizeFetchAssoc(array $results) {
    $data = [];
    
    foreach ($results as $result) {
        $row = [];
        
        foreach ($result as $column=>$value) {
            list($table, $field) = explode('__', $column);
            
            if (!array_key_exists($table, $row)) {
                $result[$table] = [];
            }
            
            $row[$table][$field] = $value;
        }
        
        $data[] = $row;
    }
    
    return $data;
}


function PdoAliasNormalizeFetchFields(array $fields=[]) {
    $data = [];
    
    foreach ($fields as $field) {
        if (false !== strpos($field, '.')) {
            list($table, $column) = explode('.', $field);
            $data["{$table}__{$column}"] = $field;
            
        } else {
            $data[] = $field;
        }
    }
    
    return $data;
}


function PdoNormalizeFetchFields(array $fields=[]) {
    if (empty($fields)) {
        return '*';
    }
    
    $data = [];
    $fields = PdoAliasNormalizeFetchFields($fields);
    
    foreach ($fields as $alias=>$field) {
        if (is_numeric($alias)) {
            $data[] = $field;
            
        } else {
            $data[] = "{$field} AS {$alias}";
        }
    }
    
    return join(', ', $data);
}



/**
 * Response messages functions
 */
define('SESS_MSG_TYPE_PRIMARY', 'primary');
define('SESS_MSG_TYPE_SUCCESS', 'success');
define('SESS_MSG_TYPE_INFO'   , 'info');
define('SESS_MSG_TYPE_WARN'   , 'warning');
define('SESS_MSG_TYPE_FAIL'   , 'danger');

function SessionMessageWrite($name, $message, $type=null, $dismiss=true) {
    $name = strtolower($name);
    $type = ($type !== null) ? $type : SESS_MSG_TYPE_PRIMARY;
    
    if (!in_array($type, [SESS_MSG_TYPE_PRIMARY, SESS_MSG_TYPE_SUCCESS, SESS_MSG_TYPE_INFO, SESS_MSG_TYPE_WARN, SESS_MSG_TYPE_FAIL])) {
        $type = SESS_MSG_TYPE_PRIMARY;
    }
    
    if ( (!is_bool($dismiss) && !is_int($dismiss)) || (is_int($dismiss) && $dismiss < 3000) ) {
        $dismiss = true;
    }
    
    if (!isset($_SESSION['messages'])) {
        $_SESSION['messages'] = [];
    }
    
    $_SESSION['messages'][$name] = ['id'=>uniqid("msg-{$type}-", false), 'type'=>$type, 'message'=>$message, 'dismiss'=>$dismiss, 'time'=>time()];
}


function SessionMessageDisplay($name) {
    if (!isset($_SESSION['messages']) || empty($_SESSION['messages'])) {
        return;
    }
    
    $names = (is_array($name)) ? $name : [$name];
    unset($name);
    
    foreach ($names as $name) {
        if (!is_string($name) || !isset($_SESSION['messages'][$name])) {
            var_dump('oopsie');
            continue;
        }
        
        $name = strtolower($name);
        $message = $_SESSION['messages'][$name];
        
        $klass = ['alert', "alert-{$message['type']}"];
        $timeout = null;
        
        if (false !== $message['dismiss']) {
            $klass[] = 'alert-dismissible';
            
            if (is_int($message['dismiss'])) {
                $timeout = $message['dismiss'];
                $klass[] = 'alert-dismissible-timeout';
            }
        }
        
        $output = '<div id="'. $message['id'] .'" class="'. join(' ', $klass) .'" role="alert" data-time="'. $message['time'] .'" data-timeout="'. $timeout .'">';
        
        if (false !== $message['dismiss']) {
            $output .= '<button type="button" class="close" data-dismiss="alert" aria-label="Close"><span aria-hidden="true">&times;</span></button>';
        }
        
        $output .= $message['message'] .'</div>';
        
        print $output;
        
        unset($_SESSION['messages'][$name]);
    }
}


function SessionMessageDisplayAll($sort=null) {
    if (!isset($_SESSION['messages']) || empty($_SESSION['messages'])) {
        return;
    }
    
    $sort = ($sort !== null || in_array($sort, ['time', 'name'])) ? $sort : 'time';
    $sortFunc = 'SessionMessageSortBy'. ucfirst(strtolower($sort));
    
    if (function_exists($sortFunc)) {
        // uksort($_SESSION['messages'], $sortFunc);
    }
    
    SessionMessageDisplay(array_keys($_SESSION['messages']));
}


function SessionMessageSortByTime($a, $b) {
    if ($_SESSION['messages'][$a]['time'] === $_SESSION['messages'][$b]['time']) {
        return 0;
    }
    
    return ($_SESSION['messages'][$a]['time'] > $_SESSION['messages'][$b]['time']) ? -1 : 1;
}


function SessionMessageSortByName($a, $b) {
    return (strtolower($_SESSION['messages'][$a]['name']) > strtolower($_SESSION['messages'][$b]['name'])) ? -1 : 1;
}


/**
 * Endpoint CRUD operations
 * 
 * id integer PRIMARY KEY
 * host text NOT NULL,
 * port integer DEFAULT 443,
 * hostname text,
 * created integer NOT NULL,
 * modified integer NOT NULL,
 * last_checked integer
 */
function verifyEndpoint(stdClass $request, stdClass $response=null) {
    global $db;
    
    if (isset($request->query['endpoint']) && isset($request->query['endpoint']['id'])) {
        $id = $request->query['endpoint']['id'];
        
    } elseif (isset($request->query['id'])) {
        $id = $request->query['id'];
    }
    
    $exec = [':limit'=>SSL_CERTIFICATE_MAX_SIMUL_CERTS];
    $fields = ['endpoint.id', 'endpoint.host', 'endpoint.hostname', 'endpoint.port', 'endpoint.last_checked'];
    
    if (!isset($id)) {
        $exec[':ts'] = time()-SSL_CERTIFICATE_MAX_RETRY_INTERVAL;
        $statement = $db->prepare( sprintf('SELECT %s FROM endpoint WHERE (endpoint.last_checked IS NULL OR endpoint.last_checked < :ts) ORDER BY endpoint.last_checked ASC LIMIT :limit', PdoNormalizeFetchFields($fields)));
        
    } else {
        $ids = is_array($id) ? $id: [$id];
        $statement = $db->prepare( sprintf('SELECT %s FROM endpoint WHERE endpoint.id IN (\'%s\') ORDER BY endpoint.last_checked ASC LIMIT :limit', PdoNormalizeFetchFields($fields), join('\', \'', $ids)));
    }
    
    try {
        $statement->execute($exec);
        $endpoints = PdoNormalizeFetchAssoc($statement->fetchAll(PDO::FETCH_ASSOC));
        
    } catch (Exception $e) {
        $endpoints = [];
    }
    
    $results = [];
    
    foreach ($endpoints as &$endpoint) {
        $event = ['id'=>null, 'endpoint_id'=>$endpoint['endpoint']['id'], 'certificate_id'=>null, 'result'=>null, 'message'=>null, 'time'=>null, 'created'=>time()];
        
        try {
            $sslStartTime = microtime(true);
            $ssl = new SslCertificate($endpoint['endpoint']);
            $event['result'] = $ssl->isValid($endpoint['endpoint']['hostname']) ? 'valid' : 'invalid';
            
            
        } catch (Exception $e) {
            $event['result'] = 'invalid';
            
            if ($e instanceof HostDoesNotExist) {
                
            }
            
            switch (true) {
                case ($e instanceof HostDoesNotExist):
                    $event['message'] = "Host {$e->getMessage()} does not exist.";
                    break;
                    
                case ($e instanceof NoCertificateInstalled):
                    $event['message'] = "No certificate install on endpoint.";
                    break;
                    
                case ($e instanceof CouldNotDownloadCertificate && trim($e->getMessage())):
                    $event['message'] = "Could not download certificate, {$e->getMessage()}";
                    break;
                    
                case ($e instanceof CouldNotDownloadCertificate && !trim($e->getMessage())):
                    $event['message'] = "Could not download certificate, unknown error.";
                    break;
                    
                default:
                    $event['message'] = $e->getMessage();
            }
        }
        
        $event['time'] = round(microtime(true) - $sslStartTime, 6);
        
        $db->beginTransaction();
        
        try {
            $statement = $db->prepare('INSERT INTO event (endpoint_id, result, message, time, created) VALUES (:eid, :result, :message, :time, :created)');
            $statement->execute([':eid'=>$event['endpoint_id'], ':result'=>$event['result'], ':message'=>$event['message'], ':time'=>$event['time'], ':created'=>$event['created']]);
            
            $event['id'] = $db->lastInsertId();
            
            $statement = $db->prepare('UPDATE endpoint SET last_checked=:lc WHERE id=:eid');
            $statement->execute([':lc'=>$event['created'], ':eid'=>$endpoint['endpoint']['id']]);
            
            $endpoint['endpoint']['last_checked'] = $event['created'];
            
            $db->commit();
            
        } catch (Exception $e) {
            $db->rollBack();
            
            throw new Sqlite3CouldNotWriteToDatabaseException('Could not write history event to database.');
        }
        
        if (isset($ssl)) {
            $statement = $db->prepare('SELECT id, serial_number, algorithm, issuer, valid_from, valid_to, domains, created, modified FROM certificate WHERE issuer=:issuer AND serial_number=:sn AND valid_to=:vt LIMIT 1');
            $statement->execute([':sn'=>$ssl->getSerialNumber(), ':issuer'=>$ssl->getIssuer(), ':vt'=>$ssl->validTo('U')]);
            $certificate = $statement->fetch(PDO::FETCH_ASSOC);
        
            $db->beginTransaction();
            
            try {
                if (!$certificate) {
                    $certificate = [
                        'id'                    => null,
                        'serial_number'         => $ssl->getSerialNumber(),
                        'algorithm'             => $ssl->getSignatureAlgorithm(),
                        'issuer'                => $ssl->getIssuer(),
                        'valid_from'            => $ssl->validFrom('U'),
                        'valid_to'              => $ssl->validTo('U'),
                        'domains'               => json_encode($ssl->getDomains()),
                        'created'               => $event['created'],
                        'modified'              => $event['created'],
                    ];
                    
                    $statement = $db->prepare('INSERT INTO certificate (serial_number, algorithm, issuer, valid_from, valid_to, domains, created, modified) VALUES (:sn, :algorithm, :issuer, :vf, :vt, :domains, :created, :modified)');
                    
                    $statement->execute([
                        ':sn'               => $certificate['serial_number'],
                        ':algorithm'        => $certificate['algorithm'],
                        ':issuer'           => $certificate['issuer'],
                        ':vf'               => $certificate['valid_from'],
                        ':vt'               => $certificate['valid_to'],
                        ':domains'          => $certificate['domains'],
                        ':created'          => $certificate['created'],
                        ':modified'         => $certificate['modified'],
                    ]);
                    
                    $certificate['id'] = $db->lastInsertId();
                }
                
                $statement = $db->prepare('UPDATE event SET certificate_id=:cid WHERE id=:id');
                $statement->execute([':id'=>$event['id'], ':cid'=>intval($certificate['id'])]);
                
                $event['certificate_id'] = $certificate['id'];
                
                $db->commit();
                
            } catch (Exception $e) {
                $db->rollBack();
                
                throw new Sqlite3CouldNotWriteToDatabaseException('Could not update history event with certificate information.', null, $e);
            }
            
        } else {
            $certificate = ['id'=>null];
        }
        
        if (!empty($certificate)) {
            if (null !== ($domains = @json_decode($certificate['domains'], true))) {
                $certificate['domains'] = $domains;
            }
        }
        
        $results[] = array_merge($endpoint, ['certificate'=>$certificate, 'event'=>$event]);
    }
    
    if ($response && (isset($request->ajax) && $request->ajax === false)) {
        $response->code = 301;
    }
    
    return $results;
}


function createEndpoint(stdClass $request, stdClass $response=null) {
    global $db;
    
    $result = [];
    
    try {
        if (!$response) {
            throw new MethodNotAllowedException();
        }
        
        if (!isset($request->data['endpoint']) || !isset($request->data['endpoint']['uri'])) {
            throw new FormDataNotValidException('Required endpoint information is missing.');
        }
        
        if (false === ($components = @parse_url($request->data['endpoint']['uri']))) {
            throw new FormDataNotValidException('Endpoint URI is not valid or could not be parsed.');
        }
        
        $components = array_merge(['port'=>443, 'hostname'=>$components['host']], $components);
        
        if (isset($request->data['endpoint']['hostname']) && !empty($request->data['endpoint']['hostname'])) {
            $components['hostname'] = $request->data['endpoint']['hostname'];
        }
        
        $endpoint = ['id'=>null, 'host'=>$components['host'], 'port'=>$components['port'], 'hostname'=>$components['hostname'], 'created'=>time()];
        $endpoint['modified'] = $endpoint['created'];
        
        unset($components);
        
        $db->beginTransaction();
        
        try {
            $statement = $db->prepare('INSERT INTO endpoint (host, port, hostname, created, modified) VALUES (:host, :port, :hostname, :created, :created)');
            $insert = $statement->execute([':host'=>$endpoint['host'], ':port'=>$endpoint['port'], ':hostname'=>$endpoint['hostname'], ':created'=>$endpoint['created']]);
            
            if (false === $insert) {
                throw new Sqlite3CouldNotWriteToDatabaseException('Unable to write endpoint to database.');
            }
            
            $db->commit();
            $endpoint['id'] = $db->lastInsertId();
            
        } catch (Exception $e) {
            $db->rollBack();
            
            throw $e;
        }
        
    } catch (Exception $x) {
        if (isset($request->ajax) && $request->ajax === true) {
            throw $x;
        }
        
        SessionMessageWrite('create-endpoint', "<p><strong>Error:</strong> Could not create endpoint.</p><p class=\"muted small\">{$x->getMessage()}</p>", SESS_MSG_TYPE_FAIL, true);
    }
    
    if (isset($endpoint) && $endpoint['id'] !== null) {
        if ($response) {
            $response->code = 201;
            $request->data = [];
        }
        
        $result = ['endpoint'=>$endpoint, 'events'=>[]];
        
        try {
            $events = verifyEndpoint((object) ['query'=>['endpoint'=>['id'=>$endpoint['id']]]]);
            
            if (empty($events)) {
                throw new Exception('Invalid endpoint verification response.');
            }
            
            unset($events[0]['endpoint']);
            
            $result['events'] = $events;
            
            if (isset($request->ajax) && $request->ajax !== true) {
                SessionMessageWrite('create-endpoint', "<p><strong>Success:</strong> Endpoint created sccessfully.</p>", SESS_MSG_TYPE_SUCCESS, true);
            }
            
        } catch (Exception $e) {
            if (isset($request->ajax) && $request->ajax !== true) {
                SessionMessageWrite('create-endpoint', "<p><strong>Warning:</strong> Endpoint created sccessfully, but initial verification could not be completed.</p><p class=\"muted small\">{$e->getMessage()}</p>", SESS_MSG_TYPE_WARN, true);
            }
        }
    }
    
    if ($response && (isset($request->ajax) && $request->ajax !== true)) {
        $response->code = 301;
    }
    
    return $result;
}


function readEndpoint(stdClass $request, stdClass $response=null) {
    global $db;
    
    $endpointFields = ['endpoint.id', 'endpoint.host', 'endpoint.hostname', 'endpoint.port', 'endpoint.created', 'endpoint.modified', 'endpoint.last_checked'];
    
    if (isset($request->query['endpoint']) && isset($request->query['endpoint']['id'])) {
        $id = $request->query['endpoint']['id'];
        
    } elseif (isset($request->query['id'])) {
        $id = $request->query['id'];
    }
    
    if (isset($id)) {
        if (empty($id) || !is_numeric($id)) {
            throw new BadRequestException();
        }
        
        $statement = $db->prepare( sprintf('SELECT %s FROM endpoint WHERE id=:id ORDER BY endpoint.host ASC', PdoNormalizeFetchFields($endpointFields)) );
        $statement->execute([':id'=>$id]);
        
    } else {
        $statement = $db->prepare( sprintf('SELECT %s FROM endpoint ORDER BY endpoint.host ASC', PdoNormalizeFetchFields($endpointFields)) );
        $statement->execute();
    }
    
    if (false === ($endpoints = $statement->fetchAll(PDO::FETCH_ASSOC))) {
        throw new Sqlite3Exception('Could not retrieve endpoints.');
    }
    
    try {
        verifyEndpoint((object) ['query'=>[]]);
        
    } catch (Exception $e) {
        // Do nothing
        var_dump($e);
    }
    
    try {
        purgeEventHistory();
        
    } catch (Exception $e) {
        if ($response && (isset($request->ajax) && $request->ajax !== true)) {
            SessionMessageWrite('purge_history', "<p>Event history purging encountered an error.</p>", SESS_MSG_TYPE_WARN, true);
        }
    }
    
    if (isset($id) && empty($endpoints)) {
        throw new NotFoundException();
    }
        
    $endpoints = PdoNormalizeFetchAssoc($endpoints);
    
    $eventFields = ['event.id', 'event.result', 'event.message', 'event.time', 'event.created'];
    $certificateFields = ['certificate.id', 'certificate.serial_number', 'certificate.algorithm', 'certificate.issuer', 'certificate.valid_from', 'certificate.valid_to', 'certificate.domains', 'certificate.created', 'certificate.modified'];
    
    $statement = $db->prepare( sprintf('SELECT %s FROM event LEFT JOIN certificate ON (certificate.id=event.certificate_id) WHERE event.endpoint_id=:eid ORDER BY event.created DESC LIMIT :limit', PdoNormalizeFetchFields(array_merge($eventFields, $certificateFields))));
    
    $eventHistoryLimit = (isset($id)) ? 100 : 5;
    
    foreach ($endpoints as &$endpoint) {
        $endpoint['events'] = [];
        $statement->execute([':eid'=>$endpoint['endpoint']['id'], ':limit'=>$eventHistoryLimit]);
        
        if (false !== ($events = $statement->fetchAll(PDO::FETCH_ASSOC))) {
            $endpoint['events'] = PdoNormalizeFetchAssoc($events);
            
            foreach ($endpoint['events'] as &$event) {
                if (!empty($event['certificate'])) {
                    if (null !== ($domains = @json_decode($event['certificate']['domains'], true))) {
                        $event['certificate']['domains'] = $domains;
                    }
                }
            }
        }
    }
    
    if (isset($id)) {
        return $endpoints[0];
    }
    
    return ['endpoints'=>$endpoints, '_total'=>count($endpoints)];
}


function updateEndpoint(stdClass $request, stdClass $response=null) {
    global $db;
    
    if (!isset($request->data['endpoint']) || !isset($request->data['endpoint']['id'])) {
        throw new BadRequestException();
    }
    
    $fields = ['id', 'host', 'hostname', 'port', 'created', 'modified', 'last_checked'];
    $statement = $db->prepare(sprintf('SELECT %s FROM endpoint WHERE id=:id', PdoNormalizeFetchFields($fields)));
    $statement->execute([':id'=>$request->data['endpoint']['id']]);
    
    if (false === ($endpoint = $statement->fetch(PDO::FETCH_ASSOC))) {
        throw new NotFoundException();
    }
    
    if (isset($request->data['endpoint']['uri'])) {
        if (false === ($components = @parse_url($request->data['endpoint']['uri']))) {
            throw new FormDataNotValidException('Endpoint URI is not valid or could not be parsed.');
        }
        
        $data = ['host'=>$components['host'], 'port'=>$components['port']];
        
        unset($components);
    }
    
    if (isset($request->data['endpoint']['hostname']) && !empty($request->data['endpoint']['hostname'])) {
        $data['hostname'] = $request->data['endpoint']['hostname'];
    }
    
    $data['modified'] = time();
    
    
    $exec = [':id'=>$endpoint['id']];
    $updateFields = [];
    
    foreach ($data as $field=>$value) {
        $updateFields[] = "{$field}=:{$field}";
        $exec[":{$field}"] = $value;
    }
    
    $statement = $db->prepare( sprintf('UPDATE endpoint SET %s WHERE id=:id', join(', ', $updateFields)) );
    
    if (false === $statement->execute($exec)) {
        throw new Sqlite3CouldNotWriteToDatabaseException($db->errorInfo());
    }
    
    if ($response && (isset($request->ajax) && $request->ajax !== true)) {
        $response->code = 301;
    }
    
    return ['endpoint'=>array_merge($endpoint, $data), '_total'=>$statement->rowCount()];
}


function deleteEndpoint(stdClass $request, stdClass $response=null) {
    global $db;
    
    if (!isset($request->data['endpoint']) || !isset($request->data['endpoint']['id'])) {
        throw new BadRequestException();
    }
    
    $ids = is_array($request->data['endpoint']['id']) ? $request->data['endpoint']['id'] : [$request->data['endpoint']['id']];
    $statement = $db->prepare(sprintf('DELETE FROM endpoint WHERE id IN (\'%s\')', join('\', \'', $ids)));
    $statement->execute();
    
    if ($response && (isset($request->ajax) && $request->ajax === false)) {
        $response->code = 301;
    }
    
    $results = ['endpoints'=>$ids, '_total'=>$statement->rowCount()];
    
    
    if ($response && (isset($request->ajax) && $request->ajax !== true)) {
        $response->code = 301;
    }
    
    return $results;
}



/**
 * Certificate CRUD operations
 * 
 * id integer PRIMARY KEY
 * serial_number text NOT NULL
 * algorithm text
 * issuer text
 * valid_from integer NOT NULL
 * valid_to integer NOT NULL
 * domains text NOT NULL
 * created integer NOT NULL
 * modified integer NOT NULL
 */
function createCertificate(stdClass $request, stdClass $response=null) {
    throw new ForbiddenException('Certificate creation cannot be complete in this request.');
}


function readCertificate(stdClass $request, stdClass $response=null) {
    throw new ForbiddenException();
}


function updateCertificate(stdClass $request, stdClass $response=null) {
    throw new NotImplementedException();
}


function deleteCertificate(stdClass $request, stdClass $response=null) {
    throw new NotImplementedException();
}



/**
 * Event CRUD operations
 */
function createEvent(stdClass $request, stdClass $response=null) {
    throw new NotImplementedException();
}


function readEvent(stdClass $request, stdClass $response=null) {
    global $db;
    
    if ($response && (isset($request->ajax) && $request->ajax !== true)) {
        throw new ForbiddenException();
    }
    
    if (!isset($request->query['event']) && (!isset($request->query['event']['id']) && !isset($request->query['event']['endpoint_id']))) {
        throw new BadRequestException('No event limiter specified.');
    }
    
    $endpointFields = ['endpoint.id', 'endpoint.host', 'endpoint.hostname', 'endpoint.port', 'endpoint.created', 'endpoint.modified', 'endpoint.last_checked'];
    $eventFields = ['event.id', 'event.result', 'event.message', 'event.time', 'event.created'];
    $certificateFields = ['certificate.id', 'certificate.serial_number', 'certificate.algorithm', 'certificate.issuer', 'certificate.valid_from', 'certificate.valid_to', 'certificate.domains', 'certificate.created', 'certificate.modified'];
        
    $exec = [];
    $whereFields = [];
    
    foreach ($request->query['event'] as $field=>$value) {
        $key = "event.". strtolower($field);
        
        if (in_array($key, array_merge($eventFields, ['event.endpoint_id', 'event.certificate_id']))) {
            $whereFields[] = "{$key}=:{$field}";
            $exec[":{$field}"] = $value;
        }
    }
    
    $statement = $db->prepare( sprintf('SELECT %s FROM event LEFT JOIN endpoint ON (endpoint.id=event.endpoint_id) LEFT JOIN certificate ON (certificate.id=event.certificate_id) WHERE (%s) ORDER BY event.created DESC', PdoNormalizeFetchFields(array_merge($eventFields, $endpointFields, $certificateFields)), join(' AND ', $whereFields)) );
    $statement->execute($exec);
    
    if (false === ($events = $statement->fetchAll(PDO::FETCH_ASSOC))) {
        $events = [];
    }
    
    if (isset($request->query['event']['id']) && empty($events)) {
        throw new NotFoundException();
    }
    
    $events = PdoNormalizeFetchAssoc($events);
    
    foreach ($events as &$event) {
        if (!empty($event['certificate'])) {
            if (null !== ($domains = @json_decode($event['certificate']['domains'], true))) {
                $event['certificate']['domains'] = $domains;
            }
        }
    }
    
    if (isset($request->query['event']['id'])) {
        return $events[0];
    }
    
    return ['events'=>$events, '_total'=>count($events)];
}


function updateEvent(stdClass $request, stdClass $response=null) {
    throw new NotImplementedException();
}


function deleteEvent(stdClass $request, stdClass $response=null) {
    throw new ForbiddenException();
}


function purgeEventHistory($days=null) {
    global $db;
    
    $days = ($days !== null) ? $days : SSL_CERTIFICATE_MAX_HISTORY_RETENTION;
    
    $ts = strtotime("-{$days} days");
    $statement = $db->prepare('SELECT id FROM event WHERE event.created < :ts');
    $statement->execute([':ts'=>$ts]);
    
    $events = [];
    
    while (false !== ($event = $statement->fetch(PDO::FETCH_ASSOC))) {
        $events[] = $event['id'];
    }
    
    if (!empty($events)) {
        $db->exec( sprintf('DELETE FROM event WHERE id IN (\'%s\')', join('\', \'', $events)) );
    }
    
    $statement = $db->prepare('SELECT DISTINCT certificate_id FROM event');
    $statement->execute();
    
    $certificates = [];
    
    while (false !== ($event = $statement->fetch(PDO::FETCH_ASSOC))) {
        $certificates[] = $event['certificate_id'];
    }
    
    if (!empty($certificates)) {
        $db->exec( sprintf('DELETE FROM certificate WHERE id NOT IN (\'%s\')', join('\', \'', $certificates)) );
    }
}







/**
 * Map request actions
 */
$requestFunctionName = $request->action . ucfirst($request->context);

if (empty($errors) && $db) {
    try {
        if (!function_exists($requestFunctionName)) {
            throw new NotImplementedException();
        }
        
        $response->body = call_user_func_array($requestFunctionName, [$request, &$response]);
        
        if (false === $response->body) {
            throw new HttpServerException();
        }
        
    } catch (Exception $e) {
        $errors[] = $e;
        $response->body = [];
        
        if ($e instanceof HttpException) {
            $response->code = $e->getCode();
            $response->body['_status'] = $e->getCode();
        }
        
        $response->body['_message'] = $e->getMessage();
    }
    
}

$response->body['_time'] = round(microtime(true) - $start, 6);


/**
 * Return AJAX requests separately
 */
if (!headers_sent()) {
    http_response_code($response->code);
    
    if (in_array($response->code, [301, 302, 307])) {
        if (!isset($_SERVER['HTTP_REFERER'])) {
            $scheme = 'http';
            
            if ( (isset($_SERVER['HTTP_X_FORWARDED_PROTO']) && strtolower($_SERVER['HTTP_X_FORWARDED_PROTO']) == 'https') || (isset($_SERVER['HTTPS']) && strtolower($_SERVER['HTTPS']) == 'on') || $_SERVER['SERVER_PORT'] == 443) {
                $scheme = 'https';
            }
            
            $_SERVER['HTTP_REFERER'] = "{$scheme}:\\{$_SERVER['HTTP_HOST']}{$_SERVER['REQUEST_URI']}";
        }
        
        header("Location: {$_SERVER['HTTP_REFERER']}");
        exit;
    }
    
    if ($request->ajax) {
        header('Content-Type: application/json');
    }
}

if ($request->ajax) {
    print json_encode($response->body);
    exit;
}

extract($response->body);

$klass = ['danger', 'success', 'warning'];
?>
<!DOCTYPE html>
<html lang="en">
<head>
	<title>EdgeHosting :: SSL Certificate Monitor</title>
	<meta charset="utf-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1, user-scalable=no">
	<link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.min.css" integrity="sha384-BVYiiSIFeK1dGmJRAkycuHAHRg32OmUcww7on3RYdg4Va+PmSTsz/K68vbdEjh4u" crossorigin="anonymous">
	<link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap-theme.min.css" integrity="sha384-rHyoN1iRsVXV4nD0JutlnGaslCJuC7uwjduW9SVrLvRYooPp2bWYgmgJQIXwl/Sp" crossorigin="anonymous">
	
	<style type="text/css">
	html {
		position: relative;
		min-height: 100%;
	}
	
	body {
		margin-bottom: 60px;
	
	}
	
	.footer {
		position: absolute;
		bottom: 0;
		width: 100%;
		height: 60px;
		background-color: #f5f5f5;
	}
	
	.footer .container {
		padding-top: 1.5em;
	}
	</style>
</head>
<body>
	<div class="container">
		<div class="page-header">
			<h1>SSL Certificate Monitor</h1>
			<p class="lead">Use this page to view and configure monitoring of your SSL/TLS certificates of your encrypted endpoints.</p>
		</div>
		
		<?php if (in_array($response->code, [200, 201]) && isset($endpoint)): ?>
    	<ol class="breadcrumb">
    		<li><a href="ssl.php">Home</a></li>
    		<li><a href="ssl.php">Endpoints</a></li>
    		
    		<?php if ($endpoint['host'] != $endpoint['hostname']): ?>
    		<li><a href="ssl.php?endpoint[host]=<?php print $endpoint['host']; ?>"><?php print $endpoint['host']; ?></a></li>
    		<?php endif; ?>
    		
    		<li class="active"><?php print $endpoint['hostname']; ?></li>
    	</ol>
    	<?php endif; ?>
    </div>
    
    <div class="container">
    	<?php // SessionMessageDisplay('create-endpoint'); ?>
    </div>
    
    
    <?php if (!isset($endpoint)): ?>
    <div class="jumbotron">
    	<div class="container">
    		<h1>Verify a certificate</h1>
    		<p>Provide the URL for your endpoint to setup certificate monitoring.</p>
    		<form id="createEndpointForm" action="" method="post">
    			<div class="form-group">
    				<label class="sr-only" for="endpointUri">Certificate URL</label>
    				<input id="endpointUri" name="endpoint[uri]" type="url" class="form-control input-lg" placeholder="https://www.yourdomain.com:443/">
    			</div>
    			<div id="certificateAdvancedFields" class="form-group collapse">
    				<label class="" for="endpointSniHostname">Alternate Hostname</label>
    				<input id="endpointSniHostname" name="endpoint[hostname]" type="text" class="form-control" placeholder="www.testdomain.com">
    			</div>
    			<div class="text-right">
    				<button class="btn btn-lg btn-default" type="button" data-toggle="collapse" data-target="#certificateAdvancedFields" aria-expanded="false" aria-controls="collapseExample">Advanced Settings</button>
    				<button type="submit" class="btn btn-lg btn-default btn-primary">Submit</button>
    			</div>
    		</form>
    	</div>
    </div>
    <?php endif; ?>

    <div class="container">
    <?php SessionMessageDisplayAll(); ?>
    </div>
    	
    <?php if (!in_array($response->code, [200, 201])): ?>
    <div class="container">
    	<ol class="breadcrumb">
    		<li><a href="ssl.php">Home</a></li>
    		<li class="active"><?php print $response->code; ?></li>
    	</ol>
    	
    	<div class="page-header text-danger">
    		<h2><strong class=""><?php print $response->code; ?></strong>&nbsp;<span class=""><?php print $_message; ?></span></h2>
    	</div>
    	<p class="lead">A <strong><?php print get_class($errors[0]); ?></strong> was thrown and your request could not be completed.</p>
    </div>
    	
    <?php elseif (isset($endpoint)): ?>
    <?php 
    /**
     * Data agregation for charts
     */
    $successRatio          = [0, 0, 0];
    $responseTimes         = [];
    $responseTimeLabels    = [];
    $responseTimeTotal     = 0;
    $responseTimeAverage   = null;
    $certificates          = [];
    $certificateHistory    = [];
    
    foreach ($events as &$event) {
        // Build certificate status field
        if (isset($event['certificate']) && $event['certificate']['id'] !== null) {
            $event['certificate']['status'] = SslCertificate::doBasicCertificateIsValid($endpoint['hostname'], $event['certificate']);
        }
        
        // Track success or fails
        if ($event['event']['result'] == 'valid') {
            if ($event['certificate']['status'] === 2) {
                $successRatio[2]++;
                
            } else {
                $successRatio[1]++;
            }
            
        } else {
            $successRatio[0]++;
        }
        
        // Track response times
        $responseTimes[] = ['y'=>floatval($event['event']['time']), 'x'=>intval($event['event']['created'])];
        $responseTimeLabels[] = date(DateTime::COOKIE, intval($event['event']['created']));
        
        // Agregate response times
        $responseTimeTotal += floatval($event['event']['time']);
        
        // Certificate History
        if (isset($event['certificate']) && $event['certificate']['id'] !== null && !in_array($event['certificate']['id'], $certificateHistory)) {
            $certificates[]       = $event['certificate'];
            $certificateHistory[] = $event['certificate']['id'];
        }
    }
    
    if ($responseTimeTotal > 0) {
        $responseTimeAverage = $responseTimeTotal / count($events);
    }
    ?>
    
    <div class="container">
    	<div class="page-header" >
    		<div class="row">
        		<div class="col-md-3">
        			<canvas id="successRatio" style="height: 200px; width: 100%;"></canvas>
        		</div>
        		<div class="col-md-9">
    				<div class="row" style="margin-top: 40px;">
    					<div class="col-md-8">
    						<h2><?php print $endpoint['hostname']; ?></h2>
    					</div>
    					<div class="col-md-4 text-right">
    						<?php $endpointCertificateStatus = (!empty($events) && isset($events[0]['certificate']) && $events[0]['certificate']['id'] !== null) ? $events[0]['certificate']['status'] : false; ?>
    						<p style="margin-top: 1.5em;">
    						<?php if ($endpointCertificateStatus === false): ?>
    							<span class="label label-danger">Invalid</span>
    						<?php elseif ($endpointCertificateStatus === true): ?>
    							<span class="label label-success">Success</span>
    						<?php else: ?>
    							<span class="label label-warning">Success, with warnings</span>
    						<?php endif; ?>
    						</p>
    					</div>
    				</div>
        			
        			<div class="row">
        				<div class="col-md-4">
        					<p><a href="https://<?php print $endpoint['host']; ?>:<?php print $endpoint['port']; ?>/" target="_blank"><?php print $endpoint['host']; ?>:<?php print $endpoint['port']; ?></a></p>
        				</div>
        				<div class="col-md-5 col-md-offset-3 text-right">
        					<p><label >Created:</label>&nbsp;<?php print date(DateTime::COOKIE, $endpoint['created']); ?></p>
        				</div>
        			</div>
        			
        			<div class="row">
        				<div class="col-md-4">
        					<p class="small"><label >Avg. Response:</label>&nbsp;<?php if (isset($responseTimeAverage)): ?><?php print round($responseTimeAverage, 4); ?> seconds<?php else: ?><strong class="text-warning">Not checked</strong><?php endif; ?></p>
        				</div>
        				<div class="col-md-5 col-md-offset-3 text-right">
        					<p class="small"><label >Last Check:</label>&nbsp;<?php print date(DateTime::COOKIE, $endpoint['last_checked']); ?></p>
        				</div>
        			</div>
        			
        			<div class="row">
        			<?php if (!empty($events)): ?>
        				<?php if (isset($events[0]['certificate'])): ?>
        				<div class="col-md-4">
        					<p class="small"><label >Issuer: </label>&nbsp;<?php print ucfirst($events[0]['certificate']['issuer']); ?></p>
        				</div>
        				<div class="col-md-4">
        					<p class="small"><label >Algorithm: </label>&nbsp;<?php print $events[0]['certificate']['algorithm']; ?></p>
        				</div>
        				<div class="col-md-4 text-right">
        					<p class="small"><label >Expires: </label>&nbsp;<?php print date(DateTime::COOKIE, $events[0]['certificate']['valid_to']); ?></p>
        				</div>
        				<?php elseif ($events[0]['event']['message']): ?>
        				<div class="col-md-12">
        					<p class="small text-danger"><em><?php print ucfirst($events[0]['event']['message']); ?></em></p>
        				</div>
        				<?php else: ?>
        				<div class="col-md-12">
        					<p class="small text-warning">No certificates associated to this endpoint.</p>
        				</div>
        				<?php endif; ?>
        			<?php else: ?>
        				<div class="col-md-12">
        					<p class="small text-warning">No events found for this endpoint.</p>
        				</div>
        			<?php endif; ?>
        			</div>
        		</div>
        	</div>
    	</div>
    	
    	<br/>
    	
    	<h3>Event Response Times</h3>
    	<canvas id="responseTimes" height="200" style="width: 100%;"></canvas>
    	
    	<br/><br/>
    	
    	<h3>Events <span class="badge"><?php print count($events); ?></span></h3>
    	<table class="table table-striped">
    		<thead>
    			<tr>
    				<th class="text-center">Result</th>
    				<th>Date</th>
    				<th class="text-center">Time (seconds)</th>
    				<th>Certificate</th>
    			</tr>
    		</thead>
    		<tbody>
    		<?php if (!empty($events)): ?>
    		<?php foreach ($events as $event): ?>
    			<tr>
    				<td class="text-center"><span class="label label-<?php print ($event['event']['result'] == 'valid') ? 'success' : 'danger'; ?>"><?php print ucfirst($event['event']['result']); ?></span></td>
    				<td>
    					<?php print date(DateTime::COOKIE, $event['event']['created']); ?>
    					<?php if ($event['event']['message']): ?>
    					<br/><span class="small"><em><?php print ucfirst($event['event']['message']); ?></em></span>
    					<?php endif; ?>
    				</td>
    				<td class="text-center"><span class="small"><?php print round($event['event']['time'], 4); ?></span></td>
    				<td>
    				<?php if (isset($event['certificate'])): ?>
    				<a href="#<?php print hash('md5', $event['certificate']['serial_number']); ?>" class="small"><?php print ucfirst(substr($event['certificate']['issuer'], 0, 38)); ?><?php if (strlen($event['certificate']['issuer']) > 38): ?>&hellip;<?php endif; ?></a>
    				<?php else: ?>
    				<span class="small text-muted">No certificate returned.</span>
    				<?php endif; ?>
    				</td>
    			</tr>
    		<?php endforeach; ?>
    		<?php else: ?>
    			<tr>
    				<td colspan="4" class="text-center text-muted"><p>There are no events registered to this endpoint.</p></td>
    			</tr>
    		<?php endif; ?>
    		</tbody>
    	</table>
    	
    	<br/><br/>
    	
    	<h3>Certificates <span class="badge"><?php print count($certificates); ?></span></h3>
    	<?php if (!empty($certificates)): ?>
    	<div class="row">
    	<?php foreach ($certificates as $certificate): ?>
    		<div class="col-md-4" style="margin-bottom: 12px;">
    			<div class="list-group-item">
    				<h5><a name="<?php print hash('md5', $certificate['serial_number']); ?>" style="overflow: hidden; text-overflow: ellipsis;"><?php print ucfirst(substr($certificate['issuer'], 0, 38)); ?><?php if (strlen($certificate['issuer']) > 38): ?>&hellip;<?php endif; ?></a></h5>
    				<p class="list-group-item-text small"><label style="width: 70px;">Status:</label>&nbsp;
    				<?php if (!SslCertificate::doCertificateDomainCovered($endpoint['hostname'], $certificate)): ?><span class="label label-danger">Invalid</span>&nbsp;DNS name not covered.
    				<?php elseif (time() >= $certificate['valid_to']): ?><span class="label label-danger">Invalid</span>&nbsp;Certificate expired.
    				<?php elseif (time() >= strtotime('-'.SSL_CERTIFICATE_WARNING_TIME_STR, $certificate['valid_to'])): ?><span class="label label-warning">Warning</span>&nbsp;Certificate expiring soon.
    				<?php else: ?><span class="label label-success">Valid</span><?php endif; ?>
    				</p>
    				<p class="list-group-item-text small"><label style="width: 70px;">Serial:</label>&nbsp;...<?php print substr($certificate['serial_number'], -6); ?></p>
    				<p class="list-group-item-text small"><label style="width: 70px;">Algorithm:</label>&nbsp;<?php print $certificate['algorithm']; ?></p>
    				<p class="list-group-item-text small"><label style="width: 70px;">Expiration:</label>&nbsp;<?php print date(DateTime::COOKIE, $certificate['valid_to']); ?></p>
    				<h6>Domains:</h6>
    				<?php foreach ($certificate['domains'] as $i=>$domain): ?>
    				<p class="list-group-item-text text-muted small"><label style="width: 62px; margin-left: 8px;">DNS.<?php print $i+1; ?>:</label>&nbsp;<?php print $domain; ?></p>
    				<?php endforeach; ?>
    			</div>
    		</div>
    		<?php endforeach; ?>
    		</div>
    	<?php else: ?>
    	<p class="lead text-danger">No certificates have been registered to this endpoint.</p>
    	<?php endif; ?>
    	
    	<br/><br/>
    	
    	<h3>Monitoring</h3>
    	<p>Use the following information to provide HTTP monitoring for this endpoint. A unique hash key will only be provided for a healthy endpoint.</p>
    	<div class="well well-sm">
    		<div class="row">
    			<div class="col-md-9">
    				<small><label class="text-muted">URL:</label>&nbsp;<?php print $request->scheme; ?>://<?php print $_SERVER['HTTP_HOST']; ?><?php print $_SERVER['DOCUMENT_URI']; ?>?endpoint[id]=<?php print $endpoint['id']; ?></small>
    			</div>
    			<div class="col-md-3">
    			<?php if (isset($endpointCertificateStatus) && $endpointCertificateStatus !== false): ?>
    				<small><label class="text-muted">Key:</label>&nbsp;<?php print hash('md5', "Endpoint[{$endpoint['id']}].Pass"); ?></small>
    			<?php else: ?>
    				&nbsp;
    			<?php endif; ?>
    			</div>
    		</div>
    	</div>
    	
    	<br/><br/>
    </div>
    
    <?php else: ?>
    <div class="container">
    	<h2>Registered Endpoints</h2><br/>
    	<table class="table table-striped">
    		<thead>
    			<tr>
    				<th class="text-center">Status</th>
    				<th class="text-center">Events</th>
    				<th>Address</th>
    				<th>Created</th>
    				<th>Last Checked</th>
    				<th>&nbsp;</th>
    			</tr>
    		</thead>
    		<tbody>
    		<?php if (!empty($endpoints)): ?>
    		<?php foreach ($endpoints as $endpoint): ?>
    			<tr id="<?php print hash('md5', "endpoint.{$endpoint['endpoint']['id']}"); ?>" style="vertical-align: center;">
    			<?php if (!empty($endpoint['events'])): ?>
    				<td class="text-center">
    				<?php if ($endpoint['events'][0]['event']['result'] == 'valid'): ?>
    					<span class="label label-success">Valid</span>
    				<?php else: ?>
    					<span class="label label-danger">Invalid</span>
    				<?php endif; ?>
    				</td>
    				<td class="text-center">
    				<?php foreach ($endpoint['events'] as $i=>$event): ?>
    					<?php if ($i > 2) { continue; } ?>
    					<?php if (!isset($event['certificate']) || $event['certificate']['id'] === null): ?><span class="label label-danger"><small><span class="glyphicon glyphicon-remove" data-toggle="tooltip" data-placement="top" title="No certificate found"></span></small></span>
        				<?php elseif ($event['event']['result'] != 'valid' && trim($event['event']['message'])): ?><span class="label label-danger"><small><span class="glyphicon glyphicon-fire" data-toggle="tooltip" data-placement="top" title="<?php print $event['event']['message']; ?>"></span></small></span>
        				<?php elseif ($event['event']['result'] != 'valid' && !trim($event['event']['message'])): ?><span class="label label-danger"><small><span class="glyphicon glyphicon-download-alt" data-toggle="tooltip" data-placement="top" title="Could not download certificate"></span></small></span>
    					<?php elseif (!SslCertificate::doCertificateDomainCovered($endpoint['endpoint']['hostname'], $event['certificate'])): ?><span class="label label-danger"><small><span class="glyphicon glyphicon-cog" data-toggle="tooltip" data-placement="top" title="Certificate DNS name mismatch"></span></small></span>
        				<?php elseif (time() >= $event['certificate']['valid_to']): ?><span class="label label-danger"><small><span class="glyphicon glyphicon-refresh" data-toggle="tooltip" data-placement="top" title="Certificate expired"></span></small></span>
        				<?php elseif (time() >= strtotime('-'.SSL_CERTIFICATE_WARNING_TIME_STR, $event['certificate']['valid_to'])): ?><span class="label label-warning"><small><span class="glyphicon glyphicon-time" data-toggle="tooltip" data-placement="top" title="Certificate expiring soon"></span></small></span>
        				<?php else: ?><span class="label label-success"><small><span class="glyphicon glyphicon-ok" data-toggle="tooltip" data-placement="top" title="Endpoint healthy"></span></small></span><?php endif; ?>
    				<?php endforeach; ?>
    				</td>
    			<?php else: ?>
    				<td colspan="2" class="text-center">
    					<span class="label label-warning">No events</span>
    				</td>
    			<?php endif; ?>
    				<td>
    					<a href="?endpoint[id]=<?php print $endpoint['endpoint']['id']; ?>"><?php print $endpoint['endpoint']['hostname']; ?></a>
    					<span class="text-muted small">[<?php print $endpoint['endpoint']['host']; ?>:<?php print $endpoint['endpoint']['port']; ?>]</span>
    				</td>
    				<td><span class="small"><?php print date('Y-M-d H:i:s T', $endpoint['endpoint']['created']); ?></span></td>
    				<td><span class="small"><?php print ($endpoint['endpoint']['last_checked']) ? date('Y-M-d H:i:s T', $endpoint['endpoint']['last_checked']) : '&nbsp;'; ?></span></td>
    				<td><a href="javascript:void();" rel="deleteEndpoint" data-endpoint="<?php print $endpoint['endpoint']['id']; ?>" data-target="<?php print hash('md5', "endpoint.{$endpoint['endpoint']['id']}"); ?>"><span class="glyphicon glyphicon-trash"></span></a></td>
    			</tr>
    		<?php endforeach; ?>
    		<?php else: ?>
    			<tr>
    				<td colspan="6" class="text-center text-muted"><p>There are currently no endpoints registered.</p></td>
    			</tr>
    		<?php endif; ?>
    		</tbody>
    	</table>
    </div>
    
    <?php endif; ?>
    
    <footer class="footer">
    	<div class="container">
    		<div class="row">
    			<div class="col-md-4">
    				<p class="text-muted"></p>
    			</div>
    			<div class="col-md-4 col-md-offset-4">
    				<p class="text-muted text-right">Completed in <?php print $_time; ?> seconds.</p>
    			</div>
    		</div>
    	</div>
    </footer>
    
    <script src="https://ajax.googleapis.com/ajax/libs/jquery/1.12.4/jquery.min.js"></script>
    <script src="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/js/bootstrap.min.js" integrity="sha384-Tc5IQib027qvyjSMfHjOMaLkfuWVxZxUPnCJA7l2mCWNIpG9mGCD8wGNIcPD7Txa" crossorigin="anonymous"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/2.6.0/Chart.bundle.min.js" integrity="sha256-VNbX9NjQNRW+Bk02G/RO6WiTKuhncWI4Ey7LkSbE+5s=" crossorigin="anonymous"></script>
    <script type="text/javascript">
    	jQuery.noConflict();

    	(function($, win, d, con, undef) {
        	var success = '#5cb85c', successFaded = '#dff0d8',
        	warning = '#f0ad4e', warningFaded = '#fcf8e3', 
        	danger = '#d9534f', dangerFaded = '#f2dede',
        	info = '#5bc0de', infoFaded = '#d9edf7', 
        	primary = '#337ab7', primaryFaded = '#337ab7';

        	$('[data-toggle="tooltip"]').tooltip();

        	<?php if (isset($endpoints) && !empty($endpoints)): ?>
        	$(d).on('click', 'a[rel=deleteEndpoint]', function(e) {
            	e.stopImmediatePropagation();
            	e.preventDefault();

            	var target = e.currentTarget;

            	$.ajax({
                	method       : 'post',
            		headers      : {
                		'X-Http-Method-Override'    : 'DELETE'
                	},
            		dataType     : 'json',
            		data         : {
                		'endpoint'    : {'id':$(target).data('endpoint')}
            		},
            		cache        : false,
                	context      : d,
                	timeout      : 60,
                	success      : function(response, status, xhr) {
                    	$("#"+$(target).data('target')).remove();
                	},
                	error        : function(xhr, status, err) {
                    	con.log(status, err);
                	}
            	});
            });
        	<?php endif; ?>
        	
        	<?php if (isset($successRatio)): ?>
        	var successChart = new Chart(d.getElementById('successRatio'), {
        	    type: 'doughnut',
        	    data: {
        	    	'datasets': [{
            	    	label                    : 'Success Ratio',
        	            data                     : <?php print json_encode($successRatio); ?>,
        	            backgroundColor          : [danger, success, warning],
        	            borderWidth              : 2,
        	            hoverBorderWidth         : 2,
        	            borderColor              : "rgb(255, 255, 255)",
        	            hoverBorderColor         : "rgb(255, 255, 255)",
        	            hoverBackgroundColor     : [dangerFaded, successFaded, warningFaded]
        	        }],
        	        
        	        labels: ['Invalid', 'Valid', 'Warnings']
        	    },
        	    options: {
            	    responsive                   : false,
        	    	cutoutPercentage             : 60,
            	    tooltips                     : {
                	    enabled: true,
                	    callbacks: {
                            labelColor: function(tooltipItem, chart) {
                                colors = [danger, success, warning];
                                
                                return {
                                    borderColor: '#fff',
                                    backgroundColor: colors[tooltipItem.index]
                                }
                            }
                        }
                	},
            	    legend                       : {display: false, position: 'right'}
        	    }
        	});
        	<?php endif; ?>

        	<?php if (isset($responseTimes)): ?>
        	var responseChart = new Chart(d.getElementById('responseTimes'), {
        	    type: 'line',
        	    data: {
        	    	'datasets': [{
            	    	label                    : 'Response times',
        	            data                     : <?php print json_encode($responseTimes); ?>,
        	            fill                     : true,
        	            lineTension              : 0,
          	            pointBackgroundColor     : primary,
          	            borderColor              : info,
          	            pointBorderColor         : primary,
          	            backgroundColor          : infoFaded
        	        }],
        	        labels: <?php print json_encode($responseTimeLabels); ?>
        	    },
        	    options: {
            	    responsive                   : false,
            	    tooltips                     : {
                	    enabled: true
                	},
            	    legend                       : {display: false},
            	    scales                       : {
                        xAxes: [{
                            display: false
                        }],
                        yAxes: [{
                            ticks: {
                            	suggestedMax: .6,
                            	callback: function(value, i, values) {
                                	return value.toFixed(1) + ' sec';
                            	}
                            }
                        }]
                    }
        	    }
        	});
        	<?php endif; ?>
        	
    	})(jQuery, window, document, console);
    </script>
</body>
</html>